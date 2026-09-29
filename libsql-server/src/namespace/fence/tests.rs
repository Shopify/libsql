//! Restart at every persistence boundary, indeterminate commits and lost responses
//! (`docs/NAMESPACE_FENCE.md` sections 8.4, 8.5 and 16; section 17 row 7).
//!
//! A restart here is a crash: each server lifetime runs on a runtime of its own, and ending it
//! shuts that runtime down without running any shutdown code and leaks the `NamespaceStore`, so
//! nothing is flushed, the namespace's `.sentinel` stays behind and the next start takes the
//! dirty-recovery path. The next lifetime opens a new `NamespaceStore` (and so a new
//! `MetaStore` and fence registry) on the same directory. The task running the fence command is
//! parked at a hook point when the crash happens, so the crash lands exactly on that boundary.

use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rusqlite::ErrorCode;
use tempfile::tempdir;
use tokio::runtime::Runtime;
use uuid::Uuid;

use super::command::{DrainPolicy, FenceCommand, FenceRequest, OnDeadline};
use super::controller::FenceController;
use super::hooks::{HookAction, HookPoint, Paused};
use super::outcome::{FenceDetail, FenceError, FenceOutcome};
use super::record::{FrozenBoundary, ServerIdentity};
use super::state::{FenceState, OperationClass};
use super::store as fence_store;
use crate::connection::config::DatabaseConfig;
use crate::connection::Connection as _;
use crate::database::{Connection, Database};
use crate::error::Error;
use crate::namespace::meta_store::{FenceCommit, FenceCommitKind, FenceInspection};
use crate::namespace::store::fence_tests::open_store;
use crate::namespace::store::NamespaceStore;
use crate::namespace::RestoreOption;

const OP: Uuid = Uuid::from_u128(0xa);
const OTHER_OP: Uuid = Uuid::from_u128(0xb);
/// Long enough that no test reaches it: a drain must never finish because of time.
const LONG: DrainPolicy = DrainPolicy {
    deadline_ms: 600_000,
    on_deadline: OnDeadline::Fail,
};
/// A deadline that has already passed: an acquisition with a writer still active answers
/// `DRAINING` at once.
const NOW: DrainPolicy = DrainPolicy {
    deadline_ms: 0,
    on_deadline: OnDeadline::Fail,
};
/// Bound on waiting for a task to reach a hook point; a test that hits it has failed.
const PROMPT: Duration = Duration::from_secs(30);
/// Rows committed to `t` before any fence command runs.
const ROWS: i64 = 3;

fn server_identity() -> ServerIdentity {
    ServerIdentity {
        build: "test".into(),
        instance_id: Uuid::from_u128(0x99),
    }
}

/// One lifetime of a server process on `dir`.
struct Server {
    rt: Runtime,
    store: NamespaceStore,
}

impl Server {
    fn boot(dir: &Path) -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();
        let store = rt.block_on(open_store(dir));
        Self { rt, store }
    }

    /// End the lifetime the way a crash does: no shutdown code runs, nothing is flushed or
    /// closed, and every task (including a fence command parked at a hook point) stops where
    /// it is.
    fn crash(self) {
        let Self { rt, store } = self;
        std::mem::forget(store);
        rt.shutdown_background();
    }

    fn run<F: Future>(&self, f: F) -> F::Output {
        self.rt.block_on(f)
    }

    /// Create `ns` with a table `t` holding [`ROWS`] rows.
    fn create_source(&self) {
        self.run(async {
            self.store
                .create(
                    "ns".into(),
                    RestoreOption::Latest,
                    DatabaseConfig {
                        // Held writers must never have the slot stolen by the timeout.
                        txn_timeout: Some(Duration::from_secs(600)),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            let conn = self.conn().await;
            raw(&conn, "create table t (x)").await.unwrap();
            for _ in 0..ROWS {
                raw(&conn, "insert into t values (1)").await.unwrap();
            }
        })
    }

    /// The namespace's controller, loading the namespace if it is not loaded.
    async fn fence(&self) -> Arc<FenceController> {
        self.store
            .with("ns".into(), |ns| ns.fence().clone())
            .await
            .unwrap()
    }

    async fn conn(&self) -> Arc<Connection> {
        let maker = self
            .store
            .with("ns".into(), |ns| ns.db.connection_maker())
            .await
            .unwrap();
        Arc::new(maker.create().await.unwrap())
    }

    /// The live replication log's id and last committed frame.
    async fn log(&self) -> (Uuid, Option<u64>) {
        self.store
            .with("ns".into(), |ns| match &ns.db {
                Database::Primary(p) => {
                    let logger = p.wal_wrapper.wrapper().logger();
                    let frame_no = *logger.new_frame_notifier.borrow();
                    (logger.log_id(), frame_no)
                }
                _ => unreachable!(),
            })
            .await
            .unwrap()
    }

    fn execute(
        &self,
        request: FenceRequest,
    ) -> tokio::task::JoinHandle<crate::Result<FenceCommit>> {
        let store = self.store.clone();
        self.rt.spawn(async move {
            store
                .execute_fence_command(request, server_identity())
                .await
        })
    }

    async fn inspect(&self) -> FenceInspection {
        self.store
            .meta_store()
            .inspect_fence("ns".into())
            .await
            .unwrap()
    }

    async fn count(&self) -> i64 {
        let conn = self.conn().await;
        tokio::task::spawn_blocking(move || {
            conn.with_raw(|c| c.query_row("select count(*) from t", (), |r| r.get(0)))
        })
        .await
        .unwrap()
        .unwrap()
    }

    /// Whether a new connection may begin a write transaction. Writes nothing.
    async fn writes_admitted(&self) -> bool {
        let conn = self.conn().await;
        match raw(&conn, "begin immediate; rollback;").await {
            Ok(()) => true,
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == ErrorCode::AuthorizationForStatementDenied =>
            {
                false
            }
            Err(e) => panic!("unexpected error probing write admission: {e}"),
        }
    }

    /// Acquire and complete the source write fence under `OP`, command 1.
    fn fence_source(&self) -> FenceCommit {
        self.run(async {
            let (log_id, _) = self.log().await;
            let commit = self
                .execute(acquire(log_id, 1, LONG))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(commit.receipt.outcome, FenceOutcome::Applied);
            commit
        })
    }
}

/// Run `sql` as one raw program on `conn`, off the async runtime (it can block on the write
/// slot).
async fn raw(conn: &Arc<Connection>, sql: &'static str) -> rusqlite::Result<()> {
    let conn = conn.clone();
    tokio::task::spawn_blocking(move || conn.with_raw(|c| c.execute_batch(sql)))
        .await
        .unwrap()
}

fn acquire(log_id: Uuid, command_id: u128, policy: DrainPolicy) -> FenceRequest {
    FenceRequest {
        namespace: "ns".into(),
        operation_id: OP,
        command_id: Uuid::from_u128(command_id),
        expected_state: FenceState::Unfenced,
        expected_revision: 0,
        command: FenceCommand::AcquireSourceWriteFence {
            expected_log_id: log_id,
            drain_policy: Some(policy),
        },
    }
}

fn release(command_id: u128, revision: u64) -> FenceRequest {
    FenceRequest {
        namespace: "ns".into(),
        operation_id: OP,
        command_id: Uuid::from_u128(command_id),
        expected_state: FenceState::SourceWriteFenced,
        expected_revision: revision,
        command: FenceCommand::ReleaseSourceWriteFence,
    }
}

fn fence_error(result: &crate::Result<FenceCommit>) -> &FenceError {
    match result {
        Err(Error::NamespaceFence(e)) => e,
        other => panic!("expected a fence error, got {other:?}"),
    }
}

fn boundary(commit: &FenceCommit) -> FrozenBoundary {
    commit
        .record
        .as_ref()
        .and_then(|r| r.frozen_boundary)
        .expect("a write-fenced source has a frozen boundary")
}

/// The marker file's bytes, if there is one.
fn read_marker_bytes(dbs: &Path) -> Option<Vec<u8>> {
    match std::fs::read(fence_store::marker_path(dbs, &"ns".into())) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => panic!("{e}"),
    }
}

/// Put the marker file back to `bytes` (`None`: no marker).
fn restore_marker_bytes(dbs: &Path, bytes: Option<&[u8]>) {
    let path = fence_store::marker_path(dbs, &"ns".into());
    match bytes {
        Some(bytes) => std::fs::write(path, bytes).unwrap(),
        None => std::fs::remove_file(path).unwrap(),
    }
}

async fn reached(paused: &Paused, case: &str, point: HookPoint) {
    tokio::time::timeout(PROMPT, paused.reached())
        .await
        .unwrap_or_else(|_| panic!("{case}: the command never reached {point:?}"));
}

#[derive(Debug, Clone, Copy)]
enum Command {
    Acquire,
    Release,
}

/// What the metastore holds for the command when the process dies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Durable {
    /// Nothing of the command.
    Nothing,
    /// The `SOURCE_DRAINING` record and the command's `DRAINING` receipt (acquisition only).
    Draining,
    /// The command's final result.
    Final,
}

#[derive(Debug, Clone, Copy)]
struct Boundary {
    name: &'static str,
    command: Command,
    point: HookPoint,
    /// The point is the one reached on the acquisition's second commit (the completion of the
    /// drain), not its first.
    second_commit: bool,
    /// The marker file is put back to what it held before the commit, as a crash between the
    /// metastore commit and the marker write leaves it.
    marker_lags: bool,
    durable: Durable,
}

const BOUNDARIES: &[Boundary] = &[
    Boundary {
        name: "acquire/after-installing-gate",
        command: Command::Acquire,
        point: HookPoint::AfterInstallingGate,
        second_commit: false,
        marker_lags: false,
        durable: Durable::Nothing,
    },
    Boundary {
        name: "acquire/before-draining-commit",
        command: Command::Acquire,
        point: HookPoint::BeforeMetastoreCommit,
        second_commit: false,
        marker_lags: false,
        durable: Durable::Nothing,
    },
    Boundary {
        name: "acquire/after-draining-commit",
        command: Command::Acquire,
        point: HookPoint::AfterMetastoreCommit,
        second_commit: false,
        marker_lags: false,
        durable: Durable::Draining,
    },
    Boundary {
        name: "acquire/after-draining-commit/marker-lags",
        command: Command::Acquire,
        point: HookPoint::AfterMetastoreCommit,
        second_commit: false,
        marker_lags: true,
        durable: Durable::Draining,
    },
    Boundary {
        name: "acquire/before-draining-publish",
        command: Command::Acquire,
        point: HookPoint::BeforeGatePublish,
        second_commit: false,
        marker_lags: false,
        durable: Durable::Draining,
    },
    Boundary {
        name: "acquire/draining-published",
        command: Command::Acquire,
        point: HookPoint::BeforeResponse,
        second_commit: false,
        marker_lags: false,
        durable: Durable::Draining,
    },
    Boundary {
        name: "acquire/before-boundary-capture",
        command: Command::Acquire,
        point: HookPoint::BeforeBoundaryCapture,
        second_commit: false,
        marker_lags: false,
        durable: Durable::Draining,
    },
    Boundary {
        name: "acquire/before-fenced-commit",
        command: Command::Acquire,
        point: HookPoint::BeforeMetastoreCommit,
        second_commit: true,
        marker_lags: false,
        durable: Durable::Draining,
    },
    Boundary {
        name: "acquire/after-fenced-commit",
        command: Command::Acquire,
        point: HookPoint::AfterMetastoreCommit,
        second_commit: true,
        marker_lags: false,
        durable: Durable::Final,
    },
    Boundary {
        name: "acquire/after-fenced-commit/marker-lags",
        command: Command::Acquire,
        point: HookPoint::AfterMetastoreCommit,
        second_commit: true,
        marker_lags: true,
        durable: Durable::Final,
    },
    Boundary {
        name: "acquire/before-fenced-publish",
        command: Command::Acquire,
        point: HookPoint::BeforeGatePublish,
        second_commit: true,
        marker_lags: false,
        durable: Durable::Final,
    },
    Boundary {
        name: "acquire/before-fenced-response",
        command: Command::Acquire,
        point: HookPoint::BeforeResponse,
        second_commit: true,
        marker_lags: false,
        durable: Durable::Final,
    },
    Boundary {
        name: "release/before-commit",
        command: Command::Release,
        point: HookPoint::BeforeMetastoreCommit,
        second_commit: false,
        marker_lags: false,
        durable: Durable::Nothing,
    },
    Boundary {
        name: "release/after-commit",
        command: Command::Release,
        point: HookPoint::AfterMetastoreCommit,
        second_commit: false,
        marker_lags: false,
        durable: Durable::Final,
    },
    Boundary {
        name: "release/after-commit/marker-lags",
        command: Command::Release,
        point: HookPoint::AfterMetastoreCommit,
        second_commit: false,
        marker_lags: true,
        durable: Durable::Final,
    },
    Boundary {
        name: "release/before-publish",
        command: Command::Release,
        point: HookPoint::BeforeGatePublish,
        second_commit: false,
        marker_lags: false,
        durable: Durable::Final,
    },
    Boundary {
        name: "release/before-response",
        command: Command::Release,
        point: HookPoint::BeforeResponse,
        second_commit: false,
        marker_lags: false,
        durable: Durable::Final,
    },
];

/// The state a restart recovers for `case`: the one before the command, or the one it
/// committed. Never anything else.
fn recovered_state(case: &Boundary) -> FenceState {
    match (case.command, case.durable) {
        (Command::Acquire, Durable::Nothing) => FenceState::Unfenced,
        (Command::Acquire, Durable::Draining) => FenceState::SourceDraining,
        (Command::Acquire, Durable::Final) => FenceState::SourceWriteFenced,
        (Command::Release, Durable::Nothing) => FenceState::SourceWriteFenced,
        (Command::Release, Durable::Final) => FenceState::Released,
        (Command::Release, Durable::Draining) => unreachable!(),
    }
}

/// Kill the process at every point where a fence command persists, publishes or answers, and
/// restart it on the same directory. The restarted server recovers exactly the state before the
/// command or the state it committed, installs that gate before it serves the namespace (so a
/// namespace is never open unless an opening transition committed), and a replay of the same
/// command then finishes it with the stored or the expected result.
#[test]
fn restart_at_each_boundary() {
    for case in BOUNDARIES {
        restart_at(case);
    }
}

fn restart_at(case: &Boundary) {
    let name = case.name;
    let dir = tempdir().unwrap();
    let dbs = dir.path().join("dbs");

    // First lifetime: run the command until it reaches the boundary, then crash.
    let server = Server::boot(dir.path());
    server.create_source();
    let (log_before, _) = server.run(server.log());
    let (request, revision_before) = match case.command {
        Command::Acquire => (acquire(log_before, 1, LONG), 0),
        Command::Release => {
            let fenced = server.fence_source();
            let revision = fenced.record.as_ref().unwrap().revision;
            (release(2, revision), revision)
        }
    };
    let committed_boundary = server.run(async {
        let fence = server.fence().await;
        let hooks = fence.hooks();
        let mut marker_before = read_marker_bytes(&dbs);
        let paused = if case.second_commit {
            let capture = hooks.pause_at(HookPoint::BeforeBoundaryCapture);
            let task = server.execute(request.clone());
            reached(&capture, name, HookPoint::BeforeBoundaryCapture).await;
            marker_before = read_marker_bytes(&dbs);
            let paused = hooks.pause_at(case.point);
            capture.resume();
            reached(&paused, name, case.point).await;
            drop(task);
            paused
        } else {
            let paused = hooks.pause_at(case.point);
            let task = server.execute(request.clone());
            reached(&paused, name, case.point).await;
            drop(task);
            paused
        };
        if case.marker_lags {
            restore_marker_bytes(&dbs, marker_before.as_deref());
        }
        // What the metastore holds at the moment of the crash.
        let inspected = server.inspect().await;
        assert_eq!(inspected.fence.state(), recovered_state(case), "{name}");
        drop(paused);
        inspected.fence.record().and_then(|r| r.frozen_boundary)
    });
    server.crash();

    // Second lifetime.
    let server = Server::boot(dir.path());
    server.run(async {
        let expected = recovered_state(case);
        let fence = server.fence().await;
        let gate = fence.gate();
        assert_eq!(gate.state(), expected, "{name}: recovered state");
        assert!(
            gate.indeterminate.is_none() && !gate.is_installing(),
            "{name}"
        );
        let open = matches!(expected, FenceState::Unfenced | FenceState::Released);
        assert_eq!(
            server.writes_admitted().await,
            open,
            "{name}: write admission"
        );
        // Committed data survived, nothing else was written.
        assert_eq!(server.count().await, ROWS, "{name}");
        // The marker was repaired if it had fallen behind.
        let marker = fence_store::read_marker(&dbs, &"ns".into()).unwrap();
        assert_eq!(
            marker.and_then(|m| m.ok()).map(|m| m.record.revision),
            gate.fence.record().map(|r| r.revision),
            "{name}: marker"
        );

        // A crash leaves the namespace dirty, so its replication log was rebuilt from the
        // database file under a new log id.
        let (log_after, frame_after) = server.log().await;
        assert_ne!(log_after, log_before, "{name}: the log was not rebuilt");

        let replay = server.execute(request.clone()).await.unwrap();
        match (case.command, case.durable) {
            (Command::Acquire, Durable::Nothing) => {
                // Nothing was acknowledged and nothing was written, and the identity the caller
                // observed is gone: the replay is refused before anything is written, and the
                // caller acquires again under the identity it reads now.
                let e = fence_error(&replay);
                assert_eq!(e.outcome(), FenceOutcome::FencePreconditionFailed, "{name}");
                assert_eq!(e.detail(), Some(FenceDetail::NamespaceIdentityMismatch));
                assert_eq!(fence.gate().state(), FenceState::Unfenced, "{name}");
                assert!(server.writes_admitted().await, "{name}");
                let commit = server
                    .execute(acquire(log_after, 3, LONG))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(commit.receipt.outcome, FenceOutcome::Applied, "{name}");
                assert_eq!(
                    boundary(&commit),
                    FrozenBoundary {
                        log_id: log_after,
                        frame_no: frame_after,
                    },
                    "{name}"
                );
            }
            (Command::Acquire, Durable::Draining) => {
                // The drain that was requested resumes and completes at once: recovery
                // discarded any uncommitted work. The boundary is on the live, rebuilt log.
                let commit = replay.unwrap();
                assert_eq!(commit.kind, FenceCommitKind::Committed, "{name}");
                assert_eq!(commit.receipt.outcome, FenceOutcome::Applied, "{name}");
                assert_eq!(commit.receipt.command_id, request.command_id);
                assert_eq!(commit.receipt.revision_after, 2, "{name}");
                let record = commit.record.as_ref().unwrap();
                assert_eq!(record.identity.log_id, Some(log_before), "{name}");
                assert_eq!(
                    boundary(&commit),
                    FrozenBoundary {
                        log_id: log_after,
                        frame_no: frame_after,
                    },
                    "{name}"
                );
            }
            (Command::Acquire, Durable::Final) => {
                // The stored result, boundary included: it names the log that was live when
                // the drain was proven.
                let commit = replay.unwrap();
                assert_eq!(commit.kind, FenceCommitKind::Replayed, "{name}");
                assert_eq!(commit.receipt.outcome, FenceOutcome::Applied, "{name}");
                assert_eq!(Some(boundary(&commit)), committed_boundary, "{name}");
                assert_eq!(boundary(&commit).log_id, log_before, "{name}");
            }
            (Command::Release, durable) => {
                let commit = replay.unwrap();
                let kind = if durable == Durable::Final {
                    FenceCommitKind::Replayed
                } else {
                    FenceCommitKind::Committed
                };
                assert_eq!(commit.kind, kind, "{name}");
                assert_eq!(commit.receipt.outcome, FenceOutcome::Applied, "{name}");
                assert_eq!(commit.receipt.revision_before, revision_before, "{name}");
                assert_eq!(commit.receipt.state_after, FenceState::Released, "{name}");
            }
        }

        // Settled: the gate is the durable state, and a further replay answers the same.
        let gate = fence.gate();
        let durable = server.inspect().await;
        assert_eq!(gate.fence, durable.fence, "{name}");
        let open = gate.state() == FenceState::Released;
        assert_eq!(server.writes_admitted().await, open, "{name}");
        assert_eq!(server.count().await, ROWS, "{name}");
    });
    server.crash();
}

/// After a restart in `SOURCE_DRAINING` with a writer that was active at the crash, nothing
/// advances by itself: the namespace stays closed, other commands cannot move it on, and only
/// the replay of the same acquisition completes the drain, at once.
#[test]
fn restart_in_draining_waits_for_the_same_command() {
    let dir = tempdir().unwrap();

    let server = Server::boot(dir.path());
    server.create_source();
    let (log_before, _) = server.run(server.log());
    let request = acquire(log_before, 1, NOW);
    server.run(async {
        let holder = server.conn().await;
        raw(&holder, "begin immediate; insert into t values (2);")
            .await
            .unwrap();
        let commit = server.execute(request.clone()).await.unwrap().unwrap();
        assert_eq!(commit.receipt.outcome, FenceOutcome::Draining);
        // The writer never finishes: its transaction dies with the process (closing the
        // connection rolls it back, which is what SQLite recovery does to it on disk).
        drop(holder);
    });
    server.crash();

    let server = Server::boot(dir.path());
    server.run(async {
        let fence = server.fence().await;
        assert_eq!(fence.gate().state(), FenceState::SourceDraining);
        assert!(!server.writes_admitted().await);
        // The uncommitted write is gone.
        assert_eq!(server.count().await, ROWS);

        // Reads are served and move nothing; other commands cannot advance the namespace.
        let set_read_fence = FenceRequest {
            namespace: "ns".into(),
            operation_id: OP,
            command_id: Uuid::from_u128(2),
            expected_state: FenceState::SourceWriteFenced,
            expected_revision: 2,
            command: FenceCommand::SetSourceReadFence { drain_policy: None },
        };
        let r = server.execute(set_read_fence).await.unwrap();
        assert!(fence_error(&r).outcome() != FenceOutcome::Applied);
        let (log_after, frame_after) = server.log().await;
        let mut other = acquire(log_after, 3, LONG);
        other.operation_id = OTHER_OP;
        let r = server.execute(other).await.unwrap();
        assert_eq!(
            fence_error(&r).outcome(),
            FenceOutcome::FenceOwnedByAnotherOperation
        );
        let inspected = server.inspect().await;
        assert_eq!(inspected.fence.state(), FenceState::SourceDraining);
        assert_eq!(inspected.fence.revision(), 1);
        assert_eq!(fence.gate().state(), FenceState::SourceDraining);

        // The same command, with the same zero deadline, completes at once.
        let commit = server.execute(request.clone()).await.unwrap().unwrap();
        assert_eq!(commit.receipt.outcome, FenceOutcome::Applied);
        assert_eq!(commit.receipt.command_id, request.command_id);
        assert_eq!(
            boundary(&commit),
            FrozenBoundary {
                log_id: log_after,
                frame_no: frame_after,
            }
        );
        assert_eq!(fence.gate().state(), FenceState::SourceWriteFenced);
        assert!(!server.writes_admitted().await);
        assert_eq!(server.count().await, ROWS);
    });
    server.crash();
}

/// A commit whose outcome is unknown closes the namespace (every class but maintenance and
/// observability), makes every other command answer `FENCE_COMMIT_INDETERMINATE`, and is
/// reconciled by replaying the same command from the durable row: both when the commit had
/// happened and when it had not.
#[test]
fn indeterminate_commit_keeps_gate_closed() {
    for committed in [true, false] {
        let dir = tempdir().unwrap();
        let server = Server::boot(dir.path());
        server.create_source();
        server.run(async {
            let (log_id, frame_no) = server.log().await;
            let fence = server.fence().await;
            let request = acquire(log_id, 1, LONG);
            fence.hooks().arm(
                if committed {
                    HookPoint::AfterMetastoreCommit
                } else {
                    HookPoint::BeforeMetastoreCommit
                },
                HookAction::Indeterminate,
            );
            let r = server.execute(request.clone()).await.unwrap();
            let e = fence_error(&r);
            assert_eq!(e.outcome(), FenceOutcome::FenceCommitIndeterminate);
            assert_eq!(e.detail(), Some(FenceDetail::IndeterminateCommit));

            let durable = server.inspect().await.fence.state();
            assert_eq!(
                durable,
                if committed {
                    FenceState::SourceDraining
                } else {
                    FenceState::Unfenced
                }
            );
            let gate = fence.gate();
            assert_eq!(gate.indeterminate, Some((OP, request.command_id)));
            assert!(!gate.is_installing());
            for class in OperationClass::ALL {
                let permitted = fence.permits(class);
                match class {
                    OperationClass::Maintenance | OperationClass::Observability => {
                        assert!(permitted.is_ok())
                    }
                    _ => assert_eq!(
                        permitted.unwrap_err().outcome(),
                        FenceOutcome::FenceStateUnavailable,
                        "{class:?}"
                    ),
                }
            }
            assert!(!server.writes_admitted().await);

            // Any other command is refused with the indeterminate code, nothing is written.
            let mut other = acquire(log_id, 2, LONG);
            other.operation_id = OTHER_OP;
            let r = server.execute(other).await.unwrap();
            assert_eq!(
                fence_error(&r).outcome(),
                FenceOutcome::FenceCommitIndeterminate
            );
            let r = server.execute(acquire(log_id, 3, LONG)).await.unwrap();
            assert_eq!(
                fence_error(&r).outcome(),
                FenceOutcome::FenceCommitIndeterminate
            );
            assert_eq!(server.inspect().await.fence.state(), durable);

            // The replay reconciles from the durable row: it resumes the drain that committed,
            // or runs the acquisition that did not, and completes it.
            let commit = server.execute(request.clone()).await.unwrap().unwrap();
            assert_eq!(commit.receipt.outcome, FenceOutcome::Applied);
            assert_eq!(commit.receipt.command_id, request.command_id);
            assert_eq!(commit.receipt.revision_after, 2);
            assert_eq!(boundary(&commit), FrozenBoundary { log_id, frame_no });
            let gate = fence.gate();
            assert_eq!(gate.indeterminate, None);
            assert_eq!(gate.state(), FenceState::SourceWriteFenced);
            assert_eq!(gate.fence, server.inspect().await.fence);
            assert!(!server.writes_admitted().await);
            // Maintenance and reads are served again.
            assert_eq!(server.count().await, ROWS);
        });
        server.crash();
    }
}

/// The caller of an acquisition goes away before it hears the answer, once while the drain is
/// still waiting and once just before the final response. The acquisition finishes on its own
/// task regardless, `InspectFence` shows the result, and a replay of the same command returns
/// it.
#[test]
fn acquire_response_loss_resolved_by_replay_and_inspect() {
    for lose_at in [HookPoint::AfterMetastoreCommit, HookPoint::BeforeResponse] {
        let dir = tempdir().unwrap();
        let server = Server::boot(dir.path());
        server.create_source();
        server.run(async {
            let (log_id, _) = server.log().await;
            let fence = server.fence().await;
            let request = acquire(log_id, 1, LONG);
            let holder = server.conn().await;
            raw(&holder, "begin immediate; insert into t values (2);")
                .await
                .unwrap();

            let hooks = fence.hooks();
            let capture = hooks.pause_at(HookPoint::BeforeBoundaryCapture);
            let first = (lose_at == HookPoint::AfterMetastoreCommit)
                .then(|| hooks.pause_at(HookPoint::AfterMetastoreCommit));
            let caller = server.execute(request.clone());
            if let Some(first) = first {
                // The caller is gone right after SOURCE_DRAINING commits.
                reached(&first, "response loss", HookPoint::AfterMetastoreCommit).await;
                caller.abort();
                first.resume();
            }

            // The drain waits for the writer, with or without a caller.
            let mut rx = fence.subscribe();
            tokio::time::timeout(
                PROMPT,
                rx.wait_for(|g| g.state() == FenceState::SourceDraining),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(
                server.inspect().await.fence.state(),
                FenceState::SourceDraining
            );
            // A replay while it runs waits for the transition lock rather than racing it.
            let replay_during = server.execute(request.clone());

            raw(&holder, "commit").await.unwrap();
            let (_, committed) = server.log().await;
            reached(&capture, "response loss", HookPoint::BeforeBoundaryCapture).await;
            if lose_at == HookPoint::BeforeResponse {
                // The caller is gone after the final commit was published, before the answer.
                let last = hooks.pause_at(HookPoint::BeforeResponse);
                capture.resume();
                reached(&last, "response loss", HookPoint::BeforeResponse).await;
                assert_eq!(fence.gate().state(), FenceState::SourceWriteFenced);
                caller.abort();
                last.resume();
            } else {
                capture.resume();
            }
            assert!(caller.await.unwrap_err().is_cancelled());
            tokio::time::timeout(
                PROMPT,
                rx.wait_for(|g| g.state() == FenceState::SourceWriteFenced),
            )
            .await
            .unwrap()
            .unwrap();

            let inspected = server.inspect().await;
            assert_eq!(inspected.fence.state(), FenceState::SourceWriteFenced);
            let record = inspected.fence.record().unwrap();
            assert_eq!(
                record.frozen_boundary,
                Some(FrozenBoundary {
                    log_id,
                    frame_no: committed,
                })
            );
            let receipt = inspected
                .receipts
                .iter()
                .filter_map(|r| r.receipt.as_ref().ok())
                .find(|r| r.command_id == request.command_id)
                .unwrap()
                .clone();
            assert_eq!(receipt.outcome, FenceOutcome::Applied);

            for replay in [
                replay_during.await.unwrap().unwrap(),
                server.execute(request.clone()).await.unwrap().unwrap(),
            ] {
                assert_eq!(replay.kind, FenceCommitKind::Replayed);
                assert_eq!(replay.receipt, receipt);
                assert_eq!(replay.record.as_ref(), Some(record));
            }
            assert_eq!(server.count().await, ROWS + 1);
            assert!(!server.writes_admitted().await);
        });
        server.crash();
    }
}
