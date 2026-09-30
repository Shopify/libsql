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
        self.fence_of("ns").await
    }

    async fn fence_of(&self, ns: &'static str) -> Arc<FenceController> {
        self.store
            .with(ns.into(), |ns| ns.fence().clone())
            .await
            .unwrap()
    }

    async fn conn(&self) -> Arc<Connection> {
        self.conn_to("ns").await
    }

    async fn conn_to(&self, ns: &'static str) -> Arc<Connection> {
        let maker = self
            .store
            .with(ns.into(), |ns| ns.db.connection_maker())
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
        self.inspect_of("ns").await
    }

    async fn inspect_of(&self, ns: &'static str) -> FenceInspection {
        self.store
            .meta_store()
            .inspect_fence(ns.into())
            .await
            .unwrap()
    }

    async fn count(&self) -> i64 {
        self.count_in("ns").await
    }

    async fn count_in(&self, ns: &'static str) -> i64 {
        let conn = self.conn_to(ns).await;
        tokio::task::spawn_blocking(move || {
            conn.with_raw(|c| c.query_row("select count(*) from t", (), |r| r.get(0)))
        })
        .await
        .unwrap()
        .unwrap()
    }

    /// Whether a new connection may begin a write transaction. Writes nothing.
    async fn writes_admitted(&self) -> bool {
        self.writes_admitted_in("ns").await
    }

    async fn writes_admitted_in(&self, ns: &'static str) -> bool {
        let conn = self.conn_to(ns).await;
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
    read_marker_bytes_of(dbs, "ns")
}

fn read_marker_bytes_of(dbs: &Path, ns: &'static str) -> Option<Vec<u8>> {
    match std::fs::read(fence_store::marker_path(dbs, &ns.into())) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => panic!("{e}"),
    }
}

/// Put the marker file back to `bytes` (`None`: no marker).
fn restore_marker_bytes(dbs: &Path, bytes: Option<&[u8]>) {
    restore_marker_bytes_of(dbs, "ns", bytes)
}

fn restore_marker_bytes_of(dbs: &Path, ns: &'static str, bytes: Option<&[u8]>) {
    let path = fence_store::marker_path(dbs, &ns.into());
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
                assert_eq!(commit.kind, FenceCommitKind::Resumed, "{name}");
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

// ---------------------------------------------------------------------------------------------
// Read fence, seal and write enable: restart at each persistence boundary (section 8.5)

mod read_and_target_boundaries {
    use super::*;
    use crate::namespace::fence::command::ValidationResult;
    use crate::namespace::fence::controller::LeaseKind;
    use crate::namespace::fence::target::tests::{create_request, enable_request, target_command};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Later {
        /// `SetSourceReadFence` on the write-fenced source `ns`.
        ReadFence,
        /// `SealTargetImport` on the quarantined target `tgt`.
        Seal,
        /// `EnableTargetWrites` on the write-fenced target `tgt`.
        Enable,
    }

    impl Later {
        fn namespace(self) -> &'static str {
            match self {
                Later::ReadFence => "ns",
                Later::Seal | Later::Enable => "tgt",
            }
        }

        /// State and revision before the command.
        fn before(self) -> (FenceState, u64) {
            match self {
                Later::ReadFence => (FenceState::SourceWriteFenced, 2),
                Later::Seal => (FenceState::TargetQuarantined, 1),
                Later::Enable => (FenceState::TargetWriteFenced, 5),
            }
        }

        /// State and revision while the command drains.
        fn draining(self) -> (FenceState, u64) {
            match self {
                Later::ReadFence => (FenceState::SourceReadDraining, 3),
                Later::Seal => (FenceState::TargetImportDraining, 2),
                Later::Enable => unreachable!("EnableTargetWrites does not drain"),
            }
        }

        /// State and revision once the command has applied.
        fn applied(self) -> (FenceState, u64) {
            match self {
                Later::ReadFence => (FenceState::SourceReadFenced, 4),
                Later::Seal => (FenceState::TargetValidating, 3),
                Later::Enable => (FenceState::TargetWritable, 6),
            }
        }

        fn state_after(self, durable: Durable) -> (FenceState, u64) {
            match durable {
                Durable::Nothing => self.before(),
                Durable::Draining => self.draining(),
                Durable::Final => self.applied(),
            }
        }

        fn request(self) -> FenceRequest {
            match self {
                Later::ReadFence => FenceRequest {
                    namespace: "ns".into(),
                    operation_id: OP,
                    command_id: Uuid::from_u128(2),
                    expected_state: FenceState::SourceWriteFenced,
                    expected_revision: 2,
                    command: FenceCommand::SetSourceReadFence {
                        drain_policy: Some(LONG),
                    },
                },
                Later::Seal => target_command(
                    10,
                    FenceState::TargetQuarantined,
                    1,
                    FenceCommand::SealTargetImport {
                        drain_policy: Some(LONG),
                    },
                ),
                Later::Enable => enable_request(30),
            }
        }
    }

    /// Where the command is when the process dies.
    #[derive(Debug, Clone, Copy)]
    enum Park {
        /// At a point of the command's first (or only) commit.
        First(HookPoint),
        /// At a point of the drain's completion, the command's second commit.
        Second(HookPoint),
        /// In the drain, waiting for a reader (read fence) or an import call (seal) that was
        /// already running when the command started.
        WaitingForHolder,
    }

    #[derive(Debug, Clone, Copy)]
    struct LaterBoundary {
        name: &'static str,
        command: Later,
        park: Park,
        /// The marker file is put back to what it held before the commit, as a crash between
        /// the metastore commit and the marker write leaves it.
        marker_lags: bool,
        durable: Durable,
    }

    const fn case(
        name: &'static str,
        command: Later,
        park: Park,
        marker_lags: bool,
        durable: Durable,
    ) -> LaterBoundary {
        LaterBoundary {
            name,
            command,
            park,
            marker_lags,
            durable,
        }
    }

    use Durable::{Draining, Final, Nothing};
    use HookPoint::{
        AfterClosingReads, AfterInstallingGate, AfterMetastoreCommit, BeforeGatePublish,
        BeforeMetastoreCommit, BeforeResponse,
    };
    use Later::{Enable, ReadFence, Seal};
    use Park::{First, Second, WaitingForHolder};

    const LATER_BOUNDARIES: &[LaterBoundary] = &[
        case(
            "read/after-closing-reads",
            ReadFence,
            First(AfterClosingReads),
            false,
            Nothing,
        ),
        case(
            "read/before-draining-commit",
            ReadFence,
            First(BeforeMetastoreCommit),
            false,
            Nothing,
        ),
        case(
            "read/after-draining-commit",
            ReadFence,
            First(AfterMetastoreCommit),
            false,
            Draining,
        ),
        case(
            "read/after-draining-commit/marker-lags",
            ReadFence,
            First(AfterMetastoreCommit),
            true,
            Draining,
        ),
        case(
            "read/before-draining-publish",
            ReadFence,
            First(BeforeGatePublish),
            false,
            Draining,
        ),
        case(
            "read/draining-published",
            ReadFence,
            First(BeforeResponse),
            false,
            Draining,
        ),
        case(
            "read/waiting-for-reader",
            ReadFence,
            WaitingForHolder,
            false,
            Draining,
        ),
        case(
            "read/before-fenced-commit",
            ReadFence,
            Second(BeforeMetastoreCommit),
            false,
            Draining,
        ),
        case(
            "read/after-fenced-commit",
            ReadFence,
            Second(AfterMetastoreCommit),
            false,
            Final,
        ),
        case(
            "read/after-fenced-commit/marker-lags",
            ReadFence,
            Second(AfterMetastoreCommit),
            true,
            Final,
        ),
        case(
            "read/before-fenced-publish",
            ReadFence,
            Second(BeforeGatePublish),
            false,
            Final,
        ),
        case(
            "read/before-fenced-response",
            ReadFence,
            Second(BeforeResponse),
            false,
            Final,
        ),
        case(
            "seal/after-installing-gate",
            Seal,
            First(AfterInstallingGate),
            false,
            Nothing,
        ),
        case(
            "seal/before-draining-commit",
            Seal,
            First(BeforeMetastoreCommit),
            false,
            Nothing,
        ),
        case(
            "seal/after-draining-commit",
            Seal,
            First(AfterMetastoreCommit),
            false,
            Draining,
        ),
        case(
            "seal/after-draining-commit/marker-lags",
            Seal,
            First(AfterMetastoreCommit),
            true,
            Draining,
        ),
        case(
            "seal/before-draining-publish",
            Seal,
            First(BeforeGatePublish),
            false,
            Draining,
        ),
        case(
            "seal/draining-published",
            Seal,
            First(BeforeResponse),
            false,
            Draining,
        ),
        case(
            "seal/waiting-for-import-call",
            Seal,
            WaitingForHolder,
            false,
            Draining,
        ),
        case(
            "seal/before-validating-commit",
            Seal,
            Second(BeforeMetastoreCommit),
            false,
            Draining,
        ),
        case(
            "seal/after-validating-commit",
            Seal,
            Second(AfterMetastoreCommit),
            false,
            Final,
        ),
        case(
            "seal/after-validating-commit/marker-lags",
            Seal,
            Second(AfterMetastoreCommit),
            true,
            Final,
        ),
        case(
            "seal/before-validating-publish",
            Seal,
            Second(BeforeGatePublish),
            false,
            Final,
        ),
        case(
            "seal/before-validating-response",
            Seal,
            Second(BeforeResponse),
            false,
            Final,
        ),
        case(
            "enable/before-commit",
            Enable,
            First(BeforeMetastoreCommit),
            false,
            Nothing,
        ),
        case(
            "enable/after-commit",
            Enable,
            First(AfterMetastoreCommit),
            false,
            Final,
        ),
        case(
            "enable/after-commit/marker-lags",
            Enable,
            First(AfterMetastoreCommit),
            true,
            Final,
        ),
        case(
            "enable/before-publish",
            Enable,
            First(BeforeGatePublish),
            false,
            Final,
        ),
        case(
            "enable/before-response",
            Enable,
            First(BeforeResponse),
            false,
            Final,
        ),
    ];

    /// Create the quarantined target `tgt` (revision 1) and import a table `t` of [`ROWS`]
    /// rows into it.
    fn create_target(server: &Server) {
        server.run(async {
            let commit = server
                .store
                .create_target_quarantined(create_request("tgt", 1), server_identity())
                .await
                .unwrap();
            assert_eq!(commit.receipt.outcome, FenceOutcome::Applied);
            let mut session = server
                .store
                .open_import_session("tgt".into(), OP, 1)
                .await
                .unwrap();
            session
                .with_raw(|c| {
                    c.execute_batch("create table t (x)")?;
                    for _ in 0..ROWS {
                        c.execute("insert into t values (1)", ())?;
                    }
                    Ok::<_, rusqlite::Error>(())
                })
                .await
                .unwrap()
                .unwrap();
        })
    }

    /// Seal, validate and publish `tgt`: `TARGET_WRITE_FENCED` at revision 5.
    fn write_fence_target(server: &Server) {
        server.run(async {
            let steps = [
                target_command(
                    10,
                    FenceState::TargetQuarantined,
                    1,
                    FenceCommand::SealTargetImport {
                        drain_policy: Some(LONG),
                    },
                ),
                target_command(
                    20,
                    FenceState::TargetValidating,
                    3,
                    FenceCommand::RecordTargetValidation {
                        result: ValidationResult::Ok,
                        summary: "rows match".into(),
                    },
                ),
                target_command(
                    21,
                    FenceState::TargetValidating,
                    4,
                    FenceCommand::PublishTargetReadableWriteFenced,
                ),
            ];
            for step in steps {
                let commit = server.execute(step).await.unwrap().unwrap();
                assert_eq!(commit.receipt.outcome, FenceOutcome::Applied);
            }
        })
    }

    fn prepare(server: &Server, command: Later) {
        match command {
            Later::ReadFence => {
                server.create_source();
                server.fence_source();
            }
            Later::Seal => create_target(server),
            Later::Enable => {
                create_target(server);
                write_fence_target(server);
            }
        }
    }

    /// What the drain of [`Park::WaitingForHolder`] waits for: a read lease, as a running SQL
    /// program holds one, or an admitted import call, as a running `ImportSession::with_raw`
    /// holds one. Neither holds a SQLite lock, so it can outlive the crash without disturbing
    /// the next lifetime's recovery. Only dropped.
    type Holder = Box<dyn std::any::Any + Send>;

    async fn hold(server: &Server, fence: &Arc<FenceController>, command: Later) -> Holder {
        match command {
            Later::ReadFence => Box::new(
                fence
                    .acquire_read_lease(OperationClass::NormalRead, LeaseKind::Sql, || {})
                    .unwrap(),
            ),
            Later::Seal => {
                let session = server
                    .store
                    .open_import_session("tgt".into(), OP, 1)
                    .await
                    .unwrap();
                let call = fence.begin_import_write(session.capability()).unwrap();
                drop(session);
                assert_eq!(fence.import_writers(), 1);
                Box::new(call)
            }
            Later::Enable => unreachable!("EnableTargetWrites does not drain"),
        }
    }

    /// Admission of new work in the gate's current state: writes only on a writable target,
    /// normal reads wherever the state admits them.
    async fn assert_admission(
        server: &Server,
        fence: &Arc<FenceController>,
        ns: &'static str,
        name: &str,
    ) {
        let state = fence.gate().state();
        let writes = state == FenceState::TargetWritable;
        let reads = matches!(
            state,
            FenceState::SourceWriteFenced
                | FenceState::TargetWriteFenced
                | FenceState::TargetWritable
        );
        assert_eq!(
            server.writes_admitted_in(ns).await,
            writes,
            "{name}: write admission in {state}"
        );
        let lease = fence.acquire_read_lease(OperationClass::NormalRead, LeaseKind::Sql, || {});
        assert_eq!(lease.is_ok(), reads, "{name}: read admission in {state}");
    }

    /// Kill the process at every point where `SetSourceReadFence`, `SealTargetImport` and
    /// `EnableTargetWrites` persist, publish, answer or wait, and restart it on the same
    /// directory. As for the source write fence (`restart_at_each_boundary`), the restarted
    /// server recovers exactly the state before the command or the state it committed and
    /// installs that gate before serving the namespace: reads stay closed once
    /// `SOURCE_READ_DRAINING` committed, import stays closed once `TARGET_IMPORT_DRAINING`
    /// committed, and target writes open only if `TARGET_WRITABLE` committed. No reader or
    /// import call survives a restart, so a replay of the same command completes an
    /// interrupted drain at once; a replay of a finished one returns its stored result.
    #[test]
    fn restart_at_each_read_and_target_boundary() {
        for case in LATER_BOUNDARIES {
            restart_later_at(case);
        }
    }

    fn restart_later_at(case: &LaterBoundary) {
        let name = case.name;
        let ns = case.command.namespace();
        let dir = tempdir().unwrap();
        let dbs = dir.path().join("dbs");
        let request = case.command.request();
        let before = case.command.before();

        // First lifetime: run the command until it reaches the boundary, then crash.
        let server = Server::boot(dir.path());
        prepare(&server, case.command);
        let holder = server.run(async {
            let fence = server.fence_of(ns).await;
            assert_eq!(
                (fence.gate().state(), fence.gate().revision()),
                before,
                "{name}"
            );
            let hooks = fence.hooks();
            let mut marker_before = read_marker_bytes_of(&dbs, ns);
            let mut holder = None;
            let paused = match case.park {
                Park::First(point) => {
                    let paused = hooks.pause_at(point);
                    let task = server.execute(request.clone());
                    reached(&paused, name, point).await;
                    drop(task);
                    Some(paused)
                }
                Park::Second(point) => {
                    // The first commit's response point comes after its publication and
                    // before the drain, which has nothing to wait for.
                    let first = hooks.pause_at(HookPoint::BeforeResponse);
                    let task = server.execute(request.clone());
                    reached(&first, name, HookPoint::BeforeResponse).await;
                    marker_before = read_marker_bytes_of(&dbs, ns);
                    let paused = hooks.pause_at(point);
                    first.resume();
                    reached(&paused, name, point).await;
                    drop(task);
                    Some(paused)
                }
                Park::WaitingForHolder => {
                    holder = Some(hold(&server, &fence, case.command).await);
                    let (draining, _) = case.command.draining();
                    let mut gate = fence.subscribe();
                    let task = server.execute(request.clone());
                    tokio::time::timeout(PROMPT, gate.wait_for(|g| g.state() == draining))
                        .await
                        .unwrap_or_else(|_| panic!("{name}: the command never started draining"))
                        .unwrap();
                    assert!(!task.is_finished(), "{name}: the drain did not wait");
                    drop(task);
                    None
                }
            };
            if case.marker_lags {
                restore_marker_bytes_of(&dbs, ns, marker_before.as_deref());
            }
            // What the metastore holds at the moment of the crash.
            let inspected = server.inspect_of(ns).await;
            assert_eq!(
                (inspected.fence.state(), inspected.fence.revision()),
                case.command.state_after(case.durable),
                "{name}: durable at the crash"
            );
            drop(paused);
            holder
        });
        server.crash();
        // The reader or import call belonged to the dead process.
        drop(holder);

        // Second lifetime.
        let server = Server::boot(dir.path());
        server.run(async {
            let recovered = case.command.state_after(case.durable);
            let fence = server.fence_of(ns).await;
            let gate = fence.gate();
            assert_eq!(
                (gate.state(), gate.revision()),
                recovered,
                "{name}: recovered state"
            );
            assert!(
                gate.indeterminate.is_none()
                    && !gate.is_installing()
                    && gate.closing_reads.is_none(),
                "{name}: an in-memory gate survived the restart"
            );
            assert_eq!(fence.read_lease_counts().total(), 0, "{name}");
            assert_eq!(fence.import_writers(), 0, "{name}");
            assert_admission(&server, &fence, ns, name).await;
            // Committed data survived, nothing else was written.
            assert_eq!(server.count_in(ns).await, ROWS, "{name}");
            // The marker was repaired if it had fallen behind.
            let marker = fence_store::read_marker(&dbs, &ns.into()).unwrap();
            assert_eq!(
                marker.and_then(|m| m.ok()).map(|m| m.record.revision),
                gate.fence.record().map(|r| r.revision),
                "{name}: marker"
            );
            if case.command == Later::Seal {
                // Import resumes only if the seal never committed.
                let session = server.store.open_import_session(ns.into(), OP, 1).await;
                match case.durable {
                    Durable::Nothing => drop(session.unwrap()),
                    Durable::Draining | Durable::Final => {
                        assert!(
                            matches!(session, Err(Error::NamespaceFence(_))),
                            "{name}: import reopened after the seal committed"
                        );
                    }
                }
            }

            let replay = server.execute(request.clone()).await.unwrap().unwrap();
            let kind = match case.durable {
                Durable::Nothing => FenceCommitKind::Committed,
                Durable::Draining => FenceCommitKind::Resumed,
                Durable::Final => FenceCommitKind::Replayed,
            };
            assert_eq!(replay.kind, kind, "{name}");
            assert_eq!(replay.receipt.outcome, FenceOutcome::Applied, "{name}");
            assert_eq!(replay.receipt.command_id, request.command_id, "{name}");
            assert_eq!(replay.receipt.revision_before, before.1, "{name}");
            assert_eq!(
                (replay.receipt.state_after, replay.receipt.revision_after),
                case.command.applied(),
                "{name}"
            );

            // Settled: the gate is the durable state, and a further replay answers the same.
            let gate = fence.gate();
            let durable = server.inspect_of(ns).await;
            assert_eq!(gate.fence, durable.fence, "{name}");
            assert_eq!(
                (gate.state(), gate.revision()),
                case.command.applied(),
                "{name}"
            );
            assert_admission(&server, &fence, ns, name).await;
            assert_eq!(server.count_in(ns).await, ROWS, "{name}");
            let again = server.execute(request.clone()).await.unwrap().unwrap();
            assert_eq!(again.kind, FenceCommitKind::Replayed, "{name}");
            assert_eq!(again.receipt, replay.receipt, "{name}");
        });
        server.crash();
    }
}

// ---------------------------------------------------------------------------------------------
// Protection against an older binary (section 13.2)

mod legacy_mirror {
    use super::*;
    use crate::namespace::fence::command::ValidationResult;
    use crate::namespace::fence::target::tests::{create_request, enable_request, target_command};
    use crate::namespace::meta_store::{metastore_connection_maker, MetaStoreConnection};
    use libsql_replication::rpc::metadata;

    /// A metastore connection set up the way an older binary sets up its own: foreign keys on,
    /// and no knowledge of the fence tables.
    async fn older_binary(dir: &Path) -> MetaStoreConnection {
        let (maker, _) = metastore_connection_maker(None, dir).await.unwrap();
        let conn = maker().unwrap();
        conn.execute("PRAGMA foreign_keys=ON", ()).unwrap();
        conn
    }

    fn encoded(config: &DatabaseConfig) -> metadata::DatabaseConfig {
        metadata::DatabaseConfig::from(config)
    }

    fn stored(meta: &rusqlite::Connection, ns: &'static str) -> DatabaseConfig {
        fence_store::read_config_row(meta, &ns.into())
            .unwrap()
            .expect("the namespace has a config row")
    }

    /// The `block_*` values section 13.2 says a fenced namespace's stored config holds in
    /// `state`, derived from the permission matrix (section 3.3) rather than from the record.
    fn mirror(state: FenceState) -> (bool, bool, Option<String>) {
        let (block_reads, block_writes) = match state {
            FenceState::SourceDraining
            | FenceState::SourceWriteFenced
            | FenceState::TargetWriteFenced => (false, true),
            FenceState::SourceReadDraining
            | FenceState::SourceReadFenced
            | FenceState::TargetQuarantined
            | FenceState::TargetImportDraining
            | FenceState::TargetValidating
            | FenceState::TargetAborted => (true, true),
            other => unreachable!("{other} does not mirror the fence"),
        };
        let reason = format!("namespace fence: {state} (operation {OP})");
        (block_reads, block_writes, Some(reason))
    }

    /// In `state`, the stored config of `ns` is the namespace's own config `own` with the fence
    /// mirrored into its `block_*` fields (or with its own values once the operation has
    /// finished); the in-memory config is `own`; a config write through the metastore is
    /// refused and changes nothing while the fence denies lifecycle work; and an older
    /// binary's delete of the config row fails on the fence row's foreign key.
    async fn check(
        server: &Server,
        meta: &rusqlite::Connection,
        ns: &'static str,
        own: &DatabaseConfig,
        state: FenceState,
    ) {
        let fence = server.fence_of(ns).await;
        assert_eq!(fence.gate().state(), state, "{ns}");
        let row = stored(meta, ns);
        let blocks = (row.block_reads, row.block_writes, row.block_reason.clone());
        let finished = matches!(
            state,
            FenceState::Unfenced | FenceState::Released | FenceState::TargetWritable
        );
        if finished {
            assert_eq!(
                blocks,
                (own.block_reads, own.block_writes, own.block_reason.clone()),
                "{ns} in {state}: the namespace's own block_* values"
            );
        } else {
            assert_eq!(blocks, mirror(state), "{ns} in {state}: the legacy mirror");
        }
        // Only the block_* fields carry the mirror.
        assert_eq!(
            encoded(&fence_store::with_legacy_blocks(
                &row,
                &fence_store::legacy_blocks_of(own)
            )),
            encoded(own),
            "{ns} in {state}"
        );
        let handle = server
            .store
            .meta_store()
            .lookup(&ns.into())
            .await
            .unwrap()
            .expect("the namespace has a config");
        assert_eq!(
            encoded(&handle.get()),
            encoded(own),
            "{ns} in {state}: in memory"
        );

        if !finished {
            let overwrite = DatabaseConfig {
                block_reads: false,
                block_writes: false,
                block_reason: None,
                max_db_pages: own.max_db_pages + 1,
                ..own.clone()
            };
            match handle.store(overwrite).await {
                Err(Error::NamespaceFence(_)) => (),
                other => panic!("{ns} in {state}: config write not refused: {other:?}"),
            }
            assert_eq!(encoded(&stored(meta, ns)), encoded(&row), "{ns} in {state}");
            assert_eq!(encoded(&handle.get()), encoded(own), "{ns} in {state}");
        }

        if state != FenceState::Unfenced {
            // SQLite enforces `ON DELETE RESTRICT` with an action trigger, so the refusal is
            // `SQLITE_CONSTRAINT_TRIGGER` carrying the foreign key message.
            match meta.execute("DELETE FROM namespace_configs WHERE namespace = ?1", [ns]) {
                Err(rusqlite::Error::SqliteFailure(e, message)) => {
                    assert_eq!(
                        e.code,
                        ErrorCode::ConstraintViolation,
                        "{ns} in {state}: {e}"
                    );
                    assert_eq!(
                        message.as_deref(),
                        Some("FOREIGN KEY constraint failed"),
                        "{ns} in {state}"
                    );
                }
                other => {
                    panic!("{ns} in {state}: an older binary's delete was not refused: {other:?}")
                }
            }
            assert_eq!(encoded(&stored(meta, ns)), encoded(&row), "{ns} in {state}");
        }
    }

    fn applied(result: Result<crate::Result<FenceCommit>, tokio::task::JoinError>) -> FenceCommit {
        let commit = result.unwrap().unwrap();
        assert_eq!(commit.receipt.outcome, FenceOutcome::Applied);
        commit
    }

    fn source_command(
        command_id: u128,
        expected_state: FenceState,
        expected_revision: u64,
        command: FenceCommand,
    ) -> FenceRequest {
        FenceRequest {
            namespace: "ns".into(),
            operation_id: OP,
            command_id: Uuid::from_u128(command_id),
            expected_state,
            expected_revision,
            command,
        }
    }

    /// Store `config` through the metastore, as `POST /v1/namespaces/:ns/config` does.
    async fn store_config(server: &Server, ns: &'static str, config: &DatabaseConfig) {
        server
            .store
            .meta_store()
            .lookup(&ns.into())
            .await
            .unwrap()
            .unwrap()
            .store(config.clone())
            .await
            .unwrap();
    }

    /// Walk a source and two targets through every stored state: in each, the config row
    /// carries the legacy mirror of section 13.2 (reads blocked where the state denies reads,
    /// writes blocked where it denies writes, and a reason naming the state and the
    /// operation), nothing else in the row changes, a config write cannot overwrite it, and the
    /// foreign key refuses an older binary's delete. Release and write enable put the
    /// namespace's own values back, after which config writes follow the existing policy; the
    /// foreign key stays with the fence row. A restart keeps the rows and gives the in-memory
    /// config the namespace's own values.
    #[test]
    fn legacy_mirror_and_fk_guard() {
        let dir = tempdir().unwrap();
        let server = Server::boot(dir.path());
        server.create_source();
        let owns = server.run(async {
            let meta = older_binary(dir.path()).await;
            let mut own = DatabaseConfig {
                block_reason: Some("pre-fence note".into()),
                max_db_pages: 1234,
                ..(*server
                    .store
                    .meta_store()
                    .lookup(&"ns".into())
                    .await
                    .unwrap()
                    .unwrap()
                    .get())
                .clone()
            };
            store_config(&server, "ns", &own).await;
            check(&server, &meta, "ns", &own, FenceState::Unfenced).await;

            // SOURCE_DRAINING, parked after its commit and before the boundary is captured.
            let fence = server.fence().await;
            let (log_id, _) = server.log().await;
            let paused = fence.hooks().pause_at(HookPoint::BeforeBoundaryCapture);
            let task = server.execute(acquire(log_id, 1, LONG));
            reached(&paused, "acquire", HookPoint::BeforeBoundaryCapture).await;
            check(&server, &meta, "ns", &own, FenceState::SourceDraining).await;
            paused.resume();
            applied(task.await);
            check(&server, &meta, "ns", &own, FenceState::SourceWriteFenced).await;

            // SOURCE_READ_DRAINING, parked after its publication and before the drain.
            let paused = fence.hooks().pause_at(HookPoint::BeforeResponse);
            let task = server.execute(source_command(
                2,
                FenceState::SourceWriteFenced,
                2,
                FenceCommand::SetSourceReadFence {
                    drain_policy: Some(LONG),
                },
            ));
            reached(&paused, "read fence", HookPoint::BeforeResponse).await;
            check(&server, &meta, "ns", &own, FenceState::SourceReadDraining).await;
            paused.resume();
            applied(task.await);
            check(&server, &meta, "ns", &own, FenceState::SourceReadFenced).await;

            applied(
                server
                    .execute(source_command(
                        3,
                        FenceState::SourceReadFenced,
                        4,
                        FenceCommand::ClearSourceReadFence,
                    ))
                    .await,
            );
            check(&server, &meta, "ns", &own, FenceState::SourceWriteFenced).await;
            applied(server.execute(release(4, 5)).await);
            check(&server, &meta, "ns", &own, FenceState::Released).await;
            // Released: config writes follow the existing policy and are stored as written.
            own = DatabaseConfig {
                block_writes: true,
                block_reason: Some("after the operation".into()),
                max_db_pages: 4321,
                ..own
            };
            store_config(&server, "ns", &own).await;
            check(&server, &meta, "ns", &own, FenceState::Released).await;

            // A target, created with the default block_* values.
            applied(Ok(server
                .store
                .create_target_quarantined(create_request("tgt", 1), server_identity())
                .await));
            let mut own_target = (*server
                .store
                .meta_store()
                .lookup(&"tgt".into())
                .await
                .unwrap()
                .unwrap()
                .get())
            .clone();
            assert!(
                !own_target.block_reads
                    && !own_target.block_writes
                    && own_target.block_reason.is_none()
            );
            check(
                &server,
                &meta,
                "tgt",
                &own_target,
                FenceState::TargetQuarantined,
            )
            .await;

            // TARGET_IMPORT_DRAINING, parked after its publication and before the drain.
            let target = server.fence_of("tgt").await;
            let paused = target.hooks().pause_at(HookPoint::BeforeResponse);
            let task = server.execute(target_command(
                10,
                FenceState::TargetQuarantined,
                1,
                FenceCommand::SealTargetImport {
                    drain_policy: Some(LONG),
                },
            ));
            reached(&paused, "seal", HookPoint::BeforeResponse).await;
            check(
                &server,
                &meta,
                "tgt",
                &own_target,
                FenceState::TargetImportDraining,
            )
            .await;
            paused.resume();
            applied(task.await);
            check(
                &server,
                &meta,
                "tgt",
                &own_target,
                FenceState::TargetValidating,
            )
            .await;

            applied(
                server
                    .execute(target_command(
                        20,
                        FenceState::TargetValidating,
                        3,
                        FenceCommand::RecordTargetValidation {
                            result: ValidationResult::Ok,
                            summary: "rows match".into(),
                        },
                    ))
                    .await,
            );
            check(
                &server,
                &meta,
                "tgt",
                &own_target,
                FenceState::TargetValidating,
            )
            .await;
            applied(
                server
                    .execute(target_command(
                        21,
                        FenceState::TargetValidating,
                        4,
                        FenceCommand::PublishTargetReadableWriteFenced,
                    ))
                    .await,
            );
            check(
                &server,
                &meta,
                "tgt",
                &own_target,
                FenceState::TargetWriteFenced,
            )
            .await;
            applied(server.execute(enable_request(30)).await);
            check(
                &server,
                &meta,
                "tgt",
                &own_target,
                FenceState::TargetWritable,
            )
            .await;
            own_target = DatabaseConfig {
                max_db_pages: 777,
                ..own_target
            };
            store_config(&server, "tgt", &own_target).await;
            check(
                &server,
                &meta,
                "tgt",
                &own_target,
                FenceState::TargetWritable,
            )
            .await;

            // An aborted target keeps everything blocked.
            applied(Ok(server
                .store
                .create_target_quarantined(create_request("tgt2", 40), server_identity())
                .await));
            let own_aborted = (*server
                .store
                .meta_store()
                .lookup(&"tgt2".into())
                .await
                .unwrap()
                .unwrap()
                .get())
            .clone();
            applied(
                server
                    .execute(FenceRequest {
                        namespace: "tgt2".into(),
                        operation_id: OP,
                        command_id: Uuid::from_u128(41),
                        expected_state: FenceState::TargetQuarantined,
                        expected_revision: 1,
                        command: FenceCommand::AbortQuarantinedTarget,
                    })
                    .await,
            );
            check(
                &server,
                &meta,
                "tgt2",
                &own_aborted,
                FenceState::TargetAborted,
            )
            .await;
            (own, own_target, own_aborted)
        });
        server.crash();

        // The rows are kept across a restart, and the in-memory config is the namespace's own.
        let (own, own_target, own_aborted) = owns;
        let server = Server::boot(dir.path());
        server.run(async {
            let meta = older_binary(dir.path()).await;
            check(&server, &meta, "ns", &own, FenceState::Released).await;
            check(
                &server,
                &meta,
                "tgt",
                &own_target,
                FenceState::TargetWritable,
            )
            .await;
            check(
                &server,
                &meta,
                "tgt2",
                &own_aborted,
                FenceState::TargetAborted,
            )
            .await;
        });
        server.crash();
    }
}
