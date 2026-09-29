//! The positive source write drain (`docs/NAMESPACE_FENCE.md` sections 8.3 and 8.4).
//!
//! `AcquireSourceWriteFence` closes write admission, persists `SOURCE_DRAINING`, and then waits
//! for the writer that was already holding the write slot when admission closed to commit or
//! roll back. It waits on the connection manager's release notification: neither elapsed time
//! nor the transaction timeout is ever taken as evidence that a writer has finished. Once no
//! connection holds the slot for a write, it reads the frozen boundary (`log_id`, last committed
//! frame) under the slot lock and persists `SOURCE_WRITE_FENCED` with it. Every step runs under
//! the namespace's transition lock, on a task of its own, so a caller that goes away does not
//! interrupt it.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use crate::namespace::meta_store::{FenceCommit, FenceContext, MetaStore};

use super::command::{DrainPolicy, FenceCommand, FenceRequest, OnDeadline};
use super::controller::{FenceController, LiveWriteDrain, Transition};
use super::hooks::HookPoint;
use super::outcome::FenceOutcome;
use super::record::FrozenBoundary;
use super::state::OperationClass;
use super::transition::DrainCompletion;

/// How long `AcquireSourceWriteFence` waits for active writers when neither the request nor
/// `--namespace-fence-default-write-drain-ms` names a deadline.
pub const DEFAULT_WRITE_DRAIN: Duration = Duration::from_secs(30);

/// After a forced rollback, how long the drain waits at least for the rolled-back writer to
/// release the slot before it answers `DRAINING` (the request's own deadline, if longer, is
/// used instead). A rollback normally releases at once; it is delayed only while a program is
/// still running on the connection. Reaching this bound is never taken as proof of anything:
/// the answer is `DRAINING` and admission stays closed.
pub const FORCED_ROLLBACK_GRACE: Duration = Duration::from_secs(10);

impl FenceController {
    /// Run one fence command to completion under the namespace's transition lock, including
    /// the drain it starts, and return its result.
    ///
    /// The command runs on its own task: a caller that goes away (a lost response) interrupts
    /// neither the commit nor the drain, and the result can be recovered by replaying the same
    /// command or inspecting the fence.
    pub async fn execute(
        self: &Arc<Self>,
        meta: &MetaStore,
        request: FenceRequest,
        ctx: FenceContext,
    ) -> crate::Result<FenceCommit> {
        let this = self.clone();
        let meta = meta.clone();
        tokio::spawn(async move {
            let mut transition = this.begin_transition().await;
            match request.command {
                FenceCommand::AcquireSourceWriteFence { .. } => {
                    acquire_source_write_fence(&mut transition, &meta, request, ctx).await
                }
                _ => transition.apply(&meta, request, ctx).await,
            }
        })
        .await?
    }
}

/// `AcquireSourceWriteFence`, steps 1 to 7 of section 8.3, under `transition`.
///
/// Returns the `APPLIED` commit of `SOURCE_WRITE_FENCED` once the drain is proven, the
/// `DRAINING` commit of `SOURCE_DRAINING` when the deadline passes first (write admission stays
/// closed and a replay of the same command resumes the drain), or the stored result of a replay.
pub async fn acquire_source_write_fence(
    transition: &mut Transition,
    meta: &MetaStore,
    request: FenceRequest,
    mut ctx: FenceContext,
) -> crate::Result<FenceCommit> {
    let controller = transition.controller().clone();
    let key = (request.operation_id, request.command_id);
    let policy = match &request.command {
        FenceCommand::AcquireSourceWriteFence { drain_policy, .. } => {
            drain_policy.unwrap_or_else(|| meta.fence_default_write_drain())
        }
        _ => return transition.apply(meta, request, ctx).await,
    };

    // Step 1 is the metastore's (replay, owner, identity, shared schema, expectation). The
    // identity it checks is the namespace's own replication log id.
    if let Some(source) = controller.live_write_drains().last() {
        ctx.namespace_log_id = Some(source.log_id);
    }

    // Steps 2 and 3: close write admission in memory. Publishing moves the write generation and
    // wakes the write queues, whose waiters then fail with MIGRATION_WRITE_FENCED. Where writes
    // are already closed (a resumed drain, an indeterminate commit being reconciled, a fenced
    // namespace) there is nothing to install.
    if controller.permits(OperationClass::NormalWrite).is_ok() {
        transition.install_closing_gate(key);
        let _ = controller.hook(HookPoint::AfterInstallingGate).await;
    }

    // Step 4: persist SOURCE_DRAINING. The commit publishes it in place of the INSTALLING gate. A
    // command proven not to have committed removes the INSTALLING gate again; one whose commit
    // is unknown has already closed the gate as indeterminate.
    let commit = match transition.apply(meta, request, ctx.clone()).await {
        Ok(commit) => commit,
        Err(e) => {
            transition.remove_installing();
            return Err(e);
        }
    };
    if commit.receipt.outcome != FenceOutcome::Draining {
        // A replay of a finished acquisition, or ALREADY_APPLIED.
        return Ok(commit);
    }
    let drain_key = (commit.receipt.operation_id, commit.receipt.command_id);

    // Steps 5 and 6.
    let boundary = match drain_writers(&controller, policy).await {
        Some(boundary) => boundary,
        None => return Ok(commit),
    };

    // Step 7.
    ctx.now_ms = now_ms();
    transition
        .complete_drain(
            meta,
            drain_key,
            DrainCompletion::SourceWrites { boundary },
            ctx,
        )
        .await
}

/// Wait until no connection manager of the namespace has a writer holding its write slot, and
/// read the frozen boundary. `None` when the drain could not be proven within the policy: the
/// deadline passed (after a forced rollback, the same deadline again, or at least
/// [`FORCED_ROLLBACK_GRACE`]), or the namespace has no
/// loaded primary whose replication log could be read.
async fn drain_writers(
    controller: &FenceController,
    policy: DrainPolicy,
) -> Option<FrozenBoundary> {
    let namespace = controller.namespace().clone();
    let deadline_after = Duration::from_millis(policy.deadline_ms);
    let mut deadline = Instant::now() + deadline_after;
    let mut forced = false;
    loop {
        // Every manager registered from now on belongs to a maker opened after write admission
        // closed, so it has no pre-cutoff writer; sources are re-read on each round anyway.
        let sources = controller.live_write_drains();
        if sources.is_empty() {
            tracing::warn!(
                %namespace,
                "the namespace has no loaded primary; the write drain cannot read its replication \
                 log and stays DRAINING until the command is replayed"
            );
            return None;
        }

        if !wait_for_writers(&sources, deadline).await {
            match policy.on_deadline {
                OnDeadline::ForceRollback if !forced => {
                    forced = true;
                    for source in &sources {
                        let manager = source.manager.clone();
                        // The rollback takes the connection's lock, which a running program
                        // holds; it releases the slot when it happens, and that release is what
                        // the drain keeps waiting for.
                        tokio::task::spawn_blocking(move || {
                            if let Some(id) = manager.abort_active() {
                                tracing::info!(
                                    connection = id,
                                    "write drain deadline passed; rolling back the active writer"
                                );
                            }
                        });
                    }
                    deadline = Instant::now() + deadline_after.max(FORCED_ROLLBACK_GRACE);
                    continue;
                }
                _ => {
                    tracing::info!(
                        %namespace,
                        deadline_ms = policy.deadline_ms,
                        on_deadline = policy.on_deadline.as_str(),
                        forced,
                        "write drain deadline passed with a writer still active; answering DRAINING"
                    );
                    return None;
                }
            }
        }

        let _ = controller.hook(HookPoint::BeforeBoundaryCapture).await;
        match capture_boundary(&sources) {
            Ok(boundary) => {
                tracing::info!(
                    %namespace,
                    log_id = %boundary.log_id,
                    frame_no = ?boundary.frame_no,
                    "write drain proven"
                );
                return Some(boundary);
            }
            // Cannot happen while write admission is closed; wait again rather than guess.
            Err((id, class)) => {
                tracing::warn!(
                    %namespace,
                    connection = id,
                    ?class,
                    "a writer holds the write slot at boundary capture; waiting again"
                );
            }
        }
    }
}

/// Wait, on each manager's release notification, until none of them has a connection holding
/// the write slot for a write. `false` when `deadline` passes first.
///
/// With write admission closed a manager that has been seen without a writer stays without one
/// (only checkpoints can take the slot), so the managers are waited for one after the other.
async fn wait_for_writers(sources: &[LiveWriteDrain], deadline: Instant) -> bool {
    for source in sources {
        loop {
            let released = source.manager.released().notified();
            tokio::pin!(released);
            // Registered before the check, so a release in between is not missed.
            released.as_mut().enable();
            if !source.manager.has_writer() {
                break;
            }
            tokio::select! {
                _ = &mut released => {}
                _ = tokio::time::sleep_until(deadline) => return false,
            }
        }
    }
    true
}

/// Step 6: under each manager's write-slot lock, observe that no connection holds the slot for a
/// write, and read the last committed frame of the replication log. The replication logger
/// commits a transaction's frames and publishes its frame number before the transaction
/// releases the slot, so what is read here is final.
fn capture_boundary(
    sources: &[LiveWriteDrain],
) -> Result<
    FrozenBoundary,
    (
        crate::connection::connection_manager::ConnId,
        OperationClass,
    ),
> {
    let mut frame_no = None;
    for source in sources {
        let frame = source
            .manager
            .with_no_writer(|| (source.current_frame_no)())?;
        frame_no = frame_no.max(frame);
    }
    let log_id = sources
        .last()
        .expect("capture_boundary is called with at least one source")
        .log_id;
    Ok(FrozenBoundary { log_id, frame_no })
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use rusqlite::ErrorCode;
    use tempfile::{tempdir, TempDir};
    use uuid::Uuid;

    use super::*;
    use crate::connection::config::DatabaseConfig;
    use crate::connection::Connection as _;
    use crate::database::{Connection, Database};
    use crate::error::Error;
    use crate::namespace::fence::hooks::HookPoint;
    use crate::namespace::fence::record::ServerIdentity;
    use crate::namespace::fence::state::FenceState;
    use crate::namespace::meta_store::FenceCommitKind;
    use crate::namespace::store::fence_tests::open_store;
    use crate::namespace::store::NamespaceStore;
    use crate::namespace::RestoreOption;
    use crate::replication::primary::logger::ReplicationLogger;

    const OP: Uuid = Uuid::from_u128(0xa);
    const OTHER_OP: Uuid = Uuid::from_u128(0xb);
    /// Long enough that no test ever reaches it: a drain must never finish because of time.
    const LONG: DrainPolicy = DrainPolicy {
        deadline_ms: 600_000,
        on_deadline: OnDeadline::Fail,
    };
    const PROMPT: Duration = Duration::from_secs(30);

    /// A primary namespace `ns` with a table `t`, served by a real `NamespaceStore`, so that the
    /// drain goes through the connection manager and replication logger the configurator
    /// registered.
    struct Source {
        _dir: TempDir,
        store: NamespaceStore,
        fence: Arc<FenceController>,
        logger: Arc<ReplicationLogger>,
    }

    impl Source {
        async fn new() -> Self {
            let dir = tempdir().unwrap();
            let store = open_store(dir.path()).await;
            store
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
            let (fence, logger) = store
                .with("ns".into(), |ns| {
                    let logger = match &ns.db {
                        Database::Primary(p) => p.wal_wrapper.wrapper().logger(),
                        _ => unreachable!(),
                    };
                    (ns.fence().clone(), logger)
                })
                .await
                .unwrap();
            let this = Self {
                _dir: dir,
                store,
                fence,
                logger,
            };
            let conn = this.conn().await;
            raw(&conn, "create table t (x)").await.unwrap();
            this
        }

        async fn conn(&self) -> Arc<Connection> {
            let maker = self
                .store
                .with("ns".into(), |ns| ns.db.connection_maker())
                .await
                .unwrap();
            Arc::new(maker.create().await.unwrap())
        }

        fn log_id(&self) -> Uuid {
            self.logger.log_id()
        }

        /// The last frame the replication log has committed.
        fn frame_no(&self) -> Option<u64> {
            *self.logger.new_frame_notifier.borrow()
        }

        fn acquire(&self, op: Uuid, command_id: u128, policy: DrainPolicy) -> FenceRequest {
            FenceRequest {
                namespace: "ns".into(),
                operation_id: op,
                command_id: Uuid::from_u128(command_id),
                expected_state: FenceState::Unfenced,
                expected_revision: 0,
                command: FenceCommand::AcquireSourceWriteFence {
                    expected_log_id: self.log_id(),
                    drain_policy: Some(policy),
                },
            }
        }

        /// Run `request` through the store, on a task of its own.
        fn execute(
            &self,
            request: FenceRequest,
        ) -> tokio::task::JoinHandle<crate::Result<FenceCommit>> {
            let store = self.store.clone();
            tokio::spawn(async move {
                store
                    .execute_fence_command(
                        request,
                        ServerIdentity {
                            build: "test".into(),
                            instance_id: Uuid::from_u128(0x99),
                        },
                    )
                    .await
            })
        }

        /// Wait until the published gate is in `state`.
        async fn until_state(&self, state: FenceState) {
            let mut rx = self.fence.subscribe();
            tokio::time::timeout(PROMPT, rx.wait_for(|g| g.state() == state))
                .await
                .expect("the gate never reached the state")
                .unwrap();
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
    }

    /// Run `sql` as one raw program on `conn`, off the async runtime (it can block on the write
    /// slot).
    async fn raw(conn: &Arc<Connection>, sql: &'static str) -> rusqlite::Result<()> {
        let conn = conn.clone();
        tokio::task::spawn_blocking(move || conn.with_raw(|c| c.execute_batch(sql)))
            .await
            .unwrap()
    }

    fn assert_fenced(result: rusqlite::Result<()>) {
        match result {
            Err(rusqlite::Error::SqliteFailure(e, _)) => {
                assert_eq!(e.code, ErrorCode::AuthorizationForStatementDenied, "{e}")
            }
            other => panic!("expected the WAL gate to refuse the write, got {other:?}"),
        }
    }

    fn fence_outcome(result: &crate::Result<FenceCommit>) -> FenceOutcome {
        match result {
            Ok(c) => c.receipt.outcome,
            Err(Error::NamespaceFence(e)) => e.outcome(),
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    fn boundary(commit: &FenceCommit) -> FrozenBoundary {
        commit
            .record
            .as_ref()
            .unwrap()
            .frozen_boundary
            .expect("a write-fenced source has a frozen boundary")
    }

    /// Two operations acquire the same namespace at once: exactly one owns it, and the other
    /// gets the typed ownership conflict. The first is parked after closing write admission so
    /// that the second is certainly waiting on the transition lock.
    #[tokio::test(flavor = "multi_thread")]
    async fn acquire_race_single_owner() {
        let s = Source::new().await;
        let paused = s.fence.hooks().pause_at(HookPoint::AfterInstallingGate);
        let first = s.execute(s.acquire(OP, 1, LONG));
        paused.reached().await;
        let second = s.execute(s.acquire(OTHER_OP, 2, LONG));
        paused.resume();

        let first = first.await.unwrap();
        let second = second.await.unwrap();
        let outcomes = [fence_outcome(&first), fence_outcome(&second)];
        assert_eq!(
            outcomes,
            [
                FenceOutcome::Applied,
                FenceOutcome::FenceOwnedByAnotherOperation
            ]
        );
        let gate = s.fence.gate();
        assert_eq!(gate.state(), FenceState::SourceWriteFenced);
        assert_eq!(gate.operation_id(), Some(OP));
        assert!(!gate.is_installing());
    }

    /// A writer that holds the write slot when the fence arrives commits, and only then is the
    /// freeze acknowledged, with a boundary that includes its commit. Writes attempted while
    /// the drain waits are refused.
    #[tokio::test(flavor = "multi_thread")]
    async fn active_writer_commits_before_ack() {
        let s = Source::new().await;
        let holder = s.conn().await;
        raw(&holder, "begin immediate; insert into t values (1);")
            .await
            .unwrap();

        let acquire = s.execute(s.acquire(OP, 1, LONG));
        s.until_state(FenceState::SourceDraining).await;
        // Admission is closed while the pre-cutoff writer is still active.
        assert_fenced(raw(&s.conn().await, "insert into t values (2)").await);
        assert!(!acquire.is_finished());

        raw(&holder, "commit").await.unwrap();
        let committed_frame = s.frame_no();
        assert!(committed_frame.is_some());

        let commit = acquire.await.unwrap().unwrap();
        assert_eq!(commit.receipt.outcome, FenceOutcome::Applied);
        assert_eq!(commit.receipt.state_after, FenceState::SourceWriteFenced);
        assert_eq!(
            boundary(&commit),
            FrozenBoundary {
                log_id: s.log_id(),
                frame_no: committed_frame,
            }
        );
        assert_eq!(s.count().await, 1);
    }

    /// Under `force_rollback`, a writer still active at the deadline is rolled back, and the
    /// freeze is acknowledged only after its slot was actually released; its write is not in
    /// the database or the boundary.
    #[tokio::test(flavor = "multi_thread")]
    async fn forced_rollback_before_ack() {
        let s = Source::new().await;
        let before = s.frame_no();
        let holder = s.conn().await;
        raw(&holder, "begin immediate; insert into t values (1);")
            .await
            .unwrap();

        let commit = s
            .execute(s.acquire(
                OP,
                1,
                DrainPolicy {
                    deadline_ms: 0,
                    on_deadline: OnDeadline::ForceRollback,
                },
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(commit.receipt.outcome, FenceOutcome::Applied);
        assert_eq!(
            boundary(&commit),
            FrozenBoundary {
                log_id: s.log_id(),
                frame_no: before,
            }
        );
        assert_eq!(s.frame_no(), before);
        assert_eq!(s.count().await, 0);
        // The rolled-back transaction is gone; its connection cannot write either.
        assert!(raw(&holder, "commit").await.is_err());
        assert_fenced(raw(&holder, "insert into t values (3)").await);
        assert_eq!(s.frame_no(), before);
    }

    /// After the acknowledgement nothing commits: the boundary is the last committed frame, and
    /// autocommit writes, explicit transactions, DDL and a read transaction opened before the
    /// fence that tries to upgrade are all refused without adding a frame.
    #[tokio::test(flavor = "multi_thread")]
    async fn no_commit_after_ack() {
        let s = Source::new().await;
        let writer = s.conn().await;
        for _ in 0..3 {
            raw(&writer, "insert into t values (1)").await.unwrap();
        }
        let last = s.frame_no();
        // A reader whose transaction predates the fence.
        let reader = s.conn().await;
        raw(&reader, "begin; select count(*) from t;")
            .await
            .unwrap();

        let commit = s.execute(s.acquire(OP, 1, LONG)).await.unwrap().unwrap();
        assert_eq!(commit.receipt.outcome, FenceOutcome::Applied);
        assert_eq!(
            boundary(&commit),
            FrozenBoundary {
                log_id: s.log_id(),
                frame_no: last,
            }
        );

        assert_fenced(raw(&writer, "insert into t values (2)").await);
        assert_fenced(raw(&writer, "begin immediate").await);
        assert_fenced(raw(&writer, "create table u (y)").await);
        assert_fenced(raw(&reader, "insert into t values (2)").await);
        assert_fenced(raw(&s.conn().await, "insert into t values (2)").await);
        assert_eq!(s.frame_no(), last);
        assert_eq!(s.count().await, 3);
        assert_eq!(boundary(&commit).frame_no, s.frame_no());
    }

    /// With `on_deadline: fail`, a writer still active at the deadline makes the command answer
    /// `DRAINING`: the durable state is `SOURCE_DRAINING` and write admission stays closed.
    #[tokio::test(flavor = "multi_thread")]
    async fn deadline_returns_draining_and_stays_closed() {
        let s = Source::new().await;
        let holder = s.conn().await;
        raw(&holder, "begin immediate; insert into t values (1);")
            .await
            .unwrap();

        let policy = DrainPolicy {
            deadline_ms: 0,
            on_deadline: OnDeadline::Fail,
        };
        let commit = s.execute(s.acquire(OP, 1, policy)).await.unwrap().unwrap();
        assert_eq!(commit.kind, FenceCommitKind::Committed);
        assert_eq!(commit.receipt.outcome, FenceOutcome::Draining);
        assert_eq!(s.fence.gate().state(), FenceState::SourceDraining);
        let inspected = s
            .store
            .meta_store()
            .inspect_fence("ns".into())
            .await
            .unwrap();
        assert_eq!(inspected.fence.state(), FenceState::SourceDraining);
        assert_fenced(raw(&s.conn().await, "insert into t values (2)").await);
        // Nothing reopens by itself; the writer that was active before the fence is still the
        // only one that can commit.
        raw(&holder, "commit").await.unwrap();
        assert_fenced(raw(&holder, "insert into t values (3)").await);
        assert_eq!(s.fence.gate().state(), FenceState::SourceDraining);
        assert_eq!(s.count().await, 1);
    }

    /// Replaying a command whose receipt is `DRAINING` resumes the same drain: it completes once
    /// the writer has finished, and a further replay returns that stored result.
    #[tokio::test(flavor = "multi_thread")]
    async fn replay_of_draining_resumes_and_completes() {
        let s = Source::new().await;
        let holder = s.conn().await;
        raw(&holder, "begin immediate; insert into t values (1);")
            .await
            .unwrap();
        let policy = DrainPolicy {
            deadline_ms: 0,
            on_deadline: OnDeadline::Fail,
        };
        let first = s.execute(s.acquire(OP, 1, policy)).await.unwrap().unwrap();
        assert_eq!(first.receipt.outcome, FenceOutcome::Draining);
        let draining_revision = s.fence.gate().revision();

        // Replayed while the writer is still active: the same drain resumes, writes nothing and,
        // with the same zero deadline, answers DRAINING again.
        let replay = s.execute(s.acquire(OP, 1, policy)).await.unwrap().unwrap();
        assert_eq!(replay.kind, FenceCommitKind::Resumed);
        assert_eq!(replay.receipt.outcome, FenceOutcome::Draining);
        assert_eq!(s.fence.gate().revision(), draining_revision);

        raw(&holder, "commit").await.unwrap();
        let committed = s.frame_no();
        let done = s.execute(s.acquire(OP, 1, policy)).await.unwrap().unwrap();
        assert_eq!(done.receipt.outcome, FenceOutcome::Applied);
        assert_eq!(done.receipt.command_id, Uuid::from_u128(1));
        assert_eq!(
            boundary(&done),
            FrozenBoundary {
                log_id: s.log_id(),
                frame_no: committed,
            }
        );
        assert_eq!(s.fence.gate().state(), FenceState::SourceWriteFenced);
        assert_eq!(s.fence.gate().revision(), draining_revision + 1);

        let again = s.execute(s.acquire(OP, 1, policy)).await.unwrap().unwrap();
        assert_eq!(again.kind, FenceCommitKind::Replayed);
        assert_eq!(again.receipt, done.receipt);
        assert_eq!(boundary(&again), boundary(&done));
    }

    /// Releasing the write fence commits, publishes a new write generation and only then
    /// answers: new programs write again, and a transaction that began under the fence cannot.
    #[tokio::test(flavor = "multi_thread")]
    async fn release_reopens_with_new_generation() {
        let s = Source::new().await;
        s.execute(s.acquire(OP, 1, LONG)).await.unwrap().unwrap();
        let fenced = s.fence.gate();
        let reader = s.conn().await;
        raw(&reader, "begin; select count(*) from t;")
            .await
            .unwrap();

        let release = FenceRequest {
            namespace: "ns".into(),
            operation_id: OP,
            command_id: Uuid::from_u128(2),
            expected_state: FenceState::SourceWriteFenced,
            expected_revision: fenced.revision(),
            command: FenceCommand::ReleaseSourceWriteFence,
        };
        let paused = s.fence.hooks().pause_at(HookPoint::BeforeResponse);
        let released = s.execute(release);
        paused.reached().await;
        // Published before the response is sent.
        let gate = s.fence.gate();
        assert_eq!(gate.state(), FenceState::Released);
        assert!(gate.write_generation > fenced.write_generation);
        assert!(!released.is_finished());
        paused.resume();
        let commit = released.await.unwrap().unwrap();
        assert_eq!(commit.receipt.outcome, FenceOutcome::Applied);

        raw(&s.conn().await, "insert into t values (1)")
            .await
            .unwrap();
        assert_fenced(raw(&reader, "insert into t values (2)").await);
        raw(&reader, "rollback").await.unwrap();
        raw(&reader, "insert into t values (3)").await.unwrap();
        assert_eq!(s.count().await, 2);
    }

    /// An acquisition refused by the metastore (here: the caller observed a different
    /// replication log) removes the INSTALLING gate it had published; writes are admitted again
    /// under a new generation.
    #[tokio::test(flavor = "multi_thread")]
    async fn refused_acquire_reopens_writes() {
        let s = Source::new().await;
        let before = s.fence.gate().write_generation;
        let mut request = s.acquire(OP, 1, LONG);
        request.command = FenceCommand::AcquireSourceWriteFence {
            expected_log_id: Uuid::from_u128(0x77),
            drain_policy: Some(LONG),
        };
        let result = s.execute(request).await.unwrap();
        assert_eq!(
            fence_outcome(&result),
            FenceOutcome::FencePreconditionFailed
        );
        let gate = s.fence.gate();
        assert_eq!(gate.state(), FenceState::Unfenced);
        assert!(!gate.is_installing());
        assert_eq!(gate.write_generation, before + 2);
        raw(&s.conn().await, "insert into t values (1)")
            .await
            .unwrap();
    }

    /// While the INSTALLING gate is up, before anything is persisted, writes are already
    /// refused and reads are served.
    #[tokio::test(flavor = "multi_thread")]
    async fn installing_gate_closes_writes_before_persisting() {
        let s = Source::new().await;
        let paused = s.fence.hooks().pause_at(HookPoint::AfterInstallingGate);
        let acquire = s.execute(s.acquire(OP, 1, LONG));
        paused.reached().await;
        let gate = s.fence.gate();
        assert!(gate.is_installing());
        assert_eq!(gate.state(), FenceState::Unfenced);
        let inspected = s
            .store
            .meta_store()
            .inspect_fence("ns".into())
            .await
            .unwrap();
        assert_eq!(inspected.fence.state(), FenceState::Unfenced);
        assert_fenced(raw(&s.conn().await, "insert into t values (1)").await);
        assert_eq!(s.count().await, 0);
        paused.resume();
        let commit = acquire.await.unwrap().unwrap();
        assert_eq!(commit.receipt.outcome, FenceOutcome::Applied);
        assert!(!s.fence.gate().is_installing());
    }
}
