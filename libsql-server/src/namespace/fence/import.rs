//! Import sessions into quarantined migration targets, and the seal that ends them
//! (`docs/NAMESPACE_FENCE.md` sections 10.2 and 11).
//!
//! An [`ImportSession`] is the only way to write into a `TARGET_QUARANTINED` target. It holds a
//! [`MigrationCapability`] issued to the operation that owns the target and a connection whose
//! fence state carries that capability, so the WAL admits its write transactions as
//! `CapabilityImport` for as long as the capability is valid, and refuses every other
//! connection's. Each call into the session counts as an import writer until it returns.
//!
//! `SealTargetImport` ends import for good. It closes import admission in memory, persists
//! `TARGET_IMPORT_DRAINING` (the revision moves, so every issued import capability is
//! invalidated and no new one can be issued), then waits for the running import calls and for
//! any import transaction still holding the write slot to end, and persists
//! `TARGET_VALIDATING`. Like the source write drain, it waits on release notifications and
//! never takes elapsed time as evidence that a writer has finished.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::Stream;
use tokio::time::Instant;

use crate::connection::legacy::LegacyConnection;
use crate::connection::Connection as _;
use crate::error::Error;
use crate::namespace::configurator::{load_dump_sql, read_dump};
use crate::namespace::meta_store::{FenceCommit, FenceCommitKind, FenceContext, MetaStore};
use crate::namespace::replication_wal::ReplicationWalWrapper;

use super::audit::{CommandReport, DrainKind, ForcedKind};
use super::capability::MigrationCapability;
use super::command::{DrainPolicy, FenceCommand, FenceRequest, OnDeadline};
use super::controller::{FenceController, LiveWriteDrain, Transition};
use super::drain::{now_ms, wait_for_writers, FORCED_ROLLBACK_GRACE};
use super::hooks::HookPoint;
use super::outcome::{FenceError, FenceOutcome};
use super::state::FenceState;
use super::transition::DrainCompletion;

/// An operation's write access to its quarantined target (section 11): a capability and a
/// connection that works under it. Dropping the session revokes the capability and closes the
/// connection, which rolls back a transaction the session left open.
pub struct ImportSession {
    capability: MigrationCapability,
    controller: Arc<FenceController>,
    conn: LegacyConnection<ReplicationWalWrapper>,
}

impl std::fmt::Debug for ImportSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportSession")
            .field("capability", &self.capability)
            .finish_non_exhaustive()
    }
}

impl ImportSession {
    pub(crate) fn new(
        capability: MigrationCapability,
        controller: Arc<FenceController>,
        conn: LegacyConnection<ReplicationWalWrapper>,
    ) -> Self {
        Self {
            capability,
            controller,
            conn,
        }
    }

    pub fn capability(&self) -> &MigrationCapability {
        &self.capability
    }

    /// Run `f` with the session's raw connection. The call is refused up front when the
    /// capability is no longer valid (the target was sealed or aborted, or its fence moved on),
    /// and counts as an import writer until `f` returns, so a seal waits for it. Inside `f` the
    /// WAL admits a write transaction only while the capability is still valid: a write that
    /// the fence refused there is reported as that refusal, whatever `f` made of the
    /// `SQLITE_AUTH` it saw.
    pub async fn with_raw<R: Send + 'static>(
        &mut self,
        f: impl FnOnce(&mut rusqlite::Connection) -> R + Send + 'static,
    ) -> Result<R, FenceError> {
        let writer = self.controller.begin_import_write(&self.capability)?;
        let conn = self.conn.clone();
        let joined = tokio::task::spawn_blocking(move || {
            let _writer = writer;
            let result = conn.with_raw(f);
            (result, conn.fence_state().take_denial())
        })
        .await;
        match joined {
            Ok((_, Some(denial))) => Err(denial),
            Ok((result, None)) => Ok(result),
            Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            Err(e) => Err(FenceError::new(
                FenceOutcome::OperationCapabilityRequired,
                format!("the import call did not complete: {e}"),
            )),
        }
    }

    /// Load a SQL dump into the target with the server's dump loader, under the capability.
    /// The dump must run in one transaction that it commits itself, as for a namespace
    /// created from a dump. Fence refusals are [`Error::NamespaceFence`]; dump errors are
    /// [`Error::LoadDumpError`].
    pub async fn load_dump<S>(&mut self, dump: S) -> crate::Result<()>
    where
        S: Stream<Item = std::io::Result<Bytes>> + Unpin,
    {
        let content = read_dump(dump).await?;
        self.with_raw(move |conn| load_dump_sql(&content, conn))
            .await??;
        Ok(())
    }
}

impl Drop for ImportSession {
    fn drop(&mut self) {
        self.controller.revoke_capability(self.capability.id());
    }
}

/// `SealTargetImport` (section 10.2), under `transition`.
///
/// Returns the `APPLIED` commit of `TARGET_VALIDATING` once no import call is running and no
/// import transaction holds the write slot, the `DRAINING` commit of `TARGET_IMPORT_DRAINING`
/// when the deadline passes first (import stays closed, and only a replay of the same command
/// resumes the drain), or the stored result of a replay.
pub async fn seal_target_import(
    transition: &mut Transition,
    meta: &MetaStore,
    request: FenceRequest,
    mut ctx: FenceContext,
) -> crate::Result<FenceCommit> {
    let controller = transition.controller().clone();
    let key = (request.operation_id, request.command_id);
    let policy = match &request.command {
        FenceCommand::SealTargetImport { drain_policy } => {
            drain_policy.unwrap_or_else(|| meta.fence_default_write_drain())
        }
        _ => return transition.apply(meta, request, ctx).await,
    };

    // Close import admission in memory before persisting: the INSTALLING gate refuses new
    // import calls and import write transactions, and moving the write generation makes every
    // transaction opened before it stale and wakes the queued import writers. Only for a seal
    // that can apply (the owner, at the current revision, of a quarantined target), so that a
    // refused command does not disturb a running import.
    let gate = controller.gate();
    let can_apply = gate.state() == FenceState::TargetQuarantined
        && gate.indeterminate.is_none()
        && !gate.is_installing()
        && gate.operation_id() == Some(request.operation_id)
        && gate.revision() == request.expected_revision;
    if can_apply {
        transition.install_closing_gate(key);
        let _ = controller.hook(HookPoint::AfterInstallingGate).await;
    }

    // Persist TARGET_IMPORT_DRAINING. Its publication replaces the INSTALLING gate and, the
    // revision having moved, drops every issued import capability.
    let commit = match transition.apply(meta, request, ctx.clone()).await {
        Ok(commit) => commit,
        Err(e) => {
            transition.remove_installing();
            return Err(e);
        }
    };
    if commit.kind == FenceCommitKind::Replayed || commit.receipt.outcome != FenceOutcome::Draining
    {
        return Ok(commit);
    }
    let resumed = commit.kind == FenceCommitKind::Resumed;
    let drain_key = (commit.receipt.operation_id, commit.receipt.command_id);

    let started = Instant::now();
    if !drain_import_writers(&controller, policy, &mut transition.report).await {
        return Ok(commit);
    }

    transition
        .report
        .drained(DrainKind::Import, started.elapsed());
    ctx.now_ms = now_ms();
    let mut completed = transition
        .complete_drain(meta, drain_key, DrainCompletion::TargetImport, ctx)
        .await?;
    if resumed {
        completed.kind = FenceCommitKind::Resumed;
    }
    Ok(completed)
}

/// Wait until no import call is running and no connection manager of the target has a writer
/// holding its write slot. At the deadline, `force_rollback` rolls back the import transactions
/// still holding the slot (an idle session's open transaction; a running call ends its own)
/// and waits again for the same deadline, but at least [`FORCED_ROLLBACK_GRACE`]. `false` when
/// the drain could not be proven within the policy.
async fn drain_import_writers(
    controller: &FenceController,
    policy: DrainPolicy,
    report: &mut CommandReport,
) -> bool {
    let namespace = controller.namespace().clone();
    let deadline_after = Duration::from_millis(policy.deadline_ms);
    let mut deadline = Instant::now() + deadline_after;
    let mut forced = false;
    loop {
        if wait_for_import_writers(controller, deadline).await {
            // With import closed, a manager seen without a writer under its slot lock stays
            // without one. A target with no loaded maker has no connection that could write.
            let sources = controller.live_write_drains();
            if sources_have_no_writer(&sources) {
                tracing::info!(%namespace, "import drain proven");
                return true;
            }
            continue;
        }
        match policy.on_deadline {
            OnDeadline::ForceRollback if !forced => {
                forced = true;
                let sources = controller.live_write_drains();
                report.forced(
                    ForcedKind::Rollback,
                    sources.iter().filter(|s| s.manager.has_writer()).count(),
                );
                for source in sources {
                    let manager = source.manager.clone();
                    // The rollback takes the connection's lock, which a running import call
                    // holds; the release it causes is what the drain keeps waiting for.
                    tokio::task::spawn_blocking(move || {
                        if let Some(id) = manager.abort_active() {
                            tracing::info!(
                                connection = id,
                                "import drain deadline passed; rolling back the active import \
                                 transaction"
                            );
                        }
                    });
                }
                deadline = Instant::now() + deadline_after.max(FORCED_ROLLBACK_GRACE);
            }
            _ => {
                tracing::info!(
                    %namespace,
                    deadline_ms = policy.deadline_ms,
                    on_deadline = policy.on_deadline.as_str(),
                    forced,
                    import_writers = controller.import_writers(),
                    "import drain deadline passed with an import writer still active; \
                     answering DRAINING"
                );
                return false;
            }
        }
    }
}

/// Wait for the running import calls to end, then for every manager's write slot to be free of
/// writers. `false` when `deadline` passes first.
async fn wait_for_import_writers(controller: &FenceController, deadline: Instant) -> bool {
    loop {
        let released = controller.import_released().notified();
        tokio::pin!(released);
        // Registered before the check, so an end in between is not missed.
        released.as_mut().enable();
        if controller.import_writers() == 0 {
            break;
        }
        tokio::select! {
            _ = &mut released => {}
            _ = tokio::time::sleep_until(deadline) => return false,
        }
    }
    wait_for_writers(&controller.live_write_drains(), deadline).await
}

fn sources_have_no_writer(sources: &[LiveWriteDrain]) -> bool {
    sources
        .iter()
        .all(|source| source.manager.with_no_writer(|| ()).is_ok())
}

/// A refusal of `open_import_session` for a namespace that is not a primary.
pub(crate) fn not_importable(namespace: &crate::namespace::NamespaceName) -> Error {
    FenceError::new(
        FenceOutcome::FencePreconditionFailed,
        format!("namespace `{namespace}` is not a primary database; it cannot be imported into"),
    )
    .with_detail(super::outcome::FenceDetail::NotPrimary)
    .into()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tempfile::{tempdir, TempDir};
    use uuid::Uuid;

    use super::*;
    use crate::database::Connection;
    use crate::namespace::fence::capability::CapabilityPurpose;
    use crate::namespace::fence::drain::tests::{assert_fenced, raw, LONG, PROMPT};
    use crate::namespace::fence::state::OperationClass;
    use crate::namespace::fence::target::tests::{create, create_request, server, OP};
    use crate::namespace::meta_store::FenceCommitKind;
    use crate::namespace::store::fence_tests::open_store;
    use crate::namespace::store::NamespaceStore;
    use crate::namespace::{NamespaceName, RestoreOption};

    const OTHER_OP: Uuid = Uuid::from_u128(0xb);
    /// A deadline that has already passed.
    const NOW: DrainPolicy = DrainPolicy {
        deadline_ms: 0,
        on_deadline: OnDeadline::Fail,
    };

    fn tgt() -> NamespaceName {
        "tgt".into()
    }

    /// A store holding the quarantined target `tgt` (revision 1), and its controller.
    async fn target() -> (TempDir, NamespaceStore, Arc<FenceController>) {
        let dir = tempdir().unwrap();
        let store = open_store(dir.path()).await;
        create(&store, create_request("tgt", 1))
            .await
            .unwrap()
            .unwrap();
        let fence = store.with(tgt(), |ns| ns.fence().clone()).await.unwrap();
        assert_eq!(fence.gate().state(), FenceState::TargetQuarantined);
        (dir, store, fence)
    }

    fn seal_request(command_id: u128, expected_revision: u64, policy: DrainPolicy) -> FenceRequest {
        FenceRequest {
            namespace: tgt(),
            operation_id: OP,
            command_id: Uuid::from_u128(command_id),
            expected_state: FenceState::TargetQuarantined,
            expected_revision,
            command: FenceCommand::SealTargetImport {
                drain_policy: Some(policy),
            },
        }
    }

    /// Run `request` through the store, on a task of its own.
    fn execute(
        store: &NamespaceStore,
        request: FenceRequest,
    ) -> tokio::task::JoinHandle<crate::Result<FenceCommit>> {
        let store = store.clone();
        tokio::spawn(async move { store.execute_fence_command(request, server()).await })
    }

    async fn until_state(fence: &FenceController, state: FenceState) {
        let mut gate = fence.subscribe();
        tokio::time::timeout(PROMPT, gate.wait_for(|g| g.state() == state))
            .await
            .expect("the fence reaches the state")
            .unwrap();
    }

    /// A normal connection to the target (what the admin shell, a SQL request or a dump load
    /// outside a capability would use).
    async fn plain_conn(store: &NamespaceStore) -> Arc<Connection> {
        let maker = store
            .with(tgt(), |ns| ns.db.connection_maker())
            .await
            .unwrap();
        Arc::new(maker.create().await.unwrap())
    }

    /// Rows in `t` on the target, read through a raw connection.
    async fn count(store: &NamespaceStore) -> i64 {
        let conn = plain_conn(store).await;
        tokio::task::spawn_blocking(move || {
            conn.with_raw(|c| c.query_row("select count(*) from t", (), |r| r.get(0)))
        })
        .await
        .unwrap()
        .unwrap()
    }

    fn fence_err<T: std::fmt::Debug>(r: crate::Result<T>) -> FenceError {
        match r {
            Err(Error::NamespaceFence(e)) => e,
            other => panic!("expected a fence error, got {other:?}"),
        }
    }

    /// Write through a connection that carries `capability`, and return the fence's refusal.
    async fn refused_with(store: &NamespaceStore, capability: MigrationCapability) -> FenceError {
        let conn = store
            .capability_connection(&tgt(), capability)
            .await
            .unwrap();
        let r = conn.with_raw(|c| c.execute_batch("insert into t values (99)"));
        assert_fenced(r);
        conn.fence_state()
            .take_denial()
            .expect("the WAL gate records its refusal")
    }

    /// Only the operation's own, server-issued capability at the current revision writes into
    /// a quarantined target: plain connections (as an admin shell would use), capabilities of
    /// another operation or revision, forged, revoked or validation capabilities are all
    /// refused at the WAL, and issuing one is refused for another operation or revision.
    #[tokio::test(flavor = "multi_thread")]
    async fn import_requires_matching_capability() {
        let (_dir, store, fence) = target().await;
        let mut session = store.open_import_session(tgt(), OP, 1).await.unwrap();
        let cap = session.capability().clone();
        assert_eq!(
            (
                cap.namespace(),
                cap.operation_id(),
                cap.purpose(),
                cap.fence_revision()
            ),
            (&tgt(), OP, CapabilityPurpose::Import, 1)
        );
        session
            .with_raw(|c| c.execute_batch("create table t (x); insert into t values (1)"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fence.import_writers(), 0);

        // A normal connection, with or without raw access.
        let conn = plain_conn(&store).await;
        assert_fenced(raw(&conn, "insert into t values (2)").await);

        // Issuing: another operation, a stale or future revision.
        let e = fence_err(store.open_import_session(tgt(), OTHER_OP, 1).await);
        assert_eq!(e.outcome(), FenceOutcome::FenceOwnedByAnotherOperation);
        for revision in [0, 2] {
            let e = fence_err(store.open_import_session(tgt(), OP, revision).await);
            assert_eq!(e.outcome(), FenceOutcome::FenceRevisionMismatch);
        }

        // At the WAL: capabilities the server never issued, of this operation at this revision,
        // of another operation, at another revision, or for validation.
        let forged =
            |op, purpose, revision| MigrationCapability::forged(tgt(), op, purpose, revision);
        let cases = [
            (
                forged(OP, CapabilityPurpose::Import, 1),
                FenceOutcome::OperationCapabilityRequired,
            ),
            (
                forged(OTHER_OP, CapabilityPurpose::Import, 1),
                FenceOutcome::FenceOwnedByAnotherOperation,
            ),
            (
                forged(OP, CapabilityPurpose::Import, 2),
                FenceOutcome::OperationCapabilityRequired,
            ),
            (
                forged(OP, CapabilityPurpose::Validate, 1),
                FenceOutcome::OperationCapabilityRequired,
            ),
        ];
        for (capability, outcome) in cases {
            let e = refused_with(&store, capability.clone()).await;
            assert_eq!(e.outcome(), outcome, "{capability:?}: {e}");
        }

        // A capability that was issued, once its session is gone.
        let other = store.open_import_session(tgt(), OP, 1).await.unwrap();
        let revoked = other.capability().clone();
        assert!(fence.capability_is_live(revoked.id()));
        drop(other);
        assert!(!fence.capability_is_live(revoked.id()));
        let e = refused_with(&store, revoked).await;
        assert_eq!(e.outcome(), FenceOutcome::OperationCapabilityRequired);

        // The live session still writes; nothing else did.
        session
            .with_raw(|c| c.execute_batch("insert into t values (3)"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(count(&store).await, 2);
    }

    /// The seal closes import at once and waits, on release notifications, for an import call
    /// that was already running: its write transaction, which held the slot before the seal,
    /// commits, and only then is `TARGET_VALIDATING` persisted.
    #[tokio::test(flavor = "multi_thread")]
    async fn seal_waits_for_import_writers() {
        let (_dir, store, fence) = target().await;
        let mut session = store.open_import_session(tgt(), OP, 1).await.unwrap();
        session
            .with_raw(|c| c.execute_batch("create table t (x)"))
            .await
            .unwrap()
            .unwrap();
        let mut idle = store.open_import_session(tgt(), OP, 1).await.unwrap();

        let (entered_tx, entered) = tokio::sync::oneshot::channel();
        let (resume, resume_rx) = std::sync::mpsc::channel::<()>();
        let committed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let running = tokio::spawn({
            let committed = committed.clone();
            async move {
                let r = session
                    .with_raw(move |c| {
                        c.execute_batch("begin immediate; insert into t values (1)")?;
                        entered_tx.send(()).unwrap();
                        resume_rx.recv().unwrap();
                        c.execute_batch("commit")?;
                        committed.store(true, std::sync::atomic::Ordering::SeqCst);
                        Ok::<_, rusqlite::Error>(())
                    })
                    .await;
                (session, r)
            }
        });
        entered.await.unwrap();
        assert_eq!(fence.import_writers(), 1);

        let sealing = execute(&store, seal_request(10, 1, LONG));
        until_state(&fence, FenceState::TargetImportDraining).await;
        assert_eq!(fence.gate().revision(), 2);

        // Import is closed for good: no new capability, and no new call on a live session.
        let e = fence_err(store.open_import_session(tgt(), OP, 2).await);
        assert_eq!(e.outcome(), FenceOutcome::OperationCapabilityRequired);
        let e = idle
            .with_raw(|c| c.execute_batch("insert into t values (2)"))
            .await
            .unwrap_err();
        assert_eq!(e.outcome(), FenceOutcome::OperationCapabilityRequired);
        assert!(!sealing.is_finished());
        assert_eq!(fence.gate().state(), FenceState::TargetImportDraining);

        // The running import finishes; its transaction commits, and only then does the seal
        // reach the commit of TARGET_VALIDATING.
        let completing = fence.hooks().pause_at(HookPoint::BeforeMetastoreCommit);
        resume.send(()).unwrap();
        tokio::time::timeout(PROMPT, completing.reached())
            .await
            .expect("the seal completes once the import writer is gone");
        assert!(
            committed.load(std::sync::atomic::Ordering::SeqCst),
            "the seal proceeded while the import transaction was still running"
        );
        completing.resume();
        let (mut session, r) = running.await.unwrap();
        r.unwrap().unwrap();
        let commit = sealing.await.unwrap().unwrap();
        assert_eq!(commit.receipt.outcome, FenceOutcome::Applied);
        assert_eq!(
            (fence.gate().state(), fence.gate().revision()),
            (FenceState::TargetValidating, 3)
        );
        // The publication of TARGET_IMPORT_DRAINING dropped both sessions' capabilities.
        assert_eq!(fence.live_capabilities(), 0);
        assert_eq!(count(&store).await, 1);
        let e = session
            .with_raw(|c| c.execute_batch("insert into t values (3)"))
            .await
            .unwrap_err();
        assert_eq!(e.outcome(), FenceOutcome::OperationCapabilityRequired);
    }

    /// An import transaction left open by an idle session holds the write slot: the seal does
    /// not complete past its deadline (`on_deadline: fail`), `TARGET_IMPORT_DRAINING` stays
    /// durable and closed (also across a restart), another operation cannot touch it, and only
    /// the owner's seal resumes it: a replay of the same seal completes once the session is
    /// gone (its transaction rolled back).
    #[tokio::test(flavor = "multi_thread")]
    async fn seal_deadline_leaves_import_draining_until_replayed() {
        let (dir, store, fence) = target().await;
        let mut session = store.open_import_session(tgt(), OP, 1).await.unwrap();
        session
            .with_raw(|c| c.execute_batch("create table t (x)"))
            .await
            .unwrap()
            .unwrap();
        session
            .with_raw(|c| c.execute_batch("begin immediate; insert into t values (1)"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fence.import_writers(), 0);

        let commit = execute(&store, seal_request(10, 1, NOW))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(commit.receipt.outcome, FenceOutcome::Draining);
        assert_eq!(
            (fence.gate().state(), fence.gate().revision()),
            (FenceState::TargetImportDraining, 2)
        );

        // Another operation's seal is refused; a new seal of the owner joins the drain, which
        // still cannot complete.
        let mut foreign = seal_request(11, 2, NOW);
        foreign.operation_id = OTHER_OP;
        foreign.expected_state = FenceState::TargetImportDraining;
        let e = fence_err(execute(&store, foreign).await.unwrap());
        assert_eq!(e.outcome(), FenceOutcome::FenceOwnedByAnotherOperation);
        let mut join = seal_request(12, 2, NOW);
        join.expected_state = FenceState::TargetImportDraining;
        let joined = execute(&store, join).await.unwrap().unwrap();
        assert_eq!(joined.receipt.outcome, FenceOutcome::Draining);
        assert_eq!(
            (fence.gate().state(), fence.gate().revision()),
            (FenceState::TargetImportDraining, 2)
        );

        // Still draining after a restart, which drops the open transaction.
        drop(session);
        store.shutdown().await.unwrap();
        let store = open_store(dir.path()).await;
        let fence = store.fence_controller(&tgt());
        assert_eq!(fence.gate().state(), FenceState::TargetImportDraining);
        assert!(fence.permits(OperationClass::CapabilityImport).is_ok());
        let e = fence_err(store.open_import_session(tgt(), OP, 2).await);
        assert_eq!(e.outcome(), FenceOutcome::OperationCapabilityRequired);

        let replay = execute(&store, seal_request(10, 1, NOW))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(replay.kind, FenceCommitKind::Resumed);
        assert_eq!(replay.receipt.outcome, FenceOutcome::Applied);
        assert_eq!(
            (fence.gate().state(), fence.gate().revision()),
            (FenceState::TargetValidating, 3)
        );
        assert_eq!(count(&store).await, 0);
        let replay = execute(&store, seal_request(10, 1, NOW))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(replay.kind, FenceCommitKind::Replayed);
    }

    /// With `on_deadline: force_rollback` the seal rolls back an import transaction that an
    /// idle session left holding the write slot, waits for the release, and completes.
    #[tokio::test(flavor = "multi_thread")]
    async fn seal_force_rollback_ends_open_import_transaction() {
        let (_dir, store, fence) = target().await;
        let mut session = store.open_import_session(tgt(), OP, 1).await.unwrap();
        session
            .with_raw(|c| c.execute_batch("create table t (x)"))
            .await
            .unwrap()
            .unwrap();
        session
            .with_raw(|c| c.execute_batch("begin immediate; insert into t values (1)"))
            .await
            .unwrap()
            .unwrap();
        let policy = DrainPolicy {
            deadline_ms: 0,
            on_deadline: OnDeadline::ForceRollback,
        };
        let commit = execute(&store, seal_request(10, 1, policy))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(commit.receipt.outcome, FenceOutcome::Applied);
        assert_eq!(fence.gate().state(), FenceState::TargetValidating);
        drop(session);
        assert_eq!(count(&store).await, 0);
    }

    /// Once sealed, nothing imports: no capability is issued at the new revision, an older
    /// session's calls are refused, and even a capability naming the current revision is
    /// refused at the WAL.
    #[tokio::test(flavor = "multi_thread")]
    async fn sealed_target_rejects_import() {
        let (_dir, store, fence) = target().await;
        let mut session = store.open_import_session(tgt(), OP, 1).await.unwrap();
        session
            .with_raw(|c| c.execute_batch("create table t (x)"))
            .await
            .unwrap()
            .unwrap();
        let commit = execute(&store, seal_request(10, 1, LONG))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(commit.receipt.outcome, FenceOutcome::Applied);
        assert_eq!(
            (fence.gate().state(), fence.gate().revision()),
            (FenceState::TargetValidating, 3)
        );

        for revision in [1, 3] {
            let e = fence_err(store.open_import_session(tgt(), OP, revision).await);
            assert_eq!(e.outcome(), FenceOutcome::OperationCapabilityRequired);
        }
        let e = session
            .with_raw(|c| c.execute_batch("insert into t values (1)"))
            .await
            .unwrap_err();
        assert_eq!(e.outcome(), FenceOutcome::OperationCapabilityRequired);
        let e = refused_with(
            &store,
            MigrationCapability::forged(tgt(), OP, CapabilityPurpose::Import, 3),
        )
        .await;
        assert_eq!(e.outcome(), FenceOutcome::OperationCapabilityRequired);
        assert_fenced(raw(&plain_conn(&store).await, "insert into t values (1)").await);
        assert_eq!(count(&store).await, 0);
    }

    /// A synthetic representative schema: tables with keys and a foreign key, indexes, a
    /// trigger, a view and an FTS5 table.
    const SCHEMA: &str = "
        create table users (id integer primary key, email text not null unique, name text);
        create table orders (
            id integer primary key,
            user_id integer not null references users(id),
            total real not null,
            note text
        );
        create index orders_by_user on orders(user_id, total);
        create table audit (id integer primary key autoincrement, what text);
        create trigger orders_audit after insert on orders begin
            insert into audit (what) values ('order ' || new.id);
        end;
        create view order_totals as
            select u.email, sum(o.total) as total from users u join orders o on o.user_id = u.id
            group by u.email;
        create virtual table docs using fts5(title, body);
        insert into users (email, name) values ('a@example.com', 'A'), ('b@example.com', 'B');
        insert into orders (user_id, total, note) values (1, 10.5, 'first'), (1, 2, null),
            (2, 7.25, 'it''s quoted');
        insert into docs (title, body) values ('fence', 'operation owned namespace fence'),
            ('import', 'quarantined target import');
    ";

    /// What a target must reproduce of the source: the schema, the rows, and the derived data
    /// (the view, the full-text index).
    fn contents(c: &rusqlite::Connection) -> Vec<String> {
        let mut out = Vec::new();
        let mut q = |sql: &str| {
            use rusqlite::types::ValueRef;
            let mut stmt = c.prepare(sql).unwrap();
            let n = stmt.column_count();
            let rows = stmt
                .query_map((), |r| {
                    (0..n)
                        .map(|i| {
                            r.get_ref(i).map(|v| match v {
                                ValueRef::Text(t) => String::from_utf8_lossy(t).into_owned(),
                                other => format!("{other:?}"),
                            })
                        })
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
                .unwrap();
            for row in rows {
                out.push(format!("{sql}: {}", row.unwrap().join(", ")));
            }
        };
        // The loader re-renders every statement it runs, so the stored SQL of an object differs
        // from the source's in case and spacing only.
        q("select type, name, tbl_name, \
           lower(replace(replace(replace(sql, ' ', ''), char(10), ''), '\"', '')) \
           from sqlite_schema order by type, name");
        q("select * from users order by id");
        q("select * from orders order by id");
        q("select * from audit order by id");
        q("select * from order_totals order by email");
        q("select title from docs where docs match 'quarantined' order by rowid");
        q("select count(*) from docs");
        out
    }

    /// The server's own dump loader runs inside an import session: a dump exported from a
    /// source with a representative schema loads into the quarantined target, which then holds
    /// exactly what the source held, while nothing else could write to it.
    #[tokio::test(flavor = "multi_thread")]
    async fn import_session_loads_dump_into_quarantined_target() {
        let (_dir, store, fence) = target().await;
        store
            .create("src".into(), RestoreOption::Latest, Default::default())
            .await
            .unwrap();
        let src = {
            let maker = store
                .with("src".into(), |ns| ns.db.connection_maker())
                .await
                .unwrap();
            Arc::new(maker.create().await.unwrap())
        };
        let (dump, expected) = {
            let src = src.clone();
            tokio::task::spawn_blocking(move || {
                src.with_raw(|c| {
                    c.execute_batch(SCHEMA).unwrap();
                    let mut dump = Vec::new();
                    crate::connection::dump::exporter::export_dump(c, &mut dump, false).unwrap();
                    (dump, contents(c))
                })
            })
            .await
            .unwrap()
        };
        let text = String::from_utf8(dump.clone()).unwrap();
        assert!(text.contains("CREATE VIRTUAL TABLE"), "{text}");

        let mut session = store.open_import_session(tgt(), OP, 1).await.unwrap();
        let stream = futures::stream::iter(
            dump.chunks(64)
                .map(|c| Ok(Bytes::copy_from_slice(c)))
                .collect::<Vec<_>>(),
        );
        session.load_dump(stream).await.unwrap();
        assert_eq!(fence.gate().state(), FenceState::TargetQuarantined);
        // Nothing but the session could have written it.
        assert_fenced(
            raw(
                &plain_conn(&store).await,
                "insert into audit (what) values ('x')",
            )
            .await,
        );

        // A second load fails as the loader always does on a dump that is not in a
        // transaction, without the fence being involved.
        let r = session
            .load_dump(futures::stream::iter(vec![Ok(Bytes::from_static(
                b"savepoint a; release a; savepoint b;",
            ))]))
            .await;
        assert!(
            matches!(
                r,
                Err(Error::LoadDumpError(crate::error::LoadDumpError::NoTxn))
            ),
            "{r:?}"
        );
        drop(session);

        let commit = execute(&store, seal_request(10, 1, LONG))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(commit.receipt.outcome, FenceOutcome::Applied);
        let conn = plain_conn(&store).await;
        let imported = tokio::task::spawn_blocking(move || conn.with_raw(|c| contents(c)))
            .await
            .unwrap();
        assert_eq!(imported, expected);
    }
}
