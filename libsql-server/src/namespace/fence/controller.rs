//! The per-namespace fence controller (`docs/NAMESPACE_FENCE.md` sections 7 and 8.4).
//!
//! A [`FenceController`] is the in-memory authority for one namespace's fence. It owns the
//! transition lock that serialises fence commands on the namespace, and the gate that every
//! admission path reads: a `watch` of [`GateSnapshot`]. The gate changes only after the
//! metastore has committed (commit → publish → respond), except that a commit whose outcome is
//! unknown closes it until the same command is replayed.
//!
//! Controllers live in the [`FenceRegistry`](super::registry::FenceRegistry), not in the
//! namespace cache, so evicting and reloading a namespace hands the reloaded namespace the
//! same controller.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::{watch, OwnedMutexGuard};
use uuid::Uuid;

use crate::error::Error;
use crate::namespace::meta_store::{FenceCommit, FenceContext, MetaStore};
use crate::namespace::NamespaceName;

use super::command::FenceRequest;
#[cfg(test)]
use super::hooks::FenceTestHooks;
use super::hooks::{HookOutcome, HookPoint};
use super::outcome::{FenceDetail, FenceError, FenceOutcome};
use super::state::{Admission, FenceState, OperationClass};
use super::store::StoredFence;
use super::transition::DrainCompletion;

/// `(operation_id, command_id)` of a fence command.
pub type CommandKey = (Uuid, Uuid);

/// What every admission path reads: the fence as last published, the write-admission
/// generation, and whether a commit is indeterminate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateSnapshot {
    /// The durable fence as of the last publication (or as loaded at startup).
    pub fence: StoredFence,
    /// Incremented on every published change of the fence state, of its owning operation, or
    /// of the indeterminate flag. A write transaction may only start when the generation its
    /// program and its read transaction were admitted under equals this one (section 8.1).
    pub write_generation: u64,
    /// A command whose commit outcome is unknown. While set, every class except maintenance
    /// and observability is denied, and every other command is refused.
    pub indeterminate: Option<CommandKey>,
}

impl GateSnapshot {
    fn new(fence: StoredFence) -> Self {
        Self {
            fence,
            write_generation: 0,
            indeterminate: None,
        }
    }

    pub fn state(&self) -> FenceState {
        self.fence.state()
    }

    pub fn revision(&self) -> u64 {
        self.fence.revision()
    }

    pub fn operation_id(&self) -> Option<Uuid> {
        self.fence.record().map(|r| r.operation_id)
    }

    pub fn is_unavailable(&self) -> bool {
        matches!(self.fence, StoredFence::Unavailable { .. })
    }

    /// The gate's decision for work of `class`.
    pub fn permits(&self, class: OperationClass) -> Result<(), FenceError> {
        if let Some((operation_id, command_id)) = self.indeterminate {
            if !matches!(
                class,
                OperationClass::Maintenance | OperationClass::Observability
            ) {
                return Err(FenceError::new(
                    FenceOutcome::FenceStateUnavailable,
                    format!(
                        "the outcome of fence command {command_id} of operation {operation_id} \
                         is not known yet"
                    ),
                )
                .with_detail(FenceDetail::IndeterminateCommit));
            }
        }
        self.fence.permits(class)
    }

    /// Normal write admission.
    pub fn write(&self) -> Admission {
        Admission::from(
            self.permits(OperationClass::NormalWrite)
                .map_err(|e| e.outcome()),
        )
    }

    /// Normal read admission.
    pub fn read(&self) -> Admission {
        Admission::from(
            self.permits(OperationClass::NormalRead)
                .map_err(|e| e.outcome()),
        )
    }
}

/// The fence controller of one namespace.
pub struct FenceController {
    namespace: NamespaceName,
    transition_lock: Arc<tokio::sync::Mutex<()>>,
    gate: watch::Sender<GateSnapshot>,
    #[cfg(test)]
    hooks: FenceTestHooks,
}

impl std::fmt::Debug for FenceController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FenceController")
            .field("namespace", &self.namespace)
            .field("gate", &*self.gate.borrow())
            .finish_non_exhaustive()
    }
}

impl FenceController {
    /// A controller whose gate starts from `fence`, as established by the metastore.
    pub fn new(namespace: NamespaceName, fence: StoredFence) -> Arc<Self> {
        let (gate, _) = watch::channel(GateSnapshot::new(fence));
        Arc::new(Self {
            namespace,
            transition_lock: Default::default(),
            gate,
            #[cfg(test)]
            hooks: FenceTestHooks::default(),
        })
    }

    /// A controller for a namespace without fence state.
    pub fn unfenced(namespace: NamespaceName) -> Arc<Self> {
        Self::new(
            namespace,
            StoredFence::None {
                namespace_exists: true,
            },
        )
    }

    pub fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }

    /// A copy of the current gate.
    pub fn gate(&self) -> GateSnapshot {
        self.gate.borrow().clone()
    }

    /// A receiver that observes every publication.
    pub fn subscribe(&self) -> watch::Receiver<GateSnapshot> {
        self.gate.subscribe()
    }

    pub fn write_generation(&self) -> u64 {
        self.gate.borrow().write_generation
    }

    /// The live gate's decision for work of `class`.
    pub fn permits(&self, class: OperationClass) -> Result<(), FenceError> {
        self.gate.borrow().permits(class)
    }

    /// Take the namespace's transition lock. Every fence command on the namespace runs while
    /// holding it, from its first check to its response.
    pub async fn begin_transition(self: &Arc<Self>) -> Transition {
        let guard = self.transition_lock.clone().lock_owned().await;
        Transition {
            controller: self.clone(),
            _guard: guard,
        }
    }

    /// Run one fence command to completion: take the transition lock, commit it in the
    /// metastore, publish the result to the gate and return it.
    ///
    /// The work runs on its own task, so a caller that goes away (a lost response) does not
    /// stop the publication of a command that committed.
    pub async fn apply_command(
        self: &Arc<Self>,
        meta: &MetaStore,
        request: FenceRequest,
        ctx: FenceContext,
    ) -> crate::Result<FenceCommit> {
        let this = self.clone();
        let meta = meta.clone();
        tokio::spawn(async move {
            let mut transition = this.begin_transition().await;
            transition.apply(&meta, request, ctx).await
        })
        .await?
    }

    #[cfg(test)]
    pub fn hooks(&self) -> &FenceTestHooks {
        &self.hooks
    }

    /// Reach a test hook point. Outside the library's own test build this does nothing.
    #[cfg(test)]
    pub(crate) async fn hook(&self, point: HookPoint) -> HookOutcome {
        self.hooks.hit(point).await
    }

    #[cfg(not(test))]
    #[inline(always)]
    pub(crate) async fn hook(&self, _point: HookPoint) -> HookOutcome {
        HookOutcome::Continue
    }

    /// Publish a new gate. `fence: None` keeps the published fence. The write generation moves
    /// whenever the state, the owning operation or the indeterminate flag changes.
    fn publish(&self, fence: Option<StoredFence>, indeterminate: Option<CommandKey>) {
        self.gate.send_modify(|gate| {
            let fence = fence.unwrap_or_else(|| gate.fence.clone());
            let changed = fence.state() != gate.fence.state()
                || fence.record().map(|r| r.operation_id)
                    != gate.fence.record().map(|r| r.operation_id)
                || indeterminate != gate.indeterminate;
            gate.fence = fence;
            gate.indeterminate = indeterminate;
            if changed {
                gate.write_generation += 1;
            }
        });
        let gate = self.gate.borrow();
        tracing::debug!(
            namespace = %self.namespace,
            state = %gate.state(),
            revision = gate.revision(),
            write_generation = gate.write_generation,
            indeterminate = gate.indeterminate.is_some(),
            "published namespace fence gate"
        );
    }
}

/// A fence command in progress on one namespace. Holds the namespace's transition lock until
/// dropped.
pub struct Transition {
    controller: Arc<FenceController>,
    _guard: OwnedMutexGuard<()>,
}

impl Transition {
    pub fn controller(&self) -> &Arc<FenceController> {
        &self.controller
    }

    /// Commit `request` in the metastore and publish the result.
    pub async fn apply(
        &mut self,
        meta: &MetaStore,
        request: FenceRequest,
        ctx: FenceContext,
    ) -> crate::Result<FenceCommit> {
        debug_assert_eq!(&request.namespace, self.controller.namespace());
        let key = (request.operation_id, request.command_id);
        self.commit(
            key,
            async move { meta.apply_fence_command(request, ctx).await },
        )
        .await
    }

    /// Complete the drain that the `DRAINING` receipt `key` started, once the caller has
    /// proven `completion`, and publish the result.
    pub async fn complete_drain(
        &mut self,
        meta: &MetaStore,
        key: CommandKey,
        completion: DrainCompletion,
        ctx: FenceContext,
    ) -> crate::Result<FenceCommit> {
        let namespace = self.controller.namespace().clone();
        self.commit(key, async move {
            meta.complete_fence_drain(namespace, key.0, key.1, completion, ctx)
                .await
        })
        .await
    }

    /// The commit → publish → respond sequence of section 8.4.
    ///
    /// - An error that proves nothing was committed leaves the gate exactly as it was.
    /// - A commit whose outcome is unknown closes the gate (every class but maintenance and
    ///   observability) and marks `key` indeterminate: other commands get
    ///   `FENCE_COMMIT_INDETERMINATE` until `key` is replayed, and the replay, which the
    ///   metastore answers from the durable row, reopens it to whatever is durable.
    /// - A commit is published before it is answered.
    async fn commit<F>(&mut self, key: CommandKey, run: F) -> crate::Result<FenceCommit>
    where
        F: std::future::Future<Output = crate::Result<FenceCommit>>,
    {
        let controller = self.controller.clone();
        if let Some(pending) = controller.gate.borrow().indeterminate {
            if pending != key {
                return Err(pending_indeterminate(pending).into());
            }
        }

        if let HookOutcome::Fail(e) = controller.hook(HookPoint::BeforeMetastoreCommit).await {
            return Err(e.into());
        }

        let result = match run.await {
            Ok(commit) => match controller.hook(HookPoint::AfterMetastoreCommit).await {
                HookOutcome::Continue => Ok(commit),
                HookOutcome::Indeterminate | HookOutcome::Fail(_) => Err(indeterminate(
                    key,
                    "the commit was not acknowledged (test hook)",
                )),
            },
            Err(e) if is_indeterminate(&e) => Err(indeterminate(key, &e.to_string())),
            Err(e) => return Err(e),
        };

        match result {
            Ok(commit) => {
                let _ = controller.hook(HookPoint::BeforeGatePublish).await;
                controller.publish(commit.record.clone().map(StoredFence::Record), None);
                let _ = controller.hook(HookPoint::BeforeResponse).await;
                Ok(commit)
            }
            Err(e) => {
                tracing::error!(
                    namespace = %controller.namespace,
                    operation_id = %key.0,
                    command_id = %key.1,
                    "fence commit outcome unknown; the namespace stays closed until the command \
                     is replayed: {e}"
                );
                controller.publish(None, Some(key));
                Err(e.into())
            }
        }
    }
}

/// Whether a metastore error leaves the commit's outcome unknown: the commit itself failed, or
/// the task running it died.
fn is_indeterminate(e: &Error) -> bool {
    match e {
        Error::NamespaceFence(f) => f.outcome() == FenceOutcome::FenceCommitIndeterminate,
        Error::RuntimeTaskJoinError(_) => true,
        _ => false,
    }
}

fn indeterminate(key: CommandKey, why: &str) -> FenceError {
    FenceError::new(
        FenceOutcome::FenceCommitIndeterminate,
        format!(
            "whether fence command {} of operation {} was committed is unknown ({why}); replay \
             the same command to reconcile",
            key.1, key.0
        ),
    )
    .with_detail(FenceDetail::IndeterminateCommit)
}

fn pending_indeterminate((operation_id, command_id): CommandKey) -> FenceError {
    FenceError::new(
        FenceOutcome::FenceCommitIndeterminate,
        format!(
            "fence command {command_id} of operation {operation_id} has an unknown outcome; \
             only a replay of that command is accepted until it is reconciled"
        ),
    )
    .with_detail(FenceDetail::IndeterminateCommit)
}

/// The fence state of one connection, shared by its WAL wrapper and its `CoreConnection`
/// (section 7.4). The WAL gate reads and writes it; this commit only installs it.
#[derive(Debug)]
pub struct FenceConnState {
    controller: Arc<FenceController>,
    class: OperationClass,
    /// The write generation the current program was admitted under.
    program_generation: AtomicU64,
    /// The write generation the current read transaction was opened under.
    txn_generation: AtomicU64,
    /// The typed outcome of the last refusal at the WAL.
    denial: Mutex<Option<FenceError>>,
}

impl FenceConnState {
    pub fn new(controller: Arc<FenceController>, class: OperationClass) -> Arc<Self> {
        let generation = controller.write_generation();
        Arc::new(Self {
            controller,
            class,
            program_generation: AtomicU64::new(generation),
            txn_generation: AtomicU64::new(generation),
            denial: Mutex::new(None),
        })
    }

    pub fn controller(&self) -> &Arc<FenceController> {
        &self.controller
    }

    pub fn class(&self) -> OperationClass {
        self.class
    }

    pub fn program_generation(&self) -> u64 {
        self.program_generation.load(Ordering::Acquire)
    }

    pub fn txn_generation(&self) -> u64 {
        self.txn_generation.load(Ordering::Acquire)
    }

    pub fn take_denial(&self) -> Option<FenceError> {
        self.denial.lock().take()
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use tempfile::tempdir;

    use super::*;
    use crate::config::MetaStoreConfig;
    use crate::connection::config::DatabaseConfig;
    use crate::database::DatabaseKind;
    use crate::namespace::fence::command::FenceCommand;
    use crate::namespace::fence::record::{FrozenBoundary, ServerIdentity};
    use crate::namespace::meta_store::{metastore_connection_maker, FenceCommitKind};

    const LOG: Uuid = Uuid::from_u128(0x10);
    const OP: Uuid = Uuid::from_u128(0xa);
    const OTHER_OP: Uuid = Uuid::from_u128(0xb);

    pub(crate) async fn open_metastore(dir: &Path) -> MetaStore {
        let (maker, manager) = metastore_connection_maker(None, dir).await.unwrap();
        let conn = maker().unwrap();
        MetaStore::new(
            MetaStoreConfig {
                namespace_fence: true,
                ..Default::default()
            },
            dir,
            conn,
            manager,
            DatabaseKind::Primary,
        )
        .await
        .unwrap()
    }

    pub(crate) async fn create_namespace(meta: &MetaStore, ns: &'static str) {
        meta.handle(ns.into())
            .await
            .unwrap()
            .store(DatabaseConfig::default())
            .await
            .unwrap();
    }

    fn ctx() -> FenceContext {
        FenceContext::now(
            ServerIdentity {
                build: "test".into(),
                instance_id: Uuid::from_u128(0x99),
            },
            Some(LOG),
        )
    }

    fn acquire(ns: &'static str, op: Uuid, command_id: u128) -> FenceRequest {
        FenceRequest {
            namespace: ns.into(),
            operation_id: op,
            command_id: Uuid::from_u128(command_id),
            expected_state: FenceState::Unfenced,
            expected_revision: 0,
            command: FenceCommand::AcquireSourceWriteFence {
                expected_log_id: LOG,
                drain_policy: None,
            },
        }
    }

    fn release(ns: &'static str, op: Uuid, command_id: u128, revision: u64) -> FenceRequest {
        FenceRequest {
            namespace: ns.into(),
            operation_id: op,
            command_id: Uuid::from_u128(command_id),
            expected_state: FenceState::SourceWriteFenced,
            expected_revision: revision,
            command: FenceCommand::ReleaseSourceWriteFence,
        }
    }

    fn outcome(r: &crate::Result<FenceCommit>) -> FenceOutcome {
        match r {
            Ok(c) => c.receipt.outcome,
            Err(Error::NamespaceFence(e)) => e.outcome(),
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    /// Acquire and complete the drain directly, as the write drain will: the controller ends in
    /// `SOURCE_WRITE_FENCED`.
    async fn fence_source(meta: &MetaStore, controller: &Arc<FenceController>, op: Uuid) {
        let commit = controller
            .apply_command(meta, acquire("ns", op, 1), ctx())
            .await
            .unwrap();
        assert_eq!(commit.receipt.outcome, FenceOutcome::Draining);
        let mut t = controller.begin_transition().await;
        let commit = t
            .complete_drain(
                meta,
                (op, Uuid::from_u128(1)),
                DrainCompletion::SourceWrites {
                    boundary: FrozenBoundary {
                        log_id: LOG,
                        frame_no: 0,
                    },
                },
                ctx(),
            )
            .await
            .unwrap();
        assert_eq!(commit.receipt.outcome, FenceOutcome::Applied);
    }

    #[tokio::test]
    async fn committed_command_publishes_new_revision_and_generation() {
        let tmp = tempdir().unwrap();
        let meta = open_metastore(tmp.path()).await;
        create_namespace(&meta, "ns").await;
        let controller = FenceController::unfenced("ns".into());
        let mut rx = controller.subscribe();
        assert!(controller.permits(OperationClass::NormalWrite).is_ok());
        assert_eq!(controller.write_generation(), 0);

        let commit = controller
            .apply_command(&meta, acquire("ns", OP, 1), ctx())
            .await
            .unwrap();
        assert_eq!(commit.kind, FenceCommitKind::Committed);
        assert!(rx.has_changed().unwrap());
        let gate = rx.borrow_and_update().clone();
        assert_eq!(gate.state(), FenceState::SourceDraining);
        assert_eq!(gate.revision(), 1);
        assert_eq!(gate.operation_id(), Some(OP));
        assert_eq!(gate.write_generation, 1);
        assert_eq!(
            controller
                .permits(OperationClass::NormalWrite)
                .unwrap_err()
                .outcome(),
            FenceOutcome::MigrationWriteFenced
        );
        assert!(controller.permits(OperationClass::NormalRead).is_ok());
        assert!(controller.permits(OperationClass::Maintenance).is_ok());

        // The published gate is the durable one.
        let inspected = meta.inspect_fence("ns".into()).await.unwrap();
        assert_eq!(inspected.fence, gate.fence);
    }

    #[tokio::test]
    async fn write_generation_bumps_on_every_write_admission_change() {
        let tmp = tempdir().unwrap();
        let meta = open_metastore(tmp.path()).await;
        create_namespace(&meta, "ns").await;
        let controller = FenceController::unfenced("ns".into());

        let mut generations = vec![controller.write_generation()];
        fence_source(&meta, &controller, OP).await;
        // UNFENCED -> SOURCE_DRAINING -> SOURCE_WRITE_FENCED: two changes of state.
        generations.push(controller.write_generation());
        let revision = controller.gate().revision();
        controller
            .apply_command(&meta, release("ns", OP, 2, revision), ctx())
            .await
            .unwrap();
        assert_eq!(controller.gate().state(), FenceState::Released);
        assert!(controller.permits(OperationClass::NormalWrite).is_ok());
        generations.push(controller.write_generation());
        assert_eq!(generations, vec![0, 2, 3]);

        // A replay publishes the same durable state and does not move the generation.
        let before = controller.gate();
        let replay = controller
            .apply_command(&meta, release("ns", OP, 2, revision), ctx())
            .await
            .unwrap();
        assert_eq!(replay.kind, FenceCommitKind::Replayed);
        assert_eq!(controller.gate(), before);
    }

    #[tokio::test]
    async fn failed_before_commit_leaves_gate_unchanged() {
        let tmp = tempdir().unwrap();
        let meta = open_metastore(tmp.path()).await;
        create_namespace(&meta, "ns").await;
        let controller = FenceController::unfenced("ns".into());
        let before = controller.gate();

        // A refusal by the transition function.
        let mut wrong = acquire("ns", OP, 1);
        wrong.expected_revision = 7;
        let r = controller.apply_command(&meta, wrong, ctx()).await;
        assert_eq!(outcome(&r), FenceOutcome::FenceRevisionMismatch);
        assert_eq!(controller.gate(), before);

        // An injected failure before the metastore transaction.
        controller.hooks().fail_at(
            HookPoint::BeforeMetastoreCommit,
            FenceError::new(FenceOutcome::FencePreconditionFailed, "injected"),
        );
        let r = controller
            .apply_command(&meta, acquire("ns", OP, 1), ctx())
            .await;
        assert_eq!(outcome(&r), FenceOutcome::FencePreconditionFailed);
        assert_eq!(controller.gate(), before);

        // The metastore is busy (another connection holds its write lock): nothing is written
        // and the gate does not move.
        let (maker, _) = metastore_connection_maker(None, tmp.path()).await.unwrap();
        let mut other = maker().unwrap();
        let lock = other
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        let r = controller
            .apply_command(&meta, acquire("ns", OP, 1), ctx())
            .await;
        assert!(
            matches!(r, Err(Error::RusqliteError(_))),
            "expected a busy metastore, got {r:?}"
        );
        assert_eq!(controller.gate(), before);
        drop(lock);
        let inspected = meta.inspect_fence("ns".into()).await.unwrap();
        assert!(matches!(inspected.fence, StoredFence::None { .. }));
        assert!(inspected.receipts.is_empty());
    }

    #[tokio::test]
    async fn indeterminate_commit_keeps_writes_closed_until_replayed() {
        let tmp = tempdir().unwrap();
        let meta = open_metastore(tmp.path()).await;
        create_namespace(&meta, "ns").await;
        let controller = FenceController::unfenced("ns".into());
        fence_source(&meta, &controller, OP).await;
        let fenced = controller.gate();
        let revision = fenced.revision();

        // Release commits, but its acknowledgement is lost.
        controller.hooks().arm(
            HookPoint::AfterMetastoreCommit,
            super::super::hooks::HookAction::Indeterminate,
        );
        let r = controller
            .apply_command(&meta, release("ns", OP, 2, revision), ctx())
            .await;
        assert_eq!(outcome(&r), FenceOutcome::FenceCommitIndeterminate);
        let gate = controller.gate();
        assert_eq!(gate.indeterminate, Some((OP, Uuid::from_u128(2))));
        assert!(gate.write_generation > fenced.write_generation);
        // The durable state says released, but nothing is admitted until it is reconciled.
        for class in [
            OperationClass::NormalWrite,
            OperationClass::NormalRead,
            OperationClass::Stream,
            OperationClass::Lifecycle,
        ] {
            let e = controller.permits(class).unwrap_err();
            assert_eq!(e.outcome(), FenceOutcome::FenceStateUnavailable);
            assert_eq!(e.detail(), Some(FenceDetail::IndeterminateCommit));
        }
        assert!(controller.permits(OperationClass::Maintenance).is_ok());

        // Any other command is refused with the indeterminate code.
        let r = controller
            .apply_command(&meta, release("ns", OTHER_OP, 3, revision), ctx())
            .await;
        assert_eq!(outcome(&r), FenceOutcome::FenceCommitIndeterminate);

        // The replay reconciles from the durable row and publishes it.
        let r = controller
            .apply_command(&meta, release("ns", OP, 2, revision), ctx())
            .await
            .unwrap();
        assert_eq!(r.kind, FenceCommitKind::Replayed);
        let gate = controller.gate();
        assert_eq!(gate.indeterminate, None);
        assert_eq!(gate.state(), FenceState::Released);
        assert!(controller.permits(OperationClass::NormalWrite).is_ok());
    }

    #[tokio::test]
    async fn indeterminate_commit_that_did_not_apply_is_retried_by_replay() {
        let tmp = tempdir().unwrap();
        let meta = open_metastore(tmp.path()).await;
        create_namespace(&meta, "ns").await;
        let controller = FenceController::unfenced("ns".into());

        // Simulate an indeterminate outcome for a command that never reached the metastore:
        // the replay applies it.
        controller.publish(None, Some((OP, Uuid::from_u128(1))));
        assert!(controller.permits(OperationClass::NormalWrite).is_err());
        let r = controller
            .apply_command(&meta, acquire("ns", OP, 1), ctx())
            .await
            .unwrap();
        assert_eq!(r.kind, FenceCommitKind::Committed);
        let gate = controller.gate();
        assert_eq!(gate.indeterminate, None);
        assert_eq!(gate.state(), FenceState::SourceDraining);
    }

    #[tokio::test]
    async fn publication_happens_before_the_response() {
        let tmp = tempdir().unwrap();
        let meta = open_metastore(tmp.path()).await;
        create_namespace(&meta, "ns").await;
        let controller = FenceController::unfenced("ns".into());
        let before_publish = controller.hooks().pause_at(HookPoint::BeforeGatePublish);

        let task = tokio::spawn({
            let controller = controller.clone();
            let meta = meta.clone();
            async move {
                controller
                    .apply_command(&meta, acquire("ns", OP, 1), ctx())
                    .await
            }
        });
        before_publish.reached().await;
        // Committed, not yet published: the gate still shows the old state.
        assert_eq!(controller.gate().state(), FenceState::Unfenced);
        assert!(matches!(
            meta.inspect_fence("ns".into()).await.unwrap().fence,
            StoredFence::Record(_)
        ));
        let before_response = controller.hooks().pause_at(HookPoint::BeforeResponse);
        before_publish.resume();
        before_response.reached().await;
        assert_eq!(controller.gate().state(), FenceState::SourceDraining);
        assert!(!task.is_finished());
        before_response.resume();
        assert_eq!(outcome(&task.await.unwrap()), FenceOutcome::Draining);
    }

    #[tokio::test]
    async fn committed_command_is_published_when_the_caller_goes_away() {
        let tmp = tempdir().unwrap();
        let meta = open_metastore(tmp.path()).await;
        create_namespace(&meta, "ns").await;
        let controller = FenceController::unfenced("ns".into());
        let after_commit = controller.hooks().pause_at(HookPoint::AfterMetastoreCommit);

        let caller = tokio::spawn({
            let controller = controller.clone();
            let meta = meta.clone();
            async move {
                controller
                    .apply_command(&meta, acquire("ns", OP, 1), ctx())
                    .await
            }
        });
        after_commit.reached().await;
        // The response is lost: the caller is cancelled after the commit.
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        let published = controller.hooks().pause_at(HookPoint::BeforeResponse);
        after_commit.resume();
        published.reached().await;
        assert_eq!(controller.gate().state(), FenceState::SourceDraining);
        published.resume();

        // The transition lock is free again and a replay answers from the receipt.
        let replay = controller
            .apply_command(&meta, acquire("ns", OP, 1), ctx())
            .await
            .unwrap();
        assert_eq!(replay.receipt.outcome, FenceOutcome::Draining);
    }

    #[tokio::test]
    async fn transition_lock_serialises_commands() {
        let tmp = tempdir().unwrap();
        let meta = open_metastore(tmp.path()).await;
        create_namespace(&meta, "ns").await;
        let controller = FenceController::unfenced("ns".into());

        let held = controller.begin_transition().await;
        let second = tokio::spawn({
            let controller = controller.clone();
            let meta = meta.clone();
            async move {
                controller
                    .apply_command(&meta, acquire("ns", OP, 1), ctx())
                    .await
            }
        });
        tokio::task::yield_now().await;
        assert!(!second.is_finished());
        assert!(controller.transition_lock.try_lock().is_err());
        drop(held);
        assert_eq!(outcome(&second.await.unwrap()), FenceOutcome::Draining);
    }

    #[test]
    fn unavailable_gate_denies_every_class_but_maintenance() {
        let controller = FenceController::new(
            "ns".into(),
            StoredFence::Unavailable {
                detail: FenceDetail::CorruptRecord,
                reason: "test".into(),
                marker: None,
            },
        );
        let gate = controller.gate();
        assert!(gate.is_unavailable());
        for class in OperationClass::ALL {
            let r = gate.permits(class);
            match class {
                OperationClass::Maintenance | OperationClass::Observability => {
                    assert!(r.is_ok())
                }
                _ => {
                    let e = r.unwrap_err();
                    assert_eq!(e.outcome(), FenceOutcome::FenceStateUnavailable);
                    assert_eq!(e.detail(), Some(FenceDetail::CorruptRecord));
                }
            }
        }
    }

    #[test]
    fn conn_state_starts_at_the_current_generation() {
        let controller = FenceController::unfenced("ns".into());
        controller.publish(None, Some((OP, OP)));
        controller.publish(None, None);
        let state = FenceConnState::new(controller.clone(), OperationClass::NormalWrite);
        assert_eq!(state.program_generation(), 2);
        assert_eq!(state.txn_generation(), 2);
        assert!(Arc::ptr_eq(state.controller(), &controller));
        assert_eq!(state.class(), OperationClass::NormalWrite);
        assert!(state.take_denial().is_none());
    }
}
