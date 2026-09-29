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

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::{watch, Notify, OwnedMutexGuard};
use uuid::Uuid;

use crate::connection::connection_manager::{ConnectionManager, WeakConnectionManager};
use crate::error::Error;
use crate::namespace::meta_store::{FenceCommit, FenceContext, MetaStore};
use crate::namespace::NamespaceName;
use crate::replication::FrameNo;

use super::capability::{CapabilityPurpose, CapabilitySet, ImportWriter, MigrationCapability};
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
    /// The in-memory `INSTALLING` gate of a closing transition that is being persisted
    /// (section 8.3, step 2): write admission is closed on top of whatever `fence` allows.
    /// Never persisted.
    pub installing: Option<CommandKey>,
    /// The in-memory read-closing gate of a `SetSourceReadFence` that is being persisted
    /// (section 9, step 2): normal reads and streams are refused on top of whatever `fence`
    /// allows. Never persisted, and cleared by every publication of a commit. It does not move
    /// the write generation: write admission is already closed wherever a read fence can be set.
    pub closing_reads: Option<CommandKey>,
    /// The in-memory gate of a `CreateTargetQuarantined` that is being persisted (section
    /// 10.1): the name is becoming a quarantined target, so everything but maintenance and
    /// observability is refused with `MIGRATION_TARGET_QUARANTINED`, and the namespace is not
    /// set up. Never persisted; replaced by the record the command's commit publishes.
    pub creating_target: Option<CommandKey>,
}

impl GateSnapshot {
    fn new(fence: StoredFence) -> Self {
        Self {
            fence,
            write_generation: 0,
            indeterminate: None,
            installing: None,
            closing_reads: None,
            creating_target: None,
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
        if let Some((operation_id, command_id)) = self.creating_target {
            if !matches!(
                class,
                OperationClass::Maintenance | OperationClass::Observability
            ) {
                return Err(FenceError::new(
                    FenceOutcome::MigrationTargetQuarantined,
                    format!(
                        "{class:?} is not permitted: fence command {command_id} of operation \
                         {operation_id} is creating this namespace as a migration target"
                    ),
                ));
            }
        }
        self.fence.permits(class)?;
        if let Some((operation_id, command_id)) = self.installing {
            if matches!(
                class,
                OperationClass::NormalWrite
                    | OperationClass::Vacuum
                    | OperationClass::CapabilityImport
                    | OperationClass::Lifecycle
            ) {
                return Err(FenceError::new(
                    FenceOutcome::MigrationWriteFenced,
                    format!(
                        "{class:?} is not permitted: fence command {command_id} of operation \
                         {operation_id} is closing write admission"
                    ),
                ));
            }
        }
        if let Some((operation_id, command_id)) = self.closing_reads {
            if matches!(class, OperationClass::NormalRead | OperationClass::Stream) {
                return Err(FenceError::new(
                    FenceOutcome::MigrationReadFenced,
                    format!(
                        "{class:?} is not permitted: fence command {command_id} of operation \
                         {operation_id} is closing read admission"
                    ),
                ));
            }
        }
        Ok(())
    }

    /// Whether a closing transition is being installed.
    pub fn is_installing(&self) -> bool {
        self.installing.is_some()
    }

    /// Whether the namespace is being created as a quarantined target.
    pub fn is_creating_target(&self) -> bool {
        self.creating_target.is_some()
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

/// Wakes one connection manager's write queue after a write-generation change; returns `false`
/// once the manager is gone.
pub type WriteQueueWaker = Box<dyn Fn() -> bool + Send + Sync>;

/// The last frame committed to a namespace's replication log, `None` while it has none.
pub type GetCurrentFrameNo = Arc<dyn Fn() -> Option<FrameNo> + Send + Sync + 'static>;

/// What the write drain needs from one primary connection maker of the namespace: its
/// connection manager (held weakly, so an evicted namespace's manager goes away with it) and
/// its replication log.
pub struct WriteDrainSource {
    pub(crate) manager: WeakConnectionManager,
    pub(crate) log_id: Uuid,
    pub(crate) current_frame_no: GetCurrentFrameNo,
}

impl WriteDrainSource {
    pub(crate) fn new(
        manager: &ConnectionManager,
        log_id: Uuid,
        current_frame_no: GetCurrentFrameNo,
    ) -> Self {
        Self {
            manager: manager.downgrade(),
            log_id,
            current_frame_no,
        }
    }
}

/// A [`WriteDrainSource`] whose manager is alive, held for the length of a drain.
pub(crate) struct LiveWriteDrain {
    pub(crate) manager: ConnectionManager,
    pub(crate) log_id: Uuid,
    pub(crate) current_frame_no: GetCurrentFrameNo,
}

/// What a read lease covers (section 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LeaseKind {
    /// A running SQL program (including a Hrana cursor producing rows), or an ATTACH of the
    /// namespace by a program running on another namespace.
    Sql,
    /// A `/dump` stream.
    Dump,
    /// A replication `log_entries` or `snapshot` stream.
    Replication,
}

/// The number of read leases held on a namespace, by kind.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReadLeaseCounts {
    pub sql: usize,
    pub dump: usize,
    pub replication: usize,
}

impl ReadLeaseCounts {
    pub fn total(&self) -> usize {
        self.sql + self.dump + self.replication
    }
}

struct LeaseEntry {
    kind: LeaseKind,
    cancel: Box<dyn Fn() + Send + Sync>,
    cancelled: Arc<AtomicBool>,
}

#[derive(Default)]
struct ReadLeaseSet {
    next_id: u64,
    live: HashMap<u64, LeaseEntry>,
}

/// Read work admitted by the gate and counted by the read drain until it is dropped
/// ([`FenceController::acquire_read_lease`]).
pub struct ReadLease {
    controller: Arc<FenceController>,
    id: u64,
    kind: LeaseKind,
    cancelled: Arc<AtomicBool>,
}

impl ReadLease {
    pub fn kind(&self) -> LeaseKind {
        self.kind
    }

    pub fn controller(&self) -> &Arc<FenceController> {
        &self.controller
    }

    /// Whether the read drain cancelled this lease's work at its deadline.
    pub fn cancelled_by_fence(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

impl std::fmt::Debug for ReadLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadLease")
            .field("namespace", &self.controller.namespace)
            .field("id", &self.id)
            .field("kind", &self.kind)
            .finish()
    }
}

impl Drop for ReadLease {
    fn drop(&mut self) {
        self.controller.release_read_lease(self.id);
    }
}

/// The fence controller of one namespace.
pub struct FenceController {
    namespace: NamespaceName,
    transition_lock: Arc<tokio::sync::Mutex<()>>,
    gate: watch::Sender<GateSnapshot>,
    /// The write queues of the namespace's connection managers (section 8.2).
    write_queues: Mutex<Vec<WriteQueueWaker>>,
    /// What the write drain needs from each of the namespace's primary connection makers
    /// (section 8.3).
    write_drains: Mutex<Vec<WriteDrainSource>>,
    /// The read leases held on the namespace (section 9).
    read_leases: Mutex<ReadLeaseSet>,
    /// Notified whenever a read lease is released.
    read_released: Notify,
    /// The migration capabilities issued and not revoked, and the import calls running under
    /// them (sections 7.2 and 10.2). Lock order: this lock may be taken before borrowing the
    /// gate, never while a gate borrow is held.
    capabilities: Mutex<CapabilitySet>,
    /// Notified whenever an import call ends.
    import_released: Notify,
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
            write_queues: Mutex::new(Vec::new()),
            write_drains: Mutex::new(Vec::new()),
            read_leases: Mutex::new(ReadLeaseSet::default()),
            read_released: Notify::new(),
            capabilities: Mutex::new(CapabilitySet::default()),
            import_released: Notify::new(),
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

    /// Register a connection manager's write queue, to be woken after every change of the write
    /// generation so that queued writers re-check the gate instead of waiting for the slot.
    /// Wakers whose manager is gone are dropped on the next change.
    pub fn register_write_queue(&self, waker: WriteQueueWaker) {
        self.write_queues.lock().push(waker);
    }

    /// Register what the write drain needs from a primary connection maker of this namespace:
    /// its connection manager and its replication log. Sources whose manager is gone are
    /// dropped the next time the drain looks.
    pub fn register_write_drain(&self, source: WriteDrainSource) {
        self.write_drains.lock().push(source);
    }

    /// The write-drain sources whose manager is still alive, oldest first. The drain holds them
    /// (and so their managers) for as long as it runs.
    pub(crate) fn live_write_drains(&self) -> Vec<LiveWriteDrain> {
        let mut sources = self.write_drains.lock();
        let mut live = Vec::with_capacity(sources.len());
        sources.retain(|source| match source.manager.upgrade() {
            Some(manager) => {
                live.push(LiveWriteDrain {
                    manager,
                    log_id: source.log_id,
                    current_frame_no: source.current_frame_no.clone(),
                });
                true
            }
            None => false,
        });
        live
    }

    /// Admit read work of `class` and hold a read lease of `kind` for it (section 9). The gate
    /// is checked under the lease lock, so a read fence that closed admission before this call
    /// is seen here, and one that closes after it counts this lease and waits for it. `cancel`
    /// is how the read drain stops the work at its deadline: it must make the work end and
    /// drop the lease, never wait for it to end. The lease is released when dropped.
    pub fn acquire_read_lease(
        self: &Arc<Self>,
        class: OperationClass,
        kind: LeaseKind,
        cancel: impl Fn() + Send + Sync + 'static,
    ) -> Result<ReadLease, FenceError> {
        let cancelled = Arc::new(AtomicBool::new(false));
        let id = {
            let mut leases = self.read_leases.lock();
            self.permits(class)?;
            let id = leases.next_id;
            leases.next_id += 1;
            leases.live.insert(
                id,
                LeaseEntry {
                    kind,
                    cancel: Box::new(cancel),
                    cancelled: cancelled.clone(),
                },
            );
            id
        };
        Ok(ReadLease {
            controller: self.clone(),
            id,
            kind,
            cancelled,
        })
    }

    /// The read leases currently held, by kind.
    pub fn read_lease_counts(&self) -> ReadLeaseCounts {
        let leases = self.read_leases.lock();
        let mut counts = ReadLeaseCounts::default();
        for entry in leases.live.values() {
            match entry.kind {
                LeaseKind::Sql => counts.sql += 1,
                LeaseKind::Dump => counts.dump += 1,
                LeaseKind::Replication => counts.replication += 1,
            }
        }
        counts
    }

    /// Cancel every read lease held now (the read drain's deadline). Each lease's work is asked
    /// to stop once; the leases stay counted until they are actually released. Returns how many
    /// were asked.
    pub(crate) fn cancel_read_leases(&self) -> usize {
        let leases = self.read_leases.lock();
        let mut asked = 0;
        for entry in leases.live.values() {
            if !entry.cancelled.swap(true, Ordering::AcqRel) {
                (entry.cancel)();
                asked += 1;
            }
        }
        asked
    }

    /// Notified on every read-lease release. Enable the notification before checking
    /// [`read_lease_counts`](Self::read_lease_counts), so a release in between is not missed.
    pub(crate) fn read_released(&self) -> &Notify {
        &self.read_released
    }

    fn release_read_lease(&self, id: u64) {
        let removed = self.read_leases.lock().live.remove(&id);
        drop(removed);
        self.read_released.notify_waiters();
    }

    /// Issue a migration capability for `purpose` to `operation_id` (section 11). The fence
    /// must be in a state the purpose admits, owned by `operation_id`, at `expected_revision`,
    /// with no command being installed or reconciled. The capability stays valid until the
    /// fence moves on (every transition moves the revision) or it is revoked.
    pub fn issue_capability(
        &self,
        purpose: CapabilityPurpose,
        operation_id: Uuid,
        expected_revision: u64,
    ) -> Result<MigrationCapability, FenceError> {
        let mut caps = self.capabilities.lock();
        let gate = self.gate.borrow();
        gate.permits(purpose.class())?;
        let Some(record) = gate.fence.record() else {
            return Err(FenceError::new(
                FenceOutcome::OperationCapabilityRequired,
                format!("namespace `{}` has no fence record", self.namespace),
            ));
        };
        if record.operation_id != operation_id {
            return Err(FenceError::new(
                FenceOutcome::FenceOwnedByAnotherOperation,
                format!(
                    "the fence of namespace `{}` is owned by operation {}, not by operation \
                     {operation_id}",
                    self.namespace, record.operation_id
                ),
            ));
        }
        if record.revision != expected_revision {
            return Err(FenceError::new(
                FenceOutcome::FenceRevisionMismatch,
                format!(
                    "the fence of namespace `{}` is at revision {}, not at the expected revision \
                     {expected_revision}",
                    self.namespace, record.revision
                ),
            ));
        }
        if !purpose.admits(record.state) {
            return Err(FenceError::new(
                FenceOutcome::OperationCapabilityRequired,
                format!(
                    "namespace `{}` is in {}, which admits no new {} capability",
                    self.namespace,
                    record.state,
                    purpose.as_str()
                ),
            ));
        }
        let cap = MigrationCapability::issue(
            self.namespace.clone(),
            operation_id,
            purpose,
            record.revision,
        );
        drop(gate);
        caps.live.insert(cap.id(), cap.clone());
        tracing::debug!(
            namespace = %self.namespace,
            %operation_id,
            capability = %cap.id(),
            purpose = purpose.as_str(),
            revision = cap.fence_revision(),
            "issued migration capability"
        );
        Ok(cap)
    }

    /// Revoke a capability: nothing is admitted under it any more.
    pub fn revoke_capability(&self, id: Uuid) {
        self.capabilities.lock().live.remove(&id);
    }

    /// Whether `id` was issued by this controller and is neither revoked nor invalidated by a
    /// transition.
    pub fn capability_is_live(&self, id: Uuid) -> bool {
        self.capabilities.lock().live.contains_key(&id)
    }

    /// Admit one import call under `cap`, counted until the returned guard is dropped. The
    /// capability is checked against the gate under the capability lock, so an import call is
    /// either refused by a seal that closed admission before it, or counted by the seal, which
    /// reads the count only after closing admission (section 10.2).
    pub fn begin_import_write(
        self: &Arc<Self>,
        cap: &MigrationCapability,
    ) -> Result<ImportWriter, FenceError> {
        if cap.namespace() != &self.namespace || cap.purpose() != CapabilityPurpose::Import {
            return Err(FenceError::new(
                FenceOutcome::OperationCapabilityRequired,
                format!(
                    "a {} capability for namespace `{}` does not admit imports into `{}`",
                    cap.purpose().as_str(),
                    cap.namespace(),
                    self.namespace
                ),
            ));
        }
        let mut caps = self.capabilities.lock();
        {
            let gate = self.gate.borrow();
            gate.permits(OperationClass::CapabilityImport)?;
            cap.check(&gate.fence)?;
        }
        if !caps.live.contains_key(&cap.id()) {
            return Err(revoked(cap));
        }
        caps.import_writers += 1;
        Ok(ImportWriter {
            controller: self.clone(),
        })
    }

    pub(super) fn end_import_write(&self) {
        {
            let mut caps = self.capabilities.lock();
            caps.import_writers = caps.import_writers.saturating_sub(1);
        }
        self.import_released.notify_waiters();
    }

    /// The import calls running now.
    pub fn import_writers(&self) -> usize {
        self.capabilities.lock().import_writers
    }

    /// The capabilities issued and still live.
    pub fn live_capabilities(&self) -> usize {
        self.capabilities.lock().live.len()
    }

    /// Notified whenever an import call ends. Enable the notification before checking
    /// [`import_writers`](Self::import_writers), so an end in between is not missed.
    pub(crate) fn import_released(&self) -> &Notify {
        &self.import_released
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
    /// whenever the state, the owning operation, the indeterminate flag, the installing gate or
    /// the target-creation gate changes. Every publication removes the read-closing gate: the
    /// commit that follows it either persists the read fence or proves that nothing changed.
    /// A publication with a fence also removes the target-creation gate, which the committed
    /// record replaces; one without keeps it.
    fn publish(
        &self,
        fence: Option<StoredFence>,
        indeterminate: Option<CommandKey>,
        installing: Option<CommandKey>,
    ) {
        let creating_target = if fence.is_some() {
            None
        } else {
            self.gate.borrow().creating_target
        };
        self.publish_gate(fence, indeterminate, installing, creating_target);
    }

    fn publish_gate(
        &self,
        fence: Option<StoredFence>,
        indeterminate: Option<CommandKey>,
        installing: Option<CommandKey>,
        creating_target: Option<CommandKey>,
    ) {
        let fence_published = fence.is_some();
        let mut generation_changed = false;
        self.gate.send_modify(|gate| {
            let fence = fence.unwrap_or_else(|| gate.fence.clone());
            let changed = fence.state() != gate.fence.state()
                || fence.record().map(|r| r.operation_id)
                    != gate.fence.record().map(|r| r.operation_id)
                || indeterminate != gate.indeterminate
                || installing != gate.installing
                || creating_target != gate.creating_target;
            gate.fence = fence;
            gate.indeterminate = indeterminate;
            gate.installing = installing;
            gate.creating_target = creating_target;
            gate.closing_reads = None;
            if changed {
                gate.write_generation += 1;
                generation_changed = true;
            }
        });
        {
            let gate = self.gate.borrow();
            tracing::debug!(
                namespace = %self.namespace,
                state = %gate.state(),
                revision = gate.revision(),
                write_generation = gate.write_generation,
                indeterminate = gate.indeterminate.is_some(),
                installing = gate.installing.is_some(),
                creating_target = gate.creating_target.is_some(),
                "published namespace fence gate"
            );
        }
        // A published transition invalidates every capability issued against an earlier state,
        // owner or revision. Cloned first: the capability lock is never taken under a gate
        // borrow.
        if fence_published {
            let fence = self.gate.borrow().fence.clone();
            self.capabilities
                .lock()
                .live
                .retain(|_, cap| cap.matches(&fence));
        }
        // After the gate is published, so that every woken writer re-checks against it.
        if generation_changed {
            self.write_queues.lock().retain(|wake| wake());
        }
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

    /// Publish the in-memory `INSTALLING` gate for the closing command `key` (section 8.3,
    /// step 2): write admission closes and the write generation moves, which wakes the write
    /// queues. It is replaced by whatever the command's commit publishes, or removed with
    /// [`remove_installing`](Self::remove_installing) when the command is proven not to have
    /// committed.
    pub fn install_closing_gate(&mut self, key: CommandKey) {
        let indeterminate = self.controller.gate.borrow().indeterminate;
        self.controller.publish(None, indeterminate, Some(key));
    }

    /// Remove the `INSTALLING` gate of a command that was proven not to have committed. The
    /// write generation moves again, so nothing admitted before it closed can write.
    pub fn remove_installing(&mut self) {
        let (indeterminate, installing) = {
            let gate = self.controller.gate.borrow();
            (gate.indeterminate, gate.installing)
        };
        if installing.is_some() {
            self.controller.publish(None, indeterminate, None);
        }
    }

    /// Publish the in-memory target-creation gate for `CreateTargetQuarantined` `key` (section
    /// 10.1): until the command's commit publishes the quarantined record, every class but
    /// maintenance and observability is refused and the namespace is not set up. It is removed
    /// with [`remove_creating_target`](Self::remove_creating_target) when the command is proven
    /// not to have committed, and kept (with the indeterminate flag) when its outcome is
    /// unknown.
    pub fn install_creating_target(&mut self, key: CommandKey) {
        let (indeterminate, installing) = {
            let gate = self.controller.gate.borrow();
            (gate.indeterminate, gate.installing)
        };
        self.controller
            .publish_gate(None, indeterminate, installing, Some(key));
    }

    /// Remove the target-creation gate of a command that was proven not to have committed.
    pub fn remove_creating_target(&mut self) {
        let (indeterminate, installing, creating) = {
            let gate = self.controller.gate.borrow();
            (gate.indeterminate, gate.installing, gate.creating_target)
        };
        if creating.is_some() {
            self.controller
                .publish_gate(None, indeterminate, installing, None);
        }
    }

    /// Publish the in-memory read-closing gate for `SetSourceReadFence` `key` (section 9,
    /// step 2): new SQL programs, dumps, replication calls and ATTACHes of the namespace are
    /// refused with `MIGRATION_READ_FENCED`. A read lease is only ever taken after checking the
    /// gate under the lease lock, so every lease taken once this returns was refused, and the
    /// drain only has to wait for the leases already held. It is replaced by whatever the
    /// command's commit publishes, or removed with
    /// [`reopen_read_admission`](Self::reopen_read_admission) when the command is proven not to
    /// have committed.
    pub fn close_read_admission(&mut self, key: CommandKey) {
        self.controller
            .gate
            .send_modify(|gate| gate.closing_reads = Some(key));
        tracing::debug!(
            namespace = %self.controller.namespace,
            operation_id = %key.0,
            command_id = %key.1,
            "closed namespace read admission"
        );
    }

    /// Remove the read-closing gate of a command that was proven not to have committed.
    pub fn reopen_read_admission(&mut self) {
        self.controller.gate.send_if_modified(|gate| {
            let was_closing = gate.closing_reads.is_some();
            gate.closing_reads = None;
            was_closing
        });
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

        let result = match controller.hook(HookPoint::BeforeMetastoreCommit).await {
            HookOutcome::Continue => run.await,
            HookOutcome::Fail(e) => return Err(e.into()),
            // A commit that failed without applying, but whose outcome the controller cannot
            // know (test hook).
            HookOutcome::Indeterminate => {
                Err(indeterminate(key, "the commit was not acknowledged (test hook)").into())
            }
        };

        let result = match result {
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
                controller.publish(commit.record.clone().map(StoredFence::Record), None, None);
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
                controller.publish(None, Some(key), None);
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

fn revoked(cap: &MigrationCapability) -> FenceError {
    FenceError::new(
        FenceOutcome::OperationCapabilityRequired,
        format!(
            "the {} capability {} of operation {} on namespace `{}` was revoked or was never \
             issued by this server",
            cap.purpose().as_str(),
            cap.id(),
            cap.operation_id(),
            cap.namespace()
        ),
    )
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

/// The read leases of one running program ([`FenceConnState::begin_read_program`]), released
/// when dropped.
#[derive(Debug)]
pub struct ProgramReadLease {
    conn: Arc<FenceConnState>,
    lease: ReadLease,
}

impl ProgramReadLease {
    /// Whether the read drain cancelled the program at its deadline.
    pub fn cancelled_by_fence(&self) -> bool {
        self.lease.cancelled_by_fence()
            || self
                .conn
                .attached_leases
                .lock()
                .iter()
                .any(ReadLease::cancelled_by_fence)
    }
}

impl Drop for ProgramReadLease {
    fn drop(&mut self) {
        let attached = std::mem::take(&mut *self.conn.attached_leases.lock());
        drop(attached);
    }
}

/// The fence state of one connection, shared by its WAL wrapper and its `CoreConnection`
/// (section 7.4).
///
/// - A program (a `CoreConnection::run`, a `with_raw` call, a vacuum) starts with
///   [`begin_program`](Self::begin_program), which records the generation it was admitted under.
/// - The WAL wrapper calls [`begin_read_txn`](Self::begin_read_txn) whenever SQLite opens a read
///   transaction, and [`admit_write`](Self::admit_write) in `begin_write_txn` before it queues for
///   the write slot. A refusal leaves its typed outcome in the denial slot, which the program
///   layer takes to report the fence error instead of the bare `SQLITE_AUTH` the WAL returns.
#[derive(Debug)]
pub struct FenceConnState {
    controller: Arc<FenceController>,
    class: OperationClass,
    /// The migration capability this connection works under, fixed at construction. Only a
    /// connection opened for an import or validation session has one.
    capability: Option<MigrationCapability>,
    /// The write generation the current program was admitted under.
    program_generation: AtomicU64,
    /// The write generation the current read transaction was opened under.
    txn_generation: AtomicU64,
    /// The typed outcome of the last refusal at the WAL.
    denial: Mutex<Option<FenceError>>,
    /// The connection's cancel flag (its progress handler interrupts the running statement
    /// while it is set), through which the read drain cancels a program at its deadline.
    cancel: std::sync::OnceLock<Arc<AtomicBool>>,
    /// The namespaces attached on this connection, by schema alias. An attachment outlives the
    /// program that made it, so every later program takes a read lease on each of them too.
    attached: Mutex<Vec<(String, Arc<FenceController>)>>,
    /// The read leases the running program holds on attached namespaces.
    attached_leases: Mutex<Vec<ReadLease>>,
}

impl FenceConnState {
    pub fn new(controller: Arc<FenceController>, class: OperationClass) -> Arc<Self> {
        Self::build(controller, class, None)
    }

    /// The fence state of a connection that works under `capability` (an import or a
    /// validation session): it is admitted as the capability's class, and only while the
    /// capability is valid.
    pub fn with_capability(
        controller: Arc<FenceController>,
        capability: MigrationCapability,
    ) -> Arc<Self> {
        let class = capability.class();
        Self::build(controller, class, Some(capability))
    }

    fn build(
        controller: Arc<FenceController>,
        class: OperationClass,
        capability: Option<MigrationCapability>,
    ) -> Arc<Self> {
        let generation = controller.write_generation();
        Arc::new(Self {
            controller,
            class,
            capability,
            program_generation: AtomicU64::new(generation),
            txn_generation: AtomicU64::new(generation),
            denial: Mutex::new(None),
            cancel: std::sync::OnceLock::new(),
            attached: Mutex::new(Vec::new()),
            attached_leases: Mutex::new(Vec::new()),
        })
    }

    /// The flag that cancels the statement running on this connection. Set once, by the
    /// connection that owns this state.
    pub fn set_cancel_flag(&self, flag: Arc<AtomicBool>) {
        let _ = self.cancel.set(flag);
    }

    /// The class this connection's reads are admitted as: a normal connection reads as
    /// `NormalRead`; a capability connection reads under its capability.
    pub fn read_class(&self) -> OperationClass {
        match self.class {
            OperationClass::NormalWrite => OperationClass::NormalRead,
            class => class,
        }
    }

    fn lease_canceller(&self) -> impl Fn() + Send + Sync + 'static {
        let flag = self.cancel.get().cloned();
        move || {
            if let Some(flag) = &flag {
                flag.store(true, Ordering::Relaxed);
            }
        }
    }

    /// Admit a program for reading and hold its read leases until the returned guard is
    /// dropped (section 9): one on this connection's namespace and one on each namespace
    /// attached on the connection. `still_attached` lists the aliases attached on the
    /// connection now (it is only asked when [`attach`](Self::attach) recorded one); `None`
    /// keeps every recorded attachment.
    pub fn begin_read_program(
        self: &Arc<Self>,
        still_attached: impl FnOnce() -> Option<Vec<String>>,
    ) -> Result<ProgramReadLease, FenceError> {
        let lease = self.controller.acquire_read_lease(
            self.read_class(),
            LeaseKind::Sql,
            self.lease_canceller(),
        )?;
        let guard = ProgramReadLease {
            conn: self.clone(),
            lease,
        };
        let attached = {
            let mut attached = self.attached.lock();
            if !attached.is_empty() {
                if let Some(live) = still_attached() {
                    attached.retain(|(alias, _)| live.iter().any(|a| a == alias));
                }
            }
            attached.clone()
        };
        for (_, controller) in attached {
            let lease = controller.acquire_read_lease(
                OperationClass::NormalRead,
                LeaseKind::Sql,
                self.lease_canceller(),
            )?;
            self.attached_leases.lock().push(lease);
        }
        Ok(guard)
    }

    /// The running program is attaching `controller`'s namespace as `alias`: admit it as a
    /// normal read of that namespace, hold a lease on it for the rest of the program, and
    /// remember the attachment for the connection's later programs.
    pub fn attach(&self, alias: &str, controller: Arc<FenceController>) -> Result<(), FenceError> {
        let lease = controller.acquire_read_lease(
            OperationClass::NormalRead,
            LeaseKind::Sql,
            self.lease_canceller(),
        )?;
        self.attached_leases.lock().push(lease);
        let mut attached = self.attached.lock();
        attached.retain(|(a, _)| a != alias);
        attached.push((alias.to_owned(), controller));
        Ok(())
    }

    pub fn controller(&self) -> &Arc<FenceController> {
        &self.controller
    }

    pub fn class(&self) -> OperationClass {
        self.class
    }

    pub fn capability(&self) -> Option<&MigrationCapability> {
        self.capability.as_ref()
    }

    pub fn program_generation(&self) -> u64 {
        self.program_generation.load(Ordering::Acquire)
    }

    pub fn txn_generation(&self) -> u64 {
        self.txn_generation.load(Ordering::Acquire)
    }

    /// Start a program on this connection: record the generation it is admitted under and
    /// forget any denial a previous program left behind. Returns that generation.
    pub fn begin_program(&self) -> u64 {
        let generation = self.controller.write_generation();
        self.program_generation.store(generation, Ordering::Release);
        *self.denial.lock() = None;
        generation
    }

    /// SQLite is opening a new read transaction on this connection: record the generation it
    /// is opened under. A later upgrade of that transaction to a write transaction must happen
    /// under the same generation.
    pub fn begin_read_txn(&self) {
        self.txn_generation
            .store(self.controller.write_generation(), Ordering::Release);
    }

    /// The authoritative write admission (section 8.1, check 2): the live gate permits this
    /// connection's class, the program and its read transaction were both admitted under the
    /// gate's current write generation, and a capability connection's capability is still the
    /// valid one (the fence's state, owner and revision are the ones it was issued at, and it
    /// is live). A validation connection never writes. On refusal the typed outcome is left in
    /// the denial slot and returned.
    pub fn admit_write(&self) -> Result<(), FenceError> {
        let result = self
            .admit_write_under_gate()
            .and_then(|()| match &self.capability {
                // Outside the gate borrow: the capability lock is never taken under one.
                Some(cap) if !self.controller.capability_is_live(cap.id()) => Err(revoked(cap)),
                _ => Ok(()),
            });
        if let Err(e) = &result {
            tracing::debug!(
                namespace = %self.controller.namespace,
                class = ?self.class,
                "write transaction refused by the namespace fence: {e}"
            );
            *self.denial.lock() = Some(e.clone());
        }
        result
    }

    fn admit_write_under_gate(&self) -> Result<(), FenceError> {
        let gate = self.controller.gate.borrow();
        gate.permits(self.class)?;
        let current = gate.write_generation;
        let program = self.program_generation();
        let txn = self.txn_generation();
        if program != current || txn != current {
            return Err(FenceError::new(
                FenceOutcome::MigrationWriteFenced,
                format!(
                    "the namespace fence changed after this transaction began (program admitted \
                     at generation {program}, transaction opened at generation {txn}, current \
                     generation {current}); roll back and begin a new transaction"
                ),
            )
            .with_detail(FenceDetail::StaleTransaction));
        }
        match (self.class, &self.capability) {
            (OperationClass::CapabilityValidate, _) => Err(FenceError::new(
                FenceOutcome::OperationCapabilityRequired,
                "a validation capability admits reads only",
            )),
            (_, Some(cap)) => cap.check(&gate.fence),
            (OperationClass::CapabilityImport, None) => Err(FenceError::new(
                FenceOutcome::OperationCapabilityRequired,
                "an import write needs a migration capability",
            )),
            _ => Ok(()),
        }
    }

    /// Take the typed outcome of the last refusal at the WAL, if any.
    pub fn take_denial(&self) -> Option<FenceError> {
        self.denial.lock().take()
    }
}

#[cfg(test)]
pub(crate) mod tests {
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
    pub(crate) const OP: Uuid = Uuid::from_u128(0xa);
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

    pub(crate) fn ctx() -> FenceContext {
        FenceContext::now(
            ServerIdentity {
                build: "test".into(),
                instance_id: Uuid::from_u128(0x99),
            },
            Some(LOG),
        )
    }

    pub(crate) fn acquire(ns: &'static str, op: Uuid, command_id: u128) -> FenceRequest {
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

    pub(crate) fn release(
        ns: &'static str,
        op: Uuid,
        command_id: u128,
        revision: u64,
    ) -> FenceRequest {
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
    pub(crate) async fn fence_source(
        meta: &MetaStore,
        controller: &Arc<FenceController>,
        op: Uuid,
    ) {
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
                        frame_no: Some(0),
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

    /// Registered write queues are woken after every change of the write generation, and only
    /// then; a waker whose manager is gone is forgotten.
    #[tokio::test]
    async fn write_queues_are_woken_on_every_generation_change() {
        let tmp = tempdir().unwrap();
        let meta = open_metastore(tmp.path()).await;
        create_namespace(&meta, "ns").await;
        let controller = FenceController::unfenced("ns".into());

        let woken = Arc::new(AtomicU64::new(0));
        let seen_generation = Arc::new(AtomicU64::new(0));
        controller.register_write_queue(Box::new({
            let woken = woken.clone();
            let seen_generation = seen_generation.clone();
            let controller = Arc::downgrade(&controller);
            move || {
                // The gate is already published when the queue is woken.
                if let Some(c) = controller.upgrade() {
                    seen_generation.store(c.write_generation(), Ordering::SeqCst);
                }
                woken.fetch_add(1, Ordering::SeqCst);
                true
            }
        }));
        let gone = Arc::new(AtomicU64::new(0));
        controller.register_write_queue(Box::new({
            let gone = gone.clone();
            move || {
                gone.fetch_add(1, Ordering::SeqCst);
                false
            }
        }));
        assert_eq!(controller.write_queues.lock().len(), 2);

        fence_source(&meta, &controller, OP).await;
        assert_eq!(woken.load(Ordering::SeqCst), 2);
        assert_eq!(seen_generation.load(Ordering::SeqCst), 2);
        assert_eq!(gone.load(Ordering::SeqCst), 1);
        assert_eq!(controller.write_queues.lock().len(), 1);

        // A replay does not move the generation and wakes nobody.
        let revision = controller.gate().revision();
        controller
            .apply_command(&meta, release("ns", OP, 2, revision), ctx())
            .await
            .unwrap();
        assert_eq!(woken.load(Ordering::SeqCst), 3);
        controller
            .apply_command(&meta, release("ns", OP, 2, revision), ctx())
            .await
            .unwrap();
        assert_eq!(woken.load(Ordering::SeqCst), 3);
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
        controller.publish(None, Some((OP, Uuid::from_u128(1))), None);
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
        controller.publish(None, Some((OP, OP)), None);
        controller.publish(None, None, None);
        let state = FenceConnState::new(controller.clone(), OperationClass::NormalWrite);
        assert_eq!(state.program_generation(), 2);
        assert_eq!(state.txn_generation(), 2);
        assert!(Arc::ptr_eq(state.controller(), &controller));
        assert_eq!(state.class(), OperationClass::NormalWrite);
        assert!(state.take_denial().is_none());
    }
}
