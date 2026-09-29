//! The pure fence transition function (`docs/NAMESPACE_FENCE.md` sections 3.2 and 5.3).
//!
//! [`apply`] decides what a command does to a namespace's fence, given everything the store
//! read inside its transaction. It performs no I/O, takes no locks and reads no clock: the
//! store supplies the current record, the stored receipt for the request's
//! `(operation_id, command_id)` if there is one, and the facts in [`ApplyEnv`]. The store
//! persists whatever [`Decision::Apply`] returns, in one transaction, before anything is
//! published or answered.
//!
//! Checks run in this order, and the order is part of the contract:
//!
//! 1. **Replay.** A stored receipt with the same fingerprint is answered from the receipt
//!    (`Replay`, or `Resume` for a drain still in progress), whatever has happened to the
//!    record since. A stored receipt with a different fingerprint is `FENCE_COMMAND_CONFLICT`.
//! 2. **Unavailable state.** A record the server cannot establish refuses everything with
//!    `FENCE_STATE_UNAVAILABLE`, except the two commands that can reconcile it: a replay of the
//!    `CreateTargetQuarantined` that left the marker, and an adoption after a metastore
//!    rollback.
//! 3. **Owner.** An unfinished record owned by another operation is
//!    `FENCE_OWNED_BY_ANOTHER_OPERATION`.
//! 4. **Already applied.** A command from the owner whose goal state the record is already in
//!    is `ALREADY_APPLIED`: a receipt is stored, the record and its revision do not change.
//!    This is checked before the revision, because the caller's stated expectation is
//!    typically the state before a response it never received.
//! 5. **Transition.** Role, then legality of the transition from the current state
//!    (`INVALID_FENCE_TRANSITION`).
//! 6. **Expectation.** `expected_state` and `expected_revision` (`FENCE_REVISION_MISMATCH`).
//! 7. **Preconditions** of the command (`FENCE_PRECONDITION_FAILED`).
//!
//! A drain that starts in `apply` (`DRAINING`) is finished by [`complete_drain`], once the
//! controller has proven that the work admitted earlier has ended.

use uuid::Uuid;

use super::command::{
    AdoptArgs, CommandKind, FenceCommand, FenceRequest, ValidationResult,
    MAX_VALIDATION_SUMMARY_BYTES,
};
use super::outcome::{FenceDetail, FenceError, FenceOutcome};
use super::record::{
    Adoption, CommandReceipt, FrozenBoundary, LegacyBlocks, NamespaceFenceRecord,
    NamespaceIdentity, ServerIdentity, ValidationRecord, ValidationSnapshot,
};
use super::state::{FenceState, Role};

/// What the store knows about a namespace's fence.
#[derive(Debug, Clone, Copy)]
pub enum CurrentFence<'a> {
    /// No record. `namespace_exists` distinguishes `UNFENCED` from `ABSENT`.
    None {
        namespace_exists: bool,
    },
    Record(&'a NamespaceFenceRecord),
    /// The control state cannot be established. `marker` is the record the namespace's marker
    /// file holds, when it has a readable one.
    Unavailable {
        detail: FenceDetail,
        marker: Option<&'a NamespaceFenceRecord>,
    },
}

impl CurrentFence<'_> {
    pub fn state(&self) -> FenceState {
        match self {
            CurrentFence::None {
                namespace_exists: true,
            } => FenceState::Unfenced,
            CurrentFence::None {
                namespace_exists: false,
            } => FenceState::Absent,
            CurrentFence::Record(r) => r.state,
            CurrentFence::Unavailable { .. } => FenceState::UnknownUnavailable,
        }
    }

    pub fn revision(&self) -> u64 {
        match self {
            CurrentFence::None { .. } => 0,
            CurrentFence::Record(r) => r.revision,
            CurrentFence::Unavailable { marker, .. } => marker.map_or(0, |m| m.revision),
        }
    }
}

/// Facts `apply` needs that are not in the record. The store fills them from inside the same
/// transaction and the live namespace.
#[derive(Debug, Clone)]
pub struct ApplyEnv {
    /// Wall-clock time, in milliseconds since the Unix epoch. Informational only: nothing in
    /// the fence expires.
    pub now_ms: i64,
    pub server: ServerIdentity,
    /// The namespace's current replication log id, if it exists and has one.
    pub namespace_log_id: Option<Uuid>,
    /// Whether the namespace is a shared schema or linked to one.
    pub shared_schema: bool,
    /// The namespace config's current `block_*` values, saved when a source is acquired and
    /// restored when it is released.
    pub legacy_blocks: LegacyBlocks,
    /// A fresh id, used as `target_incarnation_id` by `CreateTargetQuarantined`.
    pub new_incarnation_id: Uuid,
    /// Whether the request carried the configured adoption key.
    pub adoption_authorised: bool,
    /// What the server observed of the target, for `RecordTargetValidation`.
    pub validation_snapshot: Option<ValidationSnapshot>,
}

/// What a command does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The command was applied before and its answer is final: return this receipt, with
    /// `replayed: true`. Nothing is written.
    Replay(CommandReceipt),
    /// The same command started a drain that has not been completed: resume it. Nothing is
    /// written.
    Resume(CommandReceipt),
    /// Persist `record` (when `Some`; `None` leaves the record as it is) and `receipt` in one
    /// transaction, then answer `receipt.outcome`. A `DRAINING` receipt means the controller
    /// must now run the drain and finish it with [`complete_drain`].
    Apply {
        record: Option<NamespaceFenceRecord>,
        receipt: CommandReceipt,
    },
}

/// Evidence, gathered by the controller, that a drain is complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainCompletion {
    /// No normal writer holds or can take the write slot; `boundary` was read with the slot
    /// free, after the last commit published its frame.
    SourceWrites { boundary: FrozenBoundary },
    /// Every SQL, dump and replication read lease has been released.
    SourceReads,
    /// Every import writer has finished and no capability writer holds the slot.
    TargetImport,
}

fn err(outcome: FenceOutcome, message: impl Into<String>) -> FenceError {
    FenceError::new(outcome, message)
}

fn invalid(message: impl Into<String>) -> FenceError {
    err(FenceOutcome::InvalidFenceTransition, message)
}

fn precondition(detail: FenceDetail, message: impl Into<String>) -> FenceError {
    err(FenceOutcome::FencePreconditionFailed, message).with_detail(detail)
}

/// The role a command acts on. `None` for adoption, which acts on either.
fn command_role(kind: CommandKind) -> Option<Role> {
    match kind {
        CommandKind::AcquireSourceWriteFence
        | CommandKind::SetSourceReadFence
        | CommandKind::ClearSourceReadFence
        | CommandKind::ReleaseSourceWriteFence => Some(Role::Source),
        CommandKind::CreateTargetQuarantined
        | CommandKind::SealTargetImport
        | CommandKind::RecordTargetValidation
        | CommandKind::PublishTargetReadableWriteFenced
        | CommandKind::EnableTargetWrites
        | CommandKind::AbortQuarantinedTarget => Some(Role::Target),
        CommandKind::AdoptFence => None,
    }
}

/// The state a legal command moves a record from `from` to, and the receipt outcome. This is
/// the transition graph of section 3.2, minus the drain completions and adoption.
fn transition(kind: CommandKind, from: FenceState) -> Option<(FenceState, FenceOutcome)> {
    use CommandKind as K;
    use FenceOutcome::{Applied, Draining};
    use FenceState as S;

    Some(match (kind, from) {
        (K::AcquireSourceWriteFence, S::Unfenced | S::Released | S::TargetWritable) => {
            (S::SourceDraining, Draining)
        }
        (K::SetSourceReadFence, S::SourceWriteFenced) => (S::SourceReadDraining, Draining),
        (K::ClearSourceReadFence, S::SourceReadDraining | S::SourceReadFenced) => {
            (S::SourceWriteFenced, Applied)
        }
        (K::ReleaseSourceWriteFence, S::SourceDraining | S::SourceWriteFenced) => {
            (S::Released, Applied)
        }
        (K::CreateTargetQuarantined, S::Absent) => (S::TargetQuarantined, Applied),
        (K::SealTargetImport, S::TargetQuarantined) => (S::TargetImportDraining, Draining),
        (K::RecordTargetValidation, S::TargetValidating) => (S::TargetValidating, Applied),
        (K::PublishTargetReadableWriteFenced, S::TargetValidating) => {
            (S::TargetWriteFenced, Applied)
        }
        (K::EnableTargetWrites, S::TargetWriteFenced) => (S::TargetWritable, Applied),
        (
            K::AbortQuarantinedTarget,
            S::TargetQuarantined
            | S::TargetImportDraining
            | S::TargetValidating
            | S::TargetWriteFenced,
        ) => (S::TargetAborted, Applied),
        _ => return None,
    })
}

/// The draining state a command's drain runs in, for commands that drain.
fn drain_state(kind: CommandKind) -> Option<FenceState> {
    match kind {
        CommandKind::AcquireSourceWriteFence => Some(FenceState::SourceDraining),
        CommandKind::SetSourceReadFence => Some(FenceState::SourceReadDraining),
        CommandKind::SealTargetImport => Some(FenceState::TargetImportDraining),
        _ => None,
    }
}

fn receipt(
    request: &FenceRequest,
    env: &ApplyEnv,
    outcome: FenceOutcome,
    revision_before: u64,
    revision_after: u64,
    state_after: FenceState,
) -> CommandReceipt {
    CommandReceipt {
        namespace: request.namespace.clone(),
        operation_id: request.operation_id,
        command_id: request.command_id,
        command: request.command.kind(),
        fingerprint: request.fingerprint(),
        outcome,
        revision_before,
        revision_after,
        state_after,
        applied_at_ms: env.now_ms,
        instance_id: env.server.instance_id,
        adoption: None,
    }
}

/// Decide what `request` does to the namespace's fence. See the module documentation for the
/// order of the checks.
///
/// `existing` is the stored receipt for `(request.namespace, request.operation_id,
/// request.command_id)`, if any.
pub fn apply(
    current: CurrentFence<'_>,
    existing: Option<&CommandReceipt>,
    request: &FenceRequest,
    env: &ApplyEnv,
) -> Result<Decision, FenceError> {
    let kind = request.command.kind();

    // 1. Replay, before anything about the record is looked at.
    if let Some(existing) = existing {
        debug_assert_eq!(existing.operation_id, request.operation_id);
        debug_assert_eq!(existing.command_id, request.command_id);
        if existing.fingerprint != request.fingerprint() {
            return Err(err(
                FenceOutcome::FenceCommandConflict,
                format!(
                    "command {} was already used for a different request",
                    request.command_id
                ),
            ));
        }
        return Ok(if existing.is_final() {
            Decision::Replay(existing.clone())
        } else {
            Decision::Resume(existing.clone())
        });
    }

    // 2. A state the server cannot establish.
    let record = match current {
        CurrentFence::None { .. } => None,
        CurrentFence::Record(record) => Some(record),
        CurrentFence::Unavailable { detail, marker } => {
            return apply_unavailable(detail, marker, request, env);
        }
    };

    if let FenceCommand::AdoptFence(args) = &request.command {
        return apply_adopt(current, record, args, request, env);
    }

    if let Some(record) = record {
        // 3. Owner.
        let finished = record.state.is_operation_finished();
        if !finished && record.operation_id != request.operation_id {
            return Err(err(
                FenceOutcome::FenceOwnedByAnotherOperation,
                format!(
                    "namespace fence is owned by operation {}",
                    record.operation_id
                ),
            ));
        }

        let own = record.operation_id == request.operation_id;

        // 4. Already applied.
        if own && kind.goal_state() == Some(record.state) {
            let receipt = receipt(
                request,
                env,
                FenceOutcome::AlreadyApplied,
                record.revision,
                record.revision,
                record.state,
            );
            return Ok(Decision::Apply {
                record: None,
                receipt,
            });
        }

        // The owner joining its own drain under a new command id (for example after
        // adoption, or after losing the original command id): nothing changes but the receipt,
        // and the controller resumes the drain.
        if own && drain_state(kind) == Some(record.state) {
            check_expectation(current, request)?;
            let receipt = receipt(
                request,
                env,
                FenceOutcome::Draining,
                record.revision,
                record.revision,
                record.state,
            );
            return Ok(Decision::Apply {
                record: None,
                receipt,
            });
        }

        if own && finished {
            return Err(invalid(format!(
                "operation {} has finished with this namespace ({})",
                record.operation_id, record.state
            ))
            .with_detail(FenceDetail::OperationFinished));
        }
    }

    // `CreateTargetQuarantined` needs a name nobody uses, whatever the record says.
    if kind == CommandKind::CreateTargetQuarantined && current.state() != FenceState::Absent {
        return Err(precondition(
            FenceDetail::NamespaceExists,
            "the namespace already exists",
        ));
    }

    // 5. Role and transition.
    let from = current.state();
    let role = command_role(kind).expect("adoption is handled above");
    let current_role = match from {
        // A published target, or a released source, may be acquired as a source by a new
        // operation.
        FenceState::Released | FenceState::TargetWritable | FenceState::Unfenced => {
            Some(Role::Source)
        }
        FenceState::Absent => Some(Role::Target),
        other => other.role(),
    };
    if current_role != Some(role) {
        return Err(
            invalid(format!("{kind} does not apply to a namespace in {from}"))
                .with_detail(FenceDetail::RoleMismatch),
        );
    }
    let Some((to, outcome)) = transition(kind, from) else {
        return Err(invalid(format!("{kind} is not a transition from {from}")));
    };

    // 6. Expectation.
    check_expectation(current, request)?;

    // 7. Preconditions, and the next record.
    let revision_before = current.revision();
    let revision_after = revision_before + 1;
    let mut next = match record {
        Some(record) if !record.state.is_operation_finished() => record.clone(),
        _ => fresh_record(request, env, role),
    };

    match &request.command {
        FenceCommand::AcquireSourceWriteFence {
            expected_log_id,
            drain_policy,
        } => {
            if env.shared_schema {
                return Err(precondition(
                    FenceDetail::SharedSchemaUnsupported,
                    "shared-schema namespaces cannot be fenced",
                ));
            }
            if env.namespace_log_id != Some(*expected_log_id) {
                return Err(precondition(
                    FenceDetail::NamespaceIdentityMismatch,
                    "the namespace's replication log id is not the one the caller observed",
                ));
            }
            next.identity = NamespaceIdentity {
                log_id: Some(*expected_log_id),
                target_incarnation_id: None,
            };
            next.legacy_blocks = env.legacy_blocks.clone();
            next.drain_policy = *drain_policy;
            next.drain_started_at_ms = Some(env.now_ms);
        }
        FenceCommand::SetSourceReadFence { drain_policy }
        | FenceCommand::SealTargetImport { drain_policy } => {
            next.drain_policy = *drain_policy;
            next.drain_started_at_ms = Some(env.now_ms);
        }
        FenceCommand::ClearSourceReadFence
        | FenceCommand::ReleaseSourceWriteFence
        | FenceCommand::EnableTargetWrites
        | FenceCommand::AbortQuarantinedTarget => {
            next.drain_policy = None;
            next.drain_started_at_ms = None;
        }
        FenceCommand::CreateTargetQuarantined { .. } => {
            next.identity = NamespaceIdentity {
                log_id: None,
                target_incarnation_id: Some(env.new_incarnation_id),
            };
            next.legacy_blocks = LegacyBlocks::default();
        }
        FenceCommand::RecordTargetValidation { result, summary } => {
            if summary.len() > MAX_VALIDATION_SUMMARY_BYTES {
                return Err(precondition(
                    FenceDetail::InvalidArgument,
                    format!(
                        "validation summary is longer than {MAX_VALIDATION_SUMMARY_BYTES} bytes"
                    ),
                ));
            }
            next.validation = Some(ValidationRecord {
                operation_id: request.operation_id,
                command_id: request.command_id,
                result: *result,
                summary: summary.clone(),
                snapshot: env.validation_snapshot,
                recorded_at_ms: env.now_ms,
            });
        }
        FenceCommand::PublishTargetReadableWriteFenced => {
            let validated = next.validation.as_ref().is_some_and(|v| {
                v.result == ValidationResult::Ok && v.operation_id == next.operation_id
            });
            if !validated {
                return Err(precondition(
                    FenceDetail::ValidationReceiptRequired,
                    "publication requires a successful validation receipt from the owning operation",
                ));
            }
        }
        FenceCommand::AdoptFence(_) => unreachable!("handled above"),
    }

    next.state = to;
    next.revision = revision_after;
    next.last_transition_at_ms = env.now_ms;
    next.last_command_id = request.command_id;
    next.written_by = env.server.clone();

    let receipt = receipt(request, env, outcome, revision_before, revision_after, to);
    Ok(Decision::Apply {
        record: Some(next),
        receipt,
    })
}

/// A record for an operation that is starting on this namespace.
fn fresh_record(request: &FenceRequest, env: &ApplyEnv, role: Role) -> NamespaceFenceRecord {
    NamespaceFenceRecord {
        namespace: request.namespace.clone(),
        role,
        state: FenceState::Unfenced,
        revision: 0,
        operation_id: request.operation_id,
        identity: NamespaceIdentity::default(),
        drain_policy: None,
        drain_started_at_ms: None,
        frozen_boundary: None,
        validation: None,
        legacy_blocks: LegacyBlocks::default(),
        created_at_ms: env.now_ms,
        last_transition_at_ms: env.now_ms,
        last_command_id: request.command_id,
        written_by: env.server.clone(),
        adoptions: Vec::new(),
    }
}

fn check_expectation(current: CurrentFence<'_>, request: &FenceRequest) -> Result<(), FenceError> {
    let (state, revision) = (current.state(), current.revision());
    if request.expected_state != state || request.expected_revision != revision {
        return Err(err(
            FenceOutcome::FenceRevisionMismatch,
            format!(
                "expected {} at revision {}, found {} at revision {}",
                request.expected_state, request.expected_revision, state, revision
            ),
        ));
    }
    Ok(())
}

fn apply_unavailable(
    detail: FenceDetail,
    marker: Option<&NamespaceFenceRecord>,
    request: &FenceRequest,
    env: &ApplyEnv,
) -> Result<Decision, FenceError> {
    let unavailable = || {
        err(
            FenceOutcome::FenceStateUnavailable,
            "the namespace's fence state cannot be established",
        )
        .with_detail(detail)
    };

    match (&request.command, detail, marker) {
        // A crash between writing the marker and committing the target's rows: only the same
        // command completes the creation.
        (
            FenceCommand::CreateTargetQuarantined { .. },
            FenceDetail::IncompleteTargetCreation,
            Some(m),
        ) if m.state == FenceState::TargetQuarantined
            && m.revision == 1
            && m.operation_id == request.operation_id
            && m.last_command_id == request.command_id =>
        {
            let decision = apply(
                CurrentFence::None {
                    namespace_exists: false,
                },
                None,
                request,
                &ApplyEnv {
                    new_incarnation_id: m
                        .identity
                        .target_incarnation_id
                        .unwrap_or(env.new_incarnation_id),
                    ..env.clone()
                },
            )?;
            Ok(decision)
        }
        // The metastore went backwards: adoption re-establishes the record the marker last
        // recorded (it is written only after a commit), under the adopting operation.
        (FenceCommand::AdoptFence(args), FenceDetail::MetastoreBehindMarker, Some(m)) => {
            apply_adopt(CurrentFence::Record(m), Some(m), args, request, env)
        }
        _ => Err(unavailable()),
    }
}

fn apply_adopt(
    current: CurrentFence<'_>,
    record: Option<&NamespaceFenceRecord>,
    args: &AdoptArgs,
    request: &FenceRequest,
    env: &ApplyEnv,
) -> Result<Decision, FenceError> {
    let Some(record) = record else {
        return Err(invalid("there is no fence to adopt"));
    };
    if record.state.is_operation_finished() {
        return Err(
            invalid(format!("a fence in {} cannot be adopted", record.state))
                .with_detail(FenceDetail::OperationFinished),
        );
    }
    if args.current_operation_id != record.operation_id {
        return Err(err(
            FenceOutcome::FenceOwnedByAnotherOperation,
            format!(
                "namespace fence is owned by operation {}",
                record.operation_id
            ),
        ));
    }
    if request.operation_id == record.operation_id {
        return Err(invalid("an operation cannot adopt its own fence"));
    }
    check_expectation(current, request)?;
    if !env.adoption_authorised {
        return Err(precondition(
            FenceDetail::AdoptionNotAuthorised,
            "adoption requires the configured adoption key",
        ));
    }
    let approvers: Vec<&str> = args.approvers.iter().map(|a| a.trim()).collect();
    let two_distinct = approvers.len() == 2
        && approvers.iter().all(|a| !a.is_empty())
        && approvers[0] != approvers[1];
    if !two_distinct || args.incident_ref.trim().is_empty() || args.reason.trim().is_empty() {
        return Err(precondition(
            FenceDetail::AdoptionNotAuthorised,
            "adoption requires two distinct approvers, an incident reference and a reason",
        ));
    }

    let revision_after = record.revision + 1;
    let adoption = Adoption {
        previous_operation_id: record.operation_id,
        new_operation_id: request.operation_id,
        command_id: request.command_id,
        approvers: args.approvers.clone(),
        incident_ref: args.incident_ref.clone(),
        reason: args.reason.clone(),
        at_ms: env.now_ms,
        revision: revision_after,
    };

    // Ownership changes and nothing else: the state, and so every gate, stays as it was.
    let mut next = record.clone();
    next.operation_id = request.operation_id;
    next.revision = revision_after;
    next.last_transition_at_ms = env.now_ms;
    next.last_command_id = request.command_id;
    next.written_by = env.server.clone();
    next.adoptions.push(adoption.clone());

    let mut receipt = receipt(
        request,
        env,
        FenceOutcome::Applied,
        record.revision,
        revision_after,
        record.state,
    );
    receipt.adoption = Some(adoption);
    Ok(Decision::Apply {
        record: Some(next),
        receipt,
    })
}

/// Finish a drain that `apply` started. `receipt` is the owning operation's `DRAINING` receipt
/// for it; the returned receipt replaces it (same key) with the final `APPLIED` answer.
pub fn complete_drain(
    record: &NamespaceFenceRecord,
    receipt: &CommandReceipt,
    completion: DrainCompletion,
    env: &ApplyEnv,
) -> Result<(NamespaceFenceRecord, CommandReceipt), FenceError> {
    if receipt.outcome != FenceOutcome::Draining || receipt.operation_id != record.operation_id {
        return Err(invalid(
            "there is no drain of the owning operation to complete",
        ));
    }

    let (from, to) = match completion {
        DrainCompletion::SourceWrites { .. } => {
            (FenceState::SourceDraining, FenceState::SourceWriteFenced)
        }
        DrainCompletion::SourceReads => {
            (FenceState::SourceReadDraining, FenceState::SourceReadFenced)
        }
        DrainCompletion::TargetImport => (
            FenceState::TargetImportDraining,
            FenceState::TargetValidating,
        ),
    };
    if record.state != from || drain_state(receipt.command) != Some(from) {
        return Err(invalid(format!(
            "{} cannot complete a drain from {}",
            receipt.command, record.state
        )));
    }

    let mut next = record.clone();
    if let DrainCompletion::SourceWrites { boundary } = completion {
        if record.identity.log_id != Some(boundary.log_id) {
            return Err(precondition(
                FenceDetail::NamespaceIdentityMismatch,
                "the frozen boundary belongs to a different replication log",
            ));
        }
        next.frozen_boundary = Some(boundary);
    }
    next.state = to;
    next.revision = record.revision + 1;
    next.drain_policy = None;
    next.drain_started_at_ms = None;
    next.last_transition_at_ms = env.now_ms;
    next.last_command_id = receipt.command_id;
    next.written_by = env.server.clone();

    let mut final_receipt = receipt.clone();
    final_receipt.outcome = FenceOutcome::Applied;
    final_receipt.revision_after = next.revision;
    final_receipt.state_after = to;
    final_receipt.applied_at_ms = env.now_ms;
    final_receipt.instance_id = env.server.instance_id;

    Ok((next, final_receipt))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::namespace::fence::command::{DrainPolicy, OnDeadline, TargetConfig};
    use crate::namespace::fence::record::{FenceMarker, FENCE_FORMAT_VERSION};
    use crate::namespace::NamespaceName;

    use FenceOutcome as O;
    use FenceState as S;

    const LOG: Uuid = Uuid::from_u128(0x10);
    const INCARNATION: Uuid = Uuid::from_u128(0x20);
    const OP: Uuid = Uuid::from_u128(0xa);
    const OTHER_OP: Uuid = Uuid::from_u128(0xb);

    fn env() -> ApplyEnv {
        ApplyEnv {
            now_ms: 1_000,
            server: ServerIdentity {
                build: "test".into(),
                instance_id: Uuid::from_u128(0x99),
            },
            namespace_log_id: Some(LOG),
            shared_schema: false,
            legacy_blocks: LegacyBlocks::default(),
            new_incarnation_id: INCARNATION,
            adoption_authorised: false,
            validation_snapshot: None,
        }
    }

    fn policy() -> Option<DrainPolicy> {
        Some(DrainPolicy {
            deadline_ms: 1_000,
            on_deadline: OnDeadline::Fail,
        })
    }

    fn command(kind: CommandKind) -> FenceCommand {
        match kind {
            CommandKind::AcquireSourceWriteFence => FenceCommand::AcquireSourceWriteFence {
                expected_log_id: LOG,
                drain_policy: policy(),
            },
            CommandKind::SetSourceReadFence => FenceCommand::SetSourceReadFence {
                drain_policy: policy(),
            },
            CommandKind::ClearSourceReadFence => FenceCommand::ClearSourceReadFence,
            CommandKind::ReleaseSourceWriteFence => FenceCommand::ReleaseSourceWriteFence,
            CommandKind::CreateTargetQuarantined => FenceCommand::CreateTargetQuarantined {
                config: TargetConfig::default(),
            },
            CommandKind::SealTargetImport => FenceCommand::SealTargetImport {
                drain_policy: policy(),
            },
            CommandKind::RecordTargetValidation => FenceCommand::RecordTargetValidation {
                result: ValidationResult::Ok,
                summary: "row counts match".into(),
            },
            CommandKind::PublishTargetReadableWriteFenced => {
                FenceCommand::PublishTargetReadableWriteFenced
            }
            CommandKind::EnableTargetWrites => FenceCommand::EnableTargetWrites,
            CommandKind::AbortQuarantinedTarget => FenceCommand::AbortQuarantinedTarget,
            CommandKind::AdoptFence => FenceCommand::AdoptFence(AdoptArgs {
                current_operation_id: OP,
                approvers: vec!["alice".into(), "bob".into()],
                incident_ref: "INC-1".into(),
                reason: "control plane lost".into(),
            }),
        }
    }

    /// A little driver that plays the store: it keeps the record and receipts and applies
    /// decisions the way the store will.
    #[derive(Default)]
    struct Harness {
        namespace_exists: bool,
        record: Option<NamespaceFenceRecord>,
        receipts: Vec<CommandReceipt>,
        next_command: u128,
    }

    impl Harness {
        fn source() -> Self {
            Self {
                namespace_exists: true,
                ..Default::default()
            }
        }

        fn target() -> Self {
            Self::default()
        }

        fn current(&self) -> CurrentFence<'_> {
            match &self.record {
                Some(r) => CurrentFence::Record(r),
                None => CurrentFence::None {
                    namespace_exists: self.namespace_exists,
                },
            }
        }

        fn request(&mut self, op: Uuid, command: FenceCommand) -> FenceRequest {
            self.next_command += 1;
            FenceRequest {
                namespace: NamespaceName::from("db1"),
                operation_id: op,
                command_id: Uuid::from_u128(0x1000 + self.next_command),
                expected_state: self.current().state(),
                expected_revision: self.current().revision(),
                command,
            }
        }

        fn lookup(&self, request: &FenceRequest) -> Option<&CommandReceipt> {
            self.receipts.iter().find(|r| {
                r.operation_id == request.operation_id && r.command_id == request.command_id
            })
        }

        fn decide(&self, request: &FenceRequest, env: &ApplyEnv) -> Result<Decision, FenceError> {
            apply(self.current(), self.lookup(request), request, env)
        }

        fn persist(&mut self, decision: &Decision) {
            if let Decision::Apply { record, receipt } = decision {
                if let Some(record) = record {
                    // Everything apply writes must survive the durable encoding.
                    let decoded = NamespaceFenceRecord::decode(
                        FENCE_FORMAT_VERSION,
                        record.revision,
                        &record.encode(),
                    )
                    .unwrap();
                    assert_eq!(&decoded, record);
                    if let Some(old) = &self.record {
                        assert!(record.revision > old.revision, "revision must increase");
                    }
                    self.record = Some(record.clone());
                }
                self.store_receipt(receipt.clone());
            }
        }

        fn store_receipt(&mut self, receipt: CommandReceipt) {
            self.receipts.retain(|r| {
                !(r.operation_id == receipt.operation_id && r.command_id == receipt.command_id)
            });
            self.receipts.push(receipt);
        }

        /// Send a fresh command with correct expectations and persist the result.
        fn run(&mut self, op: Uuid, kind: CommandKind) -> Result<Decision, FenceError> {
            let request = self.request(op, command(kind));
            self.run_request(&request, &env())
        }

        fn run_request(
            &mut self,
            request: &FenceRequest,
            env: &ApplyEnv,
        ) -> Result<Decision, FenceError> {
            let decision = self.decide(request, env)?;
            self.persist(&decision);
            Ok(decision)
        }

        fn complete(&mut self, completion: DrainCompletion) {
            let record = self.record.clone().unwrap();
            let receipt = self
                .receipts
                .iter()
                .find(|r| r.outcome == O::Draining && r.command_id == record.last_command_id)
                .or_else(|| {
                    self.receipts
                        .iter()
                        .rev()
                        .find(|r| r.outcome == O::Draining)
                })
                .unwrap()
                .clone();
            let (next, receipt) = complete_drain(&record, &receipt, completion, &env()).unwrap();
            assert_eq!(next.revision, record.revision + 1);
            self.record = Some(next);
            self.store_receipt(receipt);
        }

        fn state(&self) -> FenceState {
            self.current().state()
        }

        fn revision(&self) -> u64 {
            self.current().revision()
        }

        /// Drive the harness into `state` with operation `OP`.
        fn in_state(state: FenceState) -> Self {
            use CommandKind as K;
            let boundary = DrainCompletion::SourceWrites {
                boundary: FrozenBoundary {
                    log_id: LOG,
                    frame_no: Some(42),
                },
            };
            let mut h = if state.role() == Some(Role::Target) || state == S::Absent {
                Self::target()
            } else {
                Self::source()
            };
            let steps: &[&dyn Fn(&mut Harness)] = match state {
                S::Unfenced | S::Absent => &[],
                S::SourceDraining => &[&|h| drop(h.run(OP, K::AcquireSourceWriteFence).unwrap())],
                S::SourceWriteFenced => &[
                    &|h| drop(h.run(OP, K::AcquireSourceWriteFence).unwrap()),
                    &|h| h.complete(boundary),
                ],
                S::SourceReadDraining => &[
                    &|h| drop(h.run(OP, K::AcquireSourceWriteFence).unwrap()),
                    &|h| h.complete(boundary),
                    &|h| drop(h.run(OP, K::SetSourceReadFence).unwrap()),
                ],
                S::SourceReadFenced => &[
                    &|h| drop(h.run(OP, K::AcquireSourceWriteFence).unwrap()),
                    &|h| h.complete(boundary),
                    &|h| drop(h.run(OP, K::SetSourceReadFence).unwrap()),
                    &|h| h.complete(DrainCompletion::SourceReads),
                ],
                S::Released => &[
                    &|h| drop(h.run(OP, K::AcquireSourceWriteFence).unwrap()),
                    &|h| h.complete(boundary),
                    &|h| drop(h.run(OP, K::ReleaseSourceWriteFence).unwrap()),
                ],
                S::TargetQuarantined => {
                    &[&|h| drop(h.run(OP, K::CreateTargetQuarantined).unwrap())]
                }
                S::TargetImportDraining => &[
                    &|h| drop(h.run(OP, K::CreateTargetQuarantined).unwrap()),
                    &|h| drop(h.run(OP, K::SealTargetImport).unwrap()),
                ],
                S::TargetValidating => &[
                    &|h| drop(h.run(OP, K::CreateTargetQuarantined).unwrap()),
                    &|h| drop(h.run(OP, K::SealTargetImport).unwrap()),
                    &|h| h.complete(DrainCompletion::TargetImport),
                ],
                S::TargetWriteFenced => &[
                    &|h| drop(h.run(OP, K::CreateTargetQuarantined).unwrap()),
                    &|h| drop(h.run(OP, K::SealTargetImport).unwrap()),
                    &|h| h.complete(DrainCompletion::TargetImport),
                    &|h| drop(h.run(OP, K::RecordTargetValidation).unwrap()),
                    &|h| drop(h.run(OP, K::PublishTargetReadableWriteFenced).unwrap()),
                ],
                S::TargetWritable => &[
                    &|h| drop(h.run(OP, K::CreateTargetQuarantined).unwrap()),
                    &|h| drop(h.run(OP, K::SealTargetImport).unwrap()),
                    &|h| h.complete(DrainCompletion::TargetImport),
                    &|h| drop(h.run(OP, K::RecordTargetValidation).unwrap()),
                    &|h| drop(h.run(OP, K::PublishTargetReadableWriteFenced).unwrap()),
                    &|h| drop(h.run(OP, K::EnableTargetWrites).unwrap()),
                ],
                S::TargetAborted => &[
                    &|h| drop(h.run(OP, K::CreateTargetQuarantined).unwrap()),
                    &|h| drop(h.run(OP, K::AbortQuarantinedTarget).unwrap()),
                ],
                S::UnknownUnavailable => panic!("not reachable by transitions"),
            };
            for step in steps {
                step(&mut h);
            }
            assert_eq!(h.state(), state);
            h
        }
    }

    fn outcome_of(result: &Result<Decision, FenceError>) -> FenceOutcome {
        match result {
            Ok(Decision::Apply { receipt, .. }) => receipt.outcome,
            Ok(Decision::Replay(r)) | Ok(Decision::Resume(r)) => r.outcome,
            Err(e) => e.outcome(),
        }
    }

    fn state_after(result: &Result<Decision, FenceError>) -> Option<FenceState> {
        match result {
            Ok(Decision::Apply { receipt, .. }) => Some(receipt.state_after),
            _ => None,
        }
    }

    const RECORD_STATES: [FenceState; 13] = [
        S::Unfenced,
        S::Absent,
        S::SourceDraining,
        S::SourceWriteFenced,
        S::SourceReadDraining,
        S::SourceReadFenced,
        S::Released,
        S::TargetQuarantined,
        S::TargetImportDraining,
        S::TargetValidating,
        S::TargetWriteFenced,
        S::TargetWritable,
        S::TargetAborted,
    ];

    /// Every (state, command) pair from the owning operation, with correct expectations,
    /// against the full expected table: the legal transitions of section 3.2, the
    /// `ALREADY_APPLIED` goal states, drain joins, and a refusal for everything else.
    #[test]
    fn exhaustive_owner_commands() {
        use CommandKind as K;

        let expected =
            |state: FenceState, kind: CommandKind| -> (FenceOutcome, Option<FenceState>) {
                if kind == K::AdoptFence {
                    // Adopting one's own fence is never allowed; finished fences cannot be
                    // adopted; no record has nothing to adopt.
                    return (O::InvalidFenceTransition, None);
                }
                if kind == K::CreateTargetQuarantined {
                    return match state {
                        S::Absent => (O::Applied, Some(S::TargetQuarantined)),
                        S::TargetQuarantined => (O::AlreadyApplied, Some(S::TargetQuarantined)),
                        // The owner has finished with the namespace.
                        s if s.is_operation_finished() => (O::InvalidFenceTransition, None),
                        // The name is in use.
                        _ => (O::FencePreconditionFailed, None),
                    };
                }
                if kind.goal_state() == Some(state) {
                    return (O::AlreadyApplied, Some(state));
                }
                if drain_state(kind) == Some(state) {
                    return (O::Draining, Some(state));
                }
                if state.is_operation_finished() && state != S::Unfenced {
                    return (O::InvalidFenceTransition, None);
                }
                match transition(kind, state) {
                    Some((to, outcome)) => {
                        if kind == K::PublishTargetReadableWriteFenced {
                            // No validation receipt has been recorded on this path.
                            (O::FencePreconditionFailed, None)
                        } else {
                            (outcome, Some(to))
                        }
                    }
                    None => (O::InvalidFenceTransition, None),
                }
            };

        for state in RECORD_STATES {
            for kind in CommandKind::ALL {
                // A target driven to TARGET_VALIDATING has no validation receipt yet.
                let mut h = Harness::in_state(state);
                let result = h.run(OP, kind);
                let (outcome, to) = expected(state, kind);
                assert_eq!(outcome_of(&result), outcome, "{state} {kind}: {result:?}");
                assert_eq!(state_after(&result), to, "{state} {kind}");
            }
        }
    }

    #[test]
    fn source_happy_path() {
        let mut h = Harness::source();
        let r = h.run(OP, CommandKind::AcquireSourceWriteFence).unwrap();
        let Decision::Apply { record, receipt } = r else {
            panic!()
        };
        let record = record.unwrap();
        assert_eq!(record.state, S::SourceDraining);
        assert_eq!(record.revision, 1);
        assert_eq!(receipt.outcome, O::Draining);
        assert_eq!((receipt.revision_before, receipt.revision_after), (0, 1));
        assert_eq!(record.identity.log_id, Some(LOG));
        assert!(!record.write_admission().is_open());
        assert!(record.read_admission().is_open());

        h.complete(DrainCompletion::SourceWrites {
            boundary: FrozenBoundary {
                log_id: LOG,
                frame_no: Some(7),
            },
        });
        assert_eq!(h.state(), S::SourceWriteFenced);
        assert_eq!(h.revision(), 2);
        assert_eq!(
            h.record.as_ref().unwrap().frozen_boundary.unwrap().frame_no,
            Some(7)
        );
        let acquire_receipt = h
            .receipts
            .iter()
            .find(|r| r.command == CommandKind::AcquireSourceWriteFence)
            .unwrap();
        assert_eq!(acquire_receipt.outcome, O::Applied);
        assert_eq!(acquire_receipt.revision_after, 2);

        h.run(OP, CommandKind::SetSourceReadFence).unwrap();
        assert_eq!((h.state(), h.revision()), (S::SourceReadDraining, 3));
        h.complete(DrainCompletion::SourceReads);
        assert_eq!((h.state(), h.revision()), (S::SourceReadFenced, 4));
        h.run(OP, CommandKind::ClearSourceReadFence).unwrap();
        assert_eq!((h.state(), h.revision()), (S::SourceWriteFenced, 5));
        h.run(OP, CommandKind::ReleaseSourceWriteFence).unwrap();
        assert_eq!((h.state(), h.revision()), (S::Released, 6));
        assert!(h.record.as_ref().unwrap().write_admission().is_open());

        // A new operation may acquire the released namespace; the revision keeps counting.
        let r = h
            .run(OTHER_OP, CommandKind::AcquireSourceWriteFence)
            .unwrap();
        assert!(matches!(r, Decision::Apply { .. }));
        let record = h.record.as_ref().unwrap();
        assert_eq!(
            (record.state, record.revision, record.operation_id),
            (S::SourceDraining, 7, OTHER_OP)
        );
        assert!(record.frozen_boundary.is_none());
    }

    #[test]
    fn target_happy_path() {
        let mut h = Harness::target();
        h.run(OP, CommandKind::CreateTargetQuarantined).unwrap();
        let record = h.record.clone().unwrap();
        assert_eq!(
            (record.role, record.state, record.revision),
            (Role::Target, S::TargetQuarantined, 1)
        );
        assert_eq!(record.identity.target_incarnation_id, Some(INCARNATION));
        assert!(!record.read_admission().is_open());

        h.run(OP, CommandKind::SealTargetImport).unwrap();
        assert_eq!((h.state(), h.revision()), (S::TargetImportDraining, 2));
        h.complete(DrainCompletion::TargetImport);
        assert_eq!((h.state(), h.revision()), (S::TargetValidating, 3));

        // Publication needs a successful validation receipt first.
        let err = h
            .run(OP, CommandKind::PublishTargetReadableWriteFenced)
            .unwrap_err();
        assert_eq!(err.outcome(), O::FencePreconditionFailed);
        assert_eq!(err.detail(), Some(FenceDetail::ValidationReceiptRequired));

        let failed = h.request(
            OP,
            FenceCommand::RecordTargetValidation {
                result: ValidationResult::Failed,
                summary: "mismatch".into(),
            },
        );
        h.run_request(&failed, &env()).unwrap();
        assert_eq!((h.state(), h.revision()), (S::TargetValidating, 4));
        let err = h
            .run(OP, CommandKind::PublishTargetReadableWriteFenced)
            .unwrap_err();
        assert_eq!(err.detail(), Some(FenceDetail::ValidationReceiptRequired));

        let snapshot = ValidationSnapshot {
            log_id: LOG,
            frame_no: 9,
            page_count: 3,
        };
        let ok = h.request(OP, command(CommandKind::RecordTargetValidation));
        h.run_request(
            &ok,
            &ApplyEnv {
                validation_snapshot: Some(snapshot),
                ..env()
            },
        )
        .unwrap();
        assert_eq!(h.revision(), 5);
        assert_eq!(
            h.record
                .as_ref()
                .unwrap()
                .validation
                .as_ref()
                .unwrap()
                .snapshot,
            Some(snapshot)
        );

        h.run(OP, CommandKind::PublishTargetReadableWriteFenced)
            .unwrap();
        assert_eq!((h.state(), h.revision()), (S::TargetWriteFenced, 6));
        assert!(h.record.as_ref().unwrap().read_admission().is_open());
        assert!(!h.record.as_ref().unwrap().write_admission().is_open());

        h.run(OP, CommandKind::EnableTargetWrites).unwrap();
        assert_eq!((h.state(), h.revision()), (S::TargetWritable, 7));
        assert!(h.record.as_ref().unwrap().write_admission().is_open());
    }

    #[test]
    fn validation_summary_is_bounded() {
        let mut h = Harness::in_state(S::TargetValidating);
        let request = h.request(
            OP,
            FenceCommand::RecordTargetValidation {
                result: ValidationResult::Ok,
                summary: "x".repeat(MAX_VALIDATION_SUMMARY_BYTES + 1),
            },
        );
        let err = h.run_request(&request, &env()).unwrap_err();
        assert_eq!(err.detail(), Some(FenceDetail::InvalidArgument));
    }

    /// Section 2.8: nothing moves a published target back, for the owning operation.
    #[test]
    fn target_writable_is_irreversible() {
        for kind in CommandKind::ALL {
            let mut h = Harness::in_state(S::TargetWritable);
            let before = h.record.clone();
            let result = h.run(OP, kind);
            match kind {
                CommandKind::EnableTargetWrites => {
                    assert_eq!(outcome_of(&result), O::AlreadyApplied)
                }
                _ => assert_eq!(outcome_of(&result), O::InvalidFenceTransition, "{kind}"),
            }
            assert_eq!(h.record, before, "{kind} changed a published target");
        }

        // Another operation cannot move it to a frozen, aborted or absent target state
        // either; it can only start a new move with the namespace as a source.
        for kind in CommandKind::ALL {
            let mut h = Harness::in_state(S::TargetWritable);
            let result = h.run(OTHER_OP, kind);
            if kind == CommandKind::AcquireSourceWriteFence {
                assert_eq!(state_after(&result), Some(S::SourceDraining));
            } else {
                assert!(outcome_of(&result).is_error(), "{kind}: {result:?}");
                assert_eq!(h.state(), S::TargetWritable);
            }
        }
    }

    #[test]
    fn exact_replay_after_revision_advanced() {
        let mut h = Harness::source();
        let acquire = h.request(OP, command(CommandKind::AcquireSourceWriteFence));
        h.run_request(&acquire, &env()).unwrap();

        // While draining, a replay resumes the same drain.
        let d = h.decide(&acquire, &env()).unwrap();
        assert!(matches!(&d, Decision::Resume(r) if r.command_id == acquire.command_id));

        h.complete(DrainCompletion::SourceWrites {
            boundary: FrozenBoundary {
                log_id: LOG,
                frame_no: Some(1),
            },
        });
        h.run(OP, CommandKind::SetSourceReadFence).unwrap();
        h.complete(DrainCompletion::SourceReads);
        assert_eq!(h.revision(), 4);

        // The original acquire's expectations (UNFENCED, 0) are long stale, but a replay is
        // answered from its receipt before any revision check.
        let d = h.decide(&acquire, &env()).unwrap();
        let Decision::Replay(receipt) = d else {
            panic!("{d:?}")
        };
        assert_eq!(receipt.outcome, O::Applied);
        assert_eq!(receipt.state_after, S::SourceWriteFenced);
        assert_eq!(receipt.revision_after, 2);
    }

    #[test]
    fn command_id_reuse_with_different_fingerprint_conflicts() {
        let mut h = Harness::source();
        let acquire = h.request(OP, command(CommandKind::AcquireSourceWriteFence));
        h.run_request(&acquire, &env()).unwrap();
        let before = (h.record.clone(), h.receipts.clone());

        let mut reused = acquire.clone();
        reused.command = FenceCommand::ReleaseSourceWriteFence;
        reused.expected_state = S::SourceDraining;
        reused.expected_revision = 1;
        let err = h.decide(&reused, &env()).unwrap_err();
        assert_eq!(err.outcome(), O::FenceCommandConflict);

        let mut reused = acquire.clone();
        reused.command = FenceCommand::AcquireSourceWriteFence {
            expected_log_id: LOG,
            drain_policy: None,
        };
        assert_eq!(
            h.decide(&reused, &env()).unwrap_err().outcome(),
            O::FenceCommandConflict
        );

        assert_eq!((h.record.clone(), h.receipts.clone()), before);
    }

    #[test]
    fn wrong_owner_is_refused() {
        for state in RECORD_STATES {
            if !state.is_durable() || state.is_operation_finished() {
                continue;
            }
            for kind in CommandKind::ALL {
                if kind == CommandKind::AdoptFence {
                    continue;
                }
                let mut h = Harness::in_state(state);
                let before = h.record.clone();
                let result = h.run(OTHER_OP, kind);
                // The owner is checked before anything about the command.
                assert_eq!(
                    outcome_of(&result),
                    O::FenceOwnedByAnotherOperation,
                    "{state} {kind}"
                );
                assert_eq!(h.record, before);
            }
        }
    }

    #[test]
    fn stale_revision_is_refused() {
        let mut h = Harness::in_state(S::SourceWriteFenced);
        let mut request = h.request(OP, command(CommandKind::SetSourceReadFence));
        request.expected_revision -= 1;
        assert_eq!(
            h.decide(&request, &env()).unwrap_err().outcome(),
            O::FenceRevisionMismatch
        );

        let mut request = h.request(OP, command(CommandKind::SetSourceReadFence));
        request.expected_state = S::SourceDraining;
        assert_eq!(
            h.decide(&request, &env()).unwrap_err().outcome(),
            O::FenceRevisionMismatch
        );

        let mut request = h.request(OP, command(CommandKind::SetSourceReadFence));
        request.expected_revision += 1;
        assert_eq!(
            h.decide(&request, &env()).unwrap_err().outcome(),
            O::FenceRevisionMismatch
        );
    }

    #[test]
    fn role_mismatch() {
        let mut h = Harness::in_state(S::SourceWriteFenced);
        let err = h.run(OP, CommandKind::SealTargetImport).unwrap_err();
        assert_eq!(err.outcome(), O::InvalidFenceTransition);
        assert_eq!(err.detail(), Some(FenceDetail::RoleMismatch));

        let mut h = Harness::in_state(S::TargetQuarantined);
        let err = h.run(OP, CommandKind::SetSourceReadFence).unwrap_err();
        assert_eq!(err.detail(), Some(FenceDetail::RoleMismatch));

        let mut h = Harness::source();
        let err = h.run(OP, CommandKind::EnableTargetWrites).unwrap_err();
        assert_eq!(err.detail(), Some(FenceDetail::RoleMismatch));

        let mut h = Harness::target();
        let err = h.run(OP, CommandKind::AcquireSourceWriteFence).unwrap_err();
        assert_eq!(err.detail(), Some(FenceDetail::RoleMismatch));
    }

    /// The pure half of `acquire_race_single_owner`: two operations race to acquire the same
    /// namespace; the store's serialised transactions mean the second decides against the
    /// first's committed record and loses with a typed conflict.
    #[test]
    fn acquire_race_single_owner() {
        let mut h = Harness::source();
        let a = h.request(OP, command(CommandKind::AcquireSourceWriteFence));
        let b = h.request(OTHER_OP, command(CommandKind::AcquireSourceWriteFence));
        h.run_request(&a, &env()).unwrap();
        let err = h.run_request(&b, &env()).unwrap_err();
        assert_eq!(err.outcome(), O::FenceOwnedByAnotherOperation);
        assert_eq!(h.record.as_ref().unwrap().operation_id, OP);
    }

    #[test]
    fn acquire_preconditions() {
        let mut h = Harness::source();
        let request = h.request(OP, command(CommandKind::AcquireSourceWriteFence));
        let err = h
            .decide(
                &request,
                &ApplyEnv {
                    namespace_log_id: Some(Uuid::from_u128(0x11)),
                    ..env()
                },
            )
            .unwrap_err();
        assert_eq!(err.detail(), Some(FenceDetail::NamespaceIdentityMismatch));

        let err = h
            .decide(
                &request,
                &ApplyEnv {
                    shared_schema: true,
                    ..env()
                },
            )
            .unwrap_err();
        assert_eq!(err.detail(), Some(FenceDetail::SharedSchemaUnsupported));
    }

    #[test]
    fn acquire_saves_and_release_restores_legacy_blocks() {
        let saved = LegacyBlocks {
            block_reads: false,
            block_writes: true,
            block_reason: Some("maintenance".into()),
        };
        let mut h = Harness::source();
        let request = h.request(OP, command(CommandKind::AcquireSourceWriteFence));
        h.run_request(
            &request,
            &ApplyEnv {
                legacy_blocks: saved.clone(),
                ..env()
            },
        )
        .unwrap();
        let mirror = h.record.as_ref().unwrap().legacy_mirror();
        assert!(mirror.block_writes);
        assert!(mirror
            .block_reason
            .unwrap()
            .starts_with("namespace fence: SOURCE_DRAINING"));

        h.run(OP, CommandKind::ReleaseSourceWriteFence).unwrap();
        assert_eq!(h.record.as_ref().unwrap().legacy_mirror(), saved);
    }

    #[test]
    fn release_from_draining_is_a_precommit_rollback() {
        let mut h = Harness::in_state(S::SourceDraining);
        h.run(OP, CommandKind::ReleaseSourceWriteFence).unwrap();
        assert_eq!((h.state(), h.revision()), (S::Released, 2));
    }

    #[test]
    fn owner_joins_its_own_drain_with_a_new_command() {
        let mut h = Harness::in_state(S::SourceDraining);
        let d = h.run(OP, CommandKind::AcquireSourceWriteFence).unwrap();
        let Decision::Apply { record, receipt } = d else {
            panic!()
        };
        assert!(record.is_none());
        assert_eq!(receipt.outcome, O::Draining);
        assert_eq!(h.revision(), 1);

        // The drain completes through the new command's receipt.
        let record = h.record.clone().unwrap();
        let (next, final_receipt) = complete_drain(
            &record,
            &receipt,
            DrainCompletion::SourceWrites {
                boundary: FrozenBoundary {
                    log_id: LOG,
                    frame_no: Some(3),
                },
            },
            &env(),
        )
        .unwrap();
        assert_eq!(next.state, S::SourceWriteFenced);
        assert_eq!(final_receipt.command_id, receipt.command_id);
        assert_eq!(final_receipt.outcome, O::Applied);
    }

    #[test]
    fn complete_drain_checks() {
        let h = Harness::in_state(S::SourceDraining);
        let record = h.record.clone().unwrap();
        let receipt = h.receipts[0].clone();

        // Wrong kind of completion for the state.
        assert!(complete_drain(&record, &receipt, DrainCompletion::SourceReads, &env()).is_err());
        assert!(complete_drain(&record, &receipt, DrainCompletion::TargetImport, &env()).is_err());

        // A boundary from another log.
        let err = complete_drain(
            &record,
            &receipt,
            DrainCompletion::SourceWrites {
                boundary: FrozenBoundary {
                    log_id: Uuid::from_u128(0x77),
                    frame_no: Some(1),
                },
            },
            &env(),
        )
        .unwrap_err();
        assert_eq!(err.detail(), Some(FenceDetail::NamespaceIdentityMismatch));

        // A final receipt, or another operation's.
        let mut final_receipt = receipt.clone();
        final_receipt.outcome = O::Applied;
        let boundary = DrainCompletion::SourceWrites {
            boundary: FrozenBoundary {
                log_id: LOG,
                frame_no: Some(1),
            },
        };
        assert!(complete_drain(&record, &final_receipt, boundary, &env()).is_err());
        let mut other = receipt.clone();
        other.operation_id = OTHER_OP;
        assert!(complete_drain(&record, &other, boundary, &env()).is_err());

        // Not draining any more.
        let h = Harness::in_state(S::SourceWriteFenced);
        let record = h.record.clone().unwrap();
        assert!(complete_drain(&record, &receipt, boundary, &env()).is_err());
    }

    #[test]
    fn unavailable_refuses_everything_else() {
        let marker = Harness::in_state(S::SourceWriteFenced).record.unwrap();
        for detail in [
            FenceDetail::CorruptRecord,
            FenceDetail::UnsupportedFormatVersion,
            FenceDetail::MetastoreBehindMarker,
            FenceDetail::IncompleteTargetCreation,
            FenceDetail::IndeterminateCommit,
        ] {
            for kind in CommandKind::ALL {
                if kind == CommandKind::AdoptFence && detail == FenceDetail::MetastoreBehindMarker {
                    continue;
                }
                let current = CurrentFence::Unavailable {
                    detail,
                    marker: Some(&marker),
                };
                let request = FenceRequest {
                    namespace: NamespaceName::from("db1"),
                    operation_id: OP,
                    command_id: Uuid::from_u128(0x5000),
                    expected_state: S::UnknownUnavailable,
                    expected_revision: marker.revision,
                    command: command(kind),
                };
                let err = apply(current, None, &request, &env()).unwrap_err();
                assert_eq!(err.outcome(), O::FenceStateUnavailable, "{detail} {kind}");
                assert_eq!(err.detail(), Some(detail));
            }
        }
    }

    #[test]
    fn incomplete_target_creation_is_completed_only_by_the_same_command() {
        let mut h = Harness::target();
        let create = h.request(OP, command(CommandKind::CreateTargetQuarantined));
        let Decision::Apply { record, .. } = h.decide(&create, &env()).unwrap() else {
            panic!()
        };
        // The store writes this marker, then crashes before the metastore commit.
        let marker = FenceMarker::for_record(record.as_ref().unwrap());
        let marker = FenceMarker::decode(&marker.encode()).unwrap().record;
        let current = CurrentFence::Unavailable {
            detail: FenceDetail::IncompleteTargetCreation,
            marker: Some(&marker),
        };

        // Another command id, even from the same operation, cannot complete it.
        let mut other = create.clone();
        other.command_id = Uuid::from_u128(0x6000);
        let err = apply(current, None, &other, &env()).unwrap_err();
        assert_eq!(err.outcome(), O::FenceStateUnavailable);

        // The same command does, with the incarnation id the marker recorded.
        let d = apply(
            current,
            None,
            &create,
            &ApplyEnv {
                new_incarnation_id: Uuid::from_u128(0x7777),
                ..env()
            },
        )
        .unwrap();
        let Decision::Apply {
            record: Some(record),
            receipt,
        } = d
        else {
            panic!()
        };
        assert_eq!(record, marker);
        assert_eq!(receipt.outcome, O::Applied);
    }

    fn adopt_request(h: &mut Harness, args: AdoptArgs) -> FenceRequest {
        h.request(OTHER_OP, FenceCommand::AdoptFence(args))
    }

    fn adopt_args() -> AdoptArgs {
        match command(CommandKind::AdoptFence) {
            FenceCommand::AdoptFence(args) => args,
            _ => unreachable!(),
        }
    }

    fn authorised() -> ApplyEnv {
        ApplyEnv {
            adoption_authorised: true,
            ..env()
        }
    }

    #[test]
    fn adopt_requires_key_and_two_approvers() {
        let mut h = Harness::in_state(S::SourceWriteFenced);
        let request = adopt_request(&mut h, adopt_args());
        let err = h.decide(&request, &env()).unwrap_err();
        assert_eq!(err.detail(), Some(FenceDetail::AdoptionNotAuthorised));

        let bad = [
            AdoptArgs {
                approvers: vec!["alice".into()],
                ..adopt_args()
            },
            AdoptArgs {
                approvers: vec!["alice".into(), " alice ".into()],
                ..adopt_args()
            },
            AdoptArgs {
                approvers: vec!["alice".into(), "".into()],
                ..adopt_args()
            },
            AdoptArgs {
                approvers: vec!["a".into(), "b".into(), "c".into()],
                ..adopt_args()
            },
            AdoptArgs {
                incident_ref: " ".into(),
                ..adopt_args()
            },
            AdoptArgs {
                reason: "".into(),
                ..adopt_args()
            },
        ];
        for args in bad {
            let request = adopt_request(&mut h, args.clone());
            let err = h.decide(&request, &authorised()).unwrap_err();
            assert_eq!(
                err.detail(),
                Some(FenceDetail::AdoptionNotAuthorised),
                "{args:?}"
            );
        }

        let wrong_owner = AdoptArgs {
            current_operation_id: Uuid::from_u128(0xdead),
            ..adopt_args()
        };
        let request = adopt_request(&mut h, wrong_owner);
        assert_eq!(
            h.decide(&request, &authorised()).unwrap_err().outcome(),
            O::FenceOwnedByAnotherOperation
        );
    }

    #[test]
    fn adopt_keeps_gates_closed() {
        for state in [
            S::SourceDraining,
            S::SourceWriteFenced,
            S::SourceReadDraining,
            S::SourceReadFenced,
            S::TargetQuarantined,
            S::TargetImportDraining,
            S::TargetValidating,
            S::TargetWriteFenced,
        ] {
            let mut h = Harness::in_state(state);
            let before = h.record.clone().unwrap();
            let request = adopt_request(&mut h, adopt_args());
            h.run_request(&request, &authorised()).unwrap();
            let after = h.record.clone().unwrap();
            assert_eq!(after.state, state);
            assert_eq!(after.write_admission(), before.write_admission());
            assert_eq!(after.read_admission(), before.read_admission());
            assert_eq!(after.revision, before.revision + 1);
            assert_eq!(after.operation_id, OTHER_OP);
            assert_eq!(after.adoptions.len(), 1);
            assert_eq!(after.adoptions[0].approvers, vec!["alice", "bob"]);
            let receipt = h.receipts.last().unwrap();
            assert_eq!(receipt.adoption.as_ref().unwrap().previous_operation_id, OP);

            // The old owner is now locked out.
            let result = h.run(OP, CommandKind::ReleaseSourceWriteFence);
            assert_eq!(outcome_of(&result), O::FenceOwnedByAnotherOperation);
        }
    }

    #[test]
    fn adopt_cannot_touch_finished_fences() {
        for state in [S::TargetWritable, S::TargetAborted, S::Released] {
            let mut h = Harness::in_state(state);
            let request = adopt_request(&mut h, adopt_args());
            let err = h.decide(&request, &authorised()).unwrap_err();
            assert_eq!(err.outcome(), O::InvalidFenceTransition, "{state}");
            assert_eq!(err.detail(), Some(FenceDetail::OperationFinished));
        }
        let mut h = Harness::source();
        let request = adopt_request(&mut h, adopt_args());
        assert_eq!(
            h.decide(&request, &authorised()).unwrap_err().outcome(),
            O::InvalidFenceTransition
        );
    }

    #[test]
    fn adopted_owner_can_finish_the_drain() {
        let mut h = Harness::in_state(S::SourceDraining);
        let request = adopt_request(&mut h, adopt_args());
        h.run_request(&request, &authorised()).unwrap();
        let d = h
            .run(OTHER_OP, CommandKind::AcquireSourceWriteFence)
            .unwrap();
        assert!(
            matches!(d, Decision::Apply { record: None, ref receipt } if receipt.outcome == O::Draining)
        );
        h.complete(DrainCompletion::SourceWrites {
            boundary: FrozenBoundary {
                log_id: LOG,
                frame_no: Some(5),
            },
        });
        assert_eq!(h.state(), S::SourceWriteFenced);
        assert_eq!(h.record.as_ref().unwrap().operation_id, OTHER_OP);
    }

    #[test]
    fn adopt_after_metastore_rollback_restores_marker_record() {
        let marker = Harness::in_state(S::SourceReadFenced).record.unwrap();
        let current = CurrentFence::Unavailable {
            detail: FenceDetail::MetastoreBehindMarker,
            marker: Some(&marker),
        };
        let request = FenceRequest {
            namespace: NamespaceName::from("db1"),
            operation_id: OTHER_OP,
            command_id: Uuid::from_u128(0x8000),
            expected_state: S::SourceReadFenced,
            expected_revision: marker.revision,
            command: FenceCommand::AdoptFence(adopt_args()),
        };
        let d = apply(current, None, &request, &authorised()).unwrap();
        let Decision::Apply {
            record: Some(record),
            ..
        } = d
        else {
            panic!()
        };
        assert_eq!(record.state, S::SourceReadFenced);
        assert_eq!(record.revision, marker.revision + 1);
        assert_eq!(record.operation_id, OTHER_OP);
        assert_eq!(record.frozen_boundary, marker.frozen_boundary);
    }

    #[test]
    fn revision_increases_by_one_per_applied_transition() {
        let h = Harness::in_state(S::TargetWritable);
        let mut receipts = h.receipts.clone();
        receipts.sort_by_key(|r| r.revision_after);
        let mut last = 0;
        for r in receipts {
            if r.outcome == O::AlreadyApplied {
                continue;
            }
            assert_eq!(
                r.revision_after,
                last + if r.command == CommandKind::SealTargetImport {
                    2
                } else {
                    1
                },
                "{r:?}"
            );
            last = r.revision_after;
        }
        assert_eq!(h.revision(), 6);
    }
}
