//! Fence records, command receipts, the on-disk marker, and their durable encoding
//! (`docs/NAMESPACE_FENCE.md` sections 5.1, 5.2 and 5.6).
//!
//! Decoding is strict: an unknown format version, an unknown enum value, a missing required
//! field, a malformed id or a record that contradicts itself is an error, which the store turns
//! into `UNKNOWN_UNAVAILABLE`. Nothing is defaulted.

use prost::Message as _;
use uuid::Uuid;

use crate::namespace::NamespaceName;

use super::command::{CommandKind, DrainPolicy, Fingerprint, TargetConfig, ValidationResult};
use super::outcome::FenceOutcome;
use super::proto;
use super::state::{Admission, FenceState, Role};

/// The only `format_version` this server writes and reads.
pub const FENCE_FORMAT_VERSION: u32 = 1;

/// Identity of the namespace copy a record is about.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NamespaceIdentity {
    /// Replication log id: for a source, captured at acquisition and checked against the
    /// caller's expectation; for a target, known once the namespace exists.
    pub log_id: Option<Uuid>,
    /// Server-generated id of a target created by `CreateTargetQuarantined`.
    pub target_incarnation_id: Option<Uuid>,
}

/// The source's replication position once no writer can commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrozenBoundary {
    pub log_id: Uuid,
    /// The last frame committed to the replication log, or `None` when the log has no frames.
    pub frame_no: Option<u64>,
}

/// The pre-fence values of the legacy `block_*` configuration fields, restored when the
/// operation finishes (section 13.2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LegacyBlocks {
    pub block_reads: bool,
    pub block_writes: bool,
    pub block_reason: Option<String>,
}

/// The server process that wrote something.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerIdentity {
    pub build: String,
    pub instance_id: Uuid,
}

/// What the server observed of a target when a validation result was recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidationSnapshot {
    pub log_id: Uuid,
    pub frame_no: u64,
    pub page_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationRecord {
    pub operation_id: Uuid,
    pub command_id: Uuid,
    pub result: ValidationResult,
    pub summary: String,
    pub snapshot: Option<ValidationSnapshot>,
    pub recorded_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adoption {
    pub previous_operation_id: Uuid,
    pub new_operation_id: Uuid,
    pub command_id: Uuid,
    pub approvers: Vec<String>,
    pub incident_ref: String,
    pub reason: String,
    pub at_ms: i64,
    /// The revision the adoption produced.
    pub revision: u64,
}

/// The durable control record of one fenced namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceFenceRecord {
    pub namespace: NamespaceName,
    pub role: Role,
    /// Always a durable state whose role is `role`.
    pub state: FenceState,
    /// Starts at 1 and increases by one on every applied transition. Survives restart.
    pub revision: u64,
    pub operation_id: Uuid,
    pub identity: NamespaceIdentity,
    pub drain_policy: Option<DrainPolicy>,
    /// When the current drain was requested, if the record is draining.
    pub drain_started_at_ms: Option<i64>,
    pub frozen_boundary: Option<FrozenBoundary>,
    /// The most recent validation result of the owning operation (target).
    pub validation: Option<ValidationRecord>,
    pub legacy_blocks: LegacyBlocks,
    pub created_at_ms: i64,
    pub last_transition_at_ms: i64,
    /// The command that produced the current revision.
    pub last_command_id: Uuid,
    pub written_by: ServerIdentity,
    pub adoptions: Vec<Adoption>,
}

impl NamespaceFenceRecord {
    pub fn write_admission(&self) -> Admission {
        self.state.write_admission()
    }

    pub fn read_admission(&self) -> Admission {
        self.state.read_admission()
    }

    /// Values of the legacy `block_*` configuration fields while this record is in force: the
    /// fence state mirrored for an older binary, or the pre-fence values once the operation
    /// has released the namespace.
    pub fn legacy_mirror(&self) -> LegacyBlocks {
        match self.state {
            FenceState::Released | FenceState::TargetWritable => self.legacy_blocks.clone(),
            state => LegacyBlocks {
                block_reads: !state.read_admission().is_open(),
                block_writes: !state.write_admission().is_open(),
                block_reason: Some(format!(
                    "namespace fence: {state} (operation {})",
                    self.operation_id
                )),
            },
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        codec::record_to_proto(self).encode_to_vec()
    }

    /// Decode a stored record. `format_version` and `revision` are the columns stored beside
    /// the payload; both must agree with it.
    pub fn decode(
        format_version: u32,
        revision: u64,
        bytes: &[u8],
    ) -> Result<Self, FenceDecodeError> {
        check_format_version(format_version)?;
        let msg = proto::FenceRecord::decode(bytes)?;
        let record = codec::record_from_proto(msg)?;
        if record.revision != revision {
            return Err(FenceDecodeError::Invalid(
                "revision column disagrees with payload",
            ));
        }
        Ok(record)
    }
}

/// The durable result of one applied command, keyed by `(namespace, operation_id, command_id)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandReceipt {
    pub namespace: NamespaceName,
    pub operation_id: Uuid,
    pub command_id: Uuid,
    pub command: CommandKind,
    pub fingerprint: Fingerprint,
    /// `APPLIED`, `ALREADY_APPLIED` or `DRAINING`. Errors are never stored.
    pub outcome: FenceOutcome,
    pub revision_before: u64,
    pub revision_after: u64,
    pub state_after: FenceState,
    pub applied_at_ms: i64,
    pub instance_id: Uuid,
    pub adoption: Option<Adoption>,
}

impl CommandReceipt {
    /// Whether the receipt holds the command's final answer, as opposed to a drain that is
    /// still to be completed.
    pub fn is_final(&self) -> bool {
        self.outcome != FenceOutcome::Draining
    }

    pub fn encode(&self) -> Vec<u8> {
        codec::receipt_to_proto(self).encode_to_vec()
    }

    pub fn decode(format_version: u32, bytes: &[u8]) -> Result<Self, FenceDecodeError> {
        check_format_version(format_version)?;
        let msg = proto::CommandReceipt::decode(bytes)?;
        codec::receipt_from_proto(msg)
    }
}

/// Contents of the per-namespace marker file: a copy of the last committed record. Written
/// after each metastore commit, and before the metastore transaction of
/// `CreateTargetQuarantined`, so recovery can tell a fenced namespace from a legacy one and
/// detect a metastore that went backwards (section 5.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FenceMarker {
    pub record: NamespaceFenceRecord,
}

impl FenceMarker {
    pub fn for_record(record: &NamespaceFenceRecord) -> Self {
        Self {
            record: record.clone(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        proto::FenceMarker {
            format_version: FENCE_FORMAT_VERSION,
            record: Some(codec::record_to_proto(&self.record)),
        }
        .encode_to_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FenceDecodeError> {
        let msg = proto::FenceMarker::decode(bytes)?;
        check_format_version(msg.format_version)?;
        let record = msg
            .record
            .ok_or(FenceDecodeError::Invalid("marker without record"))?;
        Ok(Self {
            record: codec::record_from_proto(record)?,
        })
    }
}

/// Why stored fence state could not be read. Every variant means the namespace is
/// `UNKNOWN_UNAVAILABLE`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FenceDecodeError {
    #[error("unsupported fence format version {0}")]
    UnsupportedFormatVersion(u32),
    #[error("undecodable fence payload: {0}")]
    Undecodable(String),
    #[error("invalid fence payload: {0}")]
    Invalid(&'static str),
}

impl From<prost::DecodeError> for FenceDecodeError {
    fn from(e: prost::DecodeError) -> Self {
        FenceDecodeError::Undecodable(e.to_string())
    }
}

fn check_format_version(v: u32) -> Result<(), FenceDecodeError> {
    if v != FENCE_FORMAT_VERSION {
        return Err(FenceDecodeError::UnsupportedFormatVersion(v));
    }
    Ok(())
}

/// Conversions between the domain types and their protobuf encoding.
pub(super) mod codec {
    use super::*;
    use crate::namespace::fence::command::OnDeadline;

    type R<T> = Result<T, FenceDecodeError>;

    pub fn parse_uuid(s: &str) -> R<Uuid> {
        // Only the canonical hyphenated form is ever written.
        let id = Uuid::parse_str(s).map_err(|_| FenceDecodeError::Invalid("malformed id"))?;
        if id.hyphenated().to_string() != s {
            return Err(FenceDecodeError::Invalid("non-canonical id"));
        }
        Ok(id)
    }

    fn parse_opt_uuid(s: Option<&str>) -> R<Option<Uuid>> {
        s.map(parse_uuid).transpose()
    }

    fn namespace(s: String) -> R<NamespaceName> {
        NamespaceName::from_string(s).map_err(|_| FenceDecodeError::Invalid("invalid namespace"))
    }

    pub fn role_to_proto(role: Role) -> proto::FenceRole {
        match role {
            Role::Source => proto::FenceRole::Source,
            Role::Target => proto::FenceRole::Target,
        }
    }

    pub fn role_from_proto(v: i32) -> R<Role> {
        match proto::FenceRole::try_from(v) {
            Ok(proto::FenceRole::Source) => Ok(Role::Source),
            Ok(proto::FenceRole::Target) => Ok(Role::Target),
            _ => Err(FenceDecodeError::Invalid("unknown role")),
        }
    }

    pub fn state_to_proto(state: FenceState) -> proto::FenceState {
        use proto::FenceState as P;
        match state {
            FenceState::Unfenced => P::Unfenced,
            FenceState::Absent => P::Absent,
            FenceState::SourceDraining => P::SourceDraining,
            FenceState::SourceWriteFenced => P::SourceWriteFenced,
            FenceState::SourceReadDraining => P::SourceReadDraining,
            FenceState::SourceReadFenced => P::SourceReadFenced,
            FenceState::Released => P::Released,
            FenceState::TargetQuarantined => P::TargetQuarantined,
            FenceState::TargetImportDraining => P::TargetImportDraining,
            FenceState::TargetValidating => P::TargetValidating,
            FenceState::TargetWriteFenced => P::TargetWriteFenced,
            FenceState::TargetWritable => P::TargetWritable,
            FenceState::TargetAborted => P::TargetAborted,
            FenceState::UnknownUnavailable => P::UnknownUnavailable,
        }
    }

    pub fn state_from_proto(v: i32) -> R<FenceState> {
        use proto::FenceState as P;
        let p = P::try_from(v).map_err(|_| FenceDecodeError::Invalid("unknown state"))?;
        Ok(match p {
            P::Unspecified => return Err(FenceDecodeError::Invalid("unspecified state")),
            P::Unfenced => FenceState::Unfenced,
            P::Absent => FenceState::Absent,
            P::SourceDraining => FenceState::SourceDraining,
            P::SourceWriteFenced => FenceState::SourceWriteFenced,
            P::SourceReadDraining => FenceState::SourceReadDraining,
            P::SourceReadFenced => FenceState::SourceReadFenced,
            P::Released => FenceState::Released,
            P::TargetQuarantined => FenceState::TargetQuarantined,
            P::TargetImportDraining => FenceState::TargetImportDraining,
            P::TargetValidating => FenceState::TargetValidating,
            P::TargetWriteFenced => FenceState::TargetWriteFenced,
            P::TargetWritable => FenceState::TargetWritable,
            P::TargetAborted => FenceState::TargetAborted,
            P::UnknownUnavailable => FenceState::UnknownUnavailable,
        })
    }

    /// A state stored in a record or marker: durable, and of the stated role.
    pub fn durable_state_from_proto(v: i32, role: Role) -> R<FenceState> {
        let state = state_from_proto(v)?;
        match state.role() {
            Some(r) if r == role => Ok(state),
            Some(_) => Err(FenceDecodeError::Invalid("state does not match role")),
            None => Err(FenceDecodeError::Invalid("state is not durable")),
        }
    }

    pub fn command_kind_to_proto(kind: CommandKind) -> proto::CommandKind {
        use proto::CommandKind as P;
        match kind {
            CommandKind::AcquireSourceWriteFence => P::AcquireSourceWriteFence,
            CommandKind::SetSourceReadFence => P::SetSourceReadFence,
            CommandKind::ClearSourceReadFence => P::ClearSourceReadFence,
            CommandKind::ReleaseSourceWriteFence => P::ReleaseSourceWriteFence,
            CommandKind::CreateTargetQuarantined => P::CreateTargetQuarantined,
            CommandKind::SealTargetImport => P::SealTargetImport,
            CommandKind::RecordTargetValidation => P::RecordTargetValidation,
            CommandKind::PublishTargetReadableWriteFenced => P::PublishTargetReadableWriteFenced,
            CommandKind::EnableTargetWrites => P::EnableTargetWrites,
            CommandKind::AbortQuarantinedTarget => P::AbortQuarantinedTarget,
            CommandKind::AdoptFence => P::AdoptFence,
        }
    }

    fn command_kind_from_proto(v: i32) -> R<CommandKind> {
        use proto::CommandKind as P;
        let p = P::try_from(v).map_err(|_| FenceDecodeError::Invalid("unknown command"))?;
        Ok(match p {
            P::Unspecified => return Err(FenceDecodeError::Invalid("unspecified command")),
            P::AcquireSourceWriteFence => CommandKind::AcquireSourceWriteFence,
            P::SetSourceReadFence => CommandKind::SetSourceReadFence,
            P::ClearSourceReadFence => CommandKind::ClearSourceReadFence,
            P::ReleaseSourceWriteFence => CommandKind::ReleaseSourceWriteFence,
            P::CreateTargetQuarantined => CommandKind::CreateTargetQuarantined,
            P::SealTargetImport => CommandKind::SealTargetImport,
            P::RecordTargetValidation => CommandKind::RecordTargetValidation,
            P::PublishTargetReadableWriteFenced => CommandKind::PublishTargetReadableWriteFenced,
            P::EnableTargetWrites => CommandKind::EnableTargetWrites,
            P::AbortQuarantinedTarget => CommandKind::AbortQuarantinedTarget,
            P::AdoptFence => CommandKind::AdoptFence,
        })
    }

    fn outcome_to_proto(outcome: FenceOutcome) -> proto::ReceiptOutcome {
        match outcome {
            FenceOutcome::Applied => proto::ReceiptOutcome::Applied,
            FenceOutcome::AlreadyApplied => proto::ReceiptOutcome::AlreadyApplied,
            FenceOutcome::Draining => proto::ReceiptOutcome::Draining,
            other => unreachable!("receipts never store {other}"),
        }
    }

    fn outcome_from_proto(v: i32) -> R<FenceOutcome> {
        match proto::ReceiptOutcome::try_from(v) {
            Ok(proto::ReceiptOutcome::Applied) => Ok(FenceOutcome::Applied),
            Ok(proto::ReceiptOutcome::AlreadyApplied) => Ok(FenceOutcome::AlreadyApplied),
            Ok(proto::ReceiptOutcome::Draining) => Ok(FenceOutcome::Draining),
            _ => Err(FenceDecodeError::Invalid("unknown receipt outcome")),
        }
    }

    pub fn drain_policy_to_proto(p: &DrainPolicy) -> proto::DrainPolicy {
        proto::DrainPolicy {
            deadline_ms: p.deadline_ms,
            on_deadline: match p.on_deadline {
                OnDeadline::Fail => proto::OnDeadline::Fail,
                OnDeadline::ForceRollback => proto::OnDeadline::ForceRollback,
            } as i32,
        }
    }

    fn drain_policy_from_proto(p: proto::DrainPolicy) -> R<DrainPolicy> {
        let on_deadline = match proto::OnDeadline::try_from(p.on_deadline) {
            Ok(proto::OnDeadline::Fail) => OnDeadline::Fail,
            Ok(proto::OnDeadline::ForceRollback) => OnDeadline::ForceRollback,
            _ => return Err(FenceDecodeError::Invalid("unknown drain deadline policy")),
        };
        Ok(DrainPolicy {
            deadline_ms: p.deadline_ms,
            on_deadline,
        })
    }

    pub fn validation_result_to_proto(r: ValidationResult) -> proto::ValidationResult {
        match r {
            ValidationResult::Ok => proto::ValidationResult::Ok,
            ValidationResult::Failed => proto::ValidationResult::Failed,
        }
    }

    fn validation_result_from_proto(v: i32) -> R<ValidationResult> {
        match proto::ValidationResult::try_from(v) {
            Ok(proto::ValidationResult::Ok) => Ok(ValidationResult::Ok),
            Ok(proto::ValidationResult::Failed) => Ok(ValidationResult::Failed),
            _ => Err(FenceDecodeError::Invalid("unknown validation result")),
        }
    }

    pub fn target_config_to_proto(c: &TargetConfig) -> proto::TargetConfig {
        proto::TargetConfig {
            max_db_size: c.max_db_size,
            jwt_key: c.jwt_key.clone(),
            txn_timeout_s: c.txn_timeout_s,
            allow_attach: c.allow_attach,
            durability_mode: c.durability_mode.clone(),
            bottomless_db_id: c.bottomless_db_id.clone(),
        }
    }

    fn validation_to_proto(v: &ValidationRecord) -> proto::ValidationRecord {
        proto::ValidationRecord {
            operation_id: v.operation_id.to_string(),
            command_id: v.command_id.to_string(),
            result: validation_result_to_proto(v.result) as i32,
            summary: v.summary.clone(),
            snapshot: v.snapshot.map(|s| proto::ValidationSnapshot {
                log_id: s.log_id.to_string(),
                frame_no: s.frame_no,
                page_count: s.page_count,
            }),
            recorded_at_ms: v.recorded_at_ms,
        }
    }

    fn validation_from_proto(v: proto::ValidationRecord) -> R<ValidationRecord> {
        Ok(ValidationRecord {
            operation_id: parse_uuid(&v.operation_id)?,
            command_id: parse_uuid(&v.command_id)?,
            result: validation_result_from_proto(v.result)?,
            summary: v.summary,
            snapshot: v
                .snapshot
                .map(|s| {
                    Ok::<_, FenceDecodeError>(ValidationSnapshot {
                        log_id: parse_uuid(&s.log_id)?,
                        frame_no: s.frame_no,
                        page_count: s.page_count,
                    })
                })
                .transpose()?,
            recorded_at_ms: v.recorded_at_ms,
        })
    }

    fn adoption_to_proto(a: &Adoption) -> proto::Adoption {
        proto::Adoption {
            previous_operation_id: a.previous_operation_id.to_string(),
            new_operation_id: a.new_operation_id.to_string(),
            command_id: a.command_id.to_string(),
            approvers: a.approvers.clone(),
            incident_ref: a.incident_ref.clone(),
            reason: a.reason.clone(),
            at_ms: a.at_ms,
            revision: a.revision,
        }
    }

    fn adoption_from_proto(a: proto::Adoption) -> R<Adoption> {
        Ok(Adoption {
            previous_operation_id: parse_uuid(&a.previous_operation_id)?,
            new_operation_id: parse_uuid(&a.new_operation_id)?,
            command_id: parse_uuid(&a.command_id)?,
            approvers: a.approvers,
            incident_ref: a.incident_ref,
            reason: a.reason,
            at_ms: a.at_ms,
            revision: a.revision,
        })
    }

    pub fn record_to_proto(r: &NamespaceFenceRecord) -> proto::FenceRecord {
        proto::FenceRecord {
            namespace: r.namespace.as_str().to_string(),
            role: role_to_proto(r.role) as i32,
            state: state_to_proto(r.state) as i32,
            revision: r.revision,
            operation_id: r.operation_id.to_string(),
            log_id: r.identity.log_id.map(|id| id.to_string()),
            target_incarnation_id: r.identity.target_incarnation_id.map(|id| id.to_string()),
            drain_policy: r.drain_policy.as_ref().map(drain_policy_to_proto),
            drain_started_at_ms: r.drain_started_at_ms,
            frozen_boundary: r.frozen_boundary.map(|b| proto::FrozenBoundary {
                log_id: b.log_id.to_string(),
                frame_no: b.frame_no,
            }),
            validation: r.validation.as_ref().map(validation_to_proto),
            legacy_blocks: Some(proto::LegacyBlocks {
                block_reads: r.legacy_blocks.block_reads,
                block_writes: r.legacy_blocks.block_writes,
                block_reason: r.legacy_blocks.block_reason.clone(),
            }),
            created_at_ms: r.created_at_ms,
            last_transition_at_ms: r.last_transition_at_ms,
            last_command_id: r.last_command_id.to_string(),
            written_by: Some(proto::ServerIdentity {
                build: r.written_by.build.clone(),
                instance_id: r.written_by.instance_id.to_string(),
            }),
            adoptions: r.adoptions.iter().map(adoption_to_proto).collect(),
        }
    }

    pub fn record_from_proto(m: proto::FenceRecord) -> R<NamespaceFenceRecord> {
        let role = role_from_proto(m.role)?;
        let state = durable_state_from_proto(m.state, role)?;
        if m.revision == 0 {
            return Err(FenceDecodeError::Invalid("record revision is zero"));
        }
        let legacy = m
            .legacy_blocks
            .ok_or(FenceDecodeError::Invalid("missing legacy blocks"))?;
        let written_by = m
            .written_by
            .ok_or(FenceDecodeError::Invalid("missing server identity"))?;
        let record = NamespaceFenceRecord {
            namespace: namespace(m.namespace)?,
            role,
            state,
            revision: m.revision,
            operation_id: parse_uuid(&m.operation_id)?,
            identity: NamespaceIdentity {
                log_id: parse_opt_uuid(m.log_id.as_deref())?,
                target_incarnation_id: parse_opt_uuid(m.target_incarnation_id.as_deref())?,
            },
            drain_policy: m.drain_policy.map(drain_policy_from_proto).transpose()?,
            drain_started_at_ms: m.drain_started_at_ms,
            frozen_boundary: m
                .frozen_boundary
                .map(|b| {
                    Ok::<_, FenceDecodeError>(FrozenBoundary {
                        log_id: parse_uuid(&b.log_id)?,
                        frame_no: b.frame_no,
                    })
                })
                .transpose()?,
            validation: m.validation.map(validation_from_proto).transpose()?,
            legacy_blocks: LegacyBlocks {
                block_reads: legacy.block_reads,
                block_writes: legacy.block_writes,
                block_reason: legacy.block_reason,
            },
            created_at_ms: m.created_at_ms,
            last_transition_at_ms: m.last_transition_at_ms,
            last_command_id: parse_uuid(&m.last_command_id)?,
            written_by: ServerIdentity {
                build: written_by.build,
                instance_id: parse_uuid(&written_by.instance_id)?,
            },
            adoptions: m
                .adoptions
                .into_iter()
                .map(adoption_from_proto)
                .collect::<R<_>>()?,
        };
        check_record_invariants(&record)?;
        Ok(record)
    }

    /// Facts every record written by `apply` satisfies. A record that breaks one was not
    /// written by this server and is not trusted.
    fn check_record_invariants(r: &NamespaceFenceRecord) -> R<()> {
        use FenceState::*;
        let frozen_required = matches!(
            r.state,
            SourceWriteFenced | SourceReadDraining | SourceReadFenced
        );
        if frozen_required && r.frozen_boundary.is_none() {
            return Err(FenceDecodeError::Invalid(
                "fenced source without frozen boundary",
            ));
        }
        if r.role == Role::Source && r.identity.log_id.is_none() {
            return Err(FenceDecodeError::Invalid(
                "source without namespace identity",
            ));
        }
        if r.role == Role::Target && r.identity.target_incarnation_id.is_none() {
            return Err(FenceDecodeError::Invalid("target without incarnation id"));
        }
        if matches!(r.state, TargetWriteFenced | TargetWritable)
            && !r
                .validation
                .as_ref()
                .is_some_and(|v| v.result == ValidationResult::Ok)
        {
            return Err(FenceDecodeError::Invalid(
                "published target without validation",
            ));
        }
        Ok(())
    }

    pub fn receipt_to_proto(r: &CommandReceipt) -> proto::CommandReceipt {
        proto::CommandReceipt {
            namespace: r.namespace.as_str().to_string(),
            operation_id: r.operation_id.to_string(),
            command_id: r.command_id.to_string(),
            command: command_kind_to_proto(r.command) as i32,
            fingerprint: r.fingerprint.as_bytes().to_vec(),
            outcome: outcome_to_proto(r.outcome) as i32,
            revision_before: r.revision_before,
            revision_after: r.revision_after,
            state_after: state_to_proto(r.state_after) as i32,
            applied_at_ms: r.applied_at_ms,
            instance_id: r.instance_id.to_string(),
            adoption: r.adoption.as_ref().map(adoption_to_proto),
        }
    }

    pub fn receipt_from_proto(m: proto::CommandReceipt) -> R<CommandReceipt> {
        let fingerprint: [u8; 32] = m
            .fingerprint
            .as_slice()
            .try_into()
            .map_err(|_| FenceDecodeError::Invalid("fingerprint is not 32 bytes"))?;
        let state_after = state_from_proto(m.state_after)?;
        if !state_after.is_durable() {
            return Err(FenceDecodeError::Invalid("receipt state is not durable"));
        }
        if m.revision_after < m.revision_before {
            return Err(FenceDecodeError::Invalid("receipt revision went backwards"));
        }
        Ok(CommandReceipt {
            namespace: namespace(m.namespace)?,
            operation_id: parse_uuid(&m.operation_id)?,
            command_id: parse_uuid(&m.command_id)?,
            command: command_kind_from_proto(m.command)?,
            fingerprint: Fingerprint(fingerprint),
            outcome: outcome_from_proto(m.outcome)?,
            revision_before: m.revision_before,
            revision_after: m.revision_after,
            state_after,
            applied_at_ms: m.applied_at_ms,
            instance_id: parse_uuid(&m.instance_id)?,
            adoption: m.adoption.map(adoption_from_proto).transpose()?,
        })
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::namespace::fence::command::OnDeadline;

    pub fn sample_record() -> NamespaceFenceRecord {
        NamespaceFenceRecord {
            namespace: NamespaceName::from("db1"),
            role: Role::Source,
            state: FenceState::SourceWriteFenced,
            revision: 2,
            operation_id: Uuid::from_u128(1),
            identity: NamespaceIdentity {
                log_id: Some(Uuid::from_u128(10)),
                target_incarnation_id: None,
            },
            drain_policy: Some(DrainPolicy {
                deadline_ms: 5000,
                on_deadline: OnDeadline::ForceRollback,
            }),
            drain_started_at_ms: Some(100),
            frozen_boundary: Some(FrozenBoundary {
                log_id: Uuid::from_u128(10),
                frame_no: Some(1234),
            }),
            validation: None,
            legacy_blocks: LegacyBlocks {
                block_reads: false,
                block_writes: true,
                block_reason: Some("maintenance".into()),
            },
            created_at_ms: 100,
            last_transition_at_ms: 200,
            last_command_id: Uuid::from_u128(2),
            written_by: ServerIdentity {
                build: "test".into(),
                instance_id: Uuid::from_u128(99),
            },
            adoptions: vec![Adoption {
                previous_operation_id: Uuid::from_u128(5),
                new_operation_id: Uuid::from_u128(1),
                command_id: Uuid::from_u128(6),
                approvers: vec!["a".into(), "b".into()],
                incident_ref: "inc".into(),
                reason: "lost control plane".into(),
                at_ms: 150,
                revision: 2,
            }],
        }
    }

    pub fn sample_receipt() -> CommandReceipt {
        CommandReceipt {
            namespace: NamespaceName::from("db1"),
            operation_id: Uuid::from_u128(1),
            command_id: Uuid::from_u128(2),
            command: CommandKind::AcquireSourceWriteFence,
            fingerprint: Fingerprint([7; 32]),
            outcome: FenceOutcome::Applied,
            revision_before: 0,
            revision_after: 2,
            state_after: FenceState::SourceWriteFenced,
            applied_at_ms: 200,
            instance_id: Uuid::from_u128(99),
            adoption: None,
        }
    }

    #[test]
    fn record_round_trips() {
        let record = sample_record();
        let bytes = record.encode();
        let decoded = NamespaceFenceRecord::decode(FENCE_FORMAT_VERSION, 2, &bytes).unwrap();
        assert_eq!(decoded, record);
    }

    #[test]
    fn receipt_round_trips() {
        let receipt = sample_receipt();
        let decoded = CommandReceipt::decode(FENCE_FORMAT_VERSION, &receipt.encode()).unwrap();
        assert_eq!(decoded, receipt);
    }

    #[test]
    fn marker_round_trips() {
        let marker = FenceMarker::for_record(&sample_record());
        assert_eq!(FenceMarker::decode(&marker.encode()).unwrap(), marker);
    }

    #[test]
    fn unknown_format_version_is_rejected() {
        let bytes = sample_record().encode();
        assert_eq!(
            NamespaceFenceRecord::decode(2, 2, &bytes),
            Err(FenceDecodeError::UnsupportedFormatVersion(2))
        );
        assert!(matches!(
            CommandReceipt::decode(0, &sample_receipt().encode()),
            Err(FenceDecodeError::UnsupportedFormatVersion(0))
        ));
        let mut marker = proto::FenceMarker::decode(
            FenceMarker::for_record(&sample_record())
                .encode()
                .as_slice(),
        )
        .unwrap();
        marker.format_version = 7;
        assert_eq!(
            FenceMarker::decode(&marker.encode_to_vec()),
            Err(FenceDecodeError::UnsupportedFormatVersion(7))
        );
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(matches!(
            NamespaceFenceRecord::decode(FENCE_FORMAT_VERSION, 2, &[0xff, 0xff, 0xff]),
            Err(FenceDecodeError::Undecodable(_))
        ));
        // An empty payload decodes as an all-default message, which is not a valid record.
        assert!(NamespaceFenceRecord::decode(FENCE_FORMAT_VERSION, 0, &[]).is_err());
        assert!(CommandReceipt::decode(FENCE_FORMAT_VERSION, &[]).is_err());
        assert!(FenceMarker::decode(&[]).is_err());
    }

    #[test]
    fn revision_column_must_match() {
        let bytes = sample_record().encode();
        assert!(matches!(
            NamespaceFenceRecord::decode(FENCE_FORMAT_VERSION, 3, &bytes),
            Err(FenceDecodeError::Invalid(_))
        ));
    }

    fn mutate(
        f: impl FnOnce(&mut proto::FenceRecord),
    ) -> Result<NamespaceFenceRecord, FenceDecodeError> {
        let mut m = codec::record_to_proto(&sample_record());
        f(&mut m);
        let revision = m.revision;
        NamespaceFenceRecord::decode(FENCE_FORMAT_VERSION, revision, &m.encode_to_vec())
    }

    #[test]
    fn invalid_records_are_rejected() {
        assert!(mutate(|m| m.state = 999).is_err(), "unknown state");
        assert!(
            mutate(|m| m.state = proto::FenceState::Unfenced as i32).is_err(),
            "non-durable"
        );
        assert!(
            mutate(|m| m.state = proto::FenceState::UnknownUnavailable as i32).is_err(),
            "derived state stored"
        );
        assert!(
            mutate(|m| m.state = proto::FenceState::TargetWritable as i32).is_err(),
            "state/role mismatch"
        );
        assert!(mutate(|m| m.role = 0).is_err(), "unspecified role");
        assert!(mutate(|m| m.operation_id = "not-a-uuid".into()).is_err());
        assert!(
            mutate(|m| m.operation_id = m.operation_id.replace('-', "")).is_err(),
            "non-canonical id"
        );
        assert!(mutate(|m| m.namespace = String::new()).is_err());
        assert!(mutate(|m| m.legacy_blocks = None).is_err());
        assert!(mutate(|m| m.written_by = None).is_err());
        assert!(
            mutate(|m| m.frozen_boundary = None).is_err(),
            "fenced without boundary"
        );
        assert!(
            mutate(|m| m.log_id = None).is_err(),
            "source without identity"
        );
        assert!(
            mutate(|m| {
                m.revision = 0;
            })
            .is_err(),
            "revision zero"
        );
        assert!(
            mutate(|m| m.drain_policy.as_mut().unwrap().on_deadline = 0).is_err(),
            "unspecified drain policy"
        );
    }

    #[test]
    fn invalid_receipts_are_rejected() {
        let enc = |f: &dyn Fn(&mut proto::CommandReceipt)| {
            let mut m = codec::receipt_to_proto(&sample_receipt());
            f(&mut m);
            CommandReceipt::decode(FENCE_FORMAT_VERSION, &m.encode_to_vec())
        };
        assert!(enc(&|m| m.fingerprint = vec![1; 31]).is_err());
        assert!(enc(&|m| m.outcome = 0).is_err());
        assert!(enc(&|m| m.command = 0).is_err());
        assert!(enc(&|m| m.state_after = proto::FenceState::Unfenced as i32).is_err());
        assert!(
            enc(&|m| m.revision_before = 5).is_err(),
            "revision went backwards"
        );
    }

    #[test]
    fn legacy_mirror_follows_state() {
        let mut record = sample_record();
        let m = record.legacy_mirror();
        assert!(!m.block_reads);
        assert!(m.block_writes);
        assert!(m.block_reason.unwrap().contains("SOURCE_WRITE_FENCED"));

        record.state = FenceState::SourceReadFenced;
        let m = record.legacy_mirror();
        assert!(m.block_reads && m.block_writes);

        record.state = FenceState::Released;
        assert_eq!(record.legacy_mirror(), record.legacy_blocks);

        record.role = Role::Target;
        record.state = FenceState::TargetQuarantined;
        let m = record.legacy_mirror();
        assert!(m.block_reads && m.block_writes);
        record.state = FenceState::TargetWriteFenced;
        let m = record.legacy_mirror();
        assert!(!m.block_reads && m.block_writes);
    }
}
