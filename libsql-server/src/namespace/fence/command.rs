//! Fence commands, requests and their canonical fingerprint (`docs/NAMESPACE_FENCE.md`
//! sections 4.2, 4.4 and 5.3).

use std::fmt;

use prost::Message as _;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::namespace::NamespaceName;

use super::proto;
use super::record::codec;
use super::state::FenceState;

/// Largest accepted `RecordTargetValidation` summary, in bytes.
pub const MAX_VALIDATION_SUMMARY_BYTES: usize = 4096;

/// What happens when a drain deadline passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OnDeadline {
    /// Answer `DRAINING`; the durable state stays draining and admission stays closed.
    Fail,
    /// Roll back (or cancel, for reads) the work still holding the drain open, then keep
    /// waiting for it to actually end.
    ForceRollback,
}

impl OnDeadline {
    pub const fn as_str(self) -> &'static str {
        match self {
            OnDeadline::Fail => "fail",
            OnDeadline::ForceRollback => "force_rollback",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DrainPolicy {
    pub deadline_ms: u64,
    pub on_deadline: OnDeadline,
}

/// The subset of namespace configuration `CreateTargetQuarantined` accepts. Restore options
/// and dump URLs are not part of it: import goes through the migration capability.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct TargetConfig {
    pub max_db_size: Option<u64>,
    pub jwt_key: Option<String>,
    pub txn_timeout_s: Option<u64>,
    pub allow_attach: bool,
    pub durability_mode: Option<String>,
    pub bottomless_db_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValidationResult {
    Ok,
    Failed,
}

impl ValidationResult {
    pub const fn as_str(self) -> &'static str {
        match self {
            ValidationResult::Ok => "ok",
            ValidationResult::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AdoptArgs {
    /// The operation that currently owns the record, as the adopter believes it.
    pub current_operation_id: Uuid,
    /// Two distinct, non-empty identities. Recorded, not verified (section 12).
    pub approvers: Vec<String>,
    pub incident_ref: String,
    pub reason: String,
}

/// A mutating fence command and its command-specific arguments.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FenceCommand {
    AcquireSourceWriteFence {
        /// The replication log id the caller observed on the source.
        expected_log_id: Uuid,
        drain_policy: Option<DrainPolicy>,
    },
    SetSourceReadFence {
        drain_policy: Option<DrainPolicy>,
    },
    ClearSourceReadFence,
    ReleaseSourceWriteFence,
    CreateTargetQuarantined {
        config: TargetConfig,
    },
    SealTargetImport {
        drain_policy: Option<DrainPolicy>,
    },
    RecordTargetValidation {
        result: ValidationResult,
        summary: String,
    },
    PublishTargetReadableWriteFenced,
    EnableTargetWrites,
    AbortQuarantinedTarget,
    AdoptFence(AdoptArgs),
}

/// The kind of a command, without its arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommandKind {
    AcquireSourceWriteFence,
    SetSourceReadFence,
    ClearSourceReadFence,
    ReleaseSourceWriteFence,
    CreateTargetQuarantined,
    SealTargetImport,
    RecordTargetValidation,
    PublishTargetReadableWriteFenced,
    EnableTargetWrites,
    AbortQuarantinedTarget,
    AdoptFence,
}

impl CommandKind {
    pub const ALL: [CommandKind; 11] = [
        CommandKind::AcquireSourceWriteFence,
        CommandKind::SetSourceReadFence,
        CommandKind::ClearSourceReadFence,
        CommandKind::ReleaseSourceWriteFence,
        CommandKind::CreateTargetQuarantined,
        CommandKind::SealTargetImport,
        CommandKind::RecordTargetValidation,
        CommandKind::PublishTargetReadableWriteFenced,
        CommandKind::EnableTargetWrites,
        CommandKind::AbortQuarantinedTarget,
        CommandKind::AdoptFence,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            CommandKind::AcquireSourceWriteFence => "AcquireSourceWriteFence",
            CommandKind::SetSourceReadFence => "SetSourceReadFence",
            CommandKind::ClearSourceReadFence => "ClearSourceReadFence",
            CommandKind::ReleaseSourceWriteFence => "ReleaseSourceWriteFence",
            CommandKind::CreateTargetQuarantined => "CreateTargetQuarantined",
            CommandKind::SealTargetImport => "SealTargetImport",
            CommandKind::RecordTargetValidation => "RecordTargetValidation",
            CommandKind::PublishTargetReadableWriteFenced => "PublishTargetReadableWriteFenced",
            CommandKind::EnableTargetWrites => "EnableTargetWrites",
            CommandKind::AbortQuarantinedTarget => "AbortQuarantinedTarget",
            CommandKind::AdoptFence => "AdoptFence",
        }
    }

    /// The state a successful command finally leaves the record in, where that is a single
    /// state. A command from the owner whose goal state the record is already in is
    /// `ALREADY_APPLIED`. `RecordTargetValidation` and `AdoptFence` do not move the state and
    /// have none.
    pub const fn goal_state(self) -> Option<FenceState> {
        match self {
            CommandKind::AcquireSourceWriteFence => Some(FenceState::SourceWriteFenced),
            CommandKind::SetSourceReadFence => Some(FenceState::SourceReadFenced),
            CommandKind::ClearSourceReadFence => Some(FenceState::SourceWriteFenced),
            CommandKind::ReleaseSourceWriteFence => Some(FenceState::Released),
            CommandKind::CreateTargetQuarantined => Some(FenceState::TargetQuarantined),
            CommandKind::SealTargetImport => Some(FenceState::TargetValidating),
            CommandKind::PublishTargetReadableWriteFenced => Some(FenceState::TargetWriteFenced),
            CommandKind::EnableTargetWrites => Some(FenceState::TargetWritable),
            CommandKind::AbortQuarantinedTarget => Some(FenceState::TargetAborted),
            CommandKind::RecordTargetValidation | CommandKind::AdoptFence => None,
        }
    }
}

impl fmt::Display for CommandKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FenceCommand {
    pub fn kind(&self) -> CommandKind {
        match self {
            FenceCommand::AcquireSourceWriteFence { .. } => CommandKind::AcquireSourceWriteFence,
            FenceCommand::SetSourceReadFence { .. } => CommandKind::SetSourceReadFence,
            FenceCommand::ClearSourceReadFence => CommandKind::ClearSourceReadFence,
            FenceCommand::ReleaseSourceWriteFence => CommandKind::ReleaseSourceWriteFence,
            FenceCommand::CreateTargetQuarantined { .. } => CommandKind::CreateTargetQuarantined,
            FenceCommand::SealTargetImport { .. } => CommandKind::SealTargetImport,
            FenceCommand::RecordTargetValidation { .. } => CommandKind::RecordTargetValidation,
            FenceCommand::PublishTargetReadableWriteFenced => {
                CommandKind::PublishTargetReadableWriteFenced
            }
            FenceCommand::EnableTargetWrites => CommandKind::EnableTargetWrites,
            FenceCommand::AbortQuarantinedTarget => CommandKind::AbortQuarantinedTarget,
            FenceCommand::AdoptFence(_) => CommandKind::AdoptFence,
        }
    }
}

/// One mutating request: the common fields of section 4.2 and the command.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FenceRequest {
    pub namespace: NamespaceName,
    pub operation_id: Uuid,
    pub command_id: Uuid,
    /// `Unfenced` or `Absent` for a namespace with no record.
    pub expected_state: FenceState,
    /// `0` for a namespace with no record.
    pub expected_revision: u64,
    pub command: FenceCommand,
}

impl FenceRequest {
    /// SHA-256 of the deterministic protobuf encoding of everything in the request except
    /// `command_id` (section 5.3). Two requests with the same `(operation_id, command_id)` and
    /// different fingerprints are a `FENCE_COMMAND_CONFLICT`.
    pub fn fingerprint(&self) -> Fingerprint {
        let input = proto::FingerprintInput {
            namespace: self.namespace.as_str().to_string(),
            operation_id: self.operation_id.to_string(),
            kind: codec::command_kind_to_proto(self.command.kind()) as i32,
            expected_state: codec::state_to_proto(self.expected_state) as i32,
            expected_revision: self.expected_revision,
            args: fingerprint_args(&self.command),
        };
        Fingerprint(Sha256::digest(input.encode_to_vec()).into())
    }
}

fn fingerprint_args(command: &FenceCommand) -> Option<proto::fingerprint_input::Args> {
    use proto::fingerprint_input::Args;

    let drain = |p: &Option<DrainPolicy>| proto::DrainArgs {
        drain_policy: p.as_ref().map(codec::drain_policy_to_proto),
    };

    match command {
        FenceCommand::AcquireSourceWriteFence {
            expected_log_id,
            drain_policy,
        } => Some(Args::AcquireSourceWriteFence(
            proto::AcquireSourceWriteFenceArgs {
                expected_log_id: expected_log_id.to_string(),
                drain_policy: drain_policy.as_ref().map(codec::drain_policy_to_proto),
            },
        )),
        FenceCommand::SetSourceReadFence { drain_policy } => {
            Some(Args::SetSourceReadFence(drain(drain_policy)))
        }
        FenceCommand::SealTargetImport { drain_policy } => {
            Some(Args::SealTargetImport(drain(drain_policy)))
        }
        FenceCommand::CreateTargetQuarantined { config } => Some(Args::CreateTargetQuarantined(
            codec::target_config_to_proto(config),
        )),
        FenceCommand::RecordTargetValidation { result, summary } => Some(
            Args::RecordTargetValidation(proto::RecordTargetValidationArgs {
                result: codec::validation_result_to_proto(*result) as i32,
                summary: summary.clone(),
            }),
        ),
        FenceCommand::AdoptFence(args) => Some(Args::AdoptFence(proto::AdoptFenceArgs {
            current_operation_id: args.current_operation_id.to_string(),
            approvers: args.approvers.clone(),
            incident_ref: args.incident_ref.clone(),
            reason: args.reason.clone(),
        })),
        FenceCommand::ClearSourceReadFence
        | FenceCommand::ReleaseSourceWriteFence
        | FenceCommand::PublishTargetReadableWriteFenced
        | FenceCommand::EnableTargetWrites
        | FenceCommand::AbortQuarantinedTarget => None,
    }
}

/// A canonical request fingerprint.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint(pub [u8; 32]);

impl Fingerprint {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("sha256:")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(command: FenceCommand) -> FenceRequest {
        FenceRequest {
            namespace: NamespaceName::from("db1"),
            operation_id: Uuid::from_u128(1),
            command_id: Uuid::from_u128(2),
            expected_state: FenceState::Unfenced,
            expected_revision: 0,
            command,
        }
    }

    fn acquire() -> FenceCommand {
        FenceCommand::AcquireSourceWriteFence {
            expected_log_id: Uuid::from_u128(3),
            drain_policy: Some(DrainPolicy {
                deadline_ms: 1000,
                on_deadline: OnDeadline::Fail,
            }),
        }
    }

    #[test]
    fn fingerprint_ignores_command_id() {
        let a = request(acquire());
        let mut b = a.clone();
        b.command_id = Uuid::from_u128(99);
        assert_eq!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn fingerprint_covers_every_other_field() {
        let base = request(acquire());
        let fp = base.fingerprint();

        let mut changed = Vec::new();
        let mut r = base.clone();
        r.namespace = NamespaceName::from("db2");
        changed.push(r);
        let mut r = base.clone();
        r.operation_id = Uuid::from_u128(7);
        changed.push(r);
        let mut r = base.clone();
        r.expected_state = FenceState::Released;
        changed.push(r);
        let mut r = base.clone();
        r.expected_revision = 1;
        changed.push(r);
        let mut r = base.clone();
        r.command = FenceCommand::AcquireSourceWriteFence {
            expected_log_id: Uuid::from_u128(4),
            drain_policy: Some(DrainPolicy {
                deadline_ms: 1000,
                on_deadline: OnDeadline::Fail,
            }),
        };
        changed.push(r);
        let mut r = base.clone();
        r.command = FenceCommand::AcquireSourceWriteFence {
            expected_log_id: Uuid::from_u128(3),
            drain_policy: Some(DrainPolicy {
                deadline_ms: 1000,
                on_deadline: OnDeadline::ForceRollback,
            }),
        };
        changed.push(r);
        let mut r = base.clone();
        r.command = FenceCommand::AcquireSourceWriteFence {
            expected_log_id: Uuid::from_u128(3),
            drain_policy: None,
        };
        changed.push(r);

        for r in changed {
            assert_ne!(r.fingerprint(), fp, "{r:?}");
        }
    }

    #[test]
    fn fingerprint_distinguishes_argumentless_commands() {
        let kinds = [
            FenceCommand::ClearSourceReadFence,
            FenceCommand::ReleaseSourceWriteFence,
            FenceCommand::PublishTargetReadableWriteFenced,
            FenceCommand::EnableTargetWrites,
            FenceCommand::AbortQuarantinedTarget,
            FenceCommand::SetSourceReadFence { drain_policy: None },
            FenceCommand::SealTargetImport { drain_policy: None },
        ];
        let fps: std::collections::HashSet<_> = kinds
            .into_iter()
            .map(|c| request(c).fingerprint())
            .collect();
        assert_eq!(fps.len(), 7);
    }

    /// The fingerprint is stored in receipts and compared on every replay, so its encoding must
    /// never change: a change would turn every stored receipt into a command conflict.
    #[test]
    fn fingerprint_is_stable() {
        assert_eq!(
            request(acquire()).fingerprint().to_string(),
            "sha256:c585d3570b5eb5a3ef9b8efb89eca26e2336c7e19a561fa3db667c4cde905515"
        );
    }

    #[test]
    fn every_kind_has_a_name() {
        let names: std::collections::HashSet<_> =
            CommandKind::ALL.iter().map(|k| k.as_str()).collect();
        assert_eq!(names.len(), CommandKind::ALL.len());
    }
}
