//! Roles, states, operation classes and the permission matrix of `docs/NAMESPACE_FENCE.md`
//! sections 3 and 7.3.

use std::fmt;
use std::str::FromStr;

use super::outcome::FenceOutcome;

/// Which side of a move a fence record belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    Source,
    Target,
}

impl Role {
    pub const fn as_str(self) -> &'static str {
        match self {
            Role::Source => "SOURCE",
            Role::Target => "TARGET",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The state of a namespace as the fence sees it.
///
/// `Unfenced` and `Absent` describe a namespace with no record (an ordinary namespace, or no
/// namespace at all). `UnknownUnavailable` is derived when the server cannot establish the
/// control state. None of those three is ever stored in a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FenceState {
    Unfenced,
    Absent,
    SourceDraining,
    SourceWriteFenced,
    SourceReadDraining,
    SourceReadFenced,
    Released,
    TargetQuarantined,
    TargetImportDraining,
    TargetValidating,
    TargetWriteFenced,
    TargetWritable,
    TargetAborted,
    UnknownUnavailable,
}

impl FenceState {
    pub const ALL: [FenceState; 14] = [
        FenceState::Unfenced,
        FenceState::Absent,
        FenceState::SourceDraining,
        FenceState::SourceWriteFenced,
        FenceState::SourceReadDraining,
        FenceState::SourceReadFenced,
        FenceState::Released,
        FenceState::TargetQuarantined,
        FenceState::TargetImportDraining,
        FenceState::TargetValidating,
        FenceState::TargetWriteFenced,
        FenceState::TargetWritable,
        FenceState::TargetAborted,
        FenceState::UnknownUnavailable,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            FenceState::Unfenced => "UNFENCED",
            FenceState::Absent => "ABSENT",
            FenceState::SourceDraining => "SOURCE_DRAINING",
            FenceState::SourceWriteFenced => "SOURCE_WRITE_FENCED",
            FenceState::SourceReadDraining => "SOURCE_READ_DRAINING",
            FenceState::SourceReadFenced => "SOURCE_READ_FENCED",
            FenceState::Released => "RELEASED",
            FenceState::TargetQuarantined => "TARGET_QUARANTINED",
            FenceState::TargetImportDraining => "TARGET_IMPORT_DRAINING",
            FenceState::TargetValidating => "TARGET_VALIDATING",
            FenceState::TargetWriteFenced => "TARGET_WRITE_FENCED",
            FenceState::TargetWritable => "TARGET_WRITABLE",
            FenceState::TargetAborted => "TARGET_ABORTED",
            FenceState::UnknownUnavailable => "UNKNOWN_UNAVAILABLE",
        }
    }

    /// The role a record in this state has, if the state belongs to one.
    pub const fn role(self) -> Option<Role> {
        match self {
            FenceState::SourceDraining
            | FenceState::SourceWriteFenced
            | FenceState::SourceReadDraining
            | FenceState::SourceReadFenced
            | FenceState::Released => Some(Role::Source),
            FenceState::TargetQuarantined
            | FenceState::TargetImportDraining
            | FenceState::TargetValidating
            | FenceState::TargetWriteFenced
            | FenceState::TargetWritable
            | FenceState::TargetAborted => Some(Role::Target),
            FenceState::Unfenced | FenceState::Absent | FenceState::UnknownUnavailable => None,
        }
    }

    /// Whether this state can be stored in a fence record.
    pub const fn is_durable(self) -> bool {
        self.role().is_some()
    }

    /// Whether the operation that owns a record in this state has finished with it.
    pub const fn is_operation_finished(self) -> bool {
        matches!(
            self,
            FenceState::Released | FenceState::TargetWritable | FenceState::TargetAborted
        )
    }

    /// Whether a record in this state counts as an active fence (section 4.4,
    /// `active_fences`): anything except an ordinary namespace, a released source or a
    /// published target.
    pub const fn is_active(self) -> bool {
        !matches!(
            self,
            FenceState::Unfenced
                | FenceState::Absent
                | FenceState::Released
                | FenceState::TargetWritable
        )
    }

    /// A state in which the server is waiting for work admitted earlier to end.
    pub const fn is_draining(self) -> bool {
        matches!(
            self,
            FenceState::SourceDraining
                | FenceState::SourceReadDraining
                | FenceState::TargetImportDraining
        )
    }

    /// The permission-matrix decision for work of `class` (section 3.3).
    ///
    /// For the capability classes this decides only whether the state admits capability work
    /// at all; whether a particular capability is valid is the controller's decision.
    pub fn permits(self, class: OperationClass) -> Result<(), FenceOutcome> {
        use FenceState::*;
        use OperationClass::*;

        match class {
            Maintenance | Observability => return Ok(()),
            _ => (),
        }

        if self == UnknownUnavailable {
            return Err(FenceOutcome::FenceStateUnavailable);
        }

        match class {
            NormalRead | Stream => match self {
                Unfenced | Absent | Released | SourceDraining | SourceWriteFenced
                | TargetWriteFenced | TargetWritable => Ok(()),
                SourceReadDraining | SourceReadFenced => Err(FenceOutcome::MigrationReadFenced),
                TargetQuarantined | TargetImportDraining | TargetValidating | TargetAborted => {
                    Err(FenceOutcome::MigrationTargetQuarantined)
                }
                UnknownUnavailable => unreachable!(),
            },
            NormalWrite | Vacuum | Lifecycle => match self {
                Unfenced | Absent | Released | TargetWritable => Ok(()),
                SourceDraining | SourceWriteFenced | SourceReadDraining | SourceReadFenced
                | TargetWriteFenced => Err(FenceOutcome::MigrationWriteFenced),
                TargetQuarantined | TargetImportDraining | TargetValidating | TargetAborted => {
                    Err(FenceOutcome::MigrationTargetQuarantined)
                }
                UnknownUnavailable => unreachable!(),
            },
            CapabilityImport => match self {
                TargetQuarantined => Ok(()),
                // Existing import writers may finish while draining, but no new one starts:
                // that distinction is the controller's, which tracks issued capabilities.
                TargetImportDraining => Ok(()),
                _ => Err(FenceOutcome::OperationCapabilityRequired),
            },
            CapabilityValidate => match self {
                TargetValidating | TargetWriteFenced => Ok(()),
                _ => Err(FenceOutcome::OperationCapabilityRequired),
            },
            Maintenance | Observability => unreachable!(),
        }
    }

    /// Whether normal write admission is open in this state.
    pub fn write_admission(self) -> Admission {
        Admission::from(self.permits(OperationClass::NormalWrite))
    }

    /// Whether normal read admission is open in this state.
    pub fn read_admission(self) -> Admission {
        Admission::from(self.permits(OperationClass::NormalRead))
    }
}

impl fmt::Display for FenceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown fence state `{0}`")]
pub struct UnknownFenceState(pub String);

impl FromStr for FenceState {
    type Err = UnknownFenceState;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        FenceState::ALL
            .iter()
            .copied()
            .find(|state| state.as_str() == s)
            .ok_or_else(|| UnknownFenceState(s.to_string()))
    }
}

/// Whether an admission path is open, and if it is closed, the code a denial carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Open,
    Closed(FenceOutcome),
}

impl Admission {
    pub fn is_open(self) -> bool {
        matches!(self, Admission::Open)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Admission::Open => "open",
            Admission::Closed(_) => "closed",
        }
    }
}

impl From<Result<(), FenceOutcome>> for Admission {
    fn from(value: Result<(), FenceOutcome>) -> Self {
        match value {
            Ok(()) => Admission::Open,
            Err(code) => Admission::Closed(code),
        }
    }
}

/// The class of a piece of work, which the permission matrix is keyed by (section 7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperationClass {
    /// Any logical write that is not operation-owned: SQL over every protocol, the admin
    /// shell, schema migration, dump load outside an import capability.
    NormalWrite,
    /// Work that cannot change logical contents: `TRUNCATE` checkpoints, the storage monitor,
    /// bottomless WAL upload, the replication logger's own connection.
    Maintenance,
    /// `VACUUM`. It takes a write transaction and produces replicated frames, so it is not
    /// maintenance and is skipped wherever normal writes are denied.
    Vacuum,
    /// Generic lifecycle and configuration: config mutation, delete, reset, fork, create over
    /// an existing record, restore, dump load, shared-schema linking.
    Lifecycle,
    /// Writes of an import session holding a `MigrationCapability`.
    CapabilityImport,
    /// Read-only validation through a `MigrationCapability`.
    CapabilityValidate,
    /// SQL programs, Hrana cursors, `/beta/listen`, ATTACH of the namespace.
    NormalRead,
    /// `/dump` and replication streams (`hello`, `log_entries`, `batch_log_entries`,
    /// `snapshot`).
    Stream,
    /// Stats, jobs and metrics. Never a read lease.
    Observability,
}

impl OperationClass {
    pub const ALL: [OperationClass; 9] = [
        OperationClass::NormalWrite,
        OperationClass::Maintenance,
        OperationClass::Vacuum,
        OperationClass::Lifecycle,
        OperationClass::CapabilityImport,
        OperationClass::CapabilityValidate,
        OperationClass::NormalRead,
        OperationClass::Stream,
        OperationClass::Observability,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    use FenceOutcome as O;
    use FenceState as S;
    use OperationClass as C;

    #[test]
    fn state_names_round_trip() {
        for state in FenceState::ALL {
            assert_eq!(state.as_str().parse::<FenceState>().unwrap(), state);
        }
        assert!("source_draining".parse::<FenceState>().is_err());
        assert!("".parse::<FenceState>().is_err());
    }

    #[test]
    fn durable_states_have_a_role() {
        for state in FenceState::ALL {
            let expected = !matches!(state, S::Unfenced | S::Absent | S::UnknownUnavailable);
            assert_eq!(state.is_durable(), expected, "{state}");
        }
    }

    /// The whole permission matrix of section 3.3, row by row.
    #[test]
    fn permission_matrix() {
        let allow = Ok(());
        let wf = Err(O::MigrationWriteFenced);
        let rf = Err(O::MigrationReadFenced);
        let tq = Err(O::MigrationTargetQuarantined);
        let un = Err(O::FenceStateUnavailable);
        let cap = Err(O::OperationCapabilityRequired);

        // state: (read, stream, write, lifecycle, import, validate)
        let rows = [
            (S::Unfenced, [allow, allow, allow, allow, cap, cap]),
            (S::Released, [allow, allow, allow, allow, cap, cap]),
            (S::SourceDraining, [allow, allow, wf, wf, cap, cap]),
            (S::SourceWriteFenced, [allow, allow, wf, wf, cap, cap]),
            (S::SourceReadDraining, [rf, rf, wf, wf, cap, cap]),
            (S::SourceReadFenced, [rf, rf, wf, wf, cap, cap]),
            (S::TargetQuarantined, [tq, tq, tq, tq, allow, cap]),
            (S::TargetImportDraining, [tq, tq, tq, tq, allow, cap]),
            (S::TargetValidating, [tq, tq, tq, tq, cap, allow]),
            (S::TargetWriteFenced, [allow, allow, wf, wf, cap, allow]),
            (S::TargetWritable, [allow, allow, allow, allow, cap, cap]),
            (S::TargetAborted, [tq, tq, tq, tq, cap, cap]),
            (S::UnknownUnavailable, [un, un, un, un, un, un]),
        ];

        for (state, expected) in rows {
            let classes = [
                C::NormalRead,
                C::Stream,
                C::NormalWrite,
                C::Lifecycle,
                C::CapabilityImport,
                C::CapabilityValidate,
            ];
            for (class, expected) in classes.into_iter().zip(expected) {
                assert_eq!(state.permits(class), expected, "{state} {class:?}");
            }
            // Vacuum follows the normal write column.
            assert_eq!(
                state.permits(C::Vacuum),
                state.permits(C::NormalWrite),
                "{state}"
            );
            // Maintenance and observability continue in every state.
            assert_eq!(state.permits(C::Maintenance), Ok(()), "{state}");
            assert_eq!(state.permits(C::Observability), Ok(()), "{state}");
        }
    }

    #[test]
    fn denials_are_data_plane_codes() {
        for state in FenceState::ALL {
            for class in OperationClass::ALL {
                if let Err(code) = state.permits(class) {
                    assert!(code.is_error(), "{state} {class:?} {code}");
                }
            }
        }
    }

    #[test]
    fn active_and_finished() {
        assert!(!S::Unfenced.is_active());
        assert!(!S::Released.is_active());
        assert!(!S::TargetWritable.is_active());
        assert!(S::TargetAborted.is_active());
        assert!(S::UnknownUnavailable.is_active());
        assert!(S::SourceDraining.is_active());

        for state in FenceState::ALL {
            assert_eq!(
                state.is_operation_finished(),
                matches!(state, S::Released | S::TargetWritable | S::TargetAborted)
            );
        }
    }
}
