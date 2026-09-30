//! The primary's fence as a replica server sees it (`docs/NAMESPACE_FENCE.md` section 6.2).
//!
//! A replica server holds a copy of a primary's namespace and serves reads of it locally. When
//! the primary's fence denies reads (a source read fence, a quarantined or aborted target, a
//! fence state the primary cannot establish), the primary refuses the replica's replication
//! calls and ends its streams with a typed `FAILED_PRECONDITION` status, and a `hello` it does
//! answer carries the fence it has. This module turns both into the local read denial the
//! replica publishes on its own fence controller
//! ([`FenceController::observe_primary`](super::controller::FenceController::observe_primary)),
//! and paces the replicator's reconnects while the primary keeps refusing.

use std::time::Duration;

use libsql_replication::replicator::Error as ReplicatorError;
use libsql_replication::rpc::metadata::ReplicatedFence;

use super::outcome::{FenceError, OutcomeKind};
use super::state::{FenceState, OperationClass};

/// The first pause after the primary refuses replication with a fence code.
pub const REFUSAL_BACKOFF_INITIAL: Duration = Duration::from_secs(1);
/// The longest pause between two replication attempts the primary's fence refused. It bounds
/// how long a replica keeps denying reads after the primary admits them again.
pub const REFUSAL_BACKOFF_MAX: Duration = Duration::from_secs(15);

/// A replication call the primary refused, or a stream it ended, because its fence denies
/// replication of the namespace. Carried in [`ReplicatorError::Internal`], which the
/// replicator's handshake loop does not retry by itself, so that the replica's own loop can
/// pace the next attempt.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the primary refused replication: {0}")]
pub struct PrimaryFenceRefusal(pub FenceError);

impl PrimaryFenceRefusal {
    /// The refusal a replication status reports: a data-plane fence denial in the typed form of
    /// section 6 (`FAILED_PRECONDITION` with the stable code in `x-libsql-fence-code`). `None`
    /// for every other status, which keeps its existing handling.
    pub fn from_status(status: &tonic::Status) -> Option<Self> {
        let denial = FenceError::from_grpc_status(status)?;
        (denial.outcome().kind() == OutcomeKind::DataPlane).then_some(Self(denial))
    }

    /// The refusal `error` carries, if it is one.
    pub fn of(error: &ReplicatorError) -> Option<&Self> {
        match error {
            ReplicatorError::Internal(e) => e.downcast_ref::<Self>(),
            _ => None,
        }
    }

    /// The local read denial it implies. Replication is `Stream` work, whose column of the
    /// permission matrix equals the normal-read column, so every data-plane refusal of it
    /// means the primary denies reads.
    pub fn local_denial(&self) -> FenceError {
        FenceError::new(
            self.0.outcome(),
            format!(
                "the primary denies reads of this namespace: {}",
                self.0.message()
            ),
        )
    }
}

/// `status` as a replicator error: a [`PrimaryFenceRefusal`] for a fence denial, the
/// replicator's own mapping otherwise.
pub fn replicator_error(status: tonic::Status) -> ReplicatorError {
    match PrimaryFenceRefusal::from_status(&status) {
        Some(refusal) => ReplicatorError::Internal(Box::new(refusal)),
        None => status.into(),
    }
}

/// The local read denial the fence a primary's `hello` replicated implies: `Some` only for a
/// known state whose normal-read column denies. The primary answers `hello` only where it
/// admits streams, so this is `None` in practice; a state this server does not know is not
/// a denial for the same reason.
pub fn denial_from_hello(fence: Option<&ReplicatedFence>) -> Option<FenceError> {
    let fence = fence?;
    let state = fence.state.parse::<FenceState>().ok()?;
    let outcome = state.permits(OperationClass::NormalRead).err()?;
    Some(FenceError::new(
        outcome,
        format!(
            "the primary's fence is {} at revision {}",
            fence.state, fence.revision
        ),
    ))
}

/// The pause before the next replication attempt after `consecutive` refusals in a row
/// (counting the one just received): doubling from [`REFUSAL_BACKOFF_INITIAL`] up to
/// [`REFUSAL_BACKOFF_MAX`].
pub fn refusal_backoff(consecutive: u32) -> Duration {
    let doublings = consecutive.saturating_sub(1).min(16);
    REFUSAL_BACKOFF_INITIAL
        .saturating_mul(1 << doublings)
        .min(REFUSAL_BACKOFF_MAX)
}

#[cfg(test)]
mod tests {
    use tonic::Code;

    use super::super::outcome::FenceOutcome;
    use super::*;

    fn status(outcome: FenceOutcome) -> tonic::Status {
        FenceError::new(outcome, "no")
            .to_grpc_status()
            .expect("data-plane outcomes have a gRPC mapping")
    }

    #[test]
    fn refusal_from_typed_status_only() {
        for outcome in [
            FenceOutcome::MigrationReadFenced,
            FenceOutcome::MigrationTargetQuarantined,
            FenceOutcome::FenceStateUnavailable,
        ] {
            let refusal = PrimaryFenceRefusal::from_status(&status(outcome)).unwrap();
            assert_eq!(refusal.0.outcome(), outcome);
            let denial = refusal.local_denial();
            assert_eq!(denial.outcome(), outcome);
            assert!(
                denial.message().contains("the primary denies reads"),
                "{denial}"
            );

            let error = replicator_error(status(outcome));
            assert_eq!(PrimaryFenceRefusal::of(&error), Some(&refusal));
        }

        // Untyped statuses keep the replicator's own mapping.
        for status in [
            tonic::Status::new(Code::FailedPrecondition, "MIGRATION_READ_FENCED: no"),
            tonic::Status::new(Code::Unavailable, "down"),
            tonic::Status::new(
                Code::FailedPrecondition,
                libsql_replication::rpc::replication::NAMESPACE_DOESNT_EXIST,
            ),
        ] {
            assert!(PrimaryFenceRefusal::from_status(&status).is_none());
            assert!(PrimaryFenceRefusal::of(&replicator_error(status)).is_none());
        }
        assert!(matches!(
            replicator_error(tonic::Status::new(
                Code::FailedPrecondition,
                libsql_replication::rpc::replication::NEED_SNAPSHOT_ERROR_MSG
            )),
            ReplicatorError::NeedSnapshot
        ));

        // A control outcome is never a replication refusal.
        let mut control = tonic::Status::new(Code::FailedPrecondition, "x");
        control.metadata_mut().insert(
            super::super::outcome::GRPC_FENCE_CODE_METADATA,
            tonic::metadata::MetadataValue::from_static("FENCE_PRECONDITION_FAILED"),
        );
        assert!(PrimaryFenceRefusal::from_status(&control).is_none());
    }

    #[test]
    fn hello_fence_denies_only_read_denying_states() {
        let fence = |state: &str| ReplicatedFence {
            state: state.into(),
            revision: 7,
        };
        assert_eq!(denial_from_hello(None), None);
        for state in [
            "SOURCE_DRAINING",
            "SOURCE_WRITE_FENCED",
            "TARGET_WRITE_FENCED",
            "SOMETHING_NEWER",
        ] {
            assert_eq!(denial_from_hello(Some(&fence(state))), None, "{state}");
        }
        for (state, outcome) in [
            ("SOURCE_READ_DRAINING", FenceOutcome::MigrationReadFenced),
            ("SOURCE_READ_FENCED", FenceOutcome::MigrationReadFenced),
            (
                "TARGET_QUARANTINED",
                FenceOutcome::MigrationTargetQuarantined,
            ),
            ("UNKNOWN_UNAVAILABLE", FenceOutcome::FenceStateUnavailable),
        ] {
            let denial = denial_from_hello(Some(&fence(state))).unwrap();
            assert_eq!(denial.outcome(), outcome, "{state}");
            assert!(denial.message().contains("revision 7"), "{denial}");
        }
    }

    #[test]
    fn backoff_doubles_to_its_cap() {
        let delays: Vec<_> = (1..=7).map(refusal_backoff).collect();
        assert_eq!(
            delays,
            [1, 2, 4, 8, 15, 15, 15].map(Duration::from_secs).to_vec()
        );
        assert_eq!(refusal_backoff(0), REFUSAL_BACKOFF_INITIAL);
        assert_eq!(refusal_backoff(u32::MAX), REFUSAL_BACKOFF_MAX);
    }

    #[test]
    fn observed_denial_refuses_local_reads_and_cancels_leases() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        use super::super::controller::{FenceController, LeaseKind};
        use crate::namespace::NamespaceName;

        let fence = FenceController::unfenced(NamespaceName::from_string("ns".into()).unwrap());
        let cancels = Arc::new(AtomicUsize::new(0));
        let lease = fence
            .acquire_read_lease(OperationClass::NormalRead, LeaseKind::Sql, {
                let cancels = cancels.clone();
                move || {
                    cancels.fetch_add(1, Ordering::SeqCst);
                }
            })
            .unwrap();
        let generation = fence.write_generation();
        let refusal =
            PrimaryFenceRefusal::from_status(&status(FenceOutcome::MigrationReadFenced)).unwrap();

        assert!(fence.observe_primary(Some(refusal.local_denial())));
        assert_eq!(cancels.load(Ordering::SeqCst), 1);
        assert!(lease.cancelled_by_fence());
        for class in [OperationClass::NormalRead, OperationClass::Stream] {
            let err = fence.permits(class).unwrap_err();
            assert_eq!(
                err.outcome(),
                FenceOutcome::MigrationReadFenced,
                "{class:?}"
            );
        }
        // Writes are the primary's to refuse; maintenance goes on.
        for class in [OperationClass::NormalWrite, OperationClass::Maintenance] {
            assert!(fence.permits(class).is_ok(), "{class:?}");
        }
        assert!(fence
            .acquire_read_lease(OperationClass::Stream, LeaseKind::Dump, || ())
            .is_err());
        // The same code again, from another call, is the same denial.
        assert!(!fence.observe_primary(Some(refusal.local_denial())));
        assert_eq!(cancels.load(Ordering::SeqCst), 1);
        // A different code replaces it.
        let quarantined =
            PrimaryFenceRefusal::from_status(&status(FenceOutcome::MigrationTargetQuarantined))
                .unwrap();
        assert!(fence.observe_primary(Some(quarantined.local_denial())));
        assert_eq!(
            fence
                .permits(OperationClass::NormalRead)
                .unwrap_err()
                .outcome(),
            FenceOutcome::MigrationTargetQuarantined
        );

        assert!(fence.observe_primary(None));
        assert!(fence.permits(OperationClass::NormalRead).is_ok());
        assert!(!fence.observe_primary(None));
        // Only reads were affected: the write generation never moved.
        assert_eq!(fence.write_generation(), generation);
        drop(lease);
    }
}
