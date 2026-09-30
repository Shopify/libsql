//! The fence audit log (`docs/NAMESPACE_FENCE.md` sections 12 and 15): structured events under
//! the tracing target [`AUDIT_TARGET`], so that a log pipeline can route them apart from the
//! server's operational logs.

use crate::namespace::meta_store::FenceCommit;
use crate::namespace::NamespaceName;

/// The tracing target of every fence audit event.
pub const AUDIT_TARGET: &str = "libsql_server::fence::audit";

/// One audit event for a committed `AdoptFence`: who adopted what from whom, the two recorded
/// approvers, the incident reference and the reason, and the revisions. The server cannot
/// verify the approvers (section 12); the event is the record of what the request claimed.
pub fn adoption(namespace: &NamespaceName, commit: &FenceCommit) {
    let receipt = &commit.receipt;
    let Some(adoption) = &receipt.adoption else {
        return;
    };
    tracing::info!(
        target: AUDIT_TARGET,
        event = "namespace_fence_adopted",
        namespace = %namespace,
        command = receipt.command.as_str(),
        outcome = receipt.outcome.as_str(),
        state = receipt.state_after.as_str(),
        previous_operation_id = %adoption.previous_operation_id,
        operation_id = %adoption.new_operation_id,
        command_id = %adoption.command_id,
        approvers = ?adoption.approvers,
        incident_ref = %adoption.incident_ref,
        reason = %adoption.reason,
        revision_before = receipt.revision_before,
        revision_after = receipt.revision_after,
        server_instance = %receipt.instance_id,
        "namespace fence adopted"
    );
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use uuid::Uuid;

    use super::*;
    use crate::namespace::fence::command::{AdoptArgs, FenceCommand, FenceRequest};
    use crate::namespace::fence::outcome::FenceOutcome;
    use crate::namespace::fence::record::{Adoption, CommandReceipt};
    use crate::namespace::fence::state::FenceState;
    use crate::namespace::meta_store::FenceCommitKind;

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn capture(f: impl FnOnce()) -> String {
        let captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::INFO)
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        let bytes = captured.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    fn commit(adoption: Option<Adoption>) -> FenceCommit {
        let args = AdoptArgs {
            current_operation_id: Uuid::from_u128(0xa),
            approvers: vec!["alice".into(), "bob".into()],
            incident_ref: "INC-1".into(),
            reason: "control record lost".into(),
        };
        let request = FenceRequest {
            namespace: "ns".into(),
            operation_id: Uuid::from_u128(0xb),
            command_id: Uuid::from_u128(3),
            expected_state: FenceState::SourceWriteFenced,
            expected_revision: 2,
            command: FenceCommand::AdoptFence(args),
        };
        FenceCommit {
            kind: FenceCommitKind::Committed,
            receipt: CommandReceipt {
                namespace: "ns".into(),
                operation_id: request.operation_id,
                command_id: request.command_id,
                command: request.command.kind(),
                fingerprint: request.fingerprint(),
                outcome: FenceOutcome::Applied,
                revision_before: 2,
                revision_after: 3,
                state_after: FenceState::SourceWriteFenced,
                applied_at_ms: 1_000,
                instance_id: Uuid::from_u128(0x99),
                adoption,
            },
            record: None,
            created_config: None,
        }
    }

    /// A committed adoption is one event under the audit target with every field section 12
    /// asks for; a receipt without an adoption emits nothing.
    #[test]
    fn adoption_event_fields() {
        let entry = Adoption {
            previous_operation_id: Uuid::from_u128(0xa),
            new_operation_id: Uuid::from_u128(0xb),
            command_id: Uuid::from_u128(3),
            approvers: vec!["alice".into(), "bob".into()],
            incident_ref: "INC-1".into(),
            reason: "control record lost".into(),
            at_ms: 1_000,
            revision: 3,
        };
        let out = capture(|| super::adoption(&"ns".into(), &commit(Some(entry.clone()))));
        assert_eq!(out.lines().count(), 1, "{out}");
        for expected in [
            AUDIT_TARGET,
            "namespace fence adopted",
            "event=\"namespace_fence_adopted\"",
            "namespace=ns",
            "command=\"AdoptFence\"",
            "outcome=\"APPLIED\"",
            "state=\"SOURCE_WRITE_FENCED\"",
            &format!("previous_operation_id={}", Uuid::from_u128(0xa)),
            &format!("operation_id={}", Uuid::from_u128(0xb)),
            &format!("command_id={}", Uuid::from_u128(3)),
            "approvers=[\"alice\", \"bob\"]",
            "incident_ref=INC-1",
            "reason=control record lost",
            "revision_before=2",
            "revision_after=3",
            &format!("server_instance={}", Uuid::from_u128(0x99)),
        ] {
            assert!(out.contains(expected), "`{expected}` missing from {out}");
        }

        let out = capture(|| super::adoption(&"ns".into(), &commit(None)));
        assert!(out.is_empty(), "{out}");
    }
}
