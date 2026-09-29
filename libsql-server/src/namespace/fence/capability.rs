//! Migration capabilities (`docs/NAMESPACE_FENCE.md` sections 7.3 and 11).
//!
//! A [`MigrationCapability`] is the only thing that lets operation-owned work through a
//! target's quarantine. The server creates it ([`FenceController::issue_capability`]); its
//! fields are private and it cannot be built from outside this module, so holding one is proof
//! that the fence issued it. It names the namespace, the owning operation, what it is for and
//! the fence revision it was issued at, and it is valid only while the fence is still in the
//! state its purpose needs, at that revision, owned by that operation, and while the controller
//! still lists it as live. Every transition of the target moves the revision, so a capability
//! never outlives the state it was issued in.
//!
//! [`FenceController::issue_capability`]: super::controller::FenceController::issue_capability

use std::collections::HashMap;
use std::sync::Arc;

use uuid::Uuid;

use crate::namespace::NamespaceName;

use super::controller::FenceController;
use super::outcome::{FenceError, FenceOutcome};
use super::state::{FenceState, OperationClass};
use super::store::StoredFence;

/// What a capability admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CapabilityPurpose {
    /// Writes of an import session into a `TARGET_QUARANTINED` target.
    Import,
    /// Read-only validation of a `TARGET_VALIDATING` or `TARGET_WRITE_FENCED` target.
    Validate,
}

impl CapabilityPurpose {
    /// The operation class work under a capability of this purpose is admitted as.
    pub const fn class(self) -> OperationClass {
        match self {
            CapabilityPurpose::Import => OperationClass::CapabilityImport,
            CapabilityPurpose::Validate => OperationClass::CapabilityValidate,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            CapabilityPurpose::Import => "import",
            CapabilityPurpose::Validate => "validate",
        }
    }

    /// Whether a capability of this purpose may be issued, and stays valid, in `state`.
    pub const fn admits(self, state: FenceState) -> bool {
        match self {
            CapabilityPurpose::Import => matches!(state, FenceState::TargetQuarantined),
            CapabilityPurpose::Validate => matches!(
                state,
                FenceState::TargetValidating | FenceState::TargetWriteFenced
            ),
        }
    }
}

/// A server-issued grant for operation-owned work on one namespace, valid at one fence
/// revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationCapability {
    id: Uuid,
    namespace: NamespaceName,
    operation_id: Uuid,
    purpose: CapabilityPurpose,
    fence_revision: u64,
}

impl MigrationCapability {
    /// Only the controller issues capabilities.
    pub(super) fn issue(
        namespace: NamespaceName,
        operation_id: Uuid,
        purpose: CapabilityPurpose,
        fence_revision: u64,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            namespace,
            operation_id,
            purpose,
            fence_revision,
        }
    }

    /// A capability the controller never issued, for tests that prove such a thing is refused.
    #[cfg(test)]
    pub(crate) fn forged(
        namespace: NamespaceName,
        operation_id: Uuid,
        purpose: CapabilityPurpose,
        fence_revision: u64,
    ) -> Self {
        Self::issue(namespace, operation_id, purpose, fence_revision)
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }

    pub fn operation_id(&self) -> Uuid {
        self.operation_id
    }

    pub fn purpose(&self) -> CapabilityPurpose {
        self.purpose
    }

    pub fn fence_revision(&self) -> u64 {
        self.fence_revision
    }

    pub fn class(&self) -> OperationClass {
        self.purpose.class()
    }

    /// Whether `fence` is still the fence this capability was issued against: the state its
    /// purpose needs, owned by its operation, at its revision.
    pub(crate) fn matches(&self, fence: &StoredFence) -> bool {
        self.check(fence).is_ok()
    }

    /// [`matches`](Self::matches), with the refusal a holder gets when it does not.
    pub(crate) fn check(&self, fence: &StoredFence) -> Result<(), FenceError> {
        let Some(record) = fence.record() else {
            return Err(stale(
                self,
                format!("namespace `{}` has no fence record", self.namespace),
            ));
        };
        if record.operation_id != self.operation_id {
            return Err(FenceError::new(
                FenceOutcome::FenceOwnedByAnotherOperation,
                format!(
                    "the fence of namespace `{}` is owned by operation {}, not by operation {} \
                     that holds this {} capability",
                    self.namespace,
                    record.operation_id,
                    self.operation_id,
                    self.purpose.as_str()
                ),
            ));
        }
        if !self.purpose.admits(record.state) {
            return Err(stale(
                self,
                format!(
                    "namespace `{}` is in {}, which admits no {} capability",
                    self.namespace,
                    record.state,
                    self.purpose.as_str()
                ),
            ));
        }
        if record.revision != self.fence_revision {
            return Err(stale(
                self,
                format!(
                    "the fence of namespace `{}` is at revision {}, and this {} capability was \
                     issued at revision {}",
                    self.namespace,
                    record.revision,
                    self.purpose.as_str(),
                    self.fence_revision
                ),
            ));
        }
        Ok(())
    }
}

fn stale(cap: &MigrationCapability, why: String) -> FenceError {
    FenceError::new(
        FenceOutcome::OperationCapabilityRequired,
        format!(
            "{why}: the {} capability {} is no longer valid",
            cap.purpose.as_str(),
            cap.id
        ),
    )
}

/// The capabilities a controller has issued and not yet revoked, and the import calls running
/// under them.
#[derive(Debug, Default)]
pub(super) struct CapabilitySet {
    pub(super) live: HashMap<Uuid, MigrationCapability>,
    /// Import calls running now ([`ImportWriter`]s).
    pub(super) import_writers: usize,
}

/// One running import call under a capability. The seal waits for every one of them to be
/// dropped (section 10.2).
#[derive(Debug)]
pub struct ImportWriter {
    pub(super) controller: Arc<FenceController>,
}

impl Drop for ImportWriter {
    fn drop(&mut self) {
        self.controller.end_import_write();
    }
}
