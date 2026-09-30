//! Stable outcome codes and their protocol mappings (`docs/NAMESPACE_FENCE.md` section 6).

use std::fmt;
use std::str::FromStr;

use hyper::StatusCode;

/// gRPC metadata key carrying the stable code of a fence denial.
pub const GRPC_FENCE_CODE_METADATA: &str = "x-libsql-fence-code";

/// Every machine-readable outcome a fence command or a fenced data-plane operation can report.
/// Clients match on [`FenceOutcome::as_str`], never on a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FenceOutcome {
    Applied,
    AlreadyApplied,
    Draining,
    MigrationWriteFenced,
    MigrationReadFenced,
    MigrationTargetQuarantined,
    FenceStateUnavailable,
    OperationCapabilityRequired,
    FenceOwnedByAnotherOperation,
    FenceRevisionMismatch,
    InvalidFenceTransition,
    FenceCommandConflict,
    FenceCommitIndeterminate,
    FencePreconditionFailed,
}

/// What kind of answer an outcome is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutcomeKind {
    Success,
    InProgress,
    /// A denial of ordinary data-plane or lifecycle work because of the fence.
    DataPlane,
    /// A refusal of a fence command (or of capability work).
    Control,
}

impl FenceOutcome {
    pub const ALL: [FenceOutcome; 14] = [
        FenceOutcome::Applied,
        FenceOutcome::AlreadyApplied,
        FenceOutcome::Draining,
        FenceOutcome::MigrationWriteFenced,
        FenceOutcome::MigrationReadFenced,
        FenceOutcome::MigrationTargetQuarantined,
        FenceOutcome::FenceStateUnavailable,
        FenceOutcome::OperationCapabilityRequired,
        FenceOutcome::FenceOwnedByAnotherOperation,
        FenceOutcome::FenceRevisionMismatch,
        FenceOutcome::InvalidFenceTransition,
        FenceOutcome::FenceCommandConflict,
        FenceOutcome::FenceCommitIndeterminate,
        FenceOutcome::FencePreconditionFailed,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            FenceOutcome::Applied => "APPLIED",
            FenceOutcome::AlreadyApplied => "ALREADY_APPLIED",
            FenceOutcome::Draining => "DRAINING",
            FenceOutcome::MigrationWriteFenced => "MIGRATION_WRITE_FENCED",
            FenceOutcome::MigrationReadFenced => "MIGRATION_READ_FENCED",
            FenceOutcome::MigrationTargetQuarantined => "MIGRATION_TARGET_QUARANTINED",
            FenceOutcome::FenceStateUnavailable => "FENCE_STATE_UNAVAILABLE",
            FenceOutcome::OperationCapabilityRequired => "OPERATION_CAPABILITY_REQUIRED",
            FenceOutcome::FenceOwnedByAnotherOperation => "FENCE_OWNED_BY_ANOTHER_OPERATION",
            FenceOutcome::FenceRevisionMismatch => "FENCE_REVISION_MISMATCH",
            FenceOutcome::InvalidFenceTransition => "INVALID_FENCE_TRANSITION",
            FenceOutcome::FenceCommandConflict => "FENCE_COMMAND_CONFLICT",
            FenceOutcome::FenceCommitIndeterminate => "FENCE_COMMIT_INDETERMINATE",
            FenceOutcome::FencePreconditionFailed => "FENCE_PRECONDITION_FAILED",
        }
    }

    pub const fn kind(self) -> OutcomeKind {
        match self {
            FenceOutcome::Applied | FenceOutcome::AlreadyApplied => OutcomeKind::Success,
            FenceOutcome::Draining => OutcomeKind::InProgress,
            FenceOutcome::MigrationWriteFenced
            | FenceOutcome::MigrationReadFenced
            | FenceOutcome::MigrationTargetQuarantined
            | FenceOutcome::FenceStateUnavailable => OutcomeKind::DataPlane,
            FenceOutcome::OperationCapabilityRequired
            | FenceOutcome::FenceOwnedByAnotherOperation
            | FenceOutcome::FenceRevisionMismatch
            | FenceOutcome::InvalidFenceTransition
            | FenceOutcome::FenceCommandConflict
            | FenceOutcome::FenceCommitIndeterminate
            | FenceOutcome::FencePreconditionFailed => OutcomeKind::Control,
        }
    }

    pub const fn is_error(self) -> bool {
        matches!(self.kind(), OutcomeKind::DataPlane | OutcomeKind::Control)
    }

    /// Status code on the admin API.
    pub fn admin_http_status(self) -> StatusCode {
        match self {
            FenceOutcome::Applied | FenceOutcome::AlreadyApplied => StatusCode::OK,
            FenceOutcome::Draining => StatusCode::ACCEPTED,
            FenceOutcome::MigrationWriteFenced
            | FenceOutcome::MigrationReadFenced
            | FenceOutcome::MigrationTargetQuarantined
            | FenceOutcome::FenceStateUnavailable => StatusCode::LOCKED,
            FenceOutcome::OperationCapabilityRequired => StatusCode::FORBIDDEN,
            FenceOutcome::FenceOwnedByAnotherOperation
            | FenceOutcome::FenceRevisionMismatch
            | FenceOutcome::InvalidFenceTransition
            | FenceOutcome::FenceCommandConflict
            | FenceOutcome::FenceCommitIndeterminate => StatusCode::CONFLICT,
            FenceOutcome::FencePreconditionFailed => StatusCode::PRECONDITION_FAILED,
        }
    }

    /// Status code on the user HTTP API (`/`, `/v1`, `/v2`, `/v3`, `/dump`). Only data-plane
    /// denials reach it.
    pub fn user_http_status(self) -> Option<StatusCode> {
        match self.kind() {
            OutcomeKind::DataPlane => Some(StatusCode::LOCKED),
            _ => None,
        }
    }

    /// The Hrana error `code`. Only data-plane denials reach Hrana.
    pub fn hrana_code(self) -> Option<&'static str> {
        match self.kind() {
            OutcomeKind::DataPlane => Some(self.as_str()),
            _ => None,
        }
    }

    /// The gRPC status code on RPC, proxy connection and replication services. Never
    /// `UNAVAILABLE`, which the write proxy retries without bound.
    pub fn grpc_code(self) -> Option<tonic::Code> {
        match self {
            FenceOutcome::MigrationWriteFenced
            | FenceOutcome::MigrationReadFenced
            | FenceOutcome::MigrationTargetQuarantined
            | FenceOutcome::FenceStateUnavailable
            | FenceOutcome::OperationCapabilityRequired => Some(tonic::Code::FailedPrecondition),
            _ => None,
        }
    }

    /// The value of the proxy protocol's `Error.stable_code` field.
    pub fn proxy_stable_code(self) -> Option<&'static str> {
        match self.kind() {
            OutcomeKind::DataPlane => Some(self.as_str()),
            _ => None,
        }
    }
}

impl fmt::Display for FenceOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown fence outcome `{0}`")]
pub struct UnknownFenceOutcome(pub String);

impl FromStr for FenceOutcome {
    type Err = UnknownFenceOutcome;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        FenceOutcome::ALL
            .iter()
            .copied()
            .find(|o| o.as_str() == s)
            .ok_or_else(|| UnknownFenceOutcome(s.to_string()))
    }
}

/// The bounded `detail` reason of an error outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FenceDetail {
    // FENCE_PRECONDITION_FAILED
    AdminAuthRequired,
    FenceDisabled,
    NotPrimary,
    SharedSchemaUnsupported,
    NamespaceIdentityMismatch,
    NamespaceExists,
    ValidationReceiptRequired,
    RestoreNotAllowed,
    AdoptionNotAuthorised,
    InvalidArgument,
    // INVALID_FENCE_TRANSITION
    RoleMismatch,
    OperationFinished,
    // FENCE_STATE_UNAVAILABLE
    CorruptRecord,
    UnsupportedFormatVersion,
    IncompleteTargetCreation,
    MetastoreBehindMarker,
    IndeterminateCommit,
    // MIGRATION_WRITE_FENCED
    StaleTransaction,
}

impl FenceDetail {
    pub const fn as_str(self) -> &'static str {
        match self {
            FenceDetail::AdminAuthRequired => "admin_auth_required",
            FenceDetail::FenceDisabled => "fence_disabled",
            FenceDetail::NotPrimary => "not_primary",
            FenceDetail::SharedSchemaUnsupported => "shared_schema_unsupported",
            FenceDetail::NamespaceIdentityMismatch => "namespace_identity_mismatch",
            FenceDetail::NamespaceExists => "namespace_exists",
            FenceDetail::ValidationReceiptRequired => "validation_receipt_required",
            FenceDetail::RestoreNotAllowed => "restore_not_allowed",
            FenceDetail::AdoptionNotAuthorised => "adoption_not_authorised",
            FenceDetail::InvalidArgument => "invalid_argument",
            FenceDetail::RoleMismatch => "role_mismatch",
            FenceDetail::OperationFinished => "operation_finished",
            FenceDetail::CorruptRecord => "corrupt_record",
            FenceDetail::UnsupportedFormatVersion => "unsupported_format_version",
            FenceDetail::IncompleteTargetCreation => "incomplete_target_creation",
            FenceDetail::MetastoreBehindMarker => "metastore_behind_marker",
            FenceDetail::IndeterminateCommit => "indeterminate_commit",
            FenceDetail::StaleTransaction => "stale_transaction",
        }
    }
}

impl fmt::Display for FenceDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An error outcome with its bounded detail and a human message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{outcome}: {message}")]
pub struct FenceError {
    outcome: FenceOutcome,
    detail: Option<FenceDetail>,
    message: String,
}

impl FenceError {
    /// # Panics
    ///
    /// If `outcome` is not an error outcome. That is a programming error, never input.
    pub fn new(outcome: FenceOutcome, message: impl Into<String>) -> Self {
        assert!(outcome.is_error(), "{outcome} is not an error outcome");
        Self {
            outcome,
            detail: None,
            message: message.into(),
        }
    }

    pub fn with_detail(mut self, detail: FenceDetail) -> Self {
        self.detail = Some(detail);
        self
    }

    pub fn outcome(&self) -> FenceOutcome {
        self.outcome
    }

    pub fn detail(&self) -> Option<FenceDetail> {
        self.detail
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    /// The status of this error on either HTTP API: the user API's mapping for a data-plane
    /// denial (`423`), and the admin API's for any other outcome.
    pub fn http_status(&self) -> StatusCode {
        self.outcome
            .user_http_status()
            .unwrap_or_else(|| self.outcome.admin_http_status())
    }

    /// The JSON error body of the HTTP APIs for this error: the usual `error` message plus the
    /// additive stable `code` and, when there is one, the bounded `detail`.
    pub fn http_error_body(&self) -> serde_json::Value {
        let mut body = serde_json::json!({
            "error": self.to_string(),
            "code": self.outcome.as_str(),
        });
        if let Some(detail) = self.detail {
            body["detail"] = detail.as_str().into();
        }
        body
    }

    /// A gRPC status for this error, if the outcome has a gRPC mapping. The code is in the
    /// [`GRPC_FENCE_CODE_METADATA`] entry and prefixes the message.
    pub fn to_grpc_status(&self) -> Option<tonic::Status> {
        let code = self.outcome.grpc_code()?;
        let mut status = tonic::Status::new(code, format!("{}: {}", self.outcome, self.message));
        status.metadata_mut().insert(
            GRPC_FENCE_CODE_METADATA,
            tonic::metadata::MetadataValue::from_static(self.outcome.as_str()),
        );
        Some(status)
    }

    /// The stable code carried by a gRPC status produced by [`FenceError::to_grpc_status`].
    pub fn outcome_from_grpc_status(status: &tonic::Status) -> Option<FenceOutcome> {
        status
            .metadata()
            .get(GRPC_FENCE_CODE_METADATA)?
            .to_str()
            .ok()?
            .parse()
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip() {
        for outcome in FenceOutcome::ALL {
            assert_eq!(outcome.as_str().parse::<FenceOutcome>().unwrap(), outcome);
        }
        assert!("applied".parse::<FenceOutcome>().is_err());
    }

    /// Section 6: data-plane denials are never 500, 503, 429 or gRPC UNAVAILABLE.
    #[test]
    fn denials_are_never_retryable_statuses() {
        let retryable = [
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::BAD_GATEWAY,
            StatusCode::GATEWAY_TIMEOUT,
        ];
        for outcome in FenceOutcome::ALL {
            assert!(
                !retryable.contains(&outcome.admin_http_status()),
                "{outcome}"
            );
            if let Some(status) = outcome.user_http_status() {
                assert!(!retryable.contains(&status), "{outcome}");
            }
            assert_ne!(outcome.grpc_code(), Some(tonic::Code::Unavailable));
        }
    }

    #[test]
    fn protocol_table() {
        use FenceOutcome as O;
        let rows = [
            (O::Applied, 200, None, None),
            (O::AlreadyApplied, 200, None, None),
            (O::Draining, 202, None, None),
            (
                O::MigrationWriteFenced,
                423,
                Some(423),
                Some("MIGRATION_WRITE_FENCED"),
            ),
            (
                O::MigrationReadFenced,
                423,
                Some(423),
                Some("MIGRATION_READ_FENCED"),
            ),
            (
                O::MigrationTargetQuarantined,
                423,
                Some(423),
                Some("MIGRATION_TARGET_QUARANTINED"),
            ),
            (
                O::FenceStateUnavailable,
                423,
                Some(423),
                Some("FENCE_STATE_UNAVAILABLE"),
            ),
            (O::OperationCapabilityRequired, 403, None, None),
            (O::FenceOwnedByAnotherOperation, 409, None, None),
            (O::FenceRevisionMismatch, 409, None, None),
            (O::InvalidFenceTransition, 409, None, None),
            (O::FenceCommandConflict, 409, None, None),
            (O::FenceCommitIndeterminate, 409, None, None),
            (O::FencePreconditionFailed, 412, None, None),
        ];
        assert_eq!(rows.len(), FenceOutcome::ALL.len());
        for (outcome, admin, user, hrana) in rows {
            assert_eq!(outcome.admin_http_status().as_u16(), admin, "{outcome}");
            assert_eq!(
                outcome.user_http_status().map(|s| s.as_u16()),
                user,
                "{outcome}"
            );
            assert_eq!(outcome.hrana_code(), hrana, "{outcome}");
            assert_eq!(outcome.proxy_stable_code(), hrana, "{outcome}");
        }
    }

    #[test]
    fn grpc_status_carries_code() {
        let err = FenceError::new(FenceOutcome::MigrationReadFenced, "reads are fenced");
        let status = err.to_grpc_status().unwrap();
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert!(status.message().starts_with("MIGRATION_READ_FENCED: "));
        assert_eq!(
            FenceError::outcome_from_grpc_status(&status),
            Some(FenceOutcome::MigrationReadFenced)
        );
        assert_eq!(
            FenceError::outcome_from_grpc_status(&tonic::Status::unavailable("x")),
            None
        );

        let control = FenceError::new(FenceOutcome::FenceRevisionMismatch, "stale");
        assert!(control.to_grpc_status().is_none());
    }

    #[test]
    #[should_panic]
    fn success_is_not_an_error() {
        FenceError::new(FenceOutcome::Applied, "nope");
    }
}
