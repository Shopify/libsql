//! The namespace fence admin API (`docs/NAMESPACE_FENCE.md` section 4).
//!
//! `GET /v1/fence/capabilities` is always served. The other routes answer `404` unless the
//! server was started with `--enable-namespace-fence`, except `InspectFence`, which is also
//! served while fence state exists in the metastore with the flag off (fences are enforced
//! either way, section 13.1). Every mutating route runs through
//! [`NamespaceStore::execute_fence_command`], which owns replay, the drains and target creation.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Json;
use bytes::Bytes;
use hyper::StatusCode;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::auth::parse_jwt_keys;
use crate::error::Error;
use crate::hrana::proto;
use crate::namespace::fence::command::{
    CommandKind, DrainPolicy, FenceCommand, FenceRequest, OnDeadline, TargetConfig,
    ValidationResult,
};
use crate::namespace::fence::controller::{DrainCounters, FenceController};
use crate::namespace::fence::outcome::{FenceDetail, FenceError, FenceOutcome};
use crate::namespace::fence::record::{CommandReceipt, NamespaceFenceRecord, ServerIdentity};
use crate::namespace::fence::state::FenceState;
use crate::namespace::fence::store::{StoredFence, StoredReceipt};
use crate::namespace::fence::{server_identity, FENCE_PROTOCOL_VERSION, PROXY_STABLE_CODE};
use crate::namespace::meta_store::FenceCommit;
use crate::namespace::NamespaceName;
use crate::net::Connector;

use super::AppState;

/// The most rows one `validation-query` request returns, over all of its statements. A query
/// that would return more is refused rather than truncated, so a validation never silently
/// looks at part of a result.
pub const MAX_VALIDATION_QUERY_ROWS: usize = 10_000;

/// The commands this server serves over the admin API, reported by capability discovery.
/// Adoption is served once its route exists.
const SERVED_COMMANDS: [&str; 11] = [
    "InspectFence",
    CommandKind::AcquireSourceWriteFence.as_str(),
    CommandKind::SetSourceReadFence.as_str(),
    CommandKind::ClearSourceReadFence.as_str(),
    CommandKind::ReleaseSourceWriteFence.as_str(),
    CommandKind::CreateTargetQuarantined.as_str(),
    CommandKind::SealTargetImport.as_str(),
    CommandKind::RecordTargetValidation.as_str(),
    CommandKind::PublishTargetReadableWriteFenced.as_str(),
    CommandKind::EnableTargetWrites.as_str(),
    CommandKind::AbortQuarantinedTarget.as_str(),
];

/// The fence routes, added to the admin router.
pub(super) fn routes<C: Connector>() -> axum::Router<Arc<AppState<C>>> {
    let command = |kind: CommandKind| {
        post(
            move |State(state): State<Arc<AppState<C>>>,
                  Path(namespace): Path<String>,
                  body: Bytes| async move {
                handle_command(state, namespace, kind, body).await
            },
        )
    };
    axum::Router::new()
        .route("/v1/fence/capabilities", get(handle_capabilities))
        .route("/v1/namespaces/:namespace/fence", get(handle_inspect))
        .route(
            "/v1/namespaces/:namespace/fence/source/acquire-write-fence",
            command(CommandKind::AcquireSourceWriteFence),
        )
        .route(
            "/v1/namespaces/:namespace/fence/source/set-read-fence",
            command(CommandKind::SetSourceReadFence),
        )
        .route(
            "/v1/namespaces/:namespace/fence/source/clear-read-fence",
            command(CommandKind::ClearSourceReadFence),
        )
        .route(
            "/v1/namespaces/:namespace/fence/source/release-write-fence",
            command(CommandKind::ReleaseSourceWriteFence),
        )
        .route(
            "/v1/namespaces/:namespace/fence/target/create-quarantined",
            command(CommandKind::CreateTargetQuarantined),
        )
        .route(
            "/v1/namespaces/:namespace/fence/target/seal-import",
            command(CommandKind::SealTargetImport),
        )
        .route(
            "/v1/namespaces/:namespace/fence/target/validation-receipt",
            command(CommandKind::RecordTargetValidation),
        )
        .route(
            "/v1/namespaces/:namespace/fence/target/publish-readable",
            command(CommandKind::PublishTargetReadableWriteFenced),
        )
        .route(
            "/v1/namespaces/:namespace/fence/target/enable-writes",
            command(CommandKind::EnableTargetWrites),
        )
        .route(
            "/v1/namespaces/:namespace/fence/target/abort",
            command(CommandKind::AbortQuarantinedTarget),
        )
        .route(
            "/v1/namespaces/:namespace/fence/target/validation-query",
            post(handle_validation_query),
        )
}

// ---------------------------------------------------------------------------------------------
// Handlers

async fn handle_capabilities<C>(State(state): State<Arc<AppState<C>>>) -> Json<Value> {
    let meta = state.namespaces.meta_store();
    Json(json!({
        "fence_protocol_version": FENCE_PROTOCOL_VERSION,
        "enabled": meta.fence_enabled(),
        "commands": SERVED_COMMANDS,
        "states": FenceState::ALL.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        "proxy_stable_code": PROXY_STABLE_CODE,
        "server": server_json(&server_identity()),
        "active_fences": state.namespaces.active_fences(),
        // Metastore restore provenance is not tracked yet.
        "metastore": { "restored_from_backup": false, "restored_generation": null },
    }))
}

#[derive(Debug, Default, Deserialize)]
struct InspectQuery {
    #[serde(default)]
    receipts: Option<String>,
}

async fn handle_inspect<C>(
    State(state): State<Arc<AppState<C>>>,
    Path(namespace): Path<String>,
    Query(query): Query<InspectQuery>,
) -> Response {
    let meta = state.namespaces.meta_store();
    if !meta.fence_enabled() && !meta.fence_enforced() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let namespace = match NamespaceName::from_string(namespace) {
        Ok(ns) => ns,
        Err(e) => return invalid_argument(e.to_string()).into_response(),
    };
    if !state.namespaces.is_primary() {
        return ErrorReply::new(not_primary()).into_response();
    }
    let all = match query.receipts.as_deref() {
        None => false,
        Some("all") => true,
        Some(other) => {
            return invalid_argument(format!("unknown `receipts` value `{other}`")).into_response()
        }
    };
    let (inspection, controller) = match state.namespaces.inspect_fence(&namespace).await {
        Ok(found) => found,
        Err(e) => return fence_or_error(&state, &namespace, e).await,
    };
    if matches!(
        inspection.fence,
        StoredFence::None {
            namespace_exists: false
        }
    ) && controller.as_ref().map_or(true, |c| {
        let gate = c.gate();
        matches!(
            gate.fence,
            StoredFence::None {
                namespace_exists: false
            }
        ) && gate.creating_target.is_none()
    }) {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("namespace `{namespace}` does not exist") })),
        )
            .into_response();
    }

    let owner = inspection
        .fence
        .record()
        .map(|r| r.operation_id.to_string());
    let receipts: Vec<Value> = inspection
        .receipts
        .iter()
        .filter(|r| all || owner.as_deref() == Some(r.operation_id.as_str()))
        .map(stored_receipt_json)
        .collect();
    let body = json!({
        "outcome": FenceOutcome::Applied.as_str(),
        "replayed": false,
        "fence": fence_json(&namespace, &inspection.fence, controller.as_deref()),
        "receipts": receipts,
        "drain": drain_json(controller.as_deref()),
    });
    (StatusCode::OK, Json(body)).into_response()
}

async fn handle_command<C>(
    state: Arc<AppState<C>>,
    namespace: String,
    kind: CommandKind,
    body: Bytes,
) -> Response {
    if !state.namespaces.meta_store().fence_enabled() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let namespace = match NamespaceName::from_string(namespace) {
        Ok(ns) => ns,
        Err(e) => return invalid_argument(e.to_string()).into_response(),
    };
    if let Err(e) = mutating_preconditions(&state) {
        return error_reply(&state, &namespace, e).await;
    }
    let request = match parse_command(namespace.clone(), kind, &body) {
        Ok(request) => request,
        Err(e) => return error_reply(&state, &namespace, e).await,
    };
    match state
        .namespaces
        .execute_fence_command(request, server_identity())
        .await
    {
        Ok(commit) => success_reply(&state, &namespace, commit),
        Err(e) => fence_or_error(&state, &namespace, e).await,
    }
}

async fn handle_validation_query<C>(
    State(state): State<Arc<AppState<C>>>,
    Path(namespace): Path<String>,
    body: Bytes,
) -> Response {
    if !state.namespaces.meta_store().fence_enabled() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let namespace = match NamespaceName::from_string(namespace) {
        Ok(ns) => ns,
        Err(e) => return invalid_argument(e.to_string()).into_response(),
    };
    if let Err(e) = mutating_preconditions(&state) {
        return error_reply(&state, &namespace, e).await;
    }
    let query = match parse_validation_query(&body) {
        Ok(query) => query,
        Err(e) => return error_reply(&state, &namespace, e).await,
    };
    if let Some(expected) = query.expected_state {
        let current = state
            .namespaces
            .existing_fence_controller(&namespace)
            .map(|c| c.gate().state());
        if let Some(current) = current.filter(|s| *s != expected) {
            let e = FenceError::new(
                FenceOutcome::FenceRevisionMismatch,
                format!("the namespace is {current}, not {expected}"),
            );
            return error_reply(&state, &namespace, e).await;
        }
    }
    let mut session = match state
        .namespaces
        .open_validation_session(
            namespace.clone(),
            query.operation_id,
            query.expected_revision,
        )
        .await
    {
        Ok(session) => session,
        Err(e) => return fence_or_error(&state, &namespace, e).await,
    };

    let mut results = Vec::with_capacity(query.stmts.len());
    let mut remaining = MAX_VALIDATION_QUERY_ROWS;
    for (index, stmt) in query.stmts.into_iter().enumerate() {
        let budget = remaining;
        let ran = session
            .with_raw(move |conn| run_validation_stmt(conn, &stmt, budget))
            .await;
        match ran {
            Ok(Ok(result)) => {
                remaining -= result.rows.len();
                results.push(result);
            }
            Ok(Err(e)) => {
                return error_reply(&state, &namespace, e.into_fence_error(index)).await;
            }
            Err(e) => return error_reply(&state, &namespace, e).await,
        }
    }
    drop(session);

    let controller = state.namespaces.existing_fence_controller(&namespace);
    let fence = controller
        .as_ref()
        .map(|c| fence_json(&namespace, &c.gate().fence, Some(c)))
        .unwrap_or(Value::Null);
    let body = json!({
        "results": results,
        "fence": fence,
        "drain": drain_json(controller.as_deref()),
    });
    (StatusCode::OK, Json(body)).into_response()
}

// ---------------------------------------------------------------------------------------------
// Preconditions and replies

/// Section 4.1, for every route that changes fence state or works under a capability. The admin
/// authentication itself is the admin router's middleware and has already run.
fn mutating_preconditions<C>(state: &AppState<C>) -> Result<(), FenceError> {
    if !state.namespaces.is_primary() {
        return Err(not_primary());
    }
    if !state.admin_auth_configured {
        return Err(FenceError::new(
            FenceOutcome::FencePreconditionFailed,
            "namespace fence commands need an admin auth key: without one the admin API is \
             unauthenticated",
        )
        .with_detail(FenceDetail::AdminAuthRequired));
    }
    Ok(())
}

fn not_primary() -> FenceError {
    FenceError::new(
        FenceOutcome::FencePreconditionFailed,
        "namespace fences live on the primary; this server is a replica",
    )
    .with_detail(FenceDetail::NotPrimary)
}

fn invalid_argument(message: impl Into<String>) -> ErrorReply {
    ErrorReply::new(
        FenceError::new(FenceOutcome::FencePreconditionFailed, message)
            .with_detail(FenceDetail::InvalidArgument),
    )
}

/// An error reply without a fence view (the namespace name itself could not be used).
struct ErrorReply {
    error: FenceError,
    fence: Value,
    drain: Value,
}

impl ErrorReply {
    fn new(error: FenceError) -> Self {
        Self {
            error,
            fence: Value::Null,
            drain: Value::Null,
        }
    }
}

impl IntoResponse for ErrorReply {
    fn into_response(self) -> Response {
        let outcome = self.error.outcome();
        let mut body = json!({
            "outcome": outcome.as_str(),
            "replayed": false,
            "error": self.error.message(),
            "fence": self.fence,
            "drain": self.drain,
        });
        if let Some(detail) = self.error.detail() {
            body["detail"] = json!(detail.as_str());
        }
        (outcome.admin_http_status(), Json(body)).into_response()
    }
}

/// An error reply carrying the namespace's current fence view: the live gate if the namespace
/// has a controller, otherwise what the metastore holds.
async fn error_reply<C>(
    state: &AppState<C>,
    namespace: &NamespaceName,
    error: FenceError,
) -> Response {
    let mut reply = ErrorReply::new(error);
    match state.namespaces.existing_fence_controller(namespace) {
        Some(controller) => {
            reply.fence = fence_json(namespace, &controller.gate().fence, Some(&controller));
            reply.drain = drain_json(Some(&controller));
        }
        None => {
            if let Ok((inspection, _)) = state.namespaces.inspect_fence(namespace).await {
                reply.fence = fence_json(namespace, &inspection.fence, None);
            }
        }
    }
    reply.into_response()
}

/// A fence refusal in the fence response shape; any other error as the admin API reports it.
async fn fence_or_error<C>(state: &AppState<C>, namespace: &NamespaceName, e: Error) -> Response {
    match e {
        Error::NamespaceFence(e) => error_reply(state, namespace, e).await,
        e => e.into_response(),
    }
}

fn success_reply<C>(
    state: &AppState<C>,
    namespace: &NamespaceName,
    commit: FenceCommit,
) -> Response {
    let controller = state.namespaces.existing_fence_controller(namespace);
    let fence = match (&commit.record, &controller) {
        (Some(record), _) => fence_json(
            namespace,
            &StoredFence::Record(record.clone()),
            controller.as_deref(),
        ),
        (None, Some(c)) => fence_json(namespace, &c.gate().fence, Some(c)),
        (None, None) => Value::Null,
    };
    let outcome = commit.receipt.outcome;
    let body = json!({
        "outcome": outcome.as_str(),
        "replayed": commit.kind == crate::namespace::meta_store::FenceCommitKind::Replayed,
        "fence": fence,
        "receipt": receipt_json(&commit.receipt),
        "drain": drain_json(controller.as_deref()),
    });
    (outcome.admin_http_status(), Json(body)).into_response()
}

// ---------------------------------------------------------------------------------------------
// Request parsing

/// A JSON object request body whose fields are taken one by one; whatever is left at the end is
/// an unknown field and refused.
struct Body(Map<String, Value>);

impl Body {
    fn parse(bytes: &[u8]) -> Result<Self, FenceError> {
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return Err(invalid("the request body must be a JSON object"));
        }
        match serde_json::from_slice::<Value>(bytes) {
            Ok(Value::Object(map)) => Ok(Self(map)),
            Ok(_) => Err(invalid("the request body must be a JSON object")),
            Err(e) => Err(invalid(format!("the request body is not valid JSON: {e}"))),
        }
    }

    fn has(&self, key: &str) -> bool {
        self.0.contains_key(key)
    }

    fn opt<T: DeserializeOwned>(&mut self, key: &str) -> Result<Option<T>, FenceError> {
        match self.0.remove(key) {
            None | Some(Value::Null) => Ok(None),
            // Through text rather than `from_value`: some protocol types (the Hrana values of
            // a statement) only deserialize from borrowed strings.
            Some(v) => serde_json::from_str(&v.to_string())
                .map(Some)
                .map_err(|e| invalid(format!("invalid `{key}`: {e}"))),
        }
    }

    fn req<T: DeserializeOwned>(&mut self, key: &str) -> Result<T, FenceError> {
        self.opt(key)?
            .ok_or_else(|| invalid(format!("missing `{key}`")))
    }

    fn uuid(&mut self, key: &str) -> Result<Uuid, FenceError> {
        let s: String = self.req(key)?;
        Uuid::parse_str(&s).map_err(|e| invalid(format!("invalid `{key}`: {e}")))
    }

    fn state(&mut self, key: &str) -> Result<FenceState, FenceError> {
        let s: String = self.req(key)?;
        s.parse()
            .map_err(|e: crate::namespace::fence::state::UnknownFenceState| invalid(e.to_string()))
    }

    fn finish(self) -> Result<(), FenceError> {
        match self.0.keys().next() {
            None => Ok(()),
            Some(key) => Err(invalid(format!("unknown field `{key}`"))),
        }
    }
}

fn invalid(message: impl Into<String>) -> FenceError {
    FenceError::new(FenceOutcome::FencePreconditionFailed, message)
        .with_detail(FenceDetail::InvalidArgument)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DrainPolicyBody {
    deadline_ms: u64,
    #[serde(default)]
    on_deadline: Option<String>,
}

fn drain_policy(body: &mut Body) -> Result<Option<DrainPolicy>, FenceError> {
    let Some(p) = body.opt::<DrainPolicyBody>("drain_policy")? else {
        return Ok(None);
    };
    let on_deadline = match p.on_deadline.as_deref() {
        None | Some("fail") => OnDeadline::Fail,
        Some("force_rollback") => OnDeadline::ForceRollback,
        Some(other) => {
            return Err(invalid(format!(
                "invalid `drain_policy.on_deadline` `{other}`: expected `fail` or `force_rollback`"
            )))
        }
    };
    Ok(Some(DrainPolicy {
        deadline_ms: p.deadline_ms,
        on_deadline,
    }))
}

/// Restore and dump options a target creation refuses: import goes through the migration
/// capability (section 4.4).
const RESTORE_FIELDS: [&str; 5] = [
    "dump_url",
    "restore",
    "restore_option",
    "timestamp",
    "from_backup",
];

fn parse_command(
    namespace: NamespaceName,
    kind: CommandKind,
    bytes: &[u8],
) -> Result<FenceRequest, FenceError> {
    let mut body = Body::parse(bytes)?;
    if kind == CommandKind::CreateTargetQuarantined {
        if let Some(field) = RESTORE_FIELDS.iter().find(|f| body.has(f)) {
            return Err(FenceError::new(
                FenceOutcome::FencePreconditionFailed,
                format!(
                    "`{field}` is not accepted: a migration target is created empty and filled \
                     through the operation's import capability"
                ),
            )
            .with_detail(FenceDetail::RestoreNotAllowed));
        }
        if body.has("shared_schema") || body.has("shared_schema_name") {
            return Err(FenceError::new(
                FenceOutcome::FencePreconditionFailed,
                "namespace fences do not support shared schemas",
            )
            .with_detail(FenceDetail::SharedSchemaUnsupported));
        }
    }

    let operation_id = body.uuid("operation_id")?;
    let command_id = body.uuid("command_id")?;
    let expected_state = body.state("expected_state")?;
    let expected_revision: u64 = body.req("expected_revision")?;

    let command = match kind {
        CommandKind::AcquireSourceWriteFence => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Identity {
                log_id: String,
            }
            let identity: Identity = body.req("expected_namespace_identity")?;
            let expected_log_id = Uuid::parse_str(&identity.log_id).map_err(|e| {
                invalid(format!("invalid `expected_namespace_identity.log_id`: {e}"))
            })?;
            FenceCommand::AcquireSourceWriteFence {
                expected_log_id,
                drain_policy: drain_policy(&mut body)?,
            }
        }
        CommandKind::SetSourceReadFence => FenceCommand::SetSourceReadFence {
            drain_policy: drain_policy(&mut body)?,
        },
        CommandKind::ClearSourceReadFence => FenceCommand::ClearSourceReadFence,
        CommandKind::ReleaseSourceWriteFence => FenceCommand::ReleaseSourceWriteFence,
        CommandKind::CreateTargetQuarantined => {
            let jwt_key: Option<String> = body.opt("jwt_key")?;
            if let Some(key) = jwt_key.as_deref() {
                parse_jwt_keys(key).map_err(|e| invalid(format!("invalid `jwt_key`: {e}")))?;
            }
            let max_db_size: Option<bytesize::ByteSize> = body.opt("max_db_size")?;
            FenceCommand::CreateTargetQuarantined {
                config: TargetConfig {
                    max_db_size: max_db_size.map(|s| s.as_u64()),
                    jwt_key,
                    txn_timeout_s: body.opt("txn_timeout_s")?,
                    allow_attach: body.opt("allow_attach")?.unwrap_or(false),
                    durability_mode: body.opt("durability_mode")?,
                    bottomless_db_id: body.opt("bottomless_db_id")?,
                },
            }
        }
        CommandKind::SealTargetImport => FenceCommand::SealTargetImport {
            drain_policy: drain_policy(&mut body)?,
        },
        CommandKind::RecordTargetValidation => {
            let result: String = body.req("result")?;
            let result = match result.as_str() {
                "ok" => ValidationResult::Ok,
                "failed" => ValidationResult::Failed,
                other => {
                    return Err(invalid(format!(
                        "invalid `result` `{other}`: expected `ok` or `failed`"
                    )))
                }
            };
            FenceCommand::RecordTargetValidation {
                result,
                summary: body.opt("summary")?.unwrap_or_default(),
            }
        }
        CommandKind::PublishTargetReadableWriteFenced => {
            FenceCommand::PublishTargetReadableWriteFenced
        }
        CommandKind::EnableTargetWrites => FenceCommand::EnableTargetWrites,
        CommandKind::AbortQuarantinedTarget => FenceCommand::AbortQuarantinedTarget,
        CommandKind::AdoptFence => {
            return Err(invalid("adoption is not served by this route"));
        }
    };
    body.finish()?;
    Ok(FenceRequest {
        namespace,
        operation_id,
        command_id,
        expected_state,
        expected_revision,
        command,
    })
}

struct ValidationQuery {
    operation_id: Uuid,
    expected_state: Option<FenceState>,
    expected_revision: u64,
    stmts: Vec<proto::Stmt>,
}

fn parse_validation_query(bytes: &[u8]) -> Result<ValidationQuery, FenceError> {
    let mut body = Body::parse(bytes)?;
    let operation_id = body.uuid("operation_id")?;
    let expected_state = if body.has("expected_state") {
        Some(body.state("expected_state")?)
    } else {
        None
    };
    let expected_revision = body.req("expected_revision")?;
    let stmts: Vec<proto::Stmt> = body.req("stmts")?;
    body.finish()?;
    if stmts.is_empty() {
        return Err(invalid("`stmts` is empty"));
    }
    Ok(ValidationQuery {
        operation_id,
        expected_state,
        expected_revision,
        stmts,
    })
}

// ---------------------------------------------------------------------------------------------
// Validation queries

enum StmtFailure {
    Invalid(String),
    Sqlite(rusqlite::Error),
    TooManyRows,
}

impl StmtFailure {
    fn into_fence_error(self, index: usize) -> FenceError {
        match self {
            StmtFailure::Invalid(message) => invalid(format!("statement {index}: {message}")),
            StmtFailure::Sqlite(rusqlite::Error::SqliteFailure(e, message))
                if e.code == rusqlite::ErrorCode::ReadOnly =>
            {
                FenceError::new(
                    FenceOutcome::OperationCapabilityRequired,
                    format!(
                        "statement {index}: the validation capability is read-only: {}",
                        message.unwrap_or_else(|| e.to_string())
                    ),
                )
            }
            StmtFailure::Sqlite(e) => invalid(format!("statement {index}: {e}")),
            StmtFailure::TooManyRows => invalid(format!(
                "statement {index}: the request returns more than {MAX_VALIDATION_QUERY_ROWS} rows"
            )),
        }
    }
}

impl From<rusqlite::Error> for StmtFailure {
    fn from(e: rusqlite::Error) -> Self {
        StmtFailure::Sqlite(e)
    }
}

fn to_sql_value(value: &proto::Value) -> Result<rusqlite::types::Value, StmtFailure> {
    use rusqlite::types::Value as V;
    Ok(match value {
        proto::Value::None => return Err(StmtFailure::Invalid("an argument has no value".into())),
        proto::Value::Null => V::Null,
        proto::Value::Integer { value } => V::Integer(*value),
        proto::Value::Float { value } => V::Real(*value),
        proto::Value::Text { value } => V::Text(value.to_string()),
        proto::Value::Blob { value } => V::Blob(value.to_vec()),
    })
}

fn from_sql_value(value: rusqlite::types::ValueRef<'_>) -> proto::Value {
    use rusqlite::types::ValueRef as V;
    match value {
        V::Null => proto::Value::Null,
        V::Integer(value) => proto::Value::Integer { value },
        V::Real(value) => proto::Value::Float { value },
        V::Text(bytes) => proto::Value::Text {
            value: String::from_utf8_lossy(bytes).into(),
        },
        V::Blob(bytes) => proto::Value::Blob {
            value: Bytes::copy_from_slice(bytes),
        },
    }
}

/// Run one statement of a `validation-query` and collect at most `budget` rows.
fn run_validation_stmt(
    conn: &mut rusqlite::Connection,
    stmt: &proto::Stmt,
    budget: usize,
) -> Result<proto::StmtResult, StmtFailure> {
    let sql = stmt.sql.as_deref().ok_or_else(|| {
        StmtFailure::Invalid("`sql` is required (`sql_id` is not supported)".into())
    })?;
    let mut prepared = conn.prepare(sql)?;
    if !stmt.args.is_empty() && !stmt.named_args.is_empty() {
        return Err(StmtFailure::Invalid(
            "`args` and `named_args` cannot be combined".into(),
        ));
    }
    for (i, arg) in stmt.args.iter().enumerate() {
        prepared.raw_bind_parameter(i + 1, to_sql_value(arg)?)?;
    }
    for arg in &stmt.named_args {
        let index = prepared
            .parameter_index(&arg.name)?
            .ok_or_else(|| StmtFailure::Invalid(format!("unknown parameter `{}`", arg.name)))?;
        prepared.raw_bind_parameter(index, to_sql_value(&arg.value)?)?;
    }
    let cols: Vec<proto::Col> = prepared
        .columns()
        .iter()
        .map(|c| proto::Col {
            name: Some(c.name().to_string()),
            decltype: c.decl_type().map(str::to_string),
        })
        .collect();
    let want_rows = stmt.want_rows.unwrap_or(true);
    let column_count = cols.len();
    let mut rows = Vec::new();
    let mut raw = prepared.raw_query();
    while let Some(row) = raw.next()? {
        if !want_rows {
            continue;
        }
        if rows.len() == budget {
            return Err(StmtFailure::TooManyRows);
        }
        let mut values = Vec::with_capacity(column_count);
        for i in 0..column_count {
            values.push(from_sql_value(row.get_ref(i)?));
        }
        rows.push(proto::Row { values });
    }
    Ok(proto::StmtResult {
        cols,
        rows,
        ..Default::default()
    })
}

// ---------------------------------------------------------------------------------------------
// Response views

fn timestamp(ms: i64) -> Value {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms)
        .map(|t| json!(t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)))
        .unwrap_or(Value::Null)
}

fn server_json(server: &ServerIdentity) -> Value {
    json!({ "build": server.build, "instance_id": server.instance_id.to_string() })
}

fn drain_json(controller: Option<&FenceController>) -> Value {
    let counters = controller.map(|c| c.drain_counters()).unwrap_or_default();
    let DrainCounters {
        active_writers,
        read_leases,
        import_writers,
    } = counters;
    json!({
        "active_writers": active_writers,
        "read_leases": {
            "sql": read_leases.sql,
            "dump": read_leases.dump,
            "replication": read_leases.replication,
        },
        "import_writers": import_writers,
    })
}

fn record_fields(record: &NamespaceFenceRecord, out: &mut Map<String, Value>) {
    out.insert("role".into(), json!(record.role.as_str()));
    out.insert("revision".into(), json!(record.revision));
    out.insert(
        "operation_id".into(),
        json!(record.operation_id.to_string()),
    );
    out.insert(
        "frozen_boundary".into(),
        record
            .frozen_boundary
            .map(|b| json!({ "log_id": b.log_id.to_string(), "frame_no": b.frame_no }))
            .unwrap_or(Value::Null),
    );
    out.insert(
        "drain_policy".into(),
        record
            .drain_policy
            .map(|p| json!({ "deadline_ms": p.deadline_ms, "on_deadline": p.on_deadline.as_str() }))
            .unwrap_or(Value::Null),
    );
    out.insert(
        "drain_started_at".into(),
        record
            .drain_started_at_ms
            .map(timestamp)
            .unwrap_or(Value::Null),
    );
    out.insert(
        "validation".into(),
        record
            .validation
            .as_ref()
            .map(|v| {
                json!({
                    "operation_id": v.operation_id.to_string(),
                    "command_id": v.command_id.to_string(),
                    "result": v.result.as_str(),
                    "summary": v.summary,
                    "snapshot": v.snapshot.map(|s| json!({
                        "log_id": s.log_id.to_string(),
                        "frame_no": s.frame_no,
                        "page_count": s.page_count,
                    })),
                    "recorded_at": timestamp(v.recorded_at_ms),
                })
            })
            .unwrap_or(Value::Null),
    );
    out.insert("created_at".into(), timestamp(record.created_at_ms));
    out.insert(
        "last_transition_at".into(),
        timestamp(record.last_transition_at_ms),
    );
    out.insert(
        "last_command_id".into(),
        json!(record.last_command_id.to_string()),
    );
    out.insert("written_by".into(), server_json(&record.written_by));
    out.insert(
        "adoptions".into(),
        Value::Array(
            record
                .adoptions
                .iter()
                .map(|a| {
                    json!({
                        "previous_operation_id": a.previous_operation_id.to_string(),
                        "new_operation_id": a.new_operation_id.to_string(),
                        "command_id": a.command_id.to_string(),
                        "approvers": a.approvers,
                        "incident_ref": a.incident_ref,
                        "reason": a.reason,
                        "at": timestamp(a.at_ms),
                        "revision": a.revision,
                    })
                })
                .collect(),
        ),
    );
}

/// The fence view of section 4.3. `fence` is the durable state being reported; `controller`,
/// when the namespace has one, supplies the live admission and the live log id.
fn fence_json(
    namespace: &NamespaceName,
    fence: &StoredFence,
    controller: Option<&FenceController>,
) -> Value {
    let gate = controller.map(|c| c.gate());
    let mut out = Map::new();
    out.insert("namespace".into(), json!(namespace.as_str()));
    let state = match &gate {
        Some(g) if g.is_creating_target() => FenceState::TargetQuarantined,
        _ => fence.state(),
    };
    out.insert("state".into(), json!(state.as_str()));
    out.insert("role".into(), Value::Null);
    out.insert("revision".into(), json!(fence.revision()));
    out.insert("operation_id".into(), Value::Null);
    let current_log_id = controller.and_then(|c| c.current_log_id());
    let (log_id, incarnation_id) = fence
        .record()
        .map(|r| (r.identity.log_id, r.identity.target_incarnation_id))
        .unwrap_or((None, None));
    out.insert(
        "incarnation".into(),
        json!({
            "log_id": log_id.map(|id| id.to_string()),
            "target_incarnation_id": incarnation_id.map(|id| id.to_string()),
            "current_log_id": current_log_id.map(|id| id.to_string()),
        }),
    );
    let (write, read, generation) = match &gate {
        Some(g) => (g.write(), g.read(), g.write_generation),
        None => (state.write_admission(), state.read_admission(), 0),
    };
    out.insert(
        "admission".into(),
        json!({
            "write": write.as_str(),
            "read": read.as_str(),
            "generation": generation,
            "indeterminate": gate.as_ref().is_some_and(|g| g.indeterminate.is_some()),
        }),
    );
    let marker = match fence {
        StoredFence::None { .. } => Value::Null,
        StoredFence::Record(record) => {
            record_fields(record, &mut out);
            json!("consistent")
        }
        StoredFence::Unavailable {
            detail,
            reason,
            marker,
        } => {
            out.insert("detail".into(), json!(detail.as_str()));
            out.insert("reason".into(), json!(reason));
            out.insert(
                "marker_record".into(),
                marker
                    .as_ref()
                    .map(|m| {
                        let mut inner = Map::new();
                        inner.insert("state".into(), json!(m.state.as_str()));
                        record_fields(m, &mut inner);
                        Value::Object(inner)
                    })
                    .unwrap_or(Value::Null),
            );
            json!(detail.as_str())
        }
    };
    out.insert("server".into(), server_json(&server_identity()));
    out.insert(
        "provenance".into(),
        json!({ "metastore_restored_from_backup": false, "marker": marker }),
    );
    Value::Object(out)
}

fn receipt_json(receipt: &CommandReceipt) -> Value {
    json!({
        "operation_id": receipt.operation_id.to_string(),
        "command_id": receipt.command_id.to_string(),
        "command": receipt.command.as_str(),
        "fingerprint": receipt.fingerprint.to_string(),
        "outcome": receipt.outcome.as_str(),
        "revision_before": receipt.revision_before,
        "revision_after": receipt.revision_after,
        "state_after": receipt.state_after.as_str(),
        "applied_at": timestamp(receipt.applied_at_ms),
        "instance_id": receipt.instance_id.to_string(),
    })
}

fn stored_receipt_json(stored: &StoredReceipt) -> Value {
    match &stored.receipt {
        Ok(receipt) => receipt_json(receipt),
        Err(e) => json!({
            "operation_id": stored.operation_id,
            "command_id": stored.command_id,
            "revision_after": stored.revision_after,
            "applied_at": timestamp(stored.applied_at_ms),
            "error": e.to_string(),
        }),
    }
}
