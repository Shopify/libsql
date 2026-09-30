use std::collections::HashMap;
use std::ops::Deref;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_lock::{RwLock, RwLockUpgradableReadGuard};
use futures_core::Stream;
use libsql_replication::rpc::proxy::proxy_server::Proxy;
use libsql_replication::rpc::proxy::query_result::RowResult;
use libsql_replication::rpc::proxy::{
    describe_result, Ack, DescribeRequest, DescribeResult, Description, DisconnectMessage, ExecReq,
    ExecResp, ExecuteResults, QueryResult, ResultRows, Row,
};
use libsql_replication::rpc::replication::NAMESPACE_DOESNT_EXIST;
use rusqlite::types::ValueRef;
use tokio::time::Duration;
use uuid::Uuid;

use crate::auth::parsers::parse_grpc_auth_header;
use crate::auth::{Auth, Authenticated, Jwt};
use crate::connection::{Connection as _, RequestContext};
use crate::database::Connection;
use crate::namespace::NamespaceStore;
use crate::query_result_builder::{
    Column, QueryBuilderConfig, QueryResultBuilder, QueryResultBuilderError,
};
use crate::replication::FrameNo;
use crate::rpc::streaming_exec::make_proxy_stream;

pub mod rpc {
    use anyhow::Context;
    pub use libsql_replication::rpc::proxy::*;

    use crate::query_analysis::Statement;
    use crate::{connection, error::Error as SqldError};

    use error::ErrorCode;

    impl From<SqldError> for Error {
        fn from(other: SqldError) -> Self {
            // A fence denial is an ordinary SQL error to an older replica, and carries its
            // stable code in the additive `stable_code` field for one that maps it
            // (`docs/NAMESPACE_FENCE.md` section 6.1).
            let stable_code = other
                .fence_error()
                .and_then(|e| e.outcome().proxy_stable_code());
            if let Some(fence) = other.fence_error().filter(|_| stable_code.is_some()) {
                crate::namespace::fence::audit::denied(
                    fence,
                    crate::namespace::fence::audit::DenialSurface::Rpc,
                );
            }
            let code = match other {
                _ if stable_code.is_some() => ErrorCode::SqlError,
                SqldError::LibSqlInvalidQueryParams(_) => ErrorCode::SqlError,
                SqldError::LibSqlTxTimeout => ErrorCode::TxTimeout,
                SqldError::LibSqlTxBusy => ErrorCode::TxBusy,
                _ => ErrorCode::Internal,
            };

            let extended_code = if let SqldError::RusqliteErrorExtended(_, code) = &other {
                *code
            } else {
                0
            };

            Error {
                message: other.to_string(),
                code: code as i32,
                extended_code,
                stable_code: stable_code.map(Into::into),
            }
        }
    }

    impl From<SqldError> for ErrorCode {
        fn from(other: SqldError) -> Self {
            match other {
                _ if other.fence_error().is_some() => ErrorCode::SqlError,
                SqldError::LibSqlInvalidQueryParams(_) => ErrorCode::SqlError,
                SqldError::LibSqlTxTimeout => ErrorCode::TxTimeout,
                SqldError::LibSqlTxBusy => ErrorCode::TxBusy,
                _ => ErrorCode::Internal,
            }
        }
    }

    impl From<crate::query_analysis::TxnStatus> for State {
        fn from(other: crate::query_analysis::TxnStatus) -> Self {
            match other {
                crate::query_analysis::TxnStatus::Txn => Self::Txn,
                crate::query_analysis::TxnStatus::Init => Self::Init,
                crate::query_analysis::TxnStatus::Invalid => Self::Invalid,
            }
        }
    }

    impl From<State> for crate::query_analysis::TxnStatus {
        fn from(other: State) -> Self {
            match other {
                State::Txn => crate::query_analysis::TxnStatus::Txn,
                State::Init => crate::query_analysis::TxnStatus::Init,
                State::Invalid => crate::query_analysis::TxnStatus::Invalid,
            }
        }
    }

    impl TryFrom<crate::query::Params> for query::Params {
        type Error = SqldError;
        fn try_from(value: crate::query::Params) -> Result<Self, Self::Error> {
            match value {
                crate::query::Params::Named(params) => {
                    let iter = params.into_iter().map(|(k, v)| -> Result<_, SqldError> {
                        let v = Value {
                            data: bincode::serialize(&v)?,
                        };
                        Ok((k, v))
                    });
                    let (names, values) = itertools::process_results(iter, |i| i.unzip())?;
                    Ok(Self::Named(Named { names, values }))
                }
                crate::query::Params::Positional(params) => {
                    let values = params
                        .iter()
                        .map(|v| {
                            Ok(Value {
                                data: bincode::serialize(&v)?,
                            })
                        })
                        .collect::<Result<Vec<_>, SqldError>>()?;
                    Ok(Self::Positional(Positional { values }))
                }
            }
        }
    }

    impl TryFrom<query::Params> for crate::query::Params {
        type Error = SqldError;

        fn try_from(value: query::Params) -> Result<Self, Self::Error> {
            match value {
                query::Params::Positional(pos) => {
                    let params = pos
                        .values
                        .into_iter()
                        .map(|v| bincode::deserialize(&v.data).map_err(|e| e.into()))
                        .collect::<Result<Vec<_>, SqldError>>()?;
                    Ok(Self::Positional(params))
                }
                query::Params::Named(named) => {
                    let values = named.values.iter().map(|v| bincode::deserialize(&v.data));
                    let params = itertools::process_results(values, |values| {
                        named.names.into_iter().zip(values).collect()
                    })?;
                    Ok(Self::Named(params))
                }
            }
        }
    }

    impl TryFrom<Program> for connection::program::Program {
        type Error = anyhow::Error;

        fn try_from(pgm: Program) -> Result<Self, Self::Error> {
            let steps = pgm
                .steps
                .into_iter()
                .map(TryInto::try_into)
                .collect::<anyhow::Result<_>>()?;

            Ok(Self::new(steps))
        }
    }

    impl TryFrom<Step> for connection::program::Step {
        type Error = anyhow::Error;

        fn try_from(step: Step) -> Result<Self, Self::Error> {
            Ok(Self {
                query: step.query.context("step is missing query")?.try_into()?,
                cond: step.cond.map(TryInto::try_into).transpose()?,
            })
        }
    }

    impl TryFrom<Cond> for connection::program::Cond {
        type Error = anyhow::Error;

        fn try_from(cond: Cond) -> Result<Self, Self::Error> {
            let cond = match cond.cond {
                Some(cond::Cond::Ok(OkCond { step })) => Self::Ok { step: step as _ },
                Some(cond::Cond::Err(ErrCond { step })) => Self::Err { step: step as _ },
                Some(cond::Cond::Not(cond)) => Self::Not {
                    cond: Box::new((*cond.cond.context("empty `not` condition")?).try_into()?),
                },
                Some(cond::Cond::And(AndCond { conds })) => Self::And {
                    conds: conds
                        .into_iter()
                        .map(TryInto::try_into)
                        .collect::<anyhow::Result<_>>()?,
                },
                Some(cond::Cond::Or(OrCond { conds })) => Self::Or {
                    conds: conds
                        .into_iter()
                        .map(TryInto::try_into)
                        .collect::<anyhow::Result<_>>()?,
                },
                Some(cond::Cond::IsAutocommit(_)) => Self::IsAutocommit,
                None => anyhow::bail!("invalid condition"),
            };

            Ok(cond)
        }
    }

    impl TryFrom<Query> for crate::query::Query {
        type Error = anyhow::Error;

        fn try_from(query: Query) -> Result<Self, Self::Error> {
            let stmt = Statement::parse(&query.stmt)
                .next()
                .context("invalid empty statement")??;

            Ok(Self {
                stmt,
                params: query
                    .params
                    .context("missing params in query")?
                    .try_into()?,
                want_rows: !query.skip_rows,
            })
        }
    }

    impl From<connection::program::Program> for Program {
        fn from(pgm: connection::program::Program) -> Self {
            Self {
                steps: pgm.steps.iter().map(|s| s.clone().into()).collect(),
            }
        }
    }

    impl From<crate::query::Query> for Query {
        fn from(query: crate::query::Query) -> Self {
            Self {
                stmt: query.stmt.stmt,
                params: Some(query.params.try_into().unwrap()),
                skip_rows: !query.want_rows,
            }
        }
    }

    impl From<connection::program::Step> for Step {
        fn from(step: connection::program::Step) -> Self {
            Self {
                cond: step.cond.map(|c| c.into()),
                query: Some(step.query.into()),
            }
        }
    }

    impl From<connection::program::Cond> for Cond {
        fn from(cond: connection::program::Cond) -> Self {
            let cond = match cond {
                connection::program::Cond::Ok { step } => {
                    cond::Cond::Ok(OkCond { step: step as i64 })
                }
                connection::program::Cond::Err { step } => {
                    cond::Cond::Err(ErrCond { step: step as i64 })
                }
                connection::program::Cond::Not { cond } => cond::Cond::Not(Box::new(NotCond {
                    cond: Some(Box::new(Cond::from(*cond))),
                })),
                connection::program::Cond::Or { conds } => cond::Cond::Or(OrCond {
                    conds: conds.into_iter().map(|c| c.into()).collect(),
                }),
                connection::program::Cond::And { conds } => cond::Cond::And(AndCond {
                    conds: conds.into_iter().map(|c| c.into()).collect(),
                }),
                connection::program::Cond::IsAutocommit => {
                    cond::Cond::IsAutocommit(IsAutocommitCond {})
                }
            };

            Self { cond: Some(cond) }
        }
    }
}

pub struct ProxyService {
    clients: Arc<RwLock<HashMap<Uuid, Arc<TimeoutConnection>>>>,
    namespaces: NamespaceStore,
    user_auth_strategy: Option<Auth>,
    disable_namespaces: bool,
}

impl ProxyService {
    pub fn new(
        namespaces: NamespaceStore,
        user_auth_strategy: Option<Auth>,
        disable_namespaces: bool,
    ) -> Self {
        Self {
            clients: Default::default(),
            namespaces,
            user_auth_strategy,
            disable_namespaces,
        }
    }

    pub fn clients(&self) -> Arc<RwLock<HashMap<Uuid, Arc<TimeoutConnection>>>> {
        self.clients.clone()
    }

    async fn extract_context<T>(
        &self,
        req: &mut tonic::Request<T>,
    ) -> Result<RequestContext, tonic::Status> {
        let namespace = super::extract_namespace(self.disable_namespaces, req)?;
        // todo dupe #auth
        let namespace_jwt_keys = self
            .namespaces
            .with(namespace.clone(), |ns| ns.jwt_keys())
            .await;

        let auth = match namespace_jwt_keys {
            Ok(Ok(Some(key))) => Some(Auth::new(Jwt::new(key))),
            Ok(Ok(None)) => self.user_auth_strategy.clone(),
            Err(e) => match e.as_ref() {
                crate::error::Error::NamespaceDoesntExist(_) => None,
                // A namespace the fence refuses is refused with the typed status, never
                // retried by the write proxy (`docs/NAMESPACE_FENCE.md` section 6.1).
                e => Err(fence_status(e).unwrap_or_else(|| {
                    tonic::Status::internal(format!(
                        "Error fetching jwt key for a namespace: {}",
                        e
                    ))
                }))?,
            },
            Ok(Err(e)) => Err(tonic::Status::internal(format!(
                "Error fetching jwt key for a namespace: {}",
                e
            )))?,
        };

        let auth = if let Some(auth) = auth {
            let context =
                parse_grpc_auth_header(req.metadata(), &auth.user_strategy.required_fields())
                    .map_err(|e| {
                        tonic::Status::internal(format!("Error parsing auth header: {}", e))
                    })?;
            auth.authenticate(context)?
        } else {
            Authenticated::from_proxy_grpc_request(req)?
        };

        Ok(RequestContext::new(
            auth,
            namespace,
            self.namespaces.meta_store().clone(),
        ))
    }
}

#[derive(Debug, Default)]
struct ExecuteResultsBuilder {
    output: Option<ExecuteResults>,
    results: Vec<QueryResult>,
    current_rows: Vec<Row>,
    current_row: rpc::Row,
    current_col_description: Vec<rpc::Column>,
    current_err: Option<crate::error::Error>,
    max_size: u64,
    current_size: u64,
    current_step_size: u64,
}

impl QueryResultBuilder for ExecuteResultsBuilder {
    type Ret = ExecuteResults;

    fn init(&mut self, config: &QueryBuilderConfig) -> Result<(), QueryResultBuilderError> {
        *self = Self {
            max_size: config.max_size.unwrap_or(u64::MAX),
            ..Default::default()
        };
        Ok(())
    }

    fn begin_step(&mut self) -> Result<(), QueryResultBuilderError> {
        assert!(self.current_err.is_none());
        assert!(self.current_rows.is_empty());
        self.current_step_size = 0;
        Ok(())
    }

    fn finish_step(
        &mut self,
        affected_row_count: u64,
        last_insert_rowid: Option<i64>,
    ) -> Result<(), QueryResultBuilderError> {
        self.current_size += self.current_step_size;
        match self.current_err.take() {
            Some(err) => {
                self.current_rows.clear();
                self.current_row.values.clear();
                self.current_col_description.clear();
                self.results.push(QueryResult {
                    row_result: Some(RowResult::Error(err.into())),
                })
            }
            None => {
                let result_rows = ResultRows {
                    column_descriptions: std::mem::take(&mut self.current_col_description),
                    rows: std::mem::take(&mut self.current_rows),
                    affected_row_count,
                    last_insert_rowid,
                };
                let res = QueryResult {
                    row_result: Some(RowResult::Row(result_rows)),
                };
                self.results.push(res);
            }
        }

        Ok(())
    }

    fn step_error(&mut self, error: crate::error::Error) -> Result<(), QueryResultBuilderError> {
        assert!(self.current_err.is_none());
        let error_size = error.to_string().len() as u64;
        if self.current_size + error_size > self.max_size {
            return Err(QueryResultBuilderError::ResponseTooLarge(self.max_size));
        }
        self.current_step_size = error_size;

        self.current_err = Some(error);

        Ok(())
    }

    fn cols_description<'a>(
        &mut self,
        cols: impl IntoIterator<Item = impl Into<Column<'a>>>,
    ) -> Result<(), QueryResultBuilderError> {
        assert!(self.current_col_description.is_empty());
        for col in cols {
            let col = col.into();
            let col_len =
                (col.decl_ty.map(|s| s.len()).unwrap_or_default() + col.name.len()) as u64;
            if col_len + self.current_step_size + self.current_size > self.max_size {
                return Err(QueryResultBuilderError::ResponseTooLarge(self.max_size));
            }
            self.current_step_size += col_len;

            let col = rpc::Column {
                name: col.name.to_owned(),
                decltype: col.decl_ty.map(ToString::to_string),
            };

            self.current_col_description.push(col);
        }

        Ok(())
    }

    fn begin_rows(&mut self) -> Result<(), QueryResultBuilderError> {
        Ok(())
    }

    fn begin_row(&mut self) -> Result<(), QueryResultBuilderError> {
        Ok(())
    }

    fn add_row_value(&mut self, v: ValueRef) -> Result<(), QueryResultBuilderError> {
        let data = bincode::serialize(
            &crate::query::Value::try_from(v).map_err(QueryResultBuilderError::from_any)?,
        )
        .map_err(QueryResultBuilderError::from_any)?;

        if data.len() as u64 + self.current_step_size + self.current_size > self.max_size {
            return Err(QueryResultBuilderError::ResponseTooLarge(self.max_size));
        }

        self.current_step_size += data.len() as u64;

        let value = rpc::Value { data };

        self.current_row.values.push(value);

        Ok(())
    }

    fn finish_row(&mut self) -> Result<(), QueryResultBuilderError> {
        let row = std::mem::replace(
            &mut self.current_row,
            Row {
                values: Vec::with_capacity(self.current_col_description.len()),
            },
        );
        self.current_rows.push(row);

        Ok(())
    }

    fn finish_rows(&mut self) -> Result<(), QueryResultBuilderError> {
        Ok(())
    }

    fn finish(
        &mut self,
        last_frame_no: Option<FrameNo>,
        is_autocommit: bool,
    ) -> Result<(), QueryResultBuilderError> {
        use libsql_replication::rpc::proxy::State;

        self.output = Some(ExecuteResults {
            results: std::mem::take(&mut self.results),
            state: if is_autocommit {
                State::Init.into()
            } else {
                State::Txn.into()
            },
            current_frame_no: last_frame_no,
        });
        Ok(())
    }

    fn into_ret(self) -> Self::Ret {
        self.output.unwrap()
    }

    fn add_stats(&mut self, _rows_read: u64, _rows_written: u64, _duration: Duration) {}
}

pub struct TimeoutConnection {
    inner: Connection,
    atime: AtomicU64,
}

impl TimeoutConnection {
    fn new(inner: Connection) -> Self {
        Self {
            inner,
            atime: now_millis().into(),
        }
    }
}

impl Deref for TimeoutConnection {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        self.atime.store(now_millis(), Ordering::Relaxed);
        &self.inner
    }
}

fn now_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

impl TimeoutConnection {
    pub fn idle_time(&self) -> Duration {
        let now = now_millis();
        let atime = self.atime.load(Ordering::Relaxed);
        Duration::from_millis(now.saturating_sub(atime))
    }
}

// Disconnects all clients that have been idle for more than 30 seconds.
// FIXME: we should also keep a list of recently disconnected clients,
// and if one should arrive with a late message, it should be rejected
// with an error. A similar mechanism is already implemented in hrana-over-http.
pub async fn garbage_collect(clients: &mut HashMap<Uuid, Arc<TimeoutConnection>>) {
    let limit = std::time::Duration::from_secs(30);

    clients.retain(|_, db| db.idle_time() < limit);
    if !clients.is_empty() {
        tracing::trace!("gc: remaining client handles count: {}", clients.len());
    }
}

/// The typed status of a fence denial on the proxy service (`docs/NAMESPACE_FENCE.md` section
/// 6.1): `FAILED_PRECONDITION` with the stable code, never `UNAVAILABLE`, which the write
/// proxy retries without bound.
/// Counted as a denial on the `rpc` surface when it is one.
fn fence_status(e: &crate::error::Error) -> Option<tonic::Status> {
    let fence = e.fence_error()?;
    let status = fence.to_grpc_status()?;
    crate::namespace::fence::audit::denied(
        fence,
        crate::namespace::fence::audit::DenialSurface::Rpc,
    );
    Some(status)
}

/// The status for an error looking up the namespace a proxy request names.
fn namespace_status(e: crate::error::Error) -> tonic::Status {
    if let crate::error::Error::NamespaceDoesntExist(_) = e {
        tonic::Status::failed_precondition(NAMESPACE_DOESNT_EXIST)
    } else if let Some(status) = fence_status(&e) {
        status
    } else {
        tonic::Status::internal(e.to_string())
    }
}

#[tonic::async_trait]
impl Proxy for ProxyService {
    type StreamExecStream = Pin<Box<dyn Stream<Item = Result<ExecResp, tonic::Status>> + Send>>;

    async fn stream_exec(
        &self,
        mut req: tonic::Request<tonic::Streaming<ExecReq>>,
    ) -> Result<tonic::Response<Self::StreamExecStream>, tonic::Status> {
        let ctx = self.extract_context(&mut req).await?;

        let (connection_maker, _new_frame_notifier) = self
            .namespaces
            .with(ctx.namespace().clone(), |ns| {
                let connection_maker = ns.db.connection_maker();
                let notifier = ns.db.notifier();
                (connection_maker, notifier)
            })
            .await
            .map_err(namespace_status)?;

        let conn = connection_maker.create().await.map_err(|e| {
            fence_status(&e).unwrap_or_else(|| {
                tonic::Status::unavailable(format!("Unable to create DB: {:?}", e))
            })
        })?;

        let stream = make_proxy_stream(conn, ctx, req.into_inner());

        Ok(tonic::Response::new(Box::pin(stream)))
    }

    async fn execute(
        &self,
        mut req: tonic::Request<rpc::ProgramReq>,
    ) -> Result<tonic::Response<ExecuteResults>, tonic::Status> {
        let ctx = self.extract_context(&mut req).await?;
        let req = req.into_inner();
        let pgm = crate::connection::program::Program::try_from(req.pgm.unwrap())
            .map_err(|e| tonic::Status::new(tonic::Code::InvalidArgument, e.to_string()))?;
        let client_id = Uuid::from_str(&req.client_id).unwrap();

        let connection_maker = self
            .namespaces
            .with(ctx.namespace().clone(), |ns| ns.db.connection_maker())
            .await
            .map_err(namespace_status)?;

        let conn = {
            let lock = self.clients.upgradable_read().await;
            match lock.get(&client_id) {
                Some(conn) => conn.clone(),
                None => {
                    tracing::debug!("connected: {client_id}");
                    match connection_maker.create().await {
                        Ok(conn) => {
                            if !conn.is_primary() {
                                return Err(tonic::Status::failed_precondition(
                                    "cannot run schema migration against a replica from a replica",
                                ));
                            }

                            let conn = Arc::new(TimeoutConnection::new(conn));
                            let mut lock = RwLockUpgradableReadGuard::upgrade(lock).await;
                            lock.insert(client_id, conn.clone());
                            conn
                        }
                        Err(e) => {
                            return Err(fence_status(&e).unwrap_or_else(|| {
                                tonic::Status::new(tonic::Code::Internal, e.to_string())
                            }))
                        }
                    }
                }
            }
        };

        tracing::debug!("executing request for {client_id}");

        let builder = ExecuteResultsBuilder::default();
        let builder = conn
            .execute_program(pgm, ctx, builder, None)
            .await
            // TODO: this is no necessarily a permission denied error!
            .map_err(|e| {
                fence_status(&e).unwrap_or_else(|| {
                    tonic::Status::new(tonic::Code::PermissionDenied, e.to_string())
                })
            })?;

        Ok(tonic::Response::new(builder.into_ret()))
    }

    //TODO: also handle cleanup on peer disconnect
    async fn disconnect(
        &self,
        msg: tonic::Request<DisconnectMessage>,
    ) -> Result<tonic::Response<Ack>, tonic::Status> {
        let DisconnectMessage { client_id } = msg.into_inner();
        let client_id = Uuid::from_str(&client_id).unwrap();

        tracing::debug!("disconnected: {client_id}");

        self.clients.write().await.remove(&client_id);

        Ok(tonic::Response::new(Ack {}))
    }

    async fn describe(
        &self,
        mut req: tonic::Request<DescribeRequest>,
    ) -> Result<tonic::Response<DescribeResult>, tonic::Status> {
        let ctx = self.extract_context(&mut req).await?;

        // FIXME: copypasta from execute(), creatively extract to a helper function
        let lock = self.clients.upgradable_read().await;
        let connection_maker = self
            .namespaces
            .with(ctx.namespace().clone(), |ns| ns.db.connection_maker())
            .await
            .map_err(namespace_status)?;

        let DescribeRequest { client_id, stmt } = req.into_inner();
        let client_id = Uuid::from_str(&client_id).unwrap();

        let conn = match lock.get(&client_id) {
            Some(conn) => conn.clone(),
            None => {
                tracing::debug!("connected: {client_id}");
                match connection_maker.create().await {
                    Ok(conn) => {
                        if !conn.is_primary() {
                            return Err(tonic::Status::failed_precondition(
                                "cannot run schema migration against a replica from a replica",
                            ));
                        }

                        let conn = Arc::new(TimeoutConnection::new(conn));
                        let mut lock = RwLockUpgradableReadGuard::upgrade(lock).await;
                        lock.insert(client_id, conn.clone());
                        conn
                    }
                    Err(e) => {
                        return Err(fence_status(&e).unwrap_or_else(|| {
                            tonic::Status::new(tonic::Code::Internal, e.to_string())
                        }))
                    }
                }
            }
        };

        let description = conn
            .describe(stmt, ctx, None)
            .await
            // TODO: this is no necessarily a permission denied error!
            // FIXME: the double map_err looks off
            .map_err(|e| tonic::Status::new(tonic::Code::PermissionDenied, e.to_string()))?
            .map_err(|e| tonic::Status::new(tonic::Code::PermissionDenied, e.to_string()))?;

        let param_count = description.params.len() as u64;
        let param_names = description
            .params
            .into_iter()
            .filter_map(|p| p.name)
            .collect::<Vec<_>>();

        Ok(tonic::Response::new(DescribeResult {
            describe_result: Some(describe_result::DescribeResult::Description(Description {
                column_descriptions: description
                    .cols
                    .into_iter()
                    .map(|c| crate::rpc::proxy::rpc::Column {
                        name: c.name,
                        decltype: c.decltype,
                    })
                    .collect(),
                param_names,
                param_count,
            })),
        }))
    }
}

/// Fence denials on the proxy protocol (`docs/NAMESPACE_FENCE.md` section 6.1): the primary
/// fills the additive `stable_code` of a step or program error and answers a namespace it
/// refuses with the typed `FAILED_PRECONDITION` status; the replica side turns both back into
/// the same fence denial, and an older primary's errors keep their untyped mapping.
#[cfg(test)]
mod fence_tests {
    use libsql_replication::rpc::proxy::error::ErrorCode;
    use libsql_replication::rpc::proxy::exec_resp;
    use libsql_replication::rpc::proxy::{
        resp_step, ExecReq, ProgramResp, RespStep, StepError, StreamProgramReq,
    };
    use libsql_replication::rpc::replication::NAMESPACE_METADATA_KEY;
    use tempfile::tempdir;
    use tokio_stream::wrappers::ReceiverStream;
    use tokio_stream::StreamExt as _;
    use tonic::metadata::BinaryMetadataValue;

    use super::*;
    use crate::connection::program::Program;
    use crate::error::Error;
    use crate::namespace::fence::drain::tests::{fence_outcome, Source, LONG};
    use crate::namespace::fence::outcome::{FenceError, FenceOutcome, GRPC_FENCE_CODE_METADATA};
    use crate::namespace::fence::read::tests::{fenced_source, read_fence};
    use crate::namespace::fence::store as fence_store;
    use crate::query_result_builder::QueryBuilderConfig;

    const WRITE: &str = "insert into t values (3)";
    const READ: &str = "select count(*) from t";

    fn service(s: &NamespaceStore) -> ProxyService {
        ProxyService::new(s.clone(), None, false)
    }

    fn request<T>(ns: &str, msg: T) -> tonic::Request<T> {
        let mut req = tonic::Request::new(msg);
        req.metadata_mut().insert_bin(
            NAMESPACE_METADATA_KEY,
            BinaryMetadataValue::from_bytes(ns.as_bytes()),
        );
        Authenticated::FullAccess.upgrade_grpc_request(&mut req);
        req
    }

    fn program_req(sql: &str) -> rpc::ProgramReq {
        rpc::ProgramReq {
            client_id: Uuid::new_v4().to_string(),
            pgm: Some(Program::seq(&[sql]).into()),
        }
    }

    #[track_caller]
    fn assert_fence_status(status: &tonic::Status, outcome: FenceOutcome) {
        assert_eq!(status.code(), tonic::Code::FailedPrecondition, "{status:?}");
        assert_eq!(
            status
                .metadata()
                .get(GRPC_FENCE_CODE_METADATA)
                .and_then(|v| v.to_str().ok()),
            Some(outcome.as_str()),
            "{status:?}"
        );
        assert_eq!(
            FenceError::outcome_from_grpc_status(status),
            Some(outcome),
            "{status:?}"
        );
    }

    #[track_caller]
    fn assert_proxy_error(error: &rpc::Error, outcome: FenceOutcome) {
        assert_eq!(error.code, ErrorCode::SqlError as i32, "{error:?}");
        assert_eq!(error.stable_code.as_deref(), Some(outcome.as_str()));
        assert!(error.message.starts_with(outcome.as_str()), "{error:?}");
    }

    /// The step errors of a streamed program, run on `ns` through the primary's proxy stream.
    async fn stream_program(s: &Source, sql: &str) -> Vec<exec_resp::Response> {
        let conn = s
            .store
            .with("ns".into(), |ns| ns.db.connection_maker())
            .await
            .unwrap()
            .create()
            .await
            .unwrap();
        let ctx = RequestContext::new(
            Authenticated::FullAccess,
            "ns".into(),
            s.store.meta_store().clone(),
        );
        let (snd, rcv) = tokio::sync::mpsc::channel(1);
        let stream = make_proxy_stream(conn, ctx, ReceiverStream::new(rcv));
        tokio::pin!(stream);
        snd.send(Ok(ExecReq {
            request_id: 0,
            request: Some(libsql_replication::rpc::proxy::exec_req::Request::Execute(
                StreamProgramReq {
                    pgm: Some(Program::seq(&[sql]).into()),
                },
            )),
        }))
        .await
        .unwrap();
        // The request stream stays open until the program is answered: a closed request stream
        // ends the proxy stream.
        let mut responses = Vec::new();
        while let Some(resp) = stream.next().await {
            let resp = resp.unwrap().response.unwrap();
            let last = match &resp {
                exec_resp::Response::ProgramResp(p) => p
                    .steps
                    .iter()
                    .any(|s| matches!(s.step, Some(resp_step::Step::Finish(_)))),
                _ => true,
            };
            responses.push(resp);
            if last {
                break;
            }
        }
        drop(snd);
        responses
    }

    fn step_errors(responses: &[exec_resp::Response]) -> Vec<&rpc::Error> {
        responses
            .iter()
            .filter_map(|r| match r {
                exec_resp::Response::ProgramResp(p) => Some(p),
                _ => None,
            })
            .flat_map(|p| &p.steps)
            .filter_map(|s| match &s.step {
                Some(resp_step::Step::StepError(StepError { error: Some(e) })) => Some(e),
                _ => None,
            })
            .collect()
    }

    /// Section 6.1 on the primary: a write refused at the WAL gate is a step error with the
    /// stable code, a read refused by the read fence is a program error with it (streamed) or
    /// the typed status (unary), and a namespace whose fence state is unknown is refused with
    /// the typed status before any connection is made.
    #[tokio::test]
    async fn rpc_codes() {
        let s = fenced_source().await;

        // Write-fenced: the write step carries MIGRATION_WRITE_FENCED, reads are served.
        let streamed = stream_program(&s, WRITE).await;
        let errors = step_errors(&streamed);
        assert_eq!(errors.len(), 1, "{streamed:?}");
        assert_proxy_error(errors[0], FenceOutcome::MigrationWriteFenced);
        assert!(step_errors(&stream_program(&s, READ).await).is_empty());

        let unary = service(&s.store)
            .execute(request("ns", program_req(WRITE)))
            .await
            .unwrap()
            .into_inner();
        match &unary.results[..] {
            [QueryResult {
                row_result: Some(RowResult::Error(e)),
            }] => assert_proxy_error(e, FenceOutcome::MigrationWriteFenced),
            other => panic!("{other:?}"),
        }

        // Read-fenced: the whole program is refused.
        let fenced = s.execute(read_fence(&s, 2, LONG)).await.unwrap();
        assert_eq!(fence_outcome(&fenced), FenceOutcome::Applied);
        match &stream_program(&s, READ).await[..] {
            [exec_resp::Response::Error(e)] => {
                assert_proxy_error(e, FenceOutcome::MigrationReadFenced)
            }
            other => panic!("{other:?}"),
        }
        let status = service(&s.store)
            .execute(request("ns", program_req(READ)))
            .await
            .unwrap_err();
        assert_fence_status(&status, FenceOutcome::MigrationReadFenced);

        // A namespace whose fence state cannot be established.
        let tmp = tempdir().unwrap();
        let broken = tmp.path().join("dbs").join("broken");
        std::fs::create_dir_all(&broken).unwrap();
        std::fs::write(broken.join(fence_store::MARKER_FILE_NAME), b"garbage").unwrap();
        let store = crate::namespace::open_test_store(tmp.path()).await;
        let status = service(&store)
            .execute(request("broken", program_req(READ)))
            .await
            .unwrap_err();
        assert_fence_status(&status, FenceOutcome::FenceStateUnavailable);
        assert_eq!(
            namespace_status(Error::NamespaceFence(
                store
                    .with("broken".into(), |_| ())
                    .await
                    .unwrap_err()
                    .fence_error()
                    .unwrap()
                    .clone()
            ))
            .code(),
            tonic::Code::FailedPrecondition
        );
        // A connection a fence refuses is never reported as `UNAVAILABLE`.
        let e = Error::NamespaceFence(FenceError::new(FenceOutcome::MigrationWriteFenced, "x"));
        assert_fence_status(
            &fence_status(&e).unwrap(),
            FenceOutcome::MigrationWriteFenced,
        );
        assert!(fence_status(&Error::LibSqlTxBusy).is_none());
    }

    /// Section 6.1 on the replica: a proxied fence denial becomes the fence error the replica
    /// answers its client with, whether it arrives as a step error, a program error or a
    /// status; an older primary's errors (no `stable_code`) keep their untyped mapping.
    #[tokio::test]
    async fn replica_maps_proxied_denials() {
        let denial = FenceError::new(FenceOutcome::MigrationWriteFenced, "writes are fenced");
        let proxied: rpc::Error = Error::NamespaceFence(denial.clone()).into();
        assert_eq!(proxied.code, ErrorCode::SqlError as i32);
        match Error::from_proxy_error(proxied.clone()) {
            Error::NamespaceFence(e) => assert_eq!(e, denial),
            other => panic!("{other:?}"),
        }
        // An older primary: same error without the additive field.
        let old = rpc::Error {
            stable_code: None,
            ..proxied.clone()
        };
        assert!(matches!(
            Error::from_proxy_error(old.clone()),
            Error::RpcQueryError(e) if e == old
        ));
        // A code this server does not know stays untyped too.
        let unknown = rpc::Error {
            stable_code: Some("SOMETHING_NEW".into()),
            ..proxied.clone()
        };
        assert!(matches!(
            Error::from_proxy_error(unknown),
            Error::RpcQueryError(_)
        ));
        // Other errors are unchanged.
        let busy: rpc::Error = Error::LibSqlTxBusy.into();
        assert_eq!(busy.stable_code, None);
        assert_eq!(busy.code, ErrorCode::TxBusy as i32);

        // Status at connection time: typed denial, not retried; anything else unchanged.
        match Error::from_proxy_status(denial.to_grpc_status().unwrap()) {
            Error::NamespaceFence(e) => assert_eq!(e, denial),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            Error::from_proxy_status(tonic::Status::failed_precondition("x")),
            Error::RpcQueryExecutionError(_)
        ));

        // A step error applied to the replica's result builder.
        let resp = ProgramResp {
            steps: [
                resp_step::Step::Init(Default::default()),
                resp_step::Step::BeginStep(Default::default()),
                resp_step::Step::StepError(StepError {
                    error: Some(proxied),
                }),
                resp_step::Step::FinishStep(Default::default()),
                resp_step::Step::Finish(Default::default()),
            ]
            .into_iter()
            .map(|step| RespStep { step: Some(step) })
            .collect(),
        };
        let mut builder = crate::http::user::result_builder::JsonHttpPayloadBuilder::new();
        crate::rpc::streaming_exec::apply_program_resp_to_builder(
            &QueryBuilderConfig::default(),
            &mut builder,
            resp,
            |_, _| (),
        )
        .unwrap();
        assert_eq!(builder.take_fence_denial(), Some(denial));
    }
}
