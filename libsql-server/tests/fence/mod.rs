#![allow(deprecated)]

//! Namespace fence integration tests (`docs/NAMESPACE_FENCE.md`), driven over the admin API.

mod admin;
mod lifecycle;
mod observability;
mod protocol;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use hyper::StatusCode;
use libsql_server::auth::user_auth_strategies::http_basic::HttpBasic;
use libsql_server::auth::Auth;
use libsql_server::config::{
    AdminApiConfig, FenceAdoptionKey, MetaStoreConfig, RpcClientConfig, RpcServerConfig,
    UserApiConfig,
};
use s3s::header::AUTHORIZATION;
use serde_json::{json, Value};
use tokio::sync::Notify;
use turmoil::{Builder, Sim};
use uuid::Uuid;

use crate::common::http::Client;
use crate::common::net::{
    init_tracing, SimServer as _, TestServer, TurmoilAcceptor, TurmoilConnector,
};

pub const ADMIN_KEY: &str = "fence-admin-key";

#[derive(Clone, Copy)]
pub struct Primary {
    /// `None` starts the admin API without an auth key.
    pub admin_key: Option<&'static str>,
    pub fence_enabled: bool,
    /// A basic-auth credential the user API requires; `None` leaves it unauthenticated.
    pub user_credential: Option<&'static str>,
    /// The fence adoption key; `None` leaves adoption disabled.
    pub adoption_key: Option<&'static str>,
    /// Capacity of the live namespace cache. Fence controllers live outside this cache.
    pub max_active_namespaces: usize,
}

impl Default for Primary {
    fn default() -> Self {
        Self {
            admin_key: Some(ADMIN_KEY),
            fence_enabled: true,
            user_credential: None,
            adoption_key: None,
            max_active_namespaces: 100,
        }
    }
}

pub fn sim() -> Sim<'static> {
    Builder::new()
        .simulation_duration(Duration::from_secs(1000))
        .build()
}

async fn primary_server(path: PathBuf, primary: Primary) -> anyhow::Result<TestServer> {
    let Primary {
        admin_key,
        fence_enabled,
        user_credential,
        adoption_key,
        max_active_namespaces,
    } = primary;
    Ok(TestServer {
        path: path.into(),
        user_api_config: UserApiConfig {
            auth_strategy: match user_credential {
                Some(credential) => Auth::new(HttpBasic::new(credential.into())),
                None => UserApiConfig::<TurmoilAcceptor>::default().auth_strategy,
            },
            ..Default::default()
        },
        admin_api_config: Some(AdminApiConfig {
            acceptor: TurmoilAcceptor::bind(([0, 0, 0, 0], 9090)).await?,
            connector: TurmoilConnector,
            disable_metrics: true,
            auth_key: admin_key.map(Into::into),
        }),
        rpc_server_config: Some(RpcServerConfig {
            acceptor: TurmoilAcceptor::bind(([0, 0, 0, 0], 4567)).await?,
            tls_config: None,
        }),
        meta_store_config: MetaStoreConfig {
            namespace_fence: fence_enabled,
            namespace_fence_adoption_key: adoption_key.and_then(FenceAdoptionKey::new),
            ..Default::default()
        },
        disable_namespaces: false,
        disable_default_namespace: true,
        max_active_namespaces,
        ..Default::default()
    })
}

/// A primary on host `primary`: user API on 8080, admin API on 9090.
pub fn make_primary(sim: &mut Sim, path: PathBuf, primary: Primary) {
    init_tracing();
    sim.host("primary", move || {
        let path = path.clone();
        async move {
            primary_server(path, primary).await?.start_sim(8080).await?;
            Ok(())
        }
    });
}

/// A primary that shuts down when `restart` is notified, then starts again on the same path.
/// `restarted` is notified after the second server has rebound the admin and RPC listeners; an
/// admin request made after that notification is the readiness barrier for the restarted server.
pub fn make_restartable_primary(
    sim: &mut Sim,
    path: PathBuf,
    primary: Primary,
    restart: Arc<Notify>,
    restarted: Arc<Notify>,
) {
    init_tracing();
    sim.host("primary", move || {
        let path = path.clone();
        let restart = restart.clone();
        let restarted = restarted.clone();
        async move {
            let mut server = primary_server(path.clone(), primary).await?;
            server.shutdown = restart;
            server.start_sim(8080).await?;

            let server = primary_server(path, primary).await?;
            restarted.notify_one();
            server.start_sim(8080).await?;
            Ok(())
        }
    });
}

/// A replica of `primary` on host `replica0`: user API on 8080, admin API (no auth key) on
/// 9090. It creates a namespace lazily, on first use, by replicating it from the primary.
pub fn make_replica(sim: &mut Sim, path: PathBuf) {
    init_tracing();
    sim.host("replica0", move || {
        let path = path.clone();
        async move {
            let server = TestServer {
                path: path.into(),
                user_api_config: UserApiConfig::default(),
                admin_api_config: Some(AdminApiConfig {
                    acceptor: TurmoilAcceptor::bind(([0, 0, 0, 0], 9090)).await?,
                    connector: TurmoilConnector,
                    disable_metrics: true,
                    auth_key: None,
                }),
                rpc_client_config: Some(RpcClientConfig {
                    remote_url: "http://primary:4567".into(),
                    connector: TurmoilConnector,
                    tls_config: None,
                }),
                disable_namespaces: false,
                disable_default_namespace: true,
                ..Default::default()
            };
            server.start_sim(8080).await?;
            Ok(())
        }
    });
}

/// The admin API of `primary`, authenticating with `key` when there is one.
pub struct Admin {
    client: Client,
    key: Option<String>,
}

impl Admin {
    pub fn new(key: Option<&str>) -> Self {
        Self {
            client: Client::new(),
            key: key.map(|k| format!("basic {k}")),
        }
    }

    fn headers(&self) -> Vec<(hyper::header::HeaderName, &str)> {
        self.key
            .as_deref()
            .map(|k| vec![(AUTHORIZATION, k)])
            .unwrap_or_default()
    }

    async fn json(resp: crate::common::http::Response) -> anyhow::Result<(StatusCode, Value)> {
        let status = resp.status();
        let body = resp.body_string().await?;
        let value = if body.trim().is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&body).unwrap_or(Value::String(body))
        };
        Ok((status, value))
    }

    pub async fn get(&self, path: &str) -> anyhow::Result<(StatusCode, Value)> {
        let url = format!("http://primary:9090{path}");
        Self::json(self.client.get_with_headers(&url, &self.headers()).await?).await
    }

    pub async fn post(&self, path: &str, body: Value) -> anyhow::Result<(StatusCode, Value)> {
        let url = format!("http://primary:9090{path}");
        Self::json(
            self.client
                .post_with_headers(&url, &self.headers(), body)
                .await?,
        )
        .await
    }

    pub async fn delete(&self, path: &str) -> anyhow::Result<(StatusCode, Value)> {
        let url = format!("http://primary:9090{path}");
        Self::json(
            self.client
                .delete_with_headers(&url, &self.headers(), json!({}))
                .await?,
        )
        .await
    }

    pub async fn create_namespace(&self, ns: &str) -> anyhow::Result<()> {
        let (status, body) = self
            .post(&format!("/v1/namespaces/{ns}/create"), json!({}))
            .await?;
        anyhow::ensure!(status.is_success(), "create {ns}: {status} {body}");
        Ok(())
    }

    pub async fn inspect(&self, ns: &str) -> anyhow::Result<(StatusCode, Value)> {
        self.get(&format!("/v1/namespaces/{ns}/fence")).await
    }

    /// `AdoptFence`, presenting `adoption_key` (if any) in the adoption key header.
    pub async fn adopt(
        &self,
        ns: &str,
        body: Value,
        adoption_key: Option<&str>,
    ) -> anyhow::Result<(StatusCode, Value)> {
        let url = format!("http://primary:9090/v1/namespaces/{ns}/fence/adopt");
        let mut headers = self.headers();
        let name = hyper::header::HeaderName::from_static("x-libsql-fence-adoption-key");
        if let Some(key) = adoption_key {
            headers.push((name, key));
        }
        Self::json(self.client.post_with_headers(&url, &headers, body).await?).await
    }

    /// A fence command: `route` is the part after `/fence/`.
    pub async fn command(
        &self,
        ns: &str,
        route: &str,
        body: Value,
    ) -> anyhow::Result<(StatusCode, Value)> {
        self.post(&format!("/v1/namespaces/{ns}/fence/{route}"), body)
            .await
    }
}

/// The common fields of a fence command, with `extra` merged in.
pub fn command_body(
    operation_id: Uuid,
    command_id: Uuid,
    expected_state: &str,
    expected_revision: u64,
    extra: Value,
) -> Value {
    let mut body = json!({
        "operation_id": operation_id.to_string(),
        "command_id": command_id.to_string(),
        "expected_state": expected_state,
        "expected_revision": expected_revision,
    });
    if let Value::Object(extra) = extra {
        body.as_object_mut().unwrap().extend(extra);
    }
    body
}

pub fn state_of(body: &Value) -> (&str, u64) {
    (
        body["fence"]["state"].as_str().unwrap_or("<none>"),
        body["fence"]["revision"].as_u64().unwrap_or(u64::MAX),
    )
}

/// A connection to namespace `ns` over the user API.
pub fn connect(ns: &str) -> anyhow::Result<libsql::Connection> {
    let db = libsql::Database::open_remote_with_connector(
        format!("http://{ns}.primary:8080"),
        "",
        TurmoilConnector,
    )?;
    Ok(db.connect()?)
}

/// Execute one statement through the Hrana v1 user endpoint, returning its typed body.
pub async fn user_execute(ns: &str, sql: &str) -> anyhow::Result<(StatusCode, Value)> {
    let response = Client::new()
        .post(
            &format!("http://{ns}.primary:8080/v1/execute"),
            json!({ "stmt": { "sql": sql } }),
        )
        .await?;
    let status = response.status();
    Ok((status, response.json_value().await?))
}

/// Load `ns` on the server with one write, and return the replication log id the server
/// reports for it.
pub async fn load_and_log_id(admin: &Admin, ns: &str) -> anyhow::Result<String> {
    let conn = connect(ns)?;
    conn.execute("create table if not exists t (x)", ()).await?;
    conn.execute("insert into t values (1)", ()).await?;
    let (status, body) = admin.inspect(ns).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(state_of(&body), ("UNFENCED", 0), "{body}");
    Ok(body["fence"]["incarnation"]["current_log_id"]
        .as_str()
        .unwrap_or_else(|| panic!("no current_log_id: {body}"))
        .to_string())
}

/// An `AcquireSourceWriteFence` body for a namespace in `UNFENCED` at revision 0.
pub fn acquire_body(op: Uuid, cmd: Uuid, log_id: &str) -> Value {
    command_body(
        op,
        cmd,
        "UNFENCED",
        0,
        json!({
            "expected_namespace_identity": { "log_id": log_id },
            "drain_policy": { "deadline_ms": 5000, "on_deadline": "fail" },
        }),
    )
}
