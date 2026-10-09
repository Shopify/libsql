#![allow(deprecated)]

mod dumps;
mod lifecycle;
mod meta;
mod shared_schema;

use std::path::PathBuf;
use std::time::Duration;

use crate::common::http::Client;
use crate::common::net::{init_tracing, SimServer, TestServer, TurmoilAcceptor, TurmoilConnector};
use libsql::{Database, Value};
use libsql_server::config::{AdminApiConfig, DbConfig, RpcServerConfig, UserApiConfig};
use serde_json::json;
use tempfile::tempdir;
use turmoil::{Builder, Sim};

fn make_primary(sim: &mut Sim, path: PathBuf) {
    make_primary_with_db_config(sim, path, DbConfig::default());
}

fn make_primary_with_db_config(sim: &mut Sim, path: PathBuf, db_config: DbConfig) {
    make_primary_with(sim, path, db_config, false);
}

/// A primary running in single-namespace mode (`--disable-namespaces`): only the default
/// namespace exists, and it is created at startup.
fn make_single_namespace_primary(sim: &mut Sim, path: PathBuf) {
    make_primary_with(sim, path, DbConfig::default(), true);
}

fn make_primary_with(sim: &mut Sim, path: PathBuf, db_config: DbConfig, single_namespace: bool) {
    init_tracing();
    sim.host("primary", move || {
        let path = path.clone();
        let db_config = db_config.clone();
        async move {
            let server = TestServer {
                path: path.into(),
                db_config,
                user_api_config: UserApiConfig {
                    ..Default::default()
                },
                admin_api_config: Some(AdminApiConfig {
                    acceptor: TurmoilAcceptor::bind(([0, 0, 0, 0], 9090)).await?,
                    connector: TurmoilConnector,
                    disable_metrics: true,
                    auth_key: None,
                }),
                rpc_server_config: Some(RpcServerConfig {
                    acceptor: TurmoilAcceptor::bind(([0, 0, 0, 0], 4567)).await?,
                    tls_config: None,
                }),
                disable_namespaces: single_namespace,
                disable_default_namespace: !single_namespace,
                ..Default::default()
            };

            server.start_sim(8080).await?;

            Ok(())
        }
    });
}

#[test]
fn fork_namespace() {
    let mut sim = Builder::new()
        .simulation_duration(Duration::from_secs(1000))
        .build();
    let tmp = tempdir().unwrap();
    make_primary(&mut sim, tmp.path().to_path_buf());

    sim.client("client", async {
        let client = Client::new();
        client
            .post("http://primary:9090/v1/namespaces/foo/create", json!({}))
            .await?;

        let foo =
            Database::open_remote_with_connector("http://foo.primary:8080", "", TurmoilConnector)?;
        let foo_conn = foo.connect()?;

        foo_conn.execute("create table test (c)", ()).await?;
        foo_conn.execute("insert into test values (42)", ()).await?;

        client
            .post("http://primary:9090/v1/namespaces/foo/fork/bar", ())
            .await?;

        let bar =
            Database::open_remote_with_connector("http://bar.primary:8080", "", TurmoilConnector)?;
        let bar_conn = bar.connect()?;

        // what's in foo is in bar as well
        let mut rows = bar_conn.query("select count(*) from test", ()).await?;
        assert!(matches!(
            rows.next().await.unwrap().unwrap().get_value(0).unwrap(),
            Value::Integer(1)
        ));

        bar_conn.execute("insert into test values (42)", ()).await?;

        // add something to bar
        let mut rows = bar_conn.query("select count(*) from test", ()).await?;
        assert!(matches!(
            rows.next().await.unwrap().unwrap().get_value(0)?,
            Value::Integer(2)
        ));

        // ... and make sure it doesn't exist in foo
        let mut rows = foo_conn.query("select count(*) from test", ()).await?;
        assert!(matches!(
            rows.next().await.unwrap().unwrap().get_value(0)?,
            Value::Integer(1)
        ));

        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn delete_namespace() {
    let mut sim = Builder::new()
        .simulation_duration(Duration::from_secs(1000))
        .build();
    let tmp = tempdir().unwrap();
    make_primary(&mut sim, tmp.path().to_path_buf());

    sim.client("client", async {
        let client = Client::new();
        client
            .post("http://primary:9090/v1/namespaces/foo/create", json!({}))
            .await?;

        let foo =
            Database::open_remote_with_connector("http://foo.primary:8080", "", TurmoilConnector)?;
        let foo_conn = foo.connect()?;
        foo_conn.execute("create table test (c)", ()).await?;

        client
            .delete("http://primary:9090/v1/namespaces/foo", json!({}))
            .await
            .unwrap();
        // namespace doesn't exist anymore
        let res = foo_conn.execute("create table test (c)", ()).await;
        assert!(res.is_err());

        Ok(())
    });

    sim.run().unwrap();
}
