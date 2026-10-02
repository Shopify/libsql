#![allow(deprecated)]

mod dumps;
mod meta;
mod shared_schema;

use std::path::PathBuf;
use std::time::Duration;

use crate::common::http::Client;
use crate::common::net::{init_tracing, SimServer, TestServer, TurmoilAcceptor, TurmoilConnector};
use libsql::{Database, Value};
use libsql_server::config::{AdminApiConfig, RpcServerConfig, UserApiConfig};
use serde_json::json;
use tempfile::tempdir;
use turmoil::{Builder, Sim};

fn make_primary(sim: &mut Sim, path: PathBuf) {
    init_tracing();
    sim.host("primary", move || {
        let path = path.clone();
        async move {
            let server = TestServer {
                path: path.into(),
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
                disable_namespaces: false,
                disable_default_namespace: true,
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
fn admin_rejects_namespace_path_traversal_without_touching_outside_files() {
    let mut sim = Builder::new()
        .simulation_duration(Duration::from_secs(1000))
        .build();
    let tmp = tempdir().unwrap();
    make_primary(&mut sim, tmp.path().to_path_buf());

    let outside = tmp.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("sentinel"), b"keep me").unwrap();
    let dbs = tmp.path().join("dbs");
    let absolute_victim =
        url::form_urlencoded::byte_serialize(outside.to_str().unwrap().as_bytes())
            .collect::<String>()
            .replace('+', "%20");
    let dbs_for_client = dbs.clone();

    sim.client("client", async move {
        let client = Client::new();
        assert!(client
            .post(
                "http://primary:9090/v1/namespaces/safe-1.example/create",
                json!({})
            )
            .await?
            .status()
            .is_success());
        std::fs::create_dir_all(dbs_for_client.join("sentinel"))?;
        std::fs::write(dbs_for_client.join("sentinel/marker"), b"keep me too")?;
        for name in [
            "%2e%2e".to_owned(),
            "%2e%2e%2foutside".to_owned(),
            absolute_victim,
            "bad%5cname".to_owned(),
        ] {
            assert_eq!(
                client
                    .post(
                        &format!("http://primary:9090/v1/namespaces/{name}/create"),
                        json!({})
                    )
                    .await?
                    .status(),
                hyper::StatusCode::BAD_REQUEST,
                "create {name}"
            );
            assert_eq!(
                client
                    .delete(
                        &format!("http://primary:9090/v1/namespaces/{name}"),
                        json!({})
                    )
                    .await?
                    .status(),
                hyper::StatusCode::BAD_REQUEST,
                "delete {name}"
            );
            assert_eq!(
                client
                    .post(
                        &format!("http://primary:9090/v1/namespaces/safe-1.example/fork/{name}"),
                        ()
                    )
                    .await?
                    .status(),
                hyper::StatusCode::BAD_REQUEST,
                "fork {name}"
            );
        }
        assert_eq!(
            client
                .post("http://primary:9090/v1/namespaces/%2e%2e/fork/target", ())
                .await?
                .status(),
            hyper::StatusCode::BAD_REQUEST
        );
        Ok(())
    });

    sim.run().unwrap();
    assert_eq!(std::fs::read(outside.join("sentinel")).unwrap(), b"keep me");
    assert_eq!(
        std::fs::read(dbs.join("sentinel/marker")).unwrap(),
        b"keep me too"
    );
    assert!(dbs.join("safe-1.example").exists());
    assert!(!dbs.join("target").exists());
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
