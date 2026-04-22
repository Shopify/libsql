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

#[test]
fn integrity_check_on_healthy_namespace() {
    let mut sim = Builder::new()
        .simulation_duration(Duration::from_secs(1000))
        .build();
    let tmp = tempdir().unwrap();
    make_primary(&mut sim, tmp.path().to_path_buf());

    sim.client("client", async {
        let client = Client::new();
        client
            .post("http://primary:9090/v1/namespaces/chk/create", json!({}))
            .await?;

        let db = Database::open_remote_with_connector(
            "http://chk.primary:8080",
            "",
            TurmoilConnector,
        )?;
        let conn = db.connect()?;
        conn.execute("create table t(v text)", ()).await?;
        conn.execute("insert into t values ('alive')", ()).await?;

        // quick_check should report ok on a healthy DB.
        let resp = client
            .post(
                "http://primary:9090/v1/namespaces/chk/integrity-check",
                json!({ "full": false }),
            )
            .await?;
        assert_eq!(resp.status(), hyper::http::StatusCode::OK);
        let v = resp.json_value().await?;
        assert_eq!(v["ok"], json!(true));
        assert_eq!(v["message"], json!("ok"));
        assert_eq!(v["check"], json!("quick"));

        // Full integrity_check should also succeed.
        let resp = client
            .post(
                "http://primary:9090/v1/namespaces/chk/integrity-check",
                json!({ "full": true }),
            )
            .await?;
        let v = resp.json_value().await?;
        assert_eq!(v["ok"], json!(true));
        assert_eq!(v["check"], json!("full"));

        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn reset_replication_preserves_data_on_healthy_namespace() {
    let mut sim = Builder::new()
        .simulation_duration(Duration::from_secs(1000))
        .build();
    let tmp = tempdir().unwrap();
    make_primary(&mut sim, tmp.path().to_path_buf());

    sim.client("client", async {
        let client = Client::new();
        client
            .post("http://primary:9090/v1/namespaces/reset/create", json!({}))
            .await?;

        let db = Database::open_remote_with_connector(
            "http://reset.primary:8080",
            "",
            TurmoilConnector,
        )?;
        let conn = db.connect()?;
        conn.execute("create table t(v text)", ()).await?;
        for i in 0..100 {
            conn.execute(
                &format!("insert into t values ('row-{i}')"),
                (),
            )
            .await?;
        }

        // Before reset: 100 rows.
        let mut rows = conn.query("select count(*) from t", ()).await?;
        assert!(matches!(
            rows.next().await.unwrap().unwrap().get_value(0)?,
            Value::Integer(100)
        ));

        // Reset the replication log on a healthy namespace.
        let resp = client
            .post(
                "http://primary:9090/v1/namespaces/reset/reset-replication",
                json!({}),
            )
            .await?;
        assert_eq!(resp.status(), hyper::http::StatusCode::OK);

        // After reset: still 100 rows (data preserved).
        let db2 = Database::open_remote_with_connector(
            "http://reset.primary:8080",
            "",
            TurmoilConnector,
        )?;
        let conn2 = db2.connect()?;
        let mut rows = conn2.query("select count(*) from t", ()).await?;
        assert!(matches!(
            rows.next().await.unwrap().unwrap().get_value(0)?,
            Value::Integer(100)
        ));

        // And writes still work.
        conn2
            .execute("insert into t values ('post-reset')", ())
            .await?;
        let mut rows = conn2.query("select count(*) from t", ()).await?;
        assert!(matches!(
            rows.next().await.unwrap().unwrap().get_value(0)?,
            Value::Integer(101)
        ));

        // Integrity check confirms the new DB is fine.
        let resp = client
            .post(
                "http://primary:9090/v1/namespaces/reset/integrity-check",
                json!({}),
            )
            .await?;
        let v = resp.json_value().await?;
        assert_eq!(v["ok"], json!(true));

        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn reset_replication_on_nonexistent_namespace_returns_404() {
    let mut sim = Builder::new()
        .simulation_duration(Duration::from_secs(1000))
        .build();
    let tmp = tempdir().unwrap();
    make_primary(&mut sim, tmp.path().to_path_buf());

    sim.client("client", async {
        let client = Client::new();
        let resp = client
            .post(
                "http://primary:9090/v1/namespaces/missing/reset-replication",
                json!({}),
            )
            .await;
        // Server-error path: post_with_headers bails on 5xx, but 404
        // should come through cleanly as an error response.
        match resp {
            Ok(r) => assert_eq!(r.status(), hyper::http::StatusCode::NOT_FOUND),
            Err(e) => panic!("expected 404 response, got error: {e}"),
        }
        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn reset_replication_is_idempotent() {
    // An operator (or the streamer's retry-after-reset path) may call
    // reset-replication multiple times in quick succession. Each call
    // must succeed independently without corrupting the data file.
    let mut sim = Builder::new()
        .simulation_duration(Duration::from_secs(1000))
        .build();
    let tmp = tempdir().unwrap();
    make_primary(&mut sim, tmp.path().to_path_buf());

    sim.client("client", async {
        let client = Client::new();
        client
            .post("http://primary:9090/v1/namespaces/idem/create", json!({}))
            .await?;

        let db = Database::open_remote_with_connector(
            "http://idem.primary:8080",
            "",
            TurmoilConnector,
        )?;
        let conn = db.connect()?;
        conn.execute("create table t(v text)", ()).await?;
        for i in 0..20 {
            conn.execute(&format!("insert into t values ('row-{i}')"), ())
                .await?;
        }

        // Call reset-replication three times in a row. Each must 200.
        for attempt in 0..3 {
            let resp = client
                .post(
                    "http://primary:9090/v1/namespaces/idem/reset-replication",
                    json!({}),
                )
                .await?;
            assert_eq!(
                resp.status(),
                hyper::http::StatusCode::OK,
                "attempt {attempt} should return 200"
            );
        }

        // After three resets, the 20 rows are still there.
        let db2 = Database::open_remote_with_connector(
            "http://idem.primary:8080",
            "",
            TurmoilConnector,
        )?;
        let conn2 = db2.connect()?;
        let mut rows = conn2.query("select count(*) from t", ()).await?;
        assert!(matches!(
            rows.next().await.unwrap().unwrap().get_value(0)?,
            Value::Integer(20)
        ));

        // And integrity-check still passes.
        let resp = client
            .post(
                "http://primary:9090/v1/namespaces/idem/integrity-check",
                json!({}),
            )
            .await?;
        let v = resp.json_value().await?;
        assert_eq!(v["ok"], json!(true));

        Ok(())
    });

    sim.run().unwrap();
}
