use std::time::Duration;

use libsql::{Database, Value};
use serde_json::json;
use tempfile::tempdir;
use turmoil::Builder;

use crate::common::{http::Client, net::TurmoilConnector};

use super::make_primary;

#[test]
fn fork_refuses_unloaded_destination_and_preserves_data_config_and_link() {
    let tmp = tempdir().unwrap();
    {
        let mut sim = Builder::new()
            .simulation_duration(Duration::from_secs(1000))
            .build();
        make_primary(&mut sim, tmp.path().to_path_buf());
        sim.client("client", async {
            let client = Client::new();
            for (name, body) in [
                ("source", json!({})),
                ("schema", json!({"shared_schema": true})),
                ("dest", json!({"shared_schema_name": "schema"})),
            ] {
                assert!(client
                    .post(
                        &format!("http://primary:9090/v1/namespaces/{name}/create"),
                        body
                    )
                    .await?
                    .status()
                    .is_success());
            }
            let source = Database::open_remote_with_connector(
                "http://source.primary:8080",
                "",
                TurmoilConnector,
            )?;
            source
                .connect()?
                .execute("create table source_data (v)", ())
                .await?;
            let schema = Database::open_remote_with_connector(
                "http://schema.primary:8080",
                "",
                TurmoilConnector,
            )?;
            schema
                .connect()?
                .execute("create table dest_data (v)", ())
                .await?;
            let dest = Database::open_remote_with_connector(
                "http://dest.primary:8080",
                "",
                TurmoilConnector,
            )?;
            let conn = dest.connect()?;
            // Schema migrations are asynchronous; wait for the linked tenant
            // to receive the table before persisting its own row.
            let mut inserted = false;
            for _ in 0..100 {
                if conn
                    .execute("insert into dest_data values (17)", ())
                    .await
                    .is_ok()
                {
                    inserted = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            assert!(inserted, "schema migration did not reach destination");
            assert!(client
                .post(
                    "http://primary:9090/v1/namespaces/dest/config",
                    json!({"block_reads": false, "block_writes": true})
                )
                .await?
                .status()
                .is_success());
            Ok(())
        });
        sim.run().unwrap();
    }
    let sentinel = tmp.path().join("dbs/dest/sentinel");
    std::fs::write(&sentinel, b"original destination").unwrap();
    {
        let mut sim = Builder::new()
            .simulation_duration(Duration::from_secs(1000))
            .build();
        make_primary(&mut sim, tmp.path().to_path_buf());
        sim.client("client", async {
            let client = Client::new();
            assert_eq!(
                client
                    .post("http://primary:9090/v1/namespaces/source/fork/dest", ())
                    .await?
                    .status(),
                hyper::StatusCode::BAD_REQUEST
            );
            // The existing destination is still linked to the schema; removing
            // that schema must be refused, not silently unlinked by fork cleanup.
            assert!(!client
                .delete("http://primary:9090/v1/namespaces/schema", json!({}))
                .await?
                .status()
                .is_success());
            let dest = Database::open_remote_with_connector(
                "http://dest.primary:8080",
                "",
                TurmoilConnector,
            )?;
            let conn = dest.connect()?;
            let mut rows = conn.query("select v from dest_data", ()).await?;
            assert!(matches!(
                rows.next().await?.unwrap().get_value(0)?,
                Value::Integer(17)
            ));
            assert!(conn
                .execute("insert into dest_data values (18)", ())
                .await
                .is_err());
            let source = Database::open_remote_with_connector(
                "http://source.primary:8080",
                "",
                TurmoilConnector,
            )?;
            source
                .connect()?
                .execute("select * from source_data", ())
                .await?;
            Ok(())
        });
        sim.run().unwrap();
    }
    assert_eq!(std::fs::read(sentinel).unwrap(), b"original destination");
    let conn = rusqlite::Connection::open(tmp.path().join("metastore/data")).unwrap();
    let links: i64 = conn
        .query_row(
            "SELECT count(*) FROM shared_schema_links WHERE shared_schema_name = 'schema' AND namespace = 'dest'",
            (),
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(links, 1);
}

#[test]
fn new_names_reject_filesystem_aliases_and_orphan_destinations() {
    let tmp = tempdir().unwrap();
    let mut sim = Builder::new()
        .simulation_duration(Duration::from_secs(1000))
        .build();
    make_primary(&mut sim, tmp.path().to_path_buf());
    let dbs = tmp.path().join("dbs");
    let check_dbs = dbs.clone();
    let malformed_dump = tmp.path().join("invalid-dump.sql");
    std::fs::write(
        &malformed_dump,
        "BEGIN TRANSACTION; CREATE TABLE unfinished (v);",
    )
    .unwrap();
    sim.client("client", async move {
        let client = Client::new();
        for name in ["tenant", "source", "unrelated"] {
            assert!(client
                .post(
                    &format!("http://primary:9090/v1/namespaces/{name}/create"),
                    json!({})
                )
                .await?
                .status()
                .is_success());
        }
        // Probe the actual temporary dbs volume after creating tenant.
        // On case-sensitive volumes both names are distinct.
        let case_insensitive = check_dbs.join("TENANT").exists();
        std::fs::write(check_dbs.join("tenant/sentinel"), b"keep tenant")?;
        std::fs::create_dir(check_dbs.join("orphan"))?;
        std::fs::write(check_dbs.join("orphan/sentinel"), b"keep orphan")?;
        let tenant = Database::open_remote_with_connector(
            "http://tenant.primary:8080",
            "",
            TurmoilConnector,
        )?;
        tenant
            .connect()?
            .execute("create table private_data (v)", ())
            .await?;
        let create = client
            .post("http://primary:9090/v1/namespaces/TENANT/create", json!({}))
            .await?;
        if case_insensitive {
            assert_eq!(create.status(), hyper::StatusCode::BAD_REQUEST);
            assert_eq!(
                client
                    .post("http://primary:9090/v1/namespaces/tenant/fork/TENANT", ())
                    .await?
                    .status(),
                hyper::StatusCode::BAD_REQUEST
            );
            assert_eq!(
                client
                    .delete("http://primary:9090/v1/namespaces/TENANT", json!({}))
                    .await?
                    .status(),
                hyper::StatusCode::BAD_REQUEST
            );
        } else {
            assert!(create.status().is_success());
            assert!(client
                .post("http://primary:9090/v1/namespaces/source/fork/SOURCE", ())
                .await?
                .status()
                .is_success());
        }
        assert_eq!(
            client
                .post("http://primary:9090/v1/namespaces/source/fork/orphan", ())
                .await?
                .status(),
            hyper::StatusCode::BAD_REQUEST
        );
        assert_eq!(
            client
                .post("http://primary:9090/v1/namespaces/orphan/create", json!({}))
                .await?
                .status(),
            hyper::StatusCode::BAD_REQUEST
        );
        assert_eq!(
            client
                .delete("http://primary:9090/v1/namespaces/orphan", json!({}))
                .await?
                .status(),
            hyper::StatusCode::NOT_FOUND
        );
        assert_eq!(
            client
                .post("http://primary:9090/v1/namespaces/source/fork/source", ())
                .await?
                .status(),
            hyper::StatusCode::BAD_REQUEST
        );
        // An error after reservation must release only the new directory and
        // metadata, so a later create can actually initialize the namespace.
        // The common Client::post converts 5xx into an error before callers
        // can inspect the response; use raw Hyper to assert this exact path.
        let raw = hyper::Client::builder().build::<_, hyper::Body>(TurmoilConnector);
        let request =
            hyper::Request::post("http://primary:9090/v1/namespaces/source/fork/failed-fork")
                .header("content-type", "application/json")
                .body(hyper::Body::from(serde_json::to_vec(
                    &json!({"timestamp": "2024-01-01T00:00:00"}),
                )?))?;
        let response = raw.request(request).await?;
        assert_eq!(response.status(), hyper::StatusCode::INTERNAL_SERVER_ERROR);
        let error_body = hyper::body::to_bytes(response.into_body()).await?;
        assert!(String::from_utf8_lossy(&error_body).contains("backup service not configured"));
        assert!(!check_dbs.join("failed-fork").exists());
        assert!(client
            .post(
                "http://primary:9090/v1/namespaces/failed-fork/create",
                json!({})
            )
            .await?
            .status()
            .is_success());
        assert_eq!(
            client
                .post(
                    "http://primary:9090/v1/namespaces/failed-create/create",
                    json!({"dump_url": format!("file:{}", malformed_dump.display())}),
                )
                .await?
                .status(),
            hyper::StatusCode::BAD_REQUEST
        );
        assert!(!check_dbs.join("failed-create").exists());
        assert!(client
            .post(
                "http://primary:9090/v1/namespaces/failed-create/create",
                json!({}),
            )
            .await?
            .status()
            .is_success());
        let failed = Database::open_remote_with_connector(
            "http://failed-fork.primary:8080",
            "",
            TurmoilConnector,
        )?;
        failed.connect()?.execute("select 1", ()).await?;
        let retried = Database::open_remote_with_connector(
            "http://failed-create.primary:8080",
            "",
            TurmoilConnector,
        )?;
        retried.connect()?.execute("select 1", ()).await?;
        let mut rows = tenant
            .connect()?
            .query("select count(*) from private_data", ())
            .await?;
        assert!(matches!(
            rows.next().await?.unwrap().get_value(0)?,
            Value::Integer(0)
        ));
        Ok(())
    });
    sim.run().unwrap();
    assert_eq!(
        std::fs::read(dbs.join("tenant/sentinel")).unwrap(),
        b"keep tenant"
    );
    assert_eq!(
        std::fs::read(dbs.join("orphan/sentinel")).unwrap(),
        b"keep orphan"
    );
    assert!(dbs.join("unrelated").exists());
}

#[test]
fn legacy_alias_row_cannot_open_or_delete_other_namespace() {
    let tmp = tempdir().unwrap();
    {
        let mut sim = Builder::new()
            .simulation_duration(Duration::from_secs(1000))
            .build();
        make_primary(&mut sim, tmp.path().to_path_buf());
        sim.client("client", async {
            let client = Client::new();
            assert!(client
                .post("http://primary:9090/v1/namespaces/tenant/create", json!({}))
                .await?
                .status()
                .is_success());
            let tenant = Database::open_remote_with_connector(
                "http://tenant.primary:8080",
                "",
                TurmoilConnector,
            )?;
            tenant
                .connect()?
                .execute("create table private_data (v)", ())
                .await?;
            Ok(())
        });
        sim.run().unwrap();
    }
    let dbs = tmp.path().join("dbs");
    if !dbs.join("TENANT").exists() {
        // A case-sensitive volume has no alias to test here.
        return;
    }
    let sentinel = dbs.join("tenant/sentinel");
    std::fs::write(&sentinel, b"keep tenant").unwrap();
    // Reproduce a pre-upgrade metastore containing both keys. The second key
    // must never be used to open or remove the first key's physical directory.
    let conn = rusqlite::Connection::open(tmp.path().join("metastore/data")).unwrap();
    conn.execute(
        "INSERT INTO namespace_configs (namespace, config) SELECT 'TENANT', config FROM namespace_configs WHERE namespace = 'tenant'",
        (),
    ).unwrap();
    drop(conn);
    let mut sim = Builder::new()
        .simulation_duration(Duration::from_secs(1000))
        .build();
    make_primary(&mut sim, tmp.path().to_path_buf());
    sim.client("client", async {
        let client = Client::new();
        assert_eq!(
            client
                .delete("http://primary:9090/v1/namespaces/TENANT", json!({}))
                .await?
                .status(),
            hyper::StatusCode::BAD_REQUEST
        );
        assert_eq!(
            client
                .post(
                    "http://primary:9090/v1/namespaces/TENANT/config",
                    json!({"block_reads": false, "block_writes": false}),
                )
                .await?
                .status(),
            hyper::StatusCode::BAD_REQUEST
        );
        let tenant = Database::open_remote_with_connector(
            "http://tenant.primary:8080",
            "",
            TurmoilConnector,
        )?;
        tenant
            .connect()?
            .execute("select * from private_data", ())
            .await?;
        Ok(())
    });
    sim.run().unwrap();
    assert_eq!(std::fs::read(sentinel).unwrap(), b"keep tenant");
}
