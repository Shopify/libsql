use std::path::Path;
use std::time::Duration;

use hyper::StatusCode;
use libsql::{Database, Value};
use libsql_replication::rpc::metadata;
use prost::Message;
use serde_json::json;
use tempfile::tempdir;
use turmoil::Builder;

use crate::common::auth::{encode, key_pair};
use crate::common::http::Client;
use crate::common::net::TurmoilConnector;

use super::make_primary_configured;

const DUMP: &str = "PRAGMA foreign_keys=OFF; BEGIN TRANSACTION; CREATE TABLE dumped (v); INSERT INTO dumped VALUES(42); COMMIT;";

fn persisted_default(path: &Path) -> metadata::DatabaseConfig {
    let conn = rusqlite::Connection::open(path.join("metastore/data")).unwrap();
    let bytes: Vec<u8> = conn
        .query_row(
            "SELECT config FROM namespace_configs WHERE namespace = 'default'",
            (),
            |row| row.get(0),
        )
        .unwrap();
    metadata::DatabaseConfig::decode(&bytes[..]).unwrap()
}

#[test]
fn explicit_default_create_rejects_duplicate_after_lazy_access() {
    let tmp = tempdir().unwrap();
    std::fs::write(tmp.path().join("dump.sql"), DUMP).unwrap();
    let dump_url = format!("file:{}", tmp.path().join("dump.sql").display());
    let mut sim = Builder::new()
        .simulation_duration(Duration::from_secs(1000))
        .build();
    make_primary_configured(&mut sim, tmp.path().to_path_buf(), false, false);
    sim.client("client", async move {
        let client = Client::new();
        let db = Database::open_remote_with_connector(
            "http://default.primary:8080",
            "",
            TurmoilConnector,
        )?;
        let conn = db.connect()?;
        conn.execute("create table original (v)", ()).await?;
        conn.execute("insert into original values (17)", ()).await?;

        let (_, jwt_key) = key_pair();
        let response = client
            .post(
                "http://primary:9090/v1/namespaces/default/create",
                json!({"jwt_key": jwt_key, "dump_url": dump_url, "allow_attach": true}),
            )
            .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let mut rows = conn.query("select v from original", ()).await?;
        assert!(matches!(
            rows.next().await?.unwrap().get_value(0)?,
            Value::Integer(17)
        ));
        assert!(conn.query("select * from dumped", ()).await.is_err());
        Ok(())
    });
    sim.run().unwrap();
    let config = persisted_default(tmp.path());
    assert_eq!(config.jwt_key, None);
    assert!(!config.allow_attach);
}

#[test]
fn explicit_first_default_create_applies_valid_jwt_and_dump() {
    let tmp = tempdir().unwrap();
    std::fs::write(tmp.path().join("dump.sql"), DUMP).unwrap();
    let dump_url = format!("file:{}", tmp.path().join("dump.sql").display());
    let mut sim = Builder::new()
        .simulation_duration(Duration::from_secs(1000))
        .build();
    make_primary_configured(&mut sim, tmp.path().to_path_buf(), false, false);
    sim.client("client", async move {
        let client = Client::new();
        let (enc, jwt_key) = key_pair();
        assert_eq!(
            client
                .post(
                    "http://primary:9090/v1/namespaces/default/create",
                    json!({"jwt_key": jwt_key, "dump_url": dump_url, "allow_attach": true}),
                )
                .await?
                .status(),
            StatusCode::OK
        );
        let token = encode(&json!({"id": "default"}), &enc);
        let db = Database::open_remote_with_connector(
            "http://default.primary:8080",
            &token,
            TurmoilConnector,
        )?;
        let mut rows = db.connect()?.query("select v from dumped", ()).await?;
        assert!(matches!(
            rows.next().await?.unwrap().get_value(0)?,
            Value::Integer(42)
        ));
        Ok(())
    });
    sim.run().unwrap();
    let config = persisted_default(tmp.path());
    assert!(config.jwt_key.is_some());
    assert!(config.allow_attach);
}

#[test]
fn namespace_disabled_restart_preserves_persisted_default_config() {
    let tmp = tempdir().unwrap();
    {
        let mut sim = Builder::new()
            .simulation_duration(Duration::from_secs(1000))
            .build();
        make_primary_configured(&mut sim, tmp.path().to_path_buf(), true, false);
        sim.client("client", async {
            let client = Client::new();
            let db =
                Database::open_remote_with_connector("http://primary:8080", "", TurmoilConnector)?;
            db.connect()?
                .execute("create table original (v)", ())
                .await?;
            assert_eq!(
                client
                    .post(
                        "http://primary:9090/v1/namespaces/default/config",
                        json!({"block_reads": false, "block_writes": false, "allow_attach": true}),
                    )
                    .await?
                    .status(),
                StatusCode::OK
            );
            Ok(())
        });
        sim.run().unwrap();
    }
    assert!(persisted_default(tmp.path()).allow_attach);
    {
        let mut sim = Builder::new()
            .simulation_duration(Duration::from_secs(1000))
            .build();
        make_primary_configured(&mut sim, tmp.path().to_path_buf(), true, false);
        sim.client("client", async {
            let db =
                Database::open_remote_with_connector("http://primary:8080", "", TurmoilConnector)?;
            db.connect()?.execute("select * from original", ()).await?;
            Ok(())
        });
        sim.run().unwrap();
    }
    assert!(persisted_default(tmp.path()).allow_attach);
}

#[test]
fn simultaneous_lazy_default_accesses_both_succeed() {
    let tmp = tempdir().unwrap();
    let mut sim = Builder::new()
        .simulation_duration(Duration::from_secs(1000))
        .build();
    make_primary_configured(&mut sim, tmp.path().to_path_buf(), false, false);
    sim.client("client", async {
        let request = || async {
            let db = Database::open_remote_with_connector(
                "http://default.primary:8080",
                "",
                TurmoilConnector,
            )?;
            db.connect()?.execute("select 1", ()).await?;
            Ok::<_, anyhow::Error>(())
        };
        let (first, second) = tokio::join!(request(), request());
        first?;
        second?;
        Ok(())
    });
    sim.run().unwrap();
    let conn = rusqlite::Connection::open(tmp.path().join("metastore/data")).unwrap();
    let count: i64 = conn
        .query_row(
            "SELECT count(*) FROM namespace_configs WHERE namespace = 'default'",
            (),
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
    assert!(tmp.path().join("dbs/default/data").exists());
}
