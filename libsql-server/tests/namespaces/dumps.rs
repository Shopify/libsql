use std::convert::Infallible;
use std::path::Path;
use std::time::Duration;

use bytes::Bytes;
use futures::StreamExt;
use hyper::{service::make_service_fn, Body, Response as HyperResponse, StatusCode};
use insta::{assert_json_snapshot, assert_snapshot};
use libsql::Database;
use libsql_server::config::{DbConfig, DumpImportConfig, DumpImporterKind};
use serde_json::json;
use tempfile::tempdir;
use tower::service_fn;
use turmoil::{Builder, Sim};

use crate::common::http::{Client, Response};
use crate::common::net::{TurmoilAcceptor, TurmoilConnector};
use crate::namespaces::{make_primary, make_primary_with_db_config};

pub(super) const BUFFERED: Option<&str> = Some("buffered");
pub(super) const STREAMING: Option<&str> = Some("streaming");

/// `POST /v1/namespaces/:ns/create` with `dump_url` and, optionally, `dump_importer`.
pub(super) async fn create_from_dump(
    client: &Client,
    ns: &str,
    dump_url: &str,
    importer: Option<&str>,
) -> anyhow::Result<Response> {
    let mut body = json!({ "dump_url": dump_url });
    if let Some(importer) = importer {
        body["dump_importer"] = json!(importer);
    }
    client
        .post_raw(
            &format!("http://primary:9090/v1/namespaces/{ns}/create"),
            body,
        )
        .await
}

pub(super) fn file_url(path: &Path) -> String {
    format!("file:{}", path.display())
}

pub(super) fn sim() -> Sim<'static> {
    Builder::new()
        .simulation_duration(Duration::from_secs(1000))
        .build()
}

pub(super) async fn count_rows(ns: &str, table: &str) -> anyhow::Result<i64> {
    let db = Database::open_remote_with_connector(
        &format!("http://{ns}.primary:8080"),
        "",
        TurmoilConnector,
    )?;
    let conn = db.connect()?;
    let mut rows = conn
        .query(&format!("select count(*) from {table}"), ())
        .await?;
    Ok(rows.next().await?.unwrap().get::<i64>(0)?)
}

/// Serve `chunks` as one HTTP response body on `dump-store:8080`, each chunk as its own body
/// frame. A trailing `Err` chunk aborts the body mid-way.
fn make_dump_store(sim: &mut Sim, chunks: Vec<Result<Bytes, std::io::Error>>) {
    make_dump_store_paced(sim, chunks, Duration::from_millis(1))
}

/// Like [`make_dump_store`], pausing `pause` (simulated time) before each chunk.
pub(super) fn make_dump_store_paced(
    sim: &mut Sim,
    chunks: Vec<Result<Bytes, std::io::Error>>,
    pause: Duration,
) {
    // turmoil may call the host closure more than once; the chunks are cloned per call.
    let chunks: Vec<Result<Bytes, (std::io::ErrorKind, String)>> = chunks
        .into_iter()
        .map(|c| c.map_err(|e| (e.kind(), e.to_string())))
        .collect();
    sim.host("dump-store", move || {
        let chunks = chunks.clone();
        async move {
            let incoming = TurmoilAcceptor::bind(([0, 0, 0, 0], 8080)).await?;
            let server =
                hyper::server::Server::builder(incoming).serve(make_service_fn(move |_conn| {
                    let chunks = chunks.clone();
                    async move {
                        Ok::<_, Infallible>(service_fn(move |_req| {
                            let chunks = chunks.clone();
                            async move {
                                // Yield between chunks so hyper flushes each one before the
                                // next (or an error) is produced.
                                let stream =
                                    futures::stream::iter(chunks).then(move |c| async move {
                                        tokio::time::sleep(pause).await;
                                        c.map_err(|(kind, msg)| std::io::Error::new(kind, msg))
                                    });
                                Ok::<_, Infallible>(HyperResponse::new(Body::wrap_stream(stream)))
                            }
                        }))
                    }
                }));

            server.await.unwrap();

            Ok(())
        }
    });
}

fn make_dump_store_whole(sim: &mut Sim, dump: &'static str) {
    make_dump_store(sim, vec![Ok(Bytes::from_static(dump.as_bytes()))]);
}

fn make_dump_store_chunked(sim: &mut Sim, dump: &'static str, chunk_size: usize) {
    make_dump_store(
        sim,
        dump.as_bytes()
            .chunks(chunk_size)
            .map(|c| Ok(Bytes::copy_from_slice(c)))
            .collect(),
    );
}

/// Serve `dump` from `dump-store:8080` in 64-byte chunks, 100ms (simulated) apart: with
/// turmoil's up-to-100ms message latency this keeps a creation in flight for a couple of
/// seconds, long enough for other requests to be issued while it runs.
pub(super) fn make_slow_dump_store(sim: &mut Sim, dump: &'static str) {
    make_dump_store_paced(
        sim,
        dump.as_bytes()
            .chunks(64)
            .map(|c| Ok(Bytes::copy_from_slice(c)))
            .collect(),
        Duration::from_millis(100),
    );
}

/// Ten rows, importable by both importers (no "attach" anywhere), ~1.1 KB so that
/// [`make_slow_dump_store`] delivers it in ~18 chunks.
pub(super) const SLOW_DUMP: &str = r#"PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT, note TEXT);
INSERT INTO test VALUES (1, 'one', 'the first row of a dump that takes a while to arrive');
INSERT INTO test VALUES (2, 'two', 'the second row of a dump that takes a while to arrive');
INSERT INTO test VALUES (3, 'three', 'the third row of a dump that takes a while to arrive');
INSERT INTO test VALUES (4, 'four', 'the fourth row of a dump that takes a while to arrive');
INSERT INTO test VALUES (5, 'five', 'the fifth row of a dump that takes a while to arrive');
INSERT INTO test VALUES (6, 'six', 'the sixth row of a dump that takes a while to arrive');
INSERT INTO test VALUES (7, 'seven', 'the seventh row of a dump that takes a while to arrive');
INSERT INTO test VALUES (8, 'eight', 'the eighth row of a dump that takes a while to arrive');
INSERT INTO test VALUES (9, 'nine', 'the ninth row of a dump that takes a while to arrive');
INSERT INTO test VALUES (10, 'ten', 'the tenth row of a dump that takes a while to arrive');
COMMIT;
"#;

pub(super) const SIMPLE_DUMP: &str = r#"
        PRAGMA foreign_keys=OFF;
    BEGIN TRANSACTION;
    CREATE TABLE test (x);
    INSERT INTO test VALUES(42);
    COMMIT;"#;

fn load_namespace_from_dump_from_url_with(importer: Option<&'static str>) {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    make_primary(&mut sim, tmp.path().to_path_buf());
    make_dump_store_whole(&mut sim, SIMPLE_DUMP);

    sim.client("client", async move {
        let client = Client::new();
        let resp = create_from_dump(&client, "foo", "http://dump-store:8080/", importer)
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_snapshot!(
            "load_namespace_from_dump_from_url",
            resp.body_string().await.unwrap()
        );

        assert_eq!(count_rows("foo", "test").await?, 1);

        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn load_namespace_from_dump_from_url() {
    load_namespace_from_dump_from_url_with(None);
}

#[test]
fn load_namespace_from_dump_from_url_streaming() {
    load_namespace_from_dump_from_url_with(STREAMING);
}

fn load_namespace_from_dump_from_file_with(importer: Option<&'static str>) {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    let tmp_path = tmp.path().to_path_buf();

    std::fs::write(tmp_path.join("dump.sql"), SIMPLE_DUMP).unwrap();

    make_primary(&mut sim, tmp.path().to_path_buf());

    sim.client("client", async move {
        let client = Client::new();

        // path is not absolute is an error
        let resp = create_from_dump(&client, "foo", "file:dump.sql", importer)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // path doesn't exist is an error
        let resp = create_from_dump(&client, "foo", "file:/dump.sql", importer)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp = create_from_dump(
            &client,
            "foo",
            &file_url(&tmp_path.join("dump.sql")),
            importer,
        )
        .await
        .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "{}",
            resp.json::<serde_json::Value>().await.unwrap_or_default()
        );

        assert_eq!(count_rows("foo", "test").await?, 1);

        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn load_namespace_from_dump_from_file() {
    load_namespace_from_dump_from_file_with(None);
}

#[test]
fn load_namespace_from_dump_from_file_streaming() {
    load_namespace_from_dump_from_file_with(STREAMING);
}

fn load_namespace_from_no_commit_with(importer: Option<&'static str>) {
    const DUMP: &str = r#"
    PRAGMA foreign_keys=OFF;
    BEGIN TRANSACTION;
    CREATE TABLE test (x);
    INSERT INTO test VALUES(42);
    "#;

    let mut sim = sim();
    let tmp = tempdir().unwrap();
    let tmp_path = tmp.path().to_path_buf();

    std::fs::write(tmp_path.join("dump.sql"), DUMP).unwrap();

    make_primary(&mut sim, tmp.path().to_path_buf());

    sim.client("client", async move {
        let client = Client::new();
        let resp = create_from_dump(
            &client,
            "foo",
            &file_url(&tmp_path.join("dump.sql")),
            importer,
        )
        .await
        .unwrap();
        // the dump is malformed
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "{}",
            resp.json::<serde_json::Value>().await.unwrap_or_default()
        );

        // namespace doesn't exist
        assert!(count_rows("foo", "test").await.is_err());

        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn load_namespace_from_no_commit() {
    load_namespace_from_no_commit_with(None);
}

#[test]
fn load_namespace_from_no_commit_streaming() {
    load_namespace_from_no_commit_with(STREAMING);
}

fn load_namespace_from_no_txn_with(importer: Option<&'static str>) {
    const DUMP: &str = r#"
    PRAGMA foreign_keys=OFF;
    CREATE TABLE test (x);
    INSERT INTO test VALUES(42);
    COMMIT;
    "#;

    let mut sim = sim();
    let tmp = tempdir().unwrap();
    let tmp_path = tmp.path().to_path_buf();

    std::fs::write(tmp_path.join("dump.sql"), DUMP).unwrap();

    make_primary(&mut sim, tmp.path().to_path_buf());

    sim.client("client", async move {
        let client = Client::new();
        let resp = create_from_dump(
            &client,
            "foo",
            &file_url(&tmp_path.join("dump.sql")),
            importer,
        )
        .await?;
        // the dump is malformed
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "{}",
            resp.json::<serde_json::Value>().await.unwrap_or_default()
        );
        assert_json_snapshot!(
            "load_namespace_from_no_txn",
            resp.json_value().await.unwrap()
        );

        // namespace doesn't exist
        assert!(count_rows("foo", "test").await.is_err());

        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn load_namespace_from_no_txn() {
    load_namespace_from_no_txn_with(None);
}

#[test]
fn load_namespace_from_no_txn_streaming() {
    load_namespace_from_no_txn_with(STREAMING);
}

#[test]
fn export_dump() {
    let mut sim = sim();
    let tmp = tempdir().unwrap();

    make_primary(&mut sim, tmp.path().to_path_buf());

    sim.client("client", async move {
        let client = Client::new();
        let resp = client
            .post("http://primary:9090/v1/namespaces/foo/create", json!({}))
            .await?;
        assert_eq!(resp.status(), StatusCode::OK);

        let foo =
            Database::open_remote_with_connector("http://foo.primary:8080", "", TurmoilConnector)?;
        let foo_conn = foo.connect()?;
        foo_conn.execute("create table test (x)", ()).await?;
        foo_conn.execute("insert into test values (42)", ()).await?;
        foo_conn
            .execute("insert into test values ('foo')", ())
            .await?;
        foo_conn
            .execute("insert into test values ('bar')", ())
            .await?;

        let resp = client.get("http://foo.primary:8080/dump").await?;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_snapshot!(resp.body_string().await?);

        Ok(())
    });

    sim.run().unwrap();
}

/// Rejects a dump on a (malformed) ATTACH. The buffered importer rejects on a substring
/// match before parsing; the streaming importer parses statement by statement, so the same
/// input is a syntax error there (see `load_dump_with_attach_statement_rejected_streaming`).
#[test]
fn load_dump_with_attach_rejected() {
    const DUMP: &str = r#"
        PRAGMA foreign_keys=OFF;
    BEGIN TRANSACTION;
    CREATE TABLE test (x);
    INSERT INTO test VALUES(42);
    ATTACH foo/bar.sql
    COMMIT;"#;

    let mut sim = sim();
    let tmp = tempdir().unwrap();
    let tmp_path = tmp.path().to_path_buf();

    std::fs::write(tmp_path.join("dump.sql"), DUMP).unwrap();

    make_primary(&mut sim, tmp.path().to_path_buf());

    sim.client("client", async move {
        let client = Client::new();

        // path is not absolute is an error
        let resp = create_from_dump(&client, "foo", "file:dump.sql", None)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // path doesn't exist is an error
        let resp = create_from_dump(&client, "foo", "file:/dump.sql", None)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp = create_from_dump(&client, "foo", &file_url(&tmp_path.join("dump.sql")), None)
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "{}",
            resp.json::<serde_json::Value>().await.unwrap_or_default()
        );

        assert_snapshot!(resp.body_string().await?);

        // This should error since the dump should have failed!
        assert!(count_rows("foo", "test").await.is_err());

        Ok(())
    });

    sim.run().unwrap();
}

/// A well-formed ATTACH statement is rejected by both importers with the same message.
fn load_dump_with_attach_statement_rejected_with(importer: Option<&'static str>) {
    const DUMP: &str = r#"
    PRAGMA foreign_keys=OFF;
    BEGIN TRANSACTION;
    CREATE TABLE test (x);
    ATTACH 'other.db' AS other;
    INSERT INTO test VALUES(42);
    COMMIT;"#;

    let mut sim = sim();
    let tmp = tempdir().unwrap();
    let tmp_path = tmp.path().to_path_buf();

    std::fs::write(tmp_path.join("dump.sql"), DUMP).unwrap();

    make_primary(&mut sim, tmp.path().to_path_buf());

    sim.client("client", async move {
        let client = Client::new();
        let resp = create_from_dump(
            &client,
            "foo",
            &file_url(&tmp_path.join("dump.sql")),
            importer,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_snapshot!("load_dump_with_attach_rejected", resp.body_string().await?);
        assert!(count_rows("foo", "test").await.is_err());

        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn load_dump_with_attach_statement_rejected() {
    load_dump_with_attach_statement_rejected_with(BUFFERED);
}

#[test]
fn load_dump_with_attach_statement_rejected_streaming() {
    load_dump_with_attach_statement_rejected_with(STREAMING);
}

fn load_dump_with_invalid_sql_with(importer: Option<&'static str>) {
    const DUMP: &str = r#"
        PRAGMA foreign_keys=OFF;
    BEGIN TRANSACTION;
    CREATE TABLE test (x);
    INSERT INTO test VALUES(42);
    SELECT abs(-9223372036854775808) 
    COMMIT;"#;

    let mut sim = sim();
    let tmp = tempdir().unwrap();
    let tmp_path = tmp.path().to_path_buf();

    std::fs::write(tmp_path.join("dump.sql"), DUMP).unwrap();

    make_primary(&mut sim, tmp.path().to_path_buf());

    sim.client("client", async move {
        let client = Client::new();

        // path is not absolute is an error
        let resp = create_from_dump(&client, "foo", "file:dump.sql", importer)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // path doesn't exist is an error
        let resp = create_from_dump(&client, "foo", "file:/dump.sql", importer)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp = create_from_dump(
            &client,
            "foo",
            &file_url(&tmp_path.join("dump.sql")),
            importer,
        )
        .await
        .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "{}",
            resp.json::<serde_json::Value>().await.unwrap_or_default()
        );

        // Both importers report the position in the whole dump (line 7, column 11).
        assert_snapshot!("load_dump_with_invalid_sql", resp.body_string().await?);

        // This should error since the dump should have failed!
        assert!(count_rows("foo", "test").await.is_err());

        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn load_dump_with_invalid_sql() {
    load_dump_with_invalid_sql_with(None);
}

#[test]
fn load_dump_with_invalid_sql_streaming() {
    load_dump_with_invalid_sql_with(STREAMING);
}

fn load_dump_with_trigger_with(importer: Option<&'static str>) {
    const DUMP: &str = r#"
    BEGIN TRANSACTION;
    CREATE TABLE test (x);
    CREATE TRIGGER simple_trigger 
    AFTER INSERT ON test 
    BEGIN
        INSERT INTO test VALUES (999);
    END;
    INSERT INTO test VALUES (1);
    COMMIT;"#;

    let mut sim = sim();
    let tmp = tempdir().unwrap();
    let tmp_path = tmp.path().to_path_buf();

    std::fs::write(tmp_path.join("dump.sql"), DUMP).unwrap();

    make_primary(&mut sim, tmp.path().to_path_buf());

    sim.client("client", async move {
        let client = Client::new();

        let resp = create_from_dump(
            &client,
            "debug_test",
            &file_url(&tmp_path.join("dump.sql")),
            importer,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Original INSERT: 1, Trigger INSERT: 999 = 2 total rows
        assert_eq!(count_rows("debug_test", "test").await?, 2);

        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn load_dump_with_trigger() {
    load_dump_with_trigger_with(None);
}

#[test]
fn load_dump_with_trigger_streaming() {
    load_dump_with_trigger_with(STREAMING);
}

fn load_dump_with_case_trigger_with(importer: Option<&'static str>) {
    const DUMP: &str = r#"
    BEGIN TRANSACTION;
    CREATE TABLE test (id INTEGER, rate REAL DEFAULT 0.0);
    CREATE TRIGGER case_trigger 
    AFTER INSERT ON test 
    BEGIN 
        UPDATE test 
        SET rate = 
            CASE 
                WHEN NEW.id = 1 
                    THEN 0.1 
                ELSE 0.0 
            END 
        WHERE id = NEW.id; 
    END;

    INSERT INTO test (id) VALUES (1);
    COMMIT;"#;

    let mut sim = sim();
    let tmp = tempdir().unwrap();
    let tmp_path = tmp.path().to_path_buf();

    std::fs::write(tmp_path.join("dump.sql"), DUMP).unwrap();

    make_primary(&mut sim, tmp.path().to_path_buf());

    sim.client("client", async move {
        let client = Client::new();

        let resp = create_from_dump(
            &client,
            "case_test",
            &file_url(&tmp_path.join("dump.sql")),
            importer,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let db = Database::open_remote_with_connector(
            "http://case_test.primary:8080",
            "",
            TurmoilConnector,
        )?;
        let conn = db.connect()?;

        let mut rows = conn.query("SELECT id, rate FROM test", ()).await?;
        let row = rows.next().await?.unwrap();
        assert_eq!(row.get::<i64>(0)?, 1);
        assert!((row.get::<f64>(1)? - 0.1).abs() < 0.001);

        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn load_dump_with_case_trigger() {
    load_dump_with_case_trigger_with(None);
}

#[test]
fn load_dump_with_case_trigger_streaming() {
    load_dump_with_case_trigger_with(STREAMING);
}

fn load_dump_with_nested_case_with(importer: Option<&'static str>) {
    const DUMP: &str = r#"
    BEGIN TRANSACTION;
    CREATE TABLE orders (id INTEGER, amount REAL, status TEXT);
    CREATE TRIGGER nested_trigger 
    AFTER UPDATE ON orders 
    BEGIN 
        UPDATE orders 
        SET amount = 
            CASE 
                WHEN NEW.status = 'completed' 
                    THEN 
                        CASE
                            WHEN OLD.id = 1
                                THEN OLD.amount * 0.9
                            ELSE OLD.amount * 0.8
                        END
                ELSE OLD.amount 
            END 
        WHERE id = NEW.id; 
    END;
    
    INSERT INTO orders (id, amount, status) VALUES (1, 100.0, 'pending');
    COMMIT;"#;

    let mut sim = sim();
    let tmp = tempdir().unwrap();
    let tmp_path = tmp.path().to_path_buf();

    std::fs::write(tmp_path.join("dump.sql"), DUMP).unwrap();

    make_primary(&mut sim, tmp.path().to_path_buf());

    sim.client("client", async move {
        let client = Client::new();

        let resp = create_from_dump(
            &client,
            "nested_test",
            &file_url(&tmp_path.join("dump.sql")),
            importer,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let db = Database::open_remote_with_connector(
            "http://nested_test.primary:8080",
            "",
            TurmoilConnector,
        )?;
        let conn = db.connect()?;

        conn.execute("UPDATE orders SET status = 'completed' WHERE id = 1", ())
            .await?;
        let mut rows = conn
            .query("SELECT amount FROM orders WHERE id = 1", ())
            .await?;
        let row = rows.next().await?.unwrap();
        assert!((row.get::<f64>(0)? - 90.0).abs() < 0.001);

        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn load_dump_with_nested_case() {
    load_dump_with_nested_case_with(None);
}

#[test]
fn load_dump_with_nested_case_streaming() {
    load_dump_with_nested_case_with(STREAMING);
}

// ---------------------------------------------------------------------------------------------
// Streaming-specific behavior
// ---------------------------------------------------------------------------------------------

/// Exercises framing across arbitrary HTTP body chunk boundaries, including inside multibyte
/// characters, string literals with semicolons, comments and a trigger body.
pub(super) const CHUNKY_DUMP: &str = r#"PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
-- a comment; with a semicolon
CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT);
CREATE TABLE audit (id INTEGER, note TEXT);
CREATE TRIGGER tr AFTER INSERT ON test BEGIN
  INSERT INTO audit VALUES (NEW.id, 'inserted; ' || NEW.name);
END;
INSERT INTO test VALUES (1, 'żółć; 🎉');
INSERT INTO test VALUES (2, 'say "hi"; bye');
/* block
   comment; */
INSERT INTO test VALUES (3, 'attachment');
;
COMMIT"#;

fn streaming_chunked_http_delivery_with(chunk_size: usize) {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    make_primary(&mut sim, tmp.path().to_path_buf());
    make_dump_store_chunked(&mut sim, CHUNKY_DUMP, chunk_size);

    sim.client("client", async move {
        let client = Client::new();
        let resp = create_from_dump(&client, "foo", "http://dump-store:8080/", STREAMING).await?;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "{}",
            resp.body_string().await.unwrap_or_default()
        );

        assert_eq!(count_rows("foo", "test").await?, 3);
        assert_eq!(count_rows("foo", "audit").await?, 3);

        let db =
            Database::open_remote_with_connector("http://foo.primary:8080", "", TurmoilConnector)?;
        let conn = db.connect()?;
        let mut rows = conn.query("SELECT name FROM test WHERE id = 1", ()).await?;
        assert_eq!(rows.next().await?.unwrap().get::<String>(0)?, "żółć; 🎉");
        let mut rows = conn
            .query("SELECT note FROM audit WHERE id = 3", ())
            .await?;
        assert_eq!(
            rows.next().await?.unwrap().get::<String>(0)?,
            "inserted; attachment"
        );

        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn streaming_chunked_http_delivery_1_byte() {
    streaming_chunked_http_delivery_with(1);
}

#[test]
fn streaming_chunked_http_delivery_7_bytes() {
    streaming_chunked_http_delivery_with(7);
}

#[test]
fn streaming_chunked_http_delivery_whole() {
    streaming_chunked_http_delivery_with(CHUNKY_DUMP.len());
}

/// The same dump works with the buffered importer, except that the word "attachment" in the
/// data trips its substring check.
#[test]
fn buffered_rejects_word_attach_in_data() {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    make_primary(&mut sim, tmp.path().to_path_buf());
    make_dump_store_whole(&mut sim, CHUNKY_DUMP);

    sim.client("client", async move {
        let client = Client::new();
        let resp = create_from_dump(&client, "foo", "http://dump-store:8080/", BUFFERED).await?;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_snapshot!("load_dump_with_attach_rejected", resp.body_string().await?);
        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn streaming_truncated_http_body_rolls_back() {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    make_primary(&mut sim, tmp.path().to_path_buf());

    let cut = CHUNKY_DUMP.find("INSERT INTO test VALUES (2").unwrap();
    make_dump_store(
        &mut sim,
        vec![
            Ok(Bytes::copy_from_slice(&CHUNKY_DUMP.as_bytes()[..cut])),
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "dump store went away",
            )),
        ],
    );

    sim.client("client", async move {
        let client = Client::new();
        let resp = create_from_dump(&client, "foo", "http://dump-store:8080/", STREAMING).await?;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = resp.body_string().await?;
        assert!(
            body.contains("Failed to read dump content"),
            "unexpected body: {body}"
        );

        // nothing was committed
        assert!(count_rows("foo", "test").await.is_err());

        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn streaming_statement_too_large() {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    let tmp_path = tmp.path().to_path_buf();

    let big_value = "x".repeat(DumpImportConfig::MIN_MAX_STATEMENT_BYTES);
    let dump = format!(
        "BEGIN TRANSACTION;\nCREATE TABLE test (x);\nINSERT INTO test VALUES ('{big_value}');\nCOMMIT;\n"
    );
    std::fs::write(tmp_path.join("dump.sql"), dump).unwrap();

    make_primary_with_db_config(
        &mut sim,
        tmp.path().to_path_buf(),
        DbConfig {
            dump_import: DumpImportConfig {
                max_statement_bytes: DumpImportConfig::MIN_MAX_STATEMENT_BYTES,
                ..Default::default()
            },
            ..Default::default()
        },
    );

    sim.client("client", async move {
        let client = Client::new();
        let resp = create_from_dump(
            &client,
            "foo",
            &file_url(&tmp_path.join("dump.sql")),
            STREAMING,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let body = resp.body_string().await?;
        assert!(
            body.contains("starting at line 3, column 1 exceeds the maximum allowed size"),
            "unexpected body: {body}"
        );
        assert!(count_rows("foo", "test").await.is_err());

        // the buffered importer has no such limit
        let resp = create_from_dump(
            &client,
            "bar",
            &file_url(&tmp_path.join("dump.sql")),
            BUFFERED,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(count_rows("bar", "test").await?, 1);

        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn streaming_rejects_nul_byte() {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    let tmp_path = tmp.path().to_path_buf();

    let mut dump =
        b"BEGIN TRANSACTION;\nCREATE TABLE test (x);\nINSERT INTO test VALUES ('a".to_vec();
    dump.push(0);
    dump.extend_from_slice(b"b');\nCOMMIT;\n");
    std::fs::write(tmp_path.join("dump.sql"), dump).unwrap();

    make_primary(&mut sim, tmp.path().to_path_buf());

    sim.client("client", async move {
        let client = Client::new();
        let resp = create_from_dump(
            &client,
            "foo",
            &file_url(&tmp_path.join("dump.sql")),
            STREAMING,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = resp.body_string().await?;
        assert!(
            body.contains("NUL byte at line 3, column 28"),
            "unexpected body: {body}"
        );
        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn streaming_rejects_invalid_utf8() {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    let tmp_path = tmp.path().to_path_buf();

    let mut dump =
        b"BEGIN TRANSACTION;\nCREATE TABLE test (x);\nINSERT INTO test VALUES ('".to_vec();
    dump.extend_from_slice(&[0xff, 0xfe]);
    dump.extend_from_slice(b"');\nCOMMIT;\n");
    std::fs::write(tmp_path.join("dump.sql"), dump).unwrap();

    make_primary(&mut sim, tmp.path().to_path_buf());

    sim.client("client", async move {
        let client = Client::new();
        let resp = create_from_dump(
            &client,
            "foo",
            &file_url(&tmp_path.join("dump.sql")),
            STREAMING,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = resp.body_string().await?;
        assert!(
            body.contains("not valid UTF-8 at line 3, column 27"),
            "unexpected body: {body}"
        );
        assert!(count_rows("foo", "test").await.is_err());
        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn dump_importer_requires_dump_url() {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    make_primary(&mut sim, tmp.path().to_path_buf());

    sim.client("client", async move {
        let client = Client::new();
        let resp = client
            .post(
                "http://primary:9090/v1/namespaces/foo/create",
                json!({ "dump_importer": "streaming" }),
            )
            .await?;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_json_snapshot!(resp.json_value().await?);

        // unknown importer names are rejected by deserialization (axum answers 422)
        let resp = client
            .post(
                "http://primary:9090/v1/namespaces/foo/create",
                json!({ "dump_url": "file:/dump.sql", "dump_importer": "turbo" }),
            )
            .await?;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

        Ok(())
    });

    sim.run().unwrap();
}

/// With `--dump-importer streaming`, requests that omit `dump_importer` use the streaming
/// importer. The dump contains the word "attachment", which only the buffered importer rejects.
#[test]
fn server_default_streaming() {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    make_primary_with_db_config(
        &mut sim,
        tmp.path().to_path_buf(),
        DbConfig {
            dump_import: DumpImportConfig {
                default_importer: DumpImporterKind::Streaming,
                ..Default::default()
            },
            ..Default::default()
        },
    );
    make_dump_store_whole(&mut sim, CHUNKY_DUMP);

    sim.client("client", async move {
        let client = Client::new();
        let resp = create_from_dump(&client, "foo", "http://dump-store:8080/", None).await?;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(count_rows("foo", "test").await?, 3);

        // explicit opt-out still works
        let resp = create_from_dump(&client, "bar", "http://dump-store:8080/", BUFFERED).await?;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        Ok(())
    });

    sim.run().unwrap();
}

/// Importing the same dump with both importers must yield the same data; the streaming
/// importer additionally preserves the schema SQL text verbatim.
#[test]
fn importers_produce_identical_databases() {
    const DUMP: &str = r#"PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE plain (a, b REAL, c BLOB, d TEXT);
INSERT INTO plain VALUES(1, 1.0e10, X'00ff10', 'it''s "quoted"');
INSERT INTO plain VALUES(NULL, -0.5, X'', 'multi
line');
INSERT INTO plain VALUES(3, 2.5, NULL, 'tab	inside');
CREATE TABLE seq (id INTEGER PRIMARY KEY AUTOINCREMENT, v TEXT);
INSERT INTO seq VALUES(1,'one');
INSERT INTO seq VALUES(5,'five');
DELETE FROM sqlite_sequence;
INSERT INTO sqlite_sequence VALUES('seq',5);
CREATE TABLE norowid (k TEXT PRIMARY KEY, v) WITHOUT ROWID;
INSERT INTO norowid VALUES('k1', 1);
CREATE TABLE "rowid_preserved"(rowid_ INTEGER, v);
INSERT INTO "rowid_preserved"(rowid, rowid_, v) VALUES(7, 70, 'seven');
CREATE INDEX plain_a ON plain(a);
CREATE VIEW v_plain AS SELECT a, d FROM plain WHERE a IS NOT NULL;
CREATE TRIGGER tr AFTER INSERT ON seq BEGIN UPDATE seq SET v = v || '!' WHERE id = NEW.id; END;
COMMIT;
"#;

    let mut sim = sim();
    let tmp = tempdir().unwrap();
    let tmp_path = tmp.path().to_path_buf();
    std::fs::write(tmp_path.join("dump.sql"), DUMP).unwrap();
    make_primary(&mut sim, tmp.path().to_path_buf());

    sim.client("client", async move {
        let client = Client::new();
        let url = file_url(&tmp_path.join("dump.sql"));

        for (ns, importer) in [("ns_buffered", BUFFERED), ("ns_streaming", STREAMING)] {
            let resp = create_from_dump(&client, ns, &url, importer).await?;
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "{importer:?}: {}",
                resp.body_string().await.unwrap_or_default()
            );
        }

        let mut dumps = Vec::new();
        for ns in ["ns_buffered", "ns_streaming"] {
            let resp = client
                .get(&format!(
                    "http://{ns}.primary:8080/dump?preserve_row_ids=true"
                ))
                .await?;
            assert_eq!(resp.status(), StatusCode::OK);
            dumps.push(resp.body_string().await?);
        }
        let [buffered, streaming]: [String; 2] = dumps.try_into().unwrap();

        // Same data, row for row (including preserved rowids and sqlite_sequence).
        let data = |dump: &str| -> Vec<String> {
            dump.lines()
                .filter(|l| l.starts_with("INSERT INTO") || l.starts_with("DELETE FROM"))
                .map(str::to_owned)
                .collect()
        };
        assert_eq!(data(&buffered), data(&streaming));
        assert!(streaming
            .contains("INSERT INTO rowid_preserved(rowid,rowid_,v) VALUES(7,70,'seven');"));

        // The streaming importer executes the original statement text, so the schema SQL
        // stored in sqlite_schema is exactly what the dump contained. (The buffered importer
        // executes the parser's re-serialization, which normalizes whitespace in DDL, e.g.
        // `ON plain (a)` and a multi-line trigger body.)
        for ddl in [
            "CREATE TABLE IF NOT EXISTS \"rowid_preserved\"(rowid_ INTEGER, v);",
            "CREATE INDEX plain_a ON plain(a);",
            "CREATE TRIGGER tr AFTER INSERT ON seq BEGIN UPDATE seq SET v = v || '!' WHERE id = NEW.id; END;",
        ] {
            assert!(streaming.contains(ddl), "missing {ddl:?} in:\n{streaming}");
        }
        assert_snapshot!(streaming);

        Ok(())
    });

    sim.run().unwrap();
}

/// A dump much larger than the in-flight queue budget: exercises backpressure and guards
/// against accidental quadratic behavior in framing.
#[test]
fn streaming_large_dump() {
    const ROWS: usize = 50_000;

    let mut sim = sim();
    let tmp = tempdir().unwrap();
    let tmp_path = tmp.path().to_path_buf();

    let mut dump = String::from("PRAGMA foreign_keys=OFF;\nBEGIN TRANSACTION;\nCREATE TABLE test (id INTEGER PRIMARY KEY, payload TEXT);\n");
    for i in 0..ROWS {
        dump.push_str(&format!(
            "INSERT INTO test VALUES({i}, 'row {i}; padding padding padding padding padding');\n"
        ));
    }
    dump.push_str("COMMIT;\n");
    std::fs::write(tmp_path.join("dump.sql"), &dump).unwrap();

    make_primary_with_db_config(
        &mut sim,
        tmp.path().to_path_buf(),
        DbConfig {
            dump_import: DumpImportConfig {
                queue_bytes: DumpImportConfig::MIN_QUEUE_BYTES,
                queue_depth: 8,
                ..Default::default()
            },
            ..Default::default()
        },
    );

    sim.client("client", async move {
        let client = Client::new();
        let resp = create_from_dump(
            &client,
            "foo",
            &file_url(&tmp_path.join("dump.sql")),
            STREAMING,
        )
        .await?;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "{}",
            resp.body_string().await.unwrap_or_default()
        );
        assert_eq!(count_rows("foo", "test").await?, ROWS as i64);
        Ok(())
    });

    sim.run().unwrap();
}

/// The first `CREATE TABLE libsql_wasm_func_table` of a dump is skipped by both importers and
/// does not disturb the "statement 3+ must be in a transaction" rule.
fn load_dump_skips_wasm_table_with(importer: Option<&'static str>) {
    const DUMP: &str = r#"
    PRAGMA foreign_keys=OFF;
    BEGIN TRANSACTION;
    CREATE TABLE libsql_wasm_func_table (name text PRIMARY KEY, body text) WITHOUT ROWID;
    CREATE TABLE test (x);
    INSERT INTO test VALUES(1);
    COMMIT;"#;

    let mut sim = sim();
    let tmp = tempdir().unwrap();
    let tmp_path = tmp.path().to_path_buf();
    std::fs::write(tmp_path.join("dump.sql"), DUMP).unwrap();
    make_primary(&mut sim, tmp.path().to_path_buf());

    sim.client("client", async move {
        let client = Client::new();
        let resp = create_from_dump(
            &client,
            "foo",
            &file_url(&tmp_path.join("dump.sql")),
            importer,
        )
        .await?;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "{}",
            resp.body_string().await.unwrap_or_default()
        );
        assert_eq!(count_rows("foo", "test").await?, 1);
        // the wasm table itself was not created
        assert!(count_rows("foo", "libsql_wasm_func_table").await.is_err());
        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn load_dump_skips_wasm_table() {
    load_dump_skips_wasm_table_with(BUFFERED);
}

#[test]
fn load_dump_skips_wasm_table_streaming() {
    load_dump_skips_wasm_table_with(STREAMING);
}

/// An empty (or comment-only) dump creates an empty namespace with both importers.
fn load_empty_dump_with(importer: Option<&'static str>) {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    let tmp_path = tmp.path().to_path_buf();
    std::fs::write(tmp_path.join("empty.sql"), "").unwrap();
    std::fs::write(tmp_path.join("comment.sql"), "-- nothing to see here\n").unwrap();
    make_primary(&mut sim, tmp.path().to_path_buf());

    sim.client("client", async move {
        let client = Client::new();
        for (ns, file) in [("empty", "empty.sql"), ("comment", "comment.sql")] {
            let resp =
                create_from_dump(&client, ns, &file_url(&tmp_path.join(file)), importer).await?;
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "{ns}: {}",
                resp.body_string().await.unwrap_or_default()
            );
            let db = Database::open_remote_with_connector(
                &format!("http://{ns}.primary:8080"),
                "",
                TurmoilConnector,
            )?;
            let conn = db.connect()?;
            let mut rows = conn.query("select count(*) from sqlite_schema", ()).await?;
            assert_eq!(rows.next().await?.unwrap().get::<i64>(0)?, 0);
        }
        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn load_empty_dump() {
    load_empty_dump_with(BUFFERED);
}

#[test]
fn load_empty_dump_streaming() {
    load_empty_dump_with(STREAMING);
}

/// A dump whose final `COMMIT` has no trailing `;` (the framer's `finish()` tail) commits, and
/// a file that ends in the middle of a statement is rejected cleanly.
#[test]
fn streaming_eof_without_semicolon() {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    let tmp_path = tmp.path().to_path_buf();
    std::fs::write(
        tmp_path.join("ok.sql"),
        "BEGIN TRANSACTION;\nCREATE TABLE test (x);\nINSERT INTO test VALUES(1);\nCOMMIT",
    )
    .unwrap();
    std::fs::write(
        tmp_path.join("cut.sql"),
        "BEGIN TRANSACTION;\nCREATE TABLE test (x);\nINSERT INTO test VALUES(1);\nINSERT INTO test VAL",
    )
    .unwrap();
    make_primary(&mut sim, tmp.path().to_path_buf());

    sim.client("client", async move {
        let client = Client::new();
        let resp = create_from_dump(
            &client,
            "ok",
            &file_url(&tmp_path.join("ok.sql")),
            STREAMING,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(count_rows("ok", "test").await?, 1);

        let resp = create_from_dump(
            &client,
            "cut",
            &file_url(&tmp_path.join("cut.sql")),
            STREAMING,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = resp.body_string().await?;
        assert!(
            body.contains("syntax error") && body.contains("line 4"),
            "unexpected body: {body}"
        );
        assert!(count_rows("cut", "test").await.is_err());
        Ok(())
    });

    sim.run().unwrap();
}

/// Executor failure while the reader is blocked on a saturated queue: the executor must drop
/// its receiver so the queued permits are released and the reader observes the failure instead
/// of hanging.
#[test]
fn streaming_failure_under_backpressure() {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    let tmp_path = tmp.path().to_path_buf();

    let mut dump = String::from("BEGIN TRANSACTION;\nCREATE TABLE test (x);\n");
    for i in 0..20_000 {
        dump.push_str(&format!("INSERT INTO test VALUES({i});\n"));
    }
    // an oversized statement deep inside the dump
    dump.push_str(&format!(
        "INSERT INTO test VALUES('{}');\n",
        "x".repeat(DumpImportConfig::MIN_MAX_STATEMENT_BYTES)
    ));
    for i in 0..20_000 {
        dump.push_str(&format!("INSERT INTO test VALUES({i});\n"));
    }
    dump.push_str("COMMIT;\n");
    std::fs::write(tmp_path.join("dump.sql"), dump).unwrap();

    make_primary_with_db_config(
        &mut sim,
        tmp.path().to_path_buf(),
        DbConfig {
            dump_import: DumpImportConfig {
                max_statement_bytes: DumpImportConfig::MIN_MAX_STATEMENT_BYTES,
                queue_bytes: DumpImportConfig::MIN_QUEUE_BYTES,
                queue_depth: 4,
                ..Default::default()
            },
            ..Default::default()
        },
    );

    sim.client("client", async move {
        let client = Client::new();
        let resp = create_from_dump(
            &client,
            "foo",
            &file_url(&tmp_path.join("dump.sql")),
            STREAMING,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(count_rows("foo", "test").await.is_err());

        // a statement-level failure (not a framing one) behind a full queue behaves the same
        let mut dump = String::from("BEGIN TRANSACTION;\nCREATE TABLE test (x);\n");
        for i in 0..20_000 {
            dump.push_str(&format!("INSERT INTO test VALUES({i});\n"));
        }
        dump.push_str("INSERT INTO nope VALUES(1);\n");
        for i in 0..20_000 {
            dump.push_str(&format!("INSERT INTO test VALUES({i});\n"));
        }
        dump.push_str("COMMIT;\n");
        std::fs::write(tmp_path.join("dump2.sql"), dump).unwrap();
        let resp = create_from_dump(
            &client,
            "bar",
            &file_url(&tmp_path.join("dump2.sql")),
            STREAMING,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = resp.body_string().await?;
        assert!(
            body.contains("no such table: nope"),
            "unexpected body: {body}"
        );
        assert!(count_rows("bar", "test").await.is_err());
        Ok(())
    });

    sim.run().unwrap();
}

/// The admin request is abandoned while the dump is still being transferred. The namespace
/// must not survive in any form: the importer rolls back and releases its connection, the
/// configurator removes the directory and the store never persists the config, so the name is
/// immediately reusable (see `docs/ATOMIC_NAMESPACE_CREATE_DESIGN.md`).
fn cancelled_create_leaves_no_trace_with(importer: Option<&'static str>) {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    let tmp_path = tmp.path().to_path_buf();
    make_primary(&mut sim, tmp.path().to_path_buf());

    // Deliver the dump slowly so the request is still in flight when it is abandoned. Few,
    // large chunks also keep the number of unread segments below turmoil's simulated socket
    // buffer once nobody reads them anymore.
    make_slow_dump_store(&mut sim, SLOW_DUMP);

    sim.client("client", async move {
        let client = Client::new();
        let aborted = tokio::time::timeout(
            Duration::from_millis(500),
            create_from_dump(&client, "foo", "http://dump-store:8080/", importer),
        )
        .await;
        assert!(aborted.is_err(), "the request should still be in flight");
        // Let the server notice the closed connection (simulated time) and the executor thread
        // roll back and drop its connection (real time: the sim clock doesn't wait for it).
        tokio::time::sleep(Duration::from_secs(2)).await;
        std::thread::sleep(Duration::from_millis(300));

        // The namespace does not exist, for the admin API, for users, and on disk.
        let resp = client
            .get("http://primary:9090/v1/namespaces/foo/config")
            .await?;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let err = count_rows("foo", "test").await.unwrap_err().to_string();
        assert!(err.contains("doesn't exist"), "unexpected error: {err}");
        super::lifecycle::wait_until_gone(&tmp_path.join("dbs").join("foo"));

        // ... so the same name can be created again, from the same dump.
        let resp = create_from_dump(&client, "foo", "http://dump-store:8080/", importer).await?;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(count_rows("foo", "test").await?, 10);
        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn cancelled_create_leaves_no_trace() {
    cancelled_create_leaves_no_trace_with(BUFFERED);
}

#[test]
fn cancelled_create_leaves_no_trace_streaming() {
    cancelled_create_leaves_no_trace_with(STREAMING);
}
