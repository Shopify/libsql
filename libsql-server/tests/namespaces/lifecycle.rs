//! Namespace creation is all-or-nothing: after a failed, cancelled or crashed
//! `POST /v1/namespaces/:ns/create` the namespace either does not exist (no config, no
//! directory, name reusable) or is complete. See `docs/ATOMIC_NAMESPACE_CREATE_DESIGN.md`.

use std::convert::Infallible;
use std::path::Path;
use std::time::Duration;

use bytes::Bytes;
use futures::StreamExt;
use hyper::{service::make_service_fn, Body, Response as HyperResponse, StatusCode};
use libsql::Database;
use serde_json::json;
use tempfile::tempdir;
use tower::service_fn;
use turmoil::{Builder, Sim};

use crate::common::http::{Client, Response};
use crate::common::net::{TurmoilAcceptor, TurmoilConnector};
use crate::namespaces::{make_primary, make_single_namespace_primary};

pub(super) const INCOMPLETE_MARKER: &str = ".incomplete";

/// `POST /v1/namespaces/:ns/create` with `dump_url`.
async fn create_from_dump(client: &Client, ns: &str, dump_url: &str) -> anyhow::Result<Response> {
    client
        .post_raw(
            &format!("http://primary:9090/v1/namespaces/{ns}/create"),
            json!({ "dump_url": dump_url }),
        )
        .await
}

fn file_url(path: &Path) -> String {
    format!("file:{}", path.display())
}

fn sim() -> Sim<'static> {
    Builder::new()
        .simulation_duration(Duration::from_secs(1000))
        // Dumps are served in many small chunks that the server only starts reading once the
        // namespace is set up (fsyncs, file creation: real time, during which turmoil keeps
        // advancing simulated time and the dump store keeps writing). Real TCP would apply
        // back-pressure; turmoil panics once its socket buffer (64 segments by default) is full.
        .tcp_capacity(4096)
        .build()
}

async fn count_rows(ns: &str, table: &str) -> anyhow::Result<i64> {
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

/// Serve `dump` from `dump-store:8080` as one HTTP response body in 64-byte chunks, 100ms
/// (simulated) apart: with turmoil's up-to-100ms message latency this keeps a creation in
/// flight for a couple of seconds, long enough for other requests to be issued while it runs.
fn make_slow_dump_store(sim: &mut Sim, dump: &'static str) {
    let chunks: Vec<Bytes> = dump
        .as_bytes()
        .chunks(64)
        .map(Bytes::copy_from_slice)
        .collect();
    let pause = Duration::from_millis(100);
    // turmoil may call the host closure more than once; the chunks are cloned per call.
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
                                // next is produced.
                                let stream =
                                    futures::stream::iter(chunks).then(move |c| async move {
                                        tokio::time::sleep(pause).await;
                                        Ok::<_, std::io::Error>(c)
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

/// Ten rows, ~1.1 KB, so that [`make_slow_dump_store`] delivers it in ~18 chunks.
const SLOW_DUMP: &str = r#"PRAGMA foreign_keys=OFF;
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

const SIMPLE_DUMP: &str = r#"
        PRAGMA foreign_keys=OFF;
    BEGIN TRANSACTION;
    CREATE TABLE test (x);
    INSERT INTO test VALUES(42);
    COMMIT;"#;

const BROKEN_DUMP: &str = r#"
    BEGIN TRANSACTION;
    CREATE TABLE test (x);
    INSERT INTO test VALUES(1);
    THIS IS NOT SQL;
    COMMIT;"#;

/// [`SLOW_DUMP`] with a syntax error right before the end.
const SLOW_BROKEN_DUMP: &str = r#"PRAGMA foreign_keys=OFF;
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
THIS IS NOT SQL;
COMMIT;
"#;

/// Directory removal after an aborted creation is handed to the runtime; poll (real time, the
/// blocking pool is not driven by the simulated clock) until it is gone.
pub(super) fn wait_until_gone(path: &Path) {
    for _ in 0..100 {
        if !path.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("{} still exists", path.display());
}

/// After a creation *failed* (as opposed to being cancelled) nothing of it is left by the time
/// the error is reported: no polling here.
async fn assert_absent(client: &Client, tmp: &Path, ns: &str) -> anyhow::Result<()> {
    assert!(
        !tmp.join("dbs").join(ns).exists(),
        "{ns} directory left behind"
    );
    let resp = client
        .get(&format!("http://primary:9090/v1/namespaces/{ns}/config"))
        .await?;
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "{ns} should not exist"
    );
    let err = count_rows(ns, "test").await.unwrap_err().to_string();
    assert!(err.contains("doesn't exist"), "unexpected error: {err}");
    Ok(())
}

/// A dump that fails to import leaves nothing behind, and the name can be reused right away.
/// Before this change the config survived and the next access lazily created an empty database.
fn failed_create_leaves_no_trace_with(shared_schema: bool) {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    let tmp_path = tmp.path().to_path_buf();
    std::fs::write(tmp_path.join("broken.sql"), BROKEN_DUMP).unwrap();
    std::fs::write(tmp_path.join("good.sql"), SIMPLE_DUMP).unwrap();
    make_primary(&mut sim, tmp.path().to_path_buf());

    sim.client("client", async move {
        let client = Client::new();
        let create = |dump: &str| {
            let body = json!({ "dump_url": file_url(&tmp_path.join(dump)), "shared_schema": shared_schema });
            client.post_raw("http://primary:9090/v1/namespaces/foo/create", body)
        };

        let resp = create("broken.sql").await?;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_absent(&client, &tmp_path, "foo").await?;

        let resp = create("good.sql").await?;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "{}",
            resp.body_string().await.unwrap_or_default()
        );
        assert_eq!(count_rows("foo", "test").await?, 1);
        assert!(!tmp_path.join("dbs/foo").join(INCOMPLETE_MARKER).exists());
        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn failed_create_leaves_no_trace() {
    failed_create_leaves_no_trace_with(false);
}

#[test]
fn failed_create_leaves_no_trace_shared_schema() {
    failed_create_leaves_no_trace_with(true);
}

/// Requests for a namespace that is being created wait for the outcome: a second `create`
/// for the same name is rejected once the first one succeeded, and a user request issued
/// mid-import sees the complete data.
#[test]
fn concurrent_requests_wait_for_creation() {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    make_primary(&mut sim, tmp.path().to_path_buf());
    make_slow_dump_store(&mut sim, SLOW_DUMP);

    sim.client("client", async move {
        let client = Client::new();
        let slow = create_from_dump(&client, "foo", "http://dump-store:8080/");
        // issued while the import is in progress (it takes ~2s of simulated time)
        let second = async {
            tokio::time::sleep(Duration::from_millis(500)).await;
            client
                .post_raw("http://primary:9090/v1/namespaces/foo/create", json!({}))
                .await
        };
        let user = async {
            tokio::time::sleep(Duration::from_millis(500)).await;
            count_rows("foo", "test").await
        };
        let (slow, second, user) = tokio::join!(slow, second, user);
        assert_eq!(slow?.status(), StatusCode::OK);
        let second = second?;
        assert_eq!(second.status(), StatusCode::BAD_REQUEST);
        assert!(second.body_string().await?.contains("already exists"));
        assert_eq!(user?, 10);
        Ok(())
    });

    sim.run().unwrap();
}

/// If the creation that others are waiting on fails, the waiters observe a namespace that does
/// not exist, and a subsequent `create` of the same name succeeds.
#[test]
fn concurrent_create_succeeds_after_failure() {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    let tmp_path = tmp.path().to_path_buf();
    std::fs::write(tmp_path.join("good.sql"), SIMPLE_DUMP).unwrap();
    make_primary(&mut sim, tmp.path().to_path_buf());
    make_slow_dump_store(&mut sim, SLOW_BROKEN_DUMP);

    sim.client("client", async move {
        let client = Client::new();
        let slow = create_from_dump(&client, "foo", "http://dump-store:8080/");
        // issued while the import is in progress (it takes ~2s of simulated time)
        let user = async {
            tokio::time::sleep(Duration::from_millis(500)).await;
            count_rows("foo", "test").await
        };
        let (slow, user) = tokio::join!(slow, user);
        assert_eq!(slow?.status(), StatusCode::BAD_REQUEST);
        let err = user.unwrap_err().to_string();
        assert!(err.contains("doesn't exist"), "unexpected error: {err}");
        assert_absent(&client, &tmp_path, "foo").await?;

        let resp = create_from_dump(&client, "foo", &file_url(&tmp_path.join("good.sql"))).await?;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(count_rows("foo", "test").await?, 1);
        Ok(())
    });

    sim.run().unwrap();
}

/// A directory left by a creation the process died in the middle of (it still carries the
/// marker, there is no config for it) is discarded by the next creation of that name, and is
/// not adopted as a namespace when the metastore is rebuilt from the filesystem.
#[test]
fn crash_remnant_is_discarded() {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    let tmp_path = tmp.path().to_path_buf();
    std::fs::write(tmp_path.join("good.sql"), SIMPLE_DUMP).unwrap();
    let remnant = tmp_path.join("dbs/foo");
    std::fs::create_dir_all(&remnant).unwrap();
    for f in [INCOMPLETE_MARKER, ".sentinel", "data", "wallog"] {
        std::fs::write(remnant.join(f), b"junk").unwrap();
    }
    make_primary(&mut sim, tmp.path().to_path_buf());

    sim.client("client", async move {
        let client = Client::new();
        // not recovered as a namespace at startup (the metastore was empty)
        let resp = client
            .get("http://primary:9090/v1/namespaces/foo/config")
            .await?;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let resp = create_from_dump(&client, "foo", &file_url(&tmp_path.join("good.sql"))).await?;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "{}",
            resp.body_string().await.unwrap_or_default()
        );
        assert_eq!(count_rows("foo", "test").await?, 1);
        assert!(!remnant.join(INCOMPLETE_MARKER).exists());
        Ok(())
    });

    sim.run().unwrap();
}

/// Directories without the marker are never touched by a creation, whatever is in them.
#[test]
fn unmarked_directory_is_left_alone() {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    let tmp_path = tmp.path().to_path_buf();
    std::fs::write(tmp_path.join("good.sql"), SIMPLE_DUMP).unwrap();
    let dir = tmp_path.join("dbs/foo");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("keep.txt"), b"precious").unwrap();
    make_primary(&mut sim, tmp.path().to_path_buf());

    sim.client("client", async move {
        let client = Client::new();
        // No database in there, so the import proceeds into the existing directory ...
        let resp = create_from_dump(&client, "foo", &file_url(&tmp_path.join("good.sql"))).await?;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(count_rows("foo", "test").await?, 1);
        // ... and whatever was in it is left alone, before and after.
        assert_eq!(std::fs::read(dir.join("keep.txt"))?, b"precious");
        assert!(!dir.join(INCOMPLETE_MARKER).exists());
        Ok(())
    });

    sim.run().unwrap();
}

/// A marker on a namespace that *is* known to the metastore (the process died between
/// persisting the config and removing the marker) is harmless: `create` rejects the name,
/// the data is served, and the marker is dropped when the namespace is next loaded.
#[test]
fn marker_on_published_namespace_is_ignored() {
    let tmp = tempdir().unwrap();
    let tmp_path = tmp.path().to_path_buf();
    std::fs::write(tmp_path.join("good.sql"), SIMPLE_DUMP).unwrap();
    let marker = tmp_path.join("dbs/foo").join(INCOMPLETE_MARKER);

    let mut first = sim();
    make_primary(&mut first, tmp.path().to_path_buf());
    first.client("client", {
        let tmp_path = tmp_path.clone();
        let marker = marker.clone();
        async move {
            let client = Client::new();
            let resp =
                create_from_dump(&client, "foo", &file_url(&tmp_path.join("good.sql"))).await?;
            assert_eq!(resp.status(), StatusCode::OK);
            assert!(!marker.exists());

            // simulate a crash right after the config was persisted
            std::fs::write(&marker, b"").unwrap();
            let resp =
                create_from_dump(&client, "foo", &file_url(&tmp_path.join("good.sql"))).await?;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
            assert!(resp.body_string().await?.contains("already exists"));
            assert_eq!(count_rows("foo", "test").await?, 1);
            assert!(marker.exists(), "the marker is only removed on load");
            Ok(())
        }
    });
    first.run().unwrap();
    drop(first); // the first server must be gone before the second opens the same files

    // restart: nothing is loaded yet, the marker is still there and the metastore knows the
    // name. A `create` must be rejected on the strength of the metastore alone (not wipe the
    // directory); then the namespace loads and the stale marker goes away.
    let mut restarted = sim();
    make_primary(&mut restarted, tmp.path().to_path_buf());
    restarted.client("client", async move {
        let client = Client::new();
        let resp = create_from_dump(&client, "foo", &file_url(&tmp_path.join("good.sql"))).await?;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(marker.exists(), "rejected before touching the directory");
        assert_eq!(count_rows("foo", "test").await?, 1);
        wait_until_gone(&marker);
        Ok(())
    });
    restarted.run().unwrap();
}

/// Single-namespace mode: `create` of the default namespace is a config upsert, but creating
/// it *from a dump* while it already exists must be rejected rather than silently skipping the
/// import (which is what happened before).
#[test]
fn single_namespace_mode_rejects_dump_into_existing_namespace() {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    let tmp_path = tmp.path().to_path_buf();
    std::fs::write(tmp_path.join("good.sql"), SIMPLE_DUMP).unwrap();
    make_single_namespace_primary(&mut sim, tmp.path().to_path_buf());

    sim.client("client", async move {
        let client = Client::new();
        // config upsert of the (already created) default namespace still works
        let resp = client
            .post_raw(
                "http://primary:9090/v1/namespaces/default/create",
                json!({ "max_db_size": "1mb" }),
            )
            .await?;
        assert_eq!(resp.status(), StatusCode::OK);

        let resp =
            create_from_dump(&client, "default", &file_url(&tmp_path.join("good.sql"))).await?;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(resp.body_string().await?.contains("already exists"));
        Ok(())
    });

    sim.run().unwrap();
}

/// The admin request is abandoned while the dump is still being transferred. The namespace
/// must not survive in any form: the importer rolls back and releases its connection, the
/// configurator removes the directory and the store never persists the config, so the name is
/// immediately reusable.
#[test]
fn cancelled_create_leaves_no_trace() {
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
        let dir = tmp_path.join("dbs").join("foo");
        // Cancel once the creation is provably under way: the namespace directory exists and
        // is marked incomplete (turmoil's random message latency makes a fixed delay either
        // too early or too late).
        let marker = dir.join(INCOMPLETE_MARKER);
        let request = create_from_dump(&client, "foo", "http://dump-store:8080/");
        let aborted = tokio::time::timeout(
            Duration::from_secs(10),
            futures::future::select(
                Box::pin(request),
                Box::pin(async {
                    while !marker.exists() {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                }),
            ),
        )
        .await
        .expect("the creation should have started");
        assert!(
            matches!(aborted, futures::future::Either::Right(_)),
            "the request should still be in flight"
        );
        // `aborted` holds the request future: dropping it is the cancellation.
        drop(aborted);
        // Let the server notice the closed connection (simulated time) and the importer roll
        // back and drop its connection (real time: the sim clock doesn't wait for it).
        tokio::time::sleep(Duration::from_secs(2)).await;
        std::thread::sleep(Duration::from_millis(300));

        // The namespace does not exist, for the admin API, for users, and on disk.
        let resp = client
            .get("http://primary:9090/v1/namespaces/foo/config")
            .await?;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let err = count_rows("foo", "test").await.unwrap_err().to_string();
        assert!(err.contains("doesn't exist"), "unexpected error: {err}");
        wait_until_gone(&dir);

        // ... so the same name can be created again, from the same dump, and used.
        let resp = create_from_dump(&client, "foo", "http://dump-store:8080/").await?;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(count_rows("foo", "test").await?, 10);
        let db =
            Database::open_remote_with_connector("http://foo.primary:8080", "", TurmoilConnector)?;
        let conn = db.connect()?;
        conn.execute(
            "insert into test values (11, 'eleven', 'written after the cancelled attempt')",
            (),
        )
        .await?;
        assert_eq!(count_rows("foo", "test").await?, 11);
        assert!(!marker.exists());
        Ok(())
    });

    sim.run().unwrap();
}
