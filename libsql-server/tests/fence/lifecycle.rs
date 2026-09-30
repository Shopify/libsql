//! Lifecycle and configuration operations on fenced namespaces, over the admin API
//! (`docs/NAMESPACE_FENCE.md` section 3.3, the lifecycle column; section 17 row 17).

use hyper::StatusCode;
use libsql::Value as SqlValue;
use serde_json::{json, Value};
use tempfile::tempdir;
use uuid::Uuid;

use super::{
    acquire_body, command_body, connect, load_and_log_id, make_primary, sim, state_of, Admin,
    Primary, ADMIN_KEY,
};

fn uuid(n: u128) -> Uuid {
    Uuid::from_u128(n)
}

/// Every generic lifecycle and configuration route, attempted on `ns`, with a name for the
/// failure message. `ns` must be refused by each of them.
async fn lifecycle_attempts(
    admin: &Admin,
    ns: &str,
) -> anyhow::Result<Vec<(&'static str, StatusCode, Value)>> {
    let mut results = Vec::new();
    let (status, body) = admin.delete(&format!("/v1/namespaces/{ns}")).await?;
    results.push(("delete", status, body));
    let (status, body) = admin
        .post(&format!("/v1/namespaces/{ns}/fork/{ns}-copy"), json!({}))
        .await?;
    results.push(("fork as source", status, body));
    let (status, body) = admin
        .post(&format!("/v1/namespaces/other/fork/{ns}"), json!({}))
        .await?;
    results.push(("fork as destination", status, body));
    // The dump file does not exist: a refusal made before the dump is fetched is the fence's.
    let (status, body) = admin
        .post(
            &format!("/v1/namespaces/{ns}/create"),
            json!({ "dump_url": "file:///nonexistent/dump.sql" }),
        )
        .await?;
    results.push(("create with dump_url", status, body));
    let (status, body) = admin
        .post(&format!("/v1/namespaces/{ns}/create"), json!({}))
        .await?;
    results.push(("create over the record", status, body));
    let (status, body) = admin
        .post(
            &format!("/v1/namespaces/{ns}/create"),
            json!({ "shared_schema_name": "schema" }),
        )
        .await?;
    results.push(("link to a shared schema", status, body));
    let (status, body) = admin
        .post(
            &format!("/v1/namespaces/{ns}/config"),
            json!({ "block_reads": false, "block_writes": false, "block_reason": null }),
        )
        .await?;
    results.push(("config", status, body));
    Ok(results)
}

async fn count_rows(ns: &str) -> anyhow::Result<i64> {
    let mut rows = connect(ns)?.query("select count(*) from t", ()).await?;
    let row = rows.next().await?.expect("one row");
    match row.get_value(0)? {
        SqlValue::Integer(n) => Ok(n),
        other => anyhow::bail!("unexpected count {other:?}"),
    }
}

#[test]
fn lifecycle_rejected_while_fenced() {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    make_primary(&mut sim, tmp.path().to_path_buf(), Primary::default());
    sim.client("client", async {
        let admin = Admin::new(Some(ADMIN_KEY));
        admin.create_namespace("other").await?;
        let (status, body) = admin
            .post(
                "/v1/namespaces/schema/create",
                json!({ "shared_schema": true }),
            )
            .await?;
        assert!(status.is_success(), "{status} {body}");

        // A write-fenced source.
        admin.create_namespace("src").await?;
        let log_id = load_and_log_id(&admin, "src").await?;
        let source_op = uuid(0x100);
        let (status, body) = admin
            .command(
                "src",
                "source/acquire-write-fence",
                acquire_body(source_op, uuid(1), &log_id),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        // SOURCE_DRAINING at revision 1, then SOURCE_WRITE_FENCED once the drain is proven.
        assert_eq!(state_of(&body), ("SOURCE_WRITE_FENCED", 2), "{body}");

        // A quarantined target. A target cannot be created with a shared schema.
        let target_op = uuid(0x200);
        let (status, body) = admin
            .command(
                "tgt",
                "target/create-quarantined",
                command_body(
                    target_op,
                    uuid(2),
                    "ABSENT",
                    0,
                    json!({ "shared_schema_name": "schema" }),
                ),
            )
            .await?;
        assert_eq!(status, StatusCode::PRECONDITION_FAILED, "{body}");
        assert_eq!(body["detail"], "shared_schema_unsupported", "{body}");
        let (status, body) = admin
            .command(
                "tgt",
                "target/create-quarantined",
                command_body(target_op, uuid(3), "ABSENT", 0, json!({})),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(state_of(&body), ("TARGET_QUARANTINED", 1), "{body}");

        for (ns, state, revision, code) in [
            ("src", "SOURCE_WRITE_FENCED", 2, "MIGRATION_WRITE_FENCED"),
            (
                "tgt",
                "TARGET_QUARANTINED",
                1,
                "MIGRATION_TARGET_QUARANTINED",
            ),
        ] {
            for (what, status, body) in lifecycle_attempts(&admin, ns).await? {
                assert_eq!(status, StatusCode::LOCKED, "{what} on {ns}: {body}");
                let message = body["error"].as_str().unwrap_or_default();
                assert!(
                    message.starts_with(code),
                    "{what} on {ns}: expected {code}, got {body}"
                );
                assert_eq!(body["code"], code, "{what} on {ns}: {body}");
            }
            // Nothing moved: same state and revision, and no copy was created.
            let (status, body) = admin.inspect(ns).await?;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(state_of(&body), (state, revision), "{body}");
            let (status, body) = admin
                .get(&format!("/v1/namespaces/{ns}-copy/config"))
                .await?;
            assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        }
        // The source's data is intact and still served to readers.
        assert_eq!(count_rows("src").await?, 1);
        // Reading config and stats is still allowed.
        let (status, body) = admin.get("/v1/namespaces/src/config").await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, body) = admin.get("/v1/namespaces/src/stats").await?;
        assert_eq!(status, StatusCode::OK, "{body}");

        // Released, the source is an ordinary namespace again: it takes writes and lifecycle
        // operations follow the existing policy.
        let (status, body) = admin
            .command(
                "src",
                "source/release-write-fence",
                command_body(source_op, uuid(4), "SOURCE_WRITE_FENCED", 2, json!({})),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(state_of(&body).0, "RELEASED", "{body}");
        connect("src")?
            .execute("insert into t values (2)", ())
            .await?;
        assert_eq!(count_rows("src").await?, 2);
        let (status, body) = admin
            .post(
                "/v1/namespaces/src/config",
                json!({ "block_reads": false, "block_writes": false }),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, body) = admin
            .post("/v1/namespaces/src/fork/src-copy", json!({}))
            .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(count_rows("src-copy").await?, 2);
        let (status, body) = admin.delete("/v1/namespaces/src-copy").await?;
        assert_eq!(status, StatusCode::OK, "{body}");

        // The target stays quarantined: it serves no SQL.
        assert!(count_rows("tgt").await.is_err());
        Ok(())
    });
    sim.run().unwrap();
}
