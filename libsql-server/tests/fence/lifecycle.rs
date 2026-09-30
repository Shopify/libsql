//! Lifecycle and configuration operations on fenced namespaces, over the admin API
//! (`docs/NAMESPACE_FENCE.md` section 3.3, the lifecycle column; section 17 row 17).

use std::sync::Arc;

use hyper::StatusCode;
use libsql::Value as SqlValue;
use serde_json::{json, Value};
use tempfile::tempdir;
use tokio::sync::Notify;
use uuid::Uuid;

use super::{
    acquire_body, command_body, connect, load_and_log_id, make_primary, make_restartable_primary,
    sim, state_of, user_execute, Admin, Primary, ADMIN_KEY,
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

#[track_caller]
fn assert_fence(body: &Value, state: &str, revision: u64, write: &str, read: &str) {
    assert_eq!(state_of(body), (state, revision), "{body}");
    assert_eq!(body["fence"]["admission"]["write"], write, "{body}");
    assert_eq!(body["fence"]["admission"]["read"], read, "{body}");
}

async fn assert_user_locked(ns: &str, sql: &str, code: &str) -> anyhow::Result<()> {
    let (status, body) = user_execute(ns, sql).await?;
    assert_eq!(status, StatusCode::LOCKED, "{ns}: {body}");
    assert_eq!(body["code"], code, "{ns}: {body}");
    Ok(())
}

async fn assert_user_ok(ns: &str, sql: &str) -> anyhow::Result<()> {
    let (status, body) = user_execute(ns, sql).await?;
    assert_eq!(status, StatusCode::OK, "{ns}: {body}");
    Ok(())
}

/// Create a target and move it through validation into `TARGET_WRITE_FENCED`. Returns the exact
/// publish request and response so a restart test can replay the command and compare its receipt.
async fn target_write_fenced(
    admin: &Admin,
    ns: &str,
    op: Uuid,
    command_base: u128,
) -> anyhow::Result<(Value, Value)> {
    let (status, created) = admin
        .command(
            ns,
            "target/create-quarantined",
            command_body(op, uuid(command_base), "ABSENT", 0, json!({})),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{created}");
    let (_, revision) = state_of(&created);

    let (status, sealed) = admin
        .command(
            ns,
            "target/seal-import",
            command_body(
                op,
                uuid(command_base + 1),
                "TARGET_QUARANTINED",
                revision,
                json!({}),
            ),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{sealed}");
    let (_, revision) = state_of(&sealed);

    let (status, validated) = admin
        .command(
            ns,
            "target/validation-receipt",
            command_body(
                op,
                uuid(command_base + 2),
                "TARGET_VALIDATING",
                revision,
                json!({ "result": "ok", "summary": "restart integration" }),
            ),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{validated}");
    let (_, revision) = state_of(&validated);

    let publish = command_body(
        op,
        uuid(command_base + 3),
        "TARGET_VALIDATING",
        revision,
        json!({}),
    );
    let (status, published) = admin
        .command(ns, "target/publish-readable", publish.clone())
        .await?;
    assert_eq!(status, StatusCode::OK, "{published}");
    assert_eq!(state_of(&published).0, "TARGET_WRITE_FENCED", "{published}");
    Ok((publish, published))
}

/// Capacity eviction removes the live namespace but not its controller. A reload through the user
/// protocol therefore has the same revision/generation and still rejects writes.
#[test]
fn evicted_namespace_reloads_same_gate() {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    make_primary(
        &mut sim,
        tmp.path().to_path_buf(),
        Primary {
            max_active_namespaces: 1,
            ..Primary::default()
        },
    );
    sim.client("client", async {
        let admin = Admin::new(Some(ADMIN_KEY));
        admin.create_namespace("evicted").await?;
        let log_id = load_and_log_id(&admin, "evicted").await?;
        let operation = uuid(0xac00);
        let (status, fenced) = admin
            .command(
                "evicted",
                "source/acquire-write-fence",
                acquire_body(operation, uuid(0xac01), &log_id),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{fenced}");
        let (state, revision) = state_of(&fenced);
        let generation = fenced["fence"]["admission"]["generation"].clone();
        assert_fence(&fenced, "SOURCE_WRITE_FENCED", revision, "closed", "open");
        assert_eq!(state, "SOURCE_WRITE_FENCED");

        // With capacity one, creating each distinct namespace loads it and forces the prior live
        // namespace out. More than one successor also lets the asynchronous eviction listener
        // finish before `evicted` is accessed again.
        for i in 0..4 {
            admin.create_namespace(&format!("pressure-{i}")).await?;
        }

        // This read reloads `evicted`; the controller is outside the capacity-limited cache.
        assert_user_ok("evicted", "select count(*) from t").await?;
        assert_user_locked(
            "evicted",
            "insert into t values (2)",
            "MIGRATION_WRITE_FENCED",
        )
        .await?;
        let (status, reloaded) = admin.inspect("evicted").await?;
        assert_eq!(status, StatusCode::OK, "{reloaded}");
        assert_fence(&reloaded, "SOURCE_WRITE_FENCED", revision, "closed", "open");
        assert_eq!(
            reloaded["fence"]["admission"]["generation"], generation,
            "{reloaded}"
        );
        Ok(())
    });
    sim.run().unwrap();
}

/// Every active source/target gate is reconstructed before traffic after a clean server restart,
/// and the exact command which produced it still replays its durable receipt.
#[test]
fn restart_keeps_fence() {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    let restart = Arc::new(Notify::new());
    let restarted = Arc::new(Notify::new());
    make_restartable_primary(
        &mut sim,
        tmp.path().to_path_buf(),
        Primary::default(),
        restart.clone(),
        restarted.clone(),
    );
    sim.client("client", async move {
        let admin = Admin::new(Some(ADMIN_KEY));

        admin.create_namespace("source-write").await?;
        let log_id = load_and_log_id(&admin, "source-write").await?;
        let source_write_op = uuid(0xac10);
        let source_write_request = acquire_body(source_write_op, uuid(0xac11), &log_id);
        let (status, source_write) = admin
            .command(
                "source-write",
                "source/acquire-write-fence",
                source_write_request.clone(),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{source_write}");

        admin.create_namespace("source-read").await?;
        let log_id = load_and_log_id(&admin, "source-read").await?;
        let source_read_op = uuid(0xac20);
        let (status, acquired) = admin
            .command(
                "source-read",
                "source/acquire-write-fence",
                acquire_body(source_read_op, uuid(0xac21), &log_id),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{acquired}");
        let source_read_request = command_body(
            source_read_op,
            uuid(0xac22),
            "SOURCE_WRITE_FENCED",
            state_of(&acquired).1,
            json!({ "drain_policy": { "deadline_ms": 5000 } }),
        );
        let (status, source_read) = admin
            .command(
                "source-read",
                "source/set-read-fence",
                source_read_request.clone(),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{source_read}");

        let target_quarantined_op = uuid(0xac30);
        let target_quarantined_request =
            command_body(target_quarantined_op, uuid(0xac31), "ABSENT", 0, json!({}));
        let (status, target_quarantined) = admin
            .command(
                "target-quarantined",
                "target/create-quarantined",
                target_quarantined_request.clone(),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{target_quarantined}");

        let (target_write_request, target_write) =
            target_write_fenced(&admin, "target-write-fenced", uuid(0xac40), 0xac41).await?;

        let expected = [
            (
                "source-write",
                "SOURCE_WRITE_FENCED",
                state_of(&source_write).1,
                "closed",
                "open",
            ),
            (
                "source-read",
                "SOURCE_READ_FENCED",
                state_of(&source_read).1,
                "closed",
                "closed",
            ),
            (
                "target-quarantined",
                "TARGET_QUARANTINED",
                state_of(&target_quarantined).1,
                "closed",
                "closed",
            ),
            (
                "target-write-fenced",
                "TARGET_WRITE_FENCED",
                state_of(&target_write).1,
                "closed",
                "open",
            ),
        ];
        for (ns, state, revision, write, read) in expected {
            let (status, body) = admin.inspect(ns).await?;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_fence(&body, state, revision, write, read);
        }

        restart.notify_waiters();
        restarted.notified().await;
        // A response proves the restarted admin server is serving from the rebuilt store.
        let admin = Admin::new(Some(ADMIN_KEY));
        assert_eq!(admin.get("/v1/fence/capabilities").await?.0, StatusCode::OK);

        for (ns, state, revision, write, read) in expected {
            let (status, body) = admin.inspect(ns).await?;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_fence(&body, state, revision, write, read);
        }

        for (ns, route, request, original) in [
            (
                "source-write",
                "source/acquire-write-fence",
                source_write_request,
                source_write,
            ),
            (
                "source-read",
                "source/set-read-fence",
                source_read_request,
                source_read,
            ),
            (
                "target-quarantined",
                "target/create-quarantined",
                target_quarantined_request,
                target_quarantined,
            ),
            (
                "target-write-fenced",
                "target/publish-readable",
                target_write_request,
                target_write,
            ),
        ] {
            let (status, replay) = admin.command(ns, route, request).await?;
            assert_eq!(status, StatusCode::OK, "{ns}: {replay}");
            assert_eq!(replay["replayed"], true, "{ns}: {replay}");
            assert_eq!(replay["receipt"], original["receipt"], "{ns}: {replay}");
        }

        assert_user_ok("source-write", "select count(*) from t").await?;
        assert_user_locked(
            "source-write",
            "insert into t values (2)",
            "MIGRATION_WRITE_FENCED",
        )
        .await?;
        assert_user_locked("source-read", "select * from t", "MIGRATION_READ_FENCED").await?;
        assert_user_locked(
            "target-quarantined",
            "select 1",
            "MIGRATION_TARGET_QUARANTINED",
        )
        .await?;
        assert_user_ok("target-write-fenced", "select 1").await?;
        assert_user_locked(
            "target-write-fenced",
            "create table denied (x)",
            "MIGRATION_WRITE_FENCED",
        )
        .await?;
        Ok(())
    });
    sim.run().unwrap();
}

/// `TARGET_WRITABLE` is durable too: a restart cannot put the target back in quarantine or close
/// writes, and a lost enable-writes response remains inspectable through exact replay.
#[test]
fn restart_after_enable_writes_stays_writable() {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    let restart = Arc::new(Notify::new());
    let restarted = Arc::new(Notify::new());
    make_restartable_primary(
        &mut sim,
        tmp.path().to_path_buf(),
        Primary::default(),
        restart.clone(),
        restarted.clone(),
    );
    sim.client("client", async move {
        let admin = Admin::new(Some(ADMIN_KEY));
        let operation = uuid(0xac50);
        let (_, published) =
            target_write_fenced(&admin, "target-writable", operation, 0xac51).await?;
        let enable = command_body(
            operation,
            uuid(0xac55),
            "TARGET_WRITE_FENCED",
            state_of(&published).1,
            json!({}),
        );
        let (status, enabled) = admin
            .command("target-writable", "target/enable-writes", enable.clone())
            .await?;
        assert_eq!(status, StatusCode::OK, "{enabled}");
        let revision = state_of(&enabled).1;
        assert_fence(&enabled, "TARGET_WRITABLE", revision, "open", "open");
        assert_user_ok("target-writable", "create table before_restart (x)").await?;

        restart.notify_waiters();
        restarted.notified().await;
        let admin = Admin::new(Some(ADMIN_KEY));
        let (status, body) = admin.inspect("target-writable").await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_fence(&body, "TARGET_WRITABLE", revision, "open", "open");
        assert_user_ok("target-writable", "insert into before_restart values (1)").await?;
        assert_user_ok("target-writable", "create table after_restart (x)").await?;

        let (status, replay) = admin
            .command("target-writable", "target/enable-writes", enable)
            .await?;
        assert_eq!(status, StatusCode::OK, "{replay}");
        assert_eq!(replay["replayed"], true, "{replay}");
        assert_eq!(replay["receipt"], enabled["receipt"], "{replay}");
        assert_fence(&replay, "TARGET_WRITABLE", revision, "open", "open");
        Ok(())
    });
    sim.run().unwrap();
}
