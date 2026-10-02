//! The fence admin API over HTTP (`docs/NAMESPACE_FENCE.md` section 4).

use hyper::StatusCode;
use serde_json::json;
use tempfile::tempdir;
use uuid::Uuid;

use super::{
    acquire_body, command_body, connect, load_and_log_id, make_primary, sim, state_of, Admin,
    Primary, ADMIN_KEY,
};

fn uuid(n: u128) -> Uuid {
    Uuid::from_u128(n)
}

#[test]
fn capabilities() {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    make_primary(&mut sim, tmp.path().to_path_buf(), Primary::default());
    sim.client("client", async {
        let admin = Admin::new(Some(ADMIN_KEY));
        let (status, body) = admin.get("/v1/fence/capabilities").await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["fence_protocol_version"], 1);
        assert_eq!(body["enabled"], true);
        assert_eq!(body["active_fences"], 0);
        assert_eq!(body["proxy_stable_code"], true);
        let commands: Vec<&str> = body["commands"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap())
            .collect();
        for command in [
            "InspectFence",
            "AcquireSourceWriteFence",
            "SetSourceReadFence",
            "ClearSourceReadFence",
            "ReleaseSourceWriteFence",
            "CreateTargetQuarantined",
            "SealTargetImport",
            "RecordTargetValidation",
            "PublishTargetReadableWriteFenced",
            "EnableTargetWrites",
            "AbortQuarantinedTarget",
            "AdoptFence",
        ] {
            assert!(commands.contains(&command), "{command} missing: {body}");
        }
        let states = body["states"].as_array().unwrap();
        assert!(states.contains(&json!("SOURCE_WRITE_FENCED")), "{body}");
        assert!(states.contains(&json!("UNKNOWN_UNAVAILABLE")), "{body}");
        assert!(body["server"]["build"]
            .as_str()
            .unwrap()
            .starts_with("sqld "));
        Uuid::parse_str(body["server"]["instance_id"].as_str().unwrap())?;
        // Metastore restore provenance: this server's metastore was not restored from a
        // backup, which the capability endpoint, every fence view and the gauge all report.
        assert_eq!(body["metastore"]["restored_from_backup"], false, "{body}");
        assert_eq!(
            body["metastore"]["restored_generation"],
            json!(null),
            "{body}"
        );
        assert_eq!(
            crate::common::snapshot_metrics()
                .get_gauge("libsql_server_metastore_restored_from_backup"),
            Some(0.0)
        );

        // An active fence is counted.
        admin.create_namespace("src").await?;
        let log_id = load_and_log_id(&admin, "src").await?;
        let (status, body) = admin.inspect("src").await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["fence"]["provenance"],
            json!({
                "metastore_restored_from_backup": false,
                "metastore_restored_generation": null,
                "marker": null,
            }),
            "{body}"
        );
        let (status, body) = admin
            .command(
                "src",
                "source/acquire-write-fence",
                acquire_body(uuid(1), uuid(2), &log_id),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["fence"]["provenance"]["metastore_restored_from_backup"], false,
            "{body}"
        );
        assert_eq!(
            body["fence"]["provenance"]["marker"], "consistent",
            "{body}"
        );
        let (_, body) = admin.get("/v1/fence/capabilities").await?;
        assert_eq!(body["active_fences"], 1, "{body}");

        // The admin API's own authentication still applies.
        let (status, _) = Admin::new(None).get("/v1/fence/capabilities").await?;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        Ok(())
    });
    sim.run().unwrap();
}

#[test]
fn capabilities_when_disabled() {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    make_primary(
        &mut sim,
        tmp.path().to_path_buf(),
        Primary {
            fence_enabled: false,
            ..Default::default()
        },
    );
    sim.client("client", async {
        let admin = Admin::new(Some(ADMIN_KEY));
        let (status, body) = admin.get("/v1/fence/capabilities").await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["enabled"], false);
        assert_eq!(body["fence_protocol_version"], 1);

        admin.create_namespace("src").await?;
        let (status, _) = admin.inspect("src").await?;
        assert_eq!(status, StatusCode::NOT_FOUND);
        for route in [
            "source/acquire-write-fence",
            "source/release-write-fence",
            "target/create-quarantined",
            "target/validation-query",
        ] {
            let (status, body) = admin
                .command(
                    "src",
                    route,
                    acquire_body(uuid(1), uuid(2), &uuid(3).to_string()),
                )
                .await?;
            assert_eq!(status, StatusCode::NOT_FOUND, "{route}: {body}");
        }
        // The namespace is untouched.
        let conn = connect("src")?;
        conn.execute("create table t (x)", ()).await?;
        Ok(())
    });
    sim.run().unwrap();
}

#[test]
fn mutating_routes_require_admin_key() {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    make_primary(
        &mut sim,
        tmp.path().to_path_buf(),
        Primary {
            admin_key: None,
            ..Default::default()
        },
    );
    sim.client("client", async {
        let admin = Admin::new(None);
        admin.create_namespace("src").await?;
        let log_id = load_and_log_id(&admin, "src").await?;

        let (status, body) = admin
            .command(
                "src",
                "source/acquire-write-fence",
                acquire_body(uuid(1), uuid(2), &log_id),
            )
            .await?;
        assert_eq!(status, StatusCode::PRECONDITION_FAILED, "{body}");
        assert_eq!(body["outcome"], "FENCE_PRECONDITION_FAILED");
        assert_eq!(body["detail"], "admin_auth_required");
        assert_eq!(state_of(&body), ("UNFENCED", 0), "{body}");

        let (status, body) = admin
            .command(
                "tgt",
                "target/create-quarantined",
                command_body(uuid(1), uuid(3), "ABSENT", 0, json!({})),
            )
            .await?;
        assert_eq!(status, StatusCode::PRECONDITION_FAILED, "{body}");
        assert_eq!(body["detail"], "admin_auth_required");

        let (status, body) = admin
            .command(
                "tgt",
                "target/validation-query",
                json!({
                    "operation_id": uuid(1).to_string(),
                    "expected_revision": 1,
                    "stmts": [{ "sql": "select 1" }],
                }),
            )
            .await?;
        assert_eq!(status, StatusCode::PRECONDITION_FAILED, "{body}");
        assert_eq!(body["detail"], "admin_auth_required");

        // Nothing was fenced or created, and reading the state is still possible.
        let (status, body) = admin.inspect("src").await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(state_of(&body), ("UNFENCED", 0));
        let (status, _) = admin.inspect("tgt").await?;
        assert_eq!(status, StatusCode::NOT_FOUND);
        connect("src")?
            .execute("insert into t values (2)", ())
            .await?;
        Ok(())
    });
    sim.run().unwrap();
}

/// Acceptance test: two operations race to acquire the same source; exactly one owns it.
#[test]
fn concurrent_acquire_one_owner() {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    make_primary(&mut sim, tmp.path().to_path_buf(), Primary::default());
    sim.client("client", async {
        let admin = Admin::new(Some(ADMIN_KEY));
        admin.create_namespace("src").await?;
        let log_id = load_and_log_id(&admin, "src").await?;

        let other = Admin::new(Some(ADMIN_KEY));
        let (a, b) = tokio::join!(
            admin.command(
                "src",
                "source/acquire-write-fence",
                acquire_body(uuid(0xa), uuid(1), &log_id),
            ),
            other.command(
                "src",
                "source/acquire-write-fence",
                acquire_body(uuid(0xb), uuid(2), &log_id),
            ),
        );
        let (a, b) = (a?, b?);
        let mut results = [a, b];
        results.sort_by_key(|(status, _)| status.as_u16());
        let [(won_status, won), (lost_status, lost)] = results;
        assert_eq!(won_status, StatusCode::OK, "{won}");
        assert_eq!(won["outcome"], "APPLIED");
        assert_eq!(state_of(&won).0, "SOURCE_WRITE_FENCED");
        assert_eq!(lost_status, StatusCode::CONFLICT, "{lost}");
        assert_eq!(lost["outcome"], "FENCE_OWNED_BY_ANOTHER_OPERATION");
        // The loser is shown who owns the namespace.
        assert_eq!(lost["fence"]["operation_id"], won["fence"]["operation_id"]);

        let (_, body) = admin.inspect("src").await?;
        assert_eq!(body["fence"]["operation_id"], won["fence"]["operation_id"]);
        assert!(connect("src")?
            .execute("insert into t values (2)", ())
            .await
            .is_err());
        Ok(())
    });
    sim.run().unwrap();
}

#[test]
fn source_walk_over_http() {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    make_primary(&mut sim, tmp.path().to_path_buf(), Primary::default());
    sim.client("client", async {
        let admin = Admin::new(Some(ADMIN_KEY));
        admin.create_namespace("src").await?;
        let log_id = load_and_log_id(&admin, "src").await?;
        let op = uuid(0xa);
        let conn = connect("src")?;

        // A wrong identity is refused before anything changes.
        let (status, body) = admin
            .command(
                "src",
                "source/acquire-write-fence",
                acquire_body(op, uuid(1), &uuid(0xdead).to_string()),
            )
            .await?;
        assert_eq!(status, StatusCode::PRECONDITION_FAILED, "{body}");
        assert_eq!(body["detail"], "namespace_identity_mismatch");

        let (status, acquired) = admin
            .command(
                "src",
                "source/acquire-write-fence",
                acquire_body(op, uuid(2), &log_id),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{acquired}");
        assert_eq!(acquired["outcome"], "APPLIED");
        assert_eq!(acquired["replayed"], false);
        let (state, rev) = state_of(&acquired);
        assert_eq!(state, "SOURCE_WRITE_FENCED");
        assert_eq!(acquired["fence"]["role"], "SOURCE");
        assert_eq!(acquired["fence"]["admission"]["write"], "closed");
        assert_eq!(acquired["fence"]["admission"]["read"], "open");
        assert_eq!(
            acquired["fence"]["frozen_boundary"]["log_id"],
            log_id.as_str()
        );
        assert_eq!(acquired["receipt"]["command"], "AcquireSourceWriteFence");
        assert_eq!(acquired["drain"]["active_writers"], 0);
        assert!(conn.execute("insert into t values (2)", ()).await.is_err());
        conn.query("select * from t", ()).await?;

        // Replay returns the stored receipt.
        let (status, replay) = admin
            .command(
                "src",
                "source/acquire-write-fence",
                acquire_body(op, uuid(2), &log_id),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{replay}");
        assert_eq!(replay["replayed"], true);
        assert_eq!(replay["receipt"], acquired["receipt"]);

        // The same command id with a different request is a conflict.
        let (status, body) = admin
            .command(
                "src",
                "source/acquire-write-fence",
                command_body(
                    op,
                    uuid(2),
                    "UNFENCED",
                    0,
                    json!({ "expected_namespace_identity": { "log_id": log_id } }),
                ),
            )
            .await?;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["outcome"], "FENCE_COMMAND_CONFLICT");

        // A stale revision is refused.
        let (status, body) = admin
            .command(
                "src",
                "source/set-read-fence",
                command_body(op, uuid(3), "SOURCE_WRITE_FENCED", rev - 1, json!({})),
            )
            .await?;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["outcome"], "FENCE_REVISION_MISMATCH");
        assert_eq!(state_of(&body), ("SOURCE_WRITE_FENCED", rev));

        // Read fence, then clear it.
        let (status, body) = admin
            .command(
                "src",
                "source/set-read-fence",
                command_body(
                    op,
                    uuid(4),
                    "SOURCE_WRITE_FENCED",
                    rev,
                    json!({ "drain_policy": { "deadline_ms": 5000 } }),
                ),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (state, rev) = state_of(&body);
        assert_eq!(state, "SOURCE_READ_FENCED");
        assert_eq!(body["fence"]["admission"]["read"], "closed");
        assert!(conn.query("select * from t", ()).await.is_err());

        let (status, body) = admin
            .command(
                "src",
                "source/clear-read-fence",
                command_body(op, uuid(5), "SOURCE_READ_FENCED", rev, json!({})),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (state, rev) = state_of(&body);
        assert_eq!(state, "SOURCE_WRITE_FENCED");
        connect("src")?.query("select * from t", ()).await?;

        // Release reopens writes.
        let release = command_body(op, uuid(6), "SOURCE_WRITE_FENCED", rev, json!({}));
        let (status, released) = admin
            .command("src", "source/release-write-fence", release.clone())
            .await?;
        assert_eq!(status, StatusCode::OK, "{released}");
        assert_eq!(state_of(&released).0, "RELEASED");
        assert_eq!(released["fence"]["admission"]["write"], "open");
        connect("src")?
            .execute("insert into t values (3)", ())
            .await?;

        let (status, replay) = admin
            .command("src", "source/release-write-fence", release)
            .await?;
        assert_eq!(status, StatusCode::OK, "{replay}");
        assert_eq!(replay["replayed"], true);
        assert_eq!(replay["receipt"], released["receipt"]);

        // Inspect shows the operation's receipts, and all of them on request.
        let (status, body) = admin.inspect("src").await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(state_of(&body).0, "RELEASED");
        let receipts = body["receipts"].as_array().unwrap();
        assert!(receipts.len() >= 4, "{body}");
        assert!(receipts
            .iter()
            .all(|r| r["operation_id"] == op.to_string().as_str()));
        let (_, all) = admin.get("/v1/namespaces/src/fence?receipts=all").await?;
        assert!(all["receipts"].as_array().unwrap().len() >= receipts.len());

        // Malformed requests are typed refusals.
        let (status, body) = admin
            .command(
                "src",
                "source/release-write-fence",
                json!({ "operation_id": "x" }),
            )
            .await?;
        assert_eq!(status, StatusCode::PRECONDITION_FAILED, "{body}");
        assert_eq!(body["detail"], "invalid_argument");
        let (status, body) = admin
            .command(
                "src",
                "source/release-write-fence",
                command_body(op, uuid(7), "RELEASED", 0, json!({ "surprise": 1 })),
            )
            .await?;
        assert_eq!(status, StatusCode::PRECONDITION_FAILED, "{body}");
        assert_eq!(body["detail"], "invalid_argument");
        Ok(())
    });
    sim.run().unwrap();
}

#[test]
fn target_walk_over_http() {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    make_primary(&mut sim, tmp.path().to_path_buf(), Primary::default());
    sim.client("client", async {
        let admin = Admin::new(Some(ADMIN_KEY));
        let op = uuid(0xa);

        // Restore options are refused, and nothing is created.
        let (status, body) = admin
            .command(
                "tgt",
                "target/create-quarantined",
                command_body(
                    op,
                    uuid(1),
                    "ABSENT",
                    0,
                    json!({ "dump_url": "file:///tmp/dump.sql" }),
                ),
            )
            .await?;
        assert_eq!(status, StatusCode::PRECONDITION_FAILED, "{body}");
        assert_eq!(body["detail"], "restore_not_allowed");
        assert_eq!(admin.inspect("tgt").await?.0, StatusCode::NOT_FOUND);

        let create = command_body(
            op,
            uuid(2),
            "ABSENT",
            0,
            json!({ "max_db_size": 10_000_000, "durability_mode": "strong" }),
        );
        let (status, created) = admin
            .command("tgt", "target/create-quarantined", create.clone())
            .await?;
        assert_eq!(status, StatusCode::OK, "{created}");
        assert_eq!(created["outcome"], "APPLIED");
        let (state, rev) = state_of(&created);
        assert_eq!(state, "TARGET_QUARANTINED");
        assert_eq!(created["fence"]["role"], "TARGET");
        assert!(created["fence"]["incarnation"]["target_incarnation_id"].is_string());
        let (status, replay) = admin
            .command("tgt", "target/create-quarantined", create)
            .await?;
        assert_eq!(status, StatusCode::OK, "{replay}");
        assert_eq!(replay["replayed"], true);

        // Normal SQL is refused while the target is quarantined.
        assert!(connect("tgt")?.query("select 1", ()).await.is_err());
        let (status, body) = admin
            .post("/v1/namespaces/tgt/create", json!({}))
            .await?;
        assert!(!status.is_success(), "{status} {body}");

        // Validation queries are refused before the import is sealed.
        let (status, body) = admin
            .command(
                "tgt",
                "target/validation-query",
                json!({
                    "operation_id": op.to_string(),
                    "expected_revision": rev,
                    "stmts": [{ "sql": "select 1" }],
                }),
            )
            .await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["outcome"], "OPERATION_CAPABILITY_REQUIRED");

        let (status, body) = admin
            .command(
                "tgt",
                "target/seal-import",
                command_body(op, uuid(3), "TARGET_QUARANTINED", rev, json!({})),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (state, rev) = state_of(&body);
        assert_eq!(state, "TARGET_VALIDATING");

        let (status, body) = admin
            .command(
                "tgt",
                "target/validation-query",
                json!({
                    "operation_id": op.to_string(),
                    "expected_state": "TARGET_VALIDATING",
                    "expected_revision": rev,
                    "stmts": [
                        { "sql": "select count(*) as n from sqlite_master" },
                        { "sql": "select ? + 1 as v", "args": [{ "type": "integer", "value": "41" }] },
                    ],
                }),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["results"][0]["cols"][0]["name"], "n");
        assert_eq!(
            body["results"][1]["rows"][0][0],
            json!({ "type": "integer", "value": "42" })
        );

        // A validation query cannot write.
        let (status, body) = admin
            .command(
                "tgt",
                "target/validation-query",
                json!({
                    "operation_id": op.to_string(),
                    "expected_revision": rev,
                    "stmts": [{ "sql": "create table sneaky (x)" }],
                }),
            )
            .await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["outcome"], "OPERATION_CAPABILITY_REQUIRED");

        // Another operation cannot validate.
        let (status, body) = admin
            .command(
                "tgt",
                "target/validation-query",
                json!({
                    "operation_id": uuid(0xb).to_string(),
                    "expected_revision": rev,
                    "stmts": [{ "sql": "select 1" }],
                }),
            )
            .await?;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["outcome"], "FENCE_OWNED_BY_ANOTHER_OPERATION");

        // Publication needs a successful validation receipt.
        let (status, body) = admin
            .command(
                "tgt",
                "target/publish-readable",
                command_body(op, uuid(4), "TARGET_VALIDATING", rev, json!({})),
            )
            .await?;
        assert_eq!(status, StatusCode::PRECONDITION_FAILED, "{body}");
        assert_eq!(body["detail"], "validation_receipt_required");

        let (status, body) = admin
            .command(
                "tgt",
                "target/validation-receipt",
                command_body(
                    op,
                    uuid(5),
                    "TARGET_VALIDATING",
                    rev,
                    json!({ "result": "ok", "summary": "row counts match" }),
                ),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (state, rev) = state_of(&body);
        assert_eq!(state, "TARGET_VALIDATING");
        assert_eq!(body["fence"]["validation"]["result"], "ok");
        assert!(body["fence"]["validation"]["snapshot"]["page_count"].is_u64());

        let (status, body) = admin
            .command(
                "tgt",
                "target/publish-readable",
                command_body(op, uuid(6), "TARGET_VALIDATING", rev, json!({})),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (state, rev) = state_of(&body);
        assert_eq!(state, "TARGET_WRITE_FENCED");
        let conn = connect("tgt")?;
        conn.query("select 1", ()).await?;
        assert!(conn.execute("create table t (x)", ()).await.is_err());

        let enable = command_body(op, uuid(7), "TARGET_WRITE_FENCED", rev, json!({}));
        let (status, body) = admin
            .command("tgt", "target/enable-writes", enable.clone())
            .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["outcome"], "APPLIED");
        let (state, rev_after) = state_of(&body);
        assert_eq!(state, "TARGET_WRITABLE");
        connect("tgt")?.execute("create table t (x)", ()).await?;

        let (status, body) = admin
            .command("tgt", "target/enable-writes", enable)
            .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["replayed"], true);
        let (status, body) = admin
            .command(
                "tgt",
                "target/enable-writes",
                command_body(op, uuid(8), "TARGET_WRITE_FENCED", rev, json!({})),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["outcome"], "ALREADY_APPLIED");
        assert_eq!(state_of(&body), ("TARGET_WRITABLE", rev_after));

        // Abort is not possible once writes are enabled.
        let (status, body) = admin
            .command(
                "tgt",
                "target/abort",
                command_body(op, uuid(9), "TARGET_WRITABLE", rev_after, json!({})),
            )
            .await?;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["outcome"], "INVALID_FENCE_TRANSITION");
        Ok(())
    });
    sim.run().unwrap();
}

/// A write transaction open when the fence is requested holds the drain: `InspectFence` counts
/// it, the acquisition answers `DRAINING` (202) at its deadline, and replaying the command once
/// the transaction has committed completes the fence.
#[test]
fn inspect_reports_drain_counters() {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    make_primary(&mut sim, tmp.path().to_path_buf(), Primary::default());
    sim.client("client", async {
        let admin = Admin::new(Some(ADMIN_KEY));
        admin.create_namespace("src").await?;
        let log_id = load_and_log_id(&admin, "src").await?;

        let (_, body) = admin.inspect("src").await?;
        assert_eq!(
            body["drain"],
            json!({
                "active_writers": 0,
                "read_leases": { "sql": 0, "dump": 0, "replication": 0 },
                "import_writers": 0,
            })
        );

        let conn = connect("src")?;
        let tx = conn.transaction().await?;
        tx.execute("insert into t values (2)", ()).await?;

        let (_, body) = admin.inspect("src").await?;
        assert_eq!(body["drain"]["active_writers"], 1, "{body}");

        let op = uuid(0xa);
        let acquire = command_body(
            op,
            uuid(1),
            "UNFENCED",
            0,
            json!({
                "expected_namespace_identity": { "log_id": log_id },
                "drain_policy": { "deadline_ms": 100, "on_deadline": "fail" },
            }),
        );
        let (status, body) = admin
            .command("src", "source/acquire-write-fence", acquire.clone())
            .await?;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        assert_eq!(body["outcome"], "DRAINING");
        assert_eq!(state_of(&body).0, "SOURCE_DRAINING");
        assert_eq!(body["fence"]["admission"]["write"], "closed");
        assert_eq!(body["drain"]["active_writers"], 1, "{body}");

        // The transaction admitted before the fence commits; new writes are refused.
        tx.commit().await?;
        assert!(connect("src")?
            .execute("insert into t values (3)", ())
            .await
            .is_err());

        let (status, body) = admin
            .command("src", "source/acquire-write-fence", acquire)
            .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["outcome"], "APPLIED");
        assert_eq!(state_of(&body).0, "SOURCE_WRITE_FENCED");
        assert_eq!(body["drain"]["active_writers"], 0);
        let mut rows = connect("src")?.query("select count(*) from t", ()).await?;
        let n: i64 = rows.next().await?.unwrap().get(0)?;
        assert_eq!(n, 2);
        Ok(())
    });
    sim.run().unwrap();
}

const ADOPTION_KEY: &str = "fence-adoption-key";

fn adopt_body(
    new_op: Uuid,
    cmd: Uuid,
    state: &str,
    rev: u64,
    current_op: Uuid,
) -> serde_json::Value {
    command_body(
        new_op,
        cmd,
        state,
        rev,
        json!({
            "current_operation_id": current_op.to_string(),
            "approvers": ["alice", "bob"],
            "incident_ref": "INC-1",
            "reason": "the operation's control record was lost",
        }),
    )
}

/// `AdoptFence` over HTTP (section 12): the admin credential and the adoption key header are
/// both required, two distinct approvers are required, and an adoption moves the owner and
/// nothing else. The old owner is refused afterwards and the new one finishes the operation.
#[test]
fn adopt_over_http() {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    make_primary(
        &mut sim,
        tmp.path().to_path_buf(),
        Primary {
            adoption_key: Some(ADOPTION_KEY),
            ..Default::default()
        },
    );
    sim.client("client", async {
        let admin = Admin::new(Some(ADMIN_KEY));
        admin.create_namespace("src").await?;
        let log_id = load_and_log_id(&admin, "src").await?;
        let (old, new) = (uuid(0xa), uuid(0xb));
        let conn = connect("src")?;
        let (status, acquired) = admin
            .command(
                "src",
                "source/acquire-write-fence",
                acquire_body(old, uuid(1), &log_id),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{acquired}");
        assert_eq!(state_of(&acquired), ("SOURCE_WRITE_FENCED", 2));

        let body = adopt_body(new, uuid(2), "SOURCE_WRITE_FENCED", 2, old);
        // No key, a wrong key, and the admin credential missing.
        for key in [None, Some("not-the-key")] {
            let (status, refused) = admin.adopt("src", body.clone(), key).await?;
            assert_eq!(status, StatusCode::PRECONDITION_FAILED, "{refused}");
            assert_eq!(refused["outcome"], "FENCE_PRECONDITION_FAILED");
            assert_eq!(refused["detail"], "adoption_not_authorised", "{refused}");
            assert_eq!(state_of(&refused), ("SOURCE_WRITE_FENCED", 2), "{refused}");
        }
        let (status, _) = Admin::new(None)
            .adopt("src", body.clone(), Some(ADOPTION_KEY))
            .await?;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        // One approver, the same approver twice, and an unknown field.
        for approvers in [json!(["alice"]), json!(["alice", "alice"])] {
            let mut bad = adopt_body(new, uuid(3), "SOURCE_WRITE_FENCED", 2, old);
            bad["approvers"] = approvers;
            let (status, refused) = admin.adopt("src", bad, Some(ADOPTION_KEY)).await?;
            assert_eq!(status, StatusCode::PRECONDITION_FAILED, "{refused}");
            assert_eq!(refused["detail"], "adoption_not_authorised", "{refused}");
        }
        let mut bad = adopt_body(new, uuid(3), "SOURCE_WRITE_FENCED", 2, old);
        bad["gate"] = json!("open");
        let (status, refused) = admin.adopt("src", bad, Some(ADOPTION_KEY)).await?;
        assert_eq!(status, StatusCode::PRECONDITION_FAILED, "{refused}");
        assert_eq!(refused["detail"], "invalid_argument", "{refused}");

        let (status, adopted) = admin.adopt("src", body.clone(), Some(ADOPTION_KEY)).await?;
        assert_eq!(status, StatusCode::OK, "{adopted}");
        assert_eq!(adopted["outcome"], "APPLIED");
        assert_eq!(adopted["replayed"], false);
        assert_eq!(state_of(&adopted), ("SOURCE_WRITE_FENCED", 3));
        assert_eq!(adopted["fence"]["operation_id"], new.to_string());
        assert_eq!(adopted["fence"]["admission"]["write"], "closed");
        assert_eq!(adopted["fence"]["admission"]["read"], "open");
        assert_eq!(
            adopted["fence"]["frozen_boundary"],
            acquired["fence"]["frozen_boundary"]
        );
        assert_eq!(adopted["receipt"]["command"], "AdoptFence");
        let adoption = &adopted["receipt"]["adoption"];
        assert_eq!(adoption["previous_operation_id"], old.to_string());
        assert_eq!(adoption["new_operation_id"], new.to_string());
        assert_eq!(adoption["approvers"], json!(["alice", "bob"]));
        assert_eq!(adoption["incident_ref"], "INC-1");
        assert_eq!(adopted["fence"]["adoptions"][0], *adoption);
        // Writes stay closed; reads stay open.
        assert!(conn.execute("insert into t values (2)", ()).await.is_err());
        conn.query("select * from t", ()).await?;

        // A replay returns the stored receipt, even without the key.
        let (status, replay) = admin.adopt("src", body.clone(), None).await?;
        assert_eq!(status, StatusCode::OK, "{replay}");
        assert_eq!(replay["replayed"], true);
        assert_eq!(replay["receipt"], adopted["receipt"]);

        // The old owner is refused; the new owner finishes the operation.
        let (status, refused) = admin
            .command(
                "src",
                "source/release-write-fence",
                command_body(old, uuid(4), "SOURCE_WRITE_FENCED", 3, json!({})),
            )
            .await?;
        assert_eq!(status, StatusCode::CONFLICT, "{refused}");
        assert_eq!(refused["outcome"], "FENCE_OWNED_BY_ANOTHER_OPERATION");
        let (status, released) = admin
            .command(
                "src",
                "source/release-write-fence",
                command_body(new, uuid(5), "SOURCE_WRITE_FENCED", 3, json!({})),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{released}");
        assert_eq!(state_of(&released), ("RELEASED", 4));
        conn.execute("insert into t values (3)", ()).await?;

        // A finished operation cannot be adopted.
        let (status, refused) = admin
            .adopt(
                "src",
                adopt_body(uuid(0xc), uuid(6), "RELEASED", 4, new),
                Some(ADOPTION_KEY),
            )
            .await?;
        assert_eq!(status, StatusCode::CONFLICT, "{refused}");
        assert_eq!(refused["outcome"], "INVALID_FENCE_TRANSITION");
        assert_eq!(refused["detail"], "operation_finished", "{refused}");
        Ok(())
    });
    sim.run().unwrap();
}

/// Without `--namespace-fence-adoption-key`, adoption is disabled whatever the request presents.
#[test]
fn adopt_disabled_without_key() {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    make_primary(&mut sim, tmp.path().to_path_buf(), Primary::default());
    sim.client("client", async {
        let admin = Admin::new(Some(ADMIN_KEY));
        admin.create_namespace("src").await?;
        let log_id = load_and_log_id(&admin, "src").await?;
        let (status, acquired) = admin
            .command(
                "src",
                "source/acquire-write-fence",
                acquire_body(uuid(0xa), uuid(1), &log_id),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{acquired}");
        for key in [None, Some(""), Some(ADOPTION_KEY)] {
            let (status, refused) = admin
                .adopt(
                    "src",
                    adopt_body(uuid(0xb), uuid(2), "SOURCE_WRITE_FENCED", 2, uuid(0xa)),
                    key,
                )
                .await?;
            assert_eq!(status, StatusCode::PRECONDITION_FAILED, "{refused}");
            assert_eq!(refused["detail"], "adoption_not_authorised", "{refused}");
            assert_eq!(refused["fence"]["operation_id"], uuid(0xa).to_string());
        }
        Ok(())
    });
    sim.run().unwrap();
}
