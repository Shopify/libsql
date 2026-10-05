//! Fence metrics over a running server (`docs/NAMESPACE_FENCE.md` section 15).

use hyper::StatusCode;
use metrics_util::debugging::DebugValue;
use metrics_util::MetricKind;
use serde_json::json;
use tempfile::tempdir;
use uuid::Uuid;

use super::{
    acquire_body, command_body, connect, load_and_log_id, make_primary, sim, state_of,
    user_execute, Admin, Primary, ADMIN_KEY,
};

fn uuid(n: u128) -> Uuid {
    Uuid::from_u128(n)
}

/// The value of the metric `name` of `kind` whose labels are exactly `labels`.
fn metric(kind: MetricKind, name: &str, labels: &[(&str, &str)]) -> Option<DebugValue> {
    let snapshot = crate::common::snapshot_metrics();
    let mut wanted: Vec<(String, String)> = labels
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    wanted.sort();
    snapshot
        .snapshot()
        .iter()
        .find(|(key, _)| {
            let mut have: Vec<(String, String)> = key
                .key()
                .labels()
                .map(|l| (l.key().to_string(), l.value().to_string()))
                .collect();
            have.sort();
            key.kind() == kind && key.key().name() == name && have == wanted
        })
        .map(|(_, (_, _, value))| match value {
            DebugValue::Counter(v) => DebugValue::Counter(*v),
            DebugValue::Gauge(v) => DebugValue::Gauge(*v),
            DebugValue::Histogram(v) => DebugValue::Histogram(v.clone()),
        })
}

#[track_caller]
fn counter(name: &str, labels: &[(&str, &str)]) -> u64 {
    match metric(MetricKind::Counter, name, labels) {
        Some(DebugValue::Counter(v)) => v,
        other => panic!("counter {name} {labels:?}: {other:?}"),
    }
}

#[track_caller]
fn gauge(name: &str, labels: &[(&str, &str)]) -> f64 {
    match metric(MetricKind::Gauge, name, labels) {
        Some(DebugValue::Gauge(v)) => v.0,
        other => panic!("gauge {name} {labels:?}: {other:?}"),
    }
}

/// After a source walk with a forced rollback, a replay, a command-id conflict and denials on
/// the user protocol and a lifecycle route, every fence metric of section 15 is present with
/// its bounded labels, and no fence metric has a label naming the namespace, the operation or
/// a command.
#[test]
fn metrics_and_labels() {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    make_primary(&mut sim, tmp.path().to_path_buf(), Primary::default());
    sim.client("client", async {
        let admin = Admin::new(Some(ADMIN_KEY));
        admin.create_namespace("src").await?;
        let log_id = load_and_log_id(&admin, "src").await?;
        let op = uuid(0xa);

        // A transaction admitted before the fence is still open at the deadline: the drain
        // rolls it back and is then proven.
        let conn = connect("src")?;
        let tx = conn.transaction().await?;
        tx.execute("insert into t values (2)", ()).await?;
        let acquire = command_body(
            op,
            uuid(1),
            "UNFENCED",
            0,
            json!({
                "expected_namespace_identity": { "log_id": log_id },
                "drain_policy": { "deadline_ms": 100, "on_deadline": "force_rollback" },
            }),
        );
        let (status, acquired) = admin
            .command("src", "source/acquire-write-fence", acquire.clone())
            .await?;
        assert_eq!(status, StatusCode::OK, "{acquired}");
        assert_eq!(state_of(&acquired).0, "SOURCE_WRITE_FENCED", "{acquired}");
        assert!(tx.commit().await.is_err());

        // A replay, and a conflict on the same command id.
        let (status, replay) = admin
            .command("src", "source/acquire-write-fence", acquire)
            .await?;
        assert_eq!(status, StatusCode::OK, "{replay}");
        assert_eq!(replay["replayed"], true);
        let (status, body) = admin
            .command(
                "src",
                "source/acquire-write-fence",
                acquire_body(op, uuid(1), &log_id),
            )
            .await?;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");

        // Denials: a write over Hrana, and a config change (a lifecycle operation) over the
        // admin API. (A delete is refused on a blocking thread, which this test's per-thread
        // metrics recorder does not see.)
        let (status, body) = user_execute("src", "insert into t values (3)").await?;
        assert_eq!(status, StatusCode::LOCKED, "{body}");
        assert_eq!(body["code"], "MIGRATION_WRITE_FENCED", "{body}");
        let (status, body) = admin
            .post(
                "/v1/namespaces/src/config",
                json!({ "block_reads": false, "block_writes": true, "block_reason": null }),
            )
            .await?;
        assert_eq!(status, StatusCode::LOCKED, "{body}");

        // The gauges are computed when `/metrics` is read.
        let (status, _) = admin.get("/metrics").await?;
        assert_eq!(status, StatusCode::OK);

        // First: a snapshot drains the recorded histogram values.
        match metric(
            MetricKind::Histogram,
            "libsql_server_fence_drain_duration_seconds",
            &[("kind", "write")],
        ) {
            Some(DebugValue::Histogram(v)) => assert_eq!(v.len(), 1),
            other => panic!("drain histogram: {other:?}"),
        }
        let acquire = ("command", "AcquireSourceWriteFence");
        assert_eq!(
            counter(
                "libsql_server_fence_transitions_total",
                &[acquire, ("outcome", "APPLIED")]
            ),
            2
        );
        assert_eq!(
            counter(
                "libsql_server_fence_transitions_total",
                &[acquire, ("outcome", "FENCE_COMMAND_CONFLICT")]
            ),
            1
        );
        assert_eq!(
            counter("libsql_server_fence_replays_total", &[("result", "replay")]),
            1
        );
        assert_eq!(
            counter(
                "libsql_server_fence_replays_total",
                &[("result", "conflict")]
            ),
            1
        );
        assert_eq!(
            counter("libsql_server_fence_forced_total", &[("kind", "rollback")]),
            1
        );
        for surface in ["hrana", "lifecycle", "http"] {
            assert!(
                counter(
                    "libsql_server_fence_denials_total",
                    &[("code", "MIGRATION_WRITE_FENCED"), ("surface", surface)]
                ) >= 1,
                "{surface}"
            );
        }
        assert_eq!(
            gauge(
                "libsql_server_fence_namespaces",
                &[("role", "source"), ("state", "SOURCE_WRITE_FENCED")]
            ),
            1.0
        );
        assert_eq!(
            gauge(
                "libsql_server_fence_namespaces",
                &[("role", "target"), ("state", "TARGET_QUARANTINED")]
            ),
            0.0
        );
        let age = gauge("libsql_server_fence_oldest_active_age_seconds", &[]);
        assert!(age >= 0.0, "{age}");

        // No fence metric carries a namespace, operation or command id as a label value.
        let forbidden = [
            "src".to_string(),
            op.to_string(),
            uuid(1).to_string(),
            log_id.clone(),
        ];
        let snapshot = crate::common::snapshot_metrics();
        let mut seen = 0;
        for (key, _) in snapshot.snapshot() {
            let name = key.key().name();
            if !name.starts_with("libsql_server_fence_") {
                continue;
            }
            seen += 1;
            for label in key.key().labels() {
                assert!(
                    matches!(
                        label.key(),
                        "command"
                            | "outcome"
                            | "kind"
                            | "result"
                            | "code"
                            | "surface"
                            | "role"
                            | "state"
                    ),
                    "{name}: unexpected label {}",
                    label.key()
                );
                assert!(
                    !forbidden.iter().any(|f| f == label.value()),
                    "{name}: {}={}",
                    label.key(),
                    label.value()
                );
            }
        }
        assert!(seen > 10, "{seen}");

        // Releasing moves the source out of the write-fenced count.
        let (status, body) = admin
            .command(
                "src",
                "source/release-write-fence",
                command_body(
                    op,
                    uuid(2),
                    "SOURCE_WRITE_FENCED",
                    state_of(&acquired).1,
                    json!({}),
                ),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        admin.get("/metrics").await?;
        assert_eq!(
            gauge(
                "libsql_server_fence_namespaces",
                &[("role", "source"), ("state", "SOURCE_WRITE_FENCED")]
            ),
            0.0
        );
        assert_eq!(
            gauge(
                "libsql_server_fence_namespaces",
                &[("role", "source"), ("state", "RELEASED")]
            ),
            1.0
        );
        assert_eq!(
            gauge("libsql_server_fence_oldest_active_age_seconds", &[]),
            0.0
        );
        Ok(())
    });
    sim.run().unwrap();
}
