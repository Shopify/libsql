//! Typed fence outcomes on the user-facing protocols: the legacy HTTP API, Hrana over HTTP
//! (`/v1`, `/v2`, `/v3`, cursors), Hrana over WebSocket and `/dump`
//! (`docs/NAMESPACE_FENCE.md` section 6; section 17 rows 3 and 18).

use futures::SinkExt as _;
use hyper::{Body, Method, Request, StatusCode};
use serde_json::{json, Value};
use tempfile::tempdir;
use tokio_stream::StreamExt as _;
use tokio_tungstenite::tungstenite::{self, client::IntoClientRequest};
use turmoil::net::TcpStream;
use uuid::Uuid;

use super::{
    acquire_body, command_body, load_and_log_id, make_primary, make_replica, sim, state_of, Admin,
    Primary, ADMIN_KEY,
};
use crate::common::net::TurmoilConnector;

const WRITE_FENCED: &str = "MIGRATION_WRITE_FENCED";
const READ_FENCED: &str = "MIGRATION_READ_FENCED";
const QUARANTINED: &str = "MIGRATION_TARGET_QUARANTINED";
const UNAVAILABLE: &str = "FENCE_STATE_UNAVAILABLE";

fn uuid(n: u128) -> Uuid {
    Uuid::from_u128(n)
}

/// The user API of `primary` (or of another host), for any namespace, with an optional
/// basic-auth credential.
struct User {
    client: hyper::Client<TurmoilConnector, Body>,
    auth: Option<String>,
    host: &'static str,
}

impl User {
    fn new() -> Self {
        Self::with_auth(None)
    }

    fn with_auth(credential: Option<&str>) -> Self {
        Self {
            client: hyper::Client::builder().build(TurmoilConnector),
            auth: credential.map(|c| format!("basic {c}")),
            host: "primary",
        }
    }

    /// The user API of `host` instead.
    fn on(host: &'static str) -> Self {
        Self {
            host,
            ..Self::new()
        }
    }

    async fn request(
        &self,
        method: Method,
        ns: &str,
        path: &str,
        body: Option<Value>,
    ) -> anyhow::Result<(StatusCode, String)> {
        let mut request = Request::builder()
            .method(method)
            .uri(format!("http://{ns}.{}:8080{path}", self.host));
        if let Some(auth) = &self.auth {
            request = request.header("authorization", auth.as_str());
        }
        let request = match body {
            Some(body) => request
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body)?))?,
            None => request.body(Body::empty())?,
        };
        let response = self.client.request(request).await?;
        let status = response.status();
        let body = hyper::body::to_bytes(response.into_body()).await?;
        Ok((status, String::from_utf8_lossy(&body).into_owned()))
    }

    async fn post(&self, ns: &str, path: &str, body: Value) -> anyhow::Result<(StatusCode, Value)> {
        let (status, body) = self.request(Method::POST, ns, path, Some(body)).await?;
        let value = serde_json::from_str(&body).unwrap_or(Value::String(body));
        Ok((status, value))
    }

    /// Legacy API: one batch of statements.
    async fn legacy(&self, ns: &str, sql: &[&str]) -> anyhow::Result<(StatusCode, Value)> {
        self.post(ns, "/", json!({ "statements": sql })).await
    }

    /// Hrana 1 over HTTP: one statement.
    async fn execute(&self, ns: &str, sql: &str) -> anyhow::Result<(StatusCode, Value)> {
        self.post(ns, "/v1/execute", json!({ "stmt": { "sql": sql } }))
            .await
    }

    /// Hrana 1 over HTTP: one batch, each statement conditional on nothing.
    async fn batch(&self, ns: &str, sql: &[&str]) -> anyhow::Result<(StatusCode, Value)> {
        self.post(ns, "/v1/batch", json!({ "batch": batch(sql) }))
            .await
    }

    /// Hrana 2/3 over HTTP: one pipeline.
    async fn pipeline(
        &self,
        ns: &str,
        version: u8,
        baton: Option<&str>,
        requests: Value,
    ) -> anyhow::Result<(StatusCode, Value)> {
        self.post(
            ns,
            &format!("/v{version}/pipeline"),
            json!({ "baton": baton, "requests": requests }),
        )
        .await
    }

    /// Hrana 3 over HTTP: a cursor over one batch, as the list of entries it returned.
    async fn cursor(&self, ns: &str, sql: &[&str]) -> anyhow::Result<(StatusCode, Vec<Value>)> {
        let (status, body) = self
            .request(
                Method::POST,
                ns,
                "/v3/cursor",
                Some(json!({ "baton": null, "batch": batch(sql) })),
            )
            .await?;
        let entries = body
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).unwrap_or(Value::String(line.into())))
            .collect();
        Ok((status, entries))
    }

    async fn dump(&self, ns: &str) -> anyhow::Result<(StatusCode, String)> {
        self.request(Method::GET, ns, "/dump", None).await
    }
}

/// A Hrana batch of unconditional steps.
fn batch(sql: &[&str]) -> Value {
    json!({ "steps": sql.iter().map(|sql| json!({ "stmt": { "sql": sql } })).collect::<Vec<_>>() })
}

fn execute_req(sql: &str) -> Value {
    json!({ "type": "execute", "stmt": { "sql": sql } })
}

fn batch_req(sql: &[&str]) -> Value {
    json!({ "type": "batch", "batch": batch(sql) })
}

/// A user-HTTP refusal by the fence: `423`, and the stable code in the additive `code` field.
#[track_caller]
fn assert_locked(what: &str, (status, body): &(StatusCode, Value), code: &str) {
    assert_eq!(*status, StatusCode::LOCKED, "{what}: {body}");
    assert_eq!(body["code"], code, "{what}: {body}");
}

/// A Hrana error object carrying `code`.
#[track_caller]
fn assert_hrana_error(what: &str, error: &Value, code: &str) {
    assert_eq!(error["code"], code, "{what}: {error}");
    assert!(
        error["message"].as_str().unwrap_or_default().contains(code),
        "{what}: {error}"
    );
}

/// `ns` created, loaded with table `t` holding one row, and write-fenced by `op`. Returns the
/// fence's revision.
async fn write_fenced(admin: &Admin, ns: &str, op: Uuid) -> anyhow::Result<u64> {
    admin.create_namespace(ns).await?;
    let log_id = load_and_log_id(admin, ns).await?;
    let (status, body) = admin
        .command(
            ns,
            "source/acquire-write-fence",
            acquire_body(op, uuid(op.as_u128() + 1), &log_id),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(state_of(&body).0, "SOURCE_WRITE_FENCED", "{body}");
    Ok(state_of(&body).1)
}

/// Runs the source command `route` from `state` at `revision` and returns the new revision.
async fn source_command(
    admin: &Admin,
    ns: &str,
    op: Uuid,
    command: u128,
    route: &str,
    (state, revision): (&str, u64),
    expect: &str,
) -> anyhow::Result<u64> {
    let (status, body) = admin
        .command(
            ns,
            route,
            command_body(
                op,
                uuid(command),
                state,
                revision,
                json!({ "drain_policy": { "deadline_ms": 5000 } }),
            ),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{route}: {body}");
    assert_eq!(state_of(&body).0, expect, "{route}: {body}");
    Ok(state_of(&body).1)
}

async fn read_fence(admin: &Admin, ns: &str, op: Uuid, revision: u64) -> anyhow::Result<u64> {
    source_command(
        admin,
        ns,
        op,
        op.as_u128() + 2,
        "source/set-read-fence",
        ("SOURCE_WRITE_FENCED", revision),
        "SOURCE_READ_FENCED",
    )
    .await
}

async fn clear_read_fence(admin: &Admin, ns: &str, op: Uuid, revision: u64) -> anyhow::Result<u64> {
    let (status, body) = admin
        .command(
            ns,
            "source/clear-read-fence",
            command_body(
                op,
                uuid(op.as_u128() + 3),
                "SOURCE_READ_FENCED",
                revision,
                json!({}),
            ),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(state_of(&body).0, "SOURCE_WRITE_FENCED", "{body}");
    Ok(state_of(&body).1)
}

async fn release(admin: &Admin, ns: &str, op: Uuid, revision: u64) -> anyhow::Result<()> {
    let (status, body) = admin
        .command(
            ns,
            "source/release-write-fence",
            command_body(
                op,
                uuid(op.as_u128() + 4),
                "SOURCE_WRITE_FENCED",
                revision,
                json!({}),
            ),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(state_of(&body).0, "RELEASED", "{body}");
    Ok(())
}

async fn quarantined_target(admin: &Admin, ns: &str, op: Uuid) -> anyhow::Result<()> {
    let (status, body) = admin
        .command(
            ns,
            "target/create-quarantined",
            command_body(op, uuid(op.as_u128() + 1), "ABSENT", 0, json!({})),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(state_of(&body).0, "TARGET_QUARANTINED", "{body}");
    Ok(())
}

/// Every user HTTP entry point answers a fence denial with `423` and the stable code, whether
/// the fence refused one statement (a write) or the whole request (a read, a quarantined
/// target, a fence state the server cannot establish).
#[test]
fn http_codes() {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    // A namespace directory whose fence marker cannot be decoded: its fence state cannot be
    // established, so the server refuses it (section 13.3).
    let broken = tmp.path().join("dbs").join("broken");
    std::fs::create_dir_all(&broken).unwrap();
    std::fs::write(broken.join(".fence"), b"garbage").unwrap();
    make_primary(&mut sim, tmp.path().to_path_buf(), Primary::default());
    sim.client("client", async {
        let admin = Admin::new(Some(ADMIN_KEY));
        let user = User::new();
        let op = uuid(0x100);
        let rev = write_fenced(&admin, "src", op).await?;

        // Write-fenced: writes are refused, reads are served.
        assert_locked(
            "legacy write",
            &user.legacy("src", &["insert into t values (2)"]).await?,
            WRITE_FENCED,
        );
        assert_locked(
            "legacy read then write",
            &user
                .legacy("src", &["select * from t", "insert into t values (2)"])
                .await?,
            WRITE_FENCED,
        );
        let (status, body) = user.legacy("src", &["select * from t"]).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_locked(
            "v1 execute write",
            &user.execute("src", "insert into t values (2)").await?,
            WRITE_FENCED,
        );
        let (status, body) = user.execute("src", "select * from t").await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        // A Hrana batch reports the refused step in its own error, as for any step error.
        let (status, body) = user
            .batch("src", &["select * from t", "insert into t values (2)"])
            .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body["result"]["step_results"][0].is_object(), "{body}");
        assert_hrana_error(
            "v1 batch write step",
            &body["result"]["step_errors"][1],
            WRITE_FENCED,
        );

        // Read-fenced: reads are refused as a whole.
        read_fence(&admin, "src", op, rev).await?;
        assert_locked(
            "legacy read",
            &user.legacy("src", &["select * from t"]).await?,
            READ_FENCED,
        );
        assert_locked(
            "v1 execute read",
            &user.execute("src", "select * from t").await?,
            READ_FENCED,
        );
        assert_locked(
            "v1 batch read",
            &user.batch("src", &["select * from t"]).await?,
            READ_FENCED,
        );

        // A quarantined target serves nothing.
        quarantined_target(&admin, "tgt", uuid(0x200)).await?;
        assert_locked(
            "legacy on target",
            &user.legacy("tgt", &["select 1"]).await?,
            QUARANTINED,
        );
        assert_locked(
            "v1 execute on target",
            &user.execute("tgt", "select 1").await?,
            QUARANTINED,
        );
        assert_locked(
            "v1 batch on target",
            &user.batch("tgt", &["select 1"]).await?,
            QUARANTINED,
        );

        // A namespace whose fence state is unknown is refused before a connection exists.
        for (what, response) in [
            ("legacy", user.legacy("broken", &["select 1"]).await?),
            ("v1 execute", user.execute("broken", "select 1").await?),
            (
                "v2 pipeline",
                user.pipeline("broken", 2, None, json!([execute_req("select 1")]))
                    .await?,
            ),
        ] {
            assert_locked(what, &response, UNAVAILABLE);
            assert_eq!(response.1["detail"], "corrupt_record", "{what}");
        }
        Ok(())
    });
    sim.run().unwrap();
}

/// Hrana over HTTP (`/v2`, `/v3`, `/v3/cursor`): a fence denial is a Hrana error with the
/// stable code, and the stream stays usable.
#[test]
fn hrana_http_codes() {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    make_primary(&mut sim, tmp.path().to_path_buf(), Primary::default());
    sim.client("client", async {
        let admin = Admin::new(Some(ADMIN_KEY));
        let user = User::new();
        let op = uuid(0x100);
        let rev = write_fenced(&admin, "src", op).await?;

        for version in [2, 3] {
            let what = format!("v{version}");
            let (status, body) = user
                .pipeline(
                    "src",
                    version,
                    None,
                    json!([
                        execute_req("insert into t values (2)"),
                        execute_req("select * from t"),
                        batch_req(&["select * from t", "insert into t values (2)"]),
                    ]),
                )
                .await?;
            assert_eq!(status, StatusCode::OK, "{what}: {body}");
            let results = &body["results"];
            assert_eq!(results[0]["type"], "error", "{what}: {body}");
            assert_hrana_error(&what, &results[0]["error"], WRITE_FENCED);
            assert_eq!(results[1]["type"], "ok", "{what}: {body}");
            assert_eq!(results[2]["type"], "ok", "{what}: {body}");
            assert_hrana_error(
                &what,
                &results[2]["response"]["result"]["step_errors"][1],
                WRITE_FENCED,
            );
            // The stream survives the denial.
            let baton = body["baton"].as_str().expect("the stream stays open");
            let (status, body) = user
                .pipeline(
                    "src",
                    version,
                    Some(baton),
                    json!([execute_req("select * from t"), { "type": "close" }]),
                )
                .await?;
            assert_eq!(status, StatusCode::OK, "{what}: {body}");
            assert_eq!(body["results"][0]["type"], "ok", "{what}: {body}");
        }
        let (status, entries) = user
            .cursor("src", &["select * from t", "insert into t values (2)"])
            .await?;
        assert_eq!(status, StatusCode::OK, "{entries:?}");
        let step_error = entries
            .iter()
            .find(|e| e["type"] == "step_error")
            .unwrap_or_else(|| panic!("no step error: {entries:?}"));
        assert_eq!(step_error["step"], 1, "{entries:?}");
        assert_hrana_error("cursor write step", &step_error["error"], WRITE_FENCED);

        read_fence(&admin, "src", op, rev).await?;
        for version in [2, 3] {
            let what = format!("v{version} read-fenced");
            let (status, body) = user
                .pipeline(
                    "src",
                    version,
                    None,
                    json!([
                        execute_req("select * from t"),
                        batch_req(&["select * from t"]),
                        { "type": "close" },
                    ]),
                )
                .await?;
            assert_eq!(status, StatusCode::OK, "{what}: {body}");
            let results = &body["results"];
            assert_hrana_error(&what, &results[0]["error"], READ_FENCED);
            assert_hrana_error(&what, &results[1]["error"], READ_FENCED);
            assert_eq!(results[2]["type"], "ok", "{what}: {body}");
        }
        let (status, entries) = user.cursor("src", &["select * from t"]).await?;
        assert_eq!(status, StatusCode::OK, "{entries:?}");
        let error = entries
            .iter()
            .find(|e| e["type"] == "error")
            .unwrap_or_else(|| panic!("no error entry: {entries:?}"));
        assert_hrana_error("cursor read", &error["error"], READ_FENCED);

        quarantined_target(&admin, "tgt", uuid(0x200)).await?;
        let (status, body) = user
            .pipeline("tgt", 3, None, json!([execute_req("select 1")]))
            .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_hrana_error("target", &body["results"][0]["error"], QUARANTINED);
        Ok(())
    });
    sim.run().unwrap();
}

/// Acceptance test (section 17 row 3): in a batch, the steps before a write run, the write
/// step is refused with the fence code, and conditions see the refusal as a failed step.
#[test]
fn batch_denied_mid_batch() {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    make_primary(&mut sim, tmp.path().to_path_buf(), Primary::default());
    sim.client("client", async {
        let admin = Admin::new(Some(ADMIN_KEY));
        let user = User::new();
        write_fenced(&admin, "src", uuid(0x100)).await?;

        let batch = json!({
            "steps": [
                { "stmt": { "sql": "select count(*) from t" } },
                { "stmt": { "sql": "insert into t values (2)" } },
                {
                    "condition": { "type": "ok", "step": 1 },
                    "stmt": { "sql": "insert into t values (3)" },
                },
                {
                    "condition": { "type": "not", "cond": { "type": "ok", "step": 1 } },
                    "stmt": { "sql": "select count(*) from t" },
                },
            ],
        });
        let (status, body) = user
            .pipeline(
                "src",
                3,
                None,
                json!([{ "type": "batch", "batch": batch }, { "type": "close" }]),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        let result = &body["results"][0]["response"]["result"];
        let count = |step: usize| result["step_results"][step]["rows"][0][0]["value"].clone();
        assert_eq!(count(0), "1", "{body}");
        assert!(result["step_errors"][0].is_null(), "{body}");
        assert!(result["step_results"][1].is_null(), "{body}");
        assert_hrana_error("write step", &result["step_errors"][1], WRITE_FENCED);
        // The step conditional on the write did not run; the one conditional on its failure did.
        assert!(result["step_results"][2].is_null(), "{body}");
        assert!(result["step_errors"][2].is_null(), "{body}");
        assert_eq!(count(3), "1", "{body}");
        Ok(())
    });
    sim.run().unwrap();
}

type Ws = tokio_tungstenite::WebSocketStream<TcpStream>;

/// A Hrana 3 WebSocket session to `ns`, after `hello`.
async fn ws_connect(ns: &str) -> anyhow::Result<Ws> {
    let mut request = format!("ws://{ns}.primary:8080").into_client_request()?;
    request
        .headers_mut()
        .insert("sec-websocket-protocol", "hrana3".parse()?);
    let conn = TcpStream::connect("primary:8080").await?;
    let (mut ws, _) = tokio_tungstenite::client_async(request, conn).await?;
    ws.send(tungstenite::Message::Text(
        json!({ "type": "hello", "jwt": null }).to_string(),
    ))
    .await?;
    let hello = ws_next(&mut ws).await?;
    assert_eq!(hello["type"], "hello_ok", "{hello}");
    Ok(ws)
}

async fn ws_next(ws: &mut Ws) -> anyhow::Result<Value> {
    match ws.try_next().await? {
        Some(tungstenite::Message::Text(text)) => Ok(serde_json::from_str(&text)?),
        other => anyhow::bail!("unexpected WebSocket message {other:?}"),
    }
}

/// Sends one request and returns the server's answer to it.
async fn ws_request(ws: &mut Ws, request_id: u64, request: Value) -> anyhow::Result<Value> {
    ws.send(tungstenite::Message::Text(
        json!({ "type": "request", "request_id": request_id, "request": request }).to_string(),
    ))
    .await?;
    let response = ws_next(ws).await?;
    assert_eq!(response["request_id"], request_id, "{response}");
    Ok(response)
}

async fn ws_execute(ws: &mut Ws, request_id: u64, sql: &str) -> anyhow::Result<Value> {
    ws_request(
        ws,
        request_id,
        json!({ "type": "execute", "stream_id": 1, "stmt": { "sql": sql } }),
    )
    .await
}

#[track_caller]
fn assert_ws_ok(what: &str, response: &Value) {
    assert_eq!(response["type"], "response_ok", "{what}: {response}");
}

#[track_caller]
fn assert_ws_error(what: &str, response: &Value, code: &str) {
    assert_eq!(response["type"], "response_error", "{what}: {response}");
    assert_hrana_error(what, &response["error"], code);
}

/// Hrana over WebSocket: fence denials are request errors with the stable code; the connection
/// and its stream stay usable.
#[test]
fn hrana_ws_codes() {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    make_primary(&mut sim, tmp.path().to_path_buf(), Primary::default());
    sim.client("client", async {
        let admin = Admin::new(Some(ADMIN_KEY));
        let op = uuid(0x100);
        let rev = write_fenced(&admin, "src", op).await?;

        let mut ws = ws_connect("src").await?;
        let opened =
            ws_request(&mut ws, 1, json!({ "type": "open_stream", "stream_id": 1 })).await?;
        assert_ws_ok("open_stream", &opened);
        let denied = ws_execute(&mut ws, 2, "insert into t values (2)").await?;
        assert_ws_error("write", &denied, WRITE_FENCED);
        assert_ws_ok("read", &ws_execute(&mut ws, 3, "select * from t").await?);
        let batched = ws_request(
            &mut ws,
            4,
            json!({
                "type": "batch",
                "stream_id": 1,
                "batch": batch(&["select * from t", "insert into t values (2)"]),
            }),
        )
        .await?;
        assert_ws_ok("batch", &batched);
        assert_hrana_error(
            "batch write step",
            &batched["response"]["result"]["step_errors"][1],
            WRITE_FENCED,
        );

        let rev = read_fence(&admin, "src", op, rev).await?;
        let denied = ws_execute(&mut ws, 5, "select * from t").await?;
        assert_ws_error("read-fenced read", &denied, READ_FENCED);
        let denied = ws_request(
            &mut ws,
            6,
            json!({ "type": "batch", "stream_id": 1, "batch": batch(&["select * from t"]) }),
        )
        .await?;
        assert_ws_error("read-fenced batch", &denied, READ_FENCED);

        // Clearing the read fence makes the same stream readable again.
        clear_read_fence(&admin, "src", op, rev).await?;
        assert_ws_ok(
            "read after clear",
            &ws_execute(&mut ws, 7, "select * from t").await?,
        );
        Ok(())
    });
    sim.run().unwrap();
}

/// Acceptance test (section 17 row 3): a WebSocket session whose transaction began before the
/// fence cannot write while the fence holds, nor after it is released; only a transaction
/// begun after the release writes.
#[test]
fn old_ws_session_cannot_write() {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    make_primary(&mut sim, tmp.path().to_path_buf(), Primary::default());
    sim.client("client", async {
        let admin = Admin::new(Some(ADMIN_KEY));
        admin.create_namespace("src").await?;
        let log_id = load_and_log_id(&admin, "src").await?;

        let mut ws = ws_connect("src").await?;
        let opened =
            ws_request(&mut ws, 1, json!({ "type": "open_stream", "stream_id": 1 })).await?;
        assert_ws_ok("open_stream", &opened);
        assert_ws_ok("begin", &ws_execute(&mut ws, 2, "begin").await?);
        assert_ws_ok("read", &ws_execute(&mut ws, 3, "select * from t").await?);

        let op = uuid(0x100);
        let (status, body) = admin
            .command(
                "src",
                "source/acquire-write-fence",
                acquire_body(op, uuid(0x101), &log_id),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        let rev = state_of(&body).1;

        let denied = ws_execute(&mut ws, 4, "insert into t values (2)").await?;
        assert_ws_error("write while fenced", &denied, WRITE_FENCED);

        release(&admin, "src", op, rev).await?;
        // The transaction still began under the earlier write generation.
        let denied = ws_execute(&mut ws, 5, "insert into t values (3)").await?;
        assert_ws_error("write after release", &denied, WRITE_FENCED);
        assert_ws_ok("rollback", &ws_execute(&mut ws, 6, "rollback").await?);
        // A fresh transaction on the same session writes.
        assert_ws_ok(
            "fresh write",
            &ws_execute(&mut ws, 7, "insert into t values (4)").await?,
        );
        let rows = ws_execute(&mut ws, 8, "select x from t order by x").await?;
        assert_ws_ok("rows", &rows);
        let values: Vec<Value> = rows["response"]["result"]["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row[0]["value"].clone())
            .collect();
        assert_eq!(values, vec![json!("1"), json!("4")], "{rows}");
        Ok(())
    });
    sim.run().unwrap();
}

/// `/dump`: served in full under a write fence; refused with `423` and the code under a read
/// fence and on a quarantined target. (An export cancelled mid-way is an aborted response
/// body: `namespace::fence::stream::tests::dump_response_aborted_on_cancel`.)
#[test]
fn dump_codes() {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    make_primary(&mut sim, tmp.path().to_path_buf(), Primary::default());
    sim.client("client", async {
        let admin = Admin::new(Some(ADMIN_KEY));
        let user = User::new();
        let op = uuid(0x100);
        let rev = write_fenced(&admin, "src", op).await?;

        let (status, dump) = user.dump("src").await?;
        assert_eq!(status, StatusCode::OK, "{dump}");
        assert!(dump.contains("INSERT INTO t"), "{dump}");
        assert!(dump.trim_end().ends_with("COMMIT;"), "{dump}");

        read_fence(&admin, "src", op, rev).await?;
        let (status, body) = user.dump("src").await?;
        assert_locked(
            "read-fenced dump",
            &(status, serde_json::from_str(&body)?),
            READ_FENCED,
        );

        quarantined_target(&admin, "tgt", uuid(0x200)).await?;
        let (status, body) = user.dump("tgt").await?;
        assert_locked(
            "target dump",
            &(status, serde_json::from_str(&body)?),
            QUARANTINED,
        );
        Ok(())
    });
    sim.run().unwrap();
}

/// Section 17 row 18: authentication failures and missing namespaces keep their own statuses
/// and carry no fence code, so a client can tell them from a fence denial.
#[test]
fn auth_and_not_found_distinct() {
    const CREDENTIAL: &str = "dXNlcjpwYXNz";
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    make_primary(
        &mut sim,
        tmp.path().to_path_buf(),
        Primary {
            user_credential: Some(CREDENTIAL),
            ..Default::default()
        },
    );
    sim.client("client", async {
        let admin = Admin::new(Some(ADMIN_KEY));
        let user = User::with_auth(Some(CREDENTIAL));
        admin.create_namespace("src").await?;
        for sql in ["create table t (x)", "insert into t values (1)"] {
            let (status, body) = user.execute("src", sql).await?;
            assert_eq!(status, StatusCode::OK, "{body}");
        }
        let (_, body) = admin.inspect("src").await?;
        let log_id = body["fence"]["incarnation"]["current_log_id"]
            .as_str()
            .unwrap()
            .to_string();
        let (status, body) = admin
            .command(
                "src",
                "source/acquire-write-fence",
                acquire_body(uuid(0x100), uuid(0x101), &log_id),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{body}");

        let write = "insert into t values (2)";
        let anonymous = User::new();
        let wrong = User::with_auth(Some("d3Jvbmc6d3Jvbmc="));
        for (what, response, expected) in [
            (
                "no credential",
                anonymous.execute("src", write).await?,
                StatusCode::UNAUTHORIZED,
            ),
            (
                "wrong credential",
                wrong.execute("src", write).await?,
                StatusCode::UNAUTHORIZED,
            ),
            (
                "no credential, legacy",
                anonymous.legacy("src", &[write]).await?,
                StatusCode::UNAUTHORIZED,
            ),
            (
                "no credential, v3",
                anonymous
                    .pipeline("src", 3, None, json!([execute_req(write)]))
                    .await?,
                StatusCode::UNAUTHORIZED,
            ),
            (
                "missing namespace",
                user.execute("nope", write).await?,
                StatusCode::NOT_FOUND,
            ),
            (
                "missing namespace, v3",
                user.pipeline("nope", 3, None, json!([execute_req(write)]))
                    .await?,
                StatusCode::NOT_FOUND,
            ),
        ] {
            let (status, body) = &response;
            assert_eq!(*status, expected, "{what}: {body}");
            assert!(
                body.get("code").map_or(true, |code| !code
                    .as_str()
                    .unwrap_or_default()
                    .starts_with("MIGRATION_")
                    && code != UNAVAILABLE),
                "{what}: {body}"
            );
        }
        // With the credential, on the existing namespace, it is the fence that answers.
        assert_locked(
            "fenced write",
            &user.execute("src", write).await?,
            WRITE_FENCED,
        );
        assert_locked(
            "fenced legacy write",
            &user.legacy("src", &[write]).await?,
            WRITE_FENCED,
        );
        let (status, body) = user
            .pipeline("src", 3, None, json!([execute_req(write)]))
            .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_hrana_error(
            "fenced v3 write",
            &body["results"][0]["error"],
            WRITE_FENCED,
        );
        Ok(())
    });
    sim.run().unwrap();
}

/// The replica's count of writes it delegated to the primary for `ns`.
async fn delegated_writes(ns: &str) -> anyhow::Result<u64> {
    let resp = crate::common::http::Client::new()
        .get(&format!("http://replica0:9090/v1/namespaces/{ns}/stats"))
        .await?;
    let body: Value = resp.json().await?;
    body["write_requests_delegated"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("no write_requests_delegated: {body}"))
}

/// A write sent to a replica is proxied to the primary; when the primary's fence refuses it,
/// the replica answers with the primary's denial: `423` and the stable code on HTTP, the
/// stable code as the Hrana error code (section 6.1). Reads stay local and are served, and
/// writes through the replica work again once the fence is released.
#[test]
fn replica_proxy_preserves_code() {
    let mut sim = sim();
    let primary = tempdir().unwrap();
    let replica = tempdir().unwrap();
    make_primary(&mut sim, primary.path().to_path_buf(), Primary::default());
    make_replica(&mut sim, replica.path().to_path_buf());
    sim.client("client", async {
        let admin = Admin::new(Some(ADMIN_KEY));
        let user = User::on("replica0");
        let op = uuid(0x100);
        let rev = write_fenced(&admin, "src", op).await?;
        let write = "insert into t values (2)";

        assert_locked(
            "legacy write",
            &user.legacy("src", &[write]).await?,
            WRITE_FENCED,
        );
        assert_locked(
            "v1 execute",
            &user.execute("src", write).await?,
            WRITE_FENCED,
        );
        // A refused step of a `/v1` batch is a step error, as on the primary.
        let (status, body) = user.batch("src", &["select 1", write]).await?;
        assert_eq!(status, StatusCode::OK, "v1 batch: {body}");
        assert!(
            body["result"]["step_errors"][0].is_null(),
            "v1 batch: {body}"
        );
        assert_hrana_error("v1 batch", &body["result"]["step_errors"][1], WRITE_FENCED);
        for version in [2, 3] {
            let what = format!("v{version}");
            let (status, body) = user
                .pipeline(
                    "src",
                    version,
                    None,
                    json!([execute_req(write), execute_req("select * from t")]),
                )
                .await?;
            assert_eq!(status, StatusCode::OK, "{what}: {body}");
            let results = &body["results"];
            assert_eq!(results[0]["type"], "error", "{what}: {body}");
            assert_hrana_error(&what, &results[0]["error"], WRITE_FENCED);
            assert_eq!(results[1]["type"], "ok", "{what}: {body}");
        }
        let (status, body) = user.legacy("src", &["select count(*) from t"]).await?;
        assert_eq!(status, StatusCode::OK, "{body}");

        release(&admin, "src", op, rev).await?;
        let (status, body) = user.execute("src", write).await?;
        assert_eq!(status, StatusCode::OK, "after release: {body}");
        Ok(())
    });
    sim.run().unwrap();
}

/// A fence denial is final for the request: the replica delegates each refused write to the
/// primary exactly once and answers at once, with no reconnect or retry (the write proxy's
/// only retry, of `UNAVAILABLE`, backs off 500 ms first).
#[test]
fn denial_not_retried() {
    let mut sim = sim();
    let primary = tempdir().unwrap();
    let replica = tempdir().unwrap();
    make_primary(&mut sim, primary.path().to_path_buf(), Primary::default());
    make_replica(&mut sim, replica.path().to_path_buf());
    sim.client("client", async {
        let admin = Admin::new(Some(ADMIN_KEY));
        let user = User::on("replica0");
        write_fenced(&admin, "src", uuid(0x100)).await?;
        // Load the namespace on the replica.
        let (status, body) = user.legacy("src", &["select 1"]).await?;
        assert_eq!(status, StatusCode::OK, "{body}");

        let before = delegated_writes("src").await?;
        for i in 0..3u64 {
            let started = tokio::time::Instant::now();
            assert_locked(
                "write",
                &user.execute("src", "insert into t values (2)").await?,
                WRITE_FENCED,
            );
            assert!(
                started.elapsed() < std::time::Duration::from_millis(500),
                "{:?}",
                started.elapsed()
            );
            assert_eq!(delegated_writes("src").await?, before + i + 1);
        }
        Ok(())
    });
    sim.run().unwrap();
}

/// The primary's internal replication service (the one replica servers use), as a raw client
/// that sees statuses and their metadata.
struct Replication {
    client: libsql_replication::rpc::replication::replication_log_client::ReplicationLogClient<
        tonic::transport::Channel,
    >,
    ns: String,
    token: Option<bytes::Bytes>,
}

impl Replication {
    fn new(ns: &str) -> anyhow::Result<Self> {
        use tower::ServiceExt as _;
        let uri = tonic::transport::Uri::from_static("http://primary:4567");
        let channel = tonic::transport::Channel::builder(uri.clone()).connect_with_connector_lazy(
            TurmoilConnector.map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() }),
        );
        Ok(Self {
            client: libsql_replication::rpc::replication::replication_log_client::ReplicationLogClient::with_origin(channel, uri),
            ns: ns.into(),
            token: None,
        })
    }

    fn request<T>(&self, msg: T) -> tonic::Request<T> {
        use libsql_replication::rpc::replication::{NAMESPACE_METADATA_KEY, SESSION_TOKEN_KEY};
        let mut req = tonic::Request::new(msg);
        req.metadata_mut().insert_bin(
            NAMESPACE_METADATA_KEY,
            tonic::metadata::BinaryMetadataValue::from_bytes(self.ns.as_bytes()),
        );
        if let Some(token) = &self.token {
            req.metadata_mut().insert(
                SESSION_TOKEN_KEY,
                tonic::metadata::AsciiMetadataValue::try_from(token.as_ref()).unwrap(),
            );
        }
        req
    }

    /// `hello`; on success keeps the session token and returns the replicated fence.
    async fn hello(
        &mut self,
    ) -> Result<Option<libsql_replication::rpc::metadata::ReplicatedFence>, tonic::Status> {
        let req = self.request(libsql_replication::rpc::replication::HelloRequest::new());
        let hello = self.client.hello(req).await?.into_inner();
        self.token = Some(hello.session_token.clone());
        Ok(hello.config.and_then(|c| c.fence))
    }

    fn offset(&self) -> tonic::Request<libsql_replication::rpc::replication::LogOffset> {
        self.request(libsql_replication::rpc::replication::LogOffset {
            next_offset: 0,
            wal_flavor: None,
        })
    }

    async fn log_entries(
        &mut self,
    ) -> Result<tonic::Streaming<libsql_replication::rpc::replication::Frame>, tonic::Status> {
        let req = self.offset();
        Ok(self.client.log_entries(req).await?.into_inner())
    }

    async fn snapshot(
        &mut self,
    ) -> Result<tonic::Streaming<libsql_replication::rpc::replication::Frame>, tonic::Status> {
        let req = self.offset();
        Ok(self.client.snapshot(req).await?.into_inner())
    }
}

/// A status in the typed form of section 6: `FAILED_PRECONDITION`, the stable code in
/// `x-libsql-fence-code`, and the code prefixing the message.
#[track_caller]
fn assert_fence_status(what: &str, status: &tonic::Status, code: &str) {
    assert_eq!(
        status.code(),
        tonic::Code::FailedPrecondition,
        "{what}: {status:?}"
    );
    assert_eq!(
        status
            .metadata()
            .get("x-libsql-fence-code")
            .and_then(|v| v.to_str().ok()),
        Some(code),
        "{what}: {status:?}"
    );
    assert!(status.message().starts_with(code), "{what}: {status:?}");
}

/// Replication as a raw peer of the primary sees it (sections 6.2 and 9): `hello` carries the
/// replicated fence while the primary admits replication; under a read fence an open stream
/// ends with the typed status and every call is refused with it; a quarantined target refuses
/// with its own code; after the read fence is cleared `hello` is answered again.
#[test]
fn replication_codes() {
    let mut sim = sim();
    let tmp = tempdir().unwrap();
    make_primary(&mut sim, tmp.path().to_path_buf(), Primary::default());
    sim.client("client", async {
        let admin = Admin::new(Some(ADMIN_KEY));
        let op = uuid(0x100);
        admin.create_namespace("plain").await?;
        load_and_log_id(&admin, "plain").await?;
        assert_eq!(Replication::new("plain")?.hello().await?, None, "unfenced");

        let mut repl = Replication::new("src")?;
        let rev = write_fenced(&admin, "src", op).await?;
        let fence = repl.hello().await?.expect("hello carries the write fence");
        assert_eq!(
            (fence.state.as_str(), fence.revision),
            ("SOURCE_WRITE_FENCED", rev)
        );
        let mut tail = repl.log_entries().await?;
        let frame = tail
            .next()
            .await
            .expect("a frame")
            .expect("frames are served");
        assert!(!frame.data.is_empty());

        let rev = read_fence(&admin, "src", op, rev).await?;
        // The open stream ends with the terminal status (frames already buffered first).
        let ended = loop {
            match tail.next().await {
                Some(Ok(_)) => continue,
                Some(Err(status)) => break status,
                None => panic!("the stream ended without a status"),
            }
        };
        assert_fence_status("open log_entries", &ended, READ_FENCED);
        assert!(tail.next().await.is_none());
        assert_fence_status("hello", &repl.hello().await.unwrap_err(), READ_FENCED);
        assert_fence_status(
            "log_entries",
            &repl.log_entries().await.unwrap_err(),
            READ_FENCED,
        );
        assert_fence_status("snapshot", &repl.snapshot().await.unwrap_err(), READ_FENCED);

        let rev = clear_read_fence(&admin, "src", op, rev).await?;
        let fence = repl.hello().await?.expect("hello carries the write fence");
        assert_eq!(
            (fence.state.as_str(), fence.revision),
            ("SOURCE_WRITE_FENCED", rev)
        );
        release(&admin, "src", op, rev).await?;
        assert_eq!(repl.hello().await?, None, "released");

        quarantined_target(&admin, "dst", uuid(0x200)).await?;
        let mut target = Replication::new("dst")?;
        assert_fence_status(
            "target hello",
            &target.hello().await.unwrap_err(),
            QUARANTINED,
        );
        Ok(())
    });
    sim.run().unwrap();
}

/// The first `/v2` result of `sql` on `user`'s host: `Ok(())` or the Hrana error code.
async fn v2_read(user: &User, ns: &str, sql: &str) -> anyhow::Result<Result<(), String>> {
    let (status, body) = user
        .pipeline(ns, 2, None, json!([execute_req(sql)]))
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let result = &body["results"][0];
    Ok(match result["type"].as_str() {
        Some("ok") => Ok(()),
        _ => Err(result["error"]["code"]
            .as_str()
            .unwrap_or_else(|| panic!("no error code: {body}"))
            .to_string()),
    })
}

/// Poll the legacy API on `user`'s host with `sql` until it answers `status`, for at most
/// `within` of simulated time, and return that answer and how long it took.
async fn poll_until(
    user: &User,
    ns: &str,
    sql: &str,
    status: StatusCode,
    within: std::time::Duration,
) -> anyhow::Result<(Value, std::time::Duration)> {
    let started = tokio::time::Instant::now();
    loop {
        let (got, body) = user.legacy(ns, &[sql]).await?;
        if got == status {
            return Ok((body, started.elapsed()));
        }
        assert!(
            started.elapsed() < within,
            "still {got} after {:?}: {body}",
            started.elapsed()
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// `src` write-fenced on the primary and loaded on the replica, then read-fenced; returns once
/// the replica denies local reads, with the fence's revision.
async fn replica_read_fenced(admin: &Admin, replica: &User, op: Uuid) -> anyhow::Result<u64> {
    let rev = write_fenced(admin, "src", op).await?;
    let (status, body) = replica.legacy("src", &["select count(*) from t"]).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "replica before the read fence: {body}"
    );
    let rev = read_fence(admin, "src", op, rev).await?;
    // The replica learns of the fence when its replication stream ends, which the primary's
    // read drain waits for; the denial is published as the terminal status arrives.
    let (body, took) = poll_until(
        replica,
        "src",
        "select count(*) from t",
        StatusCode::LOCKED,
        std::time::Duration::from_secs(2),
    )
    .await?;
    assert_eq!(body["code"], READ_FENCED, "{body}");
    assert!(
        took < std::time::Duration::from_millis(500),
        "took {took:?}"
    );
    Ok(rev)
}

/// A replica server denies local reads of a namespace whose primary is read-fenced, on every
/// read surface, with the primary's code (section 6.2).
#[test]
fn replica_reads_denied_while_source_read_fenced() {
    let mut sim = sim();
    let primary = tempdir().unwrap();
    let replica = tempdir().unwrap();
    make_primary(&mut sim, primary.path().to_path_buf(), Primary::default());
    make_replica(&mut sim, replica.path().to_path_buf());
    sim.client("client", async {
        let admin = Admin::new(Some(ADMIN_KEY));
        let user = User::on("replica0");
        replica_read_fenced(&admin, &user, uuid(0x100)).await?;

        assert_locked(
            "legacy read",
            &user.legacy("src", &["select * from t"]).await?,
            READ_FENCED,
        );
        assert_locked(
            "v1 execute",
            &user.execute("src", "select * from t").await?,
            READ_FENCED,
        );
        assert_eq!(
            v2_read(&user, "src", "select * from t").await?,
            Err(READ_FENCED.to_string())
        );
        // `/dump` is not served by a replica server at all ("database is not a primary").
        // Still denied later: the replica does not forget while the primary keeps refusing.
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        assert_locked(
            "legacy read later",
            &user.legacy("src", &["select * from t"]).await?,
            READ_FENCED,
        );
        Ok(())
    });
    sim.run().unwrap();
}

/// While the primary's fence refuses replication, the replica retries at a growing interval
/// capped at 15 s, not every second or in a tight loop: over 60 s of simulated time it makes
/// a handful of attempts (1 + 2 + 4 + 8 + 15 + 15 + 15 s of pauses), each counted.
#[test]
fn replica_backs_off_on_fence_code() {
    let mut sim = sim();
    let primary = tempdir().unwrap();
    let replica = tempdir().unwrap();
    make_primary(&mut sim, primary.path().to_path_buf(), Primary::default());
    make_replica(&mut sim, replica.path().to_path_buf());
    sim.client("client", async {
        let admin = Admin::new(Some(ADMIN_KEY));
        let user = User::on("replica0");
        replica_read_fenced(&admin, &user, uuid(0x100)).await?;

        let refusals = || {
            crate::common::snapshot_metrics()
                .get_counter_label(
                    "libsql_server_replica_fence_refusals_total",
                    ("code", READ_FENCED),
                )
                .unwrap_or(0)
        };
        let before = refusals();
        assert!(before >= 1, "the ended stream is counted");
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        let attempts = refusals() - before;
        assert!(
            (4..=9).contains(&attempts),
            "{attempts} refused attempts in 60 s"
        );
        Ok(())
    });
    sim.run().unwrap();
}

/// Once the primary clears the read fence the replica answers `hello` again within the
/// back-off cap, serves local reads, and replicates new writes once the source is released.
#[test]
fn replica_resumes_after_clear_read_fence() {
    let mut sim = sim();
    let primary = tempdir().unwrap();
    let replica = tempdir().unwrap();
    make_primary(&mut sim, primary.path().to_path_buf(), Primary::default());
    make_replica(&mut sim, replica.path().to_path_buf());
    sim.client("client", async {
        let admin = Admin::new(Some(ADMIN_KEY));
        let user = User::on("replica0");
        let op = uuid(0x100);
        let rev = replica_read_fenced(&admin, &user, op).await?;
        // Let the back-off grow to its cap before clearing.
        tokio::time::sleep(std::time::Duration::from_secs(40)).await;

        let rev = clear_read_fence(&admin, "src", op, rev).await?;
        let (_, took) = poll_until(
            &user,
            "src",
            "select count(*) from t",
            StatusCode::OK,
            std::time::Duration::from_secs(20),
        )
        .await?;
        assert!(took <= std::time::Duration::from_secs(16), "took {took:?}");
        assert_eq!(v2_read(&user, "src", "select * from t").await?, Ok(()));

        release(&admin, "src", op, rev).await?;
        let (status, body) = User::new()
            .legacy("src", &["insert into t values (2)"])
            .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        let started = tokio::time::Instant::now();
        loop {
            let (status, body) = user.legacy("src", &["select count(*) from t"]).await?;
            assert_eq!(status, StatusCode::OK, "{body}");
            if body[0]["results"]["rows"][0][0] == 2 {
                break;
            }
            assert!(
                started.elapsed() < std::time::Duration::from_secs(10),
                "not replicated: {body}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        Ok(())
    });
    sim.run().unwrap();
}

/// Walks the quarantined target `ns` of `op` to `TARGET_WRITE_FENCED` (readable): seal the
/// (empty) import, record a successful validation, publish. Returns the revision.
async fn publish_target(admin: &Admin, ns: &str, op: Uuid) -> anyhow::Result<u64> {
    let (_, body) = admin.inspect(ns).await?;
    let (state, mut rev) = state_of(&body);
    assert_eq!(state, "TARGET_QUARANTINED", "{body}");
    for (n, route, from, extra, to) in [
        (
            2,
            "target/seal-import",
            "TARGET_QUARANTINED",
            json!({}),
            "TARGET_VALIDATING",
        ),
        (
            3,
            "target/validation-receipt",
            "TARGET_VALIDATING",
            json!({ "result": "ok", "summary": "empty" }),
            "TARGET_VALIDATING",
        ),
        (
            4,
            "target/publish-readable",
            "TARGET_VALIDATING",
            json!({}),
            "TARGET_WRITE_FENCED",
        ),
    ] {
        let (status, body) = admin
            .command(
                ns,
                route,
                command_body(op, uuid(op.as_u128() + n), from, rev, extra),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{route}: {body}");
        assert_eq!(state_of(&body).0, to, "{route}: {body}");
        rev = state_of(&body).1;
    }
    Ok(rev)
}

/// A replica server creating a namespace lazily, for a name the primary's fence refuses to
/// replicate (here a quarantined target), fails the request at once with the primary's code
/// instead of retrying the handshake, and leaves no local copy: no namespace directory it
/// created (a directory that was already there stays) and no metastore entry. Once the target
/// is published the same name is created and served normally (section 13.3).
#[test]
fn replica_lazy_creation_refused_by_fence() {
    let mut sim = sim();
    let primary = tempdir().unwrap();
    let replica = tempdir().unwrap();
    // A directory that was on the replica before: a refused creation must not delete it.
    let kept = replica.path().join("dbs").join("kept");
    std::fs::create_dir_all(&kept).unwrap();
    std::fs::write(kept.join("sentinel"), b"x").unwrap();
    let dbs = replica.path().join("dbs");
    make_primary(&mut sim, primary.path().to_path_buf(), Primary::default());
    make_replica(&mut sim, replica.path().to_path_buf());
    sim.client("client", async move {
        let admin = Admin::new(Some(ADMIN_KEY));
        let user = User::on("replica0");
        let op = uuid(0x100);
        quarantined_target(&admin, "tgt", op).await?;
        quarantined_target(&admin, "kept", uuid(0x200)).await?;

        for attempt in 0..2 {
            let started = tokio::time::Instant::now();
            assert_locked(
                &format!("replica read of a quarantined target, attempt {attempt}"),
                &user.legacy("tgt", &["select 1"]).await?,
                QUARANTINED,
            );
            // Refused at the first handshake, not after a second of retries per attempt.
            let took = started.elapsed();
            assert!(
                took < std::time::Duration::from_millis(500),
                "took {took:?}"
            );
            assert!(
                !dbs.join("tgt").exists(),
                "the refused creation left dbs/tgt behind"
            );
        }
        assert_locked(
            "replica read of a quarantined target with a directory",
            &user.legacy("kept", &["select 1"]).await?,
            QUARANTINED,
        );
        assert!(
            kept.join("sentinel").exists(),
            "a pre-existing directory was removed"
        );

        let rev = publish_target(&admin, "tgt", op).await?;
        let (status, body) = user.legacy("tgt", &["select 1"]).await?;
        assert_eq!(status, StatusCode::OK, "after publication: {body}");
        assert!(
            dbs.join("tgt").exists(),
            "published target not created on the replica"
        );

        // Writes through the replica reach the primary once writes are enabled.
        let (status, body) = admin
            .command(
                "tgt",
                "target/enable-writes",
                command_body(
                    op,
                    uuid(op.as_u128() + 5),
                    "TARGET_WRITE_FENCED",
                    rev,
                    json!({}),
                ),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, body) = user.legacy("tgt", &["create table t (x)"]).await?;
        assert_eq!(status, StatusCode::OK, "write through the replica: {body}");
        Ok(())
    });
    sim.run().unwrap();
}
