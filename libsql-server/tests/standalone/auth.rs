use std::time::Duration;

use hyper::header::HeaderName;
use libsql::Database;

use crate::common::auth::{encode, key_pair};
use crate::common::http::Client;
use crate::common::net::TurmoilConnector;

use super::make_standalone_server;

#[test]
fn jwt_auth_namespace_access() {
    let mut sim = turmoil::Builder::new()
        .simulation_duration(Duration::from_secs(1000))
        .build();

    sim.host("primary", make_standalone_server);

    sim.client("test", async {
        let client = Client::new();

        let (enc, jwt_key) = key_pair();

        assert!(client
            .post(
                "http://primary:9090/v1/namespaces/foo/create",
                serde_json::json!({ "jwt_key": jwt_key })
            )
            .await
            .unwrap()
            .status()
            .is_success());

        let claims = serde_json::json!({
            "id": "foo",
        });
        let token = encode(&claims, &enc);

        let foo_db = Database::open_remote_with_connector(
            "http://foo.primary:8080",
            &token,
            TurmoilConnector,
        )?;
        let foo_conn = foo_db.connect().unwrap();
        foo_conn.execute("SELECT 1", ()).await.unwrap();

        Ok(())
    });

    sim.run().unwrap();
}

/// The path-routed Hrana endpoint authorizes statements against the namespace in the URL.
/// A namespace header on the same request must not change which namespace is authorized.
#[test]
fn jwt_auth_path_route_authorizes_path_namespace() {
    let mut sim = turmoil::Builder::new()
        .simulation_duration(Duration::from_secs(1000))
        .build();

    sim.host("primary", make_standalone_server);

    sim.client("test", async {
        let client = Client::new();

        let (enc, jwt_key) = key_pair();

        for ns in ["mine", "other"] {
            assert!(client
                .post(
                    &format!("http://primary:9090/v1/namespaces/{ns}/create"),
                    serde_json::json!({ "jwt_key": jwt_key })
                )
                .await
                .unwrap()
                .status()
                .is_success());
        }

        let claims = serde_json::json!({
            "p": {
                "rw": { "ns": ["mine"] },
                "ro": { "ns": ["other"] },
            },
        });
        let token = encode(&claims, &enc);
        let bearer = format!("Bearer {token}");
        let create_table = serde_json::json!({
            "requests": [
                { "type": "execute", "stmt": { "sql": "create table t (x)" } },
                { "type": "close" }
            ]
        });

        // The token may write `mine` through the path route.
        let resp = client
            .post_with_headers(
                "http://primary:8080/dev/mine/v3/pipeline",
                &[(hyper::header::AUTHORIZATION, bearer.as_str())],
                &create_table,
            )
            .await
            .unwrap();
        assert!(resp.status().is_success());
        let body = resp.json_value().await.unwrap();
        assert_eq!(
            body["results"][0]["type"], "ok",
            "write to own namespace rejected: {body}"
        );

        // `other` in the path, with a header naming a different namespace.
        let resp = client
            .post_with_headers(
                "http://primary:8080/dev/other/v3/pipeline",
                &[
                    (hyper::header::AUTHORIZATION, bearer.as_str()),
                    (HeaderName::from_static("x-namespace"), "mine"),
                ],
                &create_table,
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            hyper::StatusCode::FORBIDDEN,
            "write to other through the path route was not rejected"
        );
        let body = resp.body_string().await.unwrap();
        assert!(
            body.contains("Write permission to namespace other"),
            "unexpected error: {body}"
        );

        // The other namespace is untouched.
        let other_db = Database::open_remote_with_connector(
            "http://other.primary:8080",
            &token,
            TurmoilConnector,
        )?;
        let other_conn = other_db.connect().unwrap();
        let mut rows = other_conn
            .query("select count(*) from sqlite_master where name = 't'", ())
            .await
            .unwrap();
        let count = rows.next().await.unwrap().unwrap().get::<i64>(0).unwrap();
        assert_eq!(count, 0, "table was created in the other namespace");

        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn jwt_auth_gid_scope() {
    std::env::set_var("LIBSQL_GID", "my_gid");
    let mut sim = turmoil::Builder::new()
        .simulation_duration(Duration::from_secs(1000))
        .build();

    sim.host("primary", make_standalone_server);

    sim.client("test", async {
        let client = Client::new();

        let (enc, jwt_key) = key_pair();

        assert!(client
            .post(
                "http://primary:9090/v1/namespaces/foo/create",
                serde_json::json!({ "jwt_key": jwt_key })
            )
            .await
            .unwrap()
            .status()
            .is_success());

        {
            let claims = serde_json::json!({
                "p": {
                    "ro": {
                        "tags": ["my_gid"]
                    }
                },
            });
            let token = encode(&claims, &enc);
            let foo_db = Database::open_remote_with_connector(
                "http://foo.primary:8080",
                &token,
                TurmoilConnector,
            )?;
            let foo_conn = foo_db.connect().unwrap();
            foo_conn.execute("SELECT 1", ()).await.unwrap();
            foo_conn
                .execute("create table test (c)", ())
                .await
                .unwrap_err();
        }

        {
            let claims = serde_json::json!({
                "p": {
                    "ro": {
                        "tags": ["other_gid"]
                    }
                },
            });
            let token = encode(&claims, &enc);
            let foo_db = Database::open_remote_with_connector(
                "http://foo.primary:8080",
                &token,
                TurmoilConnector,
            )?;
            let foo_conn = foo_db.connect().unwrap();
            foo_conn.execute("SELECT 1", ()).await.unwrap_err();
            foo_conn
                .execute("create table test (c)", ())
                .await
                .unwrap_err();
        }

        Ok(())
    });

    sim.run().unwrap();
}
