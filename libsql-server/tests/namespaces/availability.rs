use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use hyper::{service::make_service_fn, Body, Response, StatusCode};
use libsql::Database;
use serde_json::json;
use tempfile::tempdir;
use tokio::sync::Notify;
use tower::service_fn;
use turmoil::Builder;

use crate::common::http::Client;
use crate::common::net::{TurmoilAcceptor, TurmoilConnector};

use super::make_primary_configured;

#[test]
fn pending_dump_does_not_block_unrelated_admin_or_default() {
    let tmp = tempdir().unwrap();
    let dbs = tmp.path().join("dbs");
    let mut sim = Builder::new()
        .simulation_duration(Duration::from_secs(1000))
        .build();
    make_primary_configured(&mut sim, tmp.path().to_path_buf(), false, false);
    let release = Arc::new(Notify::new());
    let host_release = release.clone();
    sim.host("slow-dump", move || {
        let release = host_release.clone();
        async move {
            let incoming = TurmoilAcceptor::bind(([0, 0, 0, 0], 8080)).await?;
            let server =
                hyper::server::Server::builder(incoming).serve(make_service_fn(move |_conn| {
                    let release = release.clone();
                    async move {
                        Ok::<_, Infallible>(service_fn(move |_request| {
                            let release = release.clone();
                            async move {
                                let (mut sender, body) = Body::channel();
                                tokio::spawn(async move {
                                    release.notified().await;
                                    let _ = sender
                                        .send_data(
                                            "BEGIN TRANSACTION; CREATE TABLE slow (v); COMMIT;"
                                                .into(),
                                        )
                                        .await;
                                });
                                Ok::<_, Infallible>(Response::new(body))
                            }
                        }))
                    }
                }));
            server.await.unwrap();
            Ok(())
        }
    });
    sim.client("client", async move {
        let client = Client::new();
        assert!(client
            .post("http://primary:9090/v1/namespaces/victim/create", json!({}))
            .await?
            .status()
            .is_success());
        let slow = tokio::spawn(async {
            Client::new()
                .post(
                    "http://primary:9090/v1/namespaces/slow/create",
                    json!({"dump_url": "http://slow-dump:8080/"}),
                )
                .await
        });
        // The directory is reserved only after create entered NamespaceStore;
        // waiting for that fact avoids mistaking a delayed HTTP fetch for a
        // held operation lock. This timeout is a test deadlock guard.
        tokio::time::timeout(Duration::from_secs(5), async {
            while !dbs.join("slow").exists() {
                // A continuously ready yield loop can starve Turmoil's
                // virtual clock and the other simulated hosts.
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await?;
        tokio::time::timeout(Duration::from_secs(5), async {
            assert_eq!(
                client
                    .post(
                        "http://primary:9090/v1/namespaces/unrelated/create",
                        json!({})
                    )
                    .await?
                    .status(),
                StatusCode::OK
            );
            assert!(client
                .delete("http://primary:9090/v1/namespaces/victim", json!({}))
                .await?
                .status()
                .is_success());
            let default = Database::open_remote_with_connector(
                "http://default.primary:8080",
                "",
                TurmoilConnector,
            )?;
            default.connect()?.execute("select 1", ()).await?;
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        let duplicate = tokio::spawn(async {
            Client::new()
                .post("http://primary:9090/v1/namespaces/slow/create", json!({}))
                .await
        });
        tokio::task::yield_now().await;
        assert!(!slow.is_finished());
        // A duplicate must either wait or reject; it must never take over the
        // reserved directory while the dump is still in flight.
        if duplicate.is_finished() {
            assert_eq!(duplicate.await??.status(), StatusCode::BAD_REQUEST);
        } else {
            release.notify_one();
            assert_eq!(slow.await??.status(), StatusCode::OK);
            assert_eq!(duplicate.await??.status(), StatusCode::BAD_REQUEST);
            return Ok(());
        }
        release.notify_one();
        assert_eq!(slow.await??.status(), StatusCode::OK);
        Ok(())
    });
    sim.run().unwrap();
}
