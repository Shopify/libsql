//! Tests for sqld in cluster mode
#![allow(deprecated)]

use super::common;

use insta::assert_snapshot;
use libsql::{Database, Value};
use libsql_server::config::{AdminApiConfig, RpcClientConfig, RpcServerConfig, UserApiConfig};
use serde_json::json;
use tempfile::tempdir;
use tokio::{task::JoinSet, time::Duration};
use turmoil::{Builder, Sim};

use common::net::{init_tracing, TestServer, TurmoilAcceptor, TurmoilConnector};

use crate::common::{http::Client, net::SimServer, snapshot_metrics};

mod replica_restart;
mod replication;
mod schema_dbs;

type ResetControl = (
    std::sync::Arc<tokio::sync::Notify>,
    std::sync::Arc<tokio::sync::Notify>,
    std::sync::Arc<std::sync::Mutex<Option<String>>>,
);

pub fn make_cluster(sim: &mut Sim, num_replica: usize, disable_namespaces: bool) {
    make_cluster_with_options(sim, num_replica, disable_namespaces, 100, None, None);
}

fn make_cluster_with_options(
    sim: &mut Sim,
    num_replica: usize,
    disable_namespaces: bool,
    replica_capacity: usize,
    replica_fixture: Option<(
        std::path::PathBuf,
        std::sync::Arc<tokio::sync::Notify>,
        std::sync::Arc<tokio::sync::Notify>,
    )>,
    reset_control: Option<ResetControl>,
) {
    init_tracing();
    let tmp = tempdir().unwrap();
    sim.host("primary", move || {
        let path = tmp.path().to_path_buf();
        async move {
            let server = TestServer {
                path: path.into(),
                user_api_config: UserApiConfig {
                    ..Default::default()
                },
                admin_api_config: Some(AdminApiConfig {
                    acceptor: TurmoilAcceptor::bind(([0, 0, 0, 0], 9090)).await?,
                    connector: TurmoilConnector,
                    disable_metrics: true,
                    auth_key: None,
                }),
                rpc_server_config: Some(RpcServerConfig {
                    acceptor: TurmoilAcceptor::bind(([0, 0, 0, 0], 4567)).await?,
                    tls_config: None,
                }),
                disable_namespaces,
                disable_default_namespace: !disable_namespaces,
                ..Default::default()
            };

            server.start_sim(8080).await?;

            Ok(())
        }
    });

    for i in 0..num_replica {
        let tmp = tempdir().unwrap();
        let fixture = replica_fixture.clone();
        let reset_control = reset_control.clone();
        sim.host(format!("replica{i}"), move || {
            let path = fixture
                .as_ref()
                .map(|(path, _, _)| path.clone())
                .unwrap_or_else(|| tmp.path().to_path_buf());
            let shutdown = fixture.as_ref().map(|(_, shutdown, _)| shutdown.clone());
            let done = fixture.as_ref().map(|(_, _, done)| done.clone());
            let reset_control = reset_control.clone();
            async move {
                let (store_ready, store_rx) = tokio::sync::oneshot::channel();
                let store_hook = reset_control.as_ref().map(|_| store_ready);
                let server = TestServer {
                    path: path.into(),
                    user_api_config: UserApiConfig {
                        ..Default::default()
                    },
                    admin_api_config: Some(AdminApiConfig {
                        acceptor: TurmoilAcceptor::bind(([0, 0, 0, 0], 9090)).await?,
                        connector: TurmoilConnector,
                        disable_metrics: true,
                        auth_key: None,
                    }),
                    rpc_client_config: Some(RpcClientConfig {
                        remote_url: "http://primary:4567".into(),
                        connector: TurmoilConnector,
                        tls_config: None,
                    }),
                    disable_namespaces,
                    disable_default_namespace: !disable_namespaces,
                    max_active_namespaces: replica_capacity,
                    shutdown: shutdown.unwrap_or_default(),
                    namespace_store_ready: store_hook,
                    ..Default::default()
                };
                if let Some((request, finished, failure)) = reset_control {
                    tokio::spawn(async move {
                        let result = match store_rx.await {
                            Ok(store) => {
                                request.notified().await;
                                store.evict_cached_namespace(&"schema".into()).await;
                                store
                                    .reset("tenant".into(), libsql_server::RestoreOption::Latest)
                                    .await
                            }
                            Err(e) => Err(e.into()),
                        };
                        *failure.lock().unwrap() = result.err().map(|e| e.to_string());
                        finished.notify_one();
                    });
                }
                server.start_sim(8080).await.unwrap();
                if let Some(done) = done {
                    done.notify_one();
                }

                Ok(())
            }
        });
    }
}

#[test]
fn proxy_write() {
    let mut sim = Builder::new()
        .simulation_duration(Duration::from_secs(1000))
        .build();
    make_cluster(&mut sim, 1, true);

    sim.client("client", async {
        let db =
            Database::open_remote_with_connector("http://replica0:8080", "", TurmoilConnector)?;
        let conn = db.connect()?;

        conn.execute("create table test (x)", ()).await?;
        conn.execute("insert into test values (12)", ()).await?;

        // assert that the primary got the write
        let db = Database::open_remote_with_connector("http://primary:8080", "", TurmoilConnector)?;
        let conn = db.connect()?;
        let mut rows = conn.query("select count(*) from test", ()).await?;

        assert!(matches!(
            rows.next().await.unwrap().unwrap().get_value(0).unwrap(),
            Value::Integer(1)
        ));

        snapshot_metrics().assert_gauge("libsql_server_current_frame_no", 2.0);

        Ok(())
    });

    sim.run().unwrap();
}

#[test]
#[ignore = "libsql client doesn't reuse the stream yet, so we can't do RYW"]
fn replica_read_write() {
    let mut sim = Builder::new()
        .simulation_duration(Duration::from_secs(1000))
        .build();
    make_cluster(&mut sim, 1, true);

    sim.client("client", async {
        let db =
            Database::open_remote_with_connector("http://replica0:8080", "", TurmoilConnector)?;
        let conn = db.connect()?;

        conn.execute("create table test (x)", ()).await?;
        conn.execute("insert into test values (12)", ()).await?;
        let mut rows = conn.query("select count(*) from test", ()).await?;

        assert!(matches!(
            rows.next().await.unwrap().unwrap().get_value(0).unwrap(),
            Value::Integer(1)
        ));

        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn sync_many_replica() {
    const NUM_REPLICA: usize = 10;
    let mut sim = Builder::new()
        .simulation_duration(Duration::from_secs(1000))
        .build();
    make_cluster(&mut sim, NUM_REPLICA, true);
    sim.client("client", async {
        let db = Database::open_remote_with_connector("http://primary:8080", "", TurmoilConnector)?;
        let conn = db.connect()?;

        conn.execute("create table test (x)", ()).await?;
        conn.execute("insert into test values (42)", ()).await?;

        async fn get_frame_no(url: &str) -> Option<u64> {
            let client = Client::new();
            Some(
                client
                    .get(url)
                    .await
                    .unwrap()
                    .json::<serde_json::Value>()
                    .await
                    .unwrap()
                    .get("replication_index")?
                    .as_u64()
                    .unwrap(),
            )
        }

        let primary_fno = loop {
            if let Some(fno) = get_frame_no("http://primary:9090/v1/namespaces/default/stats").await
            {
                break fno;
            }
        };

        // wait for all replicas to sync
        let mut join_set = JoinSet::new();
        for i in 0..NUM_REPLICA {
            join_set.spawn(async move {
                let uri = format!("http://replica{i}:9090/v1/namespaces/default/stats");
                loop {
                    if let Some(replica_fno) = get_frame_no(&uri).await {
                        if replica_fno == primary_fno {
                            break;
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            });
        }

        while join_set.join_next().await.is_some() {}

        for i in 0..NUM_REPLICA {
            let db = Database::open_remote_with_connector(
                format!("http://replica{i}:8080"),
                "",
                TurmoilConnector,
            )?;
            let conn = db.connect()?;
            let mut rows = conn.query("select count(*) from test", ()).await?;
            assert!(matches!(
                rows.next().await.unwrap().unwrap().get_value(0).unwrap(),
                Value::Integer(1)
            ));
        }

        let client = Client::new();

        let stats = client
            .get("http://primary:9090/v1/namespaces/default/stats")
            .await?
            .json_value()
            .await
            .unwrap();

        let stat = stats
            .get("embedded_replica_frames_replicated")
            .unwrap()
            .as_u64()
            .unwrap();

        assert_eq!(stat, 0);

        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn create_namespace() {
    let mut sim = Builder::new()
        .simulation_duration(Duration::from_secs(1000))
        .build();
    make_cluster(&mut sim, 0, false);

    sim.client("client", async {
        let db =
            Database::open_remote_with_connector("http://foo.primary:8080", "", TurmoilConnector)?;
        let conn = db.connect()?;

        let Err(e) = conn.execute("create table test (x)", ()).await else {
            panic!()
        };
        assert_snapshot!(e.to_string());

        let client = Client::new();
        let resp = client
            .post(
                "http://foo.primary:9090/v1/namespaces/foo/create",
                json!({}),
            )
            .await?;

        assert_eq!(resp.status(), 200);

        conn.execute("create table test (x)", ()).await.unwrap();
        let mut rows = conn.query("select count(*) from test", ()).await.unwrap();
        assert!(matches!(
            rows.next().await.unwrap().unwrap().get_value(0).unwrap(),
            Value::Integer(0)
        ));

        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn large_proxy_query() {
    let mut sim = Builder::new()
        .simulation_duration(Duration::from_secs(10000))
        .tcp_capacity(100000)
        .build();
    make_cluster(&mut sim, 1, true);

    sim.client("client", async {
        let db = Database::open_remote_with_connector("http://primary:8080", "", TurmoilConnector)
            .unwrap();
        let conn = db.connect().unwrap();

        conn.execute("create table test (x)", ()).await.unwrap();
        for _ in 0..5000 {
            conn.execute("insert into test values (randomblob(1000))", ())
                .await
                .unwrap();
        }

        let db = Database::open_remote_with_connector("http://replica0:8080", "", TurmoilConnector)
            .unwrap();
        let conn = db.connect().unwrap();

        conn.execute_batch("begin immediate; select * from test limit (4000)")
            .await
            .unwrap();

        Ok(())
    });

    sim.run().unwrap();
}

// Schema migrations to linked tenants run asynchronously. Wait for the
// specific prerequisite, not an arbitrary delay or a successful HTTP reply.
async fn wait_for_linked_test_table(uri: &str) -> anyhow::Result<()> {
    let db = Database::open_remote_with_connector(uri, "", TurmoilConnector)?;
    loop {
        match db.connect()?.query("select * from test", ()).await {
            Ok(_) => return Ok(()),
            Err(err) if err.to_string().contains("no such table") => {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(err) => return Err(err.into()),
        }
    }
}

#[test]
fn replica_reset_loads_uncached_shared_schema_without_identity_lock_deadlock() {
    use std::sync::Arc;
    use tokio::sync::Notify;

    let replica_dir = tempdir().unwrap();
    let marker = replica_dir.path().join("dbs/tenant/reset-marker");
    let stop = Arc::new(Notify::new());
    let done = Arc::new(Notify::new());
    let mut sim = Builder::new()
        .simulation_duration(Duration::from_secs(100))
        .tcp_capacity(100000)
        .build();
    let reset_request = Arc::new(Notify::new());
    let reset_finished = Arc::new(Notify::new());
    let reset_failure = Arc::new(std::sync::Mutex::new(None));
    make_cluster_with_options(
        &mut sim,
        1,
        false,
        1,
        Some((replica_dir.path().to_path_buf(), stop.clone(), done.clone())),
        Some((
            reset_request.clone(),
            reset_finished.clone(),
            reset_failure.clone(),
        )),
    );
    sim.client("client", async move {
        tokio::time::timeout(Duration::from_secs(30), async move {
            let admin = Client::new();
            assert!(admin
                .post(
                    "http://primary:9090/v1/namespaces/schema/create",
                    json!({"shared_schema": true})
                )
                .await?
                .status()
                .is_success());
            let schema = Database::open_remote_with_connector(
                "http://schema.primary:8080",
                "",
                TurmoilConnector,
            )?;
            schema
                .connect()?
                .execute("create table test (v integer)", ())
                .await?;
            schema
                .connect()?
                .execute("insert into test values (42)", ())
                .await?;
            assert!(admin
                .post(
                    "http://primary:9090/v1/namespaces/tenant/create",
                    json!({"shared_schema_name": "schema"})
                )
                .await?
                .status()
                .is_success());
            wait_for_linked_test_table("http://tenant.primary:8080").await?;
            assert!(admin
                .post("http://primary:9090/v1/namespaces/filler/create", json!({}))
                .await?
                .status()
                .is_success());
            wait_for_linked_test_table("http://tenant.replica0:8080").await?;
            let tenant_replica = Database::open_remote_with_connector(
                "http://tenant.replica0:8080",
                "",
                TurmoilConnector,
            )?;
            let filler = Database::open_remote_with_connector(
                "http://filler.replica0:8080",
                "",
                TurmoilConnector,
            )?;
            tenant_replica
                .connect()?
                .query("select * from test", ())
                .await?;
            // Capacity one and an extra namespace force the shared schema
            // out of cache before an explicit replica reset/handshake.
            filler.connect()?.query("select 1", ()).await?;
            tenant_replica
                .connect()?
                .query("select * from test", ())
                .await?;
            std::fs::write(&marker, b"reset must remove this")?;
            let primary_tenant = Database::open_remote_with_connector(
                "http://tenant.primary:8080",
                "",
                TurmoilConnector,
            )?;
            primary_tenant
                .connect()?
                .execute("insert into test values (19)", ())
                .await?;
            // Recreating the primary is not a deterministic trigger for a
            // cached replica's existing long-lived frame stream. Ask the
            // replica host itself to run the real NamespaceStore::reset.
            reset_request.notify_one();
            tokio::time::timeout(Duration::from_secs(20), reset_finished.notified())
                .await
                .map_err(|_| {
                    anyhow::anyhow!("replica reset/handshake stalled while schema was uncached")
                })?;
            if let Some(error) = reset_failure.lock().unwrap().take() {
                anyhow::bail!("replica NamespaceStore::reset failed: {error}");
            }
            assert!(
                !marker.exists(),
                "replica reset did not remove its old directory"
            );
            loop {
                if let Ok(mut rows) = tenant_replica
                    .connect()?
                    .query("select v from test where v = 19", ())
                    .await
                {
                    if rows.next().await?.is_some() {
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let mut schema_rows = schema
                .connect()?
                .query("select v from test where v = 42", ())
                .await?;
            assert!(schema_rows.next().await?.is_some());
            stop.notify_one();
            done.notified().await;
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        Ok(())
    });
    sim.run().unwrap();
}

#[test]
fn replica_restart_quarantines_incompatible_linked_tenant_log() {
    use std::sync::Arc;
    use tokio::sync::Notify;

    let replica_dir = tempdir().unwrap();
    let marker = replica_dir.path().join("dbs/tenant/old-log-marker");
    let stop = Arc::new(Notify::new());
    let stopped = Arc::new(Notify::new());
    let restart = Arc::new(Notify::new());
    let shutdown = Arc::new(Notify::new());
    let done = Arc::new(Notify::new());
    let mut sim = Builder::new()
        .simulation_duration(Duration::from_secs(100))
        .tcp_capacity(100000)
        .build();
    make_cluster_with_options(&mut sim, 0, false, 100, None, None);
    sim.host("replica0", {
        let path = replica_dir.path().to_path_buf();
        let (stop, stopped, restart, shutdown, done) = (
            stop.clone(),
            stopped.clone(),
            restart.clone(),
            shutdown.clone(),
            done.clone(),
        );
        move || {
            let path = path.clone();
            let (stop, stopped, restart, shutdown, done) = (
                stop.clone(),
                stopped.clone(),
                restart.clone(),
                shutdown.clone(),
                done.clone(),
            );
            async move {
                let make_server = |shutdown: std::sync::Arc<tokio::sync::Notify>| {
                    let path = path.clone();
                    async move {
                        TestServer {
                            path: path.into(),
                            user_api_config: UserApiConfig::default(),
                            admin_api_config: Some(AdminApiConfig {
                                acceptor: TurmoilAcceptor::bind(([0, 0, 0, 0], 9090))
                                    .await
                                    .unwrap(),
                                connector: TurmoilConnector,
                                disable_metrics: true,
                                auth_key: None,
                            }),
                            rpc_client_config: Some(RpcClientConfig {
                                remote_url: "http://primary:4567".into(),
                                connector: TurmoilConnector,
                                tls_config: None,
                            }),
                            disable_namespaces: false,
                            disable_default_namespace: true,
                            shutdown,
                            ..Default::default()
                        }
                    }
                };
                // Shut the first replica down cleanly. Cancelling start_sim
                // would leave its replication tasks alive across restart,
                // racing the new handshake for the old directory inode.
                make_server(stop).await.start_sim(8080).await?;
                stopped.notify_one();
                restart.notified().await;
                make_server(shutdown).await.start_sim(8080).await?;
                done.notify_one();
                Ok(())
            }
        }
    });
    sim.client("client", async move {
        tokio::time::timeout(Duration::from_secs(30), async move {
            let admin = Client::new();
            assert!(admin
                .post(
                    "http://primary:9090/v1/namespaces/schema/create",
                    json!({"shared_schema": true})
                )
                .await?
                .status()
                .is_success());
            let schema = Database::open_remote_with_connector(
                "http://schema.primary:8080",
                "",
                TurmoilConnector,
            )?;
            schema
                .connect()?
                .execute("create table test (v integer)", ())
                .await?;
            schema
                .connect()?
                .execute("insert into test values (42)", ())
                .await?;
            assert!(admin
                .post(
                    "http://primary:9090/v1/namespaces/tenant/create",
                    json!({"shared_schema_name": "schema"})
                )
                .await?
                .status()
                .is_success());
            wait_for_linked_test_table("http://tenant.primary:8080").await?;
            wait_for_linked_test_table("http://tenant.replica0:8080").await?;
            let replica = Database::open_remote_with_connector(
                "http://tenant.replica0:8080",
                "",
                TurmoilConnector,
            )?;
            replica.connect()?.query("select * from test", ()).await?;
            let tenant_primary = Database::open_remote_with_connector(
                "http://tenant.primary:8080",
                "",
                TurmoilConnector,
            )?;
            tenant_primary
                .connect()?
                .execute("insert into test values (7)", ())
                .await?;
            loop {
                let mut rows = replica
                    .connect()?
                    .query("select v from test where v = 7", ())
                    .await?;
                if rows.next().await?.is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let wal_index = replica_dir.path().join("dbs/tenant/client_wal_index");
            let wal_len = std::fs::metadata(&wal_index)?.len();
            assert!(
                wal_len >= 32,
                "replica must persist an old log identity before restart: {:?} has {wal_len} bytes",
                wal_index
            );
            std::fs::write(&marker, b"old log quarantined")?;
            stop.notify_one();
            stopped.notified().await;
            assert!(admin
                .delete("http://primary:9090/v1/namespaces/tenant", json!({}))
                .await?
                .status()
                .is_success());
            assert!(admin
                .post(
                    "http://primary:9090/v1/namespaces/tenant/create",
                    json!({"shared_schema_name": "schema"})
                )
                .await?
                .status()
                .is_success());
            restart.notify_one();
            loop {
                if replica
                    .connect()?
                    .query("select * from test", ())
                    .await
                    .is_ok()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert!(!marker.exists(), "stale log was not quarantined");
            let quarantine_root = replica_dir.path().join("replica-log-quarantine");
            let quarantined = std::fs::read_dir(&quarantine_root)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "incompatible-log handshake did not quarantine old files under {:?}: {e}",
                        quarantine_root
                    )
                })?
                .map(|entry| entry.map(|entry| entry.path().join("old-log-marker")))
                .collect::<std::io::Result<Vec<_>>>()?;
            assert!(quarantined
                .iter()
                .any(|path| std::fs::read(path).ok().as_deref() == Some(b"old log quarantined")));
            let mut rows = schema
                .connect()?
                .query("select v from test where v = 42", ())
                .await?;
            assert!(rows.next().await?.is_some());
            shutdown.notify_one();
            done.notified().await;
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        Ok(())
    });
    sim.run().unwrap();
}

#[test]
fn replicate_from_shared_schema() {
    let mut sim = Builder::new()
        .simulation_duration(Duration::from_secs(10000))
        .tcp_capacity(100000)
        .build();
    make_cluster(&mut sim, 1, true);

    sim.client("client", async {
        let db = Database::open_remote_with_connector("http://primary:8080", "", TurmoilConnector)
            .unwrap();
        let conn = db.connect().unwrap();

        conn.execute("create table test (x)", ()).await.unwrap();

        let db = Database::open_remote_with_connector("http://replica0:8080", "", TurmoilConnector)
            .unwrap();
        let conn = db.connect().unwrap();

        conn.execute_batch("select * from sqlite_master;")
            .await
            .unwrap();

        Ok(())
    });

    sim.run().unwrap();
}
