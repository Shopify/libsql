//! Live check for the namespace store: N embedded replicas, one per namespace
//! (`ns0..nsN-1`, reached as `nsK.localhost`), syncing in a tight loop against
//! a local `sqld`. Prints how many syncs succeeded and every distinct error
//! message with the time it was first and last seen, so that what a client
//! sees across a server restart can be compared between two builds.
//!
//! Driven by `libsql-server/scripts/namespace-live-checks/replica-sigterm.sh`.
//!
//! Environment: `PORT` (default 18080), `REPLICAS` (default 8), `DURATION`
//! seconds (default 12). Log lines (warn and above, which includes the
//! replicator's retry lines) go to stderr.
use libsql::Builder;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn env_or<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::WARN)
        .init();
    let port: u16 = env_or("PORT", 18080);
    let replicas: usize = env_or("REPLICAS", 8);
    let duration: f64 = env_or("DURATION", 12.0);

    let start = Instant::now();
    // message -> (count, first seen, last seen), in seconds since start
    let errors: Arc<Mutex<BTreeMap<String, (usize, f64, f64)>>> = Default::default();
    let ok = Arc::new(AtomicUsize::new(0));
    let dir = tempfile::tempdir().unwrap();

    let mut tasks = Vec::new();
    for i in 0..replicas {
        let path = dir.path().join(format!("replica{i}.db"));
        let url = format!("http://ns{i}.localhost:{port}");
        let errors = errors.clone();
        let ok = ok.clone();
        tasks.push(tokio::spawn(async move {
            let db = Builder::new_remote_replica(&path, url, String::new())
                .build()
                .await
                .expect("open the embedded replica");
            // A proxied write, so that every sync has frames to pull.
            if let Ok(conn) = db.connect() {
                let _ = conn
                    .execute("CREATE TABLE IF NOT EXISTS t (x INTEGER)", ())
                    .await;
                let _ = conn.execute("INSERT INTO t VALUES (1)", ()).await;
            }
            while start.elapsed().as_secs_f64() < duration {
                match db.sync().await {
                    Ok(_) => {
                        ok.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => {
                        let now = start.elapsed().as_secs_f64();
                        let mut errors = errors.lock().unwrap();
                        let entry = errors.entry(e.to_string()).or_insert((0, now, now));
                        entry.0 += 1;
                        entry.2 = now;
                    }
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }));
    }
    for task in tasks {
        let _ = task.await;
    }

    println!("ok syncs: {}", ok.load(Ordering::Relaxed));
    println!("errors (count, first seen, last seen):");
    for (message, (count, first, last)) in errors.lock().unwrap().iter() {
        println!("  {count:6}  +{first:7.3}s .. +{last:7.3}s  {message}");
    }
}
