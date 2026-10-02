#![allow(dead_code)]
//! Process-wide metrics.
//!
//! Counters and gauges are cached `Lazy` handles. Histograms MUST NOT be: the Prometheus exporter is
//! configured with an idle timeout (`http::admin`), and when it evicts a histogram key a cached
//! `metrics::Histogram` handle keeps pushing 16-byte samples into an `AtomicBucket` the exporter will
//! never drain again (unbounded memory growth). Record histograms through the `record_*` functions
//! below, which use the `histogram!` macro and therefore re-register the key on every call.
use std::time::Duration;

use metrics::{
    describe_counter, describe_gauge, describe_histogram, histogram, register_counter,
    register_gauge, Counter, Gauge,
};
use once_cell::sync::Lazy;

pub static CLIENT_VERSION: &str = "libsql_client_version";

pub static WRITE_QUERY_COUNT: Lazy<Counter> = Lazy::new(|| {
    const NAME: &str = "libsql_server_writes_count";
    describe_counter!(NAME, "number of write statements");
    register_counter!(NAME)
});
pub static READ_QUERY_COUNT: Lazy<Counter> = Lazy::new(|| {
    const NAME: &str = "libsql_server_reads_count";
    describe_counter!(NAME, "number of read statements");
    register_counter!(NAME)
});
pub static REQUESTS_PROXIED: Lazy<Counter> = Lazy::new(|| {
    const NAME: &str = "libsql_server_requests_proxied";
    describe_counter!(NAME, "number of proxied requests");
    register_counter!(NAME)
});
pub static CONCURRENT_CONNECTIONS_COUNT: Lazy<Gauge> = Lazy::new(|| {
    const NAME: &str = "libsql_server_concurrent_connections";
    describe_gauge!(NAME, "number of concurrent connections");
    register_gauge!(NAME)
});
/// Total in-flight response size observed before a connection lock is taken.
#[inline]
pub fn record_total_response_size_before_lock(bytes: f64) {
    histogram!("libsql_server_total_response_size_before_lock", bytes);
}
pub static STREAM_HANDLES_COUNT: Lazy<Gauge> = Lazy::new(|| {
    const NAME: &str = "libsql_server_stream_handles";
    describe_gauge!(NAME, "amount of in-memory stream handles");
    register_gauge!(NAME)
});
#[inline]
pub fn record_namespace_load_latency(elapsed: Duration) {
    histogram!("libsql_server_namespace_load_latency", elapsed);
}
#[inline]
pub fn record_connection_create_time(elapsed: Duration) {
    histogram!("libsql_server_connection_create_time", elapsed);
}
#[inline]
pub fn record_connection_alive_duration(elapsed: Duration) {
    histogram!("libsql_server_connection_alive_duration", elapsed);
}
pub static VACUUM_COUNT: Lazy<Counter> = Lazy::new(|| {
    const NAME: &str = "libsql_server_vacuum_count";
    describe_counter!(NAME, "number of vacuum operations");
    register_counter!(NAME)
});
pub static WAL_CHECKPOINT_COUNT: Lazy<Counter> = Lazy::new(|| {
    const NAME: &str = "libsql_server_wal_checkpoint_count";
    describe_counter!(NAME, "number of WAL checkpoints");
    register_counter!(NAME)
});
pub static PROGRAM_EXEC_COUNT: Lazy<Counter> = Lazy::new(|| {
    const NAME: &str = "libsql_server_libsql_execute_program";
    describe_counter!(NAME, "number of hrana program executions");
    register_counter!(NAME)
});
pub static REPLICA_LOCAL_EXEC_MISPREDICT: Lazy<Counter> = Lazy::new(|| {
    const NAME: &str = "libsql_server_replica_exec_mispredict";
    describe_counter!(
        NAME,
        "number of mispredicted hrana program executions on a replica"
    );
    register_counter!(NAME)
});
pub static REPLICA_LOCAL_PROGRAM_EXEC: Lazy<Counter> = Lazy::new(|| {
    const NAME: &str = "libsql_server_replica_exec";
    describe_counter!(
        NAME,
        "number of local hrana programs executions on a replica"
    );
    register_counter!(NAME)
});
pub static DESCRIBE_COUNT: Lazy<Counter> = Lazy::new(|| {
    const NAME: &str = "libsql_server_describe_count";
    describe_counter!(NAME, "number of calls to describe");
    register_counter!(NAME)
});
pub static LEGACY_HTTP_CALL: Lazy<Counter> = Lazy::new(|| {
    const NAME: &str = "libsql_server_legacy_http_call";
    describe_counter!(NAME, "number of calls to the legacy HTTP API");
    register_counter!(NAME)
});
pub static DIRTY_STARTUP: Lazy<Counter> = Lazy::new(|| {
    const NAME: &str = "libsql_server_dirty_startup";
    describe_counter!(
        NAME,
        "how many times an instance started with a dirty state"
    );
    register_counter!(NAME)
});
#[inline]
pub fn record_replication_latency(latency: Duration) {
    histogram!("libsql_server_replication_latency", latency);
}
pub static REPLICATION_LATENCY_OUT_OF_SYNC: Lazy<Counter> = Lazy::new(|| {
    const NAME: &str = "libsql_server_replication_latency_out_of_sync";
    describe_counter!(
        NAME,
        "Number of replication latency timestamps that were out-of-sync (clocks likely not synchronized)"
    );
    register_counter!(NAME)
});
pub static REPLICATION_LATENCY_CACHE_MISS: Lazy<Counter> = Lazy::new(|| {
    const NAME: &str = "libsql_server_replication_latencies_cache_misses";
    describe_counter!(NAME, "Number of replication latency cache misses");
    register_counter!(NAME)
});
pub static SERVER_COUNT: Lazy<Gauge> = Lazy::new(|| {
    const NAME: &str = "libsql_server_count";
    describe_gauge!(NAME, "a gauge counting the number of active servers");
    register_gauge!(NAME)
});
pub static LISTEN_EVENTS_SENT: Lazy<Counter> = Lazy::new(|| {
    const NAME: &str = "libsql_server_listen_events_sent";
    describe_counter!(NAME, "Number of listen events sent");
    register_counter!(NAME)
});
pub static LISTEN_EVENTS_DROPPED: Lazy<Counter> = Lazy::new(|| {
    const NAME: &str = "libsql_server_listen_events_dropped";
    describe_counter!(NAME, "Number of listen events dropped");
    register_counter!(NAME)
});
pub static QUERY_CANCELED: Lazy<Counter> = Lazy::new(|| {
    const NAME: &str = "libsql_server_query_canceled";
    describe_counter!(NAME, "Number of canceled queries");
    register_counter!(NAME)
});

pub static TOKIO_RUNTIME_BLOCKING_QUEUE_DEPTH: Lazy<Gauge> = Lazy::new(|| {
    const NAME: &str = "tokio_runtime_blocking_queue_depth";
    describe_gauge!(NAME, "tokio runtime blocking_queue_depth");
    register_gauge!(NAME)
});

pub static TOKIO_RUNTIME_INJECTION_QUEUE_DEPTH: Lazy<Gauge> = Lazy::new(|| {
    const NAME: &str = "tokio_runtime_injection_queue_depth";
    describe_gauge!(NAME, "tokio runtime injection_queue_depth");
    register_gauge!(NAME)
});

pub static TOKIO_RUNTIME_NUM_BLOCKING_THREADS: Lazy<Gauge> = Lazy::new(|| {
    const NAME: &str = "tokio_runtime_num_blocking_threads";
    describe_gauge!(NAME, "tokio runtime num_blocking_threads");
    register_gauge!(NAME)
});

pub static TOKIO_RUNTIME_NUM_IDLE_BLOCKING_THREADS: Lazy<Gauge> = Lazy::new(|| {
    const NAME: &str = "tokio_runtime_num_idle_blocking_threads";
    describe_gauge!(NAME, "tokio runtime num_idle_blocking_threads");
    register_gauge!(NAME)
});

pub static TOKIO_RUNTIME_NUM_WORKERS: Lazy<Gauge> = Lazy::new(|| {
    const NAME: &str = "tokio_runtime_num_workers";
    describe_gauge!(NAME, "tokio runtime num_workers");
    register_gauge!(NAME)
});

pub static TOKIO_RUNTIME_IO_DRIVER_FD_DEREGISTERED_COUNT: Lazy<Counter> = Lazy::new(|| {
    const NAME: &str = "tokio_runtime_io_driver_fd_deregistered_count";
    describe_counter!(NAME, "tokio runtime io_driver_fd_deregistered_count");
    register_counter!(NAME)
});

pub static TOKIO_RUNTIME_IO_DRIVER_FD_REGISTERED_COUNT: Lazy<Counter> = Lazy::new(|| {
    const NAME: &str = "tokio_runtime_io_driver_fd_registered_count";
    describe_counter!(NAME, "tokio runtime io_driver_fd_registered_count");
    register_counter!(NAME)
});

pub static TOKIO_RUNTIME_IO_DRIVER_READY_COUNT: Lazy<Counter> = Lazy::new(|| {
    const NAME: &str = "tokio_runtime_io_driver_ready_count";
    describe_counter!(NAME, "tokio runtime io_driver_ready_count");
    register_counter!(NAME)
});

pub static TOKIO_RUNTIME_REMOTE_SCHEDULE_COUNT: Lazy<Counter> = Lazy::new(|| {
    const NAME: &str = "tokio_runtime_remote_schedule_count";
    describe_gauge!(NAME, "tokio runtime remote_schedule_count");
    register_counter!(NAME)
});

/// Registers HELP text for every histogram. Must run after the global recorder is installed
/// (`describe_histogram!` is a no-op when no recorder is set).
pub(crate) fn describe_histograms() {
    describe_histogram!(
        "libsql_server_total_response_size_before_lock",
        "total response size value before connection lock"
    );
    describe_histogram!(
        "libsql_server_namespace_load_latency",
        "latency is us when loading a namespace"
    );
    describe_histogram!(
        "libsql_server_connection_create_time",
        "time to create a connection"
    );
    describe_histogram!(
        "libsql_server_connection_alive_duration",
        "duration for which a connection was kept alive"
    );
    describe_histogram!(
        "libsql_server_replication_latency",
        "Latency between the time a transaction was commited on the primary and the commit frame was received by the replica"
    );
    // Names recorded via `histogram!` elsewhere whose old `Lazy` statics were never forced
    // (so they never had HELP text); harmless to describe them here.
    describe_histogram!(
        "libsql_server_statement_execution_time",
        "time to execute a statement"
    );
    describe_histogram!(
        "libsql_server_statement_mem_used_bytes",
        "memory used by a prepared statement"
    );
    describe_histogram!(
        "libsql_server_wal_checkpoint_time",
        "time to checkpoint the WAL"
    );
    describe_histogram!(
        "libsql_server_returned_bytes",
        "number of bytes of values returned to the client"
    );
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, MutexGuard, PoisonError};
    use std::time::Duration;

    use metrics_exporter_prometheus::PrometheusHandle;
    use once_cell::sync::Lazy;

    const IDLE: Duration = Duration::from_millis(50);
    const PAST_IDLE: Duration = Duration::from_millis(150);

    /// `metrics` 0.21 only has a process-global recorder, installable once; every test in this
    /// module shares it. Mirrors the production configuration (same builder, same mask, global
    /// labels) with a short idle timeout.
    static HANDLE: Lazy<PrometheusHandle> = Lazy::new(|| {
        let handle = crate::http::admin::prometheus_builder(IDLE)
            .add_global_label("app", "test")
            .add_global_label("version", "0.0.0-test")
            .install_recorder()
            .expect("another global metrics recorder is installed in this test binary");
        super::describe_histograms();
        handle
    });

    /// The tests in this module run serially. Two concurrent `render()` calls race inside the
    /// exporter (one render can re-insert the recency entry of a key the other has just evicted,
    /// recreating a distribution nobody visits again), which would make eviction assertions flaky.
    /// Production has a single scraper per pod; other unit tests only record, never render.
    static SERIAL: Mutex<()> = Mutex::new(());

    fn setup() -> (MutexGuard<'static, ()>, &'static PrometheusHandle) {
        let guard = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
        (guard, &*HANDLE)
    }

    /// `<name>_count{...} N` → Some(N), or None when the series is absent from the render.
    fn count_of(rendered: &str, name: &str) -> Option<u64> {
        let prefix = format!("{name}_count");
        rendered.lines().find_map(|line| {
            // `{app="test",version="0.0.0-test"} 3` or ` 3`
            let rest = line.strip_prefix(prefix.as_str())?;
            if !(rest.starts_with('{') || rest.starts_with(' ')) {
                return None;
            }
            rest.rsplit(' ').next()?.parse().ok()
        })
    }

    fn has_help(rendered: &str, name: &str) -> bool {
        let prefix = format!("# HELP {name} ");
        rendered.lines().any(|l| l.starts_with(&prefix))
    }

    /// Renders repeatedly until `name` has been evicted (absent), or panics after `attempts`.
    /// Production names may be touched by other unit tests running in the same process, which
    /// would keep the key alive; the retry makes that a non-issue in practice.
    fn evict(handle: &PrometheusHandle, name: &str, attempts: usize) {
        for _ in 0..attempts {
            std::thread::sleep(PAST_IDLE);
            if count_of(&handle.render(), name).is_none() {
                return;
            }
        }
        panic!("{name} was never idle-evicted; is MetricKindMask::HISTOGRAM still in the mask?");
    }

    #[test]
    fn cached_histogram_handle_is_orphaned_after_idle_eviction_but_macro_path_recovers() {
        let (_serial, handle) = setup();
        const NAME: &str = "libsql_test_detached_histogram";

        // The pre-fix pattern: a cached handle (what `Lazy<Histogram>` held).
        let cached = metrics::register_histogram!(NAME);
        cached.record(1.0);
        assert_eq!(count_of(&handle.render(), NAME), Some(1));

        // Two renders > idle_timeout apart with no update → key deleted from the registry.
        evict(handle, NAME, 1);

        // Samples recorded through the orphaned handle are never rendered again: this is the leak
        // (they accumulate in an AtomicBucket nobody drains).
        cached.record(1.0);
        cached.record(1.0);
        assert_eq!(
            count_of(&handle.render(), NAME),
            None,
            "detached handle must not reappear"
        );

        // The macro re-registers the key; only the new sample is visible, and it is drained.
        metrics::histogram!(NAME, 1.0);
        assert_eq!(count_of(&handle.render(), NAME), Some(1));
        metrics::histogram!(NAME, 1.0);
        metrics::histogram!(NAME, 1.0);
        assert_eq!(count_of(&handle.render(), NAME), Some(3));
        // A render with no new samples neither grows nor loses the distribution.
        assert_eq!(count_of(&handle.render(), NAME), Some(3));
    }

    #[test]
    fn production_histograms_survive_idle_eviction() {
        let (_serial, handle) = setup();

        // (name, record-fn) for every histogram that used to be recorded through a cached handle.
        let cases: [(&str, fn()); 5] = [
            ("libsql_server_connection_create_time", || {
                super::record_connection_create_time(Duration::from_millis(1))
            }),
            ("libsql_server_connection_alive_duration", || {
                super::record_connection_alive_duration(Duration::from_millis(1))
            }),
            ("libsql_server_total_response_size_before_lock", || {
                super::record_total_response_size_before_lock(42.0)
            }),
            ("libsql_server_namespace_load_latency", || {
                super::record_namespace_load_latency(Duration::from_millis(1))
            }),
            ("libsql_server_replication_latency", || {
                super::record_replication_latency(Duration::from_millis(1))
            }),
        ];

        for (name, record) in cases {
            record();
            let rendered = handle.render();
            assert!(
                count_of(&rendered, name).unwrap_or(0) >= 1,
                "{name} missing after record"
            );
            assert!(
                has_help(&rendered, name),
                "{name} has no HELP line: describe_histograms() out of sync"
            );

            evict(handle, name, 20);

            record();
            record();
            let rendered = handle.render();
            let after = count_of(&rendered, name)
                .unwrap_or_else(|| panic!("{name} did not reappear after idle eviction"));
            assert!(
                after >= 2,
                "{name}: expected >= 2 samples after re-registration, got {after}"
            );
            // Drained: a further sample advances the count by at least what we recorded (not
            // exactly, because other unit tests may record the production metric concurrently).
            record();
            let next = count_of(&handle.render(), name).unwrap();
            assert!(
                next > after,
                "{name}: count did not advance ({after} -> {next})"
            );
        }
    }

    #[test]
    fn counters_and_gauges_are_still_pruned_when_idle() {
        let (_serial, handle) = setup();
        metrics::counter!("libsql_test_pruned_counter", 7);
        metrics::gauge!("libsql_test_pruned_gauge", 3.0);
        let rendered = handle.render();
        assert!(rendered
            .lines()
            .any(|l| l.starts_with("libsql_test_pruned_counter{") && l.ends_with(" 7")));
        assert!(rendered
            .lines()
            .any(|l| l.starts_with("libsql_test_pruned_gauge{")));

        std::thread::sleep(PAST_IDLE);
        let rendered = handle.render();
        assert!(
            !rendered.contains("libsql_test_pruned_counter"),
            "idle counter must be evicted"
        );
        assert!(
            !rendered.contains("libsql_test_pruned_gauge"),
            "idle gauge must be evicted"
        );

        // Macro-based counters/gauges come back on the next update (value restarts).
        metrics::counter!("libsql_test_pruned_counter", 1);
        assert!(handle
            .render()
            .lines()
            .any(|l| l.starts_with("libsql_test_pruned_counter{") && l.ends_with(" 1")));
    }
}
