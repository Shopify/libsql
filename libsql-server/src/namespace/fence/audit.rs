//! Fence observability (`docs/NAMESPACE_FENCE.md` sections 12 and 15): the fence metrics and
//! the audit log.
//!
//! Every fence command a server answers emits one structured event under the tracing target
//! [`AUDIT_TARGET`], so that a log pipeline can route them apart from the server's operational
//! logs, and is counted in the metrics below. Metric labels are bounded: a namespace, an
//! operation id, a command id, a revision or a caller never appears as a label value; those
//! are in the audit event.

use std::time::Duration;

use uuid::Uuid;

use super::command::CommandKind;
use super::outcome::FenceError;
use super::registry::FenceRegistry;
use super::state::FenceState;
use crate::namespace::meta_store::{FenceCommit, FenceCommitKind};
use crate::namespace::NamespaceName;

/// The tracing target of every fence audit event.
pub const AUDIT_TARGET: &str = "libsql_server::fence::audit";

pub const TRANSITIONS_TOTAL: &str = "libsql_server_fence_transitions_total";
pub const DRAIN_DURATION_SECONDS: &str = "libsql_server_fence_drain_duration_seconds";
pub const FORCED_TOTAL: &str = "libsql_server_fence_forced_total";
pub const REPLAYS_TOTAL: &str = "libsql_server_fence_replays_total";
pub const DENIALS_TOTAL: &str = "libsql_server_fence_denials_total";
pub const NAMESPACES: &str = "libsql_server_fence_namespaces";
pub const OLDEST_ACTIVE_AGE_SECONDS: &str = "libsql_server_fence_oldest_active_age_seconds";
pub const ADOPTIONS_TOTAL: &str = "libsql_server_fence_adoptions_total";

/// The label value of a command answered with an error that is not a fence outcome (an I/O or
/// metastore failure), in place of an outcome code.
pub const OTHER_ERROR: &str = "ERROR";

/// Describe the fence metrics to the recorder, once, so that `/metrics` carries their help
/// text. Called when the namespace store starts.
pub fn describe_metrics() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        metrics::describe_counter!(
            TRANSITIONS_TOTAL,
            "fence commands answered, by command and outcome code (replays and refusals included)"
        );
        metrics::describe_histogram!(
            DRAIN_DURATION_SECONDS,
            metrics::Unit::Seconds,
            "time from the start of a fence drain to its proof, by kind (write, read, import)"
        );
        metrics::describe_counter!(
            FORCED_TOTAL,
            "work ended by a fence drain at its deadline, by kind (rollback, sql_cancel, \
             dump_cancel, stream_termination)"
        );
        metrics::describe_counter!(
            REPLAYS_TOTAL,
            "fence commands that were replays of a recorded command, or reused its command id \
             for a different request (conflict)"
        );
        metrics::describe_counter!(
            DENIALS_TOTAL,
            "requests refused by a namespace fence, by outcome code and surface"
        );
        metrics::describe_gauge!(
            NAMESPACES,
            "namespaces with fence state on this server, by role and state"
        );
        metrics::describe_gauge!(
            OLDEST_ACTIVE_AGE_SECONDS,
            metrics::Unit::Seconds,
            "age of the oldest active fence record on this server, 0 when there is none"
        );
        metrics::describe_counter!(ADOPTIONS_TOTAL, "committed fence adoptions");
    });
}

/// The drain a command waited on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainKind {
    Write,
    Read,
    Import,
}

impl DrainKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            DrainKind::Write => "write",
            DrainKind::Read => "read",
            DrainKind::Import => "import",
        }
    }
}

/// Work a drain ended at its deadline instead of waiting for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ForcedKind {
    /// A write or import transaction rolled back (`on_deadline: force_rollback`).
    Rollback,
    /// A running SQL program cancelled by the read drain.
    SqlCancel,
    /// A dump cancelled by the read drain.
    DumpCancel,
    /// A replication stream terminated by the read drain.
    StreamTermination,
}

impl ForcedKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            ForcedKind::Rollback => "rollback",
            ForcedKind::SqlCancel => "sql_cancel",
            ForcedKind::DumpCancel => "dump_cancel",
            ForcedKind::StreamTermination => "stream_termination",
        }
    }
}

/// Where a request refused by a fence was refused.
///
/// A denial is counted once at each surface it crosses: a write sent to a replica and refused
/// by the primary is counted under `rpc` on the primary, and under `proxy` and the replica's
/// user protocol on the replica; a lifecycle operation refused over the admin API is counted
/// under `lifecycle` and `http`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenialSurface {
    /// An HTTP error response: legacy `/`, the admin API's lifecycle routes, schema errors.
    Http,
    /// A Hrana error: `/v1`, `/v2`, `/v3`, cursors and WebSocket streams.
    Hrana,
    /// The primary's proxy service answering a replica.
    Rpc,
    /// A replica mapping a denial its primary returned through the write proxy.
    Proxy,
    /// `/dump`.
    Dump,
    /// The replication service (`hello`, `log_entries`, `batch_log_entries`, `snapshot`).
    Replication,
    /// The admin shell.
    AdminShell,
    /// Delete, reset, fork, restore, config and schema operations.
    Lifecycle,
}

impl DenialSurface {
    pub const ALL: [DenialSurface; 8] = [
        DenialSurface::Http,
        DenialSurface::Hrana,
        DenialSurface::Rpc,
        DenialSurface::Proxy,
        DenialSurface::Dump,
        DenialSurface::Replication,
        DenialSurface::AdminShell,
        DenialSurface::Lifecycle,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            DenialSurface::Http => "http",
            DenialSurface::Hrana => "hrana",
            DenialSurface::Rpc => "rpc",
            DenialSurface::Proxy => "proxy",
            DenialSurface::Dump => "dump",
            DenialSurface::Replication => "replication",
            DenialSurface::AdminShell => "admin_shell",
            DenialSurface::Lifecycle => "lifecycle",
        }
    }
}

/// Count a request refused by a fence at `surface`.
pub fn denied(error: &FenceError, surface: DenialSurface) {
    metrics::increment_counter!(
        DENIALS_TOTAL,
        "code" => error.outcome().as_str(),
        "surface" => surface.as_str(),
    );
}

/// Count `count` pieces of work of `kind` ended by a drain.
pub fn forced(kind: ForcedKind, count: usize) {
    if count > 0 {
        metrics::counter!(FORCED_TOTAL, count as u64, "kind" => kind.as_str());
    }
}

/// What a command's drain did, filled in by the drain while it runs under the transition and
/// reported with the command's audit event.
#[derive(Debug, Clone, Default)]
pub struct CommandReport {
    drain: Option<(DrainKind, Duration)>,
    forced: Vec<ForcedKind>,
}

impl CommandReport {
    /// The drain of `kind` was proven after `duration`. Observed in the drain histogram.
    pub fn drained(&mut self, kind: DrainKind, duration: Duration) {
        metrics::histogram!(
            DRAIN_DURATION_SECONDS,
            duration.as_secs_f64(),
            "kind" => kind.as_str(),
        );
        self.drain = Some((kind, duration));
    }

    /// The drain ended `count` pieces of work of `kind` at its deadline. Counted.
    pub fn forced(&mut self, kind: ForcedKind, count: usize) {
        if count == 0 {
            return;
        }
        forced(kind, count);
        if !self.forced.contains(&kind) {
            self.forced.push(kind);
            self.forced.sort();
        }
    }

    pub fn drain(&self) -> Option<(DrainKind, Duration)> {
        self.drain
    }

    pub fn forced_kinds(&self) -> &[ForcedKind] {
        &self.forced
    }

    fn drain_ms(&self) -> Option<u128> {
        self.drain.map(|(_, d)| d.as_millis())
    }

    fn forced_list(&self) -> String {
        self.forced
            .iter()
            .map(|k| k.as_str())
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// The request fields of a command, taken before the command runs, for its audit event.
#[derive(Debug, Clone)]
pub struct CommandAudit {
    pub namespace: NamespaceName,
    pub operation_id: Uuid,
    pub command_id: Uuid,
    pub command: CommandKind,
    pub expected_revision: u64,
    /// The published state when the command took the transition lock.
    pub state_before: FenceState,
}

impl CommandAudit {
    pub fn new(request: &super::command::FenceRequest, state_before: FenceState) -> Self {
        Self {
            namespace: request.namespace.clone(),
            operation_id: request.operation_id,
            command_id: request.command_id,
            command: request.command.kind(),
            expected_revision: request.expected_revision,
            state_before,
        }
    }
}

/// Count a command's answer and emit its audit event: one per command answered, whether it
/// committed, replayed a recorded answer or was refused.
pub fn command_finished(
    audit: &CommandAudit,
    result: &crate::Result<FenceCommit>,
    report: &CommandReport,
) {
    let command = audit.command.as_str();
    match result {
        Ok(commit) => {
            let receipt = &commit.receipt;
            let replay = match commit.kind {
                FenceCommitKind::Committed => None,
                FenceCommitKind::Replayed => Some("replay"),
                FenceCommitKind::Resumed => Some("resume"),
            };
            metrics::increment_counter!(
                TRANSITIONS_TOTAL,
                "command" => command,
                "outcome" => receipt.outcome.as_str(),
            );
            if replay.is_some() {
                metrics::increment_counter!(REPLAYS_TOTAL, "result" => "replay");
            }
            let adoption = receipt
                .adoption
                .as_ref()
                .filter(|_| commit.kind == FenceCommitKind::Committed);
            if let Some(adoption) = adoption {
                metrics::increment_counter!(ADOPTIONS_TOTAL);
                tracing::info!(
                    target: AUDIT_TARGET,
                    event = "namespace_fence_adopted",
                    namespace = %audit.namespace,
                    command,
                    outcome = receipt.outcome.as_str(),
                    state_before = audit.state_before.as_str(),
                    state = receipt.state_after.as_str(),
                    previous_operation_id = %adoption.previous_operation_id,
                    operation_id = %adoption.new_operation_id,
                    command_id = %adoption.command_id,
                    approvers = ?adoption.approvers,
                    incident_ref = %adoption.incident_ref,
                    reason = %adoption.reason,
                    revision_before = receipt.revision_before,
                    revision_after = receipt.revision_after,
                    server_instance = %receipt.instance_id,
                    "namespace fence adopted"
                );
                return;
            }
            tracing::info!(
                target: AUDIT_TARGET,
                event = "namespace_fence_command",
                namespace = %audit.namespace,
                operation_id = %audit.operation_id,
                command_id = %audit.command_id,
                command,
                outcome = receipt.outcome.as_str(),
                replay = replay.unwrap_or("none"),
                revision_before = receipt.revision_before,
                revision_after = receipt.revision_after,
                state_before = audit.state_before.as_str(),
                state_after = receipt.state_after.as_str(),
                drain = report.drain.map(|(k, _)| k.as_str()).unwrap_or("none"),
                drain_ms = ?report.drain_ms(),
                forced = %report.forced_list(),
                server_instance = %receipt.instance_id,
                "namespace fence command answered"
            );
        }
        Err(error) => {
            let fence = error.fence_error();
            let outcome = fence.map(|e| e.outcome().as_str()).unwrap_or(OTHER_ERROR);
            metrics::increment_counter!(
                TRANSITIONS_TOTAL,
                "command" => command,
                "outcome" => outcome,
            );
            let conflict = fence
                .is_some_and(|e| e.outcome() == super::outcome::FenceOutcome::FenceCommandConflict);
            if conflict {
                metrics::increment_counter!(REPLAYS_TOTAL, "result" => "conflict");
            }
            tracing::info!(
                target: AUDIT_TARGET,
                event = "namespace_fence_command",
                namespace = %audit.namespace,
                operation_id = %audit.operation_id,
                command_id = %audit.command_id,
                command,
                outcome,
                detail = fence.and_then(|e| e.detail()).map(|d| d.as_str()).unwrap_or("none"),
                replay = if conflict { "conflict" } else { "none" },
                expected_revision = audit.expected_revision,
                state_before = audit.state_before.as_str(),
                drain = report.drain.map(|(k, _)| k.as_str()).unwrap_or("none"),
                drain_ms = ?report.drain_ms(),
                forced = %report.forced_list(),
                server_instance = %super::server_identity().instance_id,
                error = %error,
                "namespace fence command refused"
            );
        }
    }
}

/// Set the fence gauges from the registry: how many namespaces are in each state, by role, and
/// the age of the oldest active record. Every (role, state) pair is written, so a state that
/// emptied reads 0. Called before `/metrics` is rendered.
pub fn update_gauges(registry: &FenceRegistry, now_ms: i64) {
    let census = registry.census();
    for state in FenceState::ALL {
        let Some(role) = gauge_role(state) else {
            continue;
        };
        let count = census.iter().filter(|(s, _)| *s == state).count();
        metrics::gauge!(
            NAMESPACES,
            count as f64,
            "role" => role,
            "state" => state.as_str(),
        );
    }
    let oldest = census
        .iter()
        .filter_map(|(state, created_at_ms)| created_at_ms.filter(|_| state.is_active()))
        .min();
    let age = oldest
        .map(|created| (now_ms.saturating_sub(created)).max(0) as f64 / 1000.0)
        .unwrap_or(0.0);
    metrics::gauge!(OLDEST_ACTIVE_AGE_SECONDS, age);
}

/// The `role` label of a state counted in [`NAMESPACES`]: the record's role, `unknown` for a
/// namespace whose fence state cannot be established, none for an ordinary namespace.
fn gauge_role(state: FenceState) -> Option<&'static str> {
    match state.role() {
        Some(role) => Some(match role {
            super::state::Role::Source => "source",
            super::state::Role::Target => "target",
        }),
        None if state == FenceState::UnknownUnavailable => Some("unknown"),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
    use metrics_util::MetricKind;
    use uuid::Uuid;

    use super::*;
    use crate::namespace::fence::command::{AdoptArgs, FenceCommand, FenceRequest};
    use crate::namespace::fence::outcome::FenceOutcome;
    use crate::namespace::fence::record::tests::sample_record;
    use crate::namespace::fence::record::{Adoption, CommandReceipt};
    use crate::namespace::fence::state::FenceState;
    use crate::namespace::fence::store::StoredFence;

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    pub(crate) fn capture(f: impl FnOnce()) -> String {
        let captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::INFO)
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        let bytes = captured.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    fn adopt_request() -> FenceRequest {
        FenceRequest {
            namespace: "ns".into(),
            operation_id: Uuid::from_u128(0xb),
            command_id: Uuid::from_u128(3),
            expected_state: FenceState::SourceWriteFenced,
            expected_revision: 2,
            command: FenceCommand::AdoptFence(AdoptArgs {
                current_operation_id: Uuid::from_u128(0xa),
                approvers: vec!["alice".into(), "bob".into()],
                incident_ref: "INC-1".into(),
                reason: "control record lost".into(),
            }),
        }
    }

    fn acquire_request() -> FenceRequest {
        FenceRequest {
            namespace: "ns".into(),
            operation_id: Uuid::from_u128(0xc),
            command_id: Uuid::from_u128(4),
            expected_state: FenceState::Unfenced,
            expected_revision: 0,
            command: FenceCommand::AcquireSourceWriteFence {
                expected_log_id: Uuid::from_u128(0x10),
                drain_policy: None,
            },
        }
    }

    fn commit(
        request: &FenceRequest,
        kind: FenceCommitKind,
        outcome: FenceOutcome,
        (revision_before, revision_after): (u64, u64),
        adoption: Option<Adoption>,
    ) -> FenceCommit {
        FenceCommit {
            kind,
            receipt: CommandReceipt {
                namespace: "ns".into(),
                operation_id: request.operation_id,
                command_id: request.command_id,
                command: request.command.kind(),
                fingerprint: request.fingerprint(),
                outcome,
                revision_before,
                revision_after,
                state_after: FenceState::SourceWriteFenced,
                applied_at_ms: 1_000,
                instance_id: Uuid::from_u128(0x99),
                adoption,
            },
            record: None,
            created_config: None,
        }
    }

    fn adoption_entry() -> Adoption {
        Adoption {
            previous_operation_id: Uuid::from_u128(0xa),
            new_operation_id: Uuid::from_u128(0xb),
            command_id: Uuid::from_u128(3),
            approvers: vec!["alice".into(), "bob".into()],
            incident_ref: "INC-1".into(),
            reason: "control record lost".into(),
            at_ms: 1_000,
            revision: 3,
        }
    }

    #[track_caller]
    fn assert_contains_all(out: &str, expected: &[&str]) {
        for expected in expected {
            assert!(out.contains(expected), "`{expected}` missing from {out}");
        }
    }

    /// A committed adoption is one event under the audit target with every field section 12
    /// asks for; a replay of it is an ordinary command event without them.
    #[test]
    fn adoption_event_fields() {
        let request = adopt_request();
        let audit = CommandAudit::new(&request, FenceState::SourceWriteFenced);
        let committed = commit(
            &request,
            FenceCommitKind::Committed,
            FenceOutcome::Applied,
            (2, 3),
            Some(adoption_entry()),
        );
        let out = capture(|| command_finished(&audit, &Ok(committed), &CommandReport::default()));
        assert_eq!(out.lines().count(), 1, "{out}");
        assert_contains_all(
            &out,
            &[
                AUDIT_TARGET,
                "namespace fence adopted",
                "event=\"namespace_fence_adopted\"",
                "namespace=ns",
                "command=\"AdoptFence\"",
                "outcome=\"APPLIED\"",
                "state_before=\"SOURCE_WRITE_FENCED\"",
                "state=\"SOURCE_WRITE_FENCED\"",
                &format!("previous_operation_id={}", Uuid::from_u128(0xa)),
                &format!("operation_id={}", Uuid::from_u128(0xb)),
                &format!("command_id={}", Uuid::from_u128(3)),
                "approvers=[\"alice\", \"bob\"]",
                "incident_ref=INC-1",
                "reason=control record lost",
                "revision_before=2",
                "revision_after=3",
                &format!("server_instance={}", Uuid::from_u128(0x99)),
            ],
        );

        let replayed = commit(
            &request,
            FenceCommitKind::Replayed,
            FenceOutcome::Applied,
            (2, 3),
            Some(adoption_entry()),
        );
        let out = capture(|| command_finished(&audit, &Ok(replayed), &CommandReport::default()));
        assert_eq!(out.lines().count(), 1, "{out}");
        assert!(!out.contains("namespace_fence_adopted"), "{out}");
        assert_contains_all(
            &out,
            &["event=\"namespace_fence_command\"", "replay=\"replay\""],
        );
    }

    /// Every answer is one event under the audit target: a committed drain with its duration
    /// and forced actions, a replay, and a refusal (a command-id conflict) with its code.
    #[test]
    fn audit_event_fields() {
        let request = acquire_request();
        let audit = CommandAudit::new(&request, FenceState::Unfenced);
        let mut report = CommandReport::default();
        report.forced(ForcedKind::Rollback, 1);
        report.forced(ForcedKind::Rollback, 1);
        report.forced(ForcedKind::SqlCancel, 0);
        report.drained(DrainKind::Write, Duration::from_millis(1_500));
        assert_eq!(report.forced_kinds(), &[ForcedKind::Rollback]);

        let committed = commit(
            &request,
            FenceCommitKind::Committed,
            FenceOutcome::Applied,
            (0, 2),
            None,
        );
        let out = capture(|| command_finished(&audit, &Ok(committed), &report));
        assert_eq!(out.lines().count(), 1, "{out}");
        assert_contains_all(
            &out,
            &[
                AUDIT_TARGET,
                "namespace fence command answered",
                "event=\"namespace_fence_command\"",
                "namespace=ns",
                &format!("operation_id={}", Uuid::from_u128(0xc)),
                &format!("command_id={}", Uuid::from_u128(4)),
                "command=\"AcquireSourceWriteFence\"",
                "outcome=\"APPLIED\"",
                "replay=\"none\"",
                "revision_before=0",
                "revision_after=2",
                "state_before=\"UNFENCED\"",
                "state_after=\"SOURCE_WRITE_FENCED\"",
                "drain=\"write\"",
                "drain_ms=Some(1500)",
                "forced=rollback",
                &format!("server_instance={}", Uuid::from_u128(0x99)),
            ],
        );

        let out = capture(|| {
            let replayed = commit(
                &request,
                FenceCommitKind::Replayed,
                FenceOutcome::Applied,
                (0, 2),
                None,
            );
            command_finished(&audit, &Ok(replayed), &CommandReport::default())
        });
        assert_contains_all(&out, &["replay=\"replay\"", "drain=\"none\"", "forced= "]);

        let conflict = FenceError::new(FenceOutcome::FenceCommandConflict, "reused command id");
        let out = capture(|| {
            command_finished(
                &audit,
                &Err(crate::Error::NamespaceFence(conflict)),
                &CommandReport::default(),
            )
        });
        assert_eq!(out.lines().count(), 1, "{out}");
        assert_contains_all(
            &out,
            &[
                AUDIT_TARGET,
                "namespace fence command refused",
                "outcome=\"FENCE_COMMAND_CONFLICT\"",
                "replay=\"conflict\"",
                "expected_revision=0",
                "state_before=\"UNFENCED\"",
                &format!(
                    "server_instance={}",
                    super::super::server_identity().instance_id
                ),
            ],
        );

        let out = capture(|| {
            command_finished(
                &audit,
                &Err(crate::Error::NamespaceStoreShutdown),
                &CommandReport::default(),
            )
        });
        assert_contains_all(&out, &["outcome=\"ERROR\"", "detail=\"none\""]);
    }

    type Snapshot = HashMap<(MetricKind, String, Vec<(String, String)>), DebugValue>;

    fn snapshot() -> Snapshot {
        Snapshotter::current_thread_snapshot()
            .expect("per-thread recorder installed")
            .into_vec()
            .into_iter()
            .map(|(key, _, _, value)| {
                let (kind, key) = key.into_parts();
                let mut labels: Vec<_> = key
                    .labels()
                    .map(|l| (l.key().to_string(), l.value().to_string()))
                    .collect();
                labels.sort();
                ((kind, key.name().to_string(), labels), value)
            })
            .collect()
    }

    fn labels(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        let mut labels: Vec<_> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        labels.sort();
        labels
    }

    #[track_caller]
    fn counter(s: &Snapshot, name: &str, pairs: &[(&str, &str)]) -> u64 {
        match s.get(&(MetricKind::Counter, name.to_string(), labels(pairs))) {
            Some(DebugValue::Counter(v)) => *v,
            other => panic!("counter {name} {pairs:?}: {other:?} in {s:?}"),
        }
    }

    #[track_caller]
    fn gauge(s: &Snapshot, name: &str, pairs: &[(&str, &str)]) -> f64 {
        match s.get(&(MetricKind::Gauge, name.to_string(), labels(pairs))) {
            Some(DebugValue::Gauge(v)) => v.0,
            other => panic!("gauge {name} {pairs:?}: {other:?} in {s:?}"),
        }
    }

    /// Each metric of section 15 is recorded with its bounded labels, and no label value is a
    /// namespace, an operation id or a command id.
    #[test]
    fn metrics_and_bounded_labels() {
        let _ = DebuggingRecorder::per_thread().install();
        let acquire = acquire_request();
        let audit = CommandAudit::new(&acquire, FenceState::Unfenced);
        let mut report = CommandReport::default();
        report.forced(ForcedKind::Rollback, 2);
        report.forced(ForcedKind::StreamTermination, 1);
        report.drained(DrainKind::Write, Duration::from_millis(20));
        let applied = commit(
            &acquire,
            FenceCommitKind::Committed,
            FenceOutcome::Applied,
            (0, 2),
            None,
        );
        let replayed = FenceCommit {
            kind: FenceCommitKind::Replayed,
            ..applied.clone()
        };
        let conflict = FenceError::new(FenceOutcome::FenceCommandConflict, "reused command id");
        let _ = capture(|| {
            command_finished(&audit, &Ok(applied), &report);
            command_finished(&audit, &Ok(replayed), &CommandReport::default());
            command_finished(
                &audit,
                &Err(crate::Error::NamespaceFence(conflict)),
                &CommandReport::default(),
            );
            let adopt = adopt_request();
            let adopted = commit(
                &adopt,
                FenceCommitKind::Committed,
                FenceOutcome::Applied,
                (2, 3),
                Some(adoption_entry()),
            );
            command_finished(
                &CommandAudit::new(&adopt, FenceState::SourceWriteFenced),
                &Ok(adopted),
                &CommandReport::default(),
            );
        });
        let fenced = FenceError::new(FenceOutcome::MigrationWriteFenced, "fenced");
        for surface in DenialSurface::ALL {
            denied(&fenced, surface);
        }

        let mut quarantined = sample_record();
        quarantined.namespace = "t1".into();
        quarantined.role = super::super::state::Role::Target;
        quarantined.state = FenceState::TargetQuarantined;
        quarantined.created_at_ms = 10_000;
        let mut released = sample_record();
        released.namespace = "s2".into();
        released.state = FenceState::Released;
        released.created_at_ms = 1_000;
        let registry = FenceRegistry::seeded([
            ("s1".into(), StoredFence::Record(sample_record())),
            ("s2".into(), StoredFence::Record(released)),
            ("t1".into(), StoredFence::Record(quarantined)),
            (
                "u1".into(),
                StoredFence::Unavailable {
                    detail: super::super::outcome::FenceDetail::CorruptRecord,
                    reason: "test".into(),
                    marker: None,
                },
            ),
            (
                "plain".into(),
                StoredFence::None {
                    namespace_exists: true,
                },
            ),
        ]);
        // s1 (active) was created at 100 ms, s2 (released, not active) at 1 s.
        update_gauges(&registry, 60_100);

        let s = snapshot();
        let cmd = [("command", "AcquireSourceWriteFence")];
        assert_eq!(
            counter(&s, TRANSITIONS_TOTAL, &[cmd[0], ("outcome", "APPLIED")]),
            2
        );
        assert_eq!(
            counter(
                &s,
                TRANSITIONS_TOTAL,
                &[cmd[0], ("outcome", "FENCE_COMMAND_CONFLICT")]
            ),
            1
        );
        assert_eq!(counter(&s, REPLAYS_TOTAL, &[("result", "replay")]), 1);
        assert_eq!(counter(&s, REPLAYS_TOTAL, &[("result", "conflict")]), 1);
        assert_eq!(counter(&s, FORCED_TOTAL, &[("kind", "rollback")]), 2);
        assert_eq!(
            counter(&s, FORCED_TOTAL, &[("kind", "stream_termination")]),
            1
        );
        assert_eq!(counter(&s, ADOPTIONS_TOTAL, &[]), 1);
        match s.get(&(
            MetricKind::Histogram,
            DRAIN_DURATION_SECONDS.to_string(),
            labels(&[("kind", "write")]),
        )) {
            Some(DebugValue::Histogram(v)) => assert_eq!(v.len(), 1),
            other => panic!("drain histogram: {other:?}"),
        }
        for surface in DenialSurface::ALL {
            assert_eq!(
                counter(
                    &s,
                    DENIALS_TOTAL,
                    &[
                        ("code", "MIGRATION_WRITE_FENCED"),
                        ("surface", surface.as_str())
                    ]
                ),
                1
            );
        }
        let ns = |role, state| gauge(&s, NAMESPACES, &[("role", role), ("state", state)]);
        assert_eq!(ns("source", "SOURCE_WRITE_FENCED"), 1.0);
        assert_eq!(ns("source", "RELEASED"), 1.0);
        assert_eq!(ns("target", "TARGET_QUARANTINED"), 1.0);
        assert_eq!(ns("unknown", "UNKNOWN_UNAVAILABLE"), 1.0);
        assert_eq!(ns("source", "SOURCE_DRAINING"), 0.0);
        assert_eq!(ns("target", "TARGET_WRITABLE"), 0.0);
        assert_eq!(gauge(&s, OLDEST_ACTIVE_AGE_SECONDS, &[]), 60.0);

        let forbidden = [
            "ns".to_string(),
            "s1".to_string(),
            "t1".to_string(),
            Uuid::from_u128(0xb).to_string(),
            Uuid::from_u128(0xc).to_string(),
            Uuid::from_u128(3).to_string(),
            Uuid::from_u128(4).to_string(),
        ];
        for ((_, name, labels), _) in &s {
            if !name.starts_with("libsql_server_fence_") {
                continue;
            }
            for (key, value) in labels {
                assert!(
                    matches!(
                        key.as_str(),
                        "command"
                            | "outcome"
                            | "kind"
                            | "result"
                            | "code"
                            | "surface"
                            | "role"
                            | "state"
                    ),
                    "{name}: unexpected label {key}"
                );
                assert!(!forbidden.contains(value), "{name}: label {key}={value}");
            }
        }

        // An emptied registry sets every gauge back to zero.
        update_gauges(&FenceRegistry::seeded([]), 60_100);
        let s = snapshot();
        assert_eq!(
            gauge(
                &s,
                NAMESPACES,
                &[("role", "source"), ("state", "SOURCE_WRITE_FENCED")]
            ),
            0.0
        );
        assert_eq!(gauge(&s, OLDEST_ACTIVE_AGE_SECONDS, &[]), 0.0);
    }
}
