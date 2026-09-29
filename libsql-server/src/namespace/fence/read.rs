//! The source read fence (`docs/NAMESPACE_FENCE.md` section 9).
//!
//! `SetSourceReadFence` closes read admission in memory, persists `SOURCE_READ_DRAINING`, and
//! then waits for every read lease that was already held to be released: running SQL programs
//! (including cursors still producing rows and ATTACHes of the namespace from other
//! namespaces), dumps and replication streams. Leases are taken only after checking the gate
//! under the controller's lease lock, so once admission is closed the set can only shrink. At the
//! deadline the remaining work is cancelled and the drain keeps waiting for the actual
//! releases; it never takes elapsed time as proof that a reader has finished. Once no lease is
//! held it persists `SOURCE_READ_FENCED`.

use std::time::Duration;

use tokio::time::Instant;

use crate::namespace::meta_store::{FenceCommit, FenceContext, MetaStore};

use super::command::{DrainPolicy, FenceCommand, FenceRequest};
use super::controller::{FenceController, Transition};
use super::drain::{now_ms, FORCED_ROLLBACK_GRACE};
use super::hooks::HookPoint;
use super::outcome::FenceOutcome;
use super::state::{FenceState, OperationClass};
use super::transition::DrainCompletion;

/// How long `SetSourceReadFence` waits for running reads and streams before it cancels them,
/// when neither the request nor `--namespace-fence-default-read-drain-ms` names a deadline.
pub const DEFAULT_READ_DRAIN: Duration = Duration::from_secs(30);

/// `SetSourceReadFence`, steps 1 to 5 of section 9, under `transition`.
///
/// Returns the `APPLIED` commit of `SOURCE_READ_FENCED` once every read lease is released, the
/// `DRAINING` commit of `SOURCE_READ_DRAINING` when leases are still held after the deadline and
/// the cancellation that follows it (read admission stays closed and a replay of the same
/// command resumes the drain), or the stored result of a replay.
pub async fn set_source_read_fence(
    transition: &mut Transition,
    meta: &MetaStore,
    request: FenceRequest,
    mut ctx: FenceContext,
) -> crate::Result<FenceCommit> {
    let controller = transition.controller().clone();
    let key = (request.operation_id, request.command_id);
    let policy = match &request.command {
        FenceCommand::SetSourceReadFence { drain_policy } => {
            drain_policy.unwrap_or_else(|| meta.fence_default_read_drain())
        }
        _ => return transition.apply(meta, request, ctx).await,
    };

    // Step 2: close read admission in memory. From here on every new read lease is refused, so
    // the drain only waits for the leases already held. Where reads are already closed (a
    // resumed drain, a command being reconciled, a read-fenced namespace) nothing is closed.
    // A command the checks refuse (step 1, the metastore's) reopens it.
    if controller.permits(OperationClass::NormalRead).is_ok()
        && controller.gate().state() == FenceState::SourceWriteFenced
    {
        transition.close_read_admission(key);
        let _ = controller.hook(HookPoint::AfterClosingReads).await;
    }

    // Step 3: persist SOURCE_READ_DRAINING; its publication replaces the in-memory gate.
    let commit = match transition.apply(meta, request, ctx.clone()).await {
        Ok(commit) => commit,
        Err(e) => {
            transition.reopen_read_admission();
            return Err(e);
        }
    };
    if commit.receipt.outcome != FenceOutcome::Draining {
        return Ok(commit);
    }
    let drain_key = (commit.receipt.operation_id, commit.receipt.command_id);

    // Step 4.
    if !drain_readers(&controller, policy).await {
        return Ok(commit);
    }

    // Step 5.
    ctx.now_ms = now_ms();
    transition
        .complete_drain(meta, drain_key, DrainCompletion::SourceReads, ctx)
        .await
}

/// Wait until every read lease of the namespace is released. At the deadline the leases still
/// held are cancelled (SQL programs through their connection's cancel flag, dumps and streams
/// through their own), and the drain keeps waiting for the actual releases for one more
/// deadline, but at least [`FORCED_ROLLBACK_GRACE`]. `false` when leases are still held then:
/// the answer is `DRAINING`, never a guess.
async fn drain_readers(controller: &FenceController, policy: DrainPolicy) -> bool {
    let namespace = controller.namespace().clone();
    let deadline_after = Duration::from_millis(policy.deadline_ms);
    let deadline = Instant::now() + deadline_after;
    if wait_for_read_leases(controller, deadline).await {
        return true;
    }
    let _ = controller.hook(HookPoint::BeforeReadLeaseCancel).await;
    let held = controller.read_lease_counts();
    let asked = controller.cancel_read_leases();
    tracing::info!(
        %namespace,
        deadline_ms = policy.deadline_ms,
        sql = held.sql,
        dump = held.dump,
        replication = held.replication,
        cancelled = asked,
        "read drain deadline passed; cancelling the reads and streams still running"
    );
    let grace = Instant::now() + deadline_after.max(FORCED_ROLLBACK_GRACE);
    if wait_for_read_leases(controller, grace).await {
        return true;
    }
    let held = controller.read_lease_counts();
    tracing::warn!(
        %namespace,
        sql = held.sql,
        dump = held.dump,
        replication = held.replication,
        "read leases still held after cancellation; answering DRAINING"
    );
    false
}

/// Wait, on the controller's release notification, until no read lease is held. `false` when
/// `deadline` passes first.
async fn wait_for_read_leases(controller: &FenceController, deadline: Instant) -> bool {
    loop {
        let released = controller.read_released().notified();
        tokio::pin!(released);
        // Registered before the check, so a release in between is not missed.
        released.as_mut().enable();
        if controller.read_lease_counts().total() == 0 {
            return true;
        }
        tokio::select! {
            _ = &mut released => {}
            _ = tokio::time::sleep_until(deadline) => return false,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use rusqlite::functions::FunctionFlags;
    use uuid::Uuid;

    use super::*;
    use crate::auth::Authenticated;
    use crate::connection::config::DatabaseConfig;
    use crate::connection::program::Program;
    use crate::connection::{Connection as _, RequestContext};
    use crate::database::Connection;
    use crate::error::Error;
    use crate::namespace::fence::command::OnDeadline;
    use crate::namespace::fence::drain::tests::{fence_outcome, raw, Source, LONG, OP, PROMPT};
    use crate::namespace::fence::outcome::FenceError;
    use crate::namespace::RestoreOption;
    use crate::query_result_builder::test::{StepResult, TestBuilder};
    use crate::query_result_builder::QueryResultBuilder as _;

    const OTHER_OP: Uuid = Uuid::from_u128(0xb);
    /// A deadline that has already passed: the drain cancels at once.
    pub(crate) const NOW: DrainPolicy = DrainPolicy {
        deadline_ms: 0,
        on_deadline: OnDeadline::Fail,
    };

    /// A write-fenced source.
    pub(crate) async fn fenced_source() -> Source {
        let s = Source::new().await;
        raw(&s.conn().await, "insert into t values (1), (2)")
            .await
            .unwrap();
        let acquired = s.execute(s.acquire(OP, 1, LONG)).await.unwrap();
        assert_eq!(fence_outcome(&acquired), FenceOutcome::Applied);
        s
    }

    fn request(s: &Source, op: Uuid, command_id: u128, command: FenceCommand) -> FenceRequest {
        let gate = s.fence.gate();
        FenceRequest {
            namespace: "ns".into(),
            operation_id: op,
            command_id: Uuid::from_u128(command_id),
            expected_state: gate.state(),
            expected_revision: gate.revision(),
            command,
        }
    }

    pub(crate) fn read_fence(s: &Source, command_id: u128, policy: DrainPolicy) -> FenceRequest {
        request(
            s,
            OP,
            command_id,
            FenceCommand::SetSourceReadFence {
                drain_policy: Some(policy),
            },
        )
    }

    fn clear_read_fence(s: &Source, command_id: u128) -> FenceRequest {
        request(s, OP, command_id, FenceCommand::ClearSourceReadFence)
    }

    async fn conn_to(s: &Source, ns: &'static str) -> Arc<Connection> {
        let maker = s
            .store
            .with(ns.into(), |ns| ns.db.connection_maker())
            .await
            .unwrap();
        Arc::new(maker.create().await.unwrap())
    }

    /// Run `stmts` as one program on `conn`, the way a SQL request runs.
    async fn program(
        s: &Source,
        ns: &'static str,
        conn: &Arc<Connection>,
        stmts: &'static [&'static str],
    ) -> crate::Result<Vec<StepResult>> {
        let ctx = RequestContext::new(
            Authenticated::FullAccess,
            ns.into(),
            s.store.meta_store().clone(),
        );
        conn.execute_program(Program::seq(stmts), ctx, TestBuilder::default(), None)
            .await
            .map(|b| b.into_ret())
    }

    /// [`program`], on a task of its own.
    fn spawn_program(
        s: &Source,
        ns: &'static str,
        conn: &Arc<Connection>,
        stmts: &'static [&'static str],
    ) -> tokio::task::JoinHandle<crate::Result<Vec<StepResult>>> {
        let ctx = RequestContext::new(
            Authenticated::FullAccess,
            ns.into(),
            s.store.meta_store().clone(),
        );
        let conn = conn.clone();
        tokio::spawn(async move {
            conn.execute_program(Program::seq(stmts), ctx, TestBuilder::default(), None)
                .await
                .map(|b| b.into_ret())
        })
    }

    fn read_fenced(e: &Error) -> &FenceError {
        match e {
            Error::NamespaceFence(f) if f.outcome() == FenceOutcome::MigrationReadFenced => f,
            other => panic!("expected MIGRATION_READ_FENCED, got {other:?}"),
        }
    }

    fn step_read_fenced(step: &StepResult) {
        match step {
            Err(e) => {
                read_fenced(e);
            }
            Ok(rows) => panic!("expected MIGRATION_READ_FENCED, got rows {rows:?}"),
        }
    }

    fn assert_ok(steps: &[StepResult]) {
        for (i, step) in steps.iter().enumerate() {
            assert!(step.is_ok(), "step {i} failed: {step:?}");
        }
    }

    /// A `park()` SQL function on `conn`: it signals the returned receiver when a program
    /// reaches it, and returns once the returned sender is used. SQLite cannot interrupt it,
    /// so a program parked in it holds its read lease until the test lets it go.
    fn park(
        conn: &Connection,
    ) -> (
        tokio::sync::mpsc::UnboundedReceiver<()>,
        std::sync::mpsc::Sender<()>,
    ) {
        let (reached_tx, reached_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel::<()>();
        let parked = std::panic::AssertUnwindSafe((reached_tx, std::sync::Mutex::new(resume_rx)));
        conn.with_raw(move |c| {
            c.create_scalar_function("park", 0, FunctionFlags::SQLITE_UTF8, move |_| {
                let (reached, resume) = &*parked;
                reached.send(()).unwrap();
                resume.lock().unwrap().recv().unwrap();
                Ok(1)
            })
        })
        .unwrap();
        (reached_rx, resume_tx)
    }

    /// A `reached()` SQL function on `conn` that signals the returned receiver and returns.
    fn signal(conn: &Connection) -> tokio::sync::mpsc::UnboundedReceiver<()> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        let tx = std::panic::AssertUnwindSafe(tx);
        conn.with_raw(move |c| {
            c.create_scalar_function("reached", 0, FunctionFlags::SQLITE_UTF8, move |_| {
                tx.send(()).unwrap();
                Ok(1)
            })
        })
        .unwrap();
        rx
    }

    /// A program that is running when the read fence arrives keeps its lease: the drain waits
    /// for it and acknowledges only after it finished. Programs that start meanwhile are
    /// refused.
    #[tokio::test(flavor = "multi_thread")]
    async fn read_fence_waits_for_running_program() {
        let s = fenced_source().await;
        let conn = s.conn().await;
        let (mut reached, resume) = park(&conn);
        let running = spawn_program(
            &s,
            "ns",
            &conn,
            &["select park()", "select count(*) from t"],
        );
        reached.recv().await.unwrap();
        assert_eq!(s.fence.read_lease_counts().sql, 1);

        let fence = s.execute(read_fence(&s, 2, LONG));
        s.until_state(FenceState::SourceReadDraining).await;
        // New work is refused while the old program still runs.
        let refused = program(&s, "ns", &s.conn().await, &["select count(*) from t"]).await;
        read_fenced(&refused.unwrap_err());
        assert!(!fence.is_finished());

        resume.send(()).unwrap();
        let steps = running.await.unwrap().unwrap();
        assert_ok(&steps);
        let fenced = fence.await.unwrap();
        assert_eq!(fence_outcome(&fenced), FenceOutcome::Applied);
        assert_eq!(s.fence.gate().state(), FenceState::SourceReadFenced);
        assert_eq!(s.fence.read_lease_counts().total(), 0);
    }

    /// A program admitted after the read-closing gate is published, but before the state is
    /// persisted, is refused: the drain never has to wait for work that started after it closed
    /// admission.
    #[tokio::test(flavor = "multi_thread")]
    async fn program_after_closing_gate_is_refused() {
        let s = fenced_source().await;
        let closed = s.fence.hooks().pause_at(HookPoint::AfterClosingReads);
        let fence = s.execute(read_fence(&s, 2, LONG));
        closed.reached().await;
        assert_eq!(s.fence.gate().state(), FenceState::SourceWriteFenced);
        let refused = program(&s, "ns", &s.conn().await, &["select count(*) from t"]).await;
        read_fenced(&refused.unwrap_err());
        assert_eq!(s.fence.read_lease_counts().total(), 0);
        closed.resume();
        assert_eq!(fence_outcome(&fence.await.unwrap()), FenceOutcome::Applied);
    }

    /// At the deadline a running program is cancelled through its connection's cancel flag;
    /// the drain waits for the actual release and then acknowledges. The program reports the
    /// read fence.
    #[tokio::test(flavor = "multi_thread")]
    async fn read_fence_cancels_at_deadline() {
        let s = fenced_source().await;
        let conn = s.conn().await;
        let mut reached = signal(&conn);
        let running = spawn_program(
            &s,
            "ns",
            &conn,
            &[
                "select reached()",
                "with recursive c(x) as (select 1 union all select x + 1 from c) \
                         select count(*) from c",
            ],
        );
        reached.recv().await.unwrap();
        assert_eq!(s.fence.read_lease_counts().sql, 1);

        let fenced = tokio::time::timeout(PROMPT, s.execute(read_fence(&s, 2, NOW)))
            .await
            .expect("the cancelled program never released its lease")
            .unwrap();
        assert_eq!(fence_outcome(&fenced), FenceOutcome::Applied);
        let result = tokio::time::timeout(PROMPT, running)
            .await
            .unwrap()
            .unwrap();
        read_fenced(&result.unwrap_err());
        assert!(conn.is_autocommit().await.unwrap());
    }

    /// A lease that is not released after cancellation keeps the drain from acknowledging: the
    /// answer is `DRAINING`, reads stay closed, and a replay of the same command completes the
    /// drain once the lease is gone.
    #[tokio::test(flavor = "multi_thread")]
    async fn unreleased_lease_answers_draining_and_replay_completes() {
        let s = fenced_source().await;
        let conn = s.conn().await;
        let (mut reached, resume) = park(&conn);
        let running = spawn_program(&s, "ns", &conn, &["select park()"]);
        reached.recv().await.unwrap();

        let request = read_fence(&s, 2, NOW);
        let draining = s.execute(request.clone()).await.unwrap();
        assert_eq!(fence_outcome(&draining), FenceOutcome::Draining);
        assert_eq!(s.fence.gate().state(), FenceState::SourceReadDraining);
        let refused = program(&s, "ns", &s.conn().await, &["select 1"]).await;
        read_fenced(&refused.unwrap_err());

        resume.send(()).unwrap();
        // The program was cancelled by the fence; it reports the fence, not its rows.
        read_fenced(&running.await.unwrap().unwrap_err());
        let replayed = s.execute(request).await.unwrap();
        assert_eq!(fence_outcome(&replayed), FenceOutcome::Applied);
        assert_eq!(s.fence.gate().state(), FenceState::SourceReadFenced);
    }

    /// A connection left idle inside a transaction holds no lease, so the drain does not wait
    /// for it; its next program is refused and its transaction rolled back.
    #[tokio::test(flavor = "multi_thread")]
    async fn idle_txn_fails_on_next_program() {
        let s = fenced_source().await;
        let conn = s.conn().await;
        assert_ok(
            &program(&s, "ns", &conn, &["begin", "select count(*) from t"])
                .await
                .unwrap(),
        );
        assert!(!conn.is_autocommit().await.unwrap());
        assert_eq!(s.fence.read_lease_counts().total(), 0);

        let fenced = s.execute(read_fence(&s, 2, LONG)).await.unwrap();
        assert_eq!(fence_outcome(&fenced), FenceOutcome::Applied);

        let refused = program(&s, "ns", &conn, &["select count(*) from t", "commit"]).await;
        read_fenced(&refused.unwrap_err());
        assert!(conn.is_autocommit().await.unwrap());
    }

    /// Clearing the read fence reopens reads and leaves writes fenced.
    #[tokio::test(flavor = "multi_thread")]
    async fn clear_read_fence_reopens_reads_not_writes() {
        let s = fenced_source().await;
        let fenced = s.execute(read_fence(&s, 2, LONG)).await.unwrap();
        assert_eq!(fence_outcome(&fenced), FenceOutcome::Applied);
        let conn = s.conn().await;
        read_fenced(&program(&s, "ns", &conn, &["select 1"]).await.unwrap_err());

        let revision = s.fence.gate().revision();
        let cleared = s.execute(clear_read_fence(&s, 3)).await.unwrap();
        assert_eq!(fence_outcome(&cleared), FenceOutcome::Applied);
        let gate = s.fence.gate();
        assert_eq!(gate.state(), FenceState::SourceWriteFenced);
        assert!(gate.revision() > revision);

        let steps = program(
            &s,
            "ns",
            &conn,
            &["select count(*) from t", "insert into t values (3)"],
        )
        .await
        .unwrap();
        assert!(matches!(
            steps[0].as_ref().unwrap().as_slice(),
            [row] if matches!(row.as_slice(), [crate::query::Value::Integer(2)])
        ));
        match &steps[1] {
            Err(Error::NamespaceFence(e)) => {
                assert_eq!(e.outcome(), FenceOutcome::MigrationWriteFenced)
            }
            other => panic!("expected MIGRATION_WRITE_FENCED, got {other:?}"),
        }
        assert_eq!(s.count().await, 2);
    }

    /// A read fence the checks refuse (another operation owns the source) reopens read
    /// admission it had closed, and reads are served again.
    #[tokio::test(flavor = "multi_thread")]
    async fn refused_read_fence_reopens_reads() {
        let s = fenced_source().await;
        let request = request(
            &s,
            OTHER_OP,
            2,
            FenceCommand::SetSourceReadFence {
                drain_policy: Some(LONG),
            },
        );
        let refused = s.execute(request).await.unwrap();
        assert_eq!(
            fence_outcome(&refused),
            FenceOutcome::FenceOwnedByAnotherOperation
        );
        let gate = s.fence.gate();
        assert_eq!(gate.state(), FenceState::SourceWriteFenced);
        assert!(gate.closing_reads.is_none());
        assert_ok(
            &program(&s, "ns", &s.conn().await, &["select count(*) from t"])
                .await
                .unwrap(),
        );
    }

    /// ATTACH of a namespace is a read of that namespace: a program on another namespace that
    /// has it attached holds a lease on it, so its read fence waits for that program; once it is
    /// read-fenced, a new ATTACH and any program on a connection that still has it attached are
    /// refused, and a connection that detached it is served again.
    #[tokio::test(flavor = "multi_thread")]
    async fn attach_of_read_fenced_namespace_denied() {
        let s = Source::new().await;
        raw(&s.conn().await, "insert into t values (1)")
            .await
            .unwrap();
        let config = s
            .store
            .with("ns".into(), |ns| ns.db_config_store.clone())
            .await
            .unwrap();
        config
            .store(DatabaseConfig {
                allow_attach: true,
                txn_timeout: Some(Duration::from_secs(600)),
                ..Default::default()
            })
            .await
            .unwrap();
        s.store
            .create(
                "other".into(),
                RestoreOption::Latest,
                DatabaseConfig::default(),
            )
            .await
            .unwrap();
        let acquired = s.execute(s.acquire(OP, 1, LONG)).await.unwrap();
        assert_eq!(fence_outcome(&acquired), FenceOutcome::Applied);

        let other = conn_to(&s, "other").await;
        let steps = program(
            &s,
            "other",
            &other,
            &["attach ns as a", "select count(*) from a.t"],
        )
        .await
        .unwrap();
        assert_ok(&steps);
        assert_eq!(s.fence.read_lease_counts().total(), 0);

        // A later program on the connection that has `ns` attached holds a lease on it.
        let (mut reached, resume) = park(&other);
        let running = spawn_program(&s, "other", &other, &["select park()"]);
        reached.recv().await.unwrap();
        assert_eq!(s.fence.read_lease_counts().sql, 1);
        let fence = s.execute(read_fence(&s, 2, LONG));
        s.until_state(FenceState::SourceReadDraining).await;
        assert!(!fence.is_finished());
        resume.send(()).unwrap();
        assert_ok(&running.await.unwrap().unwrap());
        assert_eq!(fence_outcome(&fence.await.unwrap()), FenceOutcome::Applied);

        // The connection that still has it attached is refused outright...
        read_fenced(
            &program(&s, "other", &other, &["select 1"])
                .await
                .unwrap_err(),
        );
        // ...a fresh ATTACH is refused as a step...
        let fresh = conn_to(&s, "other").await;
        let steps = program(&s, "other", &fresh, &["attach ns as b"])
            .await
            .unwrap();
        step_read_fenced(&steps[0]);
        // ...and a connection that detached it is served again.
        let steps = program(&s, "other", &fresh, &["select 1"]).await.unwrap();
        assert_ok(&steps);
    }
}
