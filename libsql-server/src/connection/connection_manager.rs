use std::ops::Deref;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossbeam::deque::Steal;
use crossbeam::sync::{Parker, Unparker};
use hashbrown::HashMap;
use libsql_sys::wal::wrapper::{WrapWal, WrappedWal};
use libsql_sys::wal::{CheckpointMode, Sqlite3Wal, Sqlite3WalManager, Wal};
use metrics::atomics::AtomicU64;
use parking_lot::{Mutex, MutexGuard};
use rusqlite::ErrorCode;

use super::connection_core::CoreConnection;
use super::TXN_TIMEOUT;
use crate::namespace::fence::controller::FenceConnState;

pub type ConnId = u64;
pub type InnerWalManager = Sqlite3WalManager;

pub type InnerWal = Sqlite3Wal;
pub type ManagedConnectionWal = WrappedWal<ManagedConnectionWalWrapper, InnerWal>;

#[derive(Copy, Clone, Debug)]
struct Slot {
    id: ConnId,
    started_at: Instant,
    state: SlotState,
}

#[derive(Clone)]
struct Abort(Arc<dyn Fn() + Send + Sync + 'static>);

impl Abort {
    fn from_conn<T: Wal + Send + 'static>(conn: &Arc<Mutex<CoreConnection<T>>>) -> Self {
        let conn = Arc::downgrade(conn);
        Self(Arc::new(move || {
            conn.upgrade()
                .expect("connection still owns the slot, so it must exist")
                .lock()
                .force_rollback();
        }))
    }

    fn abort(&self) {
        (self.0)()
    }
}

#[derive(Clone)]
pub struct ConnectionManager {
    inner: Arc<ConnectionManagerInner>,
}

impl ConnectionManager {
    pub(super) fn register_connection<T: Wal + Send + Send + 'static>(
        &self,
        conn: &Arc<Mutex<CoreConnection<T>>>,
        id: ConnId,
    ) {
        let abort = Abort::from_conn(conn);
        self.inner.abort_handle.lock().insert(id, abort);
    }
}

impl Deref for ConnectionManager {
    type Target = ConnectionManagerInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl ConnectionManager {
    pub fn new(txn_timeout_duration: Duration) -> ConnectionManager {
        Self {
            inner: Arc::new(ConnectionManagerInner {
                txn_timeout_duration,
                ..Default::default()
            }),
        }
    }
}

pub struct ConnectionManagerInner {
    /// When a slot becomes available, the connection allowed to make progress is put here
    /// the connection currently holding the lock
    /// bool: acquired
    current: Mutex<Option<Slot>>,
    /// map of registered connections
    abort_handle: Mutex<HashMap<ConnId, Abort>>,
    /// threads waiting to acquire the lock
    /// todo: limit how many can be push
    write_queue: crossbeam::deque::Injector<(ConnId, Unparker)>,
    txn_timeout_duration: Duration,
    /// the time we are given to acquire a transaction after we were given a slot
    acquire_timeout_duration: Duration,
    next_conn_id: AtomicU64,
    sync_token: AtomicU64,
}

impl Default for ConnectionManagerInner {
    fn default() -> Self {
        Self {
            current: Default::default(),
            abort_handle: Default::default(),
            write_queue: Default::default(),
            txn_timeout_duration: TXN_TIMEOUT,
            acquire_timeout_duration: Duration::from_millis(15),
            next_conn_id: Default::default(),
            sync_token: AtomicU64::new(0),
        }
    }
}

#[derive(Clone)]
pub struct ManagedConnectionWalWrapper {
    id: ConnId,
    manager: ConnectionManager,
    /// The connection's fence state, which `begin_write_txn` checks against the namespace's
    /// gate (`docs/NAMESPACE_FENCE.md` section 8.1).
    fence: Arc<FenceConnState>,
}

impl ManagedConnectionWalWrapper {
    pub(crate) fn new(manager: ConnectionManager, fence: Arc<FenceConnState>) -> Self {
        let id = manager.inner.next_conn_id.fetch_add(1, Ordering::SeqCst);
        Self { id, manager, fence }
    }

    pub fn id(&self) -> ConnId {
        self.id
    }

    fn acquire(&self) -> libsql_sys::wal::Result<()> {
        let parker = Parker::new();
        let mut enqueued = false;
        let enqueued_at = Instant::now();
        let sync_token = self.manager.sync_token.load(Ordering::SeqCst);
        loop {
            let mut current = self.manager.current.lock();
            // if current is not currently us, and we havent enqueued yet, then enqueue
            // current can be us in two cases:
            // - in previous iteration, the queue was empty, and we popped ourselves
            // - we tried to acquire the lock during the previous iteration, but the underlying
            // method returned an error and we had to retry immediately, by re-entering this
            // function.
            if self.manager.sync_token.load(Ordering::SeqCst) != sync_token {
                return Err(rusqlite::ffi::Error {
                    code: ErrorCode::DatabaseBusy,
                    extended_code: 517, // stale read
                });
            }
            // If other connection is about to checkpoint - we better to immediately return.
            //
            // The reason is that write transaction are upgraded from read transactions in SQLite.
            // Due to this, every write transaction need to hold SHARED-WAL lock and if we will
            // block write transaction here - we will prevent checkpoint process from restarting the WAL
            // (because it needs to acquire EXCLUSIVE-WAL lock)
            //
            // So, the scenario is following:
            // T0: we have a bunch of SELECT queries which will execute till time T2
            // T1: CHECKPOINT process is starting: it holds CKPT and WRITE lock and attempt to acquire
            //     EXCLUSIVE-WAL locks one by one in order to check the position of readers. CHECKPOINT will
            //     use busy handler and can potentially acquire lock not from the first attempt.
            // T2: CHECKPOINT process were able to check all WAL reader positions (by acquiring lock or atomically check reader position)
            //     and started to transfer WAL to the DB file
            // T3: INSERT query starts executing: it started as a read transaction and holded SHARED-WAL lock but then it needs to
            //     upgrade to write transaction through begin_write_txn call
            // T4: CHECKPOINT transferred all pages from WAL to DB file and need to check if it can restart the WAL. In order to
            //     do that it needs to hold all EXCLUSIVE-WAL locks to make sure that all readers use only DB file
            //
            // In the scenario above, if we will park INSERT at the time T3 - CHECKPOINT will be unable to hold EXCLUSIVE-WAL
            // locks and so WAL will not be truncated.
            // In case when DB has continious load with overlapping reads and writes - this problem became very noticeable
            // as it can defer WAL truncation a lot.
            //
            // Also, such implementation is more aligned with LibSQL/SQLite behaviour where sqlite3WalBeginWriteTransaction
            // immediately abort with SQLITE_BUSY error if it can't acquire WRITE lock (which CHECKPOINT also take before start of the work)
            // and busy handler (e.g. retries) for writes are invoked by SQLite at upper layer of request processing.
            match *current {
                Some(Slot {
                    id,
                    state: SlotState::Acquired(SlotType::Checkpoint),
                    ..
                }) if id != self.id => {
                    return Err(rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY));
                }
                _ => {}
            }
            // note, that it's important that we return SQLITE_BUSY error for CHECKPOINT starvation problem before that condition
            // because after we will add something to the write_queue - we can't easily abort execution of acquire() method
            if current.as_mut().map_or(true, |slot| slot.id != self.id) && !enqueued {
                self.manager
                    .write_queue
                    .push((self.id, parker.unparker().clone()));
                enqueued = true;
                tracing::debug!("enqueued");
            }
            match *current {
                Some(ref mut slot) => {
                    tracing::debug!("current slot: {slot:?}");
                    // this is us, the previous connection put us here when it closed the
                    // transaction
                    if slot.id == self.id {
                        assert!(
                            slot.state.is_notified() || slot.state.is_failure(),
                            "{slot:?}"
                        );
                        slot.state = SlotState::Acquiring;
                        tracing::debug!(
                            line = line!(),
                            "got lock after: {:?}",
                            enqueued_at.elapsed()
                        );
                        break;
                    } else {
                        // not us, maybe we need to steal the lock?
                        let since_started = slot.started_at.elapsed();
                        let deadline = slot.started_at + self.manager.txn_timeout_duration;
                        match slot.state {
                            SlotState::Acquired(..) => {
                                if since_started >= self.manager.txn_timeout_duration {
                                    let id = slot.id;
                                    drop(current);
                                    let handle = {
                                        self.manager
                                            .inner
                                            .abort_handle
                                            .lock()
                                            .get(&id)
                                            .unwrap()
                                            .clone()
                                    };
                                    // the guard must be dropped before rolling back, or end write txn will
                                    // deadlock
                                    tracing::debug!("forcing rollback of {id}");
                                    handle.abort();
                                    tracing::debug!(line = line!(), "parking");
                                    parker.park();
                                    tracing::debug!(line = line!(), "unparked");
                                } else {
                                    // otherwise we wait for the txn to timeout, or to be unparked by it
                                    let deadline =
                                        slot.started_at + self.manager.inner.txn_timeout_duration;
                                    drop(current);
                                    tracing::debug!(line = line!(), "parking");
                                    parker.park_deadline(deadline);
                                    tracing::debug!(
                                        line = line!(),
                                        "before_deadline?: {:?}",
                                        Instant::now() < deadline
                                    );
                                }
                            }
                            // we may want to limit how long a lock takes to go from notified
                            // to acquiring
                            SlotState::Acquiring | SlotState::Notified => {
                                drop(current);
                                tracing::debug!(line = line!(), "parking");
                                parker.park_deadline(deadline);
                                tracing::debug!(
                                    line = line!(),
                                    "unparked after before_deadline?: {:?}",
                                    Instant::now() < deadline
                                );
                            }
                            SlotState::Failure => {
                                if since_started >= self.manager.inner.acquire_timeout_duration {
                                    // the connection failed to acquire a transaction during the grace
                                    // period. schedule the next transaction
                                    match self.schedule_next(&mut current) {
                                        Some(id) if id == self.id => {
                                            current.as_mut().unwrap().state = SlotState::Acquiring;
                                            break;
                                        }
                                        Some(_) => {
                                            drop(current);
                                            tracing::debug!(line = line!(), "parking");
                                            parker.park();
                                            tracing::debug!(line = line!(), "unparked");
                                        }
                                        None => {
                                            *current = Some(Slot {
                                                id: self.id,
                                                started_at: Instant::now(),
                                                state: SlotState::Acquiring,
                                            });
                                            break;
                                        }
                                    }
                                } else {
                                    tracing::trace!("noticed failure from id={}, parking until end of grace period", slot.id);
                                    let deadline = slot.started_at
                                        + self.manager.inner.acquire_timeout_duration;
                                    drop(current);
                                    tracing::debug!(line = line!(), "parking");
                                    parker.park_deadline(deadline);
                                    tracing::debug!(
                                        line = line!(),
                                        "unparked after before_deadline?: {:?}",
                                        Instant::now() < deadline
                                    );
                                }
                            }
                        }
                    }
                }
                None => match self.schedule_next(&mut current) {
                    Some(id) if id == self.id => {
                        current.as_mut().unwrap().state = SlotState::Acquiring;
                        break;
                    }
                    Some(_) => {
                        drop(current);
                        tracing::debug!(line = line!(), "parking");
                        parker.park();
                        tracing::debug!(line = line!(), "unparked");
                    }
                    None => {
                        *current = Some(Slot {
                            id: self.id,
                            started_at: Instant::now(),
                            state: SlotState::Acquiring,
                        })
                    }
                },
            }
        }

        Ok(())
    }

    #[tracing::instrument(skip(self, current))]
    #[track_caller]
    fn schedule_next(&self, current: &mut MutexGuard<Option<Slot>>) -> Option<ConnId> {
        let next = loop {
            match self.manager.write_queue.steal() {
                Steal::Empty => break None,
                Steal::Success(item) => break Some(item),
                Steal::Retry => (),
            }
        };

        match next {
            Some((id, unpaker)) => {
                tracing::debug!(line = line!(), "unparking id={id}");
                **current = Some(Slot {
                    id,
                    started_at: Instant::now(),
                    state: SlotState::Notified,
                });
                unpaker.unpark();
                Some(id)
            }
            None => None,
        }
    }

    #[tracing::instrument(skip(self))]
    #[track_caller]
    fn release(&self) {
        let mut current = self.manager.current.lock();
        let Some(slot) = current.take() else {
            unreachable!("no lock to release")
        };

        assert_eq!(slot.id, self.id);

        tracing::debug!("transaction finished after {:?}", slot.started_at.elapsed());
        match self.schedule_next(&mut current) {
            Some(_) => (),
            None => {
                *current = None;
            }
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
enum SlotType {
    WriteTxn,
    Checkpoint,
}

#[derive(Copy, Clone, Debug)]
enum SlotState {
    Notified,
    Acquiring,
    Acquired(SlotType),
    Failure,
}

impl SlotState {
    /// Returns `true` if the slot state is [`Notified`].
    ///
    /// [`Notified`]: SlotState::Notified
    #[must_use]
    fn is_notified(&self) -> bool {
        matches!(self, Self::Notified)
    }

    /// Returns `true` if the slot state is [`Failure`].
    ///
    /// [`Failure`]: SlotState::Failure
    #[must_use]
    fn is_failure(&self) -> bool {
        matches!(self, Self::Failure)
    }
}

impl WrapWal<InnerWal> for ManagedConnectionWalWrapper {
    #[tracing::instrument(skip_all, fields(id = self.id))]
    fn begin_write_txn(&mut self, wrapped: &mut InnerWal) -> libsql_sys::wal::Result<()> {
        tracing::debug!("begin write");
        // The authoritative fence check. It runs before `acquire()`, so a refusal holds no slot
        // and releases none, and it returns `SQLITE_AUTH` rather than `SQLITE_BUSY`, so SQLite's
        // busy handler does not retry it. The typed reason is left in the connection's fence
        // state for the program layer.
        if self.fence.admit_write().is_err() {
            return Err(rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_AUTH));
        }
        self.acquire()?;
        match wrapped.begin_write_txn() {
            Ok(_) => {
                tracing::debug!("transaction acquired");
                let mut lock = self.manager.current.lock();
                lock.as_mut().unwrap().state = SlotState::Acquired(SlotType::WriteTxn);

                Ok(())
            }
            Err(e) => {
                if !matches!(e.code, ErrorCode::DatabaseBusy) {
                    // this is not a retriable error
                    tracing::debug!("error acquiring lock, releasing: {e}");
                    self.release();
                } else {
                    let mut lock = self.manager.current.lock();
                    lock.as_mut().unwrap().state = SlotState::Failure;
                    tracing::debug!("error acquiring lock: {e}");
                }
                Err(e)
            }
        }
    }

    #[tracing::instrument(skip_all, fields(id = self.id))]
    fn checkpoint(
        &mut self,
        wrapped: &mut InnerWal,
        db: &mut libsql_sys::wal::Sqlite3Db,
        mode: libsql_sys::wal::CheckpointMode,
        busy_handler: Option<&mut dyn libsql_sys::wal::BusyHandler>,
        sync_flags: u32,
        // temporary scratch buffer
        buf: &mut [u8],
        checkpoint_cb: Option<&mut dyn libsql_sys::wal::CheckpointCallback>,
        in_wal: Option<&mut i32>,
        backfilled: Option<&mut i32>,
    ) -> libsql_sys::wal::Result<()> {
        let before = Instant::now();
        self.acquire()?;
        self.manager.current.lock().as_mut().unwrap().state =
            SlotState::Acquired(SlotType::Checkpoint);

        let mode = if rand::random::<f32>() < 0.1 {
            CheckpointMode::Truncate
        } else {
            mode
        };

        if mode as i32 >= CheckpointMode::Restart as i32 {
            tracing::debug!("forcing queue sync");
            self.manager.sync_token.fetch_add(1, Ordering::SeqCst);
            let queue_len = self.manager.write_queue.len();
            for _ in 0..queue_len {
                let (id, unparker) = self.manager.write_queue.steal().success().unwrap();
                tracing::debug!("forcing queue sync for id={id}");
                unparker.unpark();
            }
        }

        tracing::debug!("attempted checkpoint mode: {mode:?}");
        let ret = wrapped.checkpoint(
            db,
            mode,
            busy_handler,
            sync_flags,
            buf,
            checkpoint_cb,
            in_wal,
            backfilled,
        );

        self.release();

        tracing::debug!("checkpoint called: {:?}", before.elapsed());
        ret
    }

    #[tracing::instrument(skip_all, fields(id = self.id))]
    fn begin_read_txn(&mut self, wrapped: &mut InnerWal) -> libsql_sys::wal::Result<bool> {
        tracing::debug!("begin read txn");
        // Recorded before the snapshot is taken: a transition racing with it leaves the
        // transaction with the older generation, which can only refuse a later upgrade.
        self.fence.begin_read_txn();
        wrapped.begin_read_txn()
    }

    #[tracing::instrument(skip_all, fields(id = self.id))]
    fn end_read_txn(&mut self, wrapped: &mut InnerWal) {
        wrapped.end_read_txn();
        {
            let current = self.manager.current.lock();
            // end read will only close the write txn if we actually acquired one, so only release
            // if the slot acquire the transaction lock
            if let Some(Slot {
                id,
                state: SlotState::Acquired(..),
                ..
            }) = *current
            {
                // releasing read transaction releases the write lock (see wal.c)
                if id == self.id {
                    drop(current);
                    self.release();
                }
            }
        }
        tracing::debug!("end read txn");
    }

    #[tracing::instrument(skip_all, fields(id = self.id))]
    fn end_write_txn(&mut self, wrapped: &mut InnerWal) -> libsql_sys::wal::Result<()> {
        wrapped.end_write_txn()?;
        tracing::debug!("end write txn");
        self.release();

        Ok(())
    }

    #[tracing::instrument(skip_all, fields(id = self.id))]
    fn close<M: libsql_sys::wal::WalManager<Wal = InnerWal>>(
        &mut self,
        manager: &M,
        wrapped: &mut InnerWal,
        db: &mut libsql_sys::wal::Sqlite3Db,
        sync_flags: std::ffi::c_int,
        _scratch: Option<&mut [u8]>,
    ) -> libsql_sys::wal::Result<()> {
        let before = Instant::now();
        let ret = manager.close(wrapped, db, sync_flags, None);
        {
            let current = self.manager.current.lock();
            if let Some(slot @ Slot { id, .. }) = *current {
                if id == self.id {
                    tracing::debug!(
                        id = self.id,
                        "connection closed without releasing lock: {slot:?}"
                    );
                    drop(current);
                    self.release()
                }
            }
        }

        self.manager.inner.abort_handle.lock().remove(&self.id);
        tracing::debug!(id = self.id, "closed in {:?}", before.elapsed());
        ret
    }
}

/// The WAL write gate (`docs/NAMESPACE_FENCE.md` section 8.1): tests on real connections of a
/// namespace whose fence controller goes through committed metastore transitions.
#[cfg(test)]
mod fence_tests {
    use std::path::Path;
    use std::sync::Arc;

    use libsql_sys::wal::wrapper::PassthroughWalWrapper;
    use libsql_sys::wal::Sqlite3WalManager;
    use rusqlite::functions::FunctionFlags;
    use rusqlite::ErrorCode;
    use tempfile::tempdir;

    use crate::connection::connection_core::CoreConnection;
    use crate::connection::legacy::{LegacyConnection, MakeLegacyConnection};
    use crate::connection::program::Program;
    use crate::connection::Connection as _;
    use crate::error::Error;
    use crate::namespace::fence::controller::tests::{
        create_namespace, ctx, fence_source, open_metastore, release, OP,
    };
    use crate::namespace::fence::controller::FenceController;
    use crate::namespace::fence::outcome::{FenceDetail, FenceError, FenceOutcome};
    use crate::namespace::fence::state::FenceState;
    use crate::namespace::meta_store::{MetaStore, MetaStoreHandle};
    use crate::query_result_builder::test::{StepResult, TestBuilder};
    use crate::query_result_builder::QueryResultBuilder as _;
    use crate::DEFAULT_AUTO_CHECKPOINT;

    type Conn = LegacyConnection<PassthroughWalWrapper>;

    struct Harness {
        _dir: tempfile::TempDir,
        meta: MetaStore,
        controller: Arc<FenceController>,
        maker: MakeLegacyConnection<PassthroughWalWrapper>,
    }

    impl Harness {
        async fn new() -> Self {
            let dir = tempdir().unwrap();
            let meta_dir = dir.path().join("meta");
            let db_dir = dir.path().join("db");
            std::fs::create_dir_all(&meta_dir).unwrap();
            std::fs::create_dir_all(&db_dir).unwrap();
            let meta = open_metastore(&meta_dir).await;
            create_namespace(&meta, "ns").await;
            let controller = FenceController::unfenced("ns".into());
            let maker = make_connections(&db_dir, controller.clone()).await;
            let this = Self {
                _dir: dir,
                meta,
                controller,
                maker,
            };
            let conn = this.conn().await;
            assert_ok(&run(&conn, &["create table t (x)"]).await);
            this
        }

        async fn conn(&self) -> Conn {
            self.maker.make_connection().await.unwrap()
        }

        /// UNFENCED -> SOURCE_DRAINING -> SOURCE_WRITE_FENCED.
        async fn fence(&self) {
            fence_source(&self.meta, &self.controller, OP).await;
            assert_eq!(
                self.controller.gate().state(),
                FenceState::SourceWriteFenced
            );
        }

        /// SOURCE_WRITE_FENCED -> RELEASED: writes are admitted again, under a new generation.
        async fn release(&self) {
            let revision = self.controller.gate().revision();
            self.controller
                .apply_command(&self.meta, release("ns", OP, 2, revision), ctx())
                .await
                .unwrap();
            assert_eq!(self.controller.gate().state(), FenceState::Released);
        }
    }

    async fn make_connections(
        path: &Path,
        fence: Arc<FenceController>,
    ) -> MakeLegacyConnection<PassthroughWalWrapper> {
        MakeLegacyConnection::new(
            path.into(),
            PassthroughWalWrapper,
            Default::default(),
            Default::default(),
            MetaStoreHandle::load(path).unwrap(),
            Arc::new([]),
            100000000,
            100000000,
            DEFAULT_AUTO_CHECKPOINT,
            Arc::new(|| None),
            None,
            Default::default(),
            Arc::new(|_| unreachable!()),
            Arc::new(|| Sqlite3WalManager::default()),
            fence,
        )
        .await
        .unwrap()
    }

    async fn run(conn: &Conn, stmts: &[&'static str]) -> Vec<StepResult> {
        let inner = conn.inner.clone();
        let stmts = stmts.to_vec();
        tokio::task::spawn_blocking(move || {
            CoreConnection::run(inner, Program::seq(&stmts), TestBuilder::default())
                .unwrap()
                .into_ret()
        })
        .await
        .unwrap()
    }

    fn assert_ok(steps: &[StepResult]) {
        for (i, step) in steps.iter().enumerate() {
            assert!(step.is_ok(), "step {i} failed: {step:?}");
        }
    }

    fn fence_error(step: &StepResult) -> &FenceError {
        match step {
            Err(Error::NamespaceFence(e)) => e,
            other => panic!("expected a fence denial, got {other:?}"),
        }
    }

    async fn count(conn: &Conn) -> i64 {
        conn.with_raw(|c| c.query_row("select count(*) from t", (), |r| r.get(0)))
            .unwrap()
    }

    /// A program is admitted, the fence is acquired and released while it runs, and the write it
    /// then attempts is refused at the WAL although the live gate is open again: the program was
    /// admitted under a generation that is no longer current. The race is held open by a SQL
    /// function that parks the program between admission and its write.
    #[tokio::test(flavor = "multi_thread")]
    async fn wal_gate_rejects_program_admitted_before_fence() {
        let h = Harness::new().await;
        let conn = h.conn().await;

        let (reached_tx, mut reached_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
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

        let admitted_at = h.controller.write_generation();
        let program = tokio::spawn({
            let conn = conn.clone();
            async move { run(&conn, &["select park()", "insert into t values (1)"]).await }
        });
        reached_rx.recv().await.unwrap();
        assert_eq!(conn.fence.program_generation(), admitted_at);

        h.fence().await;
        h.release().await;
        assert!(h.controller.write_generation() > admitted_at);
        resume_tx.send(()).unwrap();

        let steps = program.await.unwrap();
        assert!(steps[0].is_ok());
        let e = fence_error(&steps[1]);
        assert_eq!(e.outcome(), FenceOutcome::MigrationWriteFenced);
        assert_eq!(e.detail(), Some(FenceDetail::StaleTransaction));
        assert_eq!(count(&conn).await, 0);

        // The next program is admitted under the current generation and writes.
        assert_ok(&run(&conn, &["insert into t values (2)"]).await);
        assert_eq!(count(&conn).await, 1);
    }

    /// A read transaction opened before a transition cannot be upgraded to a write transaction
    /// after it, whether the gate is still closed or open again.
    #[tokio::test(flavor = "multi_thread")]
    async fn fence_rejects_read_to_write_upgrade() {
        let h = Harness::new().await;
        let conn = h.conn().await;

        // Gate closed: refused before the write runs.
        assert_ok(&run(&conn, &["begin", "select * from t"]).await);
        h.fence().await;
        let steps = run(&conn, &["insert into t values (1)"]).await;
        assert_eq!(
            fence_error(&steps[0]).outcome(),
            FenceOutcome::MigrationWriteFenced
        );

        // Gate open again: the transaction still belongs to the old generation, and only the
        // WAL gate can tell.
        h.release().await;
        let steps = run(&conn, &["insert into t values (1)"]).await;
        let e = fence_error(&steps[0]);
        assert_eq!(e.outcome(), FenceOutcome::MigrationWriteFenced);
        assert_eq!(e.detail(), Some(FenceDetail::StaleTransaction));
        assert_ok(&run(&conn, &["rollback"]).await);

        // A fresh transaction writes.
        assert_ok(&run(&conn, &["begin", "insert into t values (1)", "commit"]).await);
        assert_eq!(count(&conn).await, 1);
    }

    /// DDL, a pragma that writes the header, and `BEGIN IMMEDIATE` are refused while writes are
    /// fenced; reads keep working, and nothing was written.
    #[tokio::test(flavor = "multi_thread")]
    async fn fence_rejects_ddl_and_pragma() {
        let h = Harness::new().await;
        let conn = h.conn().await;
        h.fence().await;

        for stmt in [
            "create table u (x)",
            "create index i on t (x)",
            "drop table t",
            "pragma user_version = 7",
            "begin immediate",
        ] {
            let steps = run(&conn, &[stmt]).await;
            assert_eq!(
                fence_error(&steps[0]).outcome(),
                FenceOutcome::MigrationWriteFenced,
                "{stmt}"
            );
            assert!(conn.inner.lock().is_autocommit(), "{stmt}");
        }
        assert_ok(&run(&conn, &["select * from t"]).await);

        h.release().await;
        let version: i64 = conn
            .with_raw(|c| c.query_row("pragma user_version", (), |r| r.get(0)))
            .unwrap();
        assert_eq!(version, 0);
        let tables: i64 = conn
            .with_raw(|c| {
                c.query_row(
                    "select count(*) from sqlite_schema where name in ('u', 'i')",
                    (),
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert_eq!(tables, 0);
    }

    /// `with_raw` users (admin shell, schema migration, dump load) bypass statement
    /// classification but not the WAL: the write fails with `SQLITE_AUTH` and the typed reason
    /// is in the connection's denial slot.
    #[tokio::test(flavor = "multi_thread")]
    async fn fence_rejects_raw_with_raw_write() {
        let h = Harness::new().await;
        let conn = h.conn().await;
        h.fence().await;

        for sql in ["insert into t values (1)", "begin immediate", "vacuum"] {
            let err = conn.with_raw(|c| c.execute_batch(sql)).unwrap_err();
            match err {
                rusqlite::Error::SqliteFailure(e, _) => {
                    assert_eq!(e.code, ErrorCode::AuthorizationForStatementDenied, "{sql}")
                }
                e => panic!("{sql}: unexpected error {e}"),
            }
            assert_eq!(
                conn.fence.take_denial().unwrap().outcome(),
                FenceOutcome::MigrationWriteFenced,
                "{sql}"
            );
        }
        assert_eq!(count(&conn).await, 0);

        h.release().await;
        conn.with_raw(|c| c.execute_batch("insert into t values (1)"))
            .unwrap();
        assert_eq!(count(&conn).await, 1);
    }

    /// The fence acquired and released between a transaction's first read and its write: the
    /// write is refused although the gate is open, while a connection that was idle across the
    /// transition, and the same connection after a rollback, write normally.
    #[tokio::test(flavor = "multi_thread")]
    async fn stale_generation_cannot_write_after_release() {
        let h = Harness::new().await;
        let in_txn = h.conn().await;
        let idle = h.conn().await;

        assert_ok(&run(&in_txn, &["begin", "select count(*) from t"]).await);
        h.fence().await;
        h.release().await;
        assert!(h
            .controller
            .permits(crate::namespace::fence::state::OperationClass::NormalWrite)
            .is_ok());

        let steps = run(&in_txn, &["insert into t values (1)", "commit"]).await;
        assert_eq!(
            fence_error(&steps[0]).detail(),
            Some(FenceDetail::StaleTransaction)
        );
        // The commit that follows ends the transaction without having written anything.
        assert!(steps[1].is_ok());
        assert!(in_txn.inner.lock().is_autocommit());
        assert_ok(&run(&idle, &["insert into t values (2)"]).await);
        assert_ok(&run(&in_txn, &["insert into t values (3)"]).await);
        assert_eq!(count(&idle).await, 2);
    }

    /// A namespace that never had a fence behaves as before: generation 0 everywhere, every
    /// kind of write works, and a plain `SQLITE_AUTH` from an authorizer is reported as the
    /// SQLite error it is, not as a fence denial.
    #[tokio::test(flavor = "multi_thread")]
    async fn unfenced_namespace_is_unchanged() {
        let h = Harness::new().await;
        let conn = h.conn().await;

        assert_ok(
            &run(
                &conn,
                &[
                    "insert into t values (1)",
                    "begin",
                    "select * from t",
                    "insert into t values (2)",
                    "commit",
                    "create table u (x)",
                    "pragma user_version = 3",
                ],
            )
            .await,
        );
        conn.with_raw(|c| c.execute_batch("insert into t values (3)"))
            .unwrap();
        assert_eq!(count(&conn).await, 3);
        assert_eq!(h.controller.write_generation(), 0);
        assert_eq!(conn.fence.program_generation(), 0);
        assert_eq!(conn.fence.txn_generation(), 0);

        conn.with_raw(|c| {
            c.authorizer(Some(|ctx: rusqlite::hooks::AuthContext<'_>| {
                match ctx.action {
                    rusqlite::hooks::AuthAction::Insert { .. } => {
                        rusqlite::hooks::Authorization::Deny
                    }
                    _ => rusqlite::hooks::Authorization::Allow,
                }
            }))
        });
        let steps = run(&conn, &["insert into t values (4)"]).await;
        match &steps[0] {
            Err(Error::RusqliteErrorExtended(rusqlite::Error::SqliteFailure(e, _), _)) => {
                assert_eq!(e.code, ErrorCode::AuthorizationForStatementDenied)
            }
            other => panic!("expected the authorizer's error, got {other:?}"),
        }
        assert!(conn.fence.take_denial().is_none());
    }
}
