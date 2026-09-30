//! Migration targets (`docs/NAMESPACE_FENCE.md` sections 10 and 11).
//!
//! A target namespace is created by the operation that will fill it, already in
//! `TARGET_QUARANTINED`, and it is quarantined from the first instant anything else could
//! observe it: the in-memory target-creation gate is installed before the metastore transaction
//! that writes its marker, config row, record and receipt; the committed record replaces that
//! gate; and only then is the config put where `exists()` and `lookup()` find it and the
//! namespace loaded, so its first connection maker is created behind the quarantine gate.
//!
//! [`CreateTargetRequest`] is the typed entry point that the admin route and bulk import both
//! use; `NamespaceStore::create_target_quarantined` runs it. `AbortQuarantinedTarget` needs
//! nothing of its own: it is an ordinary transition, and `TARGET_ABORTED` denies every
//! normal class exactly as the quarantine does.

use uuid::Uuid;

use crate::connection::legacy::LegacyConnection;
use crate::connection::Connection as _;
use crate::namespace::replication_wal::ReplicationWalWrapper;
use crate::namespace::NamespaceName;

use super::capability::{CapabilityPurpose, MigrationCapability};
use super::command::{FenceCommand, FenceRequest, TargetConfig};
use super::controller::FenceController;
use super::outcome::{FenceDetail, FenceError, FenceOutcome};
use super::record::ValidationSnapshot;
use super::state::FenceState;

/// `CreateTargetQuarantined` for `namespace`, by `operation_id`. The expectation is always
/// `ABSENT` at revision 0, so it is not part of the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateTargetRequest {
    pub namespace: NamespaceName,
    pub operation_id: Uuid,
    /// Idempotency key: replaying the same command returns its stored result, and completes a
    /// creation that was interrupted between its marker and its commit.
    pub command_id: Uuid,
    pub config: TargetConfig,
}

impl From<CreateTargetRequest> for FenceRequest {
    fn from(req: CreateTargetRequest) -> Self {
        FenceRequest {
            namespace: req.namespace,
            operation_id: req.operation_id,
            command_id: req.command_id,
            expected_state: FenceState::Absent,
            expected_revision: 0,
            command: FenceCommand::CreateTargetQuarantined { config: req.config },
        }
    }
}

/// Read-only access used by the owning operation to validate a sealed target. The connection
/// carries a server-issued validation capability and has SQLite's `query_only` mode enabled;
/// every call checks that the capability still matches the target's owner, state and revision.
pub struct ValidationSession {
    capability: MigrationCapability,
    controller: std::sync::Arc<FenceController>,
    conn: LegacyConnection<ReplicationWalWrapper>,
}

impl std::fmt::Debug for ValidationSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidationSession")
            .field("capability", &self.capability)
            .finish_non_exhaustive()
    }
}

impl ValidationSession {
    pub(crate) async fn new(
        capability: MigrationCapability,
        controller: std::sync::Arc<FenceController>,
        conn: LegacyConnection<ReplicationWalWrapper>,
    ) -> crate::Result<Self> {
        let mut this = Self {
            capability,
            controller,
            conn,
        };
        this.with_raw(|conn| conn.pragma_update(None, "query_only", true))
            .await??;
        Ok(this)
    }

    pub fn capability(&self) -> &MigrationCapability {
        &self.capability
    }

    /// Run a read-only operation on the capability connection. The capability is checked before
    /// the call, and a write refused at the WAL is returned as its typed fence outcome even if
    /// the closure swallowed SQLite's `SQLITE_AUTH`.
    pub async fn with_raw<R: Send + 'static>(
        &mut self,
        f: impl FnOnce(&mut rusqlite::Connection) -> R + Send + 'static,
    ) -> Result<R, FenceError> {
        self.controller
            .check_capability(&self.capability, CapabilityPurpose::Validate)?;
        let conn = self.conn.clone();
        let joined = tokio::task::spawn_blocking(move || {
            let result = conn.with_raw(f);
            (result, conn.fence_state().take_denial())
        })
        .await;
        match joined {
            Ok((_, Some(denial))) => Err(denial),
            Ok((result, None)) => Ok(result),
            Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            Err(e) => Err(FenceError::new(
                FenceOutcome::OperationCapabilityRequired,
                format!("the validation call did not complete: {e}"),
            )),
        }
    }

    /// What the server records beside `RecordTargetValidation`: the target's current
    /// replication-log identity and frame, and SQLite page count. Target writes have already
    /// been positively drained, so these observations cannot race a mutation.
    pub(crate) async fn snapshot(&mut self) -> crate::Result<ValidationSnapshot> {
        let sources = self.controller.live_write_drains();
        let Some(latest) = sources.last() else {
            return Err(FenceError::new(
                FenceOutcome::FenceStateUnavailable,
                format!(
                    "validation target `{}` has no live primary replication log",
                    self.capability.namespace()
                ),
            )
            .into());
        };
        let log_id = latest.log_id;
        let frame_no = (latest.current_frame_no)().unwrap_or(0);
        let page_count = self
            .with_raw(|conn| conn.query_row("PRAGMA page_count", (), |row| row.get::<_, u64>(0)))
            .await??;
        Ok(ValidationSnapshot {
            log_id,
            frame_no,
            page_count,
        })
    }
}

impl Drop for ValidationSession {
    fn drop(&mut self) {
        self.controller.revoke_capability(self.capability.id());
    }
}

/// The refusal of a target name that the server already knows, in memory or in the namespace
/// cache, although the metastore may not hold it yet (a create or fork in flight, or one the
/// fence refused after it had published its config in memory).
pub(crate) fn name_in_use(namespace: &NamespaceName) -> FenceError {
    FenceError::new(
        FenceOutcome::FencePreconditionFailed,
        format!("namespace `{namespace}` already exists on this server"),
    )
    .with_detail(FenceDetail::NamespaceExists)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Arc;

    use libsql_replication::rpc::replication::replication_log_server::ReplicationLog;
    use libsql_replication::rpc::replication::{HelloRequest, NAMESPACE_METADATA_KEY};
    use tempfile::{tempdir, TempDir};
    use tonic::metadata::BinaryMetadataValue;

    use super::*;
    use crate::auth::Authenticated;
    use crate::connection::config::DatabaseConfig;
    use crate::connection::program::Program;
    use crate::connection::RequestContext;
    use crate::error::Error;
    use crate::namespace::fence::command::{FenceCommand, ValidationResult};
    use crate::namespace::fence::controller::FenceController;
    use crate::namespace::fence::drain::tests::{raw, PROMPT};
    use crate::namespace::fence::hooks::{HookAction, HookPoint};
    use crate::namespace::fence::record::ServerIdentity;
    use crate::namespace::fence::state::OperationClass;
    use crate::namespace::meta_store::{metastore_connection_maker, FenceCommit, FenceCommitKind};
    use crate::namespace::store::fence_tests::open_store;
    use crate::namespace::store::NamespaceStore;
    use crate::namespace::RestoreOption;
    use crate::query_result_builder::test::TestBuilder;
    use crate::query_result_builder::QueryResultBuilder as _;
    use crate::rpc::replication::replication_log::ReplicationLogService;

    pub(crate) const OP: Uuid = Uuid::from_u128(0xa);
    const OTHER_OP: Uuid = Uuid::from_u128(0xb);

    pub(crate) fn server() -> ServerIdentity {
        ServerIdentity {
            build: "test".into(),
            instance_id: Uuid::from_u128(0x99),
        }
    }

    pub(crate) fn create_request(ns: &'static str, command_id: u128) -> CreateTargetRequest {
        CreateTargetRequest {
            namespace: ns.into(),
            operation_id: OP,
            command_id: Uuid::from_u128(command_id),
            config: TargetConfig {
                max_db_size: Some(4096 * 1000),
                ..Default::default()
            },
        }
    }

    /// Run `CreateTargetQuarantined` through the store on a task of its own.
    pub(crate) fn create(
        store: &NamespaceStore,
        req: CreateTargetRequest,
    ) -> tokio::task::JoinHandle<crate::Result<FenceCommit>> {
        let store = store.clone();
        tokio::spawn(async move { store.create_target_quarantined(req, server()).await })
    }

    pub(crate) fn target_command(
        command_id: u128,
        expected_state: FenceState,
        expected_revision: u64,
        command: FenceCommand,
    ) -> FenceRequest {
        FenceRequest {
            namespace: "tgt".into(),
            operation_id: OP,
            command_id: Uuid::from_u128(command_id),
            expected_state,
            expected_revision,
            command,
        }
    }

    fn execute(
        store: &NamespaceStore,
        request: FenceRequest,
    ) -> tokio::task::JoinHandle<crate::Result<FenceCommit>> {
        let store = store.clone();
        tokio::spawn(async move { store.execute_fence_command(request, server()).await })
    }

    /// A target with a small table, sealed at TARGET_VALIDATING revision 3.
    async fn validating_target() -> (TempDir, NamespaceStore, Arc<FenceController>) {
        let dir = tempdir().unwrap();
        let store = open_store(dir.path()).await;
        create(&store, create_request("tgt", 1))
            .await
            .unwrap()
            .unwrap();
        let mut session = store
            .open_import_session("tgt".into(), OP, 1)
            .await
            .unwrap();
        session
            .with_raw(|conn| {
                conn.execute_batch("create table t (x); insert into t values (1), (2)")
            })
            .await
            .unwrap()
            .unwrap();
        drop(session);
        let seal = target_command(
            10,
            FenceState::TargetQuarantined,
            1,
            FenceCommand::SealTargetImport { drain_policy: None },
        );
        let commit = execute(&store, seal).await.unwrap().unwrap();
        assert_eq!(commit.receipt.outcome, FenceOutcome::Applied);
        let fence = controller(&store, "tgt").await;
        assert_eq!(
            (fence.gate().state(), fence.gate().revision()),
            (FenceState::TargetValidating, 3)
        );
        (dir, store, fence)
    }

    async fn record_validation(
        store: &NamespaceStore,
        command_id: u128,
        expected_revision: u64,
        result: ValidationResult,
    ) -> FenceCommit {
        execute(
            store,
            target_command(
                command_id,
                FenceState::TargetValidating,
                expected_revision,
                FenceCommand::RecordTargetValidation {
                    result,
                    summary: format!("validation {result:?}"),
                },
            ),
        )
        .await
        .unwrap()
        .unwrap()
    }

    /// A target with successful validation, published readable and write-fenced at revision 5.
    async fn write_fenced_target() -> (TempDir, NamespaceStore, Arc<FenceController>) {
        let (dir, store, fence) = validating_target().await;
        record_validation(&store, 20, 3, ValidationResult::Ok).await;
        let publish = target_command(
            21,
            FenceState::TargetValidating,
            4,
            FenceCommand::PublishTargetReadableWriteFenced,
        );
        execute(&store, publish).await.unwrap().unwrap();
        assert_eq!(
            (fence.gate().state(), fence.gate().revision()),
            (FenceState::TargetWriteFenced, 5)
        );
        (dir, store, fence)
    }

    pub(crate) fn enable_request(command_id: u128) -> FenceRequest {
        target_command(
            command_id,
            FenceState::TargetWriteFenced,
            5,
            FenceCommand::EnableTargetWrites,
        )
    }

    async fn count_rows(store: &NamespaceStore) -> i64 {
        let (_, conn) = loaded(store, "tgt").await;
        tokio::task::spawn_blocking(move || {
            conn.with_raw(|c| c.query_row("select count(*) from t", (), |row| row.get(0)))
        })
        .await
        .unwrap()
        .unwrap()
    }

    /// Run one normal SQL program, including its legacy config checks, and require every step to
    /// succeed. Raw access is intentionally not used for restart mirror assertions.
    async fn program(
        store: &NamespaceStore,
        conn: &Arc<crate::database::Connection>,
        sql: &'static str,
    ) {
        let ctx = RequestContext::new(
            Authenticated::FullAccess,
            "tgt".into(),
            store.meta_store().clone(),
        );
        let steps = conn
            .execute_program(Program::seq(&[sql]), ctx, TestBuilder::default(), None)
            .await
            .unwrap()
            .into_ret();
        for (i, step) in steps.iter().enumerate() {
            assert!(step.is_ok(), "step {i} failed: {step:?}");
        }
    }

    fn fence_error(e: &Error) -> &FenceError {
        match e {
            Error::NamespaceFence(f) => f,
            other => panic!("expected a fence error, got {other:?}"),
        }
    }

    /// Denied by the fence, or not there at all: never served.
    fn assert_not_served<T: std::fmt::Debug>(what: &str, r: &crate::Result<T>) {
        match r {
            Err(Error::NamespaceDoesntExist(_)) => (),
            Err(Error::NamespaceFence(_)) => (),
            other => panic!("{what}: expected a denial, got {other:?}"),
        }
    }

    fn assert_quarantined(fence: &FenceController) {
        for class in [
            OperationClass::NormalRead,
            OperationClass::NormalWrite,
            OperationClass::Stream,
            OperationClass::Lifecycle,
            OperationClass::Vacuum,
        ] {
            let e = fence.permits(class).unwrap_err();
            assert_eq!(
                e.outcome(),
                FenceOutcome::MigrationTargetQuarantined,
                "{class:?}"
            );
        }
    }

    async fn controller(store: &NamespaceStore, ns: &'static str) -> Arc<FenceController> {
        store
            .fence_gate(&ns.into())
            .await
            .unwrap()
            .expect("the target has a controller")
    }

    /// The loaded target's controller, and a connection to it.
    async fn loaded(
        store: &NamespaceStore,
        ns: &'static str,
    ) -> (Arc<FenceController>, Arc<crate::database::Connection>) {
        let (fence, maker) = store
            .with(ns.into(), |ns| {
                (ns.fence().clone(), ns.db.connection_maker())
            })
            .await
            .unwrap();
        (fence, Arc::new(maker.create().await.unwrap()))
    }

    async fn replication_hello(store: &NamespaceStore, ns: &'static str) -> tonic::Status {
        let service = ReplicationLogService::new(store.clone(), None, None, false, false, true);
        let mut req = tonic::Request::new(HelloRequest {
            handshake_version: Some(1),
        });
        req.metadata_mut().insert_bin(
            NAMESPACE_METADATA_KEY,
            BinaryMetadataValue::from_bytes(ns.as_bytes()),
        );
        service.hello(req).await.unwrap_err()
    }

    /// Every way of reaching `ns` other than the fence commands: none of them is served.
    async fn attempt_everything(store: &NamespaceStore, ns: &'static str) {
        let r = store
            .with(ns.into(), |ns| ns.db.connection_maker())
            .await
            .map(|_| ());
        assert_not_served("SQL connection", &r);
        let r = store.stats(ns.into()).await.map(|_| ());
        assert_not_served("stats", &r);
        // The dump route and the replication service reach the namespace the same way.
        let hello = replication_hello(store, ns).await;
        assert_ne!(hello.code(), tonic::Code::Ok);
        assert_ne!(hello.code(), tonic::Code::Unavailable, "{hello:?}");
        let r = store
            .create(ns.into(), RestoreOption::Latest, DatabaseConfig::default())
            .await;
        assert_not_served("create", &r);
        let r = store.destroy(ns.into(), false).await;
        assert!(r.is_err(), "delete: {r:?}");
        let r = store
            .fork("src".into(), ns.into(), DatabaseConfig::default(), None)
            .await;
        assert!(r.is_err(), "fork: {r:?}");
    }

    async fn store_with_source(dir: &TempDir) -> NamespaceStore {
        let store = open_store(dir.path()).await;
        store
            .create("src".into(), RestoreOption::Latest, Default::default())
            .await
            .unwrap();
        store
    }

    /// Parked after its rows are committed and its quarantine gate published, and before its
    /// config is published and the namespace loaded, the target is never observable: SQL,
    /// dump/replication, create, delete and fork of the name are all denied or find nothing.
    /// Afterwards it is loaded behind the quarantine gate.
    #[tokio::test(flavor = "multi_thread")]
    async fn create_race_never_observable() {
        let dir = tempdir().unwrap();
        let store = store_with_source(&dir).await;
        let fence = store.fence_controller(&"tgt".into());
        let paused = fence.hooks().pause_at(HookPoint::AfterTargetRowsCommitted);
        let creating = create(&store, create_request("tgt", 1));
        paused.reached().await;

        assert_eq!(fence.gate().state(), FenceState::TargetQuarantined);
        assert!(!store.exists(&"tgt".into()).await);
        attempt_everything(&store, "tgt").await;

        paused.resume();
        let commit = creating.await.unwrap().unwrap();
        assert_eq!(commit.receipt.outcome, FenceOutcome::Applied);
        assert!(store.exists(&"tgt".into()).await);

        // Loaded behind the gate it was created with.
        let (loaded_fence, conn) = loaded(&store, "tgt").await;
        assert!(Arc::ptr_eq(&fence, &loaded_fence));
        assert_quarantined(&fence);
        let ctx = RequestContext::new(
            Authenticated::FullAccess,
            "tgt".into(),
            store.meta_store().clone(),
        );
        let e = conn
            .execute_program(
                Program::seq(&["select 1"]),
                ctx,
                TestBuilder::default(),
                None,
            )
            .await
            .map(|_| ())
            .unwrap_err();
        assert_eq!(
            fence_error(&e).outcome(),
            FenceOutcome::MigrationTargetQuarantined
        );
        crate::namespace::fence::drain::tests::assert_fenced(
            raw(&conn, "create table t (x)").await,
        );
        // The in-memory config is the logical one; the stored row carries the legacy mirror.
        let config = store.config_store("tgt".into()).await.unwrap().get();
        assert_eq!(config.max_db_pages, 1000);
        assert!(!config.block_reads && !config.block_writes);
        // Everything but the commands is still refused once it is loaded.
        attempt_everything_loaded(&store, "tgt").await;
    }

    /// Once loaded, the lifecycle paths are refused by the fence.
    async fn attempt_everything_loaded(store: &NamespaceStore, ns: &'static str) {
        let r = store
            .create(ns.into(), RestoreOption::Latest, DatabaseConfig::default())
            .await;
        assert!(r.is_err(), "create: {r:?}");
        let r = store.destroy(ns.into(), false).await;
        assert_eq!(
            fence_error(&r.unwrap_err()).outcome(),
            FenceOutcome::MigrationTargetQuarantined
        );
        let r = store
            .fork("src".into(), ns.into(), DatabaseConfig::default(), None)
            .await;
        assert!(r.is_err(), "fork: {r:?}");
        let hello = replication_hello(store, ns).await;
        assert_eq!(
            FenceError::outcome_from_grpc_status(&hello),
            Some(FenceOutcome::MigrationTargetQuarantined),
            "{hello:?}"
        );
        assert!(store.exists(&ns.into()).await);
    }

    /// Before its commit, while the target-creation gate is in place, the name is refused
    /// before any setup work.
    #[tokio::test(flavor = "multi_thread")]
    async fn creating_gate_refuses_before_commit() {
        let dir = tempdir().unwrap();
        let store = store_with_source(&dir).await;
        let fence = store.fence_controller(&"tgt".into());
        let paused = fence.hooks().pause_at(HookPoint::BeforeMetastoreCommit);
        let creating = create(&store, create_request("tgt", 1));
        paused.reached().await;

        assert!(fence.gate().is_creating_target());
        assert_quarantined(&fence);
        attempt_everything(&store, "tgt").await;
        // No database was set up under the name.
        assert!(!dir.path().join("dbs").join("tgt").join("data").exists());

        paused.resume();
        creating.await.unwrap().unwrap();
        assert!(!fence.gate().is_creating_target());
        assert_eq!(fence.gate().state(), FenceState::TargetQuarantined);
    }

    /// A creation interrupted between its marker and its commit leaves the name
    /// `UNKNOWN_UNAVAILABLE` after a restart; only the same command completes it, and the
    /// completed target is loaded quarantined.
    #[tokio::test(flavor = "multi_thread")]
    async fn create_replay_completes_interrupted_creation() {
        let dir = tempdir().unwrap();
        {
            let store = store_with_source(&dir).await;
            create(&store, create_request("tgt", 1))
                .await
                .unwrap()
                .unwrap();
            store.shutdown().await.unwrap();
        }
        // What a crash after the marker and before the commit leaves: the marker alone.
        {
            let (maker, _) = metastore_connection_maker(None, dir.path()).await.unwrap();
            let conn = maker().unwrap();
            for sql in [
                "DELETE FROM namespace_fence_receipts WHERE namespace = 'tgt'",
                "DELETE FROM namespace_fences WHERE namespace = 'tgt'",
                "DELETE FROM namespace_configs WHERE namespace = 'tgt'",
            ] {
                conn.execute(sql, ()).unwrap();
            }
        }
        std::fs::remove_file(dir.path().join("dbs").join("tgt").join("data")).ok();

        let store = open_store(dir.path()).await;
        let fence = store.fence_controller(&"tgt".into());
        assert!(fence.gate().is_unavailable());
        let r = store.with("tgt".into(), |_| ()).await;
        assert_eq!(
            fence_error(&r.unwrap_err()).detail(),
            Some(FenceDetail::IncompleteTargetCreation)
        );
        // Another command does not complete it.
        let r = create(&store, create_request("tgt", 2)).await.unwrap();
        assert_eq!(
            fence_error(&r.unwrap_err()).outcome(),
            FenceOutcome::FenceStateUnavailable
        );

        let commit = create(&store, create_request("tgt", 1))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(commit.kind, FenceCommitKind::Committed);
        assert_eq!(fence.gate().state(), FenceState::TargetQuarantined);
        let (loaded_fence, _) = loaded(&store, "tgt").await;
        assert!(Arc::ptr_eq(&fence, &loaded_fence));
        assert_quarantined(&fence);
        let config = store.config_store("tgt".into()).await.unwrap().get();
        assert!(!config.block_reads && !config.block_writes);
    }

    /// The caller going away does not stop a creation: it is published and loaded, and a replay
    /// returns the stored result.
    #[tokio::test(flavor = "multi_thread")]
    async fn create_completes_when_the_caller_goes_away() {
        let dir = tempdir().unwrap();
        let store = store_with_source(&dir).await;
        let fence = store.fence_controller(&"tgt".into());
        let paused = fence.hooks().pause_at(HookPoint::AfterTargetRowsCommitted);
        let creating = create(&store, create_request("tgt", 1));
        paused.reached().await;
        creating.abort();
        let _ = creating.await;
        paused.resume();

        // The creation carries on without its caller; the replay waits for it on the
        // transition lock and then answers from the receipt.
        let replay = tokio::time::timeout(PROMPT, create(&store, create_request("tgt", 1)))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(replay.kind, FenceCommitKind::Replayed);
        assert_eq!(replay.receipt.outcome, FenceOutcome::Applied);
        assert!(store.exists(&"tgt".into()).await);
        let (loaded_fence, _) = loaded(&store, "tgt").await;
        assert!(Arc::ptr_eq(&fence, &loaded_fence));
    }

    /// A commit whose acknowledgement is lost keeps the name closed; the replay reconciles it
    /// from the durable rows and publishes and loads the target.
    #[tokio::test(flavor = "multi_thread")]
    async fn indeterminate_create_is_completed_by_replay() {
        let dir = tempdir().unwrap();
        let store = store_with_source(&dir).await;
        let fence = store.fence_controller(&"tgt".into());
        fence
            .hooks()
            .arm(HookPoint::AfterMetastoreCommit, HookAction::Indeterminate);
        let r = create(&store, create_request("tgt", 1)).await.unwrap();
        assert_eq!(
            fence_error(&r.unwrap_err()).outcome(),
            FenceOutcome::FenceCommitIndeterminate
        );
        // Still refused before any setup, and not published.
        assert!(fence.gate().is_creating_target());
        assert!(!store.exists(&"tgt".into()).await);
        assert_not_served("SQL", &store.with("tgt".into(), |_| ()).await);

        let replay = create(&store, create_request("tgt", 1))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(replay.kind, FenceCommitKind::Replayed);
        assert!(!fence.gate().is_creating_target());
        assert!(fence.gate().indeterminate.is_none());
        assert_eq!(fence.gate().state(), FenceState::TargetQuarantined);
        assert!(store.exists(&"tgt".into()).await);
        loaded(&store, "tgt").await;
        assert_quarantined(&fence);
    }

    /// A name the server already has is refused, and its traffic is not disturbed; a name that
    /// is refused keeps no creation gate.
    #[tokio::test(flavor = "multi_thread")]
    async fn create_rejects_existing_name() {
        let dir = tempdir().unwrap();
        let store = store_with_source(&dir).await;
        let src_conn = {
            let maker = store
                .with("src".into(), |ns| ns.db.connection_maker())
                .await
                .unwrap();
            Arc::new(maker.create().await.unwrap())
        };
        raw(&src_conn, "create table t (x)").await.unwrap();
        let generation = store.fence_controller(&"src".into()).write_generation();

        let r = create(&store, create_request("src", 1)).await.unwrap();
        let e = r.unwrap_err();
        assert_eq!(
            fence_error(&e).outcome(),
            FenceOutcome::FencePreconditionFailed
        );
        assert_eq!(fence_error(&e).detail(), Some(FenceDetail::NamespaceExists));
        // The source's gate never moved, and it still takes writes.
        let src_fence = store.fence_controller(&"src".into());
        assert_eq!(src_fence.write_generation(), generation);
        assert!(!src_fence.gate().is_creating_target());
        raw(&src_conn, "insert into t values (1)").await.unwrap();

        // A name that exists in the metastore but is not loaded is refused the same way.
        store
            .create("cold".into(), RestoreOption::Latest, Default::default())
            .await
            .unwrap();
        let r = create(&store, create_request("cold", 2)).await.unwrap();
        assert_eq!(
            fence_error(&r.unwrap_err()).detail(),
            Some(FenceDetail::NamespaceExists)
        );

        // A second target of the same name by another operation is refused, and the first is
        // untouched.
        create(&store, create_request("tgt", 3))
            .await
            .unwrap()
            .unwrap();
        let mut other = create_request("tgt", 4);
        other.operation_id = OTHER_OP;
        let r = create(&store, other).await.unwrap();
        assert!(r.is_err());
        let fence = store.fence_controller(&"tgt".into());
        assert_eq!(fence.gate().operation_id(), Some(OP));
        assert!(!fence.gate().is_creating_target());
    }

    /// A validation session carries the owner's current capability, admits reads through the
    /// quarantine, is `query_only`, and is invalidated by the validation receipt's revision.
    /// The receipt records the target snapshot observed by the server.
    #[tokio::test(flavor = "multi_thread")]
    async fn validation_session_is_read_only() {
        let (_dir, store, fence) = validating_target().await;
        let mut session = store
            .open_validation_session("tgt".into(), OP, 3)
            .await
            .unwrap();
        assert_eq!(session.capability().purpose(), CapabilityPurpose::Validate);
        let (query_only, count) = session
            .with_raw(|conn| {
                let query_only =
                    conn.query_row("PRAGMA query_only", (), |row| row.get::<_, i64>(0));
                let count =
                    conn.query_row("select count(*) from t", (), |row| row.get::<_, i64>(0));
                (query_only, count)
            })
            .await
            .unwrap();
        assert_eq!(query_only.unwrap(), 1);
        assert_eq!(count.unwrap(), 2);
        match session
            .with_raw(|conn| conn.execute_batch("insert into t values (3)"))
            .await
            .unwrap()
        {
            Err(rusqlite::Error::SqliteFailure(e, _)) => {
                assert_eq!(e.code, rusqlite::ErrorCode::ReadOnly)
            }
            other => panic!("query_only validation connection accepted a write: {other:?}"),
        }
        let e = session
            .with_raw(|conn| {
                conn.pragma_update(None, "query_only", false).unwrap();
                conn.execute_batch("insert into t values (3)")
            })
            .await
            .unwrap_err();
        assert_eq!(e.outcome(), FenceOutcome::OperationCapabilityRequired);

        let error = store
            .open_validation_session("tgt".into(), OTHER_OP, 3)
            .await
            .unwrap_err();
        assert_eq!(
            fence_error(&error).outcome(),
            FenceOutcome::FenceOwnedByAnotherOperation
        );
        let error = store
            .open_validation_session("tgt".into(), OP, 2)
            .await
            .unwrap_err();
        assert_eq!(
            fence_error(&error).outcome(),
            FenceOutcome::FenceRevisionMismatch
        );

        let request = target_command(
            20,
            FenceState::TargetValidating,
            3,
            FenceCommand::RecordTargetValidation {
                result: ValidationResult::Ok,
                summary: "validation Ok".into(),
            },
        );
        let after_commit = fence.hooks().pause_at(HookPoint::AfterMetastoreCommit);
        let first = execute(&store, request.clone());
        after_commit.reached().await;
        // The metastore has the receipt but the live gate still has revision 3. The concurrent
        // replay must not demand another validation snapshot or capability before it waits for
        // the first command to publish.
        let replay = execute(&store, request);
        tokio::task::yield_now().await;
        after_commit.resume();
        let commit = first.await.unwrap().unwrap();
        let replay = replay.await.unwrap().unwrap();
        assert_eq!(replay.kind, FenceCommitKind::Replayed);
        let validation = commit.record.as_ref().unwrap().validation.as_ref().unwrap();
        let snapshot = validation.snapshot.expect("the server records a snapshot");
        let (log_id, frame_no) = store
            .with("tgt".into(), |ns| {
                let logger = ns.db.logger().unwrap();
                let frame_no = *logger.new_frame_notifier.borrow();
                (logger.log_id(), frame_no)
            })
            .await
            .unwrap();
        assert_eq!(snapshot.log_id, log_id);
        assert_eq!(snapshot.frame_no, frame_no.unwrap_or(0));
        assert!(snapshot.page_count > 0);
        assert_eq!(fence.gate().revision(), 4);

        let e = session
            .with_raw(|conn| conn.query_row("select 1", (), |row| row.get::<_, i64>(0)))
            .await
            .unwrap_err();
        assert_eq!(e.outcome(), FenceOutcome::OperationCapabilityRequired);
        let mut current = store
            .open_validation_session("tgt".into(), OP, 4)
            .await
            .unwrap();
        assert_eq!(
            current
                .with_raw(
                    |conn| conn.query_row("select count(*) from t", (), |row| row.get::<_, i64>(0))
                )
                .await
                .unwrap()
                .unwrap(),
            2
        );
    }

    /// Publication cannot make a target readable until the latest durable validation result of
    /// the owning operation is successful.
    #[tokio::test(flavor = "multi_thread")]
    async fn publish_requires_validation_receipt() {
        let (_dir, store, fence) = validating_target().await;
        let publish = |command_id, revision| {
            target_command(
                command_id,
                FenceState::TargetValidating,
                revision,
                FenceCommand::PublishTargetReadableWriteFenced,
            )
        };
        let e = execute(&store, publish(20, 3)).await.unwrap().unwrap_err();
        assert_eq!(
            fence_error(&e).detail(),
            Some(FenceDetail::ValidationReceiptRequired)
        );
        record_validation(&store, 21, 3, ValidationResult::Failed).await;
        let e = execute(&store, publish(22, 4)).await.unwrap().unwrap_err();
        assert_eq!(
            fence_error(&e).detail(),
            Some(FenceDetail::ValidationReceiptRequired)
        );
        assert_eq!(
            (fence.gate().state(), fence.gate().revision()),
            (FenceState::TargetValidating, 4)
        );
        assert!(fence.permits(OperationClass::NormalRead).is_err());
    }

    /// A successful validation makes publication possible once; exact replay returns the stored
    /// result and a new command with the same goal answers ALREADY_APPLIED without moving the
    /// revision.
    #[tokio::test(flavor = "multi_thread")]
    async fn publish_is_idempotent() {
        let (dir, store, fence) = validating_target().await;
        record_validation(&store, 20, 3, ValidationResult::Ok).await;
        let publish = target_command(
            21,
            FenceState::TargetValidating,
            4,
            FenceCommand::PublishTargetReadableWriteFenced,
        );
        let commit = execute(&store, publish.clone()).await.unwrap().unwrap();
        assert_eq!(commit.receipt.outcome, FenceOutcome::Applied);
        assert_eq!(
            (fence.gate().state(), fence.gate().revision()),
            (FenceState::TargetWriteFenced, 5)
        );
        assert!(fence.permits(OperationClass::NormalRead).is_ok());
        assert!(fence.permits(OperationClass::NormalWrite).is_err());
        assert_eq!(count_rows(&store).await, 2);

        let replay = execute(&store, publish).await.unwrap().unwrap();
        assert_eq!(replay.kind, FenceCommitKind::Replayed);
        assert_eq!(replay.receipt.outcome, FenceOutcome::Applied);
        let again = execute(
            &store,
            target_command(
                22,
                FenceState::TargetValidating,
                4,
                FenceCommand::PublishTargetReadableWriteFenced,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(again.receipt.outcome, FenceOutcome::AlreadyApplied);
        assert_eq!(
            (again.receipt.revision_before, again.receipt.revision_after),
            (5, 5)
        );
        assert_eq!(fence.gate().revision(), 5);

        store.shutdown().await.unwrap();
        let store = open_store(dir.path()).await;
        let fence = controller(&store, "tgt").await;
        assert_eq!(fence.gate().state(), FenceState::TargetWriteFenced);
        let (_, conn) = loaded(&store, "tgt").await;
        program(&store, &conn, "select count(*) from t").await;
    }

    /// Enabling writes is idempotent but irreversible: it opens normal writes exactly after the
    /// commit is published; replay and a new same-goal command are safe, while no target command
    /// can close or abort it again.
    #[tokio::test(flavor = "multi_thread")]
    async fn enable_writes_idempotent_and_irreversible() {
        let (_dir, store, fence) = write_fenced_target().await;
        let request = enable_request(30);
        let commit = execute(&store, request.clone()).await.unwrap().unwrap();
        assert_eq!(commit.receipt.outcome, FenceOutcome::Applied);
        assert_eq!(
            (fence.gate().state(), fence.gate().revision()),
            (FenceState::TargetWritable, 6)
        );
        assert!(fence.permits(OperationClass::NormalWrite).is_ok());

        let replay = execute(&store, request).await.unwrap().unwrap();
        assert_eq!(replay.kind, FenceCommitKind::Replayed);
        assert_eq!(replay.receipt.outcome, FenceOutcome::Applied);
        let again = execute(&store, enable_request(31)).await.unwrap().unwrap();
        assert_eq!(again.receipt.outcome, FenceOutcome::AlreadyApplied);
        assert_eq!(fence.gate().revision(), 6);

        let abort = target_command(
            32,
            FenceState::TargetWritable,
            6,
            FenceCommand::AbortQuarantinedTarget,
        );
        let e = execute(&store, abort).await.unwrap().unwrap_err();
        assert_eq!(
            fence_error(&e).outcome(),
            FenceOutcome::InvalidFenceTransition
        );
        assert_eq!(fence.gate().state(), FenceState::TargetWritable);
        let (_, conn) = loaded(&store, "tgt").await;
        raw(&conn, "insert into t values (3)").await.unwrap();
        assert_eq!(count_rows(&store).await, 3);
    }

    /// The committed writable state is installed before a restarted server can expose the
    /// target, and the legacy config mirror no longer blocks its writes.
    #[tokio::test(flavor = "multi_thread")]
    async fn enable_writes_survives_restart() {
        let (dir, store, _fence) = write_fenced_target().await;
        execute(&store, enable_request(30)).await.unwrap().unwrap();
        store.shutdown().await.unwrap();

        let store = open_store(dir.path()).await;
        let fence = controller(&store, "tgt").await;
        assert_eq!(
            (fence.gate().state(), fence.gate().revision()),
            (FenceState::TargetWritable, 6)
        );
        let (_, conn) = loaded(&store, "tgt").await;
        program(&store, &conn, "insert into t values (3)").await;
        assert_eq!(count_rows(&store).await, 3);
    }

    /// Losing the response after EnableTargetWrites commits is resolved by inspection and exact
    /// replay; the detached command still publishes the writable gate before it releases the
    /// transition lock.
    #[tokio::test(flavor = "multi_thread")]
    async fn enable_writes_response_loss_resolved() {
        let (_dir, store, fence) = write_fenced_target().await;
        let request = enable_request(30);
        let after_commit = fence.hooks().pause_at(HookPoint::AfterMetastoreCommit);
        let lost = execute(&store, request.clone());
        after_commit.reached().await;
        let before_response = fence.hooks().pause_at(HookPoint::BeforeResponse);
        lost.abort();
        assert!(lost.await.unwrap_err().is_cancelled());
        after_commit.resume();
        before_response.reached().await;

        assert_eq!(fence.gate().state(), FenceState::TargetWritable);
        let inspected = store
            .meta_store()
            .inspect_fence("tgt".into())
            .await
            .unwrap();
        assert_eq!(inspected.fence.state(), FenceState::TargetWritable);
        assert!(inspected.receipts.iter().any(|stored| {
            matches!(
                &stored.receipt,
                Ok(receipt)
                    if receipt.operation_id == OP
                        && receipt.command_id == Uuid::from_u128(30)
                        && receipt.outcome == FenceOutcome::Applied
            )
        }));
        before_response.resume();

        let replay = execute(&store, request).await.unwrap().unwrap();
        assert_eq!(replay.kind, FenceCommitKind::Replayed);
        assert_eq!(replay.receipt.outcome, FenceOutcome::Applied);
        assert_eq!(fence.gate().state(), FenceState::TargetWritable);
    }

    /// A read transaction opened before target write authority is published cannot upgrade to
    /// a write afterwards; rolling it back and starting a fresh program succeeds.
    #[tokio::test(flavor = "multi_thread")]
    async fn stale_generation_cannot_write_after_enable_writes() {
        let (_dir, store, fence) = write_fenced_target().await;
        let (_, conn) = loaded(&store, "tgt").await;
        raw(&conn, "begin; select count(*) from t").await.unwrap();
        execute(&store, enable_request(30)).await.unwrap().unwrap();
        assert_eq!(fence.gate().state(), FenceState::TargetWritable);

        crate::namespace::fence::drain::tests::assert_fenced(
            raw(&conn, "insert into t values (3)").await,
        );
        raw(&conn, "commit").await.unwrap();
        raw(&conn, "insert into t values (4)").await.unwrap();
        assert_eq!(count_rows(&store).await, 3);
    }

    /// `AbortQuarantinedTarget` finishes the operation and keeps every normal class denied;
    /// the target is not deletable by the generic lifecycle either.
    #[tokio::test(flavor = "multi_thread")]
    async fn abort_keeps_traffic_denied() {
        let dir = tempdir().unwrap();
        let store = store_with_source(&dir).await;
        create(&store, create_request("tgt", 1))
            .await
            .unwrap()
            .unwrap();
        let abort = FenceRequest {
            namespace: "tgt".into(),
            operation_id: OP,
            command_id: Uuid::from_u128(2),
            expected_state: FenceState::TargetQuarantined,
            expected_revision: 1,
            command: FenceCommand::AbortQuarantinedTarget,
        };
        let commit = store
            .execute_fence_command(abort.clone(), server())
            .await
            .unwrap();
        assert_eq!(commit.receipt.outcome, FenceOutcome::Applied);
        let fence = controller(&store, "tgt").await;
        assert_eq!(fence.gate().state(), FenceState::TargetAborted);
        assert_quarantined(&fence);
        let (_, conn) = loaded(&store, "tgt").await;
        crate::namespace::fence::drain::tests::assert_fenced(
            raw(&conn, "create table t (x)").await,
        );
        let r = store.destroy("tgt".into(), false).await;
        assert_eq!(
            fence_error(&r.unwrap_err()).outcome(),
            FenceOutcome::MigrationTargetQuarantined
        );
        // A replay answers from the receipt; a new creation of the name is refused.
        let replay = store.execute_fence_command(abort, server()).await.unwrap();
        assert_eq!(replay.kind, FenceCommitKind::Replayed);
        let r = create(&store, create_request("tgt", 3)).await.unwrap();
        assert!(r.is_err());

        // After a restart the aborted target is still denied.
        store.shutdown().await.unwrap();
        let store = open_store(dir.path()).await;
        let fence = controller(&store, "tgt").await;
        assert_eq!(fence.gate().state(), FenceState::TargetAborted);
        assert_quarantined(&fence);
        let (_, conn) = loaded(&store, "tgt").await;
        crate::namespace::fence::drain::tests::assert_fenced(
            raw(&conn, "create table t (x)").await,
        );
    }
}
