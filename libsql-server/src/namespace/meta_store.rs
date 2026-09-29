#![allow(clippy::mutable_key_type)]
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use std::{collections::HashMap, fs::read_dir};

use bottomless::bottomless_wal::BottomlessWalWrapper;
use bottomless::replicator::CompressionKind;
use bottomless::SavepointTracker;
use futures_core::Future;
use libsql_replication::rpc::metadata;
use libsql_sys::wal::{
    wrapper::{WalWrapper, WrappedWal},
    Sqlite3Wal, Sqlite3WalManager,
};
use parking_lot::Mutex;
use prost::Message;
use rusqlite::TransactionBehavior;
use tokio::sync::oneshot;
use tokio::sync::{
    mpsc,
    watch::{self, Receiver, Sender},
};
use uuid::Uuid;

use crate::config::BottomlessConfig;
use crate::connection::config::DatabaseConfig;
use crate::database::DatabaseKind;
use crate::schema::{MigrationDetails, MigrationSummary};
use crate::{
    config::MetaStoreConfig, connection::legacy::open_conn_active_checkpoint, error::Error, Result,
};

use super::fence::command::{FenceCommand, FenceRequest};
use super::fence::outcome::{FenceDetail, FenceError, FenceOutcome};
use super::fence::record::{
    CommandReceipt, NamespaceFenceRecord, ServerIdentity, ValidationSnapshot,
};
use super::fence::state::OperationClass;
use super::fence::store::{
    self as fence_store, FenceStoreError, MarkerStatus, StoredFence, StoredReceipt,
};
use super::fence::transition::{self, ApplyEnv, Decision, DrainCompletion};
use super::NamespaceName;

type ChangeMsg = (
    NamespaceName,
    Option<Arc<DatabaseConfig>>,
    oneshot::Sender<Result<()>>,
    bool, // flush
);
type MetaStoreWalManager = WalWrapper<Option<BottomlessWalWrapper>, Sqlite3WalManager>;
pub type MetaStoreConnection =
    libsql_sys::Connection<WrappedWal<Option<BottomlessWalWrapper>, Sqlite3Wal>>;

#[derive(Clone)]
pub struct MetaStore {
    changes_tx: mpsc::Sender<ChangeMsg>,
    inner: Arc<MetaStoreInner>,
}

#[derive(Clone, Debug)]
pub struct MetaStoreHandle {
    namespace: NamespaceName,
    inner: HandleState,
}

#[derive(Debug, Clone)]
enum HandleState {
    Internal(Arc<Mutex<Arc<DatabaseConfig>>>),
    External(mpsc::Sender<ChangeMsg>, Receiver<InnerConfig>),
}

#[derive(Debug, Default, Clone)]
struct InnerConfig {
    /// Version of this config _per_ each running process of sqld, this means
    /// that this version is not stored between restarts and is only used to track
    /// config changes during the lifetime of the sqld process.
    version: usize,
    config: Arc<DatabaseConfig>,
}

struct MetaStoreInner {
    // TODO(lucio): Use a concurrent hashmap so we don't block connection creation
    // when we are updating the config. The config si already synced via the watch
    // channel.
    configs: tokio::sync::Mutex<HashMap<NamespaceName, Sender<InnerConfig>>>,
    conn: tokio::sync::Mutex<MetaStoreConnection>,
    wal_manager: MetaStoreWalManager,
    db_kind: DatabaseKind,
    /// `<base_path>/dbs`, where namespace directories and their fence markers are.
    dbs_path: PathBuf,
    fence: FenceSettings,
}

/// How this metastore treats namespace fences (`docs/NAMESPACE_FENCE.md` section 13.1).
#[derive(Debug, Clone, Copy)]
struct FenceSettings {
    /// The fence may be used: its tables exist and commands are accepted.
    enabled: bool,
    /// The fence tables exist, so fence state is loaded and enforced.
    tables: bool,
    receipt_retention: Duration,
}

fn setup_connection(conn: &rusqlite::Connection) -> Result<()> {
    conn.execute("PRAGMA foreign_keys=ON", ())?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS namespace_configs (
            namespace TEXT NOT NULL PRIMARY KEY,
            config BLOB NOT NULL
        )
        ",
        (),
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS shared_schema_links (
            shared_schema_name TEXT NOT NULL,
            namespace TEXT NOT NULL,
            PRIMARY KEY (shared_schema_name, namespace),
            FOREIGN KEY (shared_schema_name) REFERENCES namespace_configs (namespace) ON DELETE RESTRICT ON UPDATE RESTRICT,
            FOREIGN KEY (namespace) REFERENCES namespace_configs (namespace) ON DELETE RESTRICT ON UPDATE RESTRICT
        )
        ",
        (),
    )?;

    Ok(())
}

pub async fn metastore_connection_maker(
    config: Option<BottomlessConfig>,
    base_path: &Path,
) -> crate::Result<(
    impl Fn() -> crate::Result<MetaStoreConnection>,
    MetaStoreWalManager,
)> {
    let db_path = base_path.join("metastore");
    tokio::fs::create_dir_all(&db_path).await?;
    let replicator = match config {
        Some(config) => {
            let options = bottomless::replicator::Options {
                create_bucket_if_not_exists: true,
                verify_crc: true,
                use_compression: CompressionKind::None,
                encryption_config: None,
                aws_endpoint: Some(config.bucket_endpoint),
                access_key_id: Some(config.access_key_id),
                secret_access_key: Some(config.secret_access_key),
                session_token: config.session_token,
                region: Some(config.region),
                db_id: Some(config.backup_id),
                bucket_name: config.bucket_name,
                max_frames_per_batch: 10_000,
                max_batch_interval: config.backup_interval,
                s3_max_parallelism: 32,
                s3_max_retries: 10,
                skip_snapshot: false,
                skip_shutdown_upload: false,
            };
            let mut replicator = bottomless::replicator::Replicator::with_options(
                db_path.join("data").to_str().unwrap(),
                options,
            )
            .await?;
            let (action, _did_recover) = replicator.restore(None, None).await?;
            // TODO: this logic should probably be moved to bottomless.
            match action {
                bottomless::replicator::RestoreAction::SnapshotMainDbFile => {
                    replicator.new_generation().await;
                    if let Some(_handle) = replicator.snapshot_main_db_file(true).await? {
                        tracing::trace!(
                            "got snapshot handle after restore with generation upgrade"
                        );
                    }
                    // Restoration process only leaves the local WAL file if it was
                    // detected to be newer than its remote counterpart.
                    replicator.maybe_replicate_wal().await?
                }
                bottomless::replicator::RestoreAction::ReuseGeneration(gen) => {
                    replicator.set_generation(gen);
                }
            }

            Some(replicator)
        }
        None => None,
    };

    let wal_manager = WalWrapper::new(
        replicator.map(|b| BottomlessWalWrapper::new(Arc::new(tokio::sync::Mutex::new(Some(b))))),
        Sqlite3WalManager::default(),
    );

    let maker = {
        let wal_manager = wal_manager.clone();
        move || {
            let conn =
                open_conn_active_checkpoint(&db_path, wal_manager.clone(), None, 1000, None)?;
            Ok(conn)
        }
    };

    Ok((maker, wal_manager))
}

impl MetaStoreInner {
    fn new(
        base_path: &Path,
        conn: MetaStoreConnection,
        wal_manager: MetaStoreWalManager,
        config: MetaStoreConfig,
        db_kind: DatabaseKind,
    ) -> Result<Self> {
        setup_connection(&conn)?;
        if config.namespace_fence {
            fence_store::create_tables(&conn)?;
        }
        let fence = FenceSettings {
            enabled: config.namespace_fence,
            tables: fence_store::tables_exist(&conn)?,
            receipt_retention: config
                .namespace_fence_receipt_retention
                .unwrap_or(fence_store::DEFAULT_RECEIPT_RETENTION),
        };

        let mut this = MetaStoreInner {
            configs: Default::default(),
            conn: conn.into(),
            wal_manager,
            db_kind,
            dbs_path: base_path.join("dbs"),
            fence,
        };

        if config.allow_recover_from_fs {
            this.maybe_recover_from_fs(base_path)?;
        }

        this.restore()?;
        if this.fence.tables {
            this.restore_fences()?;
        }

        Ok(this)
    }

    fn maybe_recover_from_fs(&mut self, base_path: &Path) -> Result<()> {
        let count =
            self.conn
                .get_mut()
                .query_row("SELECT count(*) FROM namespace_configs", (), |row| {
                    row.get::<_, u64>(0)
                })?;

        let txn = self.conn.get_mut().transaction()?;
        // nothing in the meta store, check fs
        let dbs_dir_path = base_path.join("dbs");
        if count == 0 && dbs_dir_path.try_exists()? {
            tracing::info!("Recovering metastore from filesystem...");
            let db_dir = read_dir(&dbs_dir_path)?;
            for entry in db_dir {
                let entry = entry?;
                if !entry.path().is_dir() {
                    continue;
                }
                let config_path = entry.path().join("config.json");
                let name =
                    NamespaceName::from_string(entry.file_name().to_str().unwrap().to_string())?;
                let config = if config_path.try_exists()? {
                    let config_bytes = std::fs::read(&config_path)?;
                    serde_json::from_slice(&config_bytes)?
                } else {
                    DatabaseConfig::default()
                };
                let config_encoded = metadata::DatabaseConfig::from(&config).encode_to_vec();
                tracing::info!("Recovered namespace config: `{name}`");
                txn.execute(
                    "INSERT INTO namespace_configs VALUES (?1, ?2)",
                    (name.as_str(), &config_encoded),
                )?;
            }
        }

        txn.commit()?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    fn restore(&mut self) -> Result<()> {
        tracing::info!("restoring meta store");

        let mut stmt = self
            .conn
            .get_mut()
            .prepare("SELECT namespace, config FROM namespace_configs")?;

        let rows = stmt.query(())?.mapped(|r| {
            let ns = r.get::<_, String>(0)?;
            let config = r.get::<_, Vec<u8>>(1)?;

            Ok((ns, config))
        });

        for row in rows {
            match row {
                Ok((k, v)) => {
                    let ns = match NamespaceName::from_string(k) {
                        Ok(ns) => ns,
                        Err(e) => {
                            tracing::warn!("unable to convert namespace name: {}", e);
                            continue;
                        }
                    };

                    let config = match metadata::DatabaseConfig::decode(&v[..]) {
                        Ok(c) => Arc::new(DatabaseConfig::from(&c)),
                        Err(e) => {
                            tracing::warn!("unable to convert config: {}", e);
                            continue;
                        }
                    };

                    // We don't store the version in the sqlitedb due to the session token
                    // changed each time we start the primary, this will cause the replica to
                    // handshake again and get the latest config.
                    let (tx, _) = watch::channel(InnerConfig { version: 0, config });

                    self.configs.get_mut().insert(ns, tx);
                }

                Err(e) => {
                    tracing::error!("meta store restore failed: {}", e);

                    return Err(Error::from(e));
                }
            }
        }

        tracing::info!("meta store restore completed");

        Ok(())
    }

    /// Load every namespace's fence after the configs (section 5.6). The stored config row of
    /// a fenced namespace carries the legacy mirror of the fence in its `block_*` fields
    /// (section 13.2); the in-memory config is the namespace's own configuration, so those
    /// fields are put back to the values the record saved. A marker that fell behind its
    /// record is rewritten. A namespace whose fence cannot be established is logged and keeps
    /// its stored config, mirror included.
    fn restore_fences(&mut self) -> Result<()> {
        let namespaces: Vec<NamespaceName> = self.configs.get_mut().keys().cloned().collect();
        let conn = self.conn.get_mut();
        let mut fenced = 0usize;
        for ns in namespaces {
            let (stored, marker) = match fence_store::read_fence(conn, &self.dbs_path, &ns) {
                Ok(r) => r,
                Err(FenceStoreError::Sqlite(e)) => return Err(e.into()),
                Err(e) => {
                    tracing::error!(namespace = %ns, "cannot establish namespace fence: {e}");
                    continue;
                }
            };
            match &stored {
                StoredFence::None { .. } => continue,
                StoredFence::Record(record) => {
                    fenced += 1;
                    if marker == MarkerStatus::Stale {
                        if let Err(e) = fence_store::write_marker(&self.dbs_path, record) {
                            tracing::error!(namespace = %ns, "failed to rewrite fence marker: {e}");
                        }
                    }
                    let sender = self.configs.get_mut().get_mut(&ns).expect("listed above");
                    let config = sender.borrow().config.clone();
                    let config = fence_store::with_legacy_blocks(&config, &record.legacy_blocks);
                    sender.send_modify(|c| c.config = Arc::new(config));
                }
                StoredFence::Unavailable { detail, reason, .. } => {
                    fenced += 1;
                    tracing::error!(
                        namespace = %ns,
                        %detail,
                        "namespace fence state is UNKNOWN_UNAVAILABLE: {reason}"
                    );
                }
            }
        }
        tracing::info!("loaded {fenced} namespace fence(s)");
        Ok(())
    }
}

/// Handles config change updates by inserting them into the database and in-memory
/// cache of configs.
fn process(msg: ChangeMsg, inner: Arc<MetaStoreInner>) {
    let (namespace, config, ret_chan, flush) = msg;
    if let Some(config) = config {
        let ret = if flush {
            try_process(&inner, &namespace, &config)
        } else {
            Ok(())
        };
        // A config that was not persisted is not published.
        if ret.is_err() {
            let _ = ret_chan.send(ret);
            return;
        }
        let mut configs = inner.configs.blocking_lock();
        if let Some(config_watch) = configs.get_mut(&namespace) {
            let new_version = config_watch.borrow().version.wrapping_add(1);

            config_watch.send_modify(|c| {
                *c = InnerConfig {
                    version: new_version,
                    config,
                };
            });
        } else {
            let (tx, _) = watch::channel(InnerConfig { version: 0, config });
            configs.insert(namespace, tx);
        }
        let _ = ret_chan.send(ret);
    } else {
        let ret = if flush {
            let mut configs = inner.configs.blocking_lock();
            if let Some(config_watch) = configs.get_mut(&namespace) {
                let config = config_watch.subscribe().borrow().clone();
                try_process(&inner, &namespace, &config.config)
            } else {
                Ok(())
            }
        } else {
            Ok(())
        };
        let _ = ret_chan.send(ret);
    }
}

fn try_process(
    inner: &MetaStoreInner,
    namespace: &NamespaceName,
    config: &DatabaseConfig,
) -> Result<()> {
    let mut conn = inner.conn.blocking_lock();
    // `BEGIN IMMEDIATE`: the write lock is what serialises this write with fence transitions
    // (docs/NAMESPACE_FENCE.md section 5.4), including those of other metastore connections.
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if inner.fence.tables {
        let (stored, _) =
            fence_store::read_fence(&tx, &inner.dbs_path, namespace).map_err(fence_store_error)?;
        stored.permits(OperationClass::Lifecycle)?;
    }
    if let Some(schema) = config.shared_schema_name.as_ref() {
        if inner.db_kind.is_primary() {
            if crate::schema::db::has_pending_migration_jobs(&tx, schema)? {
                return Err(crate::Error::PendingMigrationOnSchema(schema.clone()));
            }
        }
        fence_store::write_config_row(&tx, namespace, config)?;
        tx.execute(
            "DELETE FROM shared_schema_links WHERE namespace = ?",
            rusqlite::params![namespace.as_str()],
        )?;
        tx.execute(
            "INSERT OR REPLACE INTO shared_schema_links (shared_schema_name, namespace) VALUES (?1, ?2)",
            rusqlite::params![schema.as_str(), namespace.as_str()],
        )?;
    } else {
        fence_store::write_config_row(&tx, namespace, config)?;
    }
    tx.commit()?;

    if let Err(e) = checkpoint(&conn) {
        tracing::warn!("failed to checkpoint metastore: {e}");
    }

    Ok(())
}

fn fence_store_error(e: FenceStoreError) -> Error {
    match e {
        FenceStoreError::Fence(e) => Error::NamespaceFence(e),
        FenceStoreError::Sqlite(e) => Error::RusqliteError(e),
        FenceStoreError::Io(e) => Error::IOError(e),
    }
}

fn checkpoint(conn: &rusqlite::Connection) -> Result<()> {
    conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", (), |_| Ok(()))?;
    Ok(())
}

/// Facts about the server and the live namespace that a fence command needs and the metastore
/// does not hold (see [`ApplyEnv`]). The store adds what it reads inside the transaction.
#[derive(Debug, Clone)]
pub struct FenceContext {
    pub server: ServerIdentity,
    /// Wall-clock time in milliseconds since the Unix epoch.
    pub now_ms: i64,
    /// The namespace's current replication log id, if it exists and has one.
    pub namespace_log_id: Option<Uuid>,
    /// A fresh id for `CreateTargetQuarantined`.
    pub new_incarnation_id: Uuid,
    /// Whether the request carried the configured adoption key.
    pub adoption_authorised: bool,
    /// What the server observed of a target, for `RecordTargetValidation`.
    pub validation_snapshot: Option<ValidationSnapshot>,
}

impl FenceContext {
    /// A context for `server` at the current time with a fresh incarnation id.
    pub fn now(server: ServerIdentity, namespace_log_id: Option<Uuid>) -> Self {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
        Self {
            server,
            now_ms,
            namespace_log_id,
            new_incarnation_id: Uuid::new_v4(),
            adoption_authorised: false,
            validation_snapshot: None,
        }
    }
}

/// How a fence command was answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceCommitKind {
    /// The command had been applied before; nothing was written.
    Replayed,
    /// The command started a drain that is still to be completed; nothing was written and the
    /// controller resumes the drain.
    Resumed,
    /// The command's receipt (and, where it changed, the record) was committed.
    Committed,
}

/// The committed result of a fence command.
#[derive(Debug, Clone)]
pub struct FenceCommit {
    pub kind: FenceCommitKind,
    pub receipt: CommandReceipt,
    /// The namespace's fence record after the command (for a replay, as it is now).
    pub record: Option<NamespaceFenceRecord>,
    /// For a `CreateTargetQuarantined` that was committed, the namespace config it created.
    /// It is not in the in-memory config map yet: the caller installs the target's gate first
    /// and then publishes it.
    pub created_config: Option<Arc<DatabaseConfig>>,
}

/// A namespace's fence as read by `inspect_fence`.
#[derive(Debug, Clone)]
pub struct FenceInspection {
    pub fence: StoredFence,
    pub receipts: Vec<StoredReceipt>,
}

fn fence_disabled() -> FenceError {
    FenceError::new(
        FenceOutcome::FencePreconditionFailed,
        "namespace fences are not enabled on this server",
    )
    .with_detail(FenceDetail::FenceDisabled)
}

fn not_primary() -> FenceError {
    FenceError::new(
        FenceOutcome::FencePreconditionFailed,
        "namespace fences are only changed on a primary",
    )
    .with_detail(FenceDetail::NotPrimary)
}

fn unavailable_receipt(e: impl std::fmt::Display) -> FenceError {
    FenceError::new(
        FenceOutcome::FenceStateUnavailable,
        format!("the stored receipt for this command cannot be read: {e}"),
    )
    .with_detail(FenceDetail::CorruptRecord)
}

/// The `ApplyEnv` for a command: the caller's context plus what the transaction read.
fn apply_env(
    ctx: &FenceContext,
    stored: &StoredFence,
    config: Option<&DatabaseConfig>,
) -> ApplyEnv {
    ApplyEnv {
        now_ms: ctx.now_ms,
        server: ctx.server.clone(),
        namespace_log_id: ctx.namespace_log_id,
        shared_schema: config.is_some_and(|c| c.is_shared_schema || c.shared_schema_name.is_some()),
        // The namespace's own values: a stored record's saved values while it is in force,
        // otherwise the config row as stored.
        legacy_blocks: match stored {
            StoredFence::Record(r) if !r.state.is_operation_finished() => r.legacy_blocks.clone(),
            _ => config
                .map(fence_store::legacy_blocks_of)
                .unwrap_or_default(),
        },
        new_incarnation_id: ctx.new_incarnation_id,
        adoption_authorised: ctx.adoption_authorised,
        validation_snapshot: ctx.validation_snapshot,
    }
}

fn apply_fence_command(
    inner: &MetaStoreInner,
    request: &FenceRequest,
    ctx: &FenceContext,
) -> std::result::Result<FenceCommit, FenceStoreError> {
    if !inner.fence.enabled || !inner.fence.tables {
        return Err(fence_disabled().into());
    }
    if !inner.db_kind.is_primary() {
        return Err(not_primary().into());
    }
    let ns = &request.namespace;
    let mut conn = inner.conn.blocking_lock();
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

    let (stored, marker) = fence_store::read_fence(&tx, &inner.dbs_path, ns)?;
    let existing =
        match fence_store::read_receipt(&tx, ns, request.operation_id, request.command_id)? {
            None => None,
            Some(Ok(r)) => Some(r),
            Some(Err(e)) => return Err(unavailable_receipt(e).into()),
        };
    let config = fence_store::read_config_row(&tx, ns)?;
    let env = apply_env(ctx, &stored, config.as_ref());

    let decision = transition::apply(stored.as_current(), existing.as_ref(), request, &env)?;
    let (record, receipt) = match decision {
        Decision::Replay(receipt) | Decision::Resume(receipt) => {
            let kind = if receipt.is_final() {
                FenceCommitKind::Replayed
            } else {
                FenceCommitKind::Resumed
            };
            return Ok(FenceCommit {
                kind,
                receipt,
                record: stored.record().cloned(),
                created_config: None,
            });
        }
        Decision::Apply { record, receipt } => (record, receipt),
    };

    let mut created_config = None;
    if let Some(next) = &record {
        let previous = fence_store::stored_revision(&tx, ns)?;
        if let FenceCommand::CreateTargetQuarantined { config: target } = &request.command {
            // Section 10.1: the marker first, then the config row, the record and the receipt
            // in one transaction. A crash in between leaves a marker without rows, which only a
            // replay of this command completes.
            let logical = fence_store::target_database_config(target)?;
            fence_store::write_marker(&inner.dbs_path, next)?;
            fence_store::write_config_row(
                &tx,
                ns,
                &fence_store::with_legacy_blocks(&logical, &next.legacy_mirror()),
            )?;
            created_config = Some(Arc::new(logical));
        } else {
            let Some(config) = &config else {
                return Err(FenceError::new(
                    FenceOutcome::FenceStateUnavailable,
                    "the fenced namespace has no config row",
                )
                .with_detail(FenceDetail::CorruptRecord)
                .into());
            };
            fence_store::write_config_row(
                &tx,
                ns,
                &fence_store::with_legacy_blocks(config, &next.legacy_mirror()),
            )?;
        }
        fence_store::write_record(&tx, next, previous)?;
    }
    fence_store::write_receipt(&tx, &receipt)?;
    let owner = record
        .as_ref()
        .or(stored.record())
        .map_or(request.operation_id, |r| r.operation_id);
    fence_store::prune_receipts(&tx, ns, owner, ctx.now_ms, inner.fence.receipt_retention)?;
    tx.commit()?;

    let current = record.or_else(|| stored.record().cloned());
    after_fence_commit(
        inner,
        &conn,
        current.as_ref(),
        record_changed(&current, &stored, marker),
    );

    Ok(FenceCommit {
        kind: FenceCommitKind::Committed,
        receipt,
        record: current,
        created_config,
    })
}

/// Whether the marker has to be written after a commit: the record changed, or it had fallen
/// behind.
fn record_changed(
    current: &Option<NamespaceFenceRecord>,
    stored: &StoredFence,
    marker: MarkerStatus,
) -> bool {
    current.as_ref() != stored.record() || marker == MarkerStatus::Stale
}

fn after_fence_commit(
    inner: &MetaStoreInner,
    conn: &rusqlite::Connection,
    record: Option<&NamespaceFenceRecord>,
    write_marker: bool,
) {
    if let (Some(record), true) = (record, write_marker) {
        // The metastore is authoritative; a marker that is missing or behind is repaired on
        // the next load (section 5.6).
        if let Err(e) = fence_store::write_marker(&inner.dbs_path, record) {
            tracing::error!(namespace = %record.namespace, "failed to write fence marker: {e}");
        }
    }
    if let Err(e) = checkpoint(conn) {
        tracing::warn!("failed to checkpoint metastore: {e}");
    }
}

fn complete_fence_drain(
    inner: &MetaStoreInner,
    ns: &NamespaceName,
    operation_id: Uuid,
    command_id: Uuid,
    completion: DrainCompletion,
    ctx: &FenceContext,
) -> std::result::Result<FenceCommit, FenceStoreError> {
    if !inner.fence.tables {
        return Err(fence_disabled().into());
    }
    let mut conn = inner.conn.blocking_lock();
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

    let (stored, _) = fence_store::read_fence(&tx, &inner.dbs_path, ns)?;
    let record = match &stored {
        StoredFence::Record(r) => r.clone(),
        other => {
            return Err(other
                .permits(OperationClass::NormalWrite)
                .err()
                .unwrap_or_else(|| {
                    FenceError::new(
                        FenceOutcome::InvalidFenceTransition,
                        "the namespace has no fence record",
                    )
                })
                .into())
        }
    };
    let receipt = match fence_store::read_receipt(&tx, ns, operation_id, command_id)? {
        Some(Ok(r)) => r,
        Some(Err(e)) => return Err(unavailable_receipt(e).into()),
        None => {
            return Err(FenceError::new(
                FenceOutcome::InvalidFenceTransition,
                format!("command {command_id} of operation {operation_id} has no receipt"),
            )
            .into())
        }
    };
    if receipt.is_final() {
        return Ok(FenceCommit {
            kind: FenceCommitKind::Replayed,
            receipt,
            record: Some(record),
            created_config: None,
        });
    }

    let config = fence_store::read_config_row(&tx, ns)?;
    let env = apply_env(ctx, &stored, config.as_ref());
    let (next, final_receipt) = transition::complete_drain(&record, &receipt, completion, &env)?;
    if let Some(config) = &config {
        fence_store::write_config_row(
            &tx,
            ns,
            &fence_store::with_legacy_blocks(config, &next.legacy_mirror()),
        )?;
    }
    fence_store::write_record(&tx, &next, fence_store::stored_revision(&tx, ns)?)?;
    fence_store::write_receipt(&tx, &final_receipt)?;
    tx.commit()?;

    after_fence_commit(inner, &conn, Some(&next), true);

    Ok(FenceCommit {
        kind: FenceCommitKind::Committed,
        receipt: final_receipt,
        record: Some(next),
        created_config: None,
    })
}

impl MetaStore {
    #[tracing::instrument(skip(config, base_path, conn, wal_manager))]
    pub async fn new(
        config: MetaStoreConfig,
        base_path: &Path,
        conn: MetaStoreConnection,
        wal_manager: MetaStoreWalManager,
        db_kind: DatabaseKind,
    ) -> Result<Self> {
        let (changes_tx, mut changes_rx) = mpsc::channel(256);

        let destroy_on_error = config.destroy_on_error;

        let maybe_inner = tokio::task::spawn_blocking({
            let base_path = base_path.to_owned();
            let config = config.clone();
            move || MetaStoreInner::new(&base_path, conn, wal_manager, config.clone(), db_kind)
        })
        .await
        .unwrap();

        let inner = match maybe_inner {
            Ok(inner) => inner,
            Err(e) => {
                if destroy_on_error {
                    let db_path = base_path.join("metastore");

                    tracing::info!(
                        "meta store set to destroy on restore error, removing metastore db path folder ({:?})", db_path
                    );

                    if let Err(e) = std::fs::remove_dir_all(&db_path) {
                        tracing::error!("failed to remove base path({:?}): {}", &db_path, e);
                    }

                    if let Err(e) = std::fs::create_dir_all(&db_path) {
                        tracing::error!(
                            "failed to create meta store base path: {:?} with {}",
                            &db_path,
                            e
                        );
                    }

                    if let Err(e) = std::fs::File::create(db_path.join("data")) {
                        tracing::error!(
                            "failed to create `data` file in {:?} with: {}",
                            &db_path,
                            e
                        );
                    }

                    let (maker, wal) =
                        metastore_connection_maker(config.bottomless.clone(), base_path).await?;

                    let conn = maker()?;

                    tracing::info!("recreating metastore and restoring with fresh data");

                    let inner = tokio::task::spawn_blocking({
                        let base_path = base_path.to_owned();
                        move || MetaStoreInner::new(&base_path, conn, wal, config, db_kind)
                    })
                    .await
                    .unwrap()?;

                    tracing::info!("metastore destroy on error successful");

                    inner
                } else {
                    return Err(e);
                }
            }
        };

        let inner = Arc::new(inner);

        tokio::spawn({
            let inner = inner.clone();
            async move {
                while let Some(msg) = changes_rx.recv().await {
                    let inner = inner.clone();
                    let jh = tokio::task::spawn_blocking(move || process(msg, inner));

                    if let Err(e) = jh.await {
                        tracing::error!("error processing metastore update: {}", e);
                    }
                }
            }
        });

        Ok(Self { changes_tx, inner })
    }

    pub async fn handle(&self, namespace: NamespaceName) -> MetaStoreHandle {
        tracing::debug!("getting meta store handle");
        let change_tx = self.changes_tx.clone();

        let mut configs = self.inner.configs.lock().await;
        let sender = configs.entry(namespace.clone()).or_insert_with(|| {
            // TODO(lucio): if no entry exists we need to ensure we send the update to
            // the bg channel.
            let (tx, _) = watch::channel(InnerConfig::default());
            tx
        });

        let rx = sender.subscribe();

        tracing::debug!("meta handle subscribed");

        MetaStoreHandle {
            namespace,
            inner: HandleState::External(change_tx, rx),
        }
    }

    pub fn remove(&self, namespace: NamespaceName) -> Result<Option<Arc<DatabaseConfig>>> {
        tracing::debug!("removing namespace `{}` from meta store", namespace);

        // "configs" lock can be used in both async and sync contexts while "conn" lock always used
        // in blocking context
        //
        // so, we better to acquire "conn" lock first in order to prevent situation when "configs"
        // lock is taken but "conn" lock is not free (so, we potentially will block async tasks for
        // indefinite amount of time while "conn" lock will be acquired by other thread)
        let mut conn = self.inner.conn.blocking_lock();

        let mut configs = self.inner.configs.blocking_lock();
        let r = if let Some(sender) = configs.get(&namespace) {
            tracing::debug!("removed namespace `{}` from meta store", namespace);
            let config = sender.borrow().clone();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            if self.inner.fence.tables {
                let (stored, _) = fence_store::read_fence(&tx, &self.inner.dbs_path, &namespace)
                    .map_err(fence_store_error)?;
                stored.permits(OperationClass::Lifecycle)?;
                if !matches!(stored, StoredFence::None { .. }) {
                    // The marker goes before the commit: a crash in between leaves a record
                    // without a marker, which is repaired on load, rather than a marker
                    // without a record, which would make the name unavailable.
                    fence_store::remove_marker(&self.inner.dbs_path, &namespace)?;
                    let receipts = fence_store::delete_fence(&tx, &namespace)?;
                    tracing::info!(
                        namespace = %namespace,
                        state = %stored.state(),
                        revision = stored.revision(),
                        receipts,
                        "removing namespace fence with its namespace"
                    );
                }
            }
            if config.config.is_shared_schema {
                if crate::schema::db::schema_has_linked_dbs(&tx, &namespace)? {
                    return Err(crate::Error::HasLinkedDbs(namespace.clone()));
                }
            }
            if let Some(ref shared_schema) = config.config.shared_schema_name {
                if crate::schema::db::has_pending_migration_jobs(&tx, shared_schema)? {
                    return Err(crate::Error::PendingMigrationOnSchema(
                        shared_schema.clone(),
                    ));
                }

                tx.execute(
                    "DELETE FROM shared_schema_links WHERE shared_schema_name = ? AND namespace = ?",
                    (shared_schema.as_str(), namespace.as_str()),
                )?;
            }
            tx.execute(
                "DELETE FROM namespace_configs WHERE namespace = ?",
                [namespace.as_str()],
            )?;
            tx.commit()?;
            Ok(Some(config.config))
        } else {
            tracing::trace!("namespace `{}` not found in meta store", namespace);
            Ok(None)
        };
        configs.remove(&namespace);
        r
    }

    // TODO: we need to either make sure that the metastore is restored
    // before we start accepting connections or we need to contact bottomless
    // here to check if a namespace exists. Preferably the former.
    pub async fn exists(&self, namespace: &NamespaceName) -> bool {
        self.inner.configs.lock().await.contains_key(namespace)
    }

    /// Whether namespace fences may be used on this server.
    pub fn fence_enabled(&self) -> bool {
        self.inner.fence.enabled
    }

    /// Whether this metastore holds fence state, so fences are loaded and enforced.
    pub fn fence_enforced(&self) -> bool {
        self.inner.fence.tables
    }

    /// Run one fence command as a compare-and-swap in a single metastore transaction
    /// (`docs/NAMESPACE_FENCE.md` sections 5.3 and 5.4). Nothing is published here: the
    /// caller publishes the result only after this returns, which is after the commit.
    ///
    /// A fence outcome that is an error (`FENCE_REVISION_MISMATCH`, …) is returned as
    /// [`Error::NamespaceFence`] and nothing is written.
    pub async fn apply_fence_command(
        &self,
        request: FenceRequest,
        ctx: FenceContext,
    ) -> Result<FenceCommit> {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || apply_fence_command(&inner, &request, &ctx))
            .await?
            .map_err(fence_store_error)
    }

    /// Finish the drain that the owning operation's `DRAINING` receipt
    /// `(operation_id, command_id)` started, once the controller has proven `completion`. The
    /// final receipt replaces the `DRAINING` one. If the drain was already completed, the
    /// final receipt is returned as a replay.
    pub async fn complete_fence_drain(
        &self,
        namespace: NamespaceName,
        operation_id: Uuid,
        command_id: Uuid,
        completion: DrainCompletion,
        ctx: FenceContext,
    ) -> Result<FenceCommit> {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            complete_fence_drain(
                &inner,
                &namespace,
                operation_id,
                command_id,
                completion,
                &ctx,
            )
        })
        .await?
        .map_err(fence_store_error)
    }

    /// Read a namespace's fence and all of its receipts (`InspectFence`). Never writes.
    pub async fn inspect_fence(&self, namespace: NamespaceName) -> Result<FenceInspection> {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || -> std::result::Result<_, FenceStoreError> {
            let mut conn = inner.conn.blocking_lock();
            if !inner.fence.tables {
                let tx = conn.transaction()?;
                let exists = fence_store::read_config_row(&tx, &namespace)?.is_some();
                return Ok(FenceInspection {
                    fence: StoredFence::None {
                        namespace_exists: exists,
                    },
                    receipts: Vec::new(),
                });
            }
            let tx = conn.transaction()?;
            let (fence, _) = fence_store::read_fence(&tx, &inner.dbs_path, &namespace)?;
            let receipts = fence_store::read_receipts(&tx, &namespace)?;
            Ok(FenceInspection { fence, receipts })
        })
        .await?
        .map_err(fence_store_error)
    }

    /// Every namespace with fence state, and that state. Namespaces without a record or a
    /// marker are left out.
    pub async fn load_fences(&self) -> Result<Vec<(NamespaceName, StoredFence)>> {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || -> std::result::Result<_, FenceStoreError> {
            if !inner.fence.tables {
                return Ok(Vec::new());
            }
            let mut conn = inner.conn.blocking_lock();
            let tx = conn.transaction()?;
            let names: Vec<String> = {
                let mut stmt = tx.prepare("SELECT namespace FROM namespace_configs")?;
                let rows = stmt.query_map((), |r| r.get::<_, String>(0))?;
                rows.collect::<rusqlite::Result<_>>()?
            };
            let mut out = Vec::new();
            for name in names {
                let Ok(ns) = NamespaceName::from_string(name) else {
                    continue;
                };
                let (fence, _) = fence_store::read_fence(&tx, &inner.dbs_path, &ns)?;
                if !matches!(fence, StoredFence::None { .. }) {
                    out.push((ns, fence));
                }
            }
            Ok(out)
        })
        .await?
        .map_err(fence_store_error)
    }

    pub(crate) async fn shutdown(&self) -> crate::Result<()> {
        let replicator = self.inner.wal_manager.wrapper().as_ref();

        if let Some(maybe_replicator) = replicator {
            if let Some(mut replicator) = maybe_replicator.shutdown().await {
                tracing::info!("Started meta store backup");
                replicator.shutdown_gracefully().await?;
                tracing::info!("meta store backed up");
            }
        }

        Ok(())
    }

    pub async fn get_migrations_summary(
        &self,
        schema: NamespaceName,
    ) -> crate::Result<MigrationSummary> {
        let inner = self.inner.clone();
        let summary = tokio::task::spawn_blocking(move || {
            let mut conn = inner.conn.blocking_lock();
            crate::schema::get_migrations_summary(&mut conn, schema)
        })
        .await
        .unwrap()?;
        Ok(summary)
    }

    pub async fn get_migration_details(
        &self,
        schema: NamespaceName,
        job_id: u64,
    ) -> crate::Result<Option<MigrationDetails>> {
        let inner = self.inner.clone();
        let details = tokio::task::spawn_blocking(move || {
            let mut conn = inner.conn.blocking_lock();
            crate::schema::get_migration_details(&mut conn, schema, job_id)
        })
        .await
        .unwrap()?;
        Ok(details)
    }

    pub async fn backup_savepoint(&self) -> Option<SavepointTracker> {
        if let Some(wal) = self.inner.wal_manager.wrapper() {
            let replicator = wal.replicator();
            let lock = replicator.lock().await;
            return match &*lock {
                Some(replicator) => Some(replicator.savepoint()),
                None => None,
            };
        }
        None
    }
}

impl MetaStoreHandle {
    #[cfg(test)]
    pub fn new_test() -> Self {
        Self::internal()
    }

    #[cfg(test)]
    pub fn load(db_path: impl AsRef<std::path::Path>) -> crate::Result<Self> {
        use std::{fs, io};

        let config_path = db_path.as_ref().join("config.json");

        let config = match fs::read(config_path) {
            Ok(data) => {
                let c = metadata::DatabaseConfig::decode(&data[..])?;
                DatabaseConfig::from(&c)
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => DatabaseConfig::default(),
            Err(err) => return Err(Error::IOError(err)),
        };

        Ok(Self {
            namespace: NamespaceName::new_unchecked("testmetastore"),
            inner: HandleState::Internal(Arc::new(Mutex::new(Arc::new(config)))),
        })
    }

    pub fn internal() -> Self {
        MetaStoreHandle {
            namespace: NamespaceName::new_unchecked("testmetastore"),
            inner: HandleState::Internal(Arc::new(Mutex::new(Arc::new(DatabaseConfig::default())))),
        }
    }

    pub fn get(&self) -> Arc<DatabaseConfig> {
        match &self.inner {
            HandleState::Internal(config) => config.lock().clone(),
            HandleState::External(_, config) => config.borrow().clone().config,
        }
    }

    pub fn version(&self) -> usize {
        match &self.inner {
            HandleState::Internal(_) => 0,
            HandleState::External(_, config) => config.borrow().version,
        }
    }

    pub fn changed(&self) -> impl Future<Output = ()> {
        let mut rcv = match &self.inner {
            HandleState::Internal(_) => panic!("can't wait for change on internal handle"),
            HandleState::External(_, rcv) => rcv.clone(),
        };
        // ack the current value.
        rcv.borrow_and_update();
        async move {
            let _ = rcv.changed().await;
        }
    }

    pub async fn flush(&self) -> Result<()> {
        self.store_and_maybe_flush(None, true).await
    }

    pub async fn store(&self, new_config: impl Into<Arc<DatabaseConfig>>) -> Result<()> {
        self.store_and_maybe_flush(Some(new_config.into()), true)
            .await
    }

    pub async fn store_and_maybe_flush(
        &self,
        new_config: Option<Arc<DatabaseConfig>>,
        flush: bool,
    ) -> Result<()> {
        match &self.inner {
            HandleState::Internal(config) => {
                if let Some(c) = new_config {
                    *config.lock() = c;
                }
            }
            HandleState::External(changes_tx, config) => {
                tracing::debug!(?new_config, "storing new namespace config");
                let mut c = config.clone();
                // ack the current value.
                c.borrow_and_update();
                let changed = c.changed();
                let wait_for_change = new_config.is_some();

                let (snd, rcv) = oneshot::channel();
                changes_tx
                    .send((self.namespace.clone(), new_config, snd, flush))
                    .await
                    .map_err(|e| Error::MetaStoreUpdateFailure(e.into()))?;

                rcv.await??;
                if wait_for_change {
                    changed
                        .await
                        .map_err(|e| Error::MetaStoreUpdateFailure(e.into()))?;
                }
                tracing::debug!("done storing new namespace config");
            }
        };

        Ok(())
    }

    pub fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }
}

#[cfg(test)]
mod fence_tests {
    use std::path::Path;

    use tempfile::tempdir;

    use super::*;
    use crate::namespace::fence::command::TargetConfig;
    use crate::namespace::fence::record::{FenceMarker, FrozenBoundary};
    use crate::namespace::fence::state::FenceState;

    const LOG: Uuid = Uuid::from_u128(0x10);
    const INCARNATION: Uuid = Uuid::from_u128(0x20);
    const OP: Uuid = Uuid::from_u128(0xa);
    const OTHER_OP: Uuid = Uuid::from_u128(0xb);

    async fn open_with(dir: &Path, config: MetaStoreConfig) -> MetaStore {
        let (maker, manager) = metastore_connection_maker(None, dir).await.unwrap();
        let conn = maker().unwrap();
        MetaStore::new(config, dir, conn, manager, DatabaseKind::Primary)
            .await
            .unwrap()
    }

    async fn open(dir: &Path, fence: bool) -> MetaStore {
        open_with(
            dir,
            MetaStoreConfig {
                namespace_fence: fence,
                ..Default::default()
            },
        )
        .await
    }

    /// A second, independent connection to the same metastore database (like the schema
    /// scheduler's).
    async fn raw(dir: &Path) -> MetaStoreConnection {
        let (maker, _) = metastore_connection_maker(None, dir).await.unwrap();
        maker().unwrap()
    }

    fn raw_config(conn: &rusqlite::Connection, ns: &str) -> DatabaseConfig {
        fence_store::read_config_row(conn, &NamespaceName::from(ns.to_string().leak() as &str))
            .unwrap()
            .unwrap()
    }

    fn ctx(now_ms: i64) -> FenceContext {
        FenceContext {
            server: ServerIdentity {
                build: "test".into(),
                instance_id: Uuid::from_u128(0x99),
            },
            now_ms,
            namespace_log_id: Some(LOG),
            new_incarnation_id: INCARNATION,
            adoption_authorised: false,
            validation_snapshot: None,
        }
    }

    fn request(
        ns: &'static str,
        op: Uuid,
        command_id: u128,
        expected_state: FenceState,
        expected_revision: u64,
        command: FenceCommand,
    ) -> FenceRequest {
        FenceRequest {
            namespace: ns.into(),
            operation_id: op,
            command_id: Uuid::from_u128(command_id),
            expected_state,
            expected_revision,
            command,
        }
    }

    fn acquire(ns: &'static str, op: Uuid, command_id: u128) -> FenceRequest {
        request(
            ns,
            op,
            command_id,
            FenceState::Unfenced,
            0,
            FenceCommand::AcquireSourceWriteFence {
                expected_log_id: LOG,
                drain_policy: None,
            },
        )
    }

    fn outcome_of(r: Result<FenceCommit>) -> FenceOutcome {
        match r {
            Ok(c) => c.receipt.outcome,
            Err(Error::NamespaceFence(e)) => e.outcome(),
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    fn fence_error(r: Result<impl std::fmt::Debug>) -> FenceError {
        match r {
            Err(Error::NamespaceFence(e)) => e,
            other => panic!("expected a fence error, got {other:?}"),
        }
    }

    async fn create_namespace(store: &MetaStore, ns: &'static str) -> MetaStoreHandle {
        let handle = store.handle(ns.into()).await;
        handle
            .store(DatabaseConfig {
                max_db_pages: 1234,
                block_reason: Some("pre-fence".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        handle
    }

    fn remove_blocking(store: &MetaStore, ns: &'static str) -> Result<Option<Arc<DatabaseConfig>>> {
        let store = store.clone();
        std::thread::spawn(move || store.remove(ns.into()))
            .join()
            .unwrap()
    }

    #[tokio::test]
    async fn fence_cas_persists_across_restart() {
        let dir = tempdir().unwrap();
        let store = open(dir.path(), true).await;
        let handle = create_namespace(&store, "db").await;

        let commit = store
            .apply_fence_command(acquire("db", OP, 1), ctx(1_000))
            .await
            .unwrap();
        assert_eq!(commit.kind, FenceCommitKind::Committed);
        assert_eq!(commit.receipt.outcome, FenceOutcome::Draining);
        let record = commit.record.unwrap();
        assert_eq!(
            (record.state, record.revision),
            (FenceState::SourceDraining, 1)
        );

        // The stored row carries the legacy mirror; the in-memory config is untouched.
        let conn = raw(dir.path()).await;
        let row = raw_config(&conn, "db");
        assert!(row.block_writes && !row.block_reads);
        assert!(row
            .block_reason
            .unwrap()
            .starts_with("namespace fence: SOURCE_DRAINING"));
        assert!(!handle.get().block_writes);

        let boundary = FrozenBoundary {
            log_id: LOG,
            frame_no: 42,
        };
        let commit = store
            .complete_fence_drain(
                "db".into(),
                OP,
                Uuid::from_u128(1),
                DrainCompletion::SourceWrites { boundary },
                ctx(2_000),
            )
            .await
            .unwrap();
        assert_eq!(commit.receipt.outcome, FenceOutcome::Applied);
        let record = commit.record.unwrap();
        assert_eq!(
            (record.state, record.revision),
            (FenceState::SourceWriteFenced, 2)
        );
        // Completing again is a replay of the final answer.
        let again = store
            .complete_fence_drain(
                "db".into(),
                OP,
                Uuid::from_u128(1),
                DrainCompletion::SourceWrites { boundary },
                ctx(2_500),
            )
            .await
            .unwrap();
        assert_eq!(again.kind, FenceCommitKind::Replayed);

        let marker = fence_store::read_marker(&dir.path().join("dbs"), &"db".into())
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(marker, FenceMarker::for_record(&record));

        drop(handle);
        drop(store);

        // Restart.
        let store = open(dir.path(), true).await;
        let inspection = store.inspect_fence("db".into()).await.unwrap();
        assert_eq!(inspection.fence, StoredFence::Record(record.clone()));
        assert_eq!(inspection.fence.revision(), 2);
        assert_eq!(record.frozen_boundary, Some(boundary));
        assert_eq!(inspection.receipts.len(), 1);
        let receipt = inspection.receipts[0].receipt.clone().unwrap();
        assert_eq!(
            (receipt.outcome, receipt.revision_after),
            (FenceOutcome::Applied, 2)
        );

        // The in-memory config is the namespace's own, not the mirror.
        let handle = store.handle("db".into()).await;
        let config = handle.get();
        assert!(!config.block_writes && !config.block_reads);
        assert_eq!(config.block_reason.as_deref(), Some("pre-fence"));
        assert_eq!(config.max_db_pages, 1234);

        // The lost response of the first command is answered from its receipt, even though
        // the revision has advanced.
        let replay = store
            .apply_fence_command(acquire("db", OP, 1), ctx(3_000))
            .await
            .unwrap();
        assert_eq!(replay.kind, FenceCommitKind::Replayed);
        assert_eq!(replay.receipt, receipt);

        let fences = store.load_fences().await.unwrap();
        assert_eq!(
            fences,
            vec![("db".into(), StoredFence::Record(record.clone()))]
        );

        // Release restores the legacy fields as they were before the fence.
        let release = request(
            "db",
            OP,
            2,
            FenceState::SourceWriteFenced,
            2,
            FenceCommand::ReleaseSourceWriteFence,
        );
        let commit = store
            .apply_fence_command(release, ctx(4_000))
            .await
            .unwrap();
        assert_eq!(commit.record.unwrap().revision, 3);
        let row = raw_config(&conn, "db");
        assert!(!row.block_writes && !row.block_reads);
        assert_eq!(row.block_reason.as_deref(), Some("pre-fence"));
        assert_eq!(row.max_db_pages, 1234);
    }

    #[tokio::test]
    async fn flag_off_still_enforces_existing_fences() {
        let dir = tempdir().unwrap();
        let store = open(dir.path(), true).await;
        let handle = create_namespace(&store, "db").await;
        store
            .apply_fence_command(acquire("db", OP, 1), ctx(1_000))
            .await
            .unwrap();
        drop(handle);
        drop(store);

        let store = open(dir.path(), false).await;
        assert!(!store.fence_enabled());
        assert!(store.fence_enforced());
        let e = fence_error(
            store
                .apply_fence_command(acquire("db", OTHER_OP, 2), ctx(2_000))
                .await,
        );
        assert_eq!(e.detail(), Some(FenceDetail::FenceDisabled));
        let handle = store.handle("db".into()).await;
        let e = fence_error(handle.store(DatabaseConfig::default()).await);
        assert_eq!(e.outcome(), FenceOutcome::MigrationWriteFenced);
        assert_eq!(
            store
                .inspect_fence("db".into())
                .await
                .unwrap()
                .fence
                .state(),
            FenceState::SourceDraining
        );
    }

    #[tokio::test]
    async fn disabled_fence_creates_nothing() {
        let dir = tempdir().unwrap();
        let store = open(dir.path(), false).await;
        let handle = create_namespace(&store, "db").await;
        assert!(!store.fence_enforced());
        let e = fence_error(
            store
                .apply_fence_command(acquire("db", OP, 1), ctx(1_000))
                .await,
        );
        assert_eq!(e.outcome(), FenceOutcome::FencePreconditionFailed);
        assert_eq!(e.detail(), Some(FenceDetail::FenceDisabled));
        let conn = raw(dir.path()).await;
        assert!(!fence_store::tables_exist(&conn).unwrap());
        handle
            .store(DatabaseConfig {
                max_db_pages: 7,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(raw_config(&conn, "db").max_db_pages, 7);
        assert_eq!(
            store.inspect_fence("db".into()).await.unwrap().fence,
            StoredFence::None {
                namespace_exists: true
            }
        );
        assert!(store.load_fences().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn concurrent_cas_has_exactly_one_winner() {
        let dir = tempdir().unwrap();
        let store = open(dir.path(), true).await;
        let _handle = create_namespace(&store, "db").await;

        let attempts = (0..16u128).map(|i| {
            let store = store.clone();
            async move {
                store
                    .apply_fence_command(acquire("db", Uuid::from_u128(0x100 + i), 1), ctx(1_000))
                    .await
            }
        });
        let outcomes: Vec<_> = futures::future::join_all(attempts)
            .await
            .into_iter()
            .map(outcome_of)
            .collect();
        assert_eq!(
            outcomes
                .iter()
                .filter(|o| **o == FenceOutcome::Draining)
                .count(),
            1,
            "{outcomes:?}"
        );
        assert!(outcomes.iter().all(|o| matches!(
            o,
            FenceOutcome::Draining | FenceOutcome::FenceOwnedByAnotherOperation
        )));
        let inspection = store.inspect_fence("db".into()).await.unwrap();
        assert_eq!(inspection.fence.revision(), 1);
        assert_eq!(inspection.receipts.len(), 1);
    }

    #[tokio::test]
    async fn fence_cas_and_config_writes_serialise() {
        let dir = tempdir().unwrap();
        let store = open(dir.path(), true).await;
        let handle = create_namespace(&store, "db").await;

        // Another metastore connection holds the write lock with an uncommitted config
        // change. The fence transition cannot interleave with it: it gives up on the lock
        // and writes nothing.
        let mut other = raw(dir.path()).await;
        let tx = other
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let mut changed = raw_config(&tx, "db");
        changed.max_db_pages = 42;
        fence_store::write_config_row(&tx, &"db".into(), &changed).unwrap();
        let r = store
            .apply_fence_command(acquire("db", OP, 1), ctx(1_000))
            .await;
        assert!(
            matches!(r, Err(Error::RusqliteError(_))),
            "expected the write lock to be busy, got {r:?}"
        );
        tx.commit().unwrap();
        assert_eq!(
            store
                .inspect_fence("db".into())
                .await
                .unwrap()
                .fence
                .state(),
            FenceState::Unfenced
        );

        // After the commit the transition reads the row as committed, so the other writer's
        // change survives underneath the mirror, although the in-memory config never saw it.
        assert_eq!(handle.get().max_db_pages, 1234);
        store
            .apply_fence_command(acquire("db", OP, 1), ctx(1_000))
            .await
            .unwrap();
        let conn = raw(dir.path()).await;
        let row = raw_config(&conn, "db");
        assert_eq!(row.max_db_pages, 42);
        assert!(row.block_writes);

        // An ordinary config write is refused inside its transaction while the fence denies
        // lifecycle operations, and a refused write is not published.
        let e = fence_error(
            handle
                .store(DatabaseConfig {
                    max_db_pages: 9,
                    ..Default::default()
                })
                .await,
        );
        assert_eq!(e.outcome(), FenceOutcome::MigrationWriteFenced);
        assert_eq!(handle.get().max_db_pages, 1234);
        assert_eq!(raw_config(&conn, "db").max_db_pages, 42);
        let e = fence_error(handle.flush().await);
        assert_eq!(e.outcome(), FenceOutcome::MigrationWriteFenced);

        // So is a delete, and the fence row would stop an older binary's delete too.
        let e = fence_error(remove_blocking(&store, "db"));
        assert_eq!(e.outcome(), FenceOutcome::MigrationWriteFenced);
        assert!(conn
            .execute("DELETE FROM namespace_configs WHERE namespace = 'db'", ())
            .is_err());

        // Once released, config writes and delete work again; delete takes the fence with it.
        let release = request(
            "db",
            OP,
            2,
            FenceState::SourceDraining,
            1,
            FenceCommand::ReleaseSourceWriteFence,
        );
        store
            .apply_fence_command(release, ctx(2_000))
            .await
            .unwrap();
        handle
            .store(DatabaseConfig {
                max_db_pages: 9,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(handle.get().max_db_pages, 9);
        drop(handle);
        assert!(remove_blocking(&store, "db").unwrap().is_some());
        let inspection = store.inspect_fence("db".into()).await.unwrap();
        assert_eq!(
            inspection.fence,
            StoredFence::None {
                namespace_exists: false
            }
        );
        assert!(inspection.receipts.is_empty());
    }

    #[tokio::test]
    async fn corrupt_fence_row_fails_closed() {
        let dir = tempdir().unwrap();
        let store = open(dir.path(), true).await;
        let handle = create_namespace(&store, "db").await;
        store
            .apply_fence_command(acquire("db", OP, 1), ctx(1_000))
            .await
            .unwrap();
        drop(handle);
        drop(store);

        let conn = raw(dir.path()).await;
        conn.execute(
            "UPDATE namespace_fences SET record = x'00ff00' WHERE namespace = 'db'",
            (),
        )
        .unwrap();

        // Startup does not fail, and does not guess.
        let store = open(dir.path(), true).await;
        let fence = store.inspect_fence("db".into()).await.unwrap().fence;
        assert!(matches!(
            fence,
            StoredFence::Unavailable {
                detail: FenceDetail::CorruptRecord,
                ..
            }
        ));
        // The config keeps the stored mirror, so statement-level checks stay closed too.
        let handle = store.handle("db".into()).await;
        assert!(handle.get().block_writes);

        let release = request(
            "db",
            OP,
            2,
            FenceState::SourceDraining,
            1,
            FenceCommand::ReleaseSourceWriteFence,
        );
        let e = fence_error(store.apply_fence_command(release, ctx(2_000)).await);
        assert_eq!(e.outcome(), FenceOutcome::FenceStateUnavailable);
        assert_eq!(e.detail(), Some(FenceDetail::CorruptRecord));
        let e = fence_error(handle.store(DatabaseConfig::default()).await);
        assert_eq!(e.outcome(), FenceOutcome::FenceStateUnavailable);
        let e = fence_error(
            store
                .complete_fence_drain(
                    "db".into(),
                    OP,
                    Uuid::from_u128(1),
                    DrainCompletion::SourceWrites {
                        boundary: FrozenBoundary {
                            log_id: LOG,
                            frame_no: 1,
                        },
                    },
                    ctx(2_000),
                )
                .await,
        );
        assert_eq!(e.outcome(), FenceOutcome::FenceStateUnavailable);

        // An unknown format version is its own reason.
        conn.execute(
            "UPDATE namespace_fences SET format_version = 99 WHERE namespace = 'db'",
            (),
        )
        .unwrap();
        let fence = store.inspect_fence("db".into()).await.unwrap().fence;
        assert!(matches!(
            fence,
            StoredFence::Unavailable {
                detail: FenceDetail::UnsupportedFormatVersion,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn marker_tracks_the_metastore() {
        let dir = tempdir().unwrap();
        let dbs = dir.path().join("dbs");
        let store = open(dir.path(), true).await;
        let handle = create_namespace(&store, "db").await;
        store
            .apply_fence_command(acquire("db", OP, 1), ctx(1_000))
            .await
            .unwrap();
        let conn = raw(dir.path()).await;
        let (v1, r1, b1): (i64, i64, Vec<u8>) = conn
            .query_row(
                "SELECT format_version, revision, record FROM namespace_fences",
                (),
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        let commit = store
            .complete_fence_drain(
                "db".into(),
                OP,
                Uuid::from_u128(1),
                DrainCompletion::SourceWrites {
                    boundary: FrozenBoundary {
                        log_id: LOG,
                        frame_no: 7,
                    },
                },
                ctx(2_000),
            )
            .await
            .unwrap();
        let record = commit.record.unwrap();
        drop(handle);
        drop(store);

        // A marker lost after the commit is rewritten from the metastore on load.
        std::fs::remove_file(fence_store::marker_path(&dbs, &"db".into())).unwrap();
        let store = open(dir.path(), true).await;
        let marker = fence_store::read_marker(&dbs, &"db".into())
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(marker.record, record);
        drop(store);

        // A metastore that went backwards (restored to revision 1) is not trusted over the
        // newer marker, and loading it does not overwrite the marker.
        conn.execute(
            "UPDATE namespace_fences SET format_version = ?1, revision = ?2, record = ?3",
            rusqlite::params![v1, r1, b1],
        )
        .unwrap();
        let store = open(dir.path(), true).await;
        let fence = store.inspect_fence("db".into()).await.unwrap().fence;
        match fence {
            StoredFence::Unavailable {
                detail: FenceDetail::MetastoreBehindMarker,
                marker: Some(m),
                ..
            } => assert_eq!(m, record),
            other => panic!("expected metastore_behind_marker, got {other:?}"),
        }
        let marker = fence_store::read_marker(&dbs, &"db".into())
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(marker.record, record);
        let e = fence_error(
            store
                .apply_fence_command(
                    request(
                        "db",
                        OP,
                        3,
                        FenceState::SourceWriteFenced,
                        2,
                        FenceCommand::ReleaseSourceWriteFence,
                    ),
                    ctx(3_000),
                )
                .await,
        );
        assert_eq!(e.detail(), Some(FenceDetail::MetastoreBehindMarker));
    }

    fn create_target(ns: &'static str, command_id: u128) -> FenceRequest {
        request(
            ns,
            OP,
            command_id,
            FenceState::Absent,
            0,
            FenceCommand::CreateTargetQuarantined {
                config: TargetConfig {
                    max_db_size: Some(4096 * 100),
                    ..Default::default()
                },
            },
        )
    }

    #[tokio::test]
    async fn target_creation_is_atomic_and_replayable() {
        let dir = tempdir().unwrap();
        let dbs = dir.path().join("dbs");
        let store = open(dir.path(), true).await;

        let commit = store
            .apply_fence_command(create_target("tgt", 1), ctx(1_000))
            .await
            .unwrap();
        assert_eq!(commit.receipt.outcome, FenceOutcome::Applied);
        let record = commit.record.clone().unwrap();
        assert_eq!(
            (record.state, record.revision),
            (FenceState::TargetQuarantined, 1)
        );
        assert_eq!(record.identity.target_incarnation_id, Some(INCARNATION));
        let created = commit.created_config.unwrap();
        assert_eq!(created.max_db_pages, 100);
        assert!(!created.block_reads && !created.block_writes);
        // Not published: the caller installs the gate first.
        assert!(!store.exists(&"tgt".into()).await);
        // Stored with the legacy mirror, and with its marker.
        let conn = raw(dir.path()).await;
        let row = raw_config(&conn, "tgt");
        assert!(row.block_reads && row.block_writes);
        assert_eq!(
            fence_store::read_marker(&dbs, &"tgt".into())
                .unwrap()
                .unwrap()
                .unwrap()
                .record,
            record
        );
        let replay = store
            .apply_fence_command(create_target("tgt", 1), ctx(2_000))
            .await
            .unwrap();
        assert_eq!(replay.kind, FenceCommitKind::Replayed);
        // A new command of the owner asking for the same thing is ALREADY_APPLIED; another
        // operation cannot take the name.
        let again = store
            .apply_fence_command(create_target("tgt", 2), ctx(2_000))
            .await
            .unwrap();
        assert_eq!(again.receipt.outcome, FenceOutcome::AlreadyApplied);
        assert_eq!(again.record.unwrap().revision, 1);
        let mut other = create_target("tgt", 5);
        other.operation_id = OTHER_OP;
        let e = fence_error(store.apply_fence_command(other, ctx(2_000)).await);
        assert_eq!(e.outcome(), FenceOutcome::FenceOwnedByAnotherOperation);

        // A crash between the marker and the commit: the marker is all that is left.
        store
            .apply_fence_command(create_target("tgt2", 3), ctx(3_000))
            .await
            .unwrap();
        let marker = fence_store::read_marker(&dbs, &"tgt2".into())
            .unwrap()
            .unwrap()
            .unwrap();
        for sql in [
            "DELETE FROM namespace_fence_receipts WHERE namespace = 'tgt2'",
            "DELETE FROM namespace_fences WHERE namespace = 'tgt2'",
            "DELETE FROM namespace_configs WHERE namespace = 'tgt2'",
        ] {
            conn.execute(sql, ()).unwrap();
        }
        let fence = store.inspect_fence("tgt2".into()).await.unwrap().fence;
        assert!(matches!(
            fence,
            StoredFence::Unavailable {
                detail: FenceDetail::IncompleteTargetCreation,
                ..
            }
        ));
        // Only the same command completes it, keeping the incarnation id it announced.
        let e = fence_error(
            store
                .apply_fence_command(create_target("tgt2", 4), ctx(4_000))
                .await,
        );
        assert_eq!(e.outcome(), FenceOutcome::FenceStateUnavailable);
        let mut later = ctx(5_000);
        later.new_incarnation_id = Uuid::from_u128(0x21);
        let commit = store
            .apply_fence_command(create_target("tgt2", 3), later)
            .await
            .unwrap();
        assert_eq!(commit.kind, FenceCommitKind::Committed);
        let record = commit.record.unwrap();
        assert_eq!(
            record.identity.target_incarnation_id,
            marker.record.identity.target_incarnation_id
        );
        assert_eq!(
            store.inspect_fence("tgt2".into()).await.unwrap().fence,
            StoredFence::Record(record)
        );
    }

    async fn run_source_operation(store: &MetaStore, op: Uuid, base: u128, rev: u64, now: i64) {
        let expected = if rev == 0 {
            FenceState::Unfenced
        } else {
            FenceState::Released
        };
        let mut acq = acquire("db", op, base);
        acq.expected_state = expected;
        acq.expected_revision = rev;
        store.apply_fence_command(acq, ctx(now)).await.unwrap();
        let release = request(
            "db",
            op,
            base + 1,
            FenceState::SourceDraining,
            rev + 1,
            FenceCommand::ReleaseSourceWriteFence,
        );
        store
            .apply_fence_command(release, ctx(now + 1))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn receipts_of_finished_operations_are_pruned_after_retention() {
        let dir = tempdir().unwrap();
        let store = open_with(
            dir.path(),
            MetaStoreConfig {
                namespace_fence: true,
                namespace_fence_receipt_retention: Some(Duration::from_secs(1)),
                ..Default::default()
            },
        )
        .await;
        let _handle = create_namespace(&store, "db").await;

        run_source_operation(&store, OP, 1, 0, 1_000).await;
        // Within the retention period, the finished operation's receipts are kept.
        run_source_operation(&store, OTHER_OP, 10, 2, 1_500).await;
        let ops = |receipts: &[StoredReceipt]| {
            receipts
                .iter()
                .map(|r| r.receipt.clone().unwrap().operation_id)
                .collect::<Vec<_>>()
        };
        let inspection = store.inspect_fence("db".into()).await.unwrap();
        assert_eq!(ops(&inspection.receipts), vec![OP, OP, OTHER_OP, OTHER_OP]);
        // Later, a transition prunes other operations' old receipts, never the owner's.
        run_source_operation(&store, Uuid::from_u128(0xc), 20, 4, 10_000).await;
        let inspection = store.inspect_fence("db".into()).await.unwrap();
        assert_eq!(
            ops(&inspection.receipts),
            vec![Uuid::from_u128(0xc), Uuid::from_u128(0xc)]
        );
        assert_eq!(inspection.fence.revision(), 6);
    }
}
