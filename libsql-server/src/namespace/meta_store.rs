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
use rusqlite::{OptionalExtension, TransactionBehavior};
use tokio::sync::oneshot;
use tokio::sync::{
    mpsc,
    watch::{self, Receiver, Sender},
};
use uuid::Uuid;

use crate::config::{BottomlessConfig, FenceAdoptionKey};
use crate::connection::config::DatabaseConfig;
use crate::database::DatabaseKind;
use crate::schema::{MigrationDetails, MigrationSummary};
use crate::{
    config::MetaStoreConfig, connection::legacy::open_conn_active_checkpoint, error::Error, Result,
};

use super::fence::command::{DrainPolicy, FenceCommand, FenceRequest, OnDeadline};
use super::fence::outcome::{FenceDetail, FenceError, FenceOutcome};
use super::fence::record::{
    CommandReceipt, NamespaceFenceRecord, ServerIdentity, ValidationSnapshot,
};
use super::fence::state::{OperationClass, Role};
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
    /// Namespaces whose state could not be recovered at startup and that are therefore
    /// `UNKNOWN_UNAVAILABLE` (`docs/NAMESPACE_FENCE.md` section 13.3): an undecodable config
    /// row, a fence that cannot be established, or a marker the metastore has no trustworthy
    /// record for. They are refused by lookups and by every config or lifecycle change, and
    /// never default-created. A fence command that commits for the name takes it out.
    recovered: Mutex<HashMap<NamespaceName, StoredFence>>,
    /// Where this metastore's contents came from at startup, recorded once the server has
    /// opened it (section 13.3).
    restore_provenance: std::sync::OnceLock<MetastoreProvenance>,
    /// The secret that authorises `AdoptFence` (section 12); `None` disables adoption.
    fence_adoption_key: Option<FenceAdoptionKey>,
}

/// Whether the metastore was restored from its bottomless backup when the server started
/// (`docs/NAMESPACE_FENCE.md` sections 4.3, 4.4 and 13.3). A restored metastore can hold fence
/// records older than the namespace markers; the marker comparison makes those namespaces
/// `UNKNOWN_UNAVAILABLE`, and this is what the admin API, the startup log and the
/// `libsql_server_metastore_restored_from_backup` gauge report about the restore itself.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MetastoreProvenance {
    /// The metastore database was restored from its backup at startup.
    pub restored_from_backup: bool,
    /// The backup generation it was restored from, when known.
    pub restored_generation: Option<Uuid>,
}

impl MetastoreProvenance {
    /// The provenance of a bottomless restore that reported `did_recover`, where `generation`
    /// is the replicator's generation right after the restore: the generation restored from.
    pub fn from_restore(did_recover: bool, generation: Option<Uuid>) -> Self {
        Self {
            restored_from_backup: did_recover,
            restored_generation: generation.filter(|_| did_recover),
        }
    }
}

/// How this metastore treats namespace fences (`docs/NAMESPACE_FENCE.md` section 13.1).
#[derive(Debug, Clone, Copy)]
struct FenceSettings {
    /// The fence may be used: its tables exist and commands are accepted.
    enabled: bool,
    /// The fence tables exist, so fence state is loaded and enforced.
    tables: bool,
    /// Recovery fails closed (section 13.3): the flag is on, the fence tables exist, or a
    /// namespace directory holds a marker.
    fail_closed: bool,
    receipt_retention: Duration,
    /// The write drain deadline of an `AcquireSourceWriteFence` that names no drain policy.
    default_write_drain: Duration,
    default_read_drain: Duration,
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

/// [`metastore_connection_maker_with_provenance`] without the provenance, for tests.
#[cfg(test)]
pub async fn metastore_connection_maker(
    config: Option<BottomlessConfig>,
    base_path: &Path,
) -> crate::Result<(
    impl Fn() -> crate::Result<MetaStoreConnection>,
    MetaStoreWalManager,
)> {
    let (maker, wal_manager, _) =
        metastore_connection_maker_with_provenance(config, base_path).await?;
    Ok((maker, wal_manager))
}

/// [`metastore_connection_maker`], also returning whether the bottomless restore recovered the
/// metastore from its backup, for [`MetaStore::record_restore_provenance`].
pub async fn metastore_connection_maker_with_provenance(
    config: Option<BottomlessConfig>,
    base_path: &Path,
) -> crate::Result<(
    impl Fn() -> crate::Result<MetaStoreConnection>,
    MetaStoreWalManager,
    MetastoreProvenance,
)> {
    let db_path = base_path.join("metastore");
    tokio::fs::create_dir_all(&db_path).await?;
    let mut provenance = MetastoreProvenance::default();
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
            let (action, did_recover) = replicator.restore(None, None).await?;
            // A restore that recovered the database leaves the replicator on the generation it
            // restored from; a new generation, if any, is only started below.
            provenance =
                MetastoreProvenance::from_restore(did_recover, replicator.generation().ok());
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

    Ok((maker, wal_manager, provenance))
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
        let tables = fence_store::tables_exist(&conn)?;
        let dbs_path = base_path.join("dbs");
        let marked = marked_namespaces(&dbs_path)?;
        let fence = FenceSettings {
            enabled: config.namespace_fence,
            tables,
            fail_closed: config.namespace_fence || tables || !marked.is_empty(),
            receipt_retention: config
                .namespace_fence_receipt_retention
                .unwrap_or(fence_store::DEFAULT_RECEIPT_RETENTION),
            default_write_drain: config
                .namespace_fence_default_write_drain
                .unwrap_or(crate::namespace::fence::drain::DEFAULT_WRITE_DRAIN),
            default_read_drain: config
                .namespace_fence_default_read_drain
                .unwrap_or(crate::namespace::fence::read::DEFAULT_READ_DRAIN),
        };

        let mut this = MetaStoreInner {
            configs: Default::default(),
            conn: conn.into(),
            wal_manager,
            db_kind,
            dbs_path,
            fence,
            recovered: Default::default(),
            restore_provenance: Default::default(),
            fence_adoption_key: config.namespace_fence_adoption_key.clone(),
        };

        if config.allow_recover_from_fs {
            this.maybe_recover_from_fs(base_path)?;
        }

        this.restore()?;
        if this.fence.tables {
            this.restore_fences()?;
        }
        this.register_marked(&marked)?;

        Ok(this)
    }

    /// Register every namespace directory with a marker that the metastore has no trustworthy
    /// fence record for as `UNKNOWN_UNAVAILABLE` (section 13.3): a metastore that was rebuilt
    /// (`destroy_on_error`), recovered from the filesystem, restored from an older backup, or
    /// that lost its fence tables, and a target whose creation was interrupted.
    fn register_marked(&mut self, marked: &[NamespaceName]) -> Result<()> {
        for ns in marked {
            if self.recovered.get_mut().contains_key(ns) {
                continue;
            }
            let known = self.configs.get_mut().contains_key(ns);
            if self.fence.tables {
                if known {
                    // `restore_fences` compared the marker with the record.
                    continue;
                }
                let stored = match fence_store::read_fence(self.conn.get_mut(), &self.dbs_path, ns)
                {
                    Ok((stored, _)) => stored,
                    Err(FenceStoreError::Sqlite(e)) => return Err(e.into()),
                    Err(e) => StoredFence::Unavailable {
                        detail: FenceDetail::CorruptRecord,
                        reason: format!("the fence marker cannot be read: {e}"),
                        marker: None,
                    },
                };
                let (detail, reason, marker) = match stored {
                    StoredFence::Unavailable {
                        detail,
                        reason,
                        marker,
                    } => (detail, reason, marker),
                    other => (
                        FenceDetail::CorruptRecord,
                        format!(
                            "the namespace has fence state {} but no usable config row",
                            other.state()
                        ),
                        other.record().cloned(),
                    ),
                };
                mark_unavailable(self.recovered.get_mut(), ns.clone(), detail, reason, marker);
            } else {
                let (detail, marker) = match fence_store::read_marker(&self.dbs_path, ns)? {
                    None => continue,
                    Some(Ok(m)) => (FenceDetail::MetastoreBehindMarker, Some(m.record)),
                    Some(Err(_)) => (FenceDetail::CorruptRecord, None),
                };
                let reason = "the namespace directory holds a fence marker but the metastore has \
                    no fence tables (it was rebuilt, recovered or restored without them)"
                    .to_string();
                mark_unavailable(self.recovered.get_mut(), ns.clone(), detail, reason, marker);
            }
        }
        Ok(())
    }

    /// The fence error for a namespace registered as unavailable at startup.
    fn recovery_denial(&self, namespace: &NamespaceName) -> Option<FenceError> {
        self.recovered.lock().get(namespace).map(unavailable_error)
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
                if entry
                    .path()
                    .join(fence_store::MARKER_FILE_NAME)
                    .try_exists()?
                {
                    // A fenced namespace is never recovered with a guessed config; it is
                    // registered as unavailable below (section 13.3).
                    tracing::warn!("not recovering fenced namespace `{name}` from the filesystem");
                    continue;
                }
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

        let fence = self.fence;
        let conn: &rusqlite::Connection = self.conn.get_mut();
        let mut unavailable = Vec::new();
        let mut stmt = conn.prepare("SELECT namespace, config FROM namespace_configs")?;

        let rows = stmt.query(())?.mapped(|r| {
            let ns = r.get::<_, String>(0)?;
            let config = r.get::<_, Vec<u8>>(1)?;

            Ok((ns, config))
        });

        for row in rows {
            match row {
                Ok((k, v)) => {
                    let ns = match NamespaceName::from_string(k.clone()) {
                        Ok(ns) => ns,
                        Err(e) => {
                            // A name nothing can address cannot be served or default-created,
                            // so a legacy row is skipped as before. A fenced one is an operator
                            // problem: its fence could not be enforced or inspected.
                            if fence.tables && fence_store::stored_revision_raw(conn, &k)?.is_some()
                            {
                                return Err(Error::Internal(format!(
                                    "the metastore holds a namespace fence for `{k}`, which is not \
                                     a valid namespace name; refusing to start"
                                )));
                            }
                            tracing::warn!("unable to convert namespace name: {}", e);
                            continue;
                        }
                    };

                    let config = match metadata::DatabaseConfig::decode(&v[..]) {
                        Ok(c) => Arc::new(DatabaseConfig::from(&c)),
                        Err(e) if fence.fail_closed => {
                            unavailable
                                .push((ns, format!("the config row cannot be decoded: {e}")));
                            continue;
                        }
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

        drop(stmt);
        for (ns, reason) in unavailable {
            mark_unavailable(
                self.recovered.get_mut(),
                ns,
                FenceDetail::CorruptRecord,
                reason,
                None,
            );
        }

        tracing::info!("meta store restore completed");

        Ok(())
    }

    /// Load every namespace's fence after the configs (section 5.6). The stored config row of
    /// a fenced namespace carries the legacy mirror of the fence in its `block_*` fields
    /// (section 13.2) while the record is in force; the in-memory config is the namespace's own
    /// configuration, so those fields are put back to the values the record saved
    /// ([`fence_store::own_config`]). Once the operation has released the namespace or enabled
    /// target writes, the row holds the namespace's own values (including any config written
    /// since) and is used as it is. A marker that fell behind its
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
                    fenced += 1;
                    mark_unavailable(
                        self.recovered.get_mut(),
                        ns,
                        FenceDetail::CorruptRecord,
                        format!("the namespace fence cannot be established: {e}"),
                        None,
                    );
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
                    let config = fence_store::own_config(&config, record);
                    sender.send_modify(|c| c.config = Arc::new(config));
                }
                StoredFence::Unavailable {
                    detail,
                    reason,
                    marker,
                } => {
                    fenced += 1;
                    mark_unavailable(
                        self.recovered.get_mut(),
                        ns,
                        *detail,
                        reason.clone(),
                        marker.clone(),
                    );
                }
            }
        }
        tracing::info!("loaded {fenced} namespace fence(s)");
        Ok(())
    }
}

fn mark_unavailable(
    recovered: &mut HashMap<NamespaceName, StoredFence>,
    namespace: NamespaceName,
    detail: FenceDetail,
    reason: String,
    marker: Option<NamespaceFenceRecord>,
) {
    tracing::error!(
        namespace = %namespace,
        %detail,
        "namespace is UNKNOWN_UNAVAILABLE: {reason}"
    );
    recovered.insert(
        namespace,
        StoredFence::Unavailable {
            detail,
            reason,
            marker,
        },
    );
}

/// The namespaces under `dbs_path` whose directory holds a fence marker. A marker in a
/// directory that is not a valid namespace name stops startup: the fence it records could be
/// neither enforced nor inspected.
fn marked_namespaces(dbs_path: &Path) -> Result<Vec<NamespaceName>> {
    fence_store::scan_markers(dbs_path)?
        .into_iter()
        .map(|m| {
            m.map_err(|raw| {
                Error::Internal(format!(
                    "namespace directory `{raw}` holds a fence marker but is not a valid \
                     namespace name; refusing to start"
                ))
            })
        })
        .collect()
}

/// A namespace's fence as the metastore holds it now, for a metastore with the fence tables:
/// the live record and marker, unless they read as established while startup could not
/// recover the namespace (an undecodable config row, for instance), which stays unavailable.
fn established_fence(
    inner: &MetaStoreInner,
    conn: &rusqlite::Connection,
    namespace: &NamespaceName,
) -> std::result::Result<StoredFence, FenceStoreError> {
    let (live, _) = fence_store::read_fence(conn, &inner.dbs_path, namespace)?;
    if matches!(live, StoredFence::Unavailable { .. }) {
        return Ok(live);
    }
    Ok(inner
        .recovered
        .lock()
        .get(namespace)
        .cloned()
        .unwrap_or(live))
}

/// The error returned for a namespace whose fence state is `UNKNOWN_UNAVAILABLE`.
fn unavailable_error(stored: &StoredFence) -> FenceError {
    stored
        .permits(OperationClass::NormalRead)
        .err()
        .unwrap_or_else(|| {
            FenceError::new(
                FenceOutcome::FenceStateUnavailable,
                "the namespace's fence state cannot be established",
            )
        })
}

/// Why a name that has no config must not be created: its directory holds a marker, so it is a
/// target being created or a namespace the metastore lost (section 13.3).
fn marker_denial(dbs_path: &Path, namespace: &NamespaceName) -> Result<Option<FenceError>> {
    Ok(match fence_store::read_marker(dbs_path, namespace)? {
        None => None,
        Some(Ok(m)) => {
            let revision = m.record.revision;
            Some(
                StoredFence::Record(m.record)
                    .permits(OperationClass::Lifecycle)
                    .err()
                    .unwrap_or_else(|| {
                        unavailable_error(&StoredFence::Unavailable {
                            detail: FenceDetail::MetastoreBehindMarker,
                            reason: format!(
                                "the namespace directory holds a fence marker (revision \
                                 {revision}) but the metastore has no config for it"
                            ),
                            marker: None,
                        })
                    }),
            )
        }
        Some(Err(e)) => Some(unavailable_error(&StoredFence::Unavailable {
            detail: FenceDetail::CorruptRecord,
            reason: format!("the fence marker cannot be decoded: {e}"),
            marker: None,
        })),
    })
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
    if let Some(e) = inner.recovery_denial(namespace) {
        return Err(e.into());
    }
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

/// A fence transaction whose `COMMIT` failed: whether it took effect is unknown, and the
/// controller keeps the namespace closed until the same command is replayed (section 8.4).
fn commit_indeterminate(e: rusqlite::Error) -> FenceStoreError {
    FenceError::new(
        FenceOutcome::FenceCommitIndeterminate,
        format!("the metastore commit of a fence transition failed: {e}"),
    )
    .with_detail(FenceDetail::IndeterminateCommit)
    .into()
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
                if let FenceCommand::AdoptFence(_) = &request.command {
                    // Section 12: adoption changes the owner and nothing else. The marker holds
                    // the fence record, not the namespace's configuration (its JWT key, size
                    // limit, durability, backup id), so re-establishing the record would mean
                    // inventing a configuration. The namespace stays unavailable.
                    return Err(FenceError::new(
                        FenceOutcome::FencePreconditionFailed,
                        "the metastore holds no configuration for this namespace; adoption \
                         re-establishes a fence, not a namespace configuration",
                    )
                    .with_detail(FenceDetail::NamespaceConfigMissing)
                    .into());
                }
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
    tx.commit().map_err(commit_indeterminate)?;
    // The command established the fence from the durable state; whatever startup could not
    // recover about this name is settled.
    inner.recovered.lock().remove(ns);
    if let (StoredFence::Unavailable { .. }, Some(next)) = (&stored, &record) {
        // An adoption re-established the record the marker held (section 12). While the name
        // was unavailable its in-memory config kept whatever the stale config row held; from
        // now on it carries the namespace's own values, as `restore_fences` gives every
        // established record at startup.
        restore_own_blocks(inner, ns, next);
    }

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

/// Put the namespace's own `block_*` values ([`fence_store::own_config`]) into its in-memory
/// config, if it has one. The caller holds the connection lock, which is taken before the
/// config map's everywhere.
fn restore_own_blocks(inner: &MetaStoreInner, ns: &NamespaceName, record: &NamespaceFenceRecord) {
    let configs = inner.configs.blocking_lock();
    if let Some(sender) = configs.get(ns) {
        let config = sender.borrow().config.clone();
        let config = fence_store::own_config(&config, record);
        sender.send_modify(|c| c.config = Arc::new(config));
    }
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
    tx.commit().map_err(commit_indeterminate)?;
    inner.recovered.lock().remove(ns);

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

                    // With fences in use the broken metastore may hold the only record of a
                    // fence, so it is kept aside for the operator rather than deleted, and the
                    // rebuilt metastore registers every marked namespace as unavailable
                    // (section 13.3).
                    let keep = config.namespace_fence
                        || marked_namespaces(&base_path.join("dbs"))
                            .map_or(true, |marked| !marked.is_empty());
                    if keep {
                        let millis = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map_or(0, |d| d.as_millis());
                        let aside = base_path.join(format!("metastore.broken-{millis}"));
                        tracing::error!(
                            "meta store failed to restore ({e}); moving it aside to {aside:?} \
                             and rebuilding it"
                        );
                        if let Err(rename) = std::fs::rename(&db_path, &aside) {
                            tracing::error!(
                                "failed to move the metastore aside ({rename}); not destroying it"
                            );
                            return Err(e);
                        }
                    } else {
                        tracing::info!(
                            "meta store set to destroy on restore error, removing metastore db path folder ({:?})", db_path
                        );

                        if let Err(e) = std::fs::remove_dir_all(&db_path) {
                            tracing::error!("failed to remove base path({:?}): {}", &db_path, e);
                        }
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

                    // The rebuilt metastore is restored from the backup again, so what the
                    // server reports is this restore, not the one of the broken metastore.
                    let (maker, wal, provenance) = metastore_connection_maker_with_provenance(
                        config.bottomless.clone(),
                        base_path,
                    )
                    .await?;

                    let conn = maker()?;

                    tracing::info!("recreating metastore and restoring with fresh data");

                    let inner = tokio::task::spawn_blocking({
                        let base_path = base_path.to_owned();
                        move || MetaStoreInner::new(&base_path, conn, wal, config, db_kind)
                    })
                    .await
                    .unwrap()?;
                    let _ = inner.restore_provenance.set(provenance);

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

    /// The handle of an existing namespace, without creating one (section 13.3). `Ok(None)`
    /// when the namespace does not exist; a fence error when its state could not be recovered.
    /// Every path that only reads or serves a namespace uses this.
    pub async fn lookup(&self, namespace: &NamespaceName) -> Result<Option<MetaStoreHandle>> {
        if let Some(e) = self.inner.recovery_denial(namespace) {
            return Err(e.into());
        }
        let configs = self.inner.configs.lock().await;
        Ok(configs.get(namespace).map(|sender| MetaStoreHandle {
            namespace: namespace.clone(),
            inner: HandleState::External(self.changes_tx.clone(), sender.subscribe()),
        }))
    }

    /// The handle of `namespace`, creating an empty in-memory entry when it does not exist.
    /// Only paths that create a namespace (create, fork destination, reset, lazy creation) use
    /// this. It refuses a namespace whose state could not be recovered, and a name without a
    /// config whose directory holds a fence marker (a target being created, or a namespace the
    /// metastore lost): creating either would publish a default config where a fence belongs.
    pub async fn handle(&self, namespace: NamespaceName) -> Result<MetaStoreHandle> {
        tracing::debug!("getting meta store handle");
        if let Some(e) = self.inner.recovery_denial(&namespace) {
            return Err(e.into());
        }
        let change_tx = self.changes_tx.clone();

        let mut configs = self.inner.configs.lock().await;
        if !configs.contains_key(&namespace) {
            if let Some(e) = marker_denial(&self.inner.dbs_path, &namespace)? {
                return Err(e.into());
            }
        }
        let sender = configs.entry(namespace.clone()).or_insert_with(|| {
            // TODO(lucio): if no entry exists we need to ensure we send the update to
            // the bg channel.
            let (tx, _) = watch::channel(InnerConfig::default());
            tx
        });

        let rx = sender.subscribe();

        tracing::debug!("meta handle subscribed");

        Ok(MetaStoreHandle {
            namespace,
            inner: HandleState::External(change_tx, rx),
        })
    }

    pub fn remove(&self, namespace: NamespaceName) -> Result<Option<Arc<DatabaseConfig>>> {
        tracing::debug!("removing namespace `{}` from meta store", namespace);
        if let Some(e) = self.inner.recovery_denial(&namespace) {
            return Err(e.into());
        }

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

    /// Take out the in-memory entry that [`handle`](Self::handle) put in the map for a
    /// namespace whose creation then failed, so that [`exists`](Self::exists) and
    /// [`lookup`](Self::lookup) do not report a namespace that was never created
    /// (`docs/NAMESPACE_FENCE.md` section 13.3, replica lazy creation). Only an entry that no
    /// handle is subscribed to any more and that has no stored config row is removed: a config
    /// that was persisted, or a creation of the same name still in progress, keeps its entry.
    /// Returns whether the entry was removed.
    pub async fn forget_unstored(&self, namespace: NamespaceName) -> Result<bool> {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || -> std::result::Result<bool, FenceStoreError> {
            // The connection lock first, as everywhere else that takes both: a config being
            // persisted concurrently is either already in its row here, or finds no entry when
            // it publishes and inserts its own.
            let conn = inner.conn.blocking_lock();
            let stored = conn
                .query_row(
                    "SELECT 1 FROM namespace_configs WHERE namespace = ?1",
                    [namespace.as_str()],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            let mut configs = inner.configs.blocking_lock();
            match configs.get(&namespace) {
                Some(sender) if !stored && sender.receiver_count() == 0 => {
                    configs.remove(&namespace);
                    Ok(true)
                }
                _ => Ok(false),
            }
        })
        .await?
        .map_err(fence_store_error)
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

    /// Whether `presented`, the value of a request's `x-libsql-fence-adoption-key` header,
    /// authorises `AdoptFence` (section 12): an adoption key is configured and `presented` is
    /// that key. Compared in constant time.
    pub fn fence_adoption_authorised(&self, presented: Option<&[u8]>) -> bool {
        match (&self.inner.fence_adoption_key, presented) {
            (Some(key), Some(presented)) => key.matches(presented),
            _ => false,
        }
    }

    /// Records where this metastore's contents came from at startup, as reported by
    /// [`metastore_connection_maker_with_provenance`], then sets the
    /// `libsql_server_metastore_restored_from_backup` gauge and, after a restore from backup,
    /// logs a startup warning. What was recorded first wins: when `destroy_on_error` rebuilt
    /// the metastore while opening it, the restore of the rebuilt metastore is already recorded
    /// and is what is reported. The server calls this once, right after opening the metastore.
    pub fn record_restore_provenance(&self, provenance: MetastoreProvenance) {
        let provenance = *self.inner.restore_provenance.get_or_init(|| provenance);
        crate::metrics::METASTORE_RESTORED_FROM_BACKUP.set(if provenance.restored_from_backup {
            1.0
        } else {
            0.0
        });
        if provenance.restored_from_backup {
            tracing::warn!(
                restored_generation = ?provenance.restored_generation,
                fence_tables = self.inner.fence.tables,
                unavailable_namespaces = self.inner.recovered.lock().len(),
                "the metastore was restored from its backup at startup; fence records the backup \
                 does not hold are detected through the namespace markers and reported as \
                 UNKNOWN_UNAVAILABLE"
            );
        }
    }

    /// Where this metastore's contents came from at startup; the default (not restored) until
    /// [`record_restore_provenance`](Self::record_restore_provenance) is called.
    pub fn restore_provenance(&self) -> MetastoreProvenance {
        self.inner
            .restore_provenance
            .get()
            .copied()
            .unwrap_or_default()
    }

    /// The drain policy of an `AcquireSourceWriteFence` that names none: the configured
    /// deadline, then `DRAINING`.
    pub fn fence_default_write_drain(&self) -> DrainPolicy {
        DrainPolicy {
            deadline_ms: u64::try_from(self.inner.fence.default_write_drain.as_millis())
                .unwrap_or(u64::MAX),
            on_deadline: OnDeadline::Fail,
        }
    }

    /// The drain policy of a `SetSourceReadFence` that names none: the configured deadline,
    /// after which running reads are cancelled and streams terminated (`on_deadline` does not
    /// apply to reads).
    pub fn fence_default_read_drain(&self) -> DrainPolicy {
        DrainPolicy {
            deadline_ms: u64::try_from(self.inner.fence.default_read_drain.as_millis())
                .unwrap_or(u64::MAX),
            on_deadline: OnDeadline::Fail,
        }
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

    /// Make a migration target that the metastore holds visible in the in-memory config map,
    /// which is what makes `exists()` and `lookup()` find it (section 10.1, step 5). The config
    /// published is the namespace's own config ([`fence_store::own_config`]): the stored row
    /// with the record's saved `block_*` values in place of the legacy mirror, or the row
    /// itself once target writes are enabled, as `restore_fences` does at startup. The caller has already installed
    /// the target's gate. Returns whether the map changed; `false` also when the namespace is
    /// not a target with a stored config.
    pub async fn publish_target_config(&self, namespace: NamespaceName) -> Result<bool> {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || -> std::result::Result<bool, FenceStoreError> {
            // The connection lock first, as everywhere else that takes both.
            let mut conn = inner.conn.blocking_lock();
            let tx = conn.transaction()?;
            let (stored, _) = fence_store::read_fence(&tx, &inner.dbs_path, &namespace)?;
            let record = match stored {
                StoredFence::Record(r) if r.role == Role::Target => r,
                _ => return Ok(false),
            };
            let Some(row) = fence_store::read_config_row(&tx, &namespace)? else {
                return Ok(false);
            };
            drop(tx);
            let config = Arc::new(fence_store::own_config(&row, &record));
            let mut configs = inner.configs.blocking_lock();
            match configs.get_mut(&namespace) {
                Some(sender)
                    if metadata::DatabaseConfig::from(&*sender.borrow().config)
                        == metadata::DatabaseConfig::from(&*config) =>
                {
                    Ok(false)
                }
                // An entry that was put in the map by a create or fork of the same name that
                // the fence then refused: the durable config replaces it.
                Some(sender) => {
                    sender.send_modify(|c| {
                        c.version = c.version.wrapping_add(1);
                        c.config = config;
                    });
                    Ok(true)
                }
                None => {
                    let (tx, _) = watch::channel(InnerConfig { version: 0, config });
                    configs.insert(namespace, tx);
                    Ok(true)
                }
            }
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
                let recovered = inner.recovered.lock().get(&namespace).cloned();
                let fence = match recovered {
                    Some(fence) => fence,
                    None => {
                        let tx = conn.transaction()?;
                        StoredFence::None {
                            namespace_exists: fence_store::read_config_row(&tx, &namespace)?
                                .is_some(),
                        }
                    }
                };
                return Ok(FenceInspection {
                    fence,
                    receipts: Vec::new(),
                });
            }
            let tx = conn.transaction()?;
            let fence = established_fence(&inner, &tx, &namespace)?;
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
            let recovered: Vec<(NamespaceName, StoredFence)> = inner
                .recovered
                .lock()
                .iter()
                .map(|(ns, fence)| (ns.clone(), fence.clone()))
                .collect();
            if !inner.fence.tables {
                return Ok(recovered);
            }
            let mut conn = inner.conn.blocking_lock();
            let tx = conn.transaction()?;
            let mut names: Vec<NamespaceName> = {
                let mut stmt = tx.prepare("SELECT namespace FROM namespace_configs")?;
                let rows = stmt.query_map((), |r| r.get::<_, String>(0))?;
                rows.collect::<rusqlite::Result<Vec<_>>>()?
                    .into_iter()
                    .filter_map(|name| NamespaceName::from_string(name).ok())
                    .collect()
            };
            for (ns, _) in recovered {
                if !names.contains(&ns) {
                    names.push(ns);
                }
            }
            let mut out = Vec::new();
            for ns in names {
                let fence = established_fence(&inner, &tx, &ns)?;
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

    /// The in-memory entry a failed creation left is forgotten, so `exists()` and `lookup()` do
    /// not report the name; a stored config, or a handle still held, keeps the entry.
    #[tokio::test]
    async fn forget_unstored_only_unused_unstored_entries() {
        let tmp = tempdir().unwrap();
        let meta = open(tmp.path(), true).await;
        let ns = NamespaceName::from("lazy");

        assert!(!meta.forget_unstored(ns.clone()).await.unwrap());

        let handle = meta.handle(ns.clone()).await.unwrap();
        assert!(meta.exists(&ns).await);
        // A handle is still held (a creation in progress): kept.
        assert!(!meta.forget_unstored(ns.clone()).await.unwrap());
        assert!(meta.exists(&ns).await);
        drop(handle);
        assert!(meta.forget_unstored(ns.clone()).await.unwrap());
        assert!(!meta.exists(&ns).await);
        assert!(meta.lookup(&ns).await.unwrap().is_none());

        // A stored config is never forgotten.
        let stored = NamespaceName::from("stored");
        meta.handle(stored.clone())
            .await
            .unwrap()
            .store(DatabaseConfig::default())
            .await
            .unwrap();
        assert!(!meta.forget_unstored(stored.clone()).await.unwrap());
        assert!(meta.lookup(&stored).await.unwrap().is_some());
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
        let handle = store.handle(ns.into()).await.unwrap();
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
            frame_no: Some(42),
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
        let handle = store.handle("db".into()).await.unwrap();
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
        let handle = store.handle("db".into()).await.unwrap();
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
        // The namespace is not served and cannot be recreated. Its in-memory config keeps the
        // stored mirror, so statement-level checks would stay closed too.
        assert_eq!(
            fence_error(store.lookup(&"db".into()).await).detail(),
            Some(FenceDetail::CorruptRecord)
        );
        assert_eq!(
            fence_error(store.handle("db".into()).await).detail(),
            Some(FenceDetail::CorruptRecord)
        );
        let config = store.inner.configs.lock().await[&NamespaceName::from("db")]
            .borrow()
            .config
            .clone();
        assert!(config.block_writes);
        // A handle taken before the fence became unavailable cannot write the config either.
        let handle = MetaStoreHandle {
            namespace: "db".into(),
            inner: HandleState::External(
                store.changes_tx.clone(),
                store.inner.configs.lock().await[&NamespaceName::from("db")].subscribe(),
            ),
        };

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
                            frame_no: Some(1),
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
                        frame_no: Some(7),
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

    /// Fail-closed metastore recovery (`docs/NAMESPACE_FENCE.md` section 13.3).
    mod recovery {
        use super::*;

        fn unavailable_detail(r: Result<impl std::fmt::Debug>) -> FenceDetail {
            let e = fence_error(r);
            assert_eq!(e.outcome(), FenceOutcome::FenceStateUnavailable, "{e}");
            e.detail().expect("unavailable carries a detail")
        }

        async fn open_err(dir: &Path, config: MetaStoreConfig) -> Error {
            let (maker, manager) = metastore_connection_maker(None, dir).await.unwrap();
            let conn = maker().unwrap();
            match MetaStore::new(config, dir, conn, manager, DatabaseKind::Primary).await {
                Ok(_) => panic!("the metastore opened"),
                Err(e) => e,
            }
        }

        fn recover_from_fs(fence: bool) -> MetaStoreConfig {
            MetaStoreConfig {
                allow_recover_from_fs: true,
                namespace_fence: fence,
                ..Default::default()
            }
        }

        /// A fenced namespace `db` (SOURCE_DRAINING, revision 1, with its marker).
        async fn fenced_db(dir: &Path) -> NamespaceFenceRecord {
            let store = open(dir, true).await;
            let _handle = create_namespace(&store, "db").await;
            store
                .apply_fence_command(acquire("db", OP, 1), ctx(1_000))
                .await
                .unwrap()
                .record
                .unwrap()
        }

        fn assert_marker_unavailable(fence: &StoredFence, record: &NamespaceFenceRecord) {
            match fence {
                StoredFence::Unavailable {
                    detail: FenceDetail::MetastoreBehindMarker,
                    marker: Some(m),
                    ..
                } => assert_eq!(m, record),
                other => panic!("expected metastore_behind_marker, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn lookup_never_creates() {
            let dir = tempdir().unwrap();
            let store = open(dir.path(), true).await;
            assert!(store.lookup(&"missing".into()).await.unwrap().is_none());
            assert!(!store.exists(&"missing".into()).await);

            let _handle = create_namespace(&store, "db").await;
            let found = store.lookup(&"db".into()).await.unwrap().unwrap();
            assert_eq!(found.get().max_db_pages, 1234);
            // Only the creating path adds an entry.
            let created = store.handle("new".into()).await.unwrap();
            assert_eq!(
                created.get().max_db_pages,
                DatabaseConfig::default().max_db_pages
            );
            assert!(store.exists(&"new".into()).await);
        }

        #[tokio::test]
        async fn fs_recovery_with_marker_unavailable() {
            for fence in [true, false] {
                let dir = tempdir().unwrap();
                let record = fenced_db(dir.path()).await;
                // A legacy namespace directory without a marker.
                std::fs::create_dir_all(dir.path().join("dbs").join("legacy")).unwrap();
                std::fs::remove_dir_all(dir.path().join("metastore")).unwrap();

                let store = open_with(dir.path(), recover_from_fs(fence)).await;
                // The legacy directory is recovered as before.
                let legacy = store.lookup(&"legacy".into()).await.unwrap().unwrap();
                assert_eq!(
                    legacy.get().max_db_pages,
                    DatabaseConfig::default().max_db_pages
                );
                // The fenced one is not recovered with a guessed config, and is unavailable.
                assert_eq!(
                    unavailable_detail(store.lookup(&"db".into()).await),
                    FenceDetail::MetastoreBehindMarker,
                    "fence flag {fence}"
                );
                assert_eq!(
                    unavailable_detail(store.handle("db".into()).await),
                    FenceDetail::MetastoreBehindMarker
                );
                assert_eq!(
                    unavailable_detail(remove_blocking(&store, "db")),
                    FenceDetail::MetastoreBehindMarker
                );
                let inspection = store.inspect_fence("db".into()).await.unwrap();
                assert_marker_unavailable(&inspection.fence, &record);
                let fences = store.load_fences().await.unwrap();
                assert_eq!(fences.len(), 1);
                assert_marker_unavailable(&fences[0].1, &record);
                // Nothing was written for it, and the marker is untouched.
                let conn = raw(dir.path()).await;
                assert!(fence_store::read_config_row(&conn, &"db".into())
                    .unwrap()
                    .is_none());
                let marker = fence_store::read_marker(&dir.path().join("dbs"), &"db".into())
                    .unwrap()
                    .unwrap()
                    .unwrap();
                assert_eq!(marker.record, record);
            }
        }

        #[tokio::test]
        async fn destroy_on_error_keeps_fenced_unavailable() {
            let dir = tempdir().unwrap();
            let record = fenced_db(dir.path()).await;
            {
                // Break the metastore so that restoring it fails.
                let conn = raw(dir.path()).await;
                conn.execute(
                    "ALTER TABLE namespace_configs RENAME COLUMN config TO broken",
                    (),
                )
                .unwrap();
            }
            let store = open_with(
                dir.path(),
                MetaStoreConfig {
                    destroy_on_error: true,
                    namespace_fence: true,
                    ..Default::default()
                },
            )
            .await;
            // The broken metastore is kept aside, not deleted.
            let aside: Vec<_> = std::fs::read_dir(dir.path())
                .unwrap()
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .filter(|n| n.starts_with("metastore.broken-"))
                .collect();
            assert_eq!(aside.len(), 1, "{aside:?}");
            assert!(dir.path().join(&aside[0]).join("data").exists());
            // The rebuilt metastore knows nothing of `db`, so its marker makes it unavailable.
            assert_eq!(
                unavailable_detail(store.lookup(&"db".into()).await),
                FenceDetail::MetastoreBehindMarker
            );
            assert_eq!(
                unavailable_detail(store.handle("db".into()).await),
                FenceDetail::MetastoreBehindMarker
            );
            assert_marker_unavailable(
                &store.inspect_fence("db".into()).await.unwrap().fence,
                &record,
            );
        }

        #[tokio::test]
        async fn destroy_on_error_without_fences_is_unchanged() {
            let dir = tempdir().unwrap();
            {
                let store = open(dir.path(), false).await;
                let _handle = create_namespace(&store, "db").await;
            }
            {
                let conn = raw(dir.path()).await;
                conn.execute(
                    "ALTER TABLE namespace_configs RENAME COLUMN config TO broken",
                    (),
                )
                .unwrap();
            }
            let store = open_with(
                dir.path(),
                MetaStoreConfig {
                    destroy_on_error: true,
                    ..Default::default()
                },
            )
            .await;
            assert!(store.lookup(&"db".into()).await.unwrap().is_none());
            assert!(!std::fs::read_dir(dir.path()).unwrap().any(|e| e
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("metastore.")));
        }

        #[tokio::test]
        async fn undecodable_row_unavailable() {
            let dir = tempdir().unwrap();
            {
                let store = open(dir.path(), true).await;
                let _handle = create_namespace(&store, "good").await;
            }
            let conn = raw(dir.path()).await;
            conn.execute(
                "INSERT INTO namespace_configs VALUES ('bad', X'FFFFFFFF')",
                (),
            )
            .unwrap();
            let store = open(dir.path(), true).await;
            assert!(store.lookup(&"good".into()).await.unwrap().is_some());
            assert_eq!(
                unavailable_detail(store.lookup(&"bad".into()).await),
                FenceDetail::CorruptRecord
            );
            // Never replaced by a default config, nor deleted.
            assert_eq!(
                unavailable_detail(store.handle("bad".into()).await),
                FenceDetail::CorruptRecord
            );
            assert_eq!(
                unavailable_detail(remove_blocking(&store, "bad")),
                FenceDetail::CorruptRecord
            );
            assert!(matches!(
                store.inspect_fence("bad".into()).await.unwrap().fence,
                StoredFence::Unavailable {
                    detail: FenceDetail::CorruptRecord,
                    ..
                }
            ));
            let bytes: Vec<u8> = conn
                .query_row(
                    "SELECT config FROM namespace_configs WHERE namespace = 'bad'",
                    (),
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(bytes, vec![0xff; 4]);
        }

        #[tokio::test]
        async fn undecodable_row_without_fences_is_skipped_as_before() {
            let dir = tempdir().unwrap();
            drop(open(dir.path(), false).await);
            let conn = raw(dir.path()).await;
            conn.execute(
                "INSERT INTO namespace_configs VALUES ('bad', X'FFFFFFFF')",
                (),
            )
            .unwrap();
            let store = open(dir.path(), false).await;
            assert!(store.lookup(&"bad".into()).await.unwrap().is_none());
        }

        #[tokio::test]
        async fn undecodable_name_with_fence_fails_startup() {
            let dir = tempdir().unwrap();
            drop(open(dir.path(), true).await);
            let conn = raw(dir.path()).await;
            let config = metadata::DatabaseConfig::from(&DatabaseConfig::default()).encode_to_vec();
            conn.execute("INSERT INTO namespace_configs VALUES ('', ?1)", [&config])
                .unwrap();
            // Without a fence it is skipped, as before.
            let store = open(dir.path(), true).await;
            assert!(store.load_fences().await.unwrap().is_empty());
            drop(store);
            conn.execute("INSERT INTO namespace_fences VALUES ('', 1, 1, X'00')", ())
                .unwrap();
            let e = open_err(dir.path(), MetaStoreConfig::default()).await;
            assert!(matches!(e, Error::Internal(_)), "{e}");
        }

        #[tokio::test]
        async fn marker_in_invalid_directory_fails_startup() {
            use std::os::unix::ffi::OsStrExt;
            let dir = tempdir().unwrap();
            let bad = dir
                .path()
                .join("dbs")
                .join(std::ffi::OsStr::from_bytes(b"\xff"));
            std::fs::create_dir_all(&bad).unwrap();
            std::fs::write(bad.join(fence_store::MARKER_FILE_NAME), b"x").unwrap();
            let e = open_err(dir.path(), MetaStoreConfig::default()).await;
            assert!(matches!(e, Error::Internal(_)), "{e}");
        }

        #[tokio::test]
        async fn incomplete_target_unavailable() {
            let dir = tempdir().unwrap();
            let store = open(dir.path(), true).await;
            let commit = store
                .apply_fence_command(create_target("tgt", 3), ctx(1_000))
                .await
                .unwrap();
            let record = commit.record.unwrap();
            // Committed but not yet published: nothing can create a default namespace over it.
            let e = fence_error(store.handle("tgt".into()).await);
            assert_eq!(e.outcome(), FenceOutcome::MigrationTargetQuarantined);
            assert!(store.lookup(&"tgt".into()).await.unwrap().is_none());
            drop(store);

            // A crash between the marker and the commit: the marker is all that is left.
            let conn = raw(dir.path()).await;
            for sql in [
                "DELETE FROM namespace_fence_receipts WHERE namespace = 'tgt'",
                "DELETE FROM namespace_fences WHERE namespace = 'tgt'",
                "DELETE FROM namespace_configs WHERE namespace = 'tgt'",
            ] {
                conn.execute(sql, ()).unwrap();
            }
            let store = open(dir.path(), true).await;
            assert_eq!(
                unavailable_detail(store.lookup(&"tgt".into()).await),
                FenceDetail::IncompleteTargetCreation
            );
            assert_eq!(
                unavailable_detail(store.handle("tgt".into()).await),
                FenceDetail::IncompleteTargetCreation
            );
            let fences = store.load_fences().await.unwrap();
            assert!(matches!(
                fences.as_slice(),
                [(
                    _,
                    StoredFence::Unavailable {
                        detail: FenceDetail::IncompleteTargetCreation,
                        ..
                    }
                )]
            ));
            // The same command completes the creation, which settles the name.
            let commit = store
                .apply_fence_command(create_target("tgt", 3), ctx(2_000))
                .await
                .unwrap();
            assert_eq!(commit.kind, FenceCommitKind::Committed);
            assert_eq!(commit.record.as_ref().unwrap().identity, record.identity);
            assert!(store.lookup(&"tgt".into()).await.unwrap().is_none());
            let e = fence_error(store.handle("tgt".into()).await);
            assert_eq!(e.outcome(), FenceOutcome::MigrationTargetQuarantined);
            assert_eq!(
                store.inspect_fence("tgt".into()).await.unwrap().fence,
                StoredFence::Record(commit.record.unwrap())
            );
        }

        #[tokio::test]
        async fn metastore_rollback_detected_by_marker() {
            let dir = tempdir().unwrap();
            let conn = raw(dir.path()).await;
            let record = {
                let store = open(dir.path(), true).await;
                let _handle = create_namespace(&store, "db").await;
                let record = store
                    .apply_fence_command(acquire("db", OP, 1), ctx(1_000))
                    .await
                    .unwrap()
                    .record
                    .unwrap();
                drop(store);
                // A metastore restored from a backup taken before the fence: the namespace is
                // unfenced there, and only its marker remembers the fence.
                conn.execute("DELETE FROM namespace_fence_receipts", ())
                    .unwrap();
                conn.execute("DELETE FROM namespace_fences", ()).unwrap();
                record
            };
            let store = open(dir.path(), true).await;
            assert_eq!(
                unavailable_detail(store.lookup(&"db".into()).await),
                FenceDetail::MetastoreBehindMarker
            );
            // Neither served, nor deleted, nor given a new config.
            assert_eq!(
                unavailable_detail(store.handle("db".into()).await),
                FenceDetail::MetastoreBehindMarker
            );
            assert_eq!(
                unavailable_detail(remove_blocking(&store, "db")),
                FenceDetail::MetastoreBehindMarker
            );
            assert_marker_unavailable(
                &store.inspect_fence("db".into()).await.unwrap().fence,
                &record,
            );
            // A new operation cannot acquire over the lost fence either.
            let e = fence_error(
                store
                    .apply_fence_command(acquire("db", OTHER_OP, 2), ctx(2_000))
                    .await,
            );
            assert_eq!(e.detail(), Some(FenceDetail::MetastoreBehindMarker));
        }
    }

    /// Metastore restore provenance (`docs/NAMESPACE_FENCE.md` sections 4.3, 4.4 and 13.3).
    mod provenance {
        use super::*;

        #[test]
        fn generation_only_after_a_recovery() {
            let generation = Uuid::from_u128(0x77);
            assert_eq!(
                MetastoreProvenance::from_restore(true, Some(generation)),
                MetastoreProvenance {
                    restored_from_backup: true,
                    restored_generation: Some(generation),
                }
            );
            // A restore that found the local database up to date (or nothing to restore) did
            // not recover anything, whatever generation the replicator is on.
            assert_eq!(
                MetastoreProvenance::from_restore(false, Some(generation)),
                MetastoreProvenance::default()
            );
            assert_eq!(
                MetastoreProvenance::from_restore(true, None),
                MetastoreProvenance {
                    restored_from_backup: true,
                    restored_generation: None,
                }
            );
        }

        #[tokio::test]
        async fn not_restored_until_recorded_and_first_record_wins() {
            let dir = tempdir().unwrap();
            let store = open(dir.path(), true).await;
            assert_eq!(store.restore_provenance(), MetastoreProvenance::default());

            let restored = MetastoreProvenance {
                restored_from_backup: true,
                restored_generation: Some(Uuid::from_u128(0x77)),
            };
            store.record_restore_provenance(restored);
            assert_eq!(store.restore_provenance(), restored);
            // Every clone of the store reports the same provenance.
            assert_eq!(store.clone().restore_provenance(), restored);

            store.record_restore_provenance(MetastoreProvenance::default());
            assert_eq!(store.restore_provenance(), restored);
        }

        /// An S3 endpoint backed by a temporary directory, on a port of its own.
        async fn mock_s3() -> (tempfile::TempDir, String) {
            use s3s::auth::SimpleAuth;
            use s3s::service::S3ServiceBuilder;

            let root = tempdir().unwrap();
            let mut s3 = S3ServiceBuilder::new(s3s_fs::FileSystem::new(root.path()).unwrap());
            s3.set_auth(SimpleAuth::from_single("key", "secret"));
            let service = s3.build().into_shared().into_make_service();
            let server = hyper::Server::bind(&([127, 0, 0, 1], 0).into()).serve(service);
            let endpoint = format!("http://{}", server.local_addr());
            tokio::spawn(server);
            (root, endpoint)
        }

        fn bottomless(endpoint: String) -> BottomlessConfig {
            BottomlessConfig {
                access_key_id: "key".into(),
                secret_access_key: "secret".into(),
                session_token: None,
                region: "us-east-1".into(),
                backup_id: "metastore-provenance".into(),
                bucket_name: "provenance".into(),
                backup_interval: Duration::from_millis(100),
                bucket_endpoint: endpoint,
            }
        }

        async fn open_bottomless(
            dir: &Path,
            config: &BottomlessConfig,
        ) -> (MetaStore, MetastoreProvenance) {
            let (maker, manager, provenance) =
                metastore_connection_maker_with_provenance(Some(config.clone()), dir)
                    .await
                    .unwrap();
            let store = MetaStore::new(
                MetaStoreConfig::default(),
                dir,
                maker().unwrap(),
                manager,
                DatabaseKind::Primary,
            )
            .await
            .unwrap();
            store.record_restore_provenance(provenance);
            (store, provenance)
        }

        /// A metastore opened on an empty directory from a backup that holds one reports the
        /// restore and the generation it came from; one opened with nothing to restore does
        /// not.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn bottomless_restore_is_reported() {
            let (_s3, endpoint) = mock_s3().await;
            let config = bottomless(endpoint);

            let first = tempdir().unwrap();
            let (store, provenance) = open_bottomless(first.path(), &config).await;
            assert_eq!(provenance, MetastoreProvenance::default());
            assert_eq!(store.restore_provenance(), MetastoreProvenance::default());
            let _handle = create_namespace(&store, "db").await;
            // Uploads everything the backup does not hold yet.
            store.shutdown().await.unwrap();

            let second = tempdir().unwrap();
            let (store, provenance) = open_bottomless(second.path(), &config).await;
            assert!(provenance.restored_from_backup, "{provenance:?}");
            assert!(provenance.restored_generation.is_some(), "{provenance:?}");
            assert_eq!(store.restore_provenance(), provenance);
            // The restored metastore holds what the first one backed up.
            assert!(store.exists(&"db".into()).await);
        }
    }
}
