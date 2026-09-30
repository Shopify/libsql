#![allow(clippy::mutable_key_type)]
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
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
use tokio::sync::oneshot;
use tokio::sync::{
    mpsc,
    watch::{self, Receiver, Sender},
};

use crate::config::BottomlessConfig;
use crate::connection::config::DatabaseConfig;
use crate::database::DatabaseKind;
use crate::schema::{MigrationDetails, MigrationSummary};
use crate::{
    config::MetaStoreConfig, connection::legacy::open_conn_active_checkpoint, error::Error, Result,
};

use super::NamespaceName;

type ChangeMsg = (
    NamespaceName,
    Option<Arc<DatabaseConfig>>,
    oneshot::Sender<Result<()>>,
    bool,            // flush
    Arc<AtomicBool>, // one namespace incarnation; revoked before deletion
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
    External(
        mpsc::Sender<ChangeMsg>,
        Receiver<InnerConfig>,
        Arc<AtomicBool>,
    ),
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
    // A deleted name remains tombstoned until explicit create/replica reserve
    // installs a NEW token. Old handles and queued messages keep the revoked
    // token, even if a later namespace reuses the same spelling.
    generations: Mutex<HashMap<NamespaceName, Arc<AtomicBool>>>,
    conn: tokio::sync::Mutex<MetaStoreConnection>,
    wal_manager: MetaStoreWalManager,
    db_kind: DatabaseKind,
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

        let mut this = MetaStoreInner {
            configs: Default::default(),
            generations: Default::default(),
            conn: conn.into(),
            wal_manager,
            db_kind,
        };

        if config.allow_recover_from_fs {
            this.maybe_recover_from_fs(base_path)?;
        }

        this.restore()?;

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
                // Do not follow symlinked directories during filesystem recovery.
                if !entry.file_type()?.is_dir() {
                    continue;
                }
                let Some(file_name) = entry.file_name().to_str().map(str::to_owned) else {
                    tracing::warn!("skipping namespace directory with non-UTF-8 name");
                    continue;
                };
                let name = match NamespaceName::from_string(file_name) {
                    Ok(name) => name,
                    Err(_) => {
                        tracing::warn!("skipping invalid namespace directory during recovery");
                        continue;
                    }
                };
                let config_path = entry.path().join("config.json");
                let config = if config_path.try_exists()? {
                    let config_bytes = std::fs::read(&config_path)?;
                    serde_json::from_slice(&config_bytes).map_err(|e| {
                        Error::InvalidPersistedNamespaceConfig {
                            namespace: name.to_string(),
                            reason: format!("invalid filesystem config.json: {e}"),
                        }
                    })?
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
                    let ns = NamespaceName::from_string(k.clone()).map_err(|e| {
                        Error::InvalidPersistedNamespaceConfig {
                            namespace: k,
                            reason: format!("invalid persisted namespace name: {e}"),
                        }
                    })?;

                    // Retained invalid configs must not be treated as missing: a
                    // later create could overwrite the row and its schema links.
                    let config = metadata::DatabaseConfig::decode(&v[..])
                        .map_err(Error::from)
                        .and_then(|c| DatabaseConfig::try_from(&c))
                        .map_err(|e| Error::InvalidPersistedNamespaceConfig {
                            namespace: ns.to_string(),
                            reason: e.to_string(),
                        })?;
                    let config = Arc::new(config);

                    // We don't store the version in the sqlitedb due to the session token
                    // changed each time we start the primary, this will cause the replica to
                    // handshake again and get the latest config.
                    let (tx, _) = watch::channel(InnerConfig { version: 0, config });

                    self.generations
                        .get_mut()
                        .insert(ns.clone(), Arc::new(AtomicBool::new(true)));
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
}

/// Handles config change updates by inserting them into the database and in-memory
/// cache of configs.
fn process(msg: ChangeMsg, inner: Arc<MetaStoreInner>) {
    let (namespace, config, ret_chan, flush, generation) = msg;
    if let Some(config) = config {
        let result = if flush {
            try_process(&inner, &namespace, &config, &generation)
        } else {
            Ok(())
        };
        let mut configs = inner.configs.blocking_lock();
        // Removing a namespace takes the same lock before revoking this token.
        // Do not resurrect watch state after a queued write or a failed flush.
        let result = result.and_then(|()| {
            if !generation.load(Ordering::Acquire) {
                return Err(Error::NamespaceDoesntExist(namespace.to_string()));
            }
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
                configs.insert(namespace.clone(), tx);
            }
            Ok(())
        });
        let _ = ret_chan.send(result);
    } else {
        // Do not hold configs while waiting for conn: remove locks conn first.
        let config = if flush {
            inner
                .configs
                .blocking_lock()
                .get(&namespace)
                .map(|watch| watch.subscribe().borrow().config.clone())
        } else {
            None
        };
        let result = match config {
            Some(config) => try_process(&inner, &namespace, &config, &generation),
            None if generation.load(Ordering::Acquire) => Ok(()),
            None => Err(Error::NamespaceDoesntExist(namespace.to_string())),
        };
        let _ = ret_chan.send(result);
    }
}

fn try_process(
    inner: &MetaStoreInner,
    namespace: &NamespaceName,
    config: &DatabaseConfig,
    generation: &AtomicBool,
) -> Result<()> {
    let config_encoded = metadata::DatabaseConfig::from(config).encode_to_vec();

    let mut conn = inner.conn.blocking_lock();
    // This check is AFTER acquiring the DB lock. A pre-delete write either
    // commits before remove (and is removed), or sees the revoked generation.
    if !generation.load(Ordering::Acquire) {
        return Err(Error::NamespaceDoesntExist(namespace.to_string()));
    }
    if let Some(schema) = config.shared_schema_name.as_ref() {
        let tx = conn.transaction()?;
        if inner.db_kind.is_primary() {
            if let Some(ref schema) = config.shared_schema_name {
                if crate::schema::db::has_pending_migration_jobs(&tx, schema)? {
                    return Err(crate::Error::PendingMigrationOnSchema(schema.clone()));
                }
            }
        }
        tx.execute(
            "INSERT INTO namespace_configs (namespace, config) VALUES (?1, ?2) ON CONFLICT(namespace) DO UPDATE SET config=excluded.config",
            rusqlite::params![namespace.as_str(), config_encoded],
        )?;
        tx.execute(
            "DELETE FROM shared_schema_links WHERE namespace = ?",
            rusqlite::params![namespace.as_str()],
        )?;
        tx.execute(
            "INSERT OR REPLACE INTO shared_schema_links (shared_schema_name, namespace) VALUES (?1, ?2)",
            rusqlite::params![schema.as_str(), namespace.as_str()],
        )?;
        tx.commit()?;
    } else {
        conn.execute(
            "INSERT INTO namespace_configs (namespace, config) VALUES (?1, ?2) ON CONFLICT(namespace) DO UPDATE SET config=excluded.config",
            rusqlite::params![namespace.as_str(), config_encoded],
        )?;
    }

    if let Err(e) = checkpoint(&conn) {
        tracing::warn!("failed to checkpoint metastore: {e}");
    }

    Ok(())
}

fn checkpoint(conn: &rusqlite::Connection) -> Result<()> {
    conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", (), |_| Ok(()))?;
    Ok(())
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
                // An invalid persisted name/config requires operator repair; do
                // not erase otherwise healthy metastore links, jobs, or data.
                if matches!(e, Error::InvalidPersistedNamespaceConfig { .. }) {
                    return Err(e);
                }
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
        let generation = self
            .inner
            .generations
            .lock()
            .entry(namespace.clone())
            .or_insert_with(|| Arc::new(AtomicBool::new(true)))
            .clone();

        tracing::debug!("meta handle subscribed");

        MetaStoreHandle {
            namespace,
            inner: HandleState::External(change_tx, rx, generation),
        }
    }

    // Called under the store's per-name lock, after a new directory has been
    // reserved. Revoking old handles is distinct from checking configs: a new
    // incarnation's first INSERT must be allowed even without a stored row.
    pub(crate) fn activate_for_create(&self, namespace: &NamespaceName) {
        let mut generations = self.inner.generations.lock();
        if let Some(old) = generations.insert(namespace.clone(), Arc::new(AtomicBool::new(true))) {
            old.store(false, Ordering::Release);
        }
    }

    pub(crate) fn generation(&self, namespace: &NamespaceName) -> Option<Arc<AtomicBool>> {
        self.inner.generations.lock().get(namespace).cloned()
    }

    // A cancelled config update may already be queued when its caller drops.
    // Place a barrier after it before removing that caller's metadata, so the
    // background worker cannot reinsert a row after cleanup.
    #[cfg(test)]
    pub(crate) fn pending_change_count_for_test(&self) -> usize {
        self.changes_tx.max_capacity() - self.changes_tx.capacity()
    }

    #[cfg(test)]
    pub(crate) async fn hold_connection_for_test(
        &self,
    ) -> tokio::sync::MutexGuard<'_, MetaStoreConnection> {
        self.inner.conn.lock().await
    }

    pub(crate) async fn wait_for_pending_changes(&self) -> Result<()> {
        let (send, recv) = oneshot::channel();
        self.changes_tx
            .send((
                NamespaceName::default(),
                None,
                send,
                false,
                Arc::new(AtomicBool::new(true)),
            ))
            .await
            .map_err(|e| Error::MetaStoreUpdateFailure(e.into()))?;
        recv.await
            .map_err(|e| Error::MetaStoreUpdateFailure(e.into()))??;
        Ok(())
    }

    pub fn remove(&self, namespace: NamespaceName) -> Result<Option<Arc<DatabaseConfig>>> {
        self.remove_if_generation(namespace, None)
    }

    // For deferred destroy, an older worker may never remove a later
    // incarnation. The comparison and revocation happen under the DB lock.
    pub(crate) fn remove_if_generation(
        &self,
        namespace: NamespaceName,
        expected: Option<&Arc<AtomicBool>>,
    ) -> Result<Option<Arc<DatabaseConfig>>> {
        tracing::debug!("removing namespace `{}` from meta store", namespace);

        // "configs" lock can be used in both async and sync contexts while "conn" lock always used
        // in blocking context
        //
        // so, we better to acquire "conn" lock first in order to prevent situation when "configs"
        // lock is taken but "conn" lock is not free (so, we potentially will block async tasks for
        // indefinite amount of time while "conn" lock will be acquired by other thread)
        let mut conn = self.inner.conn.blocking_lock();

        let mut configs = self.inner.configs.blocking_lock();
        if let Some(expected) = expected {
            let generations = self.inner.generations.lock();
            if !expected.load(Ordering::Acquire)
                || !generations
                    .get(&namespace)
                    .is_some_and(|current| Arc::ptr_eq(current, expected))
            {
                return Err(Error::NamespaceDoesntExist(namespace.to_string()));
            }
        }
        let r = if let Some(sender) = configs.get(&namespace) {
            tracing::debug!("removed namespace `{}` from meta store", namespace);
            let config = sender.borrow().clone();
            let tx = conn.transaction()?;
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
            // conn + configs are still held. A worker checking its token after
            // acquiring conn cannot insert the deleted row or update watches.
            if let Some(token) = self.inner.generations.lock().get(&namespace) {
                token.store(false, Ordering::Release);
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn stale_handle_cannot_recreate_config_or_schema_link_after_delete_or_recreate() {
        let tmp = tempdir().unwrap();
        let (maker, wal) = metastore_connection_maker(None, tmp.path()).await.unwrap();
        let metadata = MetaStore::new(
            MetaStoreConfig::default(),
            tmp.path(),
            maker().unwrap(),
            wal,
            DatabaseKind::Primary,
        )
        .await
        .unwrap();
        {
            // Only the jobs columns read by the shared-schema guard matter.
            let conn = maker().unwrap();
            conn.execute_batch("CREATE TABLE jobs (schema TEXT, finished BOOLEAN)")
                .unwrap();
        }
        let schema = NamespaceName::from("schema");
        metadata
            .handle(schema.clone())
            .await
            .store(DatabaseConfig::default())
            .await
            .unwrap();
        let tenant = NamespaceName::from("tenant");
        let old = metadata.handle(tenant.clone()).await;
        let mut linked = DatabaseConfig::default();
        linked.shared_schema_name = Some(schema);
        old.store(linked.clone()).await.unwrap();
        assert!(metadata.exists(&tenant).await);
        let removed = tokio::task::spawn_blocking({
            let metadata = metadata.clone();
            let tenant = tenant.clone();
            move || metadata.remove(tenant)
        })
        .await
        .unwrap()
        .unwrap();
        assert!(removed.is_some());
        assert!(!metadata.exists(&tenant).await);
        // Simulate a message already accepted into the worker queue before
        // deletion: the handle's early check cannot protect this path.
        let stale_generation = match &old.inner {
            HandleState::External(_, _, generation) => generation.clone(),
            HandleState::Internal(_) => unreachable!(),
        };
        let stale_name = tenant.clone();
        let stale_inner = metadata.inner.clone();
        let (send, receive) = oneshot::channel();
        tokio::task::spawn_blocking(move || {
            process(
                (
                    stale_name,
                    Some(Arc::new(DatabaseConfig::default())),
                    send,
                    true,
                    stale_generation,
                ),
                stale_inner,
            );
        })
        .await
        .unwrap();
        assert!(matches!(
            receive.await.unwrap(),
            Err(Error::NamespaceDoesntExist(_))
        ));
        assert!(!metadata.exists(&tenant).await);
        assert!(matches!(
            old.store(linked.clone()).await,
            Err(Error::NamespaceDoesntExist(_))
        ));
        // A stale handle acquired anew after deletion remains tombstoned.
        assert!(matches!(
            metadata.handle(tenant.clone()).await.store(linked).await,
            Err(Error::NamespaceDoesntExist(_))
        ));
        metadata.activate_for_create(&tenant);
        let fresh = metadata.handle(tenant.clone()).await;
        fresh.store(DatabaseConfig::default()).await.unwrap();
        assert!(matches!(
            old.store(DatabaseConfig::default()).await,
            Err(Error::NamespaceDoesntExist(_))
        ));
        let conn = maker().unwrap();
        let rows: i64 = conn
            .query_row(
                "SELECT count(*) FROM namespace_configs WHERE namespace = 'tenant'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let links: i64 = conn
            .query_row(
                "SELECT count(*) FROM shared_schema_links WHERE namespace = 'tenant'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rows, 1);
        assert_eq!(links, 0);
    }

    #[tokio::test]
    async fn invalid_shared_schema_refuses_startup_without_destroying_metastore() {
        let tmp = tempdir().unwrap();
        let namespace_dir = tmp.path().join("dbs/tenant");
        std::fs::create_dir_all(&namespace_dir).unwrap();
        std::fs::write(namespace_dir.join("sentinel"), b"namespace intact").unwrap();
        let (maker, wal) = metastore_connection_maker(None, tmp.path()).await.unwrap();
        let metastore_sentinel = tmp.path().join("metastore/sentinel");
        let invalid = metadata::DatabaseConfig {
            shared_schema_name: Some("../schema".into()),
            ..metadata::DatabaseConfig::from(&DatabaseConfig::default())
        }
        .encode_to_vec();
        {
            let conn = maker().unwrap();
            setup_connection(&conn).unwrap();
            std::fs::write(&metastore_sentinel, b"metastore intact").unwrap();
            let schema = metadata::DatabaseConfig::from(&DatabaseConfig::default()).encode_to_vec();
            conn.execute(
                "INSERT INTO namespace_configs VALUES (?1, ?2)",
                rusqlite::params!["schema", schema],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO namespace_configs VALUES (?1, ?2)",
                rusqlite::params!["tenant", invalid.clone()],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO shared_schema_links VALUES ('schema', 'tenant')",
                [],
            )
            .unwrap();
        }
        let config = MetaStoreConfig {
            destroy_on_error: true,
            ..Default::default()
        };
        let err = match MetaStore::new(
            config.clone(),
            tmp.path(),
            maker().unwrap(),
            wal.clone(),
            DatabaseKind::Primary,
        )
        .await
        {
            Ok(_) => panic!("invalid persisted config should fail startup"),
            Err(e) => e,
        };
        assert!(
            matches!(err, Error::InvalidPersistedNamespaceConfig { namespace, .. } if namespace == "tenant")
        );
        assert_eq!(
            std::fs::read(&metastore_sentinel).unwrap(),
            b"metastore intact"
        );
        assert_eq!(
            std::fs::read(namespace_dir.join("sentinel")).unwrap(),
            b"namespace intact"
        );
        {
            let conn = maker().unwrap();
            let stored: Vec<u8> = conn
                .query_row(
                    "SELECT config FROM namespace_configs WHERE namespace = 'tenant'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(stored, invalid);
            let links: i64 = conn
                .query_row(
                    "SELECT count(*) FROM shared_schema_links WHERE shared_schema_name = 'schema' AND namespace = 'tenant'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(links, 1);
            let repaired = metadata::DatabaseConfig {
                shared_schema_name: Some("schema".into()),
                ..metadata::DatabaseConfig::from(&DatabaseConfig::default())
            }
            .encode_to_vec();
            conn.execute(
                "UPDATE namespace_configs SET config = ?1 WHERE namespace = 'tenant'",
                [repaired],
            )
            .unwrap();
        }
        let store = MetaStore::new(
            config,
            tmp.path(),
            maker().unwrap(),
            wal,
            DatabaseKind::Primary,
        )
        .await
        .unwrap();
        assert_eq!(
            store
                .handle(NamespaceName::from("tenant"))
                .await
                .get()
                .shared_schema_name
                .as_ref()
                .unwrap()
                .as_str(),
            "schema"
        );
    }

    #[tokio::test]
    async fn invalid_persisted_name_refuses_startup_without_erasing_other_rows() {
        let tmp = tempdir().unwrap();
        let (maker, wal) = metastore_connection_maker(None, tmp.path()).await.unwrap();
        let metastore_sentinel = tmp.path().join("metastore/sentinel");
        {
            let conn = maker().unwrap();
            setup_connection(&conn).unwrap();
            std::fs::write(&metastore_sentinel, b"keep").unwrap();
            let valid = metadata::DatabaseConfig::from(&DatabaseConfig::default()).encode_to_vec();
            conn.execute(
                "INSERT INTO namespace_configs VALUES (?1, ?2)",
                rusqlite::params!["valid", valid.clone()],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO namespace_configs VALUES (?1, ?2)",
                rusqlite::params!["../bad", valid],
            )
            .unwrap();
        }
        let config = MetaStoreConfig {
            destroy_on_error: true,
            ..Default::default()
        };
        let err = match MetaStore::new(
            config.clone(),
            tmp.path(),
            maker().unwrap(),
            wal.clone(),
            DatabaseKind::Primary,
        )
        .await
        {
            Ok(_) => panic!("invalid persisted name should fail startup"),
            Err(e) => e,
        };
        assert!(
            matches!(err, Error::InvalidPersistedNamespaceConfig { namespace, .. } if namespace == "../bad")
        );
        assert_eq!(std::fs::read(&metastore_sentinel).unwrap(), b"keep");
        {
            let conn = maker().unwrap();
            let count: i64 = conn
                .query_row("SELECT count(*) FROM namespace_configs", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 2);
            conn.execute(
                "UPDATE namespace_configs SET namespace = 'repaired' WHERE namespace = '../bad'",
                [],
            )
            .unwrap();
        }
        let store = MetaStore::new(
            config,
            tmp.path(),
            maker().unwrap(),
            wal,
            DatabaseKind::Primary,
        )
        .await
        .unwrap();
        assert!(store.exists(&NamespaceName::from("valid")).await);
        assert!(store.exists(&NamespaceName::from("repaired")).await);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fs_recovery_skips_invalid_names_without_deleting_dirs() {
        let tmp = tempdir().unwrap();
        let dbs = tmp.path().join("dbs");
        std::fs::create_dir_all(dbs.join("valid")).unwrap();
        std::fs::create_dir_all(dbs.join("bad\\name")).unwrap();
        std::fs::write(dbs.join("bad\\name/sentinel"), b"keep").unwrap();
        let outside = tmp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("sentinel"), b"outside intact").unwrap();
        std::os::unix::fs::symlink(&outside, dbs.join("alias")).unwrap();
        let (maker, wal) = metastore_connection_maker(None, tmp.path()).await.unwrap();
        let config = MetaStoreConfig {
            allow_recover_from_fs: true,
            destroy_on_error: true,
            ..Default::default()
        };
        let store = MetaStore::new(
            config,
            tmp.path(),
            maker().unwrap(),
            wal,
            DatabaseKind::Primary,
        )
        .await
        .unwrap();
        assert!(store.exists(&NamespaceName::from("valid")).await);
        assert_eq!(
            std::fs::read(dbs.join("bad\\name/sentinel")).unwrap(),
            b"keep"
        );
        assert!(!store.exists(&NamespaceName::from("alias")).await);
        assert_eq!(
            std::fs::read(outside.join("sentinel")).unwrap(),
            b"outside intact"
        );
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
                DatabaseConfig::try_from(&c)?
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => DatabaseConfig::default(),
            Err(err) => return Err(Error::IOError(err)),
        };

        Ok(Self {
            namespace: NamespaceName::from("testmetastore"),
            inner: HandleState::Internal(Arc::new(Mutex::new(Arc::new(config)))),
        })
    }

    pub fn internal() -> Self {
        MetaStoreHandle {
            namespace: NamespaceName::from("testmetastore"),
            inner: HandleState::Internal(Arc::new(Mutex::new(Arc::new(DatabaseConfig::default())))),
        }
    }

    pub fn get(&self) -> Arc<DatabaseConfig> {
        match &self.inner {
            HandleState::Internal(config) => config.lock().clone(),
            HandleState::External(_, config, _) => config.borrow().clone().config,
        }
    }

    pub fn version(&self) -> usize {
        match &self.inner {
            HandleState::Internal(_) => 0,
            HandleState::External(_, config, _) => config.borrow().version,
        }
    }

    pub fn changed(&self) -> impl Future<Output = ()> {
        let mut rcv = match &self.inner {
            HandleState::Internal(_) => panic!("can't wait for change on internal handle"),
            HandleState::External(_, rcv, _) => rcv.clone(),
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
            HandleState::External(changes_tx, config, generation) => {
                if !generation.load(Ordering::Acquire) {
                    return Err(Error::NamespaceDoesntExist(self.namespace.to_string()));
                }
                tracing::debug!(?new_config, "storing new namespace config");
                let mut c = config.clone();
                // ack the current value.
                c.borrow_and_update();
                let changed = c.changed();
                let wait_for_change = new_config.is_some();

                let (snd, rcv) = oneshot::channel();
                changes_tx
                    .send((
                        self.namespace.clone(),
                        new_config,
                        snd,
                        flush,
                        generation.clone(),
                    ))
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
