use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_lock::RwLock;
use chrono::NaiveDateTime;
use futures::TryFutureExt;
use moka::future::Cache;
use moka::ops::compute::{CompResult, Op};
use once_cell::sync::OnceCell;
use tokio::task::JoinSet;
use tokio::time::{Duration, Instant};
use tokio_stream::wrappers::BroadcastStream;

use crate::auth::Authenticated;
use crate::broadcaster::BroadcastMsg;
use crate::connection::config::DatabaseConfig;
use crate::database::DatabaseKind;
use crate::error::Error;
use crate::metrics::{
    NAMESPACE_EMPTIED_ENTRY, NAMESPACE_EMPTIED_ENTRY_GAVE_UP, NAMESPACE_LEFT_EMPTY_ENTRY_DROPPED,
    NAMESPACE_LOAD_LATENCY,
};
use crate::namespace::{NamespaceBottomlessDbId, NamespaceBottomlessDbIdInit, NamespaceName};
use crate::stats::Stats;

use super::broadcasters::{BroadcasterHandle, BroadcasterRegistry};
use super::configurator::{DynConfigurator, NamespaceConfigurators};
use super::meta_store::{MetaStore, MetaStoreHandle};
use super::schema_lock::SchemaLocksRegistry;
use super::{Namespace, ResetCb, ResetOp, ResolveNamespacePathFn, RestoreOption};

type NamespaceEntry = Arc<RwLock<Option<Namespace>>>;

/// How many times `with` looks up a namespace whose cache entry was emptied
/// under it (by shutdown, eviction or destroy) before giving up. Dropping an
/// entry that was left empty is not a lookup and does not count.
const MAX_EMPTIED_ENTRY_ATTEMPTS: usize = 3;

/// Stores and manage a set of namespaces.
pub struct NamespaceStore {
    pub inner: Arc<NamespaceStoreInner>,
}

impl Clone for NamespaceStore {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

pub struct NamespaceStoreInner {
    store: Cache<NamespaceName, NamespaceEntry>,
    metadata: MetaStore,
    allow_lazy_creation: bool,
    has_shutdown: AtomicBool,
    snapshot_at_shutdown: bool,
    schema_locks: SchemaLocksRegistry,
    broadcasters: BroadcasterRegistry,
    configurators: NamespaceConfigurators,
    db_kind: DatabaseKind,
}

impl NamespaceStore {
    pub(crate) async fn new(
        allow_lazy_creation: bool,
        snapshot_at_shutdown: bool,
        max_active_namespaces: usize,
        metadata: MetaStore,
        configurators: NamespaceConfigurators,
        db_kind: DatabaseKind,
    ) -> crate::Result<Self> {
        tracing::trace!("Max active namespaces: {max_active_namespaces}");
        let store = Cache::<NamespaceName, NamespaceEntry>::builder()
            .async_eviction_listener(move |name, ns, cause| {
                tracing::debug!("evicting namespace `{name}` asynchronously: {cause:?}");
                // TODO(sarna): not clear if we should snapshot-on-evict...
                // On the one hand, better to do so, because we have no idea
                // for how long we're evicting a namespace.
                // On the other, if there's lots of cache pressure, snapshotting
                // very often will kill the machine's I/O.
                Box::pin(async move {
                    // shutdown namespace
                    if let Some(ns) = ns.write().await.take() {
                        tracing::info!("namespace `{name}` deallocated");
                        if let Err(e) = ns.shutdown(snapshot_at_shutdown).await {
                            tracing::error!("error deallocating `{name}`: {e}")
                        }
                    }
                })
            })
            .max_capacity(max_active_namespaces as u64)
            .time_to_idle(Duration::from_secs(86400))
            .build();

        Ok(Self {
            inner: Arc::new(NamespaceStoreInner {
                store,
                metadata,
                allow_lazy_creation,
                has_shutdown: AtomicBool::new(false),
                snapshot_at_shutdown,
                schema_locks: Default::default(),
                broadcasters: Default::default(),
                configurators,
                db_kind,
            }),
        })
    }

    pub async fn exists(&self, namespace: &NamespaceName) -> bool {
        self.inner.metadata.exists(namespace).await
    }

    pub async fn destroy(&self, namespace: NamespaceName, prune_all: bool) -> crate::Result<()> {
        if self.inner.has_shutdown.load(Ordering::Relaxed) {
            return Err(Error::NamespaceStoreShutdown);
        }

        // destroy on-disk database and backups
        let db_config = tokio::task::spawn_blocking({
            let inner = self.inner.clone();
            let namespace = namespace.clone();
            move || {
                inner
                    .metadata
                    .remove(namespace.clone())?
                    .ok_or_else(|| crate::Error::NamespaceDoesntExist(namespace.to_string()))
            }
        })
        .await??;

        let mut bottomless_db_id_init = NamespaceBottomlessDbIdInit::FetchFromConfig;
        if let Some(ns) = self.inner.store.remove(&namespace).await {
            // deallocate in-memory resources
            if let Some(ns) = ns.write().await.take() {
                bottomless_db_id_init = NamespaceBottomlessDbIdInit::Provided(
                    NamespaceBottomlessDbId::from_config(&ns.db_config_store.get()),
                );
                ns.destroy().await?;
            }
        }

        self.cleanup(&namespace, &db_config, prune_all, bottomless_db_id_init)
            .await?;

        tracing::info!("destroyed namespace: {namespace}");

        Ok(())
    }

    pub async fn checkpoint(&self, namespace: NamespaceName) -> crate::Result<()> {
        // Only a loaded namespace has anything to checkpoint. Inserting an empty
        // entry for one that is not loaded would leave it cached empty.
        let Some(entry) = self.inner.store.get(&namespace).await else {
            return Ok(());
        };
        let lock = entry.read().await;
        if let Some(ns) = &*lock {
            ns.checkpoint().await?;
        }
        Ok(())
    }

    pub async fn reset(
        &self,
        namespace: NamespaceName,
        restore_option: RestoreOption,
    ) -> anyhow::Result<()> {
        if self.inner.has_shutdown.load(Ordering::Relaxed) {
            return Err(Error::NamespaceStoreShutdown.into());
        }

        // The process for reseting is as follow:
        // - get a lock on the namespace entry, if the entry exists, then it's a lock on the entry,
        // if it doesn't exist, insert an empty entry and take a lock on it
        // - destroy the old namespace
        // - create a new namespace and insert it in the held lock
        let entry = self
            .inner
            .store
            .get_with(namespace.clone(), async { Default::default() })
            .await;
        // This write lock is held across `make_namespace` below. Do not add a
        // cache call while it is held: moka runs its maintenance inline in
        // cache calls and awaits the eviction listener, which waits for this
        // lock. The same holds for `fork`'s `to_lock`. One such call predates
        // this comment: on a replica, a namespace with a shared schema loads
        // its schema through `with` during the replication handshake.
        let mut lock = entry.write().await;
        if let Some(ns) = lock.take() {
            ns.destroy().await?;
        }

        let db_config = self.inner.metadata.handle(namespace.clone()).await;
        // destroy on-disk database
        self.cleanup(
            &namespace,
            &db_config.get(),
            false,
            NamespaceBottomlessDbIdInit::FetchFromConfig,
        )
        .await?;
        let ns = self
            .make_namespace(&namespace, db_config, restore_option)
            .await?;

        lock.replace(ns);

        Ok(())
    }

    // This is only called on replica
    fn make_reset_cb(&self) -> ResetCb {
        let this = self.clone();
        Box::new(move |op| {
            let this = this.clone();
            tokio::spawn(async move {
                match op {
                    ResetOp::Reset(ns) => {
                        tracing::info!("received reset signal for: {ns}");
                        if let Err(e) = this.reset(ns.clone(), RestoreOption::Latest).await {
                            tracing::error!("error resetting namespace `{ns}`: {e}");
                        }
                    }
                }
            });
        })
    }

    pub async fn fork(
        &self,
        from: NamespaceName,
        to: NamespaceName,
        to_config: DatabaseConfig,
        timestamp: Option<NaiveDateTime>,
    ) -> crate::Result<()> {
        if self.inner.has_shutdown.load(Ordering::Relaxed) {
            return Err(Error::NamespaceStoreShutdown);
        }

        // check that the source namespace exists
        if !self.inner.metadata.exists(&from).await {
            return Err(crate::error::Error::NamespaceDoesntExist(from.to_string()));
        }
        // Load the source as `with` does, so a source whose cache entry was
        // emptied (by eviction, or left empty) is reloaded rather than failing
        // the fork, and its errors are the same as `with`'s.
        self.with(from.clone(), |_| ()).await?;

        let to_entry = self
            .inner
            .store
            .get_with(to.clone(), async { Default::default() })
            .await;
        let mut to_lock = to_entry.write().await;
        if to_lock.is_some() {
            return Err(crate::error::Error::NamespaceAlreadyExist(to.to_string()));
        }

        // FIXME: we could potentially delete the namespace while trying to fork it
        if !self.inner.metadata.exists(&from).await {
            return Err(crate::Error::NamespaceDoesntExist(from.to_string()));
        }

        let from_config = self.inner.metadata.handle(from.clone()).await;
        // Known hazard: `to_lock` is held across this cache call. moka runs its
        // maintenance inline in cache calls and awaits the eviction listener,
        // which waits for the evicted entry's write lock. If the cache is at
        // capacity and picks the fresh, empty `to_entry` as its victim, the
        // listener waits for the lock this task holds. The `with` above makes
        // this a cache hit in the normal case, which lowers the exposure
        // without removing it. Fixing it means reserving `to` outside the
        // cache; see the follow-ups in PR #56.
        let from_entry = self
            .load_namespace(&from, from_config.clone(), RestoreOption::Latest)
            .await?;
        let from_lock = from_entry.read().await;
        let Some(from_ns) = &*from_lock else {
            return Err(self.emptied_entry_error(&from).await);
        };

        struct Bomb {
            store: MetaStore,
            ns: NamespaceName,
            should_delete: bool,
        }

        impl Drop for Bomb {
            fn drop(&mut self) {
                if self.should_delete {
                    // we need to block in place because the inner connection may blocking, or
                    // unsing tokio's blocking methods (bottomless), which would cause a panic.
                    if let Err(e) =
                        tokio::task::block_in_place(|| self.store.remove(self.ns.clone()))
                    {
                        tracing::error!("failed to clean handle while forking: {e}");
                    }
                }
            }
        }

        let mut bomb = Bomb {
            store: self.inner.metadata.clone(),
            ns: to.clone(),
            should_delete: true,
        };

        let handle = self.inner.metadata.handle(to.clone()).await;
        handle
            .store_and_maybe_flush(Some(to_config.into()), false)
            .await?;
        let to_ns = self
            .get_configurator(&from_config.get())
            .fork(
                from_ns,
                from_config,
                to.clone(),
                handle.clone(),
                timestamp,
                self.clone(),
            )
            .await?;

        to_lock.replace(to_ns);
        handle.flush().await?;
        // defuse
        bomb.should_delete = false;

        Ok(())
    }

    pub async fn with_authenticated<Fun, R>(
        &self,
        namespace: NamespaceName,
        auth: Authenticated,
        f: Fun,
    ) -> crate::Result<R>
    where
        Fun: FnOnce(&Namespace) -> R + 'static,
    {
        if self.inner.has_shutdown.load(Ordering::Relaxed) {
            return Err(Error::NamespaceStoreShutdown);
        }
        if !auth.is_namespace_authorized(&namespace) {
            return Err(Error::NamespaceDoesntExist(namespace.to_string()));
        }

        self.with(namespace, f).await
    }

    pub async fn with<Fun, R>(&self, namespace: NamespaceName, f: Fun) -> crate::Result<R>
    where
        Fun: FnOnce(&Namespace) -> R,
    {
        for _ in 0..MAX_EMPTIED_ENTRY_ATTEMPTS {
            if self.inner.has_shutdown.load(Ordering::Relaxed) {
                return Err(Error::NamespaceStoreShutdown);
            }
            if namespace != NamespaceName::default()
                && !self.inner.metadata.exists(&namespace).await
                && !self.inner.allow_lazy_creation
            {
                return Err(Error::NamespaceDoesntExist(namespace.to_string()));
            }

            let handle = self.inner.metadata.handle(namespace.to_owned()).await;
            let entry = self
                .load_namespace(&namespace, handle, RestoreOption::Latest)
                .await?;
            {
                let lock = entry.read().await;
                if let Some(ns) = &*lock {
                    return Ok(f(ns));
                }
            }

            // The namespace was taken out of the entry after we got it: by
            // shutdown, by cache eviction, or by a concurrent destroy. That
            // does not mean it is missing, so look it up again. Expected
            // during a rolling restart and under cache pressure, once per
            // waiting request: the counter is the signal, not the log.
            NAMESPACE_EMPTIED_ENTRY.increment(1);
            tracing::debug!(%namespace, "namespace cache entry was emptied while in use, looking it up again");
            if self.inner.has_shutdown.load(Ordering::Relaxed) {
                return Err(Error::NamespaceStoreShutdown);
            }
            // If the emptied entry is still the cached one, nothing is going
            // to refill it (a fork that failed before storing its record
            // leaves one behind): drop it, so that the next lookup loads the
            // namespace. An evicted or destroyed entry is no longer cached,
            // and this does nothing.
            self.evict_if_still_empty(&namespace, &entry).await;
        }

        let error = self.emptied_entry_error(&namespace).await;
        if matches!(error, Error::NamespaceUnavailable(_)) {
            // Shutdown and a namespace that is really gone are not failures
            // of the store, so the counter only records this outcome.
            NAMESPACE_EMPTIED_ENTRY_GAVE_UP.increment(1);
        }
        tracing::warn!(%namespace, %error, "namespace cache entry kept being emptied, giving up");
        Err(error)
    }

    /// Removes `entry` from the cache if it is still the cached entry for
    /// `namespace` and still empty, so that the next lookup loads the namespace
    /// afresh (with its own restore option). It never fills an entry itself.
    ///
    /// What the checks guarantee, under moka's per-key compute lock: a loaded
    /// entry is never removed, and neither is an entry whose lock is held at
    /// that moment. What they do not: `try_read` cannot see a `fork` or `reset`
    /// that holds the entry but has not locked it yet. That window is not a
    /// few instructions: `get_with` makes the entry visible and may then run
    /// the cache's housekeeping, awaiting eviction listeners, before it
    /// returns. A `fork` or `reset` whose fresh entry is dropped in that window
    /// fills an entry the cache no longer holds, which nothing shuts down.
    /// `Op::Remove` also removes whatever the cache holds when it runs, which
    /// moka does not tie to the entry the closure saw; that case is detected
    /// below. Closing both needs the entry state to live in the cache value
    /// rather than behind the lock.
    async fn evict_if_still_empty(&self, namespace: &NamespaceName, entry: &NamespaceEntry) {
        let result = self
            .inner
            .store
            .entry_by_ref(namespace)
            .and_compute_with(|cached| {
                let still_empty = cached.is_some_and(|cached| {
                    Arc::ptr_eq(cached.value(), entry)
                        && entry.try_read().is_some_and(|lock| lock.is_none())
                });
                std::future::ready(if still_empty { Op::Remove } else { Op::Nop })
            })
            .await;
        if let CompResult::Removed(removed) = result {
            if Arc::ptr_eq(removed.value(), entry) {
                tracing::warn!(%namespace, "namespace cache entry was left empty, dropped it");
                NAMESPACE_LEFT_EMPTY_ENTRY_DROPPED.increment(1);
            } else {
                tracing::error!(%namespace, "dropped a different cache entry than the empty one");
            }
        }
    }

    /// The error for a namespace whose cache entry was emptied while it was
    /// being used. `NamespaceDoesntExist` only when the metastore agrees: a
    /// client must be able to trust it, and a namespace that still exists but
    /// cannot be served right now is a temporary condition, not a missing one.
    async fn emptied_entry_error(&self, namespace: &NamespaceName) -> Error {
        if self.inner.has_shutdown.load(Ordering::Relaxed) {
            Error::NamespaceStoreShutdown
        } else if !self.inner.metadata.exists(namespace).await {
            Error::NamespaceDoesntExist(namespace.to_string())
        } else {
            Error::NamespaceUnavailable(namespace.to_string())
        }
    }

    fn resolve_attach_fn(&self) -> ResolveNamespacePathFn {
        static FN: OnceCell<ResolveNamespacePathFn> = OnceCell::new();
        FN.get_or_init(|| {
            Arc::new({
                let store = self.clone();
                move |ns: &NamespaceName| {
                    tokio::runtime::Handle::current()
                        .block_on(store.with(ns.clone(), |ns| ns.path.clone()))
                }
            })
        })
        .clone()
    }

    pub(crate) async fn make_namespace(
        &self,
        namespace: &NamespaceName,
        config: MetaStoreHandle,
        restore_option: RestoreOption,
    ) -> crate::Result<Namespace> {
        let ns = self
            .get_configurator(&config.get())
            .setup(
                config,
                restore_option,
                namespace,
                self.make_reset_cb(),
                self.resolve_attach_fn(),
                self.clone(),
                self.broadcaster(namespace.clone()),
            )
            .await?;

        Ok(ns)
    }

    async fn load_namespace(
        &self,
        namespace: &NamespaceName,
        db_config: MetaStoreHandle,
        restore_option: RestoreOption,
    ) -> crate::Result<NamespaceEntry> {
        let init = async {
            // Shutdown may have started since the caller checked. A namespace
            // opened now would not be in the entries shutdown takes out, so
            // nobody would ever shut it down.
            if self.inner.has_shutdown.load(Ordering::Relaxed) {
                return Err(Error::NamespaceStoreShutdown);
            }
            let ns = self
                .make_namespace(namespace, db_config, restore_option)
                .await?;
            Ok(Some(ns))
        };

        let before_load = Instant::now();
        let ns = self
            .inner
            .store
            .try_get_with(
                namespace.clone(),
                init.map_ok(|ns| Arc::new(RwLock::new(ns))),
            )
            .await?;
        NAMESPACE_LOAD_LATENCY.record(before_load.elapsed());

        Ok(ns)
    }

    #[tracing::instrument(skip_all, fields(namespace))]
    pub async fn create(
        &self,
        namespace: NamespaceName,
        restore_option: RestoreOption,
        db_config: DatabaseConfig,
    ) -> crate::Result<()> {
        if self.inner.has_shutdown.load(Ordering::Relaxed) {
            return Err(Error::NamespaceStoreShutdown);
        }

        if let Some(shared_schema_name) = &db_config.shared_schema_name {
            // we hold a lock for the duration of the namespace creation
            let _lock = self
                .inner
                .schema_locks
                .acquire_shared(shared_schema_name.clone())
                .await;
            return self
                .fork(shared_schema_name.clone(), namespace, db_config, None)
                .await;
        };

        // With namespaces disabled, the default namespace can be auto-created,
        // otherwise it's an error.
        // FIXME: move the default namespace check out of this function.
        if self.inner.allow_lazy_creation || namespace == NamespaceName::default() {
            tracing::trace!("auto-creating the namespace");
        } else if self.inner.metadata.exists(&namespace).await {
            return Err(Error::NamespaceAlreadyExist(namespace.to_string()));
        }

        let db_config = Arc::new(db_config);
        let handle = self.inner.metadata.handle(namespace.clone()).await;
        tracing::debug!("storing db config");
        handle.store(db_config).await?;
        tracing::debug!("completed storing db config, loading namespace");
        // An empty entry left cached (for example by a fork that failed before
        // storing its record) would be returned as is, and the namespace would
        // not be loaded with `restore_option` (a dump, say).
        if let Some(entry) = self.inner.store.get(&namespace).await {
            self.evict_if_still_empty(&namespace, &entry).await;
        }
        self.load_created(&namespace, handle, restore_option)
            .await?;

        tracing::debug!("completed loading namespace");

        Ok(())
    }

    /// Loads the namespace whose record `create` has just stored. If shutdown
    /// started in between, `load_namespace` refuses before anything is opened
    /// or written, and the record is removed again. Left in place, it would
    /// make every retry answer "already exists" for a namespace that was never
    /// loaded, so its restore option would never be applied.
    async fn load_created(
        &self,
        namespace: &NamespaceName,
        handle: MetaStoreHandle,
        restore_option: RestoreOption,
    ) -> crate::Result<()> {
        let error = match self.load_namespace(namespace, handle, restore_option).await {
            Ok(_) => return Ok(()),
            Err(error) => error,
        };
        if matches!(error.as_ref(), Error::NamespaceStoreShutdown) {
            let removed = tokio::task::spawn_blocking({
                let metadata = self.inner.metadata.clone();
                let namespace = namespace.clone();
                move || metadata.remove(namespace)
            })
            .await;
            match removed {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => tracing::error!(
                    %namespace,
                    "failed to remove the record of a namespace whose creation shutdown interrupted: {e}"
                ),
                Err(e) => tracing::error!(
                    %namespace,
                    "failed to remove the record of a namespace whose creation shutdown interrupted: {e}"
                ),
            }
        }
        Err(error)
    }

    pub async fn shutdown(self) -> crate::Result<()> {
        let mut set = JoinSet::new();
        self.inner.has_shutdown.store(true, Ordering::Relaxed);

        for (_name, entry) in self.inner.store.iter() {
            let snapshow_at_shutdown = self.inner.snapshot_at_shutdown;
            let mut lock = entry.write().await;
            if let Some(ns) = lock.take() {
                set.spawn(async move {
                    ns.shutdown(snapshow_at_shutdown).await?;
                    Ok::<_, anyhow::Error>(())
                });
            }
        }

        while let Some(_) = set.join_next().await.transpose()?.transpose()? {}

        self.inner.metadata.shutdown().await?;
        self.inner.store.invalidate_all();
        self.inner.store.run_pending_tasks().await;
        Ok(())
    }

    pub(crate) async fn stats(&self, namespace: NamespaceName) -> crate::Result<Arc<Stats>> {
        self.with(namespace, |ns| ns.stats.clone()).await
    }

    pub(crate) fn broadcaster(&self, namespace: NamespaceName) -> BroadcasterHandle {
        self.inner.broadcasters.handle(namespace)
    }

    pub(crate) fn subscribe(
        &self,
        namespace: NamespaceName,
        table: String,
    ) -> BroadcastStream<BroadcastMsg> {
        self.inner.broadcasters.subscribe(namespace, table)
    }

    pub(crate) fn unsubscribe(&self, namespace: NamespaceName, table: &String) {
        self.inner.broadcasters.unsubscribe(namespace, table);
    }

    pub(crate) async fn config_store(
        &self,
        namespace: NamespaceName,
    ) -> crate::Result<MetaStoreHandle> {
        self.with(namespace, |ns| ns.db_config_store.clone()).await
    }

    pub(crate) fn meta_store(&self) -> &MetaStore {
        &self.inner.metadata
    }

    pub(crate) fn schema_locks(&self) -> &SchemaLocksRegistry {
        &self.inner.schema_locks
    }

    fn get_configurator(&self, db_config: &DatabaseConfig) -> &DynConfigurator {
        match self.inner.db_kind {
            DatabaseKind::Primary if db_config.is_shared_schema => {
                self.inner.configurators.configure_schema().unwrap()
            }
            DatabaseKind::Primary => self.inner.configurators.configure_primary().unwrap(),
            DatabaseKind::Replica => self.inner.configurators.configure_replica().unwrap(),
        }
    }

    async fn cleanup(
        &self,
        namespace: &NamespaceName,
        db_config: &DatabaseConfig,
        prune_all: bool,
        bottomless_db_id_init: NamespaceBottomlessDbIdInit,
    ) -> crate::Result<()> {
        self.get_configurator(db_config)
            .cleanup(namespace, db_config, prune_all, bottomless_db_id_init)
            .await
    }
}

#[cfg(test)]
pub(crate) mod test {
    use std::path::Path;

    use axum::response::IntoResponse;
    use hyper::StatusCode;
    use libsql_sys::wal::Sqlite3WalManager;
    use tempfile::tempdir;
    use tokio::sync::Semaphore;

    use super::*;
    use crate::namespace::configurator::{BaseNamespaceConfig, PrimaryConfig, PrimaryConfigurator};
    use crate::namespace::meta_store::metastore_connection_maker;

    pub(crate) async fn make_store(path: &Path) -> NamespaceStore {
        let (maker, manager) = metastore_connection_maker(None, path).await.unwrap();
        let meta_store = MetaStore::new(
            Default::default(),
            path,
            maker().unwrap(),
            manager,
            DatabaseKind::Primary,
        )
        .await
        .unwrap();
        let base_config = BaseNamespaceConfig {
            base_path: path.to_path_buf().into(),
            extensions: Arc::new([]),
            stats_sender: tokio::sync::mpsc::channel(1).0,
            max_response_size: 100_000_000,
            max_total_response_size: 100_000_000,
            max_concurrent_connections: Arc::new(Semaphore::new(10)),
            max_concurrent_requests: 10_000,
            encryption_config: None,
            connection_creation_timeout: None,
            disable_intelligent_throttling: false,
        };
        let primary_config = PrimaryConfig {
            max_log_size: 1_000_000_000,
            max_log_duration: None,
            bottomless_replication: None,
            scripted_backup: None,
            checkpoint_interval: None,
        };
        let mut configurators = NamespaceConfigurators::empty();
        configurators.with_primary(PrimaryConfigurator::new(
            base_config,
            primary_config,
            Arc::new(Sqlite3WalManager::default),
        ));

        NamespaceStore::new(
            false,
            false,
            10,
            meta_store,
            configurators,
            DatabaseKind::Primary,
        )
        .await
        .unwrap()
    }

    async fn create(store: &NamespaceStore, name: &str) -> NamespaceName {
        let namespace = NamespaceName::from_string(name.to_string()).unwrap();
        store
            .create(
                namespace.clone(),
                RestoreOption::Latest,
                DatabaseConfig::default(),
            )
            .await
            .unwrap();
        namespace
    }

    /// Starts `request` while the test holds `entry`'s write lock, and returns
    /// once the request holds the same entry and waits for the lock: the
    /// cache, the test and the request then share it.
    async fn start_waiting<Fut>(
        store: &NamespaceStore,
        entry: &NamespaceEntry,
        request: impl FnOnce(NamespaceStore) -> Fut,
    ) -> tokio::task::JoinHandle<Fut::Output>
    where
        Fut: std::future::Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        settle(store, entry).await;
        let request = tokio::spawn(request(store.clone()));
        wait_until("the request holds the entry", || {
            Arc::strong_count(entry) >= 3
        })
        .await;
        request
    }

    /// `start_waiting` for a `with` on `namespace`.
    async fn start_waiting_request(
        store: &NamespaceStore,
        namespace: &NamespaceName,
        entry: &NamespaceEntry,
    ) -> tokio::task::JoinHandle<crate::Result<NamespaceName>> {
        let namespace = namespace.clone();
        start_waiting(store, entry, move |store| async move {
            store.with(namespace, |ns| ns.name().clone()).await
        })
        .await
    }

    /// Lets the cache drop the extra reference it keeps to a fresh entry until
    /// its housekeeping runs, so that a third holder of `entry` can only be the
    /// request or fork under test.
    ///
    /// This and `start_waiting` count references: the cache holds one, the
    /// test one, and each waiting request one. That is how moka 0.12.8 (the
    /// version in Cargo.lock) behaves; a moka upgrade that keeps more
    /// references fails these tests with a timeout rather than hanging them.
    async fn settle(store: &NamespaceStore, entry: &NamespaceEntry) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while Arc::strong_count(entry) > 2 {
                store.inner.store.run_pending_tasks().await;
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("the cache keeps an extra reference to the entry");
        assert_eq!(Arc::strong_count(entry), 2);
    }

    /// Yields until `condition` holds; fails the test instead of hanging.
    async fn wait_until(what: &str, condition: impl Fn() -> bool) {
        wait_until_async(what, || std::future::ready(condition())).await
    }

    /// `wait_until` for a condition that is checked asynchronously.
    async fn wait_until_async<Fut: std::future::Future<Output = bool>>(
        what: &str,
        condition: impl Fn() -> Fut,
    ) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while !condition().await {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting until {what}"));
    }

    #[tokio::test]
    async fn with_after_shutdown_is_unavailable_not_missing() {
        let tmp = tempdir().unwrap();
        let store = make_store(tmp.path()).await;
        let namespace = create(&store, "ns").await;

        store.clone().shutdown().await.unwrap();

        let error = store.with(namespace, |_| ()).await.unwrap_err();
        assert!(matches!(error, Error::NamespaceStoreShutdown), "{error:?}");
    }

    #[tokio::test]
    async fn load_namespace_refuses_to_open_a_namespace_once_the_store_has_shut_down() {
        let tmp = tempdir().unwrap();
        let store = make_store(tmp.path()).await;
        let namespace = create(&store, "ns").await;
        // Not cached, so the load would open the namespace.
        store.inner.store.invalidate(&namespace).await;
        store.inner.has_shutdown.store(true, Ordering::Relaxed);

        let handle = store.inner.metadata.handle(namespace.clone()).await;
        let error = store
            .load_namespace(&namespace, handle, RestoreOption::Latest)
            .await
            .unwrap_err();

        assert!(
            matches!(error.as_ref(), Error::NamespaceStoreShutdown),
            "{error:?}"
        );
        assert!(!store.inner.store.contains_key(&namespace));
    }

    #[tokio::test]
    async fn reset_after_shutdown_is_refused() {
        let tmp = tempdir().unwrap();
        let store = make_store(tmp.path()).await;
        let namespace = create(&store, "ns").await;
        store.clone().shutdown().await.unwrap();

        let error = store
            .reset(namespace.clone(), RestoreOption::Latest)
            .await
            .unwrap_err();

        assert!(
            matches!(
                error.downcast_ref::<Error>(),
                Some(Error::NamespaceStoreShutdown)
            ),
            "{error:?}"
        );
        assert!(!store.inner.store.contains_key(&namespace));
    }

    #[tokio::test]
    async fn with_reloads_a_namespace_evicted_while_waiting_for_it() {
        let tmp = tempdir().unwrap();
        let store = make_store(tmp.path()).await;
        let namespace = create(&store, "ns").await;
        let entry = store.inner.store.get(&namespace).await.unwrap();
        let mut lock = entry.write().await;
        let request = start_waiting_request(&store, &namespace, &entry).await;

        // Evict the entry the request holds, as cache pressure or idleness
        // does. The eviction listener waits for the write lock this test
        // holds, so evict from another task and wait for the removal.
        let eviction = tokio::spawn({
            let store = store.clone();
            let namespace = namespace.clone();
            async move { store.inner.store.invalidate(&namespace).await }
        });
        wait_until("the entry is evicted", || {
            !store.inner.store.contains_key(&namespace)
        })
        .await;
        lock.take().unwrap().shutdown(false).await.unwrap();
        drop(lock);

        assert_eq!(request.await.unwrap().unwrap(), namespace);
        eviction.await.unwrap();
        // Reloaded into a fresh entry; the evicted one was not filled.
        let cached = store.inner.store.get(&namespace).await.unwrap();
        assert!(!Arc::ptr_eq(&cached, &entry));
        assert!(cached.read().await.is_some());
        assert!(entry.read().await.is_none());
    }

    #[tokio::test]
    async fn with_reports_missing_for_a_namespace_destroyed_while_waiting_for_it() {
        let tmp = tempdir().unwrap();
        let store = make_store(tmp.path()).await;
        let namespace = create(&store, "ns").await;
        let entry = store.inner.store.get(&namespace).await.unwrap();
        let mut lock = entry.write().await;
        let request = start_waiting_request(&store, &namespace, &entry).await;

        // `destroy` removes the metastore record first, then takes the
        // namespace out of its entry, for which it waits on the lock this
        // test holds. The request must answer "missing" because of the record.
        let destroy = tokio::spawn({
            let store = store.clone();
            let namespace = namespace.clone();
            async move { store.destroy(namespace, false).await }
        });
        wait_until_async("the record is removed", || async {
            !store.exists(&namespace).await
        })
        .await;
        // Take the namespace out as destroy would once it gets the lock, so
        // the request finds the entry empty whichever of the two wakes first.
        lock.take().unwrap().shutdown(false).await.unwrap();
        drop(lock);

        let error = request.await.unwrap().unwrap_err();
        assert!(matches!(error, Error::NamespaceDoesntExist(_)), "{error:?}");
        destroy.await.unwrap().unwrap();
        assert!(!store.inner.store.contains_key(&namespace));
    }

    #[tokio::test]
    async fn with_loads_a_namespace_whose_cached_entry_stays_empty() {
        let tmp = tempdir().unwrap();
        let store = make_store(tmp.path()).await;
        let namespace = create(&store, "ns").await;
        let entry = store.inner.store.get(&namespace).await.unwrap();
        let mut lock = entry.write().await;
        let request = start_waiting_request(&store, &namespace, &entry).await;

        // The namespace is taken out but its emptied entry stays cached, as an
        // entry left behind by a fork that failed before storing its record:
        // nothing else is going to refill it.
        lock.take().unwrap().shutdown(false).await.unwrap();
        drop(lock);

        assert_eq!(request.await.unwrap().unwrap(), namespace);
        // The empty entry was dropped and a fresh one loaded; it was not filled.
        let cached = store.inner.store.get(&namespace).await.unwrap();
        assert!(!Arc::ptr_eq(&cached, &entry));
        assert!(cached.read().await.is_some());
        assert!(entry.read().await.is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn requests_waiting_on_one_left_empty_entry_share_one_reloaded_namespace() {
        let tmp = tempdir().unwrap();
        let store = make_store(tmp.path()).await;
        let namespace = create(&store, "ns").await;
        let entry = store.inner.store.get(&namespace).await.unwrap();
        let mut lock = entry.write().await;
        settle(&store, &entry).await;
        const REQUESTS: usize = 8;
        let requests: Vec<_> = (0..REQUESTS)
            .map(|_| {
                tokio::spawn({
                    let store = store.clone();
                    let namespace = namespace.clone();
                    async move { store.with(namespace, |ns| ns.stats.clone()).await }
                })
            })
            .collect();
        wait_until("every request holds the entry", || {
            Arc::strong_count(&entry) >= 2 + REQUESTS
        })
        .await;

        // The namespace is taken out and its emptied entry stays cached: every
        // request finds it, and every one of them may try to drop it.
        lock.take().unwrap().shutdown(false).await.unwrap();
        drop(lock);

        let mut stats = Vec::with_capacity(REQUESTS);
        for request in requests {
            stats.push(request.await.unwrap().unwrap());
        }
        // One namespace, loaded once, into one fresh entry.
        let cached = store.inner.store.get(&namespace).await.unwrap();
        assert!(!Arc::ptr_eq(&cached, &entry));
        let loaded = cached.read().await.as_ref().unwrap().stats.clone();
        assert!(stats.iter().all(|stats| Arc::ptr_eq(stats, &loaded)));
        assert!(entry.read().await.is_none());
    }

    #[tokio::test]
    async fn evict_if_still_empty_drops_only_the_cached_unlocked_empty_entry() {
        let tmp = tempdir().unwrap();
        let store = make_store(tmp.path()).await;
        let namespace = create(&store, "ns").await;
        let cached = |store: &NamespaceStore| {
            let store = store.clone();
            let namespace = namespace.clone();
            async move { store.inner.store.get(&namespace).await }
        };

        // A loaded cached entry is not empty: it stays.
        let loaded = cached(&store).await.unwrap();
        store.evict_if_still_empty(&namespace, &loaded).await;
        assert!(Arc::ptr_eq(&cached(&store).await.unwrap(), &loaded));

        // An empty entry that is not the cached one leaves the cached empty
        // entry alone.
        let empty: NamespaceEntry = Default::default();
        store
            .inner
            .store
            .insert(namespace.clone(), empty.clone())
            .await;
        let other: NamespaceEntry = Default::default();
        store.evict_if_still_empty(&namespace, &other).await;
        assert!(Arc::ptr_eq(&cached(&store).await.unwrap(), &empty));

        // An empty cached entry whose lock is held (it may be being filled)
        // stays. Evicting it would wait for that lock, so bound the call.
        let lock = empty.write().await;
        tokio::time::timeout(
            Duration::from_secs(10),
            store.evict_if_still_empty(&namespace, &empty),
        )
        .await
        .expect("evicting a locked entry must not wait for its lock");
        assert!(Arc::ptr_eq(&cached(&store).await.unwrap(), &empty));
        drop(lock);

        // Once nobody holds it, the empty cached entry is dropped.
        store.evict_if_still_empty(&namespace, &empty).await;
        assert!(!store.inner.store.contains_key(&namespace));
    }

    #[tokio::test]
    async fn create_loads_a_namespace_over_an_empty_cached_entry() {
        let tmp = tempdir().unwrap();
        let store = make_store(tmp.path()).await;
        let namespace = NamespaceName::from_string("ns".to_string()).unwrap();
        // What a fork that failed before storing its record leaves behind.
        let empty: NamespaceEntry = Default::default();
        store
            .inner
            .store
            .insert(namespace.clone(), empty.clone())
            .await;

        store
            .create(
                namespace.clone(),
                RestoreOption::Latest,
                DatabaseConfig::default(),
            )
            .await
            .unwrap();

        // Loaded by create itself, with its restore option.
        let cached = store.inner.store.get(&namespace).await.unwrap();
        assert!(!Arc::ptr_eq(&cached, &empty));
        assert!(cached.read().await.is_some());
    }

    #[tokio::test]
    async fn create_removes_its_record_when_shutdown_starts_before_its_load() {
        let tmp = tempdir().unwrap();
        let store = make_store(tmp.path()).await;
        let namespace = NamespaceName::from_string("ns".to_string()).unwrap();

        // `create`'s steps up to its load, then shutdown starts: the only
        // place where a stored record has no loaded namespace behind it.
        assert!(!store.inner.metadata.exists(&namespace).await);
        let handle = store.inner.metadata.handle(namespace.clone()).await;
        handle
            .store(Arc::new(DatabaseConfig::default()))
            .await
            .unwrap();
        store.inner.has_shutdown.store(true, Ordering::Relaxed);

        let error = store
            .load_created(&namespace, handle, RestoreOption::Latest)
            .await
            .unwrap_err();
        assert!(
            matches!(error.as_ref(), Error::NamespaceStoreShutdown),
            "{error:?}"
        );
        assert!(!store.inner.metadata.exists(&namespace).await);

        // A retry against a fresh store on the same files creates the
        // namespace instead of answering "already exists".
        drop(store);
        let store = make_store(tmp.path()).await;
        store
            .create(
                namespace.clone(),
                RestoreOption::Latest,
                DatabaseConfig::default(),
            )
            .await
            .unwrap();
        assert!(store.inner.store.get(&namespace).await.is_some());
    }

    #[tokio::test]
    async fn create_after_shutdown_is_refused() {
        let tmp = tempdir().unwrap();
        let store = make_store(tmp.path()).await;
        store.clone().shutdown().await.unwrap();
        let namespace = NamespaceName::from_string("ns".to_string()).unwrap();

        let error = store
            .create(
                namespace.clone(),
                RestoreOption::Latest,
                DatabaseConfig::default(),
            )
            .await
            .unwrap_err();

        assert!(matches!(error, Error::NamespaceStoreShutdown), "{error:?}");
        assert!(!store.inner.metadata.exists(&namespace).await);
    }

    // `fork`'s cleanup on failure calls `block_in_place`, which panics on
    // the current-thread runtime and would hide the real error.
    #[tokio::test(flavor = "multi_thread")]
    async fn fork_loads_a_source_whose_cached_entry_was_left_empty() {
        let tmp = tempdir().unwrap();
        let store = make_store(tmp.path()).await;
        let from = create(&store, "from").await;
        let entry = store.inner.store.get(&from).await.unwrap();
        entry
            .write()
            .await
            .take()
            .unwrap()
            .shutdown(false)
            .await
            .unwrap();
        let to = NamespaceName::from_string("to".to_string()).unwrap();

        store
            .fork(from.clone(), to.clone(), DatabaseConfig::default(), None)
            .await
            .unwrap();

        assert_eq!(
            store
                .with(to.clone(), |ns| ns.name().clone())
                .await
                .unwrap(),
            to
        );
        // The source was reloaded into a fresh entry; the left-empty one was
        // not filled.
        let cached = store.inner.store.get(&from).await.unwrap();
        assert!(!Arc::ptr_eq(&cached, &entry));
        assert!(cached.read().await.is_some());
        assert!(entry.read().await.is_none());
    }

    #[tokio::test]
    async fn with_reports_shutdown_when_the_store_shuts_down_while_waiting() {
        let tmp = tempdir().unwrap();
        let store = make_store(tmp.path()).await;
        let namespace = create(&store, "ns").await;
        let entry = store.inner.store.get(&namespace).await.unwrap();
        let mut lock = entry.write().await;
        let request = start_waiting_request(&store, &namespace, &entry).await;

        // The rolling-restart case: shutdown starts while the request waits,
        // then takes the namespace out of the entry the request holds.
        let shutdown = tokio::spawn(store.clone().shutdown());
        wait_until("shutdown has started", || {
            store.inner.has_shutdown.load(Ordering::Relaxed)
        })
        .await;
        lock.take().unwrap().shutdown(false).await.unwrap();
        drop(lock);

        let error = request.await.unwrap().unwrap_err();
        assert!(matches!(error, Error::NamespaceStoreShutdown), "{error:?}");
        shutdown.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn checkpoint_does_not_cache_an_empty_entry_for_an_unloaded_namespace() {
        let tmp = tempdir().unwrap();
        let store = make_store(tmp.path()).await;
        let namespace = create(&store, "ns").await;
        store.inner.store.invalidate(&namespace).await;

        store.checkpoint(namespace.clone()).await.unwrap();

        assert!(!store.inner.store.contains_key(&namespace));
        assert_eq!(
            store
                .with(namespace.clone(), |ns| ns.name().clone())
                .await
                .unwrap(),
            namespace
        );
    }

    // `fork`'s cleanup on failure calls `block_in_place`, which panics on
    // the current-thread runtime and would hide the real error.
    #[tokio::test(flavor = "multi_thread")]
    async fn fork_reloads_a_source_emptied_while_waiting_for_it() {
        let tmp = tempdir().unwrap();
        let store = make_store(tmp.path()).await;
        let from = create(&store, "from").await;
        let to = NamespaceName::from_string("to".to_string()).unwrap();
        let entry = store.inner.store.get(&from).await.unwrap();
        let mut lock = entry.write().await;
        settle(&store, &entry).await;
        let fork = tokio::spawn({
            let store = store.clone();
            let (from, to) = (from.clone(), to.clone());
            async move { store.fork(from, to, DatabaseConfig::default(), None).await }
        });
        wait_until("the fork holds the source entry", || {
            Arc::strong_count(&entry) >= 3
        })
        .await;

        // Evict the source entry the fork holds, as cache pressure does: the
        // eviction listener waits for the write lock this test holds, so
        // evict from another task and wait for the removal.
        let eviction = tokio::spawn({
            let store = store.clone();
            let from = from.clone();
            async move { store.inner.store.invalidate(&from).await }
        });
        wait_until("the source entry is evicted", || {
            !store.inner.store.contains_key(&from)
        })
        .await;
        lock.take().unwrap().shutdown(false).await.unwrap();
        drop(lock);

        fork.await.unwrap().unwrap();
        eviction.await.unwrap();
        assert_eq!(
            store
                .with(to.clone(), |ns| ns.name().clone())
                .await
                .unwrap(),
            to
        );
        // The source was reloaded into a fresh entry; the emptied one was not
        // filled.
        let cached = store.inner.store.get(&from).await.unwrap();
        assert!(!Arc::ptr_eq(&cached, &entry));
        assert!(cached.read().await.is_some());
        assert!(entry.read().await.is_none());
    }

    // `fork`'s cleanup on failure calls `block_in_place`, which panics on
    // the current-thread runtime and would hide the real error.
    #[tokio::test(flavor = "multi_thread")]
    async fn fork_reports_unavailable_when_its_source_is_emptied_between_its_loads() {
        let tmp = tempdir().unwrap();
        let store = make_store(tmp.path()).await;
        let from = create(&store, "from").await;
        let to = NamespaceName::from_string("to".to_string()).unwrap();
        // Holding the destination entry's lock stops the fork after it loaded
        // its source through `with` and before it reads the source from its
        // own lookup.
        let to_entry: NamespaceEntry = Default::default();
        store.inner.store.insert(to.clone(), to_entry.clone()).await;
        let to_lock = to_entry.write().await;
        let fork = start_waiting(&store, &to_entry, {
            let (from, to) = (from.clone(), to.clone());
            move |store| async move { store.fork(from, to, DatabaseConfig::default(), None).await }
        })
        .await;

        // The source is taken out, and its emptied entry stays cached.
        let from_entry = store.inner.store.get(&from).await.unwrap();
        from_entry
            .write()
            .await
            .take()
            .unwrap()
            .shutdown(false)
            .await
            .unwrap();
        drop(to_lock);

        let error = fork.await.unwrap().unwrap_err();
        assert!(matches!(error, Error::NamespaceUnavailable(_)), "{error:?}");
    }

    #[tokio::test]
    async fn an_emptied_entry_is_missing_only_when_the_metastore_agrees() {
        let tmp = tempdir().unwrap();
        let store = make_store(tmp.path()).await;
        let namespace = create(&store, "ns").await;

        let error = store.emptied_entry_error(&namespace).await;
        assert!(matches!(error, Error::NamespaceUnavailable(_)), "{error:?}");

        tokio::task::spawn_blocking({
            let store = store.clone();
            let namespace = namespace.clone();
            move || store.inner.metadata.remove(namespace)
        })
        .await
        .unwrap()
        .unwrap();
        let error = store.emptied_entry_error(&namespace).await;
        assert!(matches!(error, Error::NamespaceDoesntExist(_)), "{error:?}");

        store.inner.has_shutdown.store(true, Ordering::Relaxed);
        let error = store.emptied_entry_error(&namespace).await;
        assert!(matches!(error, Error::NamespaceStoreShutdown), "{error:?}");
    }

    #[test]
    fn temporarily_unavailable_namespaces_answer_503() {
        for error in [
            Error::NamespaceStoreShutdown,
            Error::NamespaceUnavailable("ns".to_string()),
            // Wrapped by the cache, once or more.
            Error::Ref(Arc::new(Error::NamespaceStoreShutdown)),
            Error::Ref(Arc::new(Error::Ref(Arc::new(Error::NamespaceUnavailable(
                "ns".to_string(),
            ))))),
        ] {
            assert_eq!(
                error.into_response().status(),
                StatusCode::SERVICE_UNAVAILABLE
            );
        }
        assert_eq!(
            Error::NamespaceDoesntExist("ns".to_string())
                .into_response()
                .status(),
            StatusCode::NOT_FOUND
        );
    }
}
