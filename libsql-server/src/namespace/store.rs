use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_lock::{RwLock, RwLockWriteGuardArc};
use chrono::NaiveDateTime;
use futures::TryFutureExt;
use moka::future::Cache;
use once_cell::sync::OnceCell;
use tokio::task::JoinSet;
use tokio::time::{Duration, Instant};
use tokio_stream::wrappers::BroadcastStream;

use crate::auth::Authenticated;
use crate::broadcaster::BroadcastMsg;
use crate::connection::config::DatabaseConfig;
use crate::database::DatabaseKind;
use crate::error::Error;
use crate::metrics::NAMESPACE_LOAD_LATENCY;
use crate::namespace::{NamespaceBottomlessDbId, NamespaceBottomlessDbIdInit, NamespaceName};
use crate::stats::Stats;

use super::broadcasters::{BroadcasterHandle, BroadcasterRegistry};
use super::configurator::{DynConfigurator, NamespaceConfigurators};
use super::meta_store::{MetaStore, MetaStoreHandle};
use super::schema_lock::SchemaLocksRegistry;
use super::{Namespace, ResetCb, ResetOp, ResolveNamespacePathFn, RestoreOption};

type NamespaceEntry = Arc<RwLock<Option<Namespace>>>;

/// A namespace name reserved for a creation (or fork) in progress.
///
/// Holding a reservation holds the name's cache entry write-locked, so every other access to
/// the name — user requests, a second create, destroy, shutdown — waits until the outcome is
/// known. [`publish`](Self::publish) installs the finished namespace. Dropping the reservation
/// unpublished (error, or the creating request was cancelled) removes the namespace's in-memory
/// config and only then releases the lock, so waiters observe a namespace that does not exist,
/// never a half-built one.
///
/// The metastore row is only written after setup succeeds (see `create`), so the row's presence
/// implies a complete namespace. See `docs/ATOMIC_NAMESPACE_CREATE_DESIGN.md`.
struct Reservation {
    guard: Option<RwLockWriteGuardArc<Option<Namespace>>>,
    metadata: MetaStore,
    name: NamespaceName,
}

impl Reservation {
    /// Fails with `NamespaceAlreadyExist` if the namespace is loaded or known to the metastore.
    ///
    /// Must be called before `MetaStore::handle(name)`: `handle` inserts the name into the
    /// in-memory config map that `exists` reads, so the name becomes visible only while it is
    /// already locked here.
    async fn acquire(store: &NamespaceStore, name: NamespaceName) -> crate::Result<Self> {
        let entry = store
            .inner
            .store
            .get_with(name.clone(), async { Default::default() })
            .await;
        let guard = entry.write_arc().await;
        if guard.is_some() || store.inner.metadata.exists(&name).await {
            return Err(Error::NamespaceAlreadyExist(name.to_string()));
        }
        Ok(Self {
            guard: Some(guard),
            metadata: store.inner.metadata.clone(),
            name,
        })
    }

    /// Install the finished namespace and release the lock.
    fn publish(mut self, ns: Namespace) {
        self.guard
            .take()
            .expect("a reservation is published at most once")
            .replace(ns);
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let Some(guard) = self.guard.take() else {
            return;
        };
        tracing::warn!(
            namespace = %self.name,
            "namespace creation did not complete; discarding it"
        );
        metrics::increment_counter!("libsql_server_namespace_create_aborted");
        let metadata = self.metadata.clone();
        let name = self.name.clone();
        let cleanup = move || {
            // Removes the in-memory config and the metastore row, if any was written.
            if let Err(e) = metadata.remove(name.clone()) {
                tracing::error!(namespace = %name, "failed to discard namespace config: {e}");
            }
            // Release the lock only once the name no longer exists.
            drop(guard);
        };
        // `MetaStore::remove` takes blocking locks, and we may be running inside a future that
        // is being dropped: hand the work to the blocking pool instead of blocking in place.
        match tokio::runtime::Handle::try_current() {
            Ok(rt) => {
                rt.spawn_blocking(cleanup);
            }
            Err(_) => cleanup(),
        }
    }
}

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
                    tracing::info!("namespace `{name}` deallocated");
                    // shutdown namespace
                    if let Some(ns) = ns.write().await.take() {
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
        let entry = self
            .inner
            .store
            .get_with(namespace.clone(), async { Default::default() })
            .await;
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

        let reservation = Reservation::acquire(self, to.clone()).await?;

        // FIXME: we could potentially delete the namespace while trying to fork it
        if !self.inner.metadata.exists(&from).await {
            return Err(crate::Error::NamespaceDoesntExist(from.to_string()));
        }

        let from_config = self.inner.metadata.handle(from.clone()).await;
        let from_entry = self
            .load_namespace(&from, from_config.clone(), RestoreOption::Latest)
            .await?;
        let from_lock = from_entry.read().await;
        let Some(from_ns) = &*from_lock else {
            return Err(crate::error::Error::NamespaceDoesntExist(from.to_string()));
        };

        let handle = self.inner.metadata.handle(to.clone()).await;
        // In memory only: the fork reads it; nothing is persisted until it succeeded.
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

        handle.flush().await?;
        reservation.publish(to_ns);

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
        if namespace != NamespaceName::default()
            && !self.inner.metadata.exists(&namespace).await
            && !self.inner.allow_lazy_creation
        {
            return Err(Error::NamespaceDoesntExist(namespace.to_string()));
        }

        let f = {
            let name = namespace.clone();
            move |ns: NamespaceEntry| async move {
                let lock = ns.read().await;
                match &*lock {
                    Some(ns) => Ok(f(ns)),
                    // the namespace was taken out of the entry
                    None => Err(Error::NamespaceDoesntExist(name.to_string())),
                }
            }
        };

        let handle = self.inner.metadata.handle(namespace.to_owned()).await;
        f(self
            .load_namespace(&namespace, handle, RestoreOption::Latest)
            .await?)
        .await
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
            let ns = self
                .make_namespace(namespace, db_config, restore_option)
                .await?;
            // A namespace opened from the metastore is complete by definition; this only removes
            // a marker left by a crash between persisting the config and removing it.
            if let Err(e) = ns.mark_complete().await {
                tracing::warn!(namespace = %namespace, "could not remove creation marker: {e}");
            }
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

        // With namespaces disabled, the default namespace always exists and `create` is an
        // idempotent config upsert of it. Creating *from a dump* is not: the dump must never be
        // skipped because the namespace happens to be loaded already, so that case takes the
        // reserving path below like any other creation.
        // FIXME: move the default namespace check out of this function.
        if (self.inner.allow_lazy_creation || namespace == NamespaceName::default())
            && matches!(restore_option, RestoreOption::Latest)
        {
            tracing::trace!("auto-creating the namespace");
            let handle = self.inner.metadata.handle(namespace.clone()).await;
            handle.store(Arc::new(db_config)).await?;
            self.load_namespace(&namespace, handle, restore_option)
                .await?;
            return Ok(());
        }

        // Nothing below is visible or durable until the namespace is complete:
        // - the reservation locks the name; dropping it unpublished undoes the in-memory config;
        // - the configurator removes a brand-new directory if setup fails or is cancelled;
        // - the metastore row is written last, so its presence implies a complete namespace.
        let reservation = Reservation::acquire(self, namespace.clone()).await?;
        let handle = self.inner.metadata.handle(namespace.clone()).await;
        handle
            .store_and_maybe_flush(Some(Arc::new(db_config)), false)
            .await?;
        self.get_configurator(&handle.get())
            .discard_incomplete(&namespace)
            .await?;
        tracing::debug!("setting up namespace");
        let ns = self
            .make_namespace(&namespace, handle.clone(), restore_option)
            .await?;
        tracing::debug!("storing db config");
        handle.flush().await?;
        if let Err(e) = ns.mark_complete().await {
            tracing::warn!(namespace = %namespace, "could not remove creation marker: {e}");
        }
        reservation.publish(ns);

        tracing::debug!("completed creating namespace");

        Ok(())
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
