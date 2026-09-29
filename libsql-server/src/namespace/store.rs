use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_lock::{RwLock, RwLockWriteGuardArc};
use chrono::NaiveDateTime;
use futures::TryFutureExt;
use moka::future::Cache;
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use tokio::task::JoinSet;
use tokio::time::{Duration, Instant};
use tokio_stream::wrappers::BroadcastStream;

use crate::auth::Authenticated;
use crate::broadcaster::BroadcastMsg;
use crate::connection::config::DatabaseConfig;
use crate::database::{Database, DatabaseKind, PrimaryConnectionMaker};
use crate::error::Error;
use crate::metrics::NAMESPACE_LOAD_LATENCY;
use crate::namespace::{NamespaceBottomlessDbId, NamespaceBottomlessDbIdInit, NamespaceName};
use crate::stats::Stats;

use super::broadcasters::{BroadcasterHandle, BroadcasterRegistry};
use super::configurator::{DynConfigurator, NamespaceConfigurators};
use super::fence::capability::CapabilityPurpose;
use super::fence::command::{FenceCommand, FenceRequest};
use super::fence::controller::{FenceController, Transition};
use super::fence::hooks::HookPoint;
use super::fence::import::{self, ImportSession};
use super::fence::outcome::FenceOutcome;
use super::fence::record::ServerIdentity;
use super::fence::registry::FenceRegistry;
use super::fence::state::Role;
use super::fence::store::StoredFence;
use super::fence::target::{self, CreateTargetRequest};
use super::meta_store::{FenceCommit, FenceContext, MetaStore, MetaStoreHandle};
use super::schema_lock::SchemaLocksRegistry;
use super::{Namespace, ResetCb, ResetOp, ResolveNamespacePathFn, RestoreOption};

type NamespaceEntry = Arc<RwLock<Option<Namespace>>>;

/// Entries of namespaces with a creation, fork or reset in progress, pinned so that lookups keep
/// finding (and waiting on) the locked entry even if the cache evicts it meanwhile. Otherwise a
/// concurrent lookup would run a lazy load of the directory the operation is writing to.
type InFlight = Arc<Mutex<HashMap<NamespaceName, NamespaceEntry>>>;

/// Remove `name` from `in_flight`, but only if it still maps to `entry` (another operation may
/// have taken the name over in the meantime).
fn unpin(in_flight: &InFlight, name: &NamespaceName, entry: &NamespaceEntry) {
    let mut in_flight = in_flight.lock();
    if in_flight.get(name).is_some_and(|e| Arc::ptr_eq(e, entry)) {
        in_flight.remove(name);
    }
}

/// A namespace name reserved for a creation (or fork) in progress.
///
/// Holding a reservation holds the name's cache entry write-locked, so every other access to
/// the name — user requests, a second create, destroy — waits until the outcome is known.
/// [`publish`](Self::publish) installs the finished namespace. Dropping the reservation
/// unpublished (error, or the creating request was cancelled) undoes everything the creation
/// did — the namespace's config, and its directory if it is still marked incomplete — and only
/// then releases the lock, so waiters observe a namespace that does not exist, never a
/// half-built one, and a retry never races the cleanup.
///
/// The entry is pinned in [`InFlight`] for the duration, so that lookups keep finding it (and
/// waiting on it) even if the cache evicts it in the meantime.
///
/// The metastore row is only written after setup succeeds (see `create`), so the row's presence
/// implies a complete namespace. See `docs/ATOMIC_NAMESPACE_CREATE_DESIGN.md`.
struct Reservation {
    guard: Option<RwLockWriteGuardArc<Option<Namespace>>>,
    entry: NamespaceEntry,
    store: NamespaceStore,
    name: NamespaceName,
    /// Selects the configurator that owns the namespace's directory.
    config: Arc<DatabaseConfig>,
}

impl Reservation {
    /// Fails with `NamespaceAlreadyExist` if the namespace is loaded or known to the metastore.
    ///
    /// Must be called before `MetaStore::handle(name)`: `handle` inserts the name into the
    /// in-memory config map that `exists` reads, so the name becomes visible only while it is
    /// already locked here.
    async fn acquire(
        store: &NamespaceStore,
        name: NamespaceName,
        config: Arc<DatabaseConfig>,
    ) -> crate::Result<Self> {
        // Wait on the entry an operation in progress holds, if any, rather than on the cache's
        // (which may be a fresh one if that entry was evicted).
        let pinned = store.inner.in_flight.lock().get(&name).cloned();
        let entry = match pinned {
            Some(entry) => entry,
            None => {
                store
                    .inner
                    .store
                    .get_with(name.clone(), async { Default::default() })
                    .await
            }
        };
        if entry.try_write().is_none() {
            tracing::debug!(namespace = %name, "waiting for an operation in progress on the namespace");
        }
        let guard = entry.write_arc().await;
        if guard.is_some() || store.inner.metadata.exists(&name).await {
            if guard.is_none() {
                // The namespace exists but is not loaded, and `get_with` just gave it an empty
                // entry. Left there, lookups would find the empty entry instead of loading the
                // namespace (see `load_namespace`); remove it again.
                drop(guard);
                store.inner.store.invalidate(&name).await;
            }
            return Err(Error::NamespaceAlreadyExist(name.to_string()));
        }
        store
            .inner
            .in_flight
            .lock()
            .insert(name.clone(), entry.clone());
        Ok(Self {
            guard: Some(guard),
            entry,
            store: store.clone(),
            name,
            config,
        })
    }

    /// Install the finished namespace and release the lock.
    async fn publish(mut self, ns: Namespace) {
        // `install` awaits (cache lookups). Keep the guard inside `self` across them: if this
        // future is dropped there, `Drop` still sees an unpublished reservation and undoes the
        // creation — rather than leaving the name pinned and the lock released.
        {
            let guard = self
                .guard
                .as_deref_mut()
                .expect("a reservation is published at most once");
            self.store.install(&self.name, &self.entry, guard, ns).await;
        }
        let guard = self.guard.take().expect("checked above");
        // Unpin before unlocking: a lookup racing with us either still finds the pinned entry
        // (and waits for the lock, then sees the namespace) or goes through the cache, where
        // the namespace now is.
        unpin(&self.store.inner.in_flight, &self.name, &self.entry);
        drop(guard);
    }
}

impl Reservation {
    /// The creation failed: undo it, then release the name. Awaited, so that by the time the
    /// error reaches the caller the name is free and nothing is left of the attempt.
    async fn abort(mut self) {
        if let Some(cleanup) = self.take_cleanup() {
            let _ = tokio::task::spawn_blocking(cleanup).await;
        }
    }

    /// Everything that undoes an unpublished creation, in the order that keeps the name
    /// unobservable until it is clean. Blocking (`discard_blocking`).
    fn take_cleanup(&mut self) -> Option<impl FnOnce() + Send + 'static> {
        let guard = self.guard.take()?;
        metrics::increment_counter!("libsql_server_namespace_create_aborted");
        let store = self.store.clone();
        let name = self.name.clone();
        let entry = self.entry.clone();
        let config = self.config.clone();
        Some(move || {
            // 1. The config: in memory and, if the commit happened but publishing didn't, the
            //    row. From here on lookups of the name are rejected before they reach the cache.
            if let Err(e) = store.inner.metadata.discard_blocking(name.clone()) {
                tracing::error!(namespace = %name, "failed to discard namespace config: {e}");
            }
            // 2. The directory, if it is still marked incomplete (the configurator's own guard
            //    normally got it already; this covers forks and anything that guard missed).
            if let Err(e) = store.get_configurator(&config).discard_incomplete(&name) {
                tracing::error!(namespace = %name, "failed to discard namespace directory: {e}");
            }
            // 3. Only now let anyone else at the name.
            unpin(&store.inner.in_flight, &name, &entry);
            drop(guard);
        })
    }
}

impl Drop for Reservation {
    /// Neither published nor aborted: the creating future was dropped (the request was
    /// cancelled, or the server is shutting down).
    fn drop(&mut self) {
        let Some(cleanup) = self.take_cleanup() else {
            return;
        };
        tracing::warn!(
            namespace = %self.name,
            "namespace creation was cancelled; discarding it"
        );
        // We are running inside a future that is being dropped: hand the (blocking) cleanup to
        // the blocking pool instead of blocking in place. The name stays locked until it ran.
        match tokio::runtime::Handle::try_current() {
            Ok(rt) => {
                rt.spawn_blocking(cleanup);
            }
            Err(_) => cleanup(),
        }
    }
}

/// Keeps a namespace entry pinned in [`InFlight`] while `reset` holds it locked (see
/// [`Reservation`] for why). Must be created after the lock is taken and dropped before it is
/// released.
struct Pinned {
    in_flight: InFlight,
    name: NamespaceName,
    entry: NamespaceEntry,
}

impl Pinned {
    fn new(store: &NamespaceStore, name: NamespaceName, entry: NamespaceEntry) -> Self {
        store
            .inner
            .in_flight
            .lock()
            .insert(name.clone(), entry.clone());
        Self {
            in_flight: store.inner.in_flight.clone(),
            name,
            entry,
        }
    }
}

impl Drop for Pinned {
    fn drop(&mut self) {
        unpin(&self.in_flight, &self.name, &self.entry);
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
    in_flight: InFlight,
    /// Fence controllers, outside the cache: a namespace that is evicted and reloaded gets the
    /// controller it had.
    fences: FenceRegistry,
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
        let in_flight: InFlight = Default::default();
        let store = Cache::<NamespaceName, NamespaceEntry>::builder()
            .async_eviction_listener({
                let in_flight = in_flight.clone();
                move |name, ns, cause| {
                    tracing::debug!("evicting namespace `{name}` asynchronously: {cause:?}");
                    let pinned = in_flight.lock().contains_key(&name);
                    // TODO(sarna): not clear if we should snapshot-on-evict...
                    // On the one hand, better to do so, because we have no idea
                    // for how long we're evicting a namespace.
                    // On the other, if there's lots of cache pressure, snapshotting
                    // very often will kill the machine's I/O.
                    let shutdown = async move {
                        if let Some(ns) = ns.write().await.take() {
                            tracing::info!("namespace `{name}` deallocated");
                            if let Err(e) = ns.shutdown(snapshot_at_shutdown).await {
                                tracing::error!("error deallocating `{name}`: {e}")
                            }
                        }
                    };
                    // moka runs this listener inline, from whichever cache operation happens
                    // to run maintenance, and awaits it. Normally that is what we want: it
                    // serialises the shutdown with a reload of the same name. But an entry
                    // write-locked by an operation in progress (create, fork, reset) stays
                    // locked for minutes; waiting for it here would stall the cache for
                    // everyone and deadlock the operation if it touches the cache itself. That
                    // operation installs its result elsewhere (see `install`), so for it the
                    // wait only has to happen off the maintenance path.
                    if pinned {
                        tokio::spawn(shutdown);
                        Box::pin(async {}) as Pin<Box<dyn Future<Output = ()> + Send>>
                    } else {
                        Box::pin(shutdown)
                    }
                }
            })
            .max_capacity(max_active_namespaces as u64)
            .time_to_idle(Duration::from_secs(86400))
            .build();

        // Every namespace with fence state gets its controller before anything is served
        // (section 8.5).
        let fences = FenceRegistry::seeded(metadata.load_fences().await?);
        if fences.len() > 0 {
            tracing::info!("loaded {} namespace fence controllers", fences.len());
        }

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
                fences,
                in_flight,
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
        // The namespace's fence state went with it.
        self.inner.fences.remove(&namespace);

        let mut bottomless_db_id_init = NamespaceBottomlessDbIdInit::FetchFromConfig;
        // An operation in progress holds the namespace in its pinned entry (the cache's may be
        // a fresh, empty one if that entry was evicted): wait on that one, so that we destroy
        // what the operation produces rather than racing it.
        let pinned = self.inner.in_flight.lock().get(&namespace).cloned();
        let cached = self.inner.store.remove(&namespace).await;
        if let Some(ns) = pinned.or(cached) {
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
        // A namespace that is not loaded has nothing to checkpoint. (`get_with(Default)` here
        // used to leave an empty entry behind that lookups then mistook for the namespace.)
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
        // Declared after the lock so that it is unpinned before the lock is released.
        let _pinned = Pinned::new(self, namespace.clone(), entry.clone());
        if let Some(ns) = lock.take() {
            ns.destroy().await?;
        }

        let db_config = self.inner.metadata.handle(namespace.clone()).await?;
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

        self.install(&namespace, &entry, &mut lock, ns).await;

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

        // The destination is refused before anything is stored for it when it is being created
        // as a migration target or its fence state is unknown.
        self.inner.fences.check_available(&to)?;

        // check that the source namespace exists
        if !self.inner.metadata.exists(&from).await {
            return Err(crate::error::Error::NamespaceDoesntExist(from.to_string()));
        }

        let to_config = Arc::new(to_config);
        let reservation = Reservation::acquire(self, to.clone(), to_config.clone()).await?;
        match self.fork_reserved(&from, &to, to_config, timestamp).await {
            Ok(to_ns) => {
                self.publish(reservation, to_ns).await;
                Ok(())
            }
            Err(e) => {
                tracing::warn!(from = %from, to = %to, error = %e, "fork failed");
                reservation.abort().await;
                Err(e)
            }
        }
    }

    /// The part of `fork` that runs with the target name reserved.
    async fn fork_reserved(
        &self,
        from: &NamespaceName,
        to: &NamespaceName,
        to_config: Arc<DatabaseConfig>,
        timestamp: Option<NaiveDateTime>,
    ) -> crate::Result<Namespace> {
        // FIXME: we could potentially delete the namespace while trying to fork it
        let Some(from_config) = self.inner.metadata.lookup(from).await? else {
            return Err(crate::Error::NamespaceDoesntExist(from.to_string()));
        };
        let from_entry = self.load_namespace(from, from_config.clone()).await?;
        let from_lock = from_entry.read().await;
        let Some(from_ns) = &*from_lock else {
            return Err(crate::error::Error::NamespaceDoesntExist(from.to_string()));
        };

        let handle = self.inner.metadata.handle(to.clone()).await?;
        // In memory only: the fork reads it; nothing is persisted until it succeeded.
        handle.store_and_maybe_flush(Some(to_config), false).await?;
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

        if self.inner.has_shutdown.load(Ordering::Relaxed) {
            return Err(Error::NamespaceStoreShutdown);
        }
        handle.flush().await?; // commit point
        Ok(to_ns)
    }

    /// Make a namespace whose config has just been persisted visible, then drop its marker.
    ///
    /// Visible first, then unmarked: a marker that outlives the namespace's publication is
    /// harmless (removed when the namespace is next loaded), a complete directory without one
    /// is not (it could not be told from a namespace that was never ours to discard).
    async fn publish(&self, reservation: Reservation, ns: Namespace) {
        let name = reservation.name.clone();
        let marker_dir = ns.path.clone();
        reservation.publish(ns).await;
        if let Err(e) = super::remove_incomplete_marker(&marker_dir).await {
            // The namespace is published and serves; the marker is removed at its next load. It
            // matters only if the metastore is lost and rebuilt from the filesystem meanwhile.
            tracing::error!(namespace = %name, "could not remove creation marker: {e}");
        }
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

        // A namespace whose fence state is unavailable is refused before any setup work.
        self.inner.fences.check_available(&namespace)?;

        // A lookup that cannot create: only the default namespace and lazy creation create a
        // namespace here, and those refuse a name whose fence state is not established.
        let handle = match self.inner.metadata.lookup(&namespace).await? {
            Some(handle) => handle,
            None if namespace == NamespaceName::default() || self.inner.allow_lazy_creation => {
                self.inner.metadata.handle(namespace.clone()).await?
            }
            None => return Err(Error::NamespaceDoesntExist(namespace.to_string())),
        };
        f(self.load_namespace(&namespace, handle).await?).await
    }

    fn resolve_attach_fn(&self) -> ResolveNamespacePathFn {
        static FN: OnceCell<ResolveNamespacePathFn> = OnceCell::new();
        FN.get_or_init(|| {
            Arc::new({
                let store = self.clone();
                move |ns: &NamespaceName| {
                    tokio::runtime::Handle::current().block_on(store.with(ns.clone(), |ns| {
                        super::AttachTarget {
                            path: ns.path.clone(),
                            fence: ns.fence().clone(),
                        }
                    }))
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
        // The controller is handed to the namespace before its first connection exists, so no
        // connection is ever opened without a gate (section 8.5).
        self.inner.fences.check_available(namespace)?;
        let fence = self.inner.fences.controller(namespace);
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
                fence,
            )
            .await?;

        Ok(ns)
    }

    /// Install `ns` as namespace `name` at the end of an operation that held `entry` (the
    /// name's cache entry) write-locked, with `slot` its locked content.
    ///
    /// Normally `entry` is still the cache's entry for the name and `ns` goes into it. If the
    /// cache evicted `entry` meanwhile, `ns` goes into a fresh entry instead and `entry` is
    /// left empty: the eviction listener waiting on it then finds nothing to shut down, and
    /// lookups that waited on it fall through to the cache (see `load_namespace`). If the entry
    /// is gone because the namespace was *destroyed* meanwhile, `ns` goes into `entry` after
    /// all: `destroy` is waiting on it and shuts it down.
    async fn install(
        &self,
        name: &NamespaceName,
        entry: &NamespaceEntry,
        slot: &mut Option<Namespace>,
        ns: Namespace,
    ) {
        match self.inner.store.get(name).await {
            Some(current) if Arc::ptr_eq(&current, entry) => {
                slot.replace(ns);
            }
            _ if !self.inner.metadata.exists(name).await => {
                tracing::info!(
                    namespace = %name,
                    "namespace was destroyed while an operation on it was in progress"
                );
                slot.replace(ns);
            }
            _ => {
                tracing::info!(
                    namespace = %name,
                    "namespace entry was evicted while an operation on it was in progress; \
                     re-inserting"
                );
                self.inner
                    .store
                    .insert(name.clone(), Arc::new(RwLock::new(Some(ns))))
                    .await;
            }
        }
    }

    /// The entry of an existing namespace, loading it (`RestoreOption::Latest`) if needed.
    async fn load_namespace(
        &self,
        namespace: &NamespaceName,
        db_config: MetaStoreHandle,
    ) -> crate::Result<NamespaceEntry> {
        // An operation in progress on this namespace (create, fork, reset) holds its entry
        // locked and pinned: wait on that entry rather than loading the directory it is working
        // on (the cache may have evicted the entry meanwhile). If the operation leaves the entry
        // empty — it failed, or the entry was evicted and the namespace it published was shut
        // down by the eviction listener — decide like any other lookup: the metastore says
        // whether the namespace exists, and the cache (re)loads it.
        let pinned = self.inner.in_flight.lock().get(namespace).cloned();
        if let Some(entry) = pinned {
            tracing::debug!(
                namespace = %namespace,
                "waiting for an operation in progress on the namespace"
            );
            if entry.read().await.is_some() {
                return Ok(entry);
            }
            if !self.inner.metadata.exists(namespace).await {
                return Err(Error::NamespaceDoesntExist(namespace.to_string()));
            }
        }

        let lazily_created =
            *namespace == NamespaceName::default() || self.inner.allow_lazy_creation;
        // Two rounds at most: an entry that is empty once nobody holds it locked is a leftover
        // (of a reservation that was rejected, a reset that failed, a checkpoint of a namespace
        // that was not loaded) and would make the namespace unreachable until the cache evicts
        // it; drop it and load for real.
        for round in 0..2 {
            let loaded = AtomicBool::new(false);
            let init = async {
                loaded.store(true, Ordering::Relaxed);
                // The caller checked that the namespace exists; re-check now that we are the
                // one loading it, in case it was discarded or destroyed in between (otherwise
                // we would bring an empty namespace into existence for a name the metastore
                // doesn't know).
                if !lazily_created && !self.inner.metadata.exists(namespace).await {
                    return Err(Error::NamespaceDoesntExist(namespace.to_string()));
                }
                let ns = self
                    .make_namespace(namespace, db_config.clone(), RestoreOption::Latest)
                    .await?;
                // A namespace opened from the metastore is complete by definition; this only
                // removes a marker left by a crash between persisting the config and removing
                // it.
                if let Err(e) = ns.mark_complete().await {
                    tracing::warn!(namespace = %namespace, "could not remove creation marker: {e}");
                }
                Ok(Some(ns))
            };

            let before_load = Instant::now();
            let entry = self
                .inner
                .store
                .try_get_with(
                    namespace.clone(),
                    init.map_ok(|ns| Arc::new(RwLock::new(ns))),
                )
                .await?;
            if loaded.load(Ordering::Relaxed) {
                NAMESPACE_LOAD_LATENCY.record(before_load.elapsed());
                return Ok(entry);
            }

            if round == 0 && entry.read().await.is_none() {
                let still_cached = self
                    .inner
                    .store
                    .get(namespace)
                    .await
                    .is_some_and(|e| Arc::ptr_eq(&e, &entry));
                if still_cached {
                    tracing::debug!(namespace = %namespace, "dropping empty namespace entry");
                    self.inner.store.invalidate(namespace).await;
                }
                continue;
            }
            return Ok(entry);
        }
        unreachable!("the second round always returns")
    }

    #[tracing::instrument(skip_all, fields(namespace))]
    pub async fn create(
        &self,
        namespace: NamespaceName,
        restore_option: RestoreOption,
        db_config: DatabaseConfig,
    ) -> crate::Result<()> {
        // A name that is being created as a migration target, or whose fence state is unknown,
        // is refused before anything is stored for it.
        self.inner.fences.check_available(&namespace)?;
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
            let handle = self.inner.metadata.handle(namespace.clone()).await?;
            handle.store(Arc::new(db_config)).await?;
            self.load_namespace(&namespace, handle).await?;
            return Ok(());
        }

        // Nothing below is visible or durable until the namespace is complete:
        // - the reservation locks the name; dropping it unpublished undoes the in-memory config;
        // - the configurator removes a brand-new directory if setup fails or is cancelled;
        // - the metastore row is written last, so its presence implies a complete namespace.
        let started = Instant::now();
        let db_config = Arc::new(db_config);
        let reservation = Reservation::acquire(self, namespace.clone(), db_config.clone()).await?;
        match self
            .create_reserved(&namespace, db_config, restore_option)
            .await
        {
            Ok(ns) => {
                self.publish(reservation, ns).await;
                tracing::info!(
                    namespace = %namespace,
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "namespace created"
                );
                Ok(())
            }
            Err(e) => {
                tracing::warn!(namespace = %namespace, error = %e, "namespace creation failed");
                reservation.abort().await;
                Err(e)
            }
        }
    }

    /// The part of `create` that runs with the name reserved: everything up to and including
    /// the commit point.
    async fn create_reserved(
        &self,
        namespace: &NamespaceName,
        db_config: Arc<DatabaseConfig>,
        restore_option: RestoreOption,
    ) -> crate::Result<Namespace> {
        let handle = self.inner.metadata.handle(namespace.clone()).await?;
        // In memory only: setup reads it; nothing is persisted until setup succeeded.
        handle.store_and_maybe_flush(Some(db_config), false).await?;
        // whatever a creation of this name that never completed left behind
        self.get_configurator(&handle.get())
            .discard_incomplete(namespace)?;
        tracing::debug!("setting up namespace");
        let ns = self
            .make_namespace(namespace, handle.clone(), restore_option)
            .await?;
        if self.inner.has_shutdown.load(Ordering::Relaxed) {
            return Err(Error::NamespaceStoreShutdown);
        }
        tracing::debug!("storing db config");
        handle.flush().await?; // commit point
        Ok(ns)
    }

    pub async fn shutdown(self) -> crate::Result<()> {
        let mut set = JoinSet::new();
        self.inner.has_shutdown.store(true, Ordering::Relaxed);

        for (name, entry) in self.inner.store.iter() {
            let snapshow_at_shutdown = self.inner.snapshot_at_shutdown;
            if self.inner.in_flight.lock().contains_key(&name) {
                // A creation, fork or reset holds this entry locked, possibly for minutes. It
                // notices the shutdown itself (`has_shutdown`) and discards its work; waiting
                // here would hold up the shutdown of every other namespace.
                tracing::warn!(namespace = %name, "operation in progress at shutdown; not waiting for it");
                continue;
            }
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

    /// Run one fence command on its namespace, including the drain it starts
    /// (`docs/NAMESPACE_FENCE.md` sections 5.3 and 8). `AcquireSourceWriteFence` loads the
    /// namespace first, so that its connection manager and replication log are registered with
    /// the namespace's controller before the drain needs them.
    // The admin routes that call this are not part of the server yet.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn execute_fence_command(
        &self,
        request: FenceRequest,
        server: ServerIdentity,
    ) -> crate::Result<FenceCommit> {
        let controller = match request.command {
            FenceCommand::CreateTargetQuarantined { .. } => {
                return self.run_create_target(request, server).await
            }
            FenceCommand::AcquireSourceWriteFence { .. } => {
                self.with(request.namespace.clone(), |ns| ns.fence().clone())
                    .await?
            }
            _ => self.inner.fences.controller(&request.namespace),
        };
        controller
            .execute(
                &self.inner.metadata,
                request,
                FenceContext::now(server, None),
            )
            .await
    }

    /// `CreateTargetQuarantined`, atomic with namespace creation (`docs/NAMESPACE_FENCE.md`
    /// sections 10.1 and 11): the namespace is quarantined from the first instant it can be
    /// observed, and is loaded behind the quarantine gate before this returns `APPLIED`.
    ///
    /// Fence refusals are [`Error::NamespaceFence`] with their stable outcome code. The work
    /// runs on its own task under the namespace's transition lock, so a caller that goes away
    /// does not interrupt it; replaying the same request returns the stored result, completes
    /// the publication and load of a target whose commit was not acknowledged, and completes a
    /// creation interrupted between its marker and its commit.
    pub async fn create_target_quarantined(
        &self,
        request: CreateTargetRequest,
        server: ServerIdentity,
    ) -> crate::Result<FenceCommit> {
        self.run_create_target(request.into(), server).await
    }

    async fn run_create_target(
        &self,
        request: FenceRequest,
        server: ServerIdentity,
    ) -> crate::Result<FenceCommit> {
        if self.inner.has_shutdown.load(Ordering::Relaxed) {
            return Err(Error::NamespaceStoreShutdown);
        }
        let controller = self.inner.fences.controller(&request.namespace);
        let this = self.clone();
        tokio::spawn(async move {
            let mut transition = controller.begin_transition().await;
            let ctx = FenceContext::now(server, None);
            this.create_target_under(&mut transition, request, ctx)
                .await
        })
        .await?
    }

    /// Section 10.1, steps 1 to 5, under `transition`.
    async fn create_target_under(
        &self,
        transition: &mut Transition,
        request: FenceRequest,
        ctx: FenceContext,
    ) -> crate::Result<FenceCommit> {
        let controller = transition.controller().clone();
        let namespace = request.namespace.clone();
        let key = (request.operation_id, request.command_id);

        // A name with no fence state gets the target-creation gate before the metastore
        // transaction writes the marker, so nothing can set the name up, serve it or store a
        // config for it from before the commit to the load. A name that already has fence
        // state (a replay, a creation interrupted after its marker, or a refusal) already has
        // the gate its state implies. A name the server already knows is refused without
        // touching its gate; it is checked again once the gate is in place, which closes the
        // race with a create or fork that has not stored anything yet.
        let fresh = {
            let gate = controller.gate();
            matches!(gate.fence, StoredFence::None { .. }) && gate.indeterminate.is_none()
        };
        if fresh {
            if self.name_in_use(&namespace).await {
                return Err(target::name_in_use(&namespace).into());
            }
            transition.install_creating_target(key);
            let _ = controller.hook(HookPoint::AfterInstallingGate).await;
            if self.name_in_use(&namespace).await {
                transition.remove_creating_target();
                return Err(target::name_in_use(&namespace).into());
            }
        }

        // Steps 2 and 3: the marker, then the rows in one transaction. The commit publishes the
        // quarantined record in place of the creation gate. A command proven not to have
        // committed removes the creation gate; one whose commit is unknown keeps it, with the
        // indeterminate flag, until the same command is replayed.
        let commit = match transition.apply(&self.inner.metadata, request, ctx).await {
            Ok(commit) => commit,
            Err(e) => {
                if controller.gate().indeterminate != Some(key) {
                    transition.remove_creating_target();
                }
                return Err(e);
            }
        };
        let _ = controller.hook(HookPoint::AfterTargetRowsCommitted).await;

        // Steps 4 and 5: the gate is the target's; now make the config visible and load the
        // namespace, whose first connection is created behind that gate. A replay does the same,
        // which completes a creation whose commit was not acknowledged.
        let is_target = commit
            .record
            .as_ref()
            .is_some_and(|r| r.role == Role::Target && r.namespace == namespace);
        if is_target {
            self.inner
                .metadata
                .publish_target_config(namespace.clone())
                .await?;
            self.clear_empty_entry(&namespace).await;
            let loaded = self
                .with(namespace.clone(), |ns| ns.fence().clone())
                .await?;
            debug_assert!(Arc::ptr_eq(&loaded, &controller));
        }
        if commit.receipt.outcome == FenceOutcome::Applied && commit.created_config.is_some() {
            tracing::info!(
                namespace = %namespace,
                operation_id = %key.0,
                command_id = %key.1,
                "created namespace as a quarantined migration target"
            );
        }
        Ok(commit)
    }

    /// Issue an import capability to `operation_id` and open a connection that works under it
    /// (`docs/NAMESPACE_FENCE.md` section 11): the only way to write into a quarantined target.
    /// Valid only while the target is `TARGET_QUARANTINED`, owned by `operation_id`, at
    /// `expected_revision`; the target is loaded if it is not. Fence refusals are
    /// [`Error::NamespaceFence`] with their stable outcome code (`OPERATION_CAPABILITY_REQUIRED`
    /// in any other state, `FENCE_OWNED_BY_ANOTHER_OPERATION`, `FENCE_REVISION_MISMATCH`).
    pub async fn open_import_session(
        &self,
        namespace: NamespaceName,
        operation_id: uuid::Uuid,
        expected_revision: u64,
    ) -> crate::Result<ImportSession> {
        let (controller, maker) = self.primary_maker(&namespace).await?;
        let capability = controller.issue_capability(
            CapabilityPurpose::Import,
            operation_id,
            expected_revision,
        )?;
        match maker
            .inner()
            .make_capability_connection(capability.clone())
            .await
        {
            Ok(conn) => Ok(ImportSession::new(capability, controller, conn)),
            Err(e) => {
                controller.revoke_capability(capability.id());
                Err(e)
            }
        }
    }

    /// The fence controller and connection maker of the primary `namespace`, loading it.
    async fn primary_maker(
        &self,
        namespace: &NamespaceName,
    ) -> crate::Result<(Arc<FenceController>, Arc<PrimaryConnectionMaker>)> {
        let (controller, maker) = self
            .with(namespace.clone(), |ns| {
                let maker = match &ns.db {
                    Database::Primary(p) => Some(p.connection_maker()),
                    _ => None,
                };
                (ns.fence().clone(), maker)
            })
            .await?;
        match maker {
            Some(maker) => Ok((controller, maker)),
            None => Err(import::not_importable(namespace)),
        }
    }

    /// A connection to `namespace` that works under `capability`, whether or not this server
    /// issued it: for tests that prove the WAL refuses a capability that is not the valid one.
    #[cfg(test)]
    pub(crate) async fn capability_connection(
        &self,
        namespace: &NamespaceName,
        capability: super::fence::capability::MigrationCapability,
    ) -> crate::Result<
        crate::connection::legacy::LegacyConnection<super::replication_wal::ReplicationWalWrapper>,
    > {
        let (_, maker) = self.primary_maker(namespace).await?;
        maker.inner().make_capability_connection(capability).await
    }

    /// Whether the server already knows `namespace`: its config is in memory, or the namespace
    /// cache holds it (a loaded namespace, or a fork in flight, which holds its entry locked).
    async fn name_in_use(&self, namespace: &NamespaceName) -> bool {
        if self.inner.metadata.exists(namespace).await {
            return true;
        }
        match self.inner.store.get(namespace).await {
            Some(entry) => entry.read().await.is_some(),
            None => false,
        }
    }

    /// Drop an empty namespace-cache entry for `namespace`, which a refused fork or a checkpoint
    /// of a name that did not exist leaves behind, so that loading the namespace creates it.
    async fn clear_empty_entry(&self, namespace: &NamespaceName) {
        if let Some(entry) = self.inner.store.get(namespace).await {
            if entry.read().await.is_none() {
                self.inner.store.invalidate(namespace).await;
            }
        }
    }

    /// The fence controller of `namespace`, creating an `UNFENCED` one if it has none.
    #[cfg(test)]
    pub(crate) fn fence_controller(&self, namespace: &NamespaceName) -> Arc<FenceController> {
        self.inner.fences.controller(namespace)
    }

    /// The fence controller that admits reads of `namespace` without loading it: `None` when
    /// the namespace does not exist (and has no fence state). A namespace whose fence state is
    /// unavailable is refused.
    pub(crate) async fn fence_gate(
        &self,
        namespace: &NamespaceName,
    ) -> crate::Result<Option<Arc<FenceController>>> {
        self.inner.fences.check_available(namespace)?;
        if let Some(controller) = self.inner.fences.get(namespace) {
            return Ok(Some(controller));
        }
        if self.inner.metadata.exists(namespace).await {
            return Ok(Some(self.inner.fences.controller(namespace)));
        }
        Ok(None)
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
pub(crate) mod fence_tests {
    use std::path::Path;

    use libsql_sys::wal::Sqlite3WalManager;
    use tempfile::tempdir;
    use tokio::sync::Semaphore;
    use uuid::Uuid;

    use super::*;
    use crate::config::MetaStoreConfig;
    use crate::namespace::configurator::{BaseNamespaceConfig, PrimaryConfig, PrimaryConfigurator};
    use crate::namespace::fence::command::{FenceCommand, FenceRequest};
    use crate::namespace::fence::outcome::{FenceDetail, FenceOutcome};
    use crate::namespace::fence::record::ServerIdentity;
    use crate::namespace::fence::state::{FenceState, OperationClass};
    use crate::namespace::fence::store as fence_store;
    use crate::namespace::meta_store::{metastore_connection_maker, FenceContext};

    const LOG: Uuid = Uuid::from_u128(0x10);
    const OP: Uuid = Uuid::from_u128(0xa);

    pub(crate) async fn open_store(dir: &Path) -> NamespaceStore {
        open_store_with_max_log_size(dir, 1_000_000_000).await
    }

    pub(crate) async fn open_store_with_max_log_size(
        dir: &Path,
        max_log_size: u64,
    ) -> NamespaceStore {
        let (maker, manager) = metastore_connection_maker(None, dir).await.unwrap();
        let meta = MetaStore::new(
            MetaStoreConfig {
                namespace_fence: true,
                ..Default::default()
            },
            dir,
            maker().unwrap(),
            manager,
            DatabaseKind::Primary,
        )
        .await
        .unwrap();
        let mut configurators = NamespaceConfigurators::empty();
        configurators.with_primary(PrimaryConfigurator::new(
            BaseNamespaceConfig {
                base_path: dir.to_path_buf().into(),
                extensions: Arc::new([]),
                stats_sender: tokio::sync::mpsc::channel(1).0,
                max_response_size: 100_000_000,
                max_total_response_size: 100_000_000,
                max_concurrent_connections: Arc::new(Semaphore::new(10)),
                max_concurrent_requests: 10_000,
                encryption_config: None,
                connection_creation_timeout: None,
                disable_intelligent_throttling: false,
                dump_import: Default::default(),
            },
            PrimaryConfig {
                max_log_size,
                max_log_duration: None,
                bottomless_replication: None,
                scripted_backup: None,
                checkpoint_interval: None,
            },
            Arc::new(|| Sqlite3WalManager::default()),
        ));
        NamespaceStore::new(false, false, 10, meta, configurators, DatabaseKind::Primary)
            .await
            .unwrap()
    }

    fn acquire(ns: &'static str) -> FenceRequest {
        FenceRequest {
            namespace: ns.into(),
            operation_id: OP,
            command_id: Uuid::from_u128(1),
            expected_state: FenceState::Unfenced,
            expected_revision: 0,
            command: FenceCommand::AcquireSourceWriteFence {
                expected_log_id: LOG,
                drain_policy: None,
            },
        }
    }

    fn ctx() -> FenceContext {
        FenceContext::now(
            ServerIdentity {
                build: "test".into(),
                instance_id: Uuid::from_u128(0x99),
            },
            Some(LOG),
        )
    }

    #[tokio::test]
    async fn evicted_namespace_reloads_with_the_same_controller() {
        let tmp = tempdir().unwrap();
        let store = open_store(tmp.path()).await;
        store
            .create("ns".into(), RestoreOption::Latest, Default::default())
            .await
            .unwrap();
        let (fence, stats) = store
            .with("ns".into(), |ns| (ns.fence().clone(), ns.stats()))
            .await
            .unwrap();
        assert!(Arc::ptr_eq(
            &fence,
            &store.inner.fences.get(&"ns".into()).unwrap()
        ));
        fence
            .apply_command(store.meta_store(), acquire("ns"), ctx())
            .await
            .unwrap();
        let gate = fence.gate();
        assert_eq!(gate.state(), FenceState::SourceDraining);

        // Evict the namespace, as idle or capacity eviction does, and let it shut down.
        store
            .inner
            .store
            .invalidate(&NamespaceName::from("ns"))
            .await;
        store.inner.store.run_pending_tasks().await;
        assert!(store
            .inner
            .store
            .get(&NamespaceName::from("ns"))
            .await
            .is_none());

        let (reloaded, reloaded_stats) = store
            .with("ns".into(), |ns| (ns.fence().clone(), ns.stats()))
            .await
            .unwrap();
        // A new namespace instance, the same controller and gate.
        assert!(!Arc::ptr_eq(&stats, &reloaded_stats));
        assert!(Arc::ptr_eq(&fence, &reloaded));
        assert_eq!(reloaded.gate(), gate);
        assert!(reloaded.permits(OperationClass::NormalWrite).is_err());
    }

    #[tokio::test]
    async fn restart_installs_the_durable_gate_before_serving() {
        let tmp = tempdir().unwrap();
        {
            let store = open_store(tmp.path()).await;
            store
                .create("ns".into(), RestoreOption::Latest, Default::default())
                .await
                .unwrap();
            let fence = store.inner.fences.controller(&"ns".into());
            fence
                .apply_command(store.meta_store(), acquire("ns"), ctx())
                .await
                .unwrap();
            store.shutdown().await.unwrap();
        }

        let store = open_store(tmp.path()).await;
        // The registry holds the durable gate before the namespace is loaded.
        let fence = store.inner.fences.get(&"ns".into()).unwrap();
        assert_eq!(fence.gate().state(), FenceState::SourceDraining);
        assert_eq!(fence.gate().revision(), 1);
        let loaded = store
            .with("ns".into(), |ns| ns.fence().clone())
            .await
            .unwrap();
        assert!(Arc::ptr_eq(&fence, &loaded));
    }

    #[tokio::test]
    async fn unavailable_namespace_is_refused_before_setup() {
        let tmp = tempdir().unwrap();
        // An unreadable marker in a directory with no config: the fence state cannot be
        // established.
        let dir = tmp.path().join("dbs").join("lost");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(fence_store::MARKER_FILE_NAME), b"garbage").unwrap();

        let store = open_store(tmp.path()).await;
        let r = store.with("lost".into(), |_| ()).await;
        match r {
            Err(Error::NamespaceFence(e)) => {
                assert_eq!(e.outcome(), FenceOutcome::FenceStateUnavailable);
                assert_eq!(e.detail(), Some(FenceDetail::CorruptRecord));
            }
            other => panic!("expected a fence error, got {other:?}"),
        }
        // Nothing was set up: no database file, and the namespace is not cached.
        assert!(!dir.join("data").exists());
        assert!(store
            .inner
            .store
            .get(&NamespaceName::from("lost"))
            .await
            .is_none());
    }

    #[tokio::test]
    async fn destroy_forgets_the_controller() {
        let tmp = tempdir().unwrap();
        let store = open_store(tmp.path()).await;
        store
            .create("ns".into(), RestoreOption::Latest, Default::default())
            .await
            .unwrap();
        assert!(store.inner.fences.get(&"ns".into()).is_some());
        store.destroy("ns".into(), false).await.unwrap();
        assert!(store.inner.fences.get(&"ns".into()).is_none());
    }
}

#[cfg(test)]
mod test {
    use std::path::Path;

    use bytes::Bytes;
    use tokio::sync::{mpsc, Semaphore};
    use tokio_stream::wrappers::ReceiverStream;

    use crate::connection::Connection as _;
    use crate::namespace::configurator::{
        BaseNamespaceConfig, NamespaceConfigurators, PrimaryConfig, PrimaryConfigurator,
    };
    use crate::namespace::dump_import::DumpImporterKind;
    use crate::namespace::meta_store::{metastore_connection_maker, MetaStore};
    use crate::namespace::DumpSource;

    use super::*;

    async fn make_store(path: &Path) -> NamespaceStore {
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
            stats_sender: mpsc::channel(1).0,
            max_response_size: 100000000000000,
            max_total_response_size: 100000000000,
            max_concurrent_connections: Arc::new(Semaphore::new(10)),
            max_concurrent_requests: 10000,
            encryption_config: None,
            connection_creation_timeout: None,
            disable_intelligent_throttling: false,
            dump_import: Default::default(),
        };
        let primary_config = PrimaryConfig {
            max_log_size: 1000000000,
            max_log_duration: None,
            bottomless_replication: None,
            scripted_backup: None,
            checkpoint_interval: None,
        };
        let mut configurators = NamespaceConfigurators::empty();
        configurators.with_primary(PrimaryConfigurator::new(
            base_config,
            primary_config,
            Arc::new(libsql_sys::wal::Sqlite3WalManager::default),
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

    /// The reservation is taken a few awaits into `create`; wait for it rather than guess.
    async fn wait_until_in_flight(store: &NamespaceStore, name: &NamespaceName) {
        for _ in 0..500 {
            if store.inner.in_flight.lock().contains_key(name) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("creation of `{name}` never reserved the name");
    }

    fn slow_dump() -> (mpsc::Sender<std::io::Result<Bytes>>, DumpSource) {
        let (tx, rx) = mpsc::channel::<std::io::Result<Bytes>>(8);
        let dump = DumpSource::new(Box::new(ReceiverStream::new(rx)))
            .with_importer(Some(DumpImporterKind::Streaming));
        (tx, dump)
    }

    async fn count_test_rows(store: &NamespaceStore, ns: &str) -> crate::Result<i64> {
        let maker = store
            .with(NamespaceName::from_string(ns.into()).unwrap(), |ns| {
                ns.db.connection_maker()
            })
            .await?;
        let conn = maker.create().await?;
        Ok(conn.with_raw(|c| c.query_row("select count(*) from test", [], |r| r.get(0)))?)
    }

    /// The cache evicts the entry of a namespace while it is being created (here: explicitly
    /// invalidated, which takes the same path). A lookup issued afterwards must still wait for
    /// the creation and then see the imported data, instead of lazily opening the directory the
    /// import is writing to.
    #[tokio::test]
    async fn lookup_waits_for_creation_even_if_the_entry_was_evicted() {
        let tmp = tempfile::tempdir().unwrap();
        let store = make_store(tmp.path()).await;
        let foo = NamespaceName::from_string("foo".into()).unwrap();

        let (tx, rx) = mpsc::channel::<std::io::Result<Bytes>>(8);
        let dump = DumpSource::new(Box::new(ReceiverStream::new(rx)))
            .with_importer(Some(DumpImporterKind::Streaming));
        let create = tokio::spawn({
            let store = store.clone();
            let foo = foo.clone();
            async move {
                store
                    .create(foo, RestoreOption::Dump(dump), Default::default())
                    .await
            }
        });
        tx.send(Ok(Bytes::from_static(
            b"BEGIN TRANSACTION; CREATE TABLE test (x); INSERT INTO test VALUES (1);",
        )))
        .await
        .unwrap();
        wait_until_in_flight(&store, &foo).await;
        assert!(!create.is_finished());

        // "eviction" of the reserved entry
        store.inner.store.invalidate(&foo).await;
        store.inner.store.run_pending_tasks().await;
        assert!(!store.inner.store.contains_key(&foo));

        let lookup = tokio::spawn({
            let store = store.clone();
            async move { count_test_rows(&store, "foo").await }
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !lookup.is_finished(),
            "the lookup must wait for the creation, not load the directory being imported into"
        );

        tx.send(Ok(Bytes::from_static(b"COMMIT;"))).await.unwrap();
        drop(tx);
        create.await.unwrap().unwrap();
        assert_eq!(lookup.await.unwrap().unwrap(), 1);
        // the namespace was published into a fresh cache entry and is served normally
        assert!(store.inner.store.contains_key(&foo));
        assert_eq!(count_test_rows(&store, "foo").await.unwrap(), 1);
        assert!(store.inner.in_flight.lock().is_empty());
    }

    /// Same situation, but the creation fails: the waiting lookup must report that the
    /// namespace does not exist, and nothing must be left behind.
    #[tokio::test]
    async fn lookup_sees_failure_of_creation_even_if_the_entry_was_evicted() {
        let tmp = tempfile::tempdir().unwrap();
        let store = make_store(tmp.path()).await;
        let foo = NamespaceName::from_string("foo".into()).unwrap();

        let (tx, rx) = mpsc::channel::<std::io::Result<Bytes>>(8);
        let dump = DumpSource::new(Box::new(ReceiverStream::new(rx)))
            .with_importer(Some(DumpImporterKind::Streaming));
        let create = tokio::spawn({
            let store = store.clone();
            let foo = foo.clone();
            async move {
                store
                    .create(foo, RestoreOption::Dump(dump), Default::default())
                    .await
            }
        });
        tx.send(Ok(Bytes::from_static(
            b"BEGIN TRANSACTION; CREATE TABLE test (x); INSERT INTO test VALUES (1);",
        )))
        .await
        .unwrap();
        wait_until_in_flight(&store, &foo).await;

        store.inner.store.invalidate(&foo).await;
        store.inner.store.run_pending_tasks().await;

        let lookup = tokio::spawn({
            let store = store.clone();
            async move { count_test_rows(&store, "foo").await }
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!lookup.is_finished());

        tx.send(Ok(Bytes::from_static(b"THIS IS NOT SQL;")))
            .await
            .unwrap();
        drop(tx);
        assert!(create.await.unwrap().is_err());
        assert!(matches!(
            lookup.await.unwrap(),
            Err(Error::NamespaceDoesntExist(_))
        ));
        assert!(!store.exists(&foo).await);
        // the cleanup runs on the blocking pool; give it a moment
        for _ in 0..50 {
            if !tmp.path().join("dbs").join("foo").exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(!tmp.path().join("dbs").join("foo").exists());
        assert!(store.inner.in_flight.lock().is_empty());
    }

    /// `destroy` is issued while the namespace is still being created. It must wait for the
    /// creation and destroy its result: nothing left in the cache, on disk or in the metastore,
    /// and the name can be created again. (Before: the result could be re-inserted into the
    /// cache as a live namespace whose directory `destroy` had just removed.)
    #[tokio::test]
    async fn destroy_during_creation_destroys_the_result() {
        let tmp = tempfile::tempdir().unwrap();
        let store = make_store(tmp.path()).await;
        let foo = NamespaceName::from_string("foo".into()).unwrap();

        let (tx, dump) = slow_dump();
        let create = tokio::spawn({
            let (store, foo) = (store.clone(), foo.clone());
            async move {
                store
                    .create(foo, RestoreOption::Dump(dump), Default::default())
                    .await
            }
        });
        tx.send(Ok(Bytes::from_static(
            b"BEGIN TRANSACTION; CREATE TABLE test (x); INSERT INTO test VALUES (1);",
        )))
        .await
        .unwrap();
        wait_until_in_flight(&store, &foo).await;
        // make it the interesting case: the cache no longer holds the reserved entry
        store.inner.store.invalidate(&foo).await;
        store.inner.store.run_pending_tasks().await;

        let destroy = tokio::spawn({
            let (store, foo) = (store.clone(), foo.clone());
            async move { store.destroy(foo, true).await }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!destroy.is_finished(), "destroy must wait for the creation");

        tx.send(Ok(Bytes::from_static(b"COMMIT;"))).await.unwrap();
        drop(tx);
        create.await.unwrap().unwrap();
        destroy.await.unwrap().unwrap();

        assert!(!store.exists(&foo).await);
        assert!(!store.inner.store.contains_key(&foo));
        assert!(!tmp.path().join("dbs").join("foo").exists());
        assert!(store.inner.in_flight.lock().is_empty());
        assert!(matches!(
            count_test_rows(&store, "foo").await,
            Err(Error::NamespaceDoesntExist(_))
        ));

        // and the name is free again
        let (tx, dump) = slow_dump();
        let create = tokio::spawn({
            let (store, foo) = (store.clone(), foo.clone());
            async move {
                store
                    .create(foo, RestoreOption::Dump(dump), Default::default())
                    .await
            }
        });
        tx.send(Ok(Bytes::from_static(
            b"BEGIN TRANSACTION; CREATE TABLE test (x); INSERT INTO test VALUES (1); COMMIT;",
        )))
        .await
        .unwrap();
        drop(tx);
        create.await.unwrap().unwrap();
        assert_eq!(count_test_rows(&store, "foo").await.unwrap(), 1);
    }

    /// A failed creation is undone before the name is released, so a retry issued the moment
    /// the failure is reported neither races the cleanup nor finds leftovers.
    #[tokio::test]
    async fn retry_right_after_failure_starts_clean() {
        let tmp = tempfile::tempdir().unwrap();
        let store = make_store(tmp.path()).await;
        let foo = NamespaceName::from_string("foo".into()).unwrap();
        let dir = tmp.path().join("dbs").join("foo");

        for attempt in 0..3 {
            let (tx, dump) = slow_dump();
            tx.send(Ok(Bytes::from_static(
                b"BEGIN TRANSACTION; CREATE TABLE test (x); INSERT INTO test VALUES (1); NOT SQL;",
            )))
            .await
            .unwrap();
            drop(tx);
            let res = store
                .create(foo.clone(), RestoreOption::Dump(dump), Default::default())
                .await;
            assert!(res.is_err(), "attempt {attempt}");
            // no waiting: the path is free and the name unknown as soon as `create` returns
            assert!(!dir.exists(), "attempt {attempt}");
            assert!(!store.exists(&foo).await, "attempt {attempt}");
        }

        let (tx, dump) = slow_dump();
        tx.send(Ok(Bytes::from_static(
            b"BEGIN TRANSACTION; CREATE TABLE test (x); INSERT INTO test VALUES (1); COMMIT;",
        )))
        .await
        .unwrap();
        drop(tx);
        store
            .create(foo.clone(), RestoreOption::Dump(dump), Default::default())
            .await
            .unwrap();
        assert_eq!(count_test_rows(&store, "foo").await.unwrap(), 1);
        assert!(!dir
            .join(crate::namespace::incomplete::INCOMPLETE_MARKER)
            .exists());
    }

    /// The config of a namespace linked to a shared schema cannot be *removed* while the schema
    /// has pending migration jobs — but it must always be possible to *discard* it when its
    /// creation did not complete, or the name would be stuck (`exists` true, no row, no data).
    #[tokio::test]
    async fn discard_ignores_the_guards_of_remove() {
        let tmp = tempfile::tempdir().unwrap();
        let store = make_store(tmp.path()).await;
        let linked = NamespaceName::from_string("linked".into()).unwrap();
        let handle = store.inner.metadata.handle(linked.clone()).await.unwrap();
        handle
            .store_and_maybe_flush(
                Some(Arc::new(DatabaseConfig {
                    shared_schema_name: Some(NamespaceName::from_string("schema".into()).unwrap()),
                    ..Default::default()
                })),
                false,
            )
            .await
            .unwrap();
        assert!(store.exists(&linked).await);

        let metadata = store.inner.metadata.clone();
        let name = linked.clone();
        tokio::task::spawn_blocking(move || metadata.discard_blocking(name))
            .await
            .unwrap()
            .unwrap();
        assert!(!store.exists(&linked).await);
    }

    /// The creating task is aborted mid-import (the request was cancelled). The reservation is
    /// dropped unpublished: config discarded, directory discarded, name released — and a
    /// lookup that was waiting sees "doesn't exist".
    #[tokio::test]
    async fn aborted_creation_is_undone() {
        let tmp = tempfile::tempdir().unwrap();
        let store = make_store(tmp.path()).await;
        let foo = NamespaceName::from_string("foo".into()).unwrap();
        let dir = tmp.path().join("dbs").join("foo");

        let (tx, dump) = slow_dump();
        let create = tokio::spawn({
            let (store, foo) = (store.clone(), foo.clone());
            async move {
                store
                    .create(foo, RestoreOption::Dump(dump), Default::default())
                    .await
            }
        });
        tx.send(Ok(Bytes::from_static(
            b"BEGIN TRANSACTION; CREATE TABLE test (x); INSERT INTO test VALUES (1);",
        )))
        .await
        .unwrap();
        wait_until_in_flight(&store, &foo).await;
        assert!(dir
            .join(crate::namespace::incomplete::INCOMPLETE_MARKER)
            .exists());

        let lookup = tokio::spawn({
            let store = store.clone();
            async move { count_test_rows(&store, "foo").await }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!lookup.is_finished());

        create.abort();
        assert!(create.await.unwrap_err().is_cancelled());

        assert!(matches!(
            lookup.await.unwrap(),
            Err(Error::NamespaceDoesntExist(_))
        ));
        // the cleanup ran on the blocking pool; the lookup's completion proves the lock was
        // released after it, so by now everything is undone
        assert!(!store.exists(&foo).await);
        assert!(!dir.exists());
        assert!(store.inner.in_flight.lock().is_empty());

        // the importer's executor thread is still unwinding its channel; the name is free anyway
        let (tx, dump) = slow_dump();
        tx.send(Ok(Bytes::from_static(
            b"BEGIN TRANSACTION; CREATE TABLE test (x); INSERT INTO test VALUES (1); COMMIT;",
        )))
        .await
        .unwrap();
        drop(tx);
        store
            .create(foo.clone(), RestoreOption::Dump(dump), Default::default())
            .await
            .unwrap();
        assert_eq!(count_test_rows(&store, "foo").await.unwrap(), 1);
    }
}
