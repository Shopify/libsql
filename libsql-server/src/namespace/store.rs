use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_lock::{RwLock, RwLockReadGuardArc, RwLockWriteGuardArc};
use chrono::NaiveDateTime;
use futures::TryFutureExt;
use moka::future::Cache;
use moka::ops::compute::{CompResult, Op};
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
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

/// A namespace held read-locked in its cache entry, so that nothing can take it out of the
/// entry (eviction, shutdown, destroy) while it is in use. Only `load_namespace` makes one,
/// after it saw the entry filled.
pub(crate) struct LoadedNamespace(RwLockReadGuardArc<Option<Namespace>>);

impl std::ops::Deref for LoadedNamespace {
    type Target = Namespace;

    fn deref(&self) -> &Namespace {
        self.0
            .as_ref()
            .expect("a LoadedNamespace is only made from a filled entry")
    }
}

/// How many times a lookup finds its entry emptied (by shutdown, eviction or destroy) before
/// it gives up with `NamespaceUnavailable`.
///
/// Where the cache holds the working set, eviction happens at shutdown only and the second
/// lookup succeeds. The budget matters only for a cache far too small for its working set,
/// where entries live for milliseconds: at a third of the working set, three lookups gave up
/// on about one request in 20,000 and five on none in 340,000. The lookups are cheap; only the
/// one that loads the namespace is not, and a load is as likely to be evicted at once as any
/// other entry, so nothing is gained by spending more.
const MAX_EMPTIED_ENTRY_ATTEMPTS: usize = 5;

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
                // entry. Left there, lookups would find the empty entry before loading the
                // namespace (see `load_namespace`); remove it again, but only if it is still
                // that empty entry: a lookup may have loaded the namespace into a fresh one
                // since the lock was released.
                drop(guard);
                store.evict_if_still_empty(&name, &entry).await;
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
                in_flight,
            }),
        })
    }

    pub async fn exists(&self, namespace: &NamespaceName) -> bool {
        self.inner.metadata.exists(namespace).await
    }

    /// Nothing starts, and no operation in progress commits or installs anything, once shutdown
    /// has begun: a namespace opened or installed after `shutdown` collected the entries would
    /// never be shut down.
    fn refuse_if_shut_down(&self) -> crate::Result<()> {
        if self.inner.has_shutdown.load(Ordering::Relaxed) {
            return Err(Error::NamespaceStoreShutdown);
        }
        Ok(())
    }

    pub async fn destroy(&self, namespace: NamespaceName, prune_all: bool) -> crate::Result<()> {
        self.refuse_if_shut_down()?;

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
        self.refuse_if_shut_down()?;

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
        // `shutdown` does not wait for a reset in progress (its entry is pinned), so a namespace
        // installed now would never be shut down.
        self.refuse_if_shut_down()?;

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
        self.refuse_if_shut_down()?;

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
        let from_ns = self.load_namespace(from).await?;
        let from_config = from_ns.db_config_store.clone();

        let handle = self.inner.metadata.handle(to.clone()).await;
        // In memory only: the fork reads it; nothing is persisted until it succeeded.
        handle.store_and_maybe_flush(Some(to_config), false).await?;
        let to_ns = self
            .get_configurator(&from_config.get())
            .fork(
                &from_ns,
                from_config,
                to.clone(),
                handle.clone(),
                timestamp,
                self.clone(),
            )
            .await?;

        self.refuse_if_shut_down()?;
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
        self.refuse_if_shut_down()?;
        if !auth.is_namespace_authorized(&namespace) {
            return Err(Error::NamespaceDoesntExist(namespace.to_string()));
        }

        self.with(namespace, f).await
    }

    pub async fn with<Fun, R>(&self, namespace: NamespaceName, f: Fun) -> crate::Result<R>
    where
        Fun: FnOnce(&Namespace) -> R,
    {
        let ns = self.load_namespace(&namespace).await?;
        Ok(f(&ns))
    }

    /// Whether a lookup of `namespace` creates it when it does not exist (the default namespace
    /// when namespaces are disabled, and every namespace on a replica).
    fn lazily_created(&self, namespace: &NamespaceName) -> bool {
        *namespace == NamespaceName::default() || self.inner.allow_lazy_creation
    }

    /// Removes `entry` from the cache if it is still the cached entry for `namespace` and still
    /// empty, so that the next lookup loads the namespace afresh. It never fills an entry
    /// itself.
    ///
    /// The checks run under moka's per-key compute lock: a loaded entry is never removed, and
    /// neither is an entry whose lock is held at that moment, which covers an operation in
    /// progress (create, fork, reset hold their entry write-locked). An operation that got the
    /// entry from the cache but has not locked it yet can lose it here; it then fills an entry
    /// the cache no longer holds, which `install` detects and re-inserts, and lookups find it
    /// pinned in the meantime. One window stays: `Op::Remove` removes whatever the cache holds
    /// when it runs, which moka does not tie to the entry the closure saw. That is detected
    /// below; the requests holding a fresh entry removed that way see it emptied and look the
    /// namespace up again.
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
                tracing::debug!(%namespace, "dropped an empty namespace cache entry");
                NAMESPACE_LEFT_EMPTY_ENTRY_DROPPED.increment(1);
            } else {
                tracing::error!(%namespace, "dropped a different cache entry than the empty one");
            }
        }
    }

    /// The error for a namespace whose cache entry was emptied while it was being used.
    /// `NamespaceDoesntExist` only when the metastore agrees: a client must be able to trust
    /// it, and a namespace that still exists but cannot be served right now is a temporary
    /// condition, not a missing one.
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

    /// An existing namespace, read-locked in its entry; loaded (`RestoreOption::Latest`) if it
    /// is not in the cache.
    ///
    /// The entry it finds may be emptied before it gets to read it (by eviction, shutdown or a
    /// concurrent destroy), or may have been left empty (by a reservation that was rejected or
    /// a reset that failed). Neither means the namespace is missing, so the lookup is repeated,
    /// up to `MAX_EMPTIED_ENTRY_ATTEMPTS` times, after dropping the empty entry from the cache
    /// so that the next lookup loads for real. Only the metastore decides that a namespace does
    /// not exist. Expected during a rolling restart and under cache pressure, once per waiting
    /// request: the counter is the signal, not the log.
    async fn load_namespace(&self, namespace: &NamespaceName) -> crate::Result<LoadedNamespace> {
        for _ in 0..MAX_EMPTIED_ENTRY_ATTEMPTS {
            self.refuse_if_shut_down()?;
            // `handle` registers the name in the metastore's in-memory map as a side effect,
            // which is what `exists` reads: a namespace that must already exist is looked up
            // with the side-effect-free `existing_handle`, so that a lookup racing with the end
            // of a failed creation, or with `destroy`, cannot bring the name back to life.
            let db_config = if self.lazily_created(namespace) {
                self.inner.metadata.handle(namespace.clone()).await
            } else {
                match self.inner.metadata.existing_handle(namespace.clone()).await {
                    Some(handle) => handle,
                    None => return Err(Error::NamespaceDoesntExist(namespace.to_string())),
                }
            };
            match self.lookup(namespace, &db_config).await? {
                Some(ns) => return Ok(ns),
                None => {
                    NAMESPACE_EMPTIED_ENTRY.increment(1);
                    tracing::debug!(%namespace, "namespace cache entry was emptied, looking it up again");
                }
            }
        }

        let error = self.emptied_entry_error(namespace).await;
        if matches!(error, Error::NamespaceUnavailable(_)) {
            // Shutdown and a namespace that is really gone are not failures of the store, so
            // the counter only records this outcome.
            NAMESPACE_EMPTIED_ENTRY_GAVE_UP.increment(1);
        }
        tracing::warn!(%namespace, %error, "namespace cache entry kept being emptied, giving up");
        Err(error)
    }

    /// One attempt of `load_namespace`. `Ok(None)` means the entry it found was empty, and has
    /// been dropped from the cache if it was still there.
    async fn lookup(
        &self,
        namespace: &NamespaceName,
        db_config: &MetaStoreHandle,
    ) -> crate::Result<Option<LoadedNamespace>> {
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
            let lock = entry.read_arc().await;
            if lock.is_some() {
                return Ok(Some(LoadedNamespace(lock)));
            }
            drop(lock);
            if !self.inner.metadata.exists(namespace).await {
                return Err(Error::NamespaceDoesntExist(namespace.to_string()));
            }
        }

        let loaded = AtomicBool::new(false);
        let init = async {
            loaded.store(true, Ordering::Relaxed);
            // Shutdown may have started since the caller checked. A namespace opened now
            // would not be in the entries shutdown takes out, so nobody would ever shut it
            // down.
            self.refuse_if_shut_down()?;
            // The caller checked that the namespace exists; re-check now that we are the
            // one loading it, in case it was discarded or destroyed in between (otherwise
            // we would bring an empty namespace into existence for a name the metastore
            // doesn't know).
            if !self.lazily_created(namespace) && !self.inner.metadata.exists(namespace).await {
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
        }

        let lock = entry.read_arc().await;
        if lock.is_some() {
            return Ok(Some(LoadedNamespace(lock)));
        }
        drop(lock);
        // Emptied by an eviction, the entry is already out of the cache; only an entry that
        // was left empty is still there. `contains_key` records no access and runs no
        // maintenance, unlike the compute call behind `evict_if_still_empty`.
        if self.inner.store.contains_key(namespace) {
            self.evict_if_still_empty(namespace, &entry).await;
        }
        Ok(None)
    }

    #[tracing::instrument(skip_all, fields(namespace))]
    pub async fn create(
        &self,
        namespace: NamespaceName,
        restore_option: RestoreOption,
        db_config: DatabaseConfig,
    ) -> crate::Result<()> {
        self.refuse_if_shut_down()?;

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
            self.load_namespace(&namespace).await?;
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
        let handle = self.inner.metadata.handle(namespace.clone()).await;
        // In memory only: setup reads it; nothing is persisted until setup succeeded.
        handle.store_and_maybe_flush(Some(db_config), false).await?;
        // whatever a creation of this name that never completed left behind
        self.get_configurator(&handle.get())
            .discard_incomplete(namespace)?;
        tracing::debug!("setting up namespace");
        let ns = self
            .make_namespace(namespace, handle.clone(), restore_option)
            .await?;
        self.refuse_if_shut_down()?;
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
    use axum::response::IntoResponse;
    use hyper::StatusCode;
    use tempfile::tempdir;

    use super::*;

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
        let handle = store.inner.metadata.handle(linked.clone()).await;
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
        // `lookup` rather than `load_namespace`: this targets the check inside the load itself,
        // which `load_namespace`'s own check before each attempt would mask.
        let Err(error) = store.lookup(&namespace, &handle).await else {
            panic!("the load was not refused");
        };

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

    #[tokio::test(flavor = "multi_thread")]
    async fn requests_waiting_on_one_evicted_entry_share_one_reloaded_namespace() {
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

        // The entry every request holds is evicted: all of them look the
        // namespace up again at once.
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

        let mut stats = Vec::with_capacity(REQUESTS);
        for request in requests {
            stats.push(request.await.unwrap().unwrap());
        }
        eviction.await.unwrap();
        // The lookups coalesced: one namespace, loaded once, into one fresh
        // entry, not one load per waiting request.
        let cached = store.inner.store.get(&namespace).await.unwrap();
        assert!(!Arc::ptr_eq(&cached, &entry));
        let loaded = cached.read().await.as_ref().unwrap().stats.clone();
        assert!(stats.iter().all(|stats| Arc::ptr_eq(stats, &loaded)));
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
        assert!(
            matches!(error.as_ref(), Error::NamespaceDoesntExist(_)),
            "{error:?}"
        );
        destroy.await.unwrap().unwrap();
        assert!(!store.inner.store.contains_key(&namespace));
    }

    #[tokio::test]
    async fn with_loads_a_namespace_whose_cached_entry_was_left_empty() {
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

    /// Shutdown starts while a creation is setting the namespace up. The creation notices it
    /// at its commit point and is undone: no record is left behind, so a retry against a fresh
    /// store on the same files creates the namespace (with its dump) instead of answering
    /// "already exists".
    #[tokio::test]
    async fn create_interrupted_by_shutdown_leaves_no_record() {
        let tmp = tempdir().unwrap();
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
        store.inner.has_shutdown.store(true, Ordering::Relaxed);
        tx.send(Ok(Bytes::from_static(b"COMMIT;"))).await.unwrap();
        drop(tx);

        let error = create.await.unwrap().unwrap_err();
        assert!(
            matches!(error.as_ref(), Error::NamespaceStoreShutdown),
            "{error:?}"
        );
        assert!(!store.exists(&foo).await);
        assert!(store.inner.in_flight.lock().is_empty());

        drop(store);
        let store = make_store(tmp.path()).await;
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

    #[tokio::test]
    async fn reset_interrupted_by_shutdown_installs_nothing() {
        let tmp = tempdir().unwrap();
        let store = make_store(tmp.path()).await;
        let foo = create(&store, "foo").await;

        let (tx, dump) = slow_dump();
        let reset = tokio::spawn({
            let (store, foo) = (store.clone(), foo.clone());
            async move { store.reset(foo, RestoreOption::Dump(dump)).await }
        });
        tx.send(Ok(Bytes::from_static(
            b"BEGIN TRANSACTION; CREATE TABLE test (x); INSERT INTO test VALUES (1);",
        )))
        .await
        .unwrap();
        wait_until_in_flight(&store, &foo).await;
        // Shutdown does not wait for the reset in progress; it must not install its result.
        store.inner.has_shutdown.store(true, Ordering::Relaxed);
        tx.send(Ok(Bytes::from_static(b"COMMIT;"))).await.unwrap();
        drop(tx);

        let error = reset.await.unwrap().unwrap_err();
        assert!(
            matches!(
                error.downcast_ref::<Error>(),
                Some(Error::NamespaceStoreShutdown)
            ),
            "{error:?}"
        );
        let entry = store
            .inner
            .store
            .get(&foo)
            .await
            .expect("the entry stays cached");
        assert!(entry.read().await.is_none(), "a namespace was installed");
        assert!(store.inner.in_flight.lock().is_empty());
    }

    #[tokio::test]
    async fn shutdown_does_not_wait_for_a_creation_in_progress() {
        let tmp = tempdir().unwrap();
        let store = make_store(tmp.path()).await;
        let foo = NamespaceName::from_string("foo".into()).unwrap();
        let bar = create(&store, "bar").await;

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

        // The creation is blocked on its dump and holds its entry locked. Shutdown must finish
        // without it, and still shut the other namespaces down.
        tokio::time::timeout(Duration::from_secs(5), store.clone().shutdown())
            .await
            .expect("shutdown waited for the creation in progress")
            .unwrap();
        assert!(
            store.inner.store.get(&bar).await.is_none(),
            "the other namespace was not shut down"
        );

        tx.send(Ok(Bytes::from_static(b"COMMIT;"))).await.unwrap();
        drop(tx);
        let error = create.await.unwrap().unwrap_err();
        assert!(
            matches!(error.as_ref(), Error::NamespaceStoreShutdown),
            "{error:?}"
        );
        assert!(!store.exists(&foo).await);
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

    /// An empty entry left cached (a fork that failed before storing its record leaves one) is
    /// taken by the creation's reservation and filled with the new namespace, with its dump
    /// applied. Before, `create` got the empty entry back from the cache and returned without
    /// loading anything.
    #[tokio::test]
    async fn create_over_a_left_empty_entry_applies_its_dump() {
        let tmp = tempdir().unwrap();
        let store = make_store(tmp.path()).await;
        let foo = NamespaceName::from_string("foo".into()).unwrap();
        let empty: NamespaceEntry = Default::default();
        store.inner.store.insert(foo.clone(), empty.clone()).await;

        let (tx, dump) = slow_dump();
        tx.send(Ok(Bytes::from_static(
            b"BEGIN TRANSACTION; CREATE TABLE test (x); INSERT INTO test VALUES (1), (2); COMMIT;",
        )))
        .await
        .unwrap();
        drop(tx);
        store
            .create(foo.clone(), RestoreOption::Dump(dump), Default::default())
            .await
            .unwrap();

        assert_eq!(count_test_rows(&store, "foo").await.unwrap(), 2);
        assert!(store.inner.in_flight.lock().is_empty());
    }

    /// Creating a namespace that exists but is not loaded is refused, and the empty entry the
    /// reservation put in the cache for it is removed again, so the namespace stays reachable.
    #[tokio::test]
    async fn create_of_an_existing_unloaded_namespace_leaves_no_empty_entry() {
        let tmp = tempdir().unwrap();
        let store = make_store(tmp.path()).await;
        let namespace = create(&store, "ns").await;
        store.inner.store.invalidate(&namespace).await;
        store.inner.store.run_pending_tasks().await;

        let error = store
            .create(
                namespace.clone(),
                RestoreOption::Latest,
                DatabaseConfig::default(),
            )
            .await
            .unwrap_err();

        assert!(
            matches!(error, Error::NamespaceAlreadyExist(_)),
            "{error:?}"
        );
        assert!(!store.inner.store.contains_key(&namespace));
        assert_eq!(
            store
                .with(namespace.clone(), |ns| ns.name().clone())
                .await
                .unwrap(),
            namespace
        );
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
        assert!(
            matches!(error.as_ref(), Error::NamespaceStoreShutdown),
            "{error:?}"
        );
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

    /// Clients tell a missing namespace from a temporarily unavailable one by
    /// the status, and some also by the message: a 503 must never read like
    /// a 404.
    #[test]
    fn temporarily_unavailable_messages_do_not_claim_the_namespace_is_missing() {
        for error in [
            Error::NamespaceStoreShutdown,
            Error::NamespaceUnavailable("ns".to_string()),
        ] {
            let message = error.to_string();
            assert!(!message.contains("doesn't exist"), "{message}");
            assert!(!message.contains("not found"), "{message}");
        }
        assert!(Error::NamespaceDoesntExist("ns".to_string())
            .to_string()
            .contains("doesn't exist"));
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
