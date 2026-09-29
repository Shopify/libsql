use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_lock::RwLock;
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
use super::fence::command::{FenceCommand, FenceRequest};
use super::fence::controller::{FenceController, Transition};
use super::fence::hooks::HookPoint;
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

        // The destination is refused before anything is stored for it when it is being created
        // as a migration target or its fence state is unknown.
        self.inner.fences.check_available(&to)?;

        // check that the source namespace exists
        if !self.inner.metadata.exists(&from).await {
            return Err(crate::error::Error::NamespaceDoesntExist(from.to_string()));
        }

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

        let Some(from_config) = self.inner.metadata.lookup(&from).await? else {
            return Err(crate::Error::NamespaceDoesntExist(from.to_string()));
        };
        let from_entry = self
            .load_namespace(&from, from_config.clone(), RestoreOption::Latest)
            .await?;
        let from_lock = from_entry.read().await;
        let Some(from_ns) = &*from_lock else {
            return Err(crate::error::Error::NamespaceDoesntExist(from.to_string()));
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

        let handle = self.inner.metadata.handle(to.clone()).await?;
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

        // With namespaces disabled, the default namespace can be auto-created,
        // otherwise it's an error.
        // FIXME: move the default namespace check out of this function.
        if self.inner.allow_lazy_creation || namespace == NamespaceName::default() {
            tracing::trace!("auto-creating the namespace");
        } else if self.inner.metadata.exists(&namespace).await {
            return Err(Error::NamespaceAlreadyExist(namespace.to_string()));
        }

        let db_config = Arc::new(db_config);
        let handle = self.inner.metadata.handle(namespace.clone()).await?;
        tracing::debug!("storing db config");
        handle.store(db_config).await?;
        tracing::debug!("completed storing db config, loading namespace");
        self.load_namespace(&namespace, handle, restore_option)
            .await?;

        tracing::debug!("completed loading namespace");

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
