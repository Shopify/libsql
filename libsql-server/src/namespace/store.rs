use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::{Mutex as StdMutex, Weak};

use async_lock::RwLock;
use chrono::NaiveDateTime;
use futures::TryFutureExt;
use moka::future::Cache;
use once_cell::sync::OnceCell;
use tokio::sync::OwnedMutexGuard;
use tokio::task::JoinSet;
use tokio::time::{Duration, Instant};
use tokio_stream::wrappers::BroadcastStream;

use crate::auth::Authenticated;
use crate::broadcaster::BroadcastMsg;
use crate::connection::config::DatabaseConfig;
use crate::database::DatabaseKind;
use crate::error::Error;
use crate::metrics::{NAMESPACE_LOAD_LATENCY, NAMESPACE_QUARANTINE_COUNT};
use crate::namespace::{NamespaceBottomlessDbId, NamespaceBottomlessDbIdInit, NamespaceName};
use crate::stats::Stats;

use super::broadcasters::{BroadcasterHandle, BroadcasterRegistry};
use super::cleanup_guard::{CleanupFuture, DeferredCleanup};
use super::configurator::{DynConfigurator, NamespaceConfigurators};
use super::meta_store::{MetaStore, MetaStoreHandle};
use super::schema_lock::SchemaLocksRegistry;
use super::{Namespace, ResetCb, ResetOp, ResolveNamespacePathFn, RestoreOption};

type NamespaceEntry = Arc<RwLock<Option<Namespace>>>;

#[derive(serde::Serialize, serde::Deserialize)]
struct ResetIntent {
    old_identity: (u64, u64),
    old_config: Vec<u8>,
}

// A new directory is owned only after create_dir succeeds. Dropping a
// reservation never deletes by path: cancellation without a cleanup worker
// must leave a safe, explicit orphan instead of racing a later creator.
struct DirectoryReservation {
    path: PathBuf,
    identity: Option<(u64, u64)>,
    owned: bool,
}

struct PendingCleanup {
    metadata: MetaStore,
    namespace: NamespaceName,
    directory: DirectoryReservation,
    // Held across the queued-write barrier, metadata removal, and disk cleanup.
    _operation: Vec<OwnedMutexGuard<()>>,
}

type CleanupGuard = DeferredCleanup<PendingCleanup>;

fn pending_cleanup(
    metadata: MetaStore,
    namespace: NamespaceName,
    directory: DirectoryReservation,
    operation: Vec<OwnedMutexGuard<()>>,
) -> CleanupGuard {
    fn run(pending: PendingCleanup, remove_directory: bool) -> CleanupFuture {
        Box::pin(pending.run(remove_directory))
    }
    CleanupGuard::new(
        PendingCleanup {
            metadata,
            namespace,
            directory,
            _operation: operation,
        },
        run,
    )
}

impl PendingCleanup {
    async fn run(mut self, remove_directory: bool) {
        if !remove_directory {
            // A cancelled filesystem future may still run in Tokio's blocking
            // pool. Retain its exact path so late writes cannot hit a retry.
            tracing::warn!(
                "quarantining cancelled namespace directory {:?}",
                self.directory.path
            );
            NAMESPACE_QUARANTINE_COUNT.increment(1);
            self.directory.disarm();
        }
        if let Err(e) = self.metadata.wait_for_pending_changes().await {
            tracing::error!("namespace cleanup quarantined after config barrier failure: {e}");
            return;
        }
        // Once started, the blocking closure owns the operation guard, so
        // cancellation of this async task cannot release it while removal is
        // running (or let an older cleanup delete a later reservation).
        let task = tokio::task::spawn_blocking(move || {
            if let Err(e) = self.metadata.remove(self.namespace) {
                tracing::error!("namespace cleanup quarantined after metadata failure: {e}");
                return;
            }
            self.directory.remove_if_owned();
        });
        if let Err(e) = task.await {
            tracing::error!("namespace cleanup worker failed: {e}");
        }
    }
}

// Unix directory fsync orders the intent's publication ahead of SQLite's
// delete commit. Windows does not expose a portable directory fsync here:
// process-crash recovery works, but sudden-power-loss durability is NOT
// promised on Windows (nor does macOS fsync imply hardware F_FULLFSYNC).
fn sync_directory(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    std::fs::File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn directory_identity(metadata: &std::fs::Metadata) -> Option<(u64, u64)> {
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some((metadata.dev(), metadata.ino()))
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        Some((
            metadata.volume_serial_number()? as u64,
            metadata.file_index()?,
        ))
    }
    #[cfg(not(any(unix, windows)))]
    {
        None
    }
}

impl Drop for DirectoryReservation {
    fn drop(&mut self) {
        if self.owned {
            tracing::warn!(
                "leaving reserved namespace directory {:?} for repair",
                self.path
            );
        }
    }
}

impl DirectoryReservation {
    fn disarm(&mut self) {
        self.owned = false;
    }

    fn remove_if_owned(mut self) {
        if !self.owned {
            return;
        }
        // A replaced entry (or an unavailable identity) is not ours to
        // remove. This is run on a blocking worker, never in Drop.
        let still_owned = self.identity.is_some_and(|identity| {
            std::fs::symlink_metadata(&self.path)
                .ok()
                .and_then(|m| directory_identity(&m))
                == Some(identity)
        });
        if still_owned {
            if let Err(e) = std::fs::remove_dir_all(&self.path) {
                tracing::error!(
                    "failed to clean reserved namespace directory {:?}: {e}",
                    self.path
                );
            }
        } else {
            tracing::warn!(
                "leaving replaced or unidentified namespace directory {:?}",
                self.path
            );
        }
        self.disarm();
    }
}

#[cfg(test)]
mod directory_tests {
    use super::*;
    use crate::namespace::configurator::{
        BaseNamespaceConfig, ConfigureNamespace, PrimaryConfig, PrimaryConfigurator,
    };
    use crate::namespace::meta_store::metastore_connection_maker;
    use libsql_sys::wal::Sqlite3WalManager;
    use prost::Message;
    use tokio::sync::{Notify, Semaphore};
    use tokio::time::timeout;

    struct StalledCleanupConfigurator {
        primary: PrimaryConfigurator,
        entered: Arc<Notify>,
        release: Arc<Notify>,
        fail_backup: bool,
    }

    impl ConfigureNamespace for StalledCleanupConfigurator {
        fn setup<'a>(
            &'a self,
            db_config: MetaStoreHandle,
            restore: RestoreOption,
            name: &'a NamespaceName,
            reset: ResetCb,
            resolve: ResolveNamespacePathFn,
            store: NamespaceStore,
            broadcaster: BroadcasterHandle,
        ) -> std::pin::Pin<Box<dyn futures::Future<Output = crate::Result<Namespace>> + Send + 'a>>
        {
            self.primary
                .setup(db_config, restore, name, reset, resolve, store, broadcaster)
        }

        fn prepare_cleanup<'a>(
            &'a self,
            namespace: &'a NamespaceName,
            config: &'a DatabaseConfig,
            prune_all: bool,
            init: NamespaceBottomlessDbIdInit,
        ) -> std::pin::Pin<Box<dyn futures::Future<Output = crate::Result<()>> + Send + 'a>>
        {
            Box::pin(async move {
                self.entered.notify_one();
                self.release.notified().await;
                if self.fail_backup {
                    return Err(Error::InvalidPath(
                        "injected backup confirmation failure".into(),
                    ));
                }
                self.primary
                    .prepare_cleanup(namespace, config, prune_all, init)
                    .await
            })
        }

        fn fork<'a>(
            &'a self,
            source: &'a Namespace,
            source_config: MetaStoreHandle,
            destination: NamespaceName,
            dest_config: MetaStoreHandle,
            timestamp: Option<NaiveDateTime>,
            store: NamespaceStore,
        ) -> std::pin::Pin<Box<dyn futures::Future<Output = crate::Result<Namespace>> + Send + 'a>>
        {
            self.primary.fork(
                source,
                source_config,
                destination,
                dest_config,
                timestamp,
                store,
            )
        }
    }

    async fn cleanup_fixture() -> (
        tempfile::TempDir,
        MetaStore,
        Arc<tokio::sync::Mutex<()>>,
        CleanupGuard,
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let (maker, wal) = metastore_connection_maker(None, tmp.path()).await.unwrap();
        let metadata = MetaStore::new(
            Default::default(),
            tmp.path(),
            maker().unwrap(),
            wal,
            DatabaseKind::Primary,
        )
        .await
        .unwrap();
        let dbs = tmp.path().join("dbs");
        std::fs::create_dir(&dbs).unwrap();
        let path = dbs.join("failed");
        std::fs::create_dir(&path).unwrap();
        let reservation = DirectoryReservation {
            identity: directory_identity(&std::fs::symlink_metadata(&path).unwrap()),
            path,
            owned: true,
        };
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        let operation = lock.clone().lock_owned().await;
        let cleanup = pending_cleanup(
            metadata.clone(),
            NamespaceName::from("failed"),
            reservation,
            vec![operation],
        );
        (tmp, metadata, lock, cleanup)
    }

    async fn primary_fixture() -> (tempfile::TempDir, NamespaceStore) {
        primary_fixture_with_cleanup_gate(None).await
    }

    async fn reopened_store(tmp: &tempfile::TempDir) -> NamespaceStore {
        let (maker, wal) = metastore_connection_maker(None, tmp.path()).await.unwrap();
        let metadata = MetaStore::new(
            crate::config::MetaStoreConfig {
                allow_recover_from_fs: true,
                ..Default::default()
            },
            tmp.path(),
            maker().unwrap(),
            wal,
            DatabaseKind::Primary,
        )
        .await
        .unwrap();
        NamespaceStore::new(
            false,
            false,
            10,
            metadata,
            NamespaceConfigurators::empty(),
            DatabaseKind::Primary,
            tmp.path(),
        )
        .await
        .unwrap()
    }

    async fn primary_fixture_with_cleanup_gate(
        gate: Option<(Arc<Notify>, Arc<Notify>, bool)>,
    ) -> (tempfile::TempDir, NamespaceStore) {
        let tmp = tempfile::tempdir().unwrap();
        let (maker, wal) = metastore_connection_maker(None, tmp.path()).await.unwrap();
        let metadata = MetaStore::new(
            Default::default(),
            tmp.path(),
            maker().unwrap(),
            wal,
            DatabaseKind::Primary,
        )
        .await
        .unwrap();
        let base = BaseNamespaceConfig {
            base_path: tmp.path().to_path_buf().into(),
            extensions: Arc::new([]),
            stats_sender: tokio::sync::mpsc::channel(1).0,
            max_response_size: 100000000000000,
            max_total_response_size: 100000000000,
            max_concurrent_connections: Arc::new(Semaphore::new(10)),
            max_concurrent_requests: 10000,
            encryption_config: None,
            connection_creation_timeout: None,
            disable_intelligent_throttling: false,
        };
        let primary = PrimaryConfig {
            max_log_size: 1000000000,
            max_log_duration: None,
            bottomless_replication: None,
            scripted_backup: None,
            checkpoint_interval: None,
        };
        let mut configurators = NamespaceConfigurators::empty();
        let primary =
            PrimaryConfigurator::new(base, primary, Arc::new(|| Sqlite3WalManager::default()));
        if let Some((entered, release, fail_backup)) = gate {
            configurators.with_primary(StalledCleanupConfigurator {
                primary,
                entered,
                release,
                fail_backup,
            });
        } else {
            configurators.with_primary(primary);
        }
        let store = NamespaceStore::new(
            false,
            false,
            10,
            metadata,
            configurators,
            DatabaseKind::Primary,
            tmp.path(),
        )
        .await
        .unwrap();
        (tmp, store)
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn ensure_existing_directory_single_scan_rejects_symlink_alias() {
        use std::os::unix::fs::symlink;
        let (tmp, store) = primary_fixture().await;
        let real = tmp.path().join("dbs/real");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::write(real.join("sentinel"), b"real").unwrap();
        symlink(&real, tmp.path().join("dbs/alias")).unwrap();
        assert!(store
            .ensure_existing_directory(&NamespaceName::from("alias"))
            .await
            .is_err());
        assert!(store
            .ensure_existing_directory(&NamespaceName::from("real"))
            .await
            .unwrap()
            .is_none());
        assert_eq!(std::fs::read(real.join("sentinel")).unwrap(), b"real");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cache_miss_does_not_resurrect_primary_after_concurrent_destroy() {
        let (tmp, store) = primary_fixture().await;
        let name = NamespaceName::from("victim");
        store
            .create(
                name.clone(),
                RestoreOption::Latest,
                DatabaseConfig::default(),
            )
            .await
            .unwrap();
        store.evict_cached_namespace(&name).await;
        let entered = Arc::new(Notify::new());
        let resume = Arc::new(Notify::new());
        let read = tokio::spawn({
            let store = store.clone();
            let name = name.clone();
            let entered = entered.clone();
            let resume = resume.clone();
            async move {
                store
                    .with_after_initial_check(name, |ns| ns.path.clone(), async move {
                        entered.notify_one();
                        resume.notified().await;
                    })
                    .await
            }
        });
        timeout(Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        store.destroy(name.clone(), false).await.unwrap();
        resume.notify_one();
        assert!(matches!(
            timeout(Duration::from_secs(5), read)
                .await
                .unwrap()
                .unwrap(),
            Err(Error::NamespaceDoesntExist(_))
        ));
        assert!(!store.exists(&name).await);
        assert!(!tmp.path().join("dbs/victim").exists());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn delete_fences_delayed_config_handle_and_new_create_gets_new_generation() {
        let (tmp, store) = primary_fixture().await;
        let name = NamespaceName::from("tenant");
        store
            .create(
                name.clone(),
                RestoreOption::Latest,
                DatabaseConfig::default(),
            )
            .await
            .unwrap();
        let stale = store.config_store(name.clone()).await.unwrap();
        store.destroy(name.clone(), false).await.unwrap();
        assert!(!tmp.path().join("dbs/tenant").exists());
        assert!(!store.exists(&name).await);
        assert!(matches!(
            stale.store(DatabaseConfig::default()).await,
            Err(Error::NamespaceDoesntExist(_))
        ));
        store
            .create(
                name.clone(),
                RestoreOption::Latest,
                DatabaseConfig::default(),
            )
            .await
            .unwrap();
        assert!(matches!(
            stale.store(DatabaseConfig::default()).await,
            Err(Error::NamespaceDoesntExist(_))
        ));
        assert!(store.exists(&name).await);
        assert!(tmp.path().join("dbs/tenant").exists());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn reset_rotates_config_generation_without_dropping_new_writes() {
        let (_tmp, store) = primary_fixture().await;
        let name = NamespaceName::from("tenant");
        store
            .create(
                name.clone(),
                RestoreOption::Latest,
                DatabaseConfig::default(),
            )
            .await
            .unwrap();
        let stale = store.config_store(name.clone()).await.unwrap();
        store
            .reset(name.clone(), RestoreOption::Latest)
            .await
            .unwrap();
        assert!(matches!(
            stale.store(DatabaseConfig::default()).await,
            Err(Error::NamespaceDoesntExist(_))
        ));
        store
            .config_store(name.clone())
            .await
            .unwrap()
            .store(DatabaseConfig::default())
            .await
            .unwrap();
        assert!(store.exists(&name).await);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn teardown_refuses_replaced_directory_and_preserves_both_inodes() {
        let (tmp, store) = primary_fixture().await;
        let name = NamespaceName::from("victim");
        let path = tmp.path().join("dbs/victim");
        std::fs::create_dir_all(&path).unwrap();
        let expected = store.cleanup_directory_identity(&name).await.unwrap();
        std::fs::rename(&path, tmp.path().join("original")).unwrap();
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("sentinel"), b"new owner").unwrap();
        assert!(store
            .detach_owned_directory(&name, expected, false, None)
            .await
            .is_err());
        assert_eq!(std::fs::read(path.join("sentinel")).unwrap(), b"new owner");
        assert!(tmp.path().join("original").exists());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stalled_destroy_backup_does_not_serialize_unrelated_namespaces() {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let (tmp, store) =
            primary_fixture_with_cleanup_gate(Some((entered.clone(), release.clone(), false)))
                .await;
        let victim = NamespaceName::from("victim");
        store
            .create(
                victim.clone(),
                RestoreOption::Latest,
                DatabaseConfig::default(),
            )
            .await
            .unwrap();
        let victim_path = tmp.path().join("dbs/victim");
        std::fs::write(victim_path.join("sentinel"), b"old data").unwrap();
        let destroy = tokio::spawn({
            let store = store.clone();
            let victim = victim.clone();
            async move { store.destroy(victim, false).await }
        });
        timeout(Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(victim_path.join("sentinel")).unwrap(),
            b"old data"
        );
        // This is an actual store/configurator cleanup halted at the point
        // where bottomless savepoint().confirmed() would await remote I/O.
        timeout(
            Duration::from_secs(5),
            store.create(
                NamespaceName::from("unrelated"),
                RestoreOption::Latest,
                DatabaseConfig::default(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        let retry = tokio::spawn({
            let store = store.clone();
            let victim = victim.clone();
            async move {
                store
                    .create(victim, RestoreOption::Latest, DatabaseConfig::default())
                    .await
            }
        });
        tokio::task::yield_now().await;
        assert!(!retry.is_finished());
        assert!(victim_path.join("sentinel").exists());
        release.notify_one();
        timeout(Duration::from_secs(5), destroy)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        timeout(Duration::from_secs(5), retry)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(!victim_path.join("sentinel").exists());
        assert!(store.exists(&victim).await);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn reset_setup_failure_fences_old_data_until_restart() {
        let (tmp, store) = primary_fixture().await;
        let name = NamespaceName::from("victim");
        store
            .create(
                name.clone(),
                RestoreOption::Latest,
                DatabaseConfig::default(),
            )
            .await
            .unwrap();
        let path = tmp.path().join("dbs/victim");
        std::fs::write(path.join("sentinel"), b"old").unwrap();
        let old = store.cleanup_directory_identity(&name).await.unwrap();
        let dump = futures::stream::iter(vec![Ok(bytes::Bytes::from_static(b"not valid SQL;"))]);
        assert!(store
            .reset(name.clone(), RestoreOption::Dump(Box::new(dump)))
            .await
            .is_err());
        assert_eq!(
            std::fs::read(store.reset_quarantine_path(&name).join("sentinel")).unwrap(),
            b"old"
        );
        assert!(store.reset_intent_path(&name).exists());
        assert!(store.lock_names(&[name.clone()]).await.is_err());
        // Simulate config changes from setup that must not remain paired with
        // the restored old database after process restart.
        let mut changed = DatabaseConfig::default();
        changed.block_reads = true;
        store
            .inner
            .metadata
            .handle(name.clone())
            .await
            .store(changed)
            .await
            .unwrap();
        drop(store);
        let restarted = reopened_store(&tmp).await;
        assert_eq!(
            restarted.cleanup_directory_identity(&name).await.unwrap(),
            old
        );
        assert_eq!(std::fs::read(path.join("sentinel")).unwrap(), b"old");
        assert!(
            !restarted
                .inner
                .metadata
                .handle(name.clone())
                .await
                .get()
                .block_reads
        );
        assert!(!restarted.reset_intent_path(&name).exists());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_reset_waiter_cannot_release_name_lock_during_setup() {
        let (tmp, store) = primary_fixture().await;
        let name = NamespaceName::from("victim");
        store
            .create(
                name.clone(),
                RestoreOption::Latest,
                DatabaseConfig::default(),
            )
            .await
            .unwrap();
        let path = tmp.path().join("dbs/victim");
        std::fs::write(path.join("sentinel"), b"old").unwrap();
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let dump = futures::stream::once({
            let entered = entered.clone();
            let release = release.clone();
            async move {
                entered.notify_one();
                release.notified().await;
                Ok(bytes::Bytes::from_static(b"not valid SQL;"))
            }
        });
        let waiter = tokio::spawn({
            let store = store.clone();
            let name = name.clone();
            async move {
                store
                    .reset(name, RestoreOption::Dump(Box::new(Box::pin(dump))))
                    .await
            }
        });
        timeout(Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        let name_lock = store
            .inner
            .name_operations
            .lock()
            .unwrap()
            .get(&name)
            .unwrap()
            .upgrade()
            .unwrap();
        assert!(
            timeout(Duration::from_millis(50), name_lock.clone().lock_owned())
                .await
                .is_err()
        );
        release.notify_one();
        // The detached owner finishes (or safely fences on setup failure)
        // before a new same-name operation can proceed.
        let guard = timeout(Duration::from_secs(5), name_lock.lock_owned())
            .await
            .unwrap();
        assert!(store.reset_intent_path(&name).exists());
        assert_eq!(
            std::fs::read(store.reset_quarantine_path(&name).join("sentinel")).unwrap(),
            b"old"
        );
        drop(guard);
        drop(store);
        let restarted = reopened_store(&tmp).await;
        assert_eq!(std::fs::read(path.join("sentinel")).unwrap(), b"old");
        assert!(!restarted.reset_intent_path(&name).exists());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn restart_reconciles_reset_at_each_boundary() {
        let name = NamespaceName::from("victim");
        for stage in 0..7 {
            let (tmp, store) = primary_fixture().await;
            store
                .create(
                    name.clone(),
                    RestoreOption::Latest,
                    DatabaseConfig::default(),
                )
                .await
                .unwrap();
            store.evict_cached_namespace(&name).await;
            let path = tmp.path().join("dbs/victim");
            std::fs::write(path.join("sentinel"), b"old").unwrap();
            let expected = store
                .cleanup_directory_identity(&name)
                .await
                .unwrap()
                .unwrap();
            let old_config = tokio::task::spawn_blocking({
                let metadata = store.inner.metadata.clone();
                let name = name.clone();
                move || metadata.pin_reset_and_snapshot(&name).unwrap()
            })
            .await
            .unwrap();
            let bytes = serde_json::to_vec(&ResetIntent {
                old_identity: expected,
                old_config,
            })
            .unwrap();
            store
                .publish_reset_file(&store.reset_intent_path(&name), &bytes)
                .unwrap();
            if stage >= 1 {
                store
                    .detach_owned_directory(
                        &name,
                        Some(expected),
                        true,
                        Some(store.reset_quarantine_path(&name)),
                    )
                    .await
                    .unwrap();
                if stage >= 2 {
                    std::fs::write(path.join("partial"), b"new").unwrap();
                }
                let mut changed = DatabaseConfig::default();
                changed.block_reads = true;
                store
                    .inner
                    .metadata
                    .handle(name.clone())
                    .await
                    .store(changed)
                    .await
                    .unwrap();
            }
            if stage >= 3 {
                let fresh = store
                    .cleanup_directory_identity(&name)
                    .await
                    .unwrap()
                    .unwrap();
                store
                    .publish_reset_file(
                        &store.reset_committed_path(&name),
                        format!("committed {} {}\n", fresh.0, fresh.1).as_bytes(),
                    )
                    .unwrap();
            }
            if stage >= 4 {
                std::fs::remove_dir_all(store.reset_quarantine_path(&name)).unwrap();
            }
            if stage >= 5 {
                std::fs::remove_file(store.reset_intent_path(&name)).unwrap();
            }
            if stage == 6 {
                std::fs::remove_file(store.reset_committed_path(&name)).unwrap();
            }
            drop(store);
            let restarted = reopened_store(&tmp).await;
            assert!(!restarted.reset_intent_path(&name).exists());
            assert!(!restarted.reset_committed_path(&name).exists());
            if stage < 3 {
                assert_eq!(
                    restarted.cleanup_directory_identity(&name).await.unwrap(),
                    Some(expected)
                );
                assert_eq!(std::fs::read(path.join("sentinel")).unwrap(), b"old");
                assert!(
                    !restarted
                        .inner
                        .metadata
                        .handle(name.clone())
                        .await
                        .get()
                        .block_reads
                );
                if stage >= 1 {
                    assert!(
                        std::fs::read_dir(tmp.path().join("namespace-reset-abandoned"))
                            .unwrap()
                            .next()
                            .is_some()
                    );
                }
            } else {
                assert_ne!(
                    restarted.cleanup_directory_identity(&name).await.unwrap(),
                    Some(expected)
                );
                assert_eq!(std::fs::read(path.join("partial")).unwrap(), b"new");
                assert!(
                    restarted
                        .inner
                        .metadata
                        .handle(name.clone())
                        .await
                        .get()
                        .block_reads
                );
                assert!(!restarted.reset_quarantine_path(&name).exists());
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pending_reset_refuses_schema_switch_and_keeps_migration_membership() {
        let (tmp, store) = primary_fixture().await;
        let tenant = NamespaceName::from("tenant");
        store
            .create(
                tenant.clone(),
                RestoreOption::Latest,
                DatabaseConfig::default(),
            )
            .await
            .unwrap();
        store.evict_cached_namespace(&tenant).await;
        std::fs::write(tmp.path().join("dbs/tenant/sentinel"), b"old tenant").unwrap();
        {
            let conn = store.inner.metadata.hold_connection_for_test().await;
            conn.execute_batch("CREATE TABLE jobs (schema TEXT, finished BOOLEAN)")
                .unwrap();
        }
        let a = NamespaceName::from("schema-a");
        let b = NamespaceName::from("schema-b");
        let mut schema_config = DatabaseConfig::default();
        schema_config.is_shared_schema = true;
        store
            .inner
            .metadata
            .handle(a.clone())
            .await
            .store(schema_config.clone())
            .await
            .unwrap();
        store
            .inner
            .metadata
            .handle(b.clone())
            .await
            .store(schema_config)
            .await
            .unwrap();
        let mut linked = DatabaseConfig::default();
        linked.shared_schema_name = Some(a.clone());
        store
            .inner
            .metadata
            .handle(tenant.clone())
            .await
            .store(linked.clone())
            .await
            .unwrap();
        let old_identity = store
            .cleanup_directory_identity(&tenant)
            .await
            .unwrap()
            .unwrap();
        let old_config = tokio::task::spawn_blocking({
            let metadata = store.inner.metadata.clone();
            let tenant = tenant.clone();
            move || metadata.pin_reset_and_snapshot(&tenant).unwrap()
        })
        .await
        .unwrap();
        store
            .publish_reset_file(
                &store.reset_intent_path(&tenant),
                &serde_json::to_vec(&ResetIntent {
                    old_identity,
                    old_config,
                })
                .unwrap(),
            )
            .unwrap();
        store
            .detach_owned_directory(
                &tenant,
                Some(old_identity),
                true,
                Some(store.reset_quarantine_path(&tenant)),
            )
            .await
            .unwrap();
        assert!(store.ensure_schema_has_no_pending_resets(&a).await.is_err());
        linked.shared_schema_name = Some(b.clone());
        // Refuse the switch rather than create a second A+B link: links are
        // also the schema migration worklist, not only a deletion guard.
        assert!(store
            .inner
            .metadata
            .handle(tenant.clone())
            .await
            .store(linked)
            .await
            .is_err());
        let remove_a = tokio::task::spawn_blocking({
            let metadata = store.inner.metadata.clone();
            let a = a.clone();
            move || metadata.remove(a)
        })
        .await
        .unwrap();
        assert!(matches!(remove_a, Err(crate::Error::HasLinkedDbs(_))));
        drop(store);
        let restarted = reopened_store(&tmp).await;
        assert!(restarted
            .ensure_schema_has_no_pending_resets(&a)
            .await
            .is_ok());
        assert_eq!(
            restarted.cleanup_directory_identity(&tenant).await.unwrap(),
            Some(old_identity)
        );
        assert_eq!(
            std::fs::read(tmp.path().join("dbs/tenant/sentinel")).unwrap(),
            b"old tenant"
        );
        assert_eq!(
            restarted
                .inner
                .metadata
                .handle(tenant.clone())
                .await
                .get()
                .shared_schema_name
                .as_ref(),
            Some(&a)
        );
        let conn = restarted.inner.metadata.hold_connection_for_test().await;
        let links_a: i64 = conn.query_row(
            "SELECT count(*) FROM shared_schema_links WHERE shared_schema_name = 'schema-a' AND namespace = 'tenant'",
            [], |row| row.get(0)).unwrap();
        let links_b: i64 = conn.query_row(
            "SELECT count(*) FROM shared_schema_links WHERE shared_schema_name = 'schema-b' AND namespace = 'tenant'",
            [], |row| row.get(0)).unwrap();
        assert_eq!((links_a, links_b), (1, 0));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn schema_own_reset_blocks_migration_registration_until_recovered() {
        let (tmp, store) = primary_fixture().await;
        let schema = NamespaceName::from("schema-a");
        let mut config = DatabaseConfig::default();
        config.is_shared_schema = true;
        store
            .inner
            .metadata
            .handle(schema.clone())
            .await
            .store(config)
            .await
            .unwrap();
        std::fs::create_dir_all(tmp.path().join("dbs/schema-a")).unwrap();
        let old = store
            .cleanup_directory_identity(&schema)
            .await
            .unwrap()
            .unwrap();
        let snapshot = tokio::task::spawn_blocking({
            let metadata = store.inner.metadata.clone();
            let schema = schema.clone();
            move || metadata.pin_reset_and_snapshot(&schema).unwrap()
        })
        .await
        .unwrap();
        assert_eq!(
            MetaStore::reset_snapshot_schema_lock(&schema, &snapshot).unwrap(),
            Some(schema.clone())
        );
        let shared = store.schema_locks().acquire_shared(schema.clone()).await;
        let registration = tokio::spawn({
            let store = store.clone();
            let schema = schema.clone();
            async move {
                let _exclusive = store.schema_locks().acquire_exlusive(schema.clone()).await;
                store.ensure_schema_has_no_pending_resets(&schema).await
            }
        });
        tokio::task::yield_now().await;
        assert!(!registration.is_finished());
        let intent = serde_json::to_vec(&ResetIntent {
            old_identity: old,
            old_config: snapshot,
        })
        .unwrap();
        store
            .publish_reset_file(&store.reset_intent_path(&schema), &intent)
            .unwrap();
        drop(shared);
        assert!(timeout(Duration::from_secs(5), registration)
            .await
            .unwrap()
            .unwrap()
            .is_err());
        drop(store);
        let restarted = reopened_store(&tmp).await;
        assert!(!restarted.reset_intent_path(&schema).exists());
        assert_eq!(
            restarted.cleanup_directory_identity(&schema).await.unwrap(),
            Some(old)
        );
        assert!(restarted
            .ensure_schema_has_no_pending_resets(&schema)
            .await
            .is_ok());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn reset_refuses_pending_schema_migration_before_detaching_old_data() {
        let (_tmp, store) = primary_fixture().await;
        let name = NamespaceName::from("tenant");
        store
            .create(
                name.clone(),
                RestoreOption::Latest,
                DatabaseConfig::default(),
            )
            .await
            .unwrap();
        let a = NamespaceName::from("schema-a");
        {
            let conn = store.inner.metadata.hold_connection_for_test().await;
            conn.execute_batch("CREATE TABLE jobs (schema TEXT, finished BOOLEAN)")
                .unwrap();
        }
        store
            .inner
            .metadata
            .handle(a.clone())
            .await
            .store(DatabaseConfig::default())
            .await
            .unwrap();
        let mut linked = DatabaseConfig::default();
        linked.shared_schema_name = Some(a);
        store
            .inner
            .metadata
            .handle(name.clone())
            .await
            .store(linked)
            .await
            .unwrap();
        {
            let conn = store.inner.metadata.hold_connection_for_test().await;
            conn.execute("INSERT INTO jobs VALUES ('schema-a', false)", [])
                .unwrap();
        }
        let old = store.cleanup_directory_identity(&name).await.unwrap();
        assert!(store
            .reset(name.clone(), RestoreOption::Latest)
            .await
            .is_err());
        assert_eq!(store.cleanup_directory_identity(&name).await.unwrap(), old);
        assert!(!store.reset_intent_path(&name).exists());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn reset_schema_lock_uses_persisted_snapshot_not_stale_watch() {
        let (_tmp, store) = primary_fixture().await;
        let tenant = NamespaceName::from("tenant");
        store
            .create(
                tenant.clone(),
                RestoreOption::Latest,
                DatabaseConfig::default(),
            )
            .await
            .unwrap();
        let a = NamespaceName::from("schema-a");
        let b = NamespaceName::from("schema-b");
        {
            let conn = store.inner.metadata.hold_connection_for_test().await;
            conn.execute_batch("CREATE TABLE jobs (schema TEXT, finished BOOLEAN)")
                .unwrap();
        }
        store
            .inner
            .metadata
            .handle(a.clone())
            .await
            .store(DatabaseConfig::default())
            .await
            .unwrap();
        store
            .inner
            .metadata
            .handle(b.clone())
            .await
            .store(DatabaseConfig::default())
            .await
            .unwrap();
        let mut linked = DatabaseConfig::default();
        linked.shared_schema_name = Some(b);
        store
            .inner
            .metadata
            .handle(tenant.clone())
            .await
            .store(linked.clone())
            .await
            .unwrap();
        // Reproduce the worker gap after SQL committed A but before it updates
        // the watch: the cache still says B while the old row/link says A.
        linked.shared_schema_name = Some(a.clone());
        let encoded =
            libsql_replication::rpc::metadata::DatabaseConfig::from(&linked).encode_to_vec();
        {
            let conn = store.inner.metadata.hold_connection_for_test().await;
            conn.execute(
                "UPDATE namespace_configs SET config = ?1 WHERE namespace = 'tenant'",
                [encoded],
            )
            .unwrap();
            conn.execute(
                "DELETE FROM shared_schema_links WHERE namespace = 'tenant'",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO shared_schema_links VALUES ('schema-a', 'tenant')",
                [],
            )
            .unwrap();
            conn.execute("INSERT INTO jobs VALUES ('schema-a', false)", [])
                .unwrap();
        }
        let old = store.cleanup_directory_identity(&tenant).await.unwrap();
        assert!(store
            .reset(tenant.clone(), RestoreOption::Latest)
            .await
            .is_err());
        assert_eq!(
            store.cleanup_directory_identity(&tenant).await.unwrap(),
            old
        );
        assert!(!store.reset_intent_path(&tenant).exists());
        assert_eq!(
            store
                .inner
                .metadata
                .handle(tenant)
                .await
                .get()
                .shared_schema_name,
            Some(a)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn failed_reset_journal_publication_releases_ephemeral_schema_pin() {
        let (tmp, store) = primary_fixture().await;
        let name = NamespaceName::from("tenant");
        store
            .create(
                name.clone(),
                RestoreOption::Latest,
                DatabaseConfig::default(),
            )
            .await
            .unwrap();
        let old = store.cleanup_directory_identity(&name).await.unwrap();
        std::fs::write(
            tmp.path().join("namespace-reset-intents"),
            b"not a directory",
        )
        .unwrap();
        assert!(store
            .reset(name.clone(), RestoreOption::Latest)
            .await
            .is_err());
        assert_eq!(store.cleanup_directory_identity(&name).await.unwrap(), old);
        // The failed temporary journal write must not leave an invisible
        // in-memory pin blocking otherwise valid config updates.
        {
            let conn = store.inner.metadata.hold_connection_for_test().await;
            conn.execute_batch("CREATE TABLE jobs (schema TEXT, finished BOOLEAN)")
                .unwrap();
        }
        let schema = NamespaceName::from("schema-b");
        store
            .inner
            .metadata
            .handle(schema.clone())
            .await
            .store(DatabaseConfig::default())
            .await
            .unwrap();
        let mut changed = DatabaseConfig::default();
        changed.shared_schema_name = Some(schema);
        store
            .inner
            .metadata
            .handle(name.clone())
            .await
            .store(changed)
            .await
            .unwrap();
        assert!(!store.reset_intent_path(&name).exists());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn failed_reset_backup_preserves_old_inode_without_journal() {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let (tmp, store) =
            primary_fixture_with_cleanup_gate(Some((entered.clone(), release.clone(), true))).await;
        let name = NamespaceName::from("victim");
        store
            .create(
                name.clone(),
                RestoreOption::Latest,
                DatabaseConfig::default(),
            )
            .await
            .unwrap();
        let path = tmp.path().join("dbs/victim");
        std::fs::write(path.join("sentinel"), b"old data").unwrap();
        let old = store.cleanup_directory_identity(&name).await.unwrap();
        let reset = tokio::spawn({
            let store = store.clone();
            let name = name.clone();
            async move { store.reset(name, RestoreOption::Latest).await }
        });
        timeout(Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        assert_eq!(store.cleanup_directory_identity(&name).await.unwrap(), old);
        release.notify_one();
        assert!(timeout(Duration::from_secs(5), reset)
            .await
            .unwrap()
            .unwrap()
            .is_err());
        assert_eq!(store.cleanup_directory_identity(&name).await.unwrap(), old);
        assert_eq!(std::fs::read(path.join("sentinel")).unwrap(), b"old data");
        assert!(!store.reset_intent_path(&name).exists());
        assert!(!store.reset_quarantine_path(&name).exists());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stalled_reset_backup_keeps_old_inode_until_confirmed() {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let (tmp, store) =
            primary_fixture_with_cleanup_gate(Some((entered.clone(), release.clone(), false)))
                .await;
        let name = NamespaceName::from("victim");
        store
            .create(
                name.clone(),
                RestoreOption::Latest,
                DatabaseConfig::default(),
            )
            .await
            .unwrap();
        let path = tmp.path().join("dbs/victim");
        std::fs::write(path.join("sentinel"), b"old data").unwrap();
        let reset = tokio::spawn({
            let store = store.clone();
            let name = name.clone();
            async move { store.reset(name, RestoreOption::Latest).await }
        });
        timeout(Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        assert_eq!(std::fs::read(path.join("sentinel")).unwrap(), b"old data");
        timeout(
            Duration::from_secs(5),
            store.create(
                NamespaceName::from("unrelated"),
                RestoreOption::Latest,
                DatabaseConfig::default(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        let same_name = tokio::spawn({
            let store = store.clone();
            let name = name.clone();
            async move { store.with(name, |ns| ns.path.clone()).await }
        });
        tokio::task::yield_now().await;
        assert!(!same_name.is_finished());
        release.notify_one();
        timeout(Duration::from_secs(5), reset)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        timeout(Duration::from_secs(5), same_name)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(!path.join("sentinel").exists());
        assert!(store.exists(&name).await);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn failed_backup_keeps_old_directory_and_rejects_same_name_retry() {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let (tmp, store) =
            primary_fixture_with_cleanup_gate(Some((entered.clone(), release.clone(), true))).await;
        let name = NamespaceName::from("victim");
        store
            .create(
                name.clone(),
                RestoreOption::Latest,
                DatabaseConfig::default(),
            )
            .await
            .unwrap();
        let path = tmp.path().join("dbs/victim");
        std::fs::write(path.join("sentinel"), b"not backed up").unwrap();
        let destroy = tokio::spawn({
            let store = store.clone();
            let name = name.clone();
            async move { store.destroy(name, false).await }
        });
        timeout(Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        release.notify_one();
        assert!(timeout(Duration::from_secs(5), destroy)
            .await
            .unwrap()
            .unwrap()
            .is_err());
        assert_eq!(
            std::fs::read(path.join("sentinel")).unwrap(),
            b"not backed up"
        );
        assert!(store.exists(&name).await);
        assert!(store
            .create(name, RestoreOption::Latest, DatabaseConfig::default())
            .await
            .is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn shutdown_reports_failed_drain_while_backup_confirmation_is_stalled() {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let (_tmp, store) =
            primary_fixture_with_cleanup_gate(Some((entered.clone(), release.clone(), false)))
                .await;
        let name = NamespaceName::from("victim");
        store
            .create(
                name.clone(),
                RestoreOption::Latest,
                DatabaseConfig::default(),
            )
            .await
            .unwrap();
        let destroy = tokio::spawn({
            let store = store.clone();
            async move { store.destroy(name, false).await }
        });
        timeout(Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        let result = timeout(
            Duration::from_secs(2),
            store
                .clone()
                .shutdown_with_timeout(Duration::from_millis(40)),
        )
        .await
        .unwrap();
        assert!(matches!(result, Err(Error::Blocked(_))));
        release.notify_one();
        timeout(Duration::from_secs(5), destroy)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_backup_keeps_old_directory() {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let (tmp, store) =
            primary_fixture_with_cleanup_gate(Some((entered.clone(), release, false))).await;
        let name = NamespaceName::from("victim");
        store
            .create(
                name.clone(),
                RestoreOption::Latest,
                DatabaseConfig::default(),
            )
            .await
            .unwrap();
        let path = tmp.path().join("dbs/victim");
        std::fs::write(path.join("sentinel"), b"not confirmed").unwrap();
        let destroy = tokio::spawn({
            let store = store.clone();
            let name = name.clone();
            async move { store.destroy(name, false).await }
        });
        timeout(Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        destroy.abort();
        assert!(destroy.await.unwrap_err().is_cancelled());
        assert_eq!(
            std::fs::read(path.join("sentinel")).unwrap(),
            b"not confirmed"
        );
        assert!(store.exists(&name).await);
        assert!(store
            .create(name, RestoreOption::Latest, DatabaseConfig::default())
            .await
            .is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_waiter_after_backup_confirmation_drains_owned_teardown() {
        let (tmp, store) = primary_fixture().await;
        let name = NamespaceName::from("victim");
        store
            .create(
                name.clone(),
                RestoreOption::Latest,
                DatabaseConfig::default(),
            )
            .await
            .unwrap();
        let held_connection = store.inner.metadata.hold_connection_for_test().await;
        let ready = Arc::new(Notify::new());
        let destroy = tokio::spawn({
            let store = store.clone();
            let name = name.clone();
            let ready = ready.clone();
            async move {
                store
                    .destroy_with_commit_signal(name, false, Some(ready))
                    .await
            }
        });
        timeout(Duration::from_secs(5), ready.notified())
            .await
            .unwrap();
        destroy.abort();
        assert!(destroy.await.unwrap_err().is_cancelled());
        // The worker retains the name lock even after the caller exits.
        let operation = store
            .inner
            .name_operations
            .lock()
            .unwrap()
            .get(&name)
            .and_then(Weak::upgrade)
            .unwrap();
        assert!(timeout(Duration::from_millis(20), operation.lock())
            .await
            .is_err());
        drop(held_connection);
        timeout(Duration::from_secs(5), async {
            loop {
                if !store.exists(&name).await && !tmp.path().join("dbs/victim").exists() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        timeout(
            Duration::from_secs(5),
            store.create(
                name.clone(),
                RestoreOption::Latest,
                DatabaseConfig::default(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(store.exists(&name).await);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn confirmed_destroy_rejects_replaced_inode_without_losing_metadata() {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let (tmp, store) =
            primary_fixture_with_cleanup_gate(Some((entered.clone(), release.clone(), false)))
                .await;
        let name = NamespaceName::from("victim");
        store
            .create(
                name.clone(),
                RestoreOption::Latest,
                DatabaseConfig::default(),
            )
            .await
            .unwrap();
        let path = tmp.path().join("dbs/victim");
        std::fs::write(path.join("sentinel"), b"old inode").unwrap();
        let destroy = tokio::spawn({
            let store = store.clone();
            let name = name.clone();
            async move { store.destroy(name, false).await }
        });
        timeout(Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        std::fs::rename(&path, tmp.path().join("original")).unwrap();
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("sentinel"), b"replacement").unwrap();
        release.notify_one();
        assert!(timeout(Duration::from_secs(5), destroy)
            .await
            .unwrap()
            .unwrap()
            .is_err());
        assert!(store.exists(&name).await);
        assert_eq!(
            std::fs::read(path.join("sentinel")).unwrap(),
            b"replacement"
        );
        assert_eq!(
            std::fs::read(tmp.path().join("original/sentinel")).unwrap(),
            b"old inode"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sql_failure_after_intent_publication_preserves_original_directory() {
        let (tmp, store) = primary_fixture().await;
        let name = NamespaceName::from("victim");
        store
            .create(
                name.clone(),
                RestoreOption::Latest,
                DatabaseConfig::default(),
            )
            .await
            .unwrap();
        let path = tmp.path().join("dbs/victim");
        std::fs::write(path.join("sentinel"), b"original").unwrap();
        let conn = store.inner.metadata.hold_connection_for_test().await;
        conn.execute_batch("CREATE TRIGGER reject_delete BEFORE DELETE ON namespace_configs BEGIN SELECT RAISE(ABORT, 'injected failure'); END;")
            .unwrap();
        let destroy = tokio::spawn({
            let store = store.clone();
            let name = name.clone();
            async move { store.destroy(name, false).await }
        });
        // Prove the durable intent is published *before* entering SQL. This
        // assertion distinguishes this protocol from the old trigger test.
        tokio::time::timeout(Duration::from_secs(5), async {
            while !store.destroy_intent_path(&name).exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(store.exists(&name).await);
        drop(conn);
        assert!(destroy.await.unwrap().is_err());
        assert!(!store.destroy_intent_path(&name).exists());
        assert!(store.exists(&name).await);
        assert_eq!(std::fs::read(path.join("sentinel")).unwrap(), b"original");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn restart_recovers_destroy_at_each_durable_boundary() {
        for stage in 0..3 {
            let (tmp, store) = primary_fixture().await;
            let name = NamespaceName::from("victim");
            store
                .create(
                    name.clone(),
                    RestoreOption::Latest,
                    DatabaseConfig::default(),
                )
                .await
                .unwrap();
            let path = tmp.path().join("dbs/victim");
            std::fs::write(path.join("sentinel"), b"old data").unwrap();
            store.evict_cached_namespace(&name).await;
            let identity = store.cleanup_directory_identity(&name).await.unwrap();
            store.persist_destroy_intent(&name, identity).unwrap();
            if stage >= 1 {
                tokio::task::spawn_blocking({
                    let metadata = store.inner.metadata.clone();
                    let name = name.clone();
                    move || metadata.remove(name).unwrap()
                })
                .await
                .unwrap();
            }
            if stage == 2 {
                let identity = store.cleanup_directory_identity(&name).await.unwrap();
                store
                    .detach_owned_directory(
                        &name,
                        identity,
                        false,
                        Some(store.destroy_quarantine_path(&name)),
                    )
                    .await
                    .unwrap();
            }
            // Open a fresh SQLite-backed metastore as on process restart.
            drop(store);
            let (maker, wal) = metastore_connection_maker(None, tmp.path()).await.unwrap();
            let metadata = MetaStore::new(
                crate::config::MetaStoreConfig {
                    allow_recover_from_fs: true,
                    ..Default::default()
                },
                tmp.path(),
                maker().unwrap(),
                wal,
                DatabaseKind::Primary,
            )
            .await
            .unwrap();
            let restarted = NamespaceStore::new(
                false,
                false,
                10,
                metadata,
                NamespaceConfigurators::empty(),
                DatabaseKind::Primary,
                tmp.path(),
            )
            .await
            .unwrap();
            assert!(!restarted.destroy_intent_path(&name).exists());
            assert!(!restarted.destroy_quarantine_path(&name).exists());
            if stage == 0 {
                assert!(restarted.exists(&name).await);
                assert_eq!(std::fs::read(path.join("sentinel")).unwrap(), b"old data");
            } else {
                assert!(!restarted.exists(&name).await);
                assert!(!path.exists());
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unpublished_truncated_intent_is_discarded_without_hiding_live_row() {
        let (tmp, store) = primary_fixture().await;
        let name = NamespaceName::from("victim");
        store
            .create(
                name.clone(),
                RestoreOption::Latest,
                DatabaseConfig::default(),
            )
            .await
            .unwrap();
        store.evict_cached_namespace(&name).await;
        let path = tmp.path().join("dbs/victim");
        std::fs::write(path.join("sentinel"), b"original").unwrap();
        let root = store.destroy_intent_root();
        std::fs::create_dir_all(&root).unwrap();
        let temp = root.join(".tmp-interrupted-write");
        std::fs::write(&temp, b"destroy 123").unwrap();
        drop(store);
        let (maker, wal) = metastore_connection_maker(None, tmp.path()).await.unwrap();
        let metadata = MetaStore::new(
            Default::default(),
            tmp.path(),
            maker().unwrap(),
            wal,
            DatabaseKind::Primary,
        )
        .await
        .unwrap();
        let restarted = NamespaceStore::new(
            false,
            false,
            10,
            metadata,
            NamespaceConfigurators::empty(),
            DatabaseKind::Primary,
            tmp.path(),
        )
        .await
        .unwrap();
        assert!(!temp.exists());
        assert!(restarted.exists(&name).await);
        assert_eq!(std::fs::read(path.join("sentinel")).unwrap(), b"original");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn incomplete_destroy_intent_prevents_reuse_until_recovered() {
        let (tmp, store) = primary_fixture().await;
        let name = NamespaceName::from("victim");
        store.persist_destroy_intent(&name, None).unwrap();
        assert!(store.ensure_existing_directory(&name).await.is_err());
        assert!(store
            .create(
                name.clone(),
                RestoreOption::Latest,
                DatabaseConfig::default()
            )
            .await
            .is_err());
        let restarted = NamespaceStore::new(
            false,
            false,
            10,
            store.inner.metadata.clone(),
            NamespaceConfigurators::empty(),
            DatabaseKind::Primary,
            tmp.path(),
        )
        .await
        .unwrap();
        assert!(!restarted.destroy_intent_path(&name).exists());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pending_destroy_fences_fork_destination_and_reset() {
        let (tmp, store) = primary_fixture().await;
        let source = NamespaceName::from("source");
        let destination = NamespaceName::from("destination");
        store
            .create(
                source.clone(),
                RestoreOption::Latest,
                DatabaseConfig::default(),
            )
            .await
            .unwrap();
        store.persist_destroy_intent(&destination, None).unwrap();
        assert!(store
            .fork(
                source.clone(),
                destination.clone(),
                DatabaseConfig::default(),
                None
            )
            .await
            .is_err());
        assert!(!store.exists(&destination).await);
        assert!(!tmp.path().join("dbs/destination").exists());
        let identity = store.cleanup_directory_identity(&source).await.unwrap();
        store.persist_destroy_intent(&source, identity).unwrap();
        assert!(store
            .reset(source.clone(), RestoreOption::Latest)
            .await
            .is_err());
        assert!(store.exists(&source).await);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn row_with_missing_original_and_destroy_intent_fails_closed() {
        let (tmp, store) = primary_fixture().await;
        let name = NamespaceName::from("victim");
        store
            .create(
                name.clone(),
                RestoreOption::Latest,
                DatabaseConfig::default(),
            )
            .await
            .unwrap();
        store.evict_cached_namespace(&name).await;
        let identity = store.cleanup_directory_identity(&name).await.unwrap();
        store.persist_destroy_intent(&name, identity).unwrap();
        std::fs::rename(tmp.path().join("dbs/victim"), tmp.path().join("saved")).unwrap();
        let result = NamespaceStore::new(
            false,
            false,
            10,
            store.inner.metadata.clone(),
            NamespaceConfigurators::empty(),
            DatabaseKind::Primary,
            tmp.path(),
        )
        .await;
        assert!(result.is_err());
        assert!(tmp.path().join("saved").is_dir());
        assert!(store.exists(&name).await);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pending_dump_does_not_block_unrelated_operations_and_shutdown() {
        let (tmp, store) = primary_fixture().await;
        store
            .create(
                NamespaceName::from("victim"),
                RestoreOption::Latest,
                DatabaseConfig::default(),
            )
            .await
            .unwrap();
        let slow = tokio::spawn({
            let store = store.clone();
            async move {
                let pending = futures::stream::pending::<std::io::Result<bytes::Bytes>>();
                store
                    .create(
                        NamespaceName::from("slow"),
                        RestoreOption::Dump(Box::new(pending)),
                        DatabaseConfig::default(),
                    )
                    .await
            }
        });
        timeout(Duration::from_secs(5), async {
            while !tmp.path().join("dbs/slow").exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        timeout(Duration::from_secs(5), async {
            store
                .create(
                    NamespaceName::from("fast"),
                    RestoreOption::Latest,
                    DatabaseConfig::default(),
                )
                .await?;
            store.destroy(NamespaceName::from("victim"), false).await?;
            store.ensure_default_namespace().await?;
            Ok::<_, crate::Error>(())
        })
        .await
        .unwrap()
        .unwrap();
        assert!(!slow.is_finished());
        let duplicate = tokio::spawn({
            let store = store.clone();
            async move {
                store
                    .create(
                        NamespaceName::from("slow"),
                        RestoreOption::Latest,
                        DatabaseConfig::default(),
                    )
                    .await
            }
        });
        // Shutdown signals slow restore to cancel, and drains its detached
        // quarantine cleanup before metastore backup; it must not wait 20s.
        timeout(Duration::from_secs(5), store.clone().shutdown())
            .await
            .unwrap()
            .unwrap();
        assert!(slow.await.unwrap().is_err());
        assert!(duplicate.await.unwrap().is_err());
        assert!(tmp.path().join("dbs/slow").exists());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn incompatible_replica_log_quarantines_contents_without_replacing_directory() {
        let (tmp, store) = primary_fixture().await;
        let name = NamespaceName::from("tenant");
        let path = tmp.path().join("dbs/tenant");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("old-log"), b"preserved").unwrap();
        let identity = store.replica_directory_identity(&name).await.unwrap();
        store
            .quarantine_incompatible_replica_log(&name, identity)
            .await
            .unwrap();
        assert_eq!(
            store.replica_directory_identity(&name).await.unwrap(),
            identity
        );
        assert!(!path.join("old-log").exists());
        let root = tmp.path().join("replica-log-quarantine");
        let quarantined = std::fs::read_dir(root)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        assert_eq!(
            std::fs::read(quarantined.join("old-log")).unwrap(),
            b"preserved"
        );

        std::fs::rename(&path, tmp.path().join("moved")).unwrap();
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("new-log"), b"untouched").unwrap();
        assert!(store
            .quarantine_incompatible_replica_log(&name, identity)
            .await
            .is_err());
        assert_eq!(std::fs::read(path.join("new-log")).unwrap(), b"untouched");
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn incompatible_replica_log_refuses_alias_directory() {
        use std::os::unix::fs::symlink;
        let (tmp, store) = primary_fixture().await;
        let path = tmp.path().join("dbs/actual");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("sentinel"), b"untouched").unwrap();
        symlink(&path, tmp.path().join("dbs/alias")).unwrap();
        assert!(store
            .replica_directory_identity(&NamespaceName::from("alias"))
            .await
            .is_err());
        assert_eq!(std::fs::read(path.join("sentinel")).unwrap(), b"untouched");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn name_lock_registry_prunes_idle_names() {
        let (_tmp, store) = primary_fixture().await;
        for id in 0..128 {
            let namespace = NamespaceName::from_string(format!("test-{id}")).unwrap();
            drop(store.lock_names(&[namespace]).await.unwrap());
        }
        assert!(store.inner.name_operations.lock().unwrap().len() <= 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn shutdown_returns_bounded_error_if_operation_cannot_drain() {
        let (_tmp, store) = primary_fixture().await;
        let held = store
            .lock_names(&[NamespaceName::from("stuck")])
            .await
            .unwrap();
        let result = timeout(
            Duration::from_secs(2),
            store
                .clone()
                .shutdown_with_timeout(Duration::from_millis(40)),
        )
        .await
        .unwrap();
        assert!(matches!(result, Err(Error::Blocked(_))));
        drop(held);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn current_thread_error_cleanup_awaits_barrier_and_removes_owned_directory() {
        let (tmp, metadata, _lock, cleanup) = cleanup_fixture().await;
        let namespace = NamespaceName::from("failed");
        metadata
            .handle(namespace.clone())
            .await
            .store(Arc::new(DatabaseConfig::default()))
            .await
            .unwrap();
        cleanup.finish().await;
        assert!(!metadata.exists(&namespace).await);
        assert!(!tmp.path().join("dbs/failed").exists());
    }

    async fn cancelled_cleanup_keeps_lock_until_queued_write_and_removal_finish() {
        let (tmp, metadata, lock, cleanup) = cleanup_fixture().await;
        let namespace = NamespaceName::from("failed");
        let handle = metadata.handle(namespace.clone()).await;
        let held_conn = metadata.hold_connection_for_test().await;
        let mut queued_write = Box::pin(handle.store(Arc::new(DatabaseConfig::default())));
        // Poll once while the connection is locked: the write is enqueued but
        // cannot complete. Cancel its caller, as with a cancelled fork/create.
        assert!(matches!(
            futures::poll!(queued_write.as_mut()),
            std::task::Poll::Pending
        ));
        drop(queued_write);
        // Wait until the worker has consumed the blocked write, then observe
        // the barrier enqueued by cleanup before cancelling its waiter.
        timeout(Duration::from_secs(2), async {
            while metadata.pending_change_count_for_test() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let waiter = tokio::spawn(cleanup.finish());
        timeout(Duration::from_secs(2), async {
            while metadata.pending_change_count_for_test() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        waiter.abort();
        assert!(waiter.await.is_err());
        assert!(timeout(Duration::from_millis(30), lock.lock())
            .await
            .is_err());
        drop(held_conn);
        let _next_operation = timeout(Duration::from_secs(5), lock.lock()).await.unwrap();
        assert!(!metadata.exists(&namespace).await);
        assert!(!tmp.path().join("dbs/failed").exists());
        // A later reservation must not be removed or reinserted by the old
        // detached cleanup, even after it has had another scheduling turn.
        std::fs::create_dir(tmp.path().join("dbs/failed")).unwrap();
        std::fs::write(tmp.path().join("dbs/failed/sentinel"), b"new owner").unwrap();
        // The real create path rotates the revoked generation only after a
        // fresh directory is reserved under this name's operation lock.
        metadata.activate_for_create(&namespace);
        metadata
            .handle(namespace.clone())
            .await
            .store(Arc::new(DatabaseConfig::default()))
            .await
            .unwrap();
        tokio::task::yield_now().await;
        assert_eq!(
            std::fs::read(tmp.path().join("dbs/failed/sentinel")).unwrap(),
            b"new owner"
        );
        assert!(metadata.exists(&namespace).await);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_operation_quarantines_directory_and_queued_write() {
        let (tmp, metadata, lock, cleanup) = cleanup_fixture().await;
        let namespace = NamespaceName::from("failed");
        let other = tmp.path().join("dbs/other");
        std::fs::create_dir(&other).unwrap();
        std::fs::write(other.join("sentinel"), b"unrelated").unwrap();
        let held_conn = metadata.hold_connection_for_test().await;
        let handle = metadata.handle(namespace.clone()).await;
        let mut queued_write = Box::pin(handle.store(Arc::new(DatabaseConfig::default())));
        assert!(matches!(
            futures::poll!(queued_write.as_mut()),
            std::task::Poll::Pending
        ));
        drop(queued_write);
        let (ready, started) = tokio::sync::oneshot::channel();
        let cancelled = tokio::spawn(async move {
            let _cleanup = cleanup;
            ready.send(()).unwrap();
            futures::future::pending::<()>().await;
        });
        started.await.unwrap();
        cancelled.abort();
        assert!(cancelled.await.is_err());
        assert!(timeout(Duration::from_millis(30), lock.lock())
            .await
            .is_err());
        drop(held_conn);
        let _next_operation = timeout(Duration::from_secs(5), lock.lock()).await.unwrap();
        assert!(!metadata.exists(&namespace).await);
        assert!(tmp.path().join("dbs/failed").is_dir());
        assert_eq!(
            std::fs::create_dir(tmp.path().join("dbs/failed"))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(other.join("sentinel")).unwrap(), b"unrelated");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancellation_on_current_thread_is_ordered() {
        cancelled_cleanup_keeps_lock_until_queued_write_and_removal_finish().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancellation_on_multithread_is_ordered() {
        cancelled_cleanup_keeps_lock_until_queued_write_and_removal_finish().await;
    }

    #[test]
    fn reservation_cleanup_does_not_remove_replacement() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("dest");
        std::fs::create_dir(&path).unwrap();
        let identity = directory_identity(&std::fs::symlink_metadata(&path).unwrap());
        let reservation = DirectoryReservation {
            path: path.clone(),
            identity,
            owned: true,
        };
        std::fs::rename(&path, tmp.path().join("original")).unwrap();
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("sentinel"), b"do not remove replacement").unwrap();
        reservation.remove_if_owned();
        assert_eq!(
            std::fs::read(path.join("sentinel")).unwrap(),
            b"do not remove replacement"
        );
        assert!(tmp.path().join("original").is_dir());
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
    dbs_path: PathBuf,
    // The short exact-name scan and rename remain synchronous while this
    // lock is held. Naively awaiting spawn_blocking would release a cancelled
    // caller's name lock while a late filesystem mutation is still running.
    // Large directory scans can stall a current-thread executor; offloading
    // them requires moving BOTH the name and identity guards to a detached,
    // cancellation-independent worker (not just the filesystem syscall).
    fs_operations: Arc<tokio::sync::Mutex<()>>,
    name_operations: StdMutex<HashMap<NamespaceName, Weak<tokio::sync::Mutex<()>>>>,
    shutdown_signal: tokio::sync::watch::Sender<bool>,
}

impl NamespaceStore {
    pub(crate) async fn new(
        allow_lazy_creation: bool,
        snapshot_at_shutdown: bool,
        max_active_namespaces: usize,
        metadata: MetaStore,
        configurators: NamespaceConfigurators,
        db_kind: DatabaseKind,
        base_path: &Path,
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

        let this = Self {
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
                dbs_path: base_path.join("dbs"),
                fs_operations: Arc::new(tokio::sync::Mutex::new(())),
                name_operations: StdMutex::new(HashMap::new()),
                shutdown_signal: tokio::sync::watch::channel(false).0,
            }),
        };
        this.recover_reset_intents().await?;
        this.recover_destroy_intents().await?;
        Ok(this)
    }

    pub async fn exists(&self, namespace: &NamespaceName) -> bool {
        self.inner.metadata.exists(namespace).await
    }

    /// Test/embedding hook: force a cache miss without touching persisted
    /// config or namespace files. Integration tests use this to exercise a
    /// replica reset whose linked schema really is unloaded at handshake.
    #[doc(hidden)]
    pub async fn evict_cached_namespace(&self, namespace: &NamespaceName) {
        self.inner.store.invalidate(namespace).await;
    }

    // Weak entries prevent an unbounded registry. All operations acquire
    // multiple names in lexical order (source before/destination as sorted),
    // then the short filesystem identity lock if needed.
    async fn lock_names(&self, names: &[NamespaceName]) -> crate::Result<Vec<OwnedMutexGuard<()>>> {
        let mut names = names.to_vec();
        names.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        names.dedup();
        let locks = {
            let mut registry = self.inner.name_operations.lock().unwrap();
            registry.retain(|_, lock| lock.strong_count() > 0);
            names
                .iter()
                .map(|name| {
                    if let Some(lock) = registry.get(name).and_then(Weak::upgrade) {
                        lock
                    } else {
                        let lock = Arc::new(tokio::sync::Mutex::new(()));
                        registry.insert(name.clone(), Arc::downgrade(&lock));
                        lock
                    }
                })
                .collect::<Vec<_>>()
        };
        let mut guards = Vec::with_capacity(locks.len());
        for lock in locks {
            guards.push(lock.lock_owned().await);
        }
        if self.inner.has_shutdown.load(Ordering::Relaxed) {
            return Err(Error::NamespaceStoreShutdown);
        }
        for name in &names {
            self.check_no_destroy_intent(name)?;
        }
        Ok(guards)
    }

    fn directory_path(&self, namespace: &NamespaceName) -> PathBuf {
        self.inner.dbs_path.join(namespace.as_str())
    }

    fn reset_intent_root(&self) -> PathBuf {
        self.inner
            .dbs_path
            .parent()
            .unwrap()
            .join("namespace-reset-intents")
    }

    fn reset_intent_path(&self, namespace: &NamespaceName) -> PathBuf {
        self.reset_intent_root().join(Self::destroy_key(namespace))
    }

    fn reset_committed_path(&self, namespace: &NamespaceName) -> PathBuf {
        self.reset_intent_root()
            .join(format!("{}.committed", Self::destroy_key(namespace)))
    }

    fn reset_quarantine_path(&self, namespace: &NamespaceName) -> PathBuf {
        self.inner
            .dbs_path
            .parent()
            .unwrap()
            .join("namespace-teardown-quarantine")
            .join(format!("reset-{}", Self::destroy_key(namespace)))
    }

    fn destroy_intent_root(&self) -> PathBuf {
        self.inner
            .dbs_path
            .parent()
            .unwrap()
            .join("namespace-destroy-intents")
    }

    fn destroy_key(namespace: &NamespaceName) -> String {
        namespace
            .as_slice()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn destroy_intent_path(&self, namespace: &NamespaceName) -> PathBuf {
        self.destroy_intent_root()
            .join(Self::destroy_key(namespace))
    }

    fn check_no_destroy_intent(&self, namespace: &NamespaceName) -> crate::Result<()> {
        for path in [
            self.destroy_intent_path(namespace),
            self.reset_intent_path(namespace),
            self.reset_committed_path(namespace),
        ] {
            match std::fs::symlink_metadata(&path) {
                Ok(_) => {
                    return Err(Error::InvalidPath(format!(
                        "unfinished namespace operation for `{namespace}` requires recovery"
                    )))
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    fn destroy_quarantine_path(&self, namespace: &NamespaceName) -> PathBuf {
        self.inner
            .dbs_path
            .parent()
            .unwrap()
            .join("namespace-teardown-quarantine")
            .join(format!("destroy-{}", Self::destroy_key(namespace)))
    }

    // The intent must reach disk before SQLite commits deletion. Without it,
    // restart could mistake the old directory for a new, unowned namespace.
    fn persist_destroy_intent(
        &self,
        namespace: &NamespaceName,
        expected: Option<(u64, u64)>,
    ) -> crate::Result<()> {
        let root = self.destroy_intent_root();
        std::fs::create_dir_all(&root)?;
        if !std::fs::symlink_metadata(&root)?.file_type().is_dir() {
            return Err(Error::InvalidPath(format!(
                "unsafe destroy intent root {:?}",
                root
            )));
        }
        let path = self.destroy_intent_path(namespace);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                return Err(Error::InvalidPath(format!(
                    "destroy intent already exists: {:?}",
                    path
                )))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        // An incomplete temp file never authorizes metadata deletion. Publish
        // only the fully written, synced record with an atomic rename.
        let temp = root.join(format!(".tmp-{}", uuid::Uuid::new_v4()));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        let record = match expected {
            Some((device, inode)) => format!("destroy {device} {inode}\n"),
            None => "destroy none\n".to_owned(),
        };
        file.write_all(record.as_bytes())?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temp, &path)?;
        sync_directory(&root)?;
        sync_directory(root.parent().unwrap())?;
        Ok(())
    }

    fn clear_destroy_intent(&self, namespace: &NamespaceName) -> crate::Result<()> {
        std::fs::remove_file(self.destroy_intent_path(namespace))?;
        sync_directory(&self.destroy_intent_root())?;
        Ok(())
    }

    // Reset's pending record is immutable; a separate atomic commit marker
    // decides which incarnation wins after a process crash. Both are published
    // through a synced temporary file so a truncated record is never visible.
    fn publish_reset_file(&self, path: &Path, content: &[u8]) -> crate::Result<()> {
        let root = self.reset_intent_root();
        std::fs::create_dir_all(&root)?;
        if !std::fs::symlink_metadata(&root)?.file_type().is_dir() {
            return Err(Error::InvalidPath(format!(
                "unsafe reset intent root {:?}",
                root
            )));
        }
        match std::fs::symlink_metadata(path) {
            Ok(_) => {
                return Err(Error::InvalidPath(format!(
                    "reset intent already exists: {:?}",
                    path
                )))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let temp = root.join(format!(".tmp-{}", uuid::Uuid::new_v4()));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(content)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temp, path)?;
        sync_directory(&root)?;
        sync_directory(root.parent().unwrap())?;
        Ok(())
    }

    fn read_reset_commit(&self, namespace: &NamespaceName) -> crate::Result<Option<(u64, u64)>> {
        let path = self.reset_committed_path(namespace);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if !metadata.file_type().is_file() {
            return Err(Error::InvalidPath(format!(
                "invalid reset commit marker {:?}",
                path
            )));
        }
        let content = std::fs::read_to_string(&path)?;
        let parts = content
            .strip_suffix('\n')
            .unwrap_or("")
            .split(' ')
            .collect::<Vec<_>>();
        if parts.len() != 3 || parts[0] != "committed" {
            return Err(Error::InvalidPath(format!(
                "invalid reset commit marker {:?}",
                path
            )));
        }
        Ok(Some((
            parts[1]
                .parse()
                .map_err(|_| Error::InvalidPath("invalid reset commit inode".into()))?,
            parts[2]
                .parse()
                .map_err(|_| Error::InvalidPath("invalid reset commit inode".into()))?,
        )))
    }

    fn clear_reset_intent(&self, namespace: &NamespaceName) -> crate::Result<()> {
        let root = self.reset_intent_root();
        std::fs::remove_file(self.reset_intent_path(namespace))?;
        sync_directory(&root)?;
        match std::fs::remove_file(self.reset_committed_path(namespace)) {
            Ok(()) => sync_directory(&root)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        Ok(())
    }

    async fn recover_reset_intents(&self) -> crate::Result<()> {
        let root = self.reset_intent_root();
        match std::fs::symlink_metadata(&root) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
            Ok(metadata) if !metadata.file_type().is_dir() => {
                return Err(Error::InvalidPath(format!(
                    "unsafe reset intent root {:?}",
                    root
                )))
            }
            Ok(_) => {}
        }
        for entry in std::fs::read_dir(&root)? {
            let entry = entry?;
            let key = entry
                .file_name()
                .into_string()
                .map_err(|_| Error::InvalidPath("invalid reset intent name".into()))?;
            if key.starts_with(".tmp-") {
                if !entry.file_type()?.is_file() {
                    return Err(Error::InvalidPath(format!(
                        "unsafe reset temp {:?}",
                        entry.path()
                    )));
                }
                std::fs::remove_file(entry.path())?;
                sync_directory(&root)?;
                continue;
            }
            if key.ends_with(".committed") {
                continue;
            }
            if key.is_empty()
                || key.len() % 2 != 0
                || !key.is_ascii()
                || !entry.file_type()?.is_file()
            {
                return Err(Error::InvalidPath(format!(
                    "invalid reset intent {:?}",
                    entry.path()
                )));
            }
            let bytes = (0..key.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&key[i..i + 2], 16))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| {
                    Error::InvalidPath(format!("invalid reset intent {:?}", entry.path()))
                })?;
            let namespace = NamespaceName::from_bytes(bytes.into())?;
            if key != Self::destroy_key(&namespace) || !self.inner.metadata.exists(&namespace).await
            {
                return Err(Error::InvalidPath(format!(
                    "reset of `{namespace}` has no persisted row"
                )));
            }
            let intent: ResetIntent = serde_json::from_slice(&std::fs::read(entry.path())?)
                .map_err(|e| Error::InvalidPath(format!("invalid reset intent: {e}")))?;
            let old = self.reset_quarantine_path(&namespace);
            let old_at_quarantine = match std::fs::symlink_metadata(&old) {
                Ok(meta) => {
                    if directory_identity(&meta) != Some(intent.old_identity) {
                        return Err(Error::InvalidPath(format!(
                            "reset old inode changed for `{namespace}`"
                        )));
                    }
                    true
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
                Err(e) => return Err(e.into()),
            };
            let committed = self.read_reset_commit(&namespace)?;
            if let Some(new_identity) = committed {
                let replacement = self.cleanup_directory_identity(&namespace).await?;
                if replacement != Some(new_identity) || replacement == Some(intent.old_identity) {
                    return Err(Error::InvalidPath(format!(
                        "missing committed reset directory for `{namespace}`"
                    )));
                }
                tokio::task::spawn_blocking({
                    let metadata = self.inner.metadata.clone();
                    let namespace = namespace.clone();
                    move || metadata.release_reset_pin(&namespace)
                })
                .await?;
                if old_at_quarantine {
                    Self::remove_detached_directory(Some(old.clone())).await?;
                    sync_directory(old.parent().unwrap())?;
                }
            } else if old_at_quarantine {
                // Only process restart can guarantee all canceled setup and
                // blocking/path-open workers are gone. Retain partial new data
                // for inspection; never recursively delete by namespace path.
                let _identity = self.inner.fs_operations.lock().await;
                self.check_existing_directory(&namespace).await?;
                let path = self.directory_path(&namespace);
                match std::fs::symlink_metadata(&path) {
                    Ok(meta) => {
                        if directory_identity(&meta).is_none() {
                            return Err(Error::InvalidPath(format!(
                                "unsafe reset replacement for `{namespace}`"
                            )));
                        }
                        let abandoned_root = self
                            .inner
                            .dbs_path
                            .parent()
                            .unwrap()
                            .join("namespace-reset-abandoned");
                        std::fs::create_dir_all(&abandoned_root)?;
                        if !std::fs::symlink_metadata(&abandoned_root)?
                            .file_type()
                            .is_dir()
                        {
                            return Err(Error::InvalidPath(format!(
                                "unsafe abandoned reset root {:?}",
                                abandoned_root
                            )));
                        }
                        let abandoned = abandoned_root.join(uuid::Uuid::new_v4().to_string());
                        std::fs::rename(&path, &abandoned)?;
                        NAMESPACE_QUARANTINE_COUNT.increment(1);
                        sync_directory(&self.inner.dbs_path)?;
                        sync_directory(&abandoned_root)?;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
                std::fs::rename(&old, &path)?;
                sync_directory(&self.inner.dbs_path)?;
                sync_directory(old.parent().unwrap())?;
            } else if self.cleanup_directory_identity(&namespace).await?
                != Some(intent.old_identity)
            {
                return Err(Error::InvalidPath(format!(
                    "pending reset lost old directory for `{namespace}`"
                )));
            }
            if committed.is_none() {
                tokio::task::spawn_blocking({
                    let metadata = self.inner.metadata.clone();
                    let namespace = namespace.clone();
                    move || metadata.restore_reset_config(&namespace, &intent.old_config)
                })
                .await??;
            }
            self.clear_reset_intent(&namespace)?;
        }
        // A crash after deleting the pending record, before deleting the
        // commit marker, leaves only a harmless committed marker.
        for entry in std::fs::read_dir(&root)? {
            let entry = entry?;
            let Some(key) = entry.file_name().to_str().map(str::to_owned) else {
                return Err(Error::InvalidPath("invalid reset marker name".into()));
            };
            let Some(hex) = key.strip_suffix(".committed") else {
                continue;
            };
            if hex.len() % 2 != 0 || hex.is_empty() || !hex.is_ascii() {
                return Err(Error::InvalidPath(format!(
                    "invalid reset commit marker {:?}",
                    entry.path()
                )));
            }
            let bytes = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| Error::InvalidPath("invalid reset commit marker".into()))?;
            let namespace = NamespaceName::from_bytes(bytes.into())?;
            if hex != Self::destroy_key(&namespace)
                || !entry.file_type()?.is_file()
                || !self.inner.metadata.exists(&namespace).await
                || self.cleanup_directory_identity(&namespace).await?
                    != self.read_reset_commit(&namespace)?
                || std::fs::symlink_metadata(self.reset_quarantine_path(&namespace)).is_ok()
            {
                return Err(Error::InvalidPath(format!(
                    "orphan reset marker for `{namespace}`"
                )));
            }
            std::fs::remove_file(entry.path())?;
            sync_directory(&root)?;
        }
        Ok(())
    }

    async fn recover_destroy_intents(&self) -> crate::Result<()> {
        let root = self.destroy_intent_root();
        match std::fs::symlink_metadata(&root) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
            Ok(metadata) if !metadata.file_type().is_dir() => {
                return Err(Error::InvalidPath(format!(
                    "unsafe destroy intent root {:?}",
                    root
                )))
            }
            Ok(_) => {}
        }
        for entry in std::fs::read_dir(&root)? {
            let entry = entry?;
            let key = entry
                .file_name()
                .into_string()
                .map_err(|_| Error::InvalidPath("invalid destroy intent name".into()))?;
            if key.starts_with(".tmp-") {
                // The metadata DELETE is never attempted before publication.
                // Truncated/unpublished files cannot be treated as intents.
                if !entry.file_type()?.is_file() {
                    return Err(Error::InvalidPath(format!(
                        "unsafe destroy temp {:?}",
                        entry.path()
                    )));
                }
                std::fs::remove_file(entry.path())?;
                sync_directory(&root)?;
                continue;
            }
            if key.len() % 2 != 0 || key.is_empty() || !key.is_ascii() {
                return Err(Error::InvalidPath(format!(
                    "invalid destroy intent {:?}",
                    entry.path()
                )));
            }
            let bytes = (0..key.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&key[i..i + 2], 16))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| {
                    Error::InvalidPath(format!("invalid destroy intent {:?}", entry.path()))
                })?;
            let namespace = NamespaceName::from_bytes(bytes.into())?;
            if key != Self::destroy_key(&namespace) || !entry.file_type()?.is_file() {
                return Err(Error::InvalidPath(format!(
                    "invalid destroy intent {:?}",
                    entry.path()
                )));
            }
            let record = std::fs::read_to_string(entry.path())?;
            let expected = if record == "destroy none\n" {
                None
            } else {
                let parts = record.trim_end_matches('\n').split(' ').collect::<Vec<_>>();
                if parts.len() != 3 || parts[0] != "destroy" || !record.ends_with('\n') {
                    return Err(Error::InvalidPath(format!(
                        "invalid destroy intent {:?}",
                        entry.path()
                    )));
                }
                Some((
                    parts[1]
                        .parse::<u64>()
                        .map_err(|_| Error::InvalidPath("invalid destroy identity".into()))?,
                    parts[2]
                        .parse::<u64>()
                        .map_err(|_| Error::InvalidPath("invalid destroy identity".into()))?,
                ))
            };
            let quarantine = self.destroy_quarantine_path(&namespace);
            if self.inner.metadata.exists(&namespace).await {
                // Commit did not happen. Do not discard the old database or
                // allow a missing directory to be lazily replaced with a blank one.
                if std::fs::symlink_metadata(&quarantine).is_ok()
                    || self.cleanup_directory_identity(&namespace).await? != expected
                    || expected.is_none()
                {
                    // In particular, never let the live row reopen a blank
                    // directory if the original files went missing.
                    return Err(Error::InvalidPath(format!(
                        "incomplete destroy of `{namespace}` requires repair"
                    )));
                }
                self.check_existing_directory(&namespace).await?;
            } else {
                let actual = self.cleanup_directory_identity(&namespace).await?;
                if actual.is_some() {
                    if actual != expected {
                        return Err(Error::InvalidPath(format!(
                            "destroy of `{namespace}` found a replaced directory"
                        )));
                    }
                    let (detached, _) = self
                        .detach_owned_directory(
                            &namespace,
                            expected,
                            false,
                            Some(quarantine.clone()),
                        )
                        .await?;
                    Self::remove_detached_directory(detached).await?;
                    sync_directory(quarantine.parent().unwrap())?;
                } else if std::fs::symlink_metadata(&quarantine).is_ok() {
                    let metadata = std::fs::symlink_metadata(&quarantine)?;
                    if directory_identity(&metadata) != expected {
                        return Err(Error::InvalidPath(format!(
                            "replaced destroy quarantine {:?}",
                            quarantine
                        )));
                    }
                    Self::remove_detached_directory(Some(quarantine.clone())).await?;
                    sync_directory(quarantine.parent().unwrap())?;
                }
            }
            self.clear_destroy_intent(&namespace)?;
        }
        Ok(())
    }

    // Lookup by path alone is insufficient on case-insensitive/normalizing
    // filesystems. The actual entry must be spelled exactly as the metastore key.
    async fn check_existing_directory(&self, namespace: &NamespaceName) -> crate::Result<()> {
        let path = self.directory_path(namespace);
        match tokio::fs::symlink_metadata(&path).await {
            Ok(_) => {
                let mut entries = tokio::fs::read_dir(&self.inner.dbs_path).await?;
                while let Some(entry) = entries.next_entry().await? {
                    if entry.file_name() == namespace.as_str() {
                        if entry.file_type().await?.is_dir() {
                            return Ok(());
                        }
                        break;
                    }
                }
                Err(Error::InvalidPath(format!(
                    "namespace `{namespace}` resolves to a different or non-directory filesystem entry"
                )))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    async fn reserve_directory(
        &self,
        namespace: &NamespaceName,
    ) -> crate::Result<DirectoryReservation> {
        tokio::fs::create_dir_all(&self.inner.dbs_path).await?;
        self.check_no_destroy_intent(namespace)?;
        let path = self.directory_path(namespace);
        match tokio::fs::create_dir(&path).await {
            Ok(()) => {
                let identity = tokio::fs::symlink_metadata(&path)
                    .await
                    .ok()
                    .and_then(|m| directory_identity(&m));
                Ok(DirectoryReservation {
                    path,
                    identity,
                    owned: true,
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(Error::NamespaceAlreadyExist(namespace.to_string()))
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn ensure_existing_directory(
        &self,
        namespace: &NamespaceName,
    ) -> crate::Result<Option<DirectoryReservation>> {
        // Also serialize restoration of a missing persisted directory with
        // deletion of a legacy filesystem alias, which may have another key.
        let _identity = self.inner.fs_operations.lock().await;
        // The exact-name scan rejects aliases and symlinks. No store operation
        // can replace the entry before mkdir while this lock is held; another
        // scan on AlreadyExists would repeat the same directory traversal.
        self.check_existing_directory(namespace).await?;
        match self.reserve_directory(namespace).await {
            Ok(reservation) => Ok(Some(reservation)),
            Err(Error::NamespaceAlreadyExist(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    // Replica setup calls this before opening its WAL. Never hold this lock
    // during handshake: linked-schema resolution may load another namespace.
    pub(crate) async fn replica_directory_identity(
        &self,
        namespace: &NamespaceName,
    ) -> crate::Result<(u64, u64)> {
        let _identity = self.inner.fs_operations.lock().await;
        self.check_existing_directory(namespace).await?;
        let path = self.directory_path(namespace);
        let metadata = tokio::fs::symlink_metadata(&path).await?;
        directory_identity(&metadata).ok_or_else(|| {
            Error::InvalidPath(format!(
                "replica directory `{namespace}` has no safe filesystem identity"
            ))
        })
    }

    // Keep the directory inode (and any DirectoryReservation for it) stable.
    // Move incompatible files to a separate quarantine outside dbs rather
    // than deleting the directory by name or recursively retrying setup.
    pub(crate) async fn quarantine_incompatible_replica_log(
        &self,
        namespace: &NamespaceName,
        expected: (u64, u64),
    ) -> crate::Result<()> {
        let _identity = self.inner.fs_operations.lock().await;
        self.check_existing_directory(namespace).await?;
        let path = self.directory_path(namespace);
        let actual = std::fs::symlink_metadata(&path)
            .ok()
            .and_then(|metadata| directory_identity(&metadata));
        if actual != Some(expected) {
            return Err(Error::InvalidPath(format!(
                "replica directory `{namespace}` changed during handshake; refusing to replace its log"
            )));
        }
        let quarantine_root = self
            .inner
            .dbs_path
            .parent()
            .unwrap()
            .join("replica-log-quarantine");
        std::fs::create_dir_all(&quarantine_root)?;
        let metadata = std::fs::symlink_metadata(&quarantine_root)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(Error::InvalidPath(format!(
                "replica quarantine path {:?} is not a directory",
                quarantine_root
            )));
        }
        let quarantine = quarantine_root.join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir(&quarantine)?;
        // Count the newly retained directory before any fallible read/rename:
        // partial moves and an empty quarantine still require inspection.
        NAMESPACE_QUARANTINE_COUNT.increment(1);
        let entries = std::fs::read_dir(&path)?
            .map(|entry| entry.map(|entry| (entry.path(), entry.file_name())))
            .collect::<std::io::Result<Vec<_>>>()?;
        for (source, name) in entries {
            std::fs::rename(source, quarantine.join(name))?;
        }
        if std::fs::read_dir(&path)?.next().is_some() {
            return Err(Error::InvalidPath(format!(
                "replica directory `{namespace}` changed while quarantining its log"
            )));
        }
        tracing::warn!(
            "quarantined incompatible replica files for `{namespace}` at {:?}",
            quarantine
        );
        Ok(())
    }

    async fn cleanup_directory_identity(
        &self,
        namespace: &NamespaceName,
    ) -> crate::Result<Option<(u64, u64)>> {
        let _identity = self.inner.fs_operations.lock().await;
        self.check_existing_directory(namespace).await?;
        match std::fs::symlink_metadata(self.directory_path(namespace)) {
            Ok(metadata) => directory_identity(&metadata).map(Some).ok_or_else(|| {
                Error::InvalidPath(format!(
                    "namespace `{namespace}` has no safe directory identity"
                ))
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    // Call only after remote backup confirmation and task teardown, while
    // holding the name's operation guard. The identity lock protects the
    // check/rename/reservation transaction, never backup or recursive removal.
    async fn detach_owned_directory(
        &self,
        namespace: &NamespaceName,
        expected: Option<(u64, u64)>,
        replace: bool,
        destroy_target: Option<PathBuf>,
    ) -> crate::Result<(Option<PathBuf>, Option<DirectoryReservation>)> {
        let _identity = self.inner.fs_operations.lock().await;
        self.check_existing_directory(namespace).await?;
        let path = self.directory_path(namespace);
        let actual = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => directory_identity(&metadata),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        if actual != expected {
            return Err(Error::InvalidPath(format!(
                "namespace `{namespace}` directory changed during cleanup; refusing to remove it"
            )));
        }
        let durable_destroy = destroy_target.is_some();
        let detached = if actual.is_some() {
            let root = self
                .inner
                .dbs_path
                .parent()
                .unwrap()
                .join("namespace-teardown-quarantine");
            std::fs::create_dir_all(&root)?;
            let metadata = std::fs::symlink_metadata(&root)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(Error::InvalidPath(format!(
                    "unsafe namespace teardown path {:?}",
                    root
                )));
            }
            let target =
                destroy_target.unwrap_or_else(|| root.join(uuid::Uuid::new_v4().to_string()));
            if std::fs::symlink_metadata(&target).is_ok() {
                return Err(Error::InvalidPath(format!(
                    "namespace teardown target already exists: {:?}",
                    target
                )));
            }
            std::fs::rename(&path, &target)?;
            if durable_destroy {
                sync_directory(&self.inner.dbs_path)?;
                sync_directory(&root)?;
            }
            Some(target)
        } else {
            None
        };
        // There is no await between detaching the old inode and reserving
        // the replacement. An alias cannot take over this path in between.
        let reservation = if replace {
            let result = (|| -> crate::Result<DirectoryReservation> {
                std::fs::create_dir_all(&self.inner.dbs_path)?;
                std::fs::create_dir(&path)?;
                let identity = directory_identity(&std::fs::symlink_metadata(&path)?);
                Ok(DirectoryReservation {
                    path: path.clone(),
                    identity,
                    owned: true,
                })
            })();
            match result {
                Ok(reservation) => Some(reservation),
                Err(e) => {
                    if let Some(ref old) = detached {
                        if let Err(rollback) = std::fs::rename(old, &path) {
                            tracing::error!("failed to restore namespace `{namespace}` after reservation failure; old data retained at {:?}: {rollback}", old);
                        }
                    }
                    return Err(e);
                }
            }
        } else {
            None
        };
        Ok((detached, reservation))
    }

    async fn remove_detached_directory(path: Option<PathBuf>) -> crate::Result<()> {
        if let Some(path) = path {
            tokio::fs::remove_dir_all(&path).await?;
        }
        Ok(())
    }

    pub async fn destroy(&self, namespace: NamespaceName, prune_all: bool) -> crate::Result<()> {
        self.destroy_with_commit_signal(namespace, prune_all, None)
            .await
    }

    async fn destroy_with_commit_signal(
        &self,
        namespace: NamespaceName,
        prune_all: bool,
        after_commit_started: Option<Arc<tokio::sync::Notify>>,
    ) -> crate::Result<()> {
        let operation = self.lock_names(&[namespace.clone()]).await?;
        // Until remote backup confirmation, metadata and the old inode remain
        // available. Cancellation here cannot strand a metadata-less orphan.
        if !self.inner.metadata.exists(&namespace).await {
            return Err(Error::NamespaceDoesntExist(namespace.to_string()));
        }
        let expected = self.cleanup_directory_identity(&namespace).await?;
        let db_config = self.inner.metadata.handle(namespace.clone()).await;
        let generation = self
            .inner
            .metadata
            .generation(&namespace)
            .expect("persisted namespace has a generation");
        let mut bottomless_db_id_init = NamespaceBottomlessDbIdInit::FetchFromConfig;
        if let Some(ns) = self.inner.store.remove(&namespace).await {
            if let Some(ns) = ns.write().await.take() {
                bottomless_db_id_init = NamespaceBottomlessDbIdInit::Provided(
                    NamespaceBottomlessDbId::from_config(&ns.db_config_store.get()),
                );
                ns.destroy().await?;
            }
        }

        self.prepare_cleanup(
            &namespace,
            &db_config.get(),
            prune_all,
            bottomless_db_id_init,
        )
        .await?;

        // From this point on, cancellation of the request must not interrupt
        // the metadata+directory teardown. Transfer the name lock to a worker
        // BEFORE the next await; shutdown and a new create wait for this lock.
        let store = self.clone();
        let task = tokio::spawn(async move {
            let _operation = operation;
            // If the directory changed during backup, preserve its row and
            // files for operator repair instead of deleting a replacement.
            if store.cleanup_directory_identity(&namespace).await? != expected {
                return Err(Error::InvalidPath(format!(
                    "namespace `{namespace}` directory changed before confirmed teardown"
                )));
            }
            // Persist the intent before the database transaction. Recovery
            // rolls it back if the row survived, and finishes teardown if not.
            tokio::task::spawn_blocking({
                let store = store.clone();
                let name = namespace.clone();
                move || store.persist_destroy_intent(&name, expected)
            })
            .await??;
            let metadata = store.inner.metadata.clone();
            let name = namespace.clone();
            let removed = tokio::task::spawn_blocking(move || {
                metadata
                    .remove_if_generation(name.clone(), Some(&generation))?
                    .ok_or_else(|| Error::NamespaceDoesntExist(name.to_string()))
            })
            .await?;
            if let Err(e) = removed {
                // A commit error can be ambiguous. The in-memory watch map
                // may still contain a row that SQLite has already deleted.
                // Check the committed SQL state before discarding the intent;
                // on any uncertainty leave it to startup reconciliation.
                let persisted = tokio::task::spawn_blocking({
                    let metadata = store.inner.metadata.clone();
                    let name = namespace.clone();
                    move || metadata.persisted_namespace_exists(&name)
                })
                .await;
                match persisted {
                    Ok(Ok(true))
                        if expected.is_some()
                            && store.cleanup_directory_identity(&namespace).await? == expected =>
                    {
                        tokio::task::spawn_blocking({
                            let store = store.clone();
                            let name = namespace.clone();
                            move || store.clear_destroy_intent(&name)
                        })
                        .await??;
                    }
                    Ok(Err(ref check_error)) => tracing::warn!(
                        "retaining destroy intent after failed persisted-row check: {check_error}"
                    ),
                    Err(ref check_error) => tracing::warn!(
                        "retaining destroy intent after failed persisted-row worker: {check_error}"
                    ),
                    _ => {}
                }
                return Err(e);
            }
            let (detached, _) = store
                .detach_owned_directory(
                    &namespace,
                    expected,
                    false,
                    Some(store.destroy_quarantine_path(&namespace)),
                )
                .await?;
            Self::remove_detached_directory(detached).await?;
            // Durable completion of quarantine removal precedes clearing the
            // intent, so restart cannot lose the record for stranded files.
            let quarantine_root = store.destroy_quarantine_path(&namespace);
            if expected.is_some() {
                tokio::task::spawn_blocking(move || {
                    sync_directory(quarantine_root.parent().unwrap())
                })
                .await??;
            }
            tokio::task::spawn_blocking({
                let store = store.clone();
                let name = namespace.clone();
                move || store.clear_destroy_intent(&name)
            })
            .await??;
            tracing::info!("destroyed namespace: {namespace}");
            Ok(())
        });
        if let Some(ready) = after_commit_started {
            ready.notify_one();
        }
        task.await?
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

    async fn release_unpublished_reset_pin(&self, namespace: &NamespaceName) {
        // A sync failure after atomic publication leaves the valid final
        // intent in place; keep the pin and fail closed. A failed temp write
        // left no intent and must not constrain ordinary future updates.
        if matches!(std::fs::symlink_metadata(self.reset_intent_path(namespace)),
            Err(ref e) if e.kind() == std::io::ErrorKind::NotFound)
        {
            let metadata = self.inner.metadata.clone();
            let name = namespace.clone();
            let _ = tokio::task::spawn_blocking(move || metadata.release_reset_pin(&name)).await;
        }
    }

    pub async fn reset(
        &self,
        namespace: NamespaceName,
        restore_option: RestoreOption,
    ) -> anyhow::Result<()> {
        let operation = self.lock_names(&[namespace.clone()]).await?;
        // The task owns the name lock before the request can be cancelled.
        // Never cancel setup after detaching the old inode: blocking/path-open
        // work can survive cancellation and corrupt a live rollback by name.
        let store = self.clone();
        tokio::spawn(async move {
            store
                .reset_owned(namespace, restore_option, operation)
                .await
        })
        .await?
    }

    async fn reset_owned(
        &self,
        namespace: NamespaceName,
        restore_option: RestoreOption,
        _operation: Vec<OwnedMutexGuard<()>>,
    ) -> anyhow::Result<()> {
        if !self.inner.metadata.exists(&namespace).await {
            return Err(Error::NamespaceDoesntExist(namespace.to_string()).into());
        }
        let old_identity = self
            .cleanup_directory_identity(&namespace)
            .await?
            .ok_or_else(|| {
                Error::InvalidPath(format!(
                    "reset of `{namespace}` needs an existing directory"
                ))
            })?;
        let entry = self
            .inner
            .store
            .get_with(namespace.clone(), async { Default::default() })
            .await;
        let mut lock = entry.write().await;
        if let Some(ns) = lock.take() {
            ns.destroy().await?;
        }
        // Revoke old handles and pin the original schema membership while
        // taking the SQL snapshot. A pending reset cannot switch schemas:
        // shared_schema_links is also the migration task worklist.
        let pinned = tokio::task::spawn_blocking({
            let metadata = self.inner.metadata.clone();
            let name = namespace.clone();
            move || metadata.pin_reset_and_snapshot(&name)
        })
        .await;
        let old_config = match pinned {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(e)) => return Err(e.into()),
            Err(e) => {
                self.release_unpublished_reset_pin(&namespace).await;
                return Err(e.into());
            }
        };
        // Registration takes the exclusive schema lock. Hold this shared
        // guard across the worker; after an error the journal fences future
        // registrations without starving the migration scheduler.
        // Use the exact committed snapshot, never the watch (which can lag a
        // SQL commit between the config worker's DB and watch updates).
        let old_schema = MetaStore::reset_snapshot_schema_lock(&namespace, &old_config)?;
        let _schema_guard = if let Some(schema) = old_schema {
            let guard = self.inner.schema_locks.acquire_shared(schema.clone()).await;
            let pending = tokio::task::spawn_blocking({
                let metadata = self.inner.metadata.clone();
                let schema = schema.clone();
                move || metadata.schema_has_pending_jobs(&schema)
            })
            .await;
            match pending {
                Ok(Ok(true)) => {
                    self.release_unpublished_reset_pin(&namespace).await;
                    return Err(Error::PendingMigrationOnSchema(schema).into());
                }
                Ok(Ok(false)) => Some(guard),
                Ok(Err(e)) => {
                    self.release_unpublished_reset_pin(&namespace).await;
                    return Err(e.into());
                }
                Err(e) => {
                    self.release_unpublished_reset_pin(&namespace).await;
                    return Err(e.into());
                }
            }
        } else {
            None
        };
        // Backup confirmation must use the same persisted config that will
        // be journaled; a lagging watch can have different backup/schema IDs.
        let pinned_config = self.inner.metadata.handle(namespace.clone()).await.get();
        if let Err(e) = self
            .prepare_cleanup(
                &namespace,
                &pinned_config,
                false,
                NamespaceBottomlessDbIdInit::FetchFromConfig,
            )
            .await
        {
            self.release_unpublished_reset_pin(&namespace).await;
            return Err(e.into());
        }
        let intent = ResetIntent {
            old_identity,
            old_config,
        };
        let bytes = match serde_json::to_vec(&intent) {
            Ok(bytes) => bytes,
            Err(e) => {
                self.release_unpublished_reset_pin(&namespace).await;
                return Err(e.into());
            }
        };
        let published = tokio::task::spawn_blocking({
            let store = self.clone();
            let name = namespace.clone();
            move || store.publish_reset_file(&store.reset_intent_path(&name), &bytes)
        })
        .await;
        match published {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                self.release_unpublished_reset_pin(&namespace).await;
                return Err(e.into());
            }
            Err(e) => {
                self.release_unpublished_reset_pin(&namespace).await;
                return Err(e.into());
            }
        }
        let (old, reservation) = self
            .detach_owned_directory(
                &namespace,
                Some(old_identity),
                true,
                Some(self.reset_quarantine_path(&namespace)),
            )
            .await?;
        let mut reservation = reservation.expect("reset reserves replacement directory");
        let fresh = self.inner.metadata.handle(namespace.clone()).await;
        let ns = match self.make_namespace(&namespace, fresh, restore_option).await {
            Ok(ns) => ns,
            Err(e) => {
                // No live rollback: an already queued path-open/blocking setup
                // write could target the old inode after rename-back. Leave the
                // intent and old data fenced until all workers die on restart.
                tracing::error!(
                    "reset setup failed for `{namespace}`; old data retained until restart: {e}"
                );
                NAMESPACE_QUARANTINE_COUNT.increment(1);
                reservation.disarm();
                return Err(e.into());
            }
        };
        // Committing the marker chooses the new incarnation on restart. The
        // original cannot be deleted before this publication is durable.
        let new_identity = reservation.identity.ok_or_else(|| {
            Error::InvalidPath(format!(
                "reset of `{namespace}` has no new directory identity"
            ))
        })?;
        if self.cleanup_directory_identity(&namespace).await? != Some(new_identity) {
            return Err(Error::InvalidPath(format!(
                "reset of `{namespace}` replaced its new directory"
            ))
            .into());
        }
        tokio::task::spawn_blocking({
            let store = self.clone();
            let name = namespace.clone();
            let marker = format!("committed {} {}\n", new_identity.0, new_identity.1);
            move || store.publish_reset_file(&store.reset_committed_path(&name), marker.as_bytes())
        })
        .await??;
        reservation.disarm();
        lock.replace(ns);
        tokio::task::spawn_blocking({
            let metadata = self.inner.metadata.clone();
            let name = namespace.clone();
            move || metadata.release_reset_pin(&name)
        })
        .await?;
        Self::remove_detached_directory(old).await?;
        let root = self.reset_quarantine_path(&namespace);
        tokio::task::spawn_blocking(move || sync_directory(root.parent().unwrap())).await??;
        tokio::task::spawn_blocking({
            let store = self.clone();
            move || store.clear_reset_intent(&namespace)
        })
        .await??;
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
        if from == to {
            return Err(Error::NamespaceAlreadyExist(to.to_string()));
        }
        let operation = self.lock_names(&[from.clone(), to.clone()]).await?;
        if self.inner.has_shutdown.load(Ordering::Relaxed) {
            return Err(Error::NamespaceStoreShutdown);
        }

        // check that the source namespace exists
        if !self.inner.metadata.exists(&from).await {
            return Err(crate::error::Error::NamespaceDoesntExist(from.to_string()));
        }

        // Reject a persisted destination before inserting an empty cache
        // entry: an unloaded existing namespace must remain loadable after
        // the rejected fork. The name lock excludes competing create/destroy.
        if self.inner.metadata.exists(&to).await {
            return Err(Error::NamespaceAlreadyExist(to.to_string()));
        }
        let to_entry = self
            .inner
            .store
            .get_with(to.clone(), async { Default::default() })
            .await;
        let mut to_lock = to_entry.write().await;
        if to_lock.is_some() || self.inner.metadata.exists(&to).await {
            return Err(crate::error::Error::NamespaceAlreadyExist(to.to_string()));
        }

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

        // Atomic mkdir is the filesystem's identity check: it rejects case and
        // normalization aliases as well as orphan directories and symlinks.
        // Reserve before creating any destination metadata.
        let destination = {
            let _identity = self.inner.fs_operations.lock().await;
            if self.inner.metadata.exists(&to).await {
                return Err(Error::NamespaceAlreadyExist(to.to_string()));
            }
            self.reserve_directory(&to).await?
        };
        self.inner.metadata.activate_for_create(&to);
        let mut cleanup = pending_cleanup(
            self.inner.metadata.clone(),
            to.clone(),
            destination,
            operation,
        );
        let mut shutdown = self.inner.shutdown_signal.subscribe();
        let work = async {
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

            // Persist only after the destination is ready; do not publish an
            // unflushed namespace or leave it running if the flush fails.
            if let Err(e) = handle.flush().await {
                if let Err(shutdown_err) = to_ns.shutdown(false).await {
                    tracing::error!("failed to shut down uncommitted fork: {shutdown_err}");
                }
                return Err(e);
            }
            Ok(to_ns)
        };
        let result = tokio::select! {
            biased;
            _ = shutdown.wait_for(|requested| *requested) => {
                // Cancellation keeps the new directory quarantined; the guard
                // drains queued config updates without blocking this runtime.
                return Err(Error::NamespaceStoreShutdown);
            }
            result = work => result,
        };
        match result {
            Ok(to_ns) => {
                // No fallible or cancellable step after publishing.
                to_lock.replace(to_ns);
                if let Some(mut pending) = cleanup.disarm() {
                    pending.directory.disarm();
                }
                Ok(())
            }
            Err(e) => {
                cleanup.finish().await;
                Err(e)
            }
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
        self.with_after_initial_check(namespace, f, std::future::ready(()))
            .await
    }

    // The hook permits deterministic regression coverage of a delete racing
    // the first metadata read. Production callers pass an immediately ready
    // future and add no scheduling point.
    async fn with_after_initial_check<Fun, R, Hook>(
        &self,
        namespace: NamespaceName,
        f: Fun,
        after_check: Hook,
    ) -> crate::Result<R>
    where
        Fun: FnOnce(&Namespace) -> R,
        Hook: std::future::Future<Output = ()>,
    {
        if namespace != NamespaceName::default()
            && !self.inner.metadata.exists(&namespace).await
            && !self.inner.allow_lazy_creation
        {
            return Err(Error::NamespaceDoesntExist(namespace.to_string()));
        }

        after_check.await;
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

        if self.inner.db_kind.is_primary() && namespace == NamespaceName::default() {
            // The first request may race startup or another first request.
            // This is internal ensure/load, not an explicit create operation.
            // Recheck under the fs lock only when the namespace is not yet
            // loaded, so ordinary requests do not serialize on it.
            let loaded = self
                .inner
                .store
                .get(&namespace)
                .await
                .is_some_and(|entry| entry.try_read().is_some_and(|ns| ns.is_some()));
            if !loaded {
                self.ensure_default_namespace().await?;
            }
        }
        // A cached namespace needs only its entry read lock. For a cache miss,
        // own this name through the entire load/handshake, including any
        // incompatible-log quarantine. Do not hold this lock over f: callers
        // may themselves resolve other namespaces.
        if let Some(entry) = self.inner.store.get(&namespace).await {
            if entry.try_read().is_some_and(|guard| guard.is_some()) {
                return f(entry).await;
            }
        }
        let _name_operation = self.lock_names(&[namespace.clone()]).await?;
        let is_new = !self.inner.metadata.exists(&namespace).await;
        // The initial check above preceded this lock. A concurrent destroy
        // may have removed the persisted row in between; never resurrect a
        // primary cache miss using the default config without its metadata.
        if is_new
            && self.inner.db_kind.is_primary()
            && namespace != NamespaceName::default()
            && !self.inner.allow_lazy_creation
        {
            return Err(Error::NamespaceDoesntExist(namespace.to_string()));
        }
        // Replicas can have an exact, previously replicated directory without
        // local metadata. Reserve/check it before handle() registers a name.
        let mut reservation = if is_new && self.inner.db_kind.is_replica() {
            let _identity = self.inner.fs_operations.lock().await;
            match self.reserve_directory(&namespace).await {
                Ok(reservation) => Some(reservation),
                Err(Error::NamespaceAlreadyExist(_)) => {
                    self.check_existing_directory(&namespace).await?;
                    None
                }
                Err(e) => return Err(e),
            }
        } else {
            None
        };
        if is_new && self.inner.db_kind.is_replica() {
            self.inner.metadata.activate_for_create(&namespace);
        }
        let handle = self.inner.metadata.handle(namespace.to_owned()).await;
        let entry = self
            .load_namespace(&namespace, handle, RestoreOption::Latest)
            .await?;
        if let Some(ref mut reservation) = reservation {
            reservation.disarm();
        }
        drop(_name_operation);
        f(entry).await
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
        // A prior failed/cancelled fork may have published a None cache entry;
        // the persisted metastore row, not that placeholder, is authoritative.
        self.forget_empty_cache_entry(namespace).await;
        let init = async {
            let mut reservation = self.ensure_existing_directory(namespace).await?;
            // If opening a persisted namespace whose directory was missing
            // fails or is cancelled, leave its new directory for repair. It
            // has no operation guard and cannot safely race a later destroy.
            let ns = self
                .make_namespace(namespace, db_config, restore_option)
                .await?;
            if let Some(ref mut reservation) = reservation {
                reservation.disarm();
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
        if ns.read().await.is_none() {
            return Err(Error::NamespaceDoesntExist(namespace.to_string()));
        }

        Ok(ns)
    }

    async fn forget_empty_cache_entry(&self, namespace: &NamespaceName) {
        // Checkpoint and failed forks can leave an empty cache entry. It must
        // not prevent a legitimate persisted namespace from loading.
        if let Some(entry) = self.inner.store.get(namespace).await {
            let empty = entry.read().await.is_none();
            if empty {
                self.inner.store.invalidate(namespace).await;
            }
        }
    }

    /// Internal startup/lazy-load path. Unlike explicit create, an existing
    /// default is loaded using its persisted config rather than replaced.
    pub(crate) async fn ensure_default_namespace(&self) -> crate::Result<()> {
        let namespace = NamespaceName::default();
        let operation = self.lock_names(&[namespace.clone()]).await?;
        if self.inner.has_shutdown.load(Ordering::Relaxed) {
            return Err(Error::NamespaceStoreShutdown);
        }
        self.forget_empty_cache_entry(&namespace).await;
        if self.inner.metadata.exists(&namespace).await {
            let handle = self.inner.metadata.handle(namespace.clone()).await;
            self.load_namespace(&namespace, handle, RestoreOption::Latest)
                .await?;
        } else {
            self.create_new_namespace(
                namespace,
                RestoreOption::Latest,
                DatabaseConfig::default(),
                operation,
            )
            .await?;
        }
        Ok(())
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

        let operation = self.lock_names(&[namespace.clone()]).await?;
        if self.inner.has_shutdown.load(Ordering::Relaxed) {
            return Err(Error::NamespaceStoreShutdown);
        }
        if self.inner.metadata.exists(&namespace).await {
            return Err(Error::NamespaceAlreadyExist(namespace.to_string()));
        }
        self.create_new_namespace(namespace, restore_option, db_config, operation)
            .await
    }

    // Caller holds the namespace operation lock. The filesystem identity
    // lock below covers only the atomic reservation, not dump/setup/cleanup.
    async fn create_new_namespace(
        &self,
        namespace: NamespaceName,
        restore_option: RestoreOption,
        db_config: DatabaseConfig,
        operation: Vec<OwnedMutexGuard<()>>,
    ) -> crate::Result<()> {
        // Protect new namespace identity before publishing its metadata.
        let reservation = {
            let _identity = self.inner.fs_operations.lock().await;
            if self.inner.metadata.exists(&namespace).await {
                return Err(Error::NamespaceAlreadyExist(namespace.to_string()));
            }
            self.reserve_directory(&namespace).await?
        };
        self.inner.metadata.activate_for_create(&namespace);
        let mut cleanup = pending_cleanup(
            self.inner.metadata.clone(),
            namespace.clone(),
            reservation,
            operation,
        );
        let mut shutdown = self.inner.shutdown_signal.subscribe();
        let work = async {
            // A failed/cancelled fork may have left an empty cache entry for
            // this name; it must not make a subsequent create skip setup.
            self.forget_empty_cache_entry(&namespace).await;
            let handle = self.inner.metadata.handle(namespace.clone()).await;
            handle.store(Arc::new(db_config)).await?;
            tracing::debug!("completed storing db config, loading namespace");
            self.load_namespace(&namespace, handle, restore_option)
                .await?;
            Ok(())
        };
        let result = tokio::select! {
            biased;
            _ = shutdown.wait_for(|requested| *requested) => {
                return Err(Error::NamespaceStoreShutdown);
            }
            result = work => result,
        };
        match result {
            Ok(()) => {
                if let Some(mut pending) = cleanup.disarm() {
                    pending.directory.disarm();
                }
                tracing::debug!("completed loading namespace");
                Ok(())
            }
            Err(e) => {
                cleanup.finish().await;
                Err(e)
            }
        }
    }

    pub async fn shutdown(self) -> crate::Result<()> {
        // Existing server shutdown defaults to 30s. Reserve 10s for namespace
        // and metastore backup after draining in-flight operations.
        self.shutdown_with_timeout(Duration::from_secs(20)).await
    }

    async fn shutdown_with_timeout(self, operation_drain_timeout: Duration) -> crate::Result<()> {
        let mut set = JoinSet::new();
        self.inner.has_shutdown.store(true, Ordering::Relaxed);
        self.inner.shutdown_signal.send_replace(true);
        let locks = {
            let registry = self.inner.name_operations.lock().unwrap();
            let mut locks = registry
                .iter()
                .filter_map(|(name, lock)| lock.upgrade().map(|lock| (name.clone(), lock)))
                .collect::<Vec<_>>();
            locks.sort_by(|(a, _), (b, _)| a.as_str().cmp(b.as_str()));
            locks.into_iter().map(|(_, lock)| lock).collect::<Vec<_>>()
        };
        let identity = self.inner.fs_operations.clone();
        let (_operations, identity_guard) = tokio::time::timeout(operation_drain_timeout, async move {
            let mut guards = Vec::with_capacity(locks.len());
            for lock in locks {
                guards.push(lock.lock_owned().await);
            }
            let identity = identity.lock_owned().await;
            (guards, identity)
        })
        .await
        .map_err(|_| Error::Blocked(Some("namespace operations did not drain before shutdown; incomplete directories remain quarantined".into())))?;
        // No new operations can enter after has_shutdown. Release every
        // coordination lock before checkpoint or shutdown callbacks, which
        // may otherwise reenter namespace loading.
        drop(identity_guard);
        drop(_operations);

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

    /// Called under the scheduler's exclusive schema lock before registration.
    /// An in-progress reset holds the shared lock; a failed reset leaves an
    /// intent that prevents enqueuing a task targeting its fenced namespace.
    pub(crate) async fn ensure_schema_has_no_pending_resets(
        &self,
        schema: &NamespaceName,
    ) -> crate::Result<()> {
        // Also fence reset of the schema namespace itself, not just tenants
        // linked to it. The caller holds this schema's exclusive lock.
        for path in [
            self.reset_intent_path(schema),
            self.reset_committed_path(schema),
        ] {
            match std::fs::symlink_metadata(&path) {
                Ok(_) => {
                    return Err(Error::InvalidPath(format!(
                        "migration on `{schema}` blocked by its own pending reset"
                    )))
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        let namespaces = tokio::task::spawn_blocking({
            let metadata = self.inner.metadata.clone();
            let schema = schema.clone();
            move || metadata.linked_namespaces(&schema)
        })
        .await??;
        for namespace in namespaces {
            for path in [
                self.reset_intent_path(&namespace),
                self.reset_committed_path(&namespace),
            ] {
                match std::fs::symlink_metadata(&path) {
                    Ok(_) => {
                        return Err(Error::InvalidPath(format!(
                            "migration on `{schema}` blocked by pending reset of `{namespace}`"
                        )))
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
        Ok(())
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

    async fn prepare_cleanup(
        &self,
        namespace: &NamespaceName,
        db_config: &DatabaseConfig,
        prune_all: bool,
        bottomless_db_id_init: NamespaceBottomlessDbIdInit,
    ) -> crate::Result<()> {
        self.get_configurator(db_config)
            .prepare_cleanup(namespace, db_config, prune_all, bottomless_db_id_init)
            .await
    }
}
