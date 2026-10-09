use std::path::Path;
use std::sync::Weak;
use std::sync::{atomic::AtomicBool, Arc};
use std::time::Duration;

use anyhow::Context as _;
use bottomless::replicator::Options;
use enclose::enclose;
use libsql_sys::EncryptionConfig;
use tokio::task::JoinSet;

use crate::connection::config::DatabaseConfig;
use crate::connection::connection_manager::InnerWalManager;
use crate::connection::legacy::MakeLegacyConnection;
use crate::connection::{Connection as _, MakeConnection, MakeThrottledConnection};
use crate::database::PrimaryConnectionMaker;
use crate::error::LoadDumpError;
use crate::namespace::broadcasters::BroadcasterHandle;
use crate::namespace::meta_store::MetaStoreHandle;
use crate::namespace::replication_wal::{make_replication_wal_wrapper, ReplicationWalWrapper};
use crate::namespace::{
    NamespaceBottomlessDbId, NamespaceBottomlessDbIdInit, NamespaceName, ResolveNamespacePathFn,
    RestoreOption, INCOMPLETE_MARKER,
};
use crate::replication::ReplicationLogger;
use crate::stats::Stats;
use crate::{StatsSender, BLOCKING_RT, DB_CREATE_TIMEOUT, DEFAULT_AUTO_CHECKPOINT};

use super::{BaseNamespaceConfig, PrimaryConfig};

/// The directory of a namespace that does not exist yet.
///
/// Created (with the [`INCOMPLETE_MARKER`]) by [`begin`](Self::begin) and removed again when the
/// guard is dropped before [`keep`](Self::keep) is called: on error, or when the request that was
/// creating the namespace is cancelled and its future dropped. The marker itself is removed by
/// the namespace store once the namespace's config is persisted.
pub(super) struct FreshDir {
    path: Option<Arc<Path>>,
}

impl FreshDir {
    /// Returns `None` when a namespace directory already exists at `db_path`.
    pub(super) async fn begin(db_path: &Arc<Path>) -> crate::Result<Option<Self>> {
        if db_path.try_exists()? {
            return Ok(None);
        }
        tokio::fs::create_dir_all(db_path).await?;
        tokio::fs::File::create(db_path.join(INCOMPLETE_MARKER)).await?;
        Ok(Some(Self {
            path: Some(db_path.clone()),
        }))
    }

    /// The namespace was set up; the directory stays.
    pub(super) fn keep(mut self) {
        self.path.take();
    }
}

impl Drop for FreshDir {
    fn drop(&mut self) {
        let Some(path) = self.path.take() else {
            return;
        };
        tracing::warn!(
            path = %path.display(),
            "namespace creation did not complete; removing its directory"
        );
        // Dropping may happen while the creating future is being torn down (cancellation), so
        // the removal is handed to the runtime rather than awaited here. Should it fail, the
        // directory still carries the marker and the next creation of this namespace discards it.
        match tokio::runtime::Handle::try_current() {
            Ok(rt) => {
                rt.spawn(async move {
                    if let Err(e) = tokio::fs::remove_dir_all(&*path).await {
                        log_remove_error(&path, e);
                    }
                });
            }
            Err(_) => {
                if let Err(e) = std::fs::remove_dir_all(&*path) {
                    log_remove_error(&path, e);
                }
            }
        }
    }
}

fn log_remove_error(path: &Path, e: std::io::Error) {
    if e.kind() != std::io::ErrorKind::NotFound {
        tracing::error!(
            path = %path.display(),
            "failed to remove unfinished namespace directory: {e}"
        );
    }
}

/// Remove `dbs/<namespace>` if it was left behind by a creation that never completed, i.e. if it
/// still carries the [`INCOMPLETE_MARKER`]. Directories without the marker are left alone.
pub(super) async fn discard_incomplete(
    base: &BaseNamespaceConfig,
    namespace: &NamespaceName,
) -> crate::Result<()> {
    let db_path = base.base_path.join("dbs").join(namespace.as_str());
    if !db_path.join(INCOMPLETE_MARKER).try_exists()? {
        return Ok(());
    }
    tracing::warn!(
        namespace = %namespace,
        path = %db_path.display(),
        "discarding namespace directory left by an interrupted creation"
    );
    metrics::increment_counter!("libsql_server_namespace_create_discarded_incomplete");
    tokio::fs::remove_dir_all(&db_path).await?;
    Ok(())
}

#[tracing::instrument(skip_all)]
pub(super) async fn make_primary_connection_maker(
    primary_config: &PrimaryConfig,
    base_config: &BaseNamespaceConfig,
    meta_store_handle: &MetaStoreHandle,
    db_path: &Path,
    name: &NamespaceName,
    restore_option: RestoreOption,
    block_writes: Arc<AtomicBool>,
    join_set: &mut JoinSet<anyhow::Result<()>>,
    resolve_attach_path: ResolveNamespacePathFn,
    broadcaster: BroadcasterHandle,
    make_wal_manager: Arc<dyn Fn() -> InnerWalManager + Sync + Send + 'static>,
    encryption_config: Option<EncryptionConfig>,
) -> crate::Result<(
    Arc<PrimaryConnectionMaker>,
    ReplicationWalWrapper,
    Arc<Stats>,
)> {
    let db_config = meta_store_handle.get();
    let bottomless_db_id = NamespaceBottomlessDbId::from_config(&db_config);
    // FIXME: figure how to to it per-db
    let mut is_dirty = {
        let sentinel_path = db_path.join(".sentinel");
        if sentinel_path.try_exists()? {
            if std::env::var("LIBSQL_IGNORE_DIRTY_LOG").is_ok() {
                tracing::warn!("ignoring dirty log");
                false
            } else {
                true
            }
        } else {
            tokio::fs::File::create(&sentinel_path).await?;
            false
        }
    };

    // FIXME: due to a bug in logger::checkpoint_db we call regular checkpointing code
    // instead of our virtual WAL one. It's a bit tangled to fix right now, because
    // we need WAL context for checkpointing, and WAL context needs the ReplicationLogger...
    // So instead we checkpoint early, *before* bottomless gets initialized. That way
    // we're sure bottomless won't try to back up any existing WAL frames and will instead
    // treat the existing db file as the source of truth.

    let bottomless_replicator = match primary_config.bottomless_replication {
        Some(ref options) => {
            // TODO: figure out why we really need this the fixme above is not clear enough but
            // disabling this allows us to prevent checkpointing of the wal file.
            if !std::env::var("LIBSQL_DISABLE_INIT_CHECKPOINTING").is_ok() {
                tracing::debug!("Checkpointing before initializing bottomless");
                crate::replication::primary::logger::checkpoint_db(&db_path.join("data"))?;
                tracing::debug!("Checkpointed before initializing bottomless");
            } else {
                tracing::warn!("Disabling initial checkpoint before bottomless");
            }

            let options = make_bottomless_options(options, bottomless_db_id, name.clone());
            let (replicator, did_recover) =
                init_bottomless_replicator(db_path.join("data"), options, &restore_option).await?;
            tracing::debug!("Completed init of bottomless replicator");
            is_dirty |= did_recover;
            Some(replicator)
        }
        None => None,
    };

    tracing::debug!("Checking fresh db");
    let is_fresh_db = check_fresh_db(&db_path)?;
    // switch frame-count checkpoint to time-based one
    let auto_checkpoint = if primary_config.checkpoint_interval.is_some() {
        0
    } else {
        DEFAULT_AUTO_CHECKPOINT
    };

    let logger = Arc::new(ReplicationLogger::open(
        &db_path,
        primary_config.max_log_size,
        primary_config.max_log_duration,
        is_dirty,
        auto_checkpoint,
        primary_config.scripted_backup.clone(),
        name.clone(),
        encryption_config.clone(),
    )?);

    tracing::debug!("sending stats");

    let stats = make_stats(
        &db_path,
        join_set,
        meta_store_handle.clone(),
        base_config.stats_sender.clone(),
        name.clone(),
    )
    .await?;

    join_set.spawn({
        let stats = stats.clone();
        let mut rcv = logger.new_frame_notifier.subscribe();
        async move {
            let _ = rcv
                .wait_for(move |fno| {
                    if let Some(fno) = *fno {
                        stats.set_current_frame_no(fno);
                    }
                    false
                })
                .await;
            Ok(())
        }
    });

    tracing::debug!("Making replication wal wrapper");
    let wal_wrapper = make_replication_wal_wrapper(bottomless_replicator, logger.clone());

    tracing::debug!("Opening libsql connection");

    let get_current_frame_no = Arc::new({
        let rcv = logger.new_frame_notifier.subscribe();
        move || *rcv.borrow()
    });
    let connection_maker = Arc::new(
        MakeLegacyConnection::new(
            db_path.to_path_buf(),
            wal_wrapper.clone(),
            stats.clone(),
            broadcaster,
            meta_store_handle.clone(),
            base_config.extensions.clone(),
            base_config.max_response_size,
            base_config.max_total_response_size,
            auto_checkpoint,
            get_current_frame_no,
            encryption_config,
            block_writes,
            resolve_attach_path,
            make_wal_manager.clone(),
        )
        .await?
        .throttled(
            base_config.max_concurrent_connections.clone(),
            base_config
                .connection_creation_timeout
                .or(Some(DB_CREATE_TIMEOUT)),
            base_config.max_total_response_size,
            base_config.max_concurrent_requests,
            base_config.disable_intelligent_throttling,
        ),
    );

    tracing::debug!("Completed opening libsql connection");

    join_set.spawn(run_storage_monitor(
        Arc::downgrade(&stats),
        connection_maker.clone(),
    ));

    // this must happen after we create the connection maker. The connection maker old on a
    // connection to ensure that no other connection is closing while we try to open the dump.
    // that would cause a SQLITE_LOCKED error.
    match restore_option {
        RestoreOption::Dump(_) if !is_fresh_db => {
            Err(LoadDumpError::LoadDumpExistingDb)?;
        }
        RestoreOption::Dump(source) => {
            let conn = connection_maker.create().await?;
            let kind = source
                .importer
                .unwrap_or(base_config.dump_import.default_importer);
            crate::namespace::dump_import::load_dump(
                kind,
                source.stream,
                conn,
                &base_config.dump_import,
                name,
            )
            .await?;
        }
        _ => { /* other cases were already handled when creating bottomless */ }
    }

    join_set.spawn(run_periodic_compactions(logger.clone()));

    tracing::debug!("Done making primary connection");

    Ok((connection_maker, wal_wrapper, stats))
}

pub(super) fn make_bottomless_options(
    options: &Options,
    namespace_db_id: NamespaceBottomlessDbId,
    name: NamespaceName,
) -> Options {
    let mut options = options.clone();
    let mut db_id = match namespace_db_id {
        NamespaceBottomlessDbId::Namespace(id) => id,
        // FIXME(marin): I don't like that, if bottomless is enabled, proper config must be passed.
        NamespaceBottomlessDbId::NotProvided => options.db_id.unwrap_or_default(),
    };

    db_id = format!("ns-{db_id}:{name}");
    options.db_id = Some(db_id);
    options
}

async fn init_bottomless_replicator(
    path: impl AsRef<std::path::Path>,
    options: bottomless::replicator::Options,
    restore_option: &RestoreOption,
) -> anyhow::Result<(bottomless::replicator::Replicator, bool)> {
    tracing::debug!("Initializing bottomless replication");
    let path = path
        .as_ref()
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid db path"))?
        .to_owned();
    let mut replicator = bottomless::replicator::Replicator::with_options(path, options).await?;

    let (generation, timestamp) = match restore_option {
        RestoreOption::Latest | RestoreOption::Dump(_) => (None, None),
        RestoreOption::Generation(generation) => (Some(*generation), None),
        RestoreOption::PointInTime(timestamp) => (None, Some(*timestamp)),
    };

    let (action, did_recover) = replicator.restore(generation, timestamp).await?;
    match action {
        bottomless::replicator::RestoreAction::SnapshotMainDbFile => {
            replicator.new_generation().await;
            if let Some(_handle) = replicator.snapshot_main_db_file(true).await? {
                tracing::trace!("got snapshot handle after restore with generation upgrade");
            }
            // Restoration process only leaves the local WAL file if it was
            // detected to be newer than its remote counterpart.
            replicator.maybe_replicate_wal().await?
        }
        bottomless::replicator::RestoreAction::ReuseGeneration(gen) => {
            replicator.set_generation(gen);
        }
    }

    Ok((replicator, did_recover))
}

async fn run_periodic_compactions(logger: Arc<ReplicationLogger>) -> anyhow::Result<()> {
    // calling `ReplicationLogger::maybe_compact()` is cheap if the compaction does not actually
    // take place, so we can afford to poll it very often for simplicity
    let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(1000));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        interval.tick().await;
        let handle = BLOCKING_RT.spawn_blocking(enclose! {(logger) move || {
            logger.maybe_compact()
        }});
        handle
            .await
            .expect("Compaction task crashed")
            .context("Compaction failed")?;
    }
}

fn check_fresh_db(path: &Path) -> crate::Result<bool> {
    let is_fresh = !path.join("wallog").try_exists()?;
    Ok(is_fresh)
}

pub(super) async fn make_stats(
    db_path: &Path,
    join_set: &mut JoinSet<anyhow::Result<()>>,
    meta_store_handle: MetaStoreHandle,
    stats_sender: StatsSender,
    name: NamespaceName,
) -> anyhow::Result<Arc<Stats>> {
    tracing::debug!("creating stats type");
    let stats = Stats::new(name.clone(), db_path, join_set).await?;

    // the storage monitor is optional, so we ignore the error here.
    tracing::debug!("stats created, sending stats");
    let _ = stats_sender
        .send((name.clone(), meta_store_handle, Arc::downgrade(&stats)))
        .await;

    tracing::debug!("done sending stats, and creating bg tasks");

    Ok(stats)
}

// Periodically check the storage used by the database and save it in the Stats structure.
// TODO: Once we have a separate fiber that does WAL checkpoints, running this routine
// right after checkpointing is exactly where it should be done.
pub(crate) async fn run_storage_monitor<M: MakeConnection>(
    stats: Weak<Stats>,
    connection_maker: Arc<MakeThrottledConnection<M>>,
) -> anyhow::Result<()> {
    // on initialization, the database file doesn't exist yet, so we wait a bit for it to be
    // created
    tokio::time::sleep(Duration::from_secs(1)).await;

    let duration = tokio::time::Duration::from_secs(60);
    loop {
        let Some(stats) = stats.upgrade() else {
            return Ok(());
        };

        match connection_maker.untracked().await {
            Ok(conn) => {
                let _ = BLOCKING_RT
                    .spawn_blocking(move || {
                        conn.with_raw(|conn| {
                            if let Ok(tx) = conn.transaction() {
                                let page_count = tx.query_row("pragma page_count;", [], |row| {
                                    row.get::<usize, u64>(0)
                                });
                                let freelist_count =
                                    tx.query_row("pragma freelist_count;", [], |row| {
                                        row.get::<usize, u64>(0)
                                    });
                                if let (Ok(page_count), Ok(freelist_count)) =
                                    (page_count, freelist_count)
                                {
                                    let storage_bytes_used = (page_count - freelist_count) * 4096;
                                    stats.set_storage_bytes_used(storage_bytes_used);
                                }
                            }
                        })
                    })
                    .await;
            }
            Err(e) => {
                tracing::warn!("failed to open connection for storage monitor: {e}, trying again in {duration:?}");
            }
        }

        tokio::time::sleep(duration).await;
    }
}

pub(super) async fn cleanup_primary(
    base: &BaseNamespaceConfig,
    primary_config: &PrimaryConfig,
    namespace: &NamespaceName,
    db_config: &DatabaseConfig,
    prune_all: bool,
    bottomless_db_id_init: NamespaceBottomlessDbIdInit,
) -> crate::Result<()> {
    let ns_path = base.base_path.join("dbs").join(namespace.as_str());
    if let Some(ref options) = primary_config.bottomless_replication {
        let bottomless_db_id = match bottomless_db_id_init {
            NamespaceBottomlessDbIdInit::Provided(db_id) => db_id,
            NamespaceBottomlessDbIdInit::FetchFromConfig => {
                NamespaceBottomlessDbId::from_config(db_config)
            }
        };
        let options = make_bottomless_options(options, bottomless_db_id, namespace.clone());
        let replicator = bottomless::replicator::Replicator::with_options(
            ns_path.join("data").to_str().unwrap(),
            options,
        )
        .await?;
        if prune_all {
            let delete_all = replicator.delete_all(None).await?;
            // perform hard deletion in the background
            tokio::spawn(delete_all.commit());
        } else {
            // for soft delete make sure that local db is fully backed up
            replicator.savepoint().confirmed().await?;
        }
    }

    if ns_path.try_exists()? {
        tracing::debug!("removing database directory: {}", ns_path.display());
        tokio::fs::remove_dir_all(ns_path).await?;
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    async fn settle() {
        // the removal is spawned; give it a chance to run
        for _ in 0..50 {
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    #[tokio::test]
    async fn fresh_dir_is_removed_unless_kept() {
        let tmp = tempfile::tempdir().unwrap();
        let path: Arc<Path> = tmp.path().join("dbs").join("ns").into();

        let fresh = FreshDir::begin(&path).await.unwrap().expect("fresh");
        assert!(path.join(INCOMPLETE_MARKER).exists());
        drop(fresh);
        settle().await;
        assert!(!path.exists(), "dropped before keep: removed");

        let fresh = FreshDir::begin(&path).await.unwrap().expect("fresh again");
        fresh.keep();
        settle().await;
        assert!(
            path.join(INCOMPLETE_MARKER).exists(),
            "kept: stays, marker included"
        );

        assert!(
            FreshDir::begin(&path).await.unwrap().is_none(),
            "an existing directory is not fresh"
        );
    }

    #[tokio::test]
    async fn fresh_dir_is_removed_when_its_future_is_dropped() {
        let tmp = tempfile::tempdir().unwrap();
        let path: Arc<Path> = tmp.path().join("dbs").join("ns").into();

        let setup = {
            let path = path.clone();
            async move {
                let fresh = FreshDir::begin(&path).await.unwrap();
                std::future::pending::<()>().await; // "the import"
                fresh.map(FreshDir::keep);
            }
        };
        let aborted = tokio::time::timeout(Duration::from_millis(50), setup).await;
        assert!(aborted.is_err());
        settle().await;
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn discard_incomplete_only_removes_marked_directories() {
        let tmp = tempfile::tempdir().unwrap();
        let base = BaseNamespaceConfig {
            base_path: tmp.path().into(),
            extensions: Arc::new([]),
            stats_sender: tokio::sync::mpsc::channel(1).0,
            max_response_size: 0,
            max_total_response_size: 0,
            max_concurrent_connections: Arc::new(tokio::sync::Semaphore::new(1)),
            max_concurrent_requests: 0,
            encryption_config: None,
            connection_creation_timeout: None,
            disable_intelligent_throttling: false,
            dump_import: Default::default(),
        };
        let marked = tmp.path().join("dbs").join("marked");
        let unmarked = tmp.path().join("dbs").join("unmarked");
        for dir in [&marked, &unmarked] {
            std::fs::create_dir_all(dir).unwrap();
            std::fs::write(dir.join("data"), b"junk").unwrap();
        }
        std::fs::write(marked.join(INCOMPLETE_MARKER), b"").unwrap();

        discard_incomplete(&base, &NamespaceName::from_string("marked".into()).unwrap())
            .await
            .unwrap();
        discard_incomplete(
            &base,
            &NamespaceName::from_string("unmarked".into()).unwrap(),
        )
        .await
        .unwrap();
        discard_incomplete(&base, &NamespaceName::from_string("absent".into()).unwrap())
            .await
            .unwrap();

        assert!(!marked.exists());
        assert!(unmarked.join("data").exists());
    }
}
