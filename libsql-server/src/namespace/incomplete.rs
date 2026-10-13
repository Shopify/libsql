//! On-disk protocol for namespaces whose creation has not completed.
//!
//! A namespace directory carries [`INCOMPLETE_MARKER`] from the moment it is created until the
//! namespace's config has been persisted to the metastore. A directory that still carries it
//! belongs to a creation that did not complete — the request failed or was cancelled and the
//! cleanup could not finish, or the process died — and is garbage.
//!
//! Garbage is never deleted in place: [`discard_dir`] atomically renames the directory into
//! `<base>/.discarded/` first, so that its path under `dbs/` is free immediately and nothing that
//! still has files open in it (an import executor finishing its rollback, say) can recreate
//! anything under the old path, and deletes the tombstone in the background. [`sweep`] removes
//! tombstones and marked orphans left by a crash at startup.
//!
//! See `docs/ATOMIC_NAMESPACE_CREATE_DESIGN.md`.

use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use std::time::Duration;

#[cfg(test)]
use crate::connection::config::DatabaseConfig;

use super::meta_store::MetaStore;
use super::NamespaceName;

/// Present in a namespace directory until its config has been persisted to the metastore.
pub(crate) const INCOMPLETE_MARKER: &str = ".incomplete";

/// Where discarded directories go before they are deleted.
const DISCARDED_DIR: &str = ".discarded";

/// Path of the directory of namespace `name`.
pub(crate) fn namespace_dir(base: &Path, name: &NamespaceName) -> PathBuf {
    base.join("dbs").join(name.as_str())
}

/// Create the directory of a namespace that does not exist yet, marked incomplete.
///
/// Synchronous (a few small filesystem operations) so that there is no await point between
/// creating the directory and marking it. The marker and the directory entry are fsynced: the
/// marker must be durable before anything else in the directory can be, or a power loss could
/// leave a directory with content but no marker, which nothing would dare discard.
pub(crate) fn create_marked_dir(db_path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(db_path)?;
    mark_incomplete(db_path)
}

/// Write the marker into an existing directory and make it durable.
pub(crate) fn mark_incomplete(db_path: &Path) -> std::io::Result<()> {
    std::fs::File::create(db_path.join(INCOMPLETE_MARKER))?.sync_all()?;
    std::fs::File::open(db_path)?.sync_all()
}

/// Remove `db_path` (a namespace directory under `base`): rename it into the discarded area
/// right away and delete it in the background. Returns `Ok` if it does not exist.
///
/// Synchronous so that it can run in `Drop` and on the blocking pool; the rename is instant,
/// the deletion is handed to the runtime (or done inline if there is none).
pub(crate) fn discard_dir(base: &Path, db_path: &Path) -> std::io::Result<()> {
    let discarded = base.join(DISCARDED_DIR);
    std::fs::create_dir_all(&discarded)?;
    let name = db_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tombstone = discarded.join(format!("{name}-{}", uuid::Uuid::new_v4()));
    match std::fs::rename(db_path, &tombstone) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    }
    tracing::info!(
        path = %db_path.display(),
        tombstone = %tombstone.display(),
        "discarded namespace directory"
    );
    delete_in_background(tombstone);
    Ok(())
}

/// Discard the directory of `name` under `base` if it carries the marker. Directories without
/// the marker are left alone.
pub(crate) fn discard_if_incomplete(base: &Path, name: &NamespaceName) -> std::io::Result<bool> {
    let db_path = namespace_dir(base, name);
    if !db_path.join(INCOMPLETE_MARKER).try_exists()? {
        return Ok(false);
    }
    tracing::warn!(
        namespace = %name,
        path = %db_path.display(),
        "discarding namespace directory left by a creation that did not complete"
    );
    discard_dir(base, &db_path)?;
    metrics::increment_counter!("libsql_server_namespace_create_discarded_incomplete");
    Ok(true)
}

fn delete_in_background(tombstone: PathBuf) {
    let delete = move || {
        if let Err(e) = std::fs::remove_dir_all(&tombstone) {
            if e.kind() != std::io::ErrorKind::NotFound {
                // left for `sweep` at the next start
                tracing::error!(
                    path = %tombstone.display(),
                    "failed to delete discarded namespace directory: {e}"
                );
            }
        }
    };
    match tokio::runtime::Handle::try_current() {
        Ok(rt) => {
            rt.spawn_blocking(delete);
        }
        Err(_) => delete(),
    }
}

/// Startup sweep: delete leftover tombstones and discard marked directories of namespaces the
/// metastore does not know (creations the process died in the middle of).
pub(crate) async fn sweep(base: &Path, meta_store: &MetaStore) -> std::io::Result<()> {
    let discarded = base.join(DISCARDED_DIR);
    if let Ok(entries) = std::fs::read_dir(&discarded) {
        for entry in entries.flatten() {
            tracing::warn!(path = %entry.path().display(), "deleting leftover discarded namespace directory");
            delete_in_background(entry.path());
        }
    }

    let dbs = base.join("dbs");
    let Ok(entries) = std::fs::read_dir(&dbs) else {
        return Ok(());
    };
    for entry in entries.flatten() {
        if !entry.path().join(INCOMPLETE_MARKER).try_exists()? {
            continue;
        }
        let Ok(name) = NamespaceName::from_string(entry.file_name().to_string_lossy().into_owned())
        else {
            continue;
        };
        if meta_store.exists(&name).await {
            // persisted, but the marker was not removed yet (crash right after the commit); it
            // is removed when the namespace is loaded
            continue;
        }
        discard_if_incomplete(base, &name)?;
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::database::DatabaseKind;
    use crate::namespace::meta_store::metastore_connection_maker;

    async fn meta_store(path: &Path) -> MetaStore {
        let (maker, manager) = metastore_connection_maker(None, path).await.unwrap();
        MetaStore::new(
            Default::default(),
            path,
            maker().unwrap(),
            manager,
            DatabaseKind::Primary,
        )
        .await
        .unwrap()
    }

    fn ns(s: &str) -> NamespaceName {
        NamespaceName::from_string(s.into()).unwrap()
    }

    #[tokio::test]
    async fn discard_dir_frees_the_path_immediately() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("dbs").join("foo");
        create_marked_dir(&dir).unwrap();
        std::fs::write(dir.join("data"), b"junk").unwrap();
        // a file is still open inside; the rename doesn't care, and neither does the deletion
        let _open = std::fs::File::open(dir.join("data")).unwrap();

        discard_dir(tmp.path(), &dir).unwrap();
        assert!(!dir.exists());
        // idempotent
        discard_dir(tmp.path(), &dir).unwrap();

        for _ in 0..100 {
            if std::fs::read_dir(tmp.path().join(DISCARDED_DIR))
                .unwrap()
                .next()
                .is_none()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("tombstone was not deleted");
    }

    /// Startup: tombstones are deleted; marked directories of names the metastore doesn't
    /// know are discarded; marked directories of known names and unmarked directories stay.
    #[tokio::test]
    async fn sweep_cleans_leftovers_of_a_crash() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let store = meta_store(base).await;
        store
            .handle(ns("known"))
            .await
            .store(Arc::new(DatabaseConfig::default()))
            .await
            .unwrap();

        let tombstone = base.join(DISCARDED_DIR).join("old-123");
        std::fs::create_dir_all(&tombstone).unwrap();
        std::fs::write(tombstone.join("data"), b"junk").unwrap();
        let crashed = base.join("dbs").join("crashed");
        create_marked_dir(&crashed).unwrap();
        let known = base.join("dbs").join("known");
        create_marked_dir(&known).unwrap();
        let unmarked = base.join("dbs").join("unmarked");
        std::fs::create_dir_all(&unmarked).unwrap();

        sweep(base, &store).await.unwrap();

        assert!(!crashed.exists());
        assert!(
            known.join(INCOMPLETE_MARKER).exists(),
            "known: left for load"
        );
        assert!(unmarked.exists());
        for _ in 0..100 {
            if !tombstone.exists() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("tombstone was not deleted");
    }

    /// Rebuilding an empty metastore from the filesystem must not adopt a directory whose
    /// creation never completed.
    #[tokio::test]
    async fn recovery_from_fs_skips_marked_directories() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        std::fs::create_dir_all(base.join("dbs").join("complete")).unwrap();
        create_marked_dir(&base.join("dbs").join("crashed")).unwrap();

        let (maker, manager) = metastore_connection_maker(None, base).await.unwrap();
        let store = MetaStore::new(
            crate::config::MetaStoreConfig {
                allow_recover_from_fs: true,
                ..Default::default()
            },
            base,
            maker().unwrap(),
            manager,
            DatabaseKind::Primary,
        )
        .await
        .unwrap();

        assert!(store.exists(&ns("complete")).await);
        assert!(!store.exists(&ns("crashed")).await);
    }
}
