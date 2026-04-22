use std::path::Path;
use std::sync::Arc;

use anyhow::Context as _;
use bytes::Bytes;
use chrono::NaiveDateTime;
use futures_core::{Future, Stream};
use tokio::task::JoinSet;
use uuid::Uuid;

use crate::auth::parse_jwt_keys;
use crate::connection::config::DatabaseConfig;
use crate::connection::Connection as _;
use crate::database::Database;
use crate::stats::Stats;

use self::meta_store::MetaStoreHandle;
pub use self::name::NamespaceName;
pub use self::store::NamespaceStore;

pub mod broadcasters;
pub(crate) mod configurator;
pub mod meta_store;
mod name;
pub mod replication_wal;
mod schema_lock;
mod store;

pub type ResetCb = Box<dyn Fn(ResetOp) + Send + Sync + 'static>;
pub type ResolveNamespacePathFn =
    Arc<dyn Fn(&NamespaceName) -> crate::Result<Arc<Path>> + Sync + Send + 'static>;

pub enum ResetOp {
    Reset(NamespaceName),
}

#[derive(Clone, Debug)]
pub enum NamespaceBottomlessDbId {
    Namespace(String),
    NotProvided,
}

impl NamespaceBottomlessDbId {
    fn from_config(config: &DatabaseConfig) -> NamespaceBottomlessDbId {
        match config.bottomless_db_id.clone() {
            Some(db_id) => NamespaceBottomlessDbId::Namespace(db_id),
            None => NamespaceBottomlessDbId::NotProvided,
        }
    }
}

#[derive(Clone, Debug)]
pub enum NamespaceBottomlessDbIdInit {
    Provided(NamespaceBottomlessDbId),
    FetchFromConfig,
}

/// A namespace isolates the resources pertaining to a database of type T
#[derive(Debug)]
pub struct Namespace {
    pub db: Database,
    name: NamespaceName,
    /// The set of tasks associated with this namespace
    tasks: JoinSet<anyhow::Result<()>>,
    stats: Arc<Stats>,
    db_config_store: MetaStoreHandle,
    path: Arc<Path>,
}

impl Namespace {
    pub(crate) fn name(&self) -> &NamespaceName {
        &self.name
    }

    /// On-disk path of this namespace's files (data, wallog, snapshots/,
    /// to_compact/, .sentinel).
    pub(crate) fn path(&self) -> &Arc<Path> {
        &self.path
    }

    async fn destroy(mut self) -> anyhow::Result<()> {
        self.tasks.shutdown().await;
        self.db.destroy();
        Ok(())
    }

    async fn checkpoint(&self) -> anyhow::Result<()> {
        let conn = self.db.connection_maker().create().await?;
        conn.vacuum_if_needed().await?;
        conn.checkpoint().await?;
        Ok(())
    }

    /// Run `PRAGMA quick_check` (or `integrity_check` if `full=true`) on
    /// the namespace's live DB file and return the result string.
    ///
    /// For a healthy DB this returns `"ok"`. Anything else is an
    /// integrity diagnostic message from SQLite.
    ///
    /// A catastrophically corrupt DB can fail before PRAGMA runs (e.g.
    /// `malformed database schema` raised while the prepared statement
    /// is parsing the schema). We normalize that into the same
    /// `Ok(String)` return path so callers get a uniform classification
    /// signal instead of a server error.
    async fn integrity_check(&self, full: bool) -> anyhow::Result<String> {
        // Even creating a connection can fail ("malformed database schema")
        // when the DB is badly corrupt — that IS an integrity signal so we
        // surface it as `Ok(String)` rather than an Err that becomes a 500.
        let conn = match self.db.connection_maker().create().await {
            Ok(c) => c,
            Err(e) => {
                return Ok(format!("connection failed: {e}"));
            }
        };
        let pragma = if full { "integrity_check" } else { "quick_check" };
        let result = conn.with_raw(move |raw| -> rusqlite::Result<Vec<String>> {
            let mut stmt = raw.prepare(&format!("PRAGMA {pragma}"))?;
            let mut rows = stmt.query([])?;
            let mut out = Vec::new();
            while let Some(row) = rows.next()? {
                let s: String = row.get(0)?;
                out.push(s);
            }
            Ok(out)
        });
        match result {
            Ok(rows) => Ok(rows.join("\n")),
            Err(e) => {
                // SQLite surfaces integrity failures as prepare/query errors
                // rather than PRAGMA rows. Treat those as integrity signals.
                Ok(format!("{e}"))
            }
        }
    }

    async fn shutdown(mut self, should_checkpoint: bool) -> anyhow::Result<()> {
        self.tasks.shutdown().await;
        if should_checkpoint {
            self.checkpoint().await?;
        }
        self.db.shutdown().await?;
        // Historically `.sentinel` was removed unconditionally on graceful
        // shutdown. This makes the documented `touch .sentinel + kubectl
        // delete pod` operator recovery path silently ineffective, because
        // kubectl sends SIGTERM first which invokes this graceful shutdown
        // and removes the sentinel before the pod actually stops.
        //
        // Guard the removal behind `LIBSQL_PRESERVE_SENTINEL_ON_SHUTDOWN`.
        // When set, the sentinel survives graceful shutdown, so the next
        // namespace init will correctly trigger dirty-recovery from the
        // live `data` file.
        //
        // Default remains: remove (preserves existing behavior for the
        // 99% of deployments that don't need this recovery path, now that
        // `POST /v1/namespaces/:ns/reset-replication` is the primary
        // recovery primitive).
        let preserve_sentinel =
            std::env::var("LIBSQL_PRESERVE_SENTINEL_ON_SHUTDOWN").is_ok();
        if !preserve_sentinel {
            if let Err(e) = tokio::fs::remove_file(self.path.join(".sentinel")).await {
                tracing::error!("unable to remove .sentinel file: {}", e);
            }
        } else {
            tracing::info!(
                "LIBSQL_PRESERVE_SENTINEL_ON_SHUTDOWN set; keeping .sentinel for recovery"
            );
        }
        Ok(())
    }

    pub fn config(&self) -> Arc<DatabaseConfig> {
        self.db_config_store.get()
    }

    pub fn config_version(&self) -> usize {
        self.db_config_store.version()
    }

    pub fn jwt_keys(&self) -> crate::Result<Option<Vec<jsonwebtoken::DecodingKey>>> {
        let config = self.db_config_store.get();
        if let Some(jwt_key) = config.jwt_key.as_deref() {
            Ok(Some(
                parse_jwt_keys(jwt_key).context("Could not parse JWT decoding key(s)")?,
            ))
        } else {
            Ok(None)
        }
    }

    pub fn stats(&self) -> Arc<Stats> {
        self.stats.clone()
    }

    pub fn config_changed(&self) -> impl Future<Output = ()> {
        self.db_config_store.changed()
    }
}

pub type DumpStream =
    Box<dyn Stream<Item = std::io::Result<Bytes>> + Send + Sync + 'static + Unpin>;

#[derive(Default)]
pub enum RestoreOption {
    /// Restore database state from the most recent version found in a backup.
    #[default]
    Latest,
    /// Restore database from SQLite dump.
    Dump(DumpStream),
    /// Restore database state to a backup version equal to specific generation.
    Generation(Uuid),
    /// Restore database state to a backup version present at a specific point in time.
    /// Granularity depends of how frequently WAL log pages are being snapshotted.
    PointInTime(NaiveDateTime),
}
