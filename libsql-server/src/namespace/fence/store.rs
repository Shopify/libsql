//! Durable fence state: the metastore tables, the fence compare-and-swap, and the
//! per-namespace marker file (`docs/NAMESPACE_FENCE.md` sections 5.1 and 5.4 to 5.6).
//!
//! Everything here runs on a metastore connection, inside a transaction the caller opened with
//! `BEGIN IMMEDIATE`, so a fence transition, an ordinary config write and a delete of the same
//! namespace are serialised by SQLite's write lock whichever connection they use. The functions
//! only read and write rows and files: what a command does is decided by
//! [`transition::apply`](super::transition::apply), and when the result is published is the
//! caller's decision, made only after the transaction has committed.
//!
//! Reading is strict. A row with an unknown format version, an undecodable payload, or a
//! revision column that disagrees with its payload, and a marker that says more than the
//! metastore does, all read as [`StoredFence::Unavailable`]: the namespace is
//! `UNKNOWN_UNAVAILABLE` and every gate that consults it stays closed.

use std::fs::{self, File};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use prost::Message as _;
use rusqlite::{params, OptionalExtension};
use uuid::Uuid;

use crate::connection::config::{DatabaseConfig, DurabilityMode};
use crate::namespace::NamespaceName;
use crate::LIBSQL_PAGE_SIZE;
use libsql_replication::rpc::metadata;

use super::command::TargetConfig;
use super::outcome::{FenceDetail, FenceError, FenceOutcome};
use super::record::{
    CommandReceipt, FenceDecodeError, FenceMarker, LegacyBlocks, NamespaceFenceRecord,
    FENCE_FORMAT_VERSION,
};
use super::state::{FenceState, OperationClass};
use super::transition::CurrentFence;

/// Name of the per-namespace marker file, inside the namespace's directory.
pub const MARKER_FILE_NAME: &str = ".fence";

/// How long receipts of finished operations are kept by default (section 5.5).
pub const DEFAULT_RECEIPT_RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);

const CREATE_FENCES_TABLE: &str = "
    CREATE TABLE IF NOT EXISTS namespace_fences (
        namespace TEXT NOT NULL PRIMARY KEY,
        format_version INTEGER NOT NULL,
        revision INTEGER NOT NULL,
        record BLOB NOT NULL,
        FOREIGN KEY (namespace) REFERENCES namespace_configs (namespace)
            ON DELETE RESTRICT ON UPDATE RESTRICT
    )";

const CREATE_RECEIPTS_TABLE: &str = "
    CREATE TABLE IF NOT EXISTS namespace_fence_receipts (
        namespace TEXT NOT NULL,
        operation_id TEXT NOT NULL,
        command_id TEXT NOT NULL,
        format_version INTEGER NOT NULL,
        revision_after INTEGER NOT NULL,
        applied_at INTEGER NOT NULL,
        receipt BLOB NOT NULL,
        PRIMARY KEY (namespace, operation_id, command_id)
    )";

/// Errors of the persistence layer. A fence outcome is a result the caller answers with; the
/// others are faults of the metastore or the filesystem.
#[derive(Debug, thiserror::Error)]
pub enum FenceStoreError {
    #[error(transparent)]
    Fence(#[from] FenceError),
    #[error("metastore error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("fence marker I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Create the fence tables. Called when the fence is enabled; the tables are additive, and
/// the metastore of a server that never enabled the fence does not have them.
pub fn create_tables(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    conn.execute(CREATE_FENCES_TABLE, ())?;
    conn.execute(CREATE_RECEIPTS_TABLE, ())?;
    Ok(())
}

/// Whether this metastore has ever held fence state. Once it has, fences are loaded and
/// enforced whether or not the fence is enabled (section 13.1).
pub fn tables_exist(conn: &rusqlite::Connection) -> rusqlite::Result<bool> {
    let count: i64 = conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table'
            AND name IN ('namespace_fences', 'namespace_fence_receipts')",
        (),
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

/// What the store established about one namespace's fence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredFence {
    /// No fence record and no marker. `namespace_exists` is whether the namespace has a config
    /// row: `UNFENCED` when it does, `ABSENT` when it does not.
    None {
        namespace_exists: bool,
    },
    Record(NamespaceFenceRecord),
    /// The control state cannot be established: `UNKNOWN_UNAVAILABLE`.
    Unavailable {
        detail: FenceDetail,
        /// What was wrong, for the operator log and `InspectFence`.
        reason: String,
        /// The record the marker file holds, when it has a readable one.
        marker: Option<NamespaceFenceRecord>,
    },
}

impl StoredFence {
    pub fn as_current(&self) -> CurrentFence<'_> {
        match self {
            StoredFence::None { namespace_exists } => CurrentFence::None {
                namespace_exists: *namespace_exists,
            },
            StoredFence::Record(r) => CurrentFence::Record(r),
            StoredFence::Unavailable { detail, marker, .. } => CurrentFence::Unavailable {
                detail: *detail,
                marker: marker.as_ref(),
            },
        }
    }

    pub fn state(&self) -> FenceState {
        self.as_current().state()
    }

    pub fn revision(&self) -> u64 {
        self.as_current().revision()
    }

    pub fn record(&self) -> Option<&NamespaceFenceRecord> {
        match self {
            StoredFence::Record(r) => Some(r),
            _ => None,
        }
    }

    /// The permission-matrix decision for work of `class`, as an error a caller can return.
    pub fn permits(&self, class: OperationClass) -> Result<(), FenceError> {
        self.state().permits(class).map_err(|outcome| {
            let err = FenceError::new(outcome, self.denial_message(class));
            match self {
                StoredFence::Unavailable { detail, .. } => err.with_detail(*detail),
                _ => err,
            }
        })
    }

    fn denial_message(&self, class: OperationClass) -> String {
        match self {
            StoredFence::Record(r) => format!(
                "{class:?} is not permitted while the namespace fence is {} (operation {}, revision {})",
                r.state, r.operation_id, r.revision
            ),
            StoredFence::Unavailable { reason, .. } => {
                format!("the namespace's fence state cannot be established: {reason}")
            }
            StoredFence::None { .. } => format!("{class:?} is not permitted"),
        }
    }
}

/// Where the marker of `namespace` lives, under the server's `dbs` directory.
pub fn marker_path(dbs_path: &Path, namespace: &NamespaceName) -> PathBuf {
    dbs_path.join(namespace.as_str()).join(MARKER_FILE_NAME)
}

/// Read a namespace's marker. `Ok(None)` when there is none; `Ok(Some(Err(_)))` when there is
/// one that cannot be decoded.
pub fn read_marker(
    dbs_path: &Path,
    namespace: &NamespaceName,
) -> io::Result<Option<Result<FenceMarker, FenceDecodeError>>> {
    match fs::read(marker_path(dbs_path, namespace)) {
        Ok(bytes) => Ok(Some(FenceMarker::decode(&bytes))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Durably replace a namespace's marker with a copy of `record`: write a temporary file, fsync
/// it, rename it over the marker and fsync the directory. Creates the namespace directory if
/// it does not exist yet (a target that is being created).
pub fn write_marker(dbs_path: &Path, record: &NamespaceFenceRecord) -> io::Result<()> {
    let path = marker_path(dbs_path, &record.namespace);
    let dir = path.parent().expect("marker path has a parent");
    fs::create_dir_all(dir)?;
    let tmp = dir.join(format!("{MARKER_FILE_NAME}.tmp"));
    {
        let mut file = File::create(&tmp)?;
        file.write_all(&FenceMarker::for_record(record).encode())?;
        file.sync_all()?;
    }
    fs::rename(&tmp, &path)?;
    File::open(dir)?.sync_all()?;
    Ok(())
}

/// Remove a namespace's marker, if it has one, and fsync its directory.
pub fn remove_marker(dbs_path: &Path, namespace: &NamespaceName) -> io::Result<()> {
    let path = marker_path(dbs_path, namespace);
    match fs::remove_file(&path) {
        Ok(()) => File::open(path.parent().expect("marker path has a parent"))?.sync_all(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// The namespace directories under `dbs_path` that hold a marker, in no particular order. A
/// directory whose name is not a valid namespace name is returned as its raw name, so the
/// caller can refuse to start rather than ignore it.
pub fn scan_markers(dbs_path: &Path) -> io::Result<Vec<Result<NamespaceName, String>>> {
    let entries = match fs::read_dir(dbs_path) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir() || !entry.path().join(MARKER_FILE_NAME).try_exists()? {
            continue;
        }
        let raw = entry.file_name();
        out.push(match raw.to_str() {
            Some(name) => {
                NamespaceName::from_string(name.to_string()).map_err(|_| name.to_string())
            }
            None => Err(raw.to_string_lossy().into_owned()),
        });
    }
    Ok(out)
}

/// Whether the marker agrees with what the metastore says. Returned by [`read_fence`] so a
/// loader can repair a marker that fell behind (a crash between commit and marker write).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkerStatus {
    /// The marker holds the stored record, or there is neither.
    Current,
    /// The metastore has a record and the marker is missing or older: rewrite it.
    Stale,
    /// The marker is what makes the namespace unavailable, or cannot be read.
    Conflicting,
}

struct RawFenceRow {
    format_version: i64,
    revision: i64,
    record: Vec<u8>,
}

fn read_raw_row(
    conn: &rusqlite::Connection,
    namespace: &NamespaceName,
) -> rusqlite::Result<Option<RawFenceRow>> {
    conn.query_row(
        "SELECT format_version, revision, record FROM namespace_fences WHERE namespace = ?1",
        [namespace.as_str()],
        |row| {
            Ok(RawFenceRow {
                format_version: row.get(0)?,
                revision: row.get(1)?,
                record: row.get(2)?,
            })
        },
    )
    .optional()
}

/// The stored revision column of `namespace`'s fence row, whatever its payload says.
pub fn stored_revision(
    conn: &rusqlite::Connection,
    namespace: &NamespaceName,
) -> rusqlite::Result<Option<i64>> {
    conn.query_row(
        "SELECT revision FROM namespace_fences WHERE namespace = ?1",
        [namespace.as_str()],
        |row| row.get(0),
    )
    .optional()
}

/// Like [`stored_revision`], for a namespace name that is not a valid [`NamespaceName`].
pub fn stored_revision_raw(
    conn: &rusqlite::Connection,
    namespace: &str,
) -> rusqlite::Result<Option<i64>> {
    conn.query_row(
        "SELECT revision FROM namespace_fences WHERE namespace = ?1",
        [namespace],
        |row| row.get(0),
    )
    .optional()
}

fn decode_row(row: &RawFenceRow) -> Result<NamespaceFenceRecord, FenceDecodeError> {
    let format_version = u32::try_from(row.format_version)
        .map_err(|_| FenceDecodeError::UnsupportedFormatVersion(u32::MAX))?;
    let revision = u64::try_from(row.revision)
        .map_err(|_| FenceDecodeError::Invalid("negative revision column"))?;
    NamespaceFenceRecord::decode(format_version, revision, &row.record)
}

fn decode_detail(e: &FenceDecodeError) -> FenceDetail {
    match e {
        FenceDecodeError::UnsupportedFormatVersion(_) => FenceDetail::UnsupportedFormatVersion,
        FenceDecodeError::Undecodable(_) | FenceDecodeError::Invalid(_) => {
            FenceDetail::CorruptRecord
        }
    }
}

/// Read the config row of `namespace`, if it has one.
pub fn read_config_row(
    conn: &rusqlite::Connection,
    namespace: &NamespaceName,
) -> Result<Option<DatabaseConfig>, FenceStoreError> {
    let bytes: Option<Vec<u8>> = conn
        .query_row(
            "SELECT config FROM namespace_configs WHERE namespace = ?1",
            [namespace.as_str()],
            |row| row.get(0),
        )
        .optional()?;
    match bytes {
        None => Ok(None),
        Some(bytes) => match metadata::DatabaseConfig::decode(&bytes[..]) {
            Ok(c) => Ok(Some(DatabaseConfig::from(&c))),
            Err(e) => Err(FenceError::new(
                FenceOutcome::FenceStateUnavailable,
                format!("the namespace's config row cannot be decoded: {e}"),
            )
            .with_detail(FenceDetail::CorruptRecord)
            .into()),
        },
    }
}

fn config_row_exists(
    conn: &rusqlite::Connection,
    namespace: &NamespaceName,
) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT count(*) FROM namespace_configs WHERE namespace = ?1",
        [namespace.as_str()],
        |row| row.get::<_, i64>(0),
    )
    .map(|n| n > 0)
}

/// Establish the fence of `namespace` from its row and its marker (section 5.6).
///
/// Only a metastore that has the fence tables can hold a record; `dbs_path` is where the
/// namespace directories, and so the markers, are.
pub fn read_fence(
    conn: &rusqlite::Connection,
    dbs_path: &Path,
    namespace: &NamespaceName,
) -> Result<(StoredFence, MarkerStatus), FenceStoreError> {
    let row = read_raw_row(conn, namespace)?;
    let marker = read_marker(dbs_path, namespace)?;

    let marker_record = match &marker {
        Some(Ok(m)) => Some(m.record.clone()),
        _ => None,
    };

    let Some(row) = row else {
        return Ok(match marker {
            None => (
                StoredFence::None {
                    namespace_exists: config_row_exists(conn, namespace)?,
                },
                MarkerStatus::Current,
            ),
            Some(Err(e)) => (
                StoredFence::Unavailable {
                    detail: FenceDetail::CorruptRecord,
                    reason: format!("the fence marker cannot be decoded: {e}"),
                    marker: None,
                },
                MarkerStatus::Conflicting,
            ),
            Some(Ok(m)) => {
                let incomplete_creation = m.record.state == FenceState::TargetQuarantined
                    && m.record.revision == 1
                    && !config_row_exists(conn, namespace)?;
                let (detail, reason) = if incomplete_creation {
                    (
                        FenceDetail::IncompleteTargetCreation,
                        "a target creation was interrupted before its metastore commit".to_string(),
                    )
                } else {
                    (
                        FenceDetail::MetastoreBehindMarker,
                        format!(
                            "the marker records revision {} but the metastore has no fence record",
                            m.record.revision
                        ),
                    )
                };
                (
                    StoredFence::Unavailable {
                        detail,
                        reason,
                        marker: Some(m.record),
                    },
                    MarkerStatus::Conflicting,
                )
            }
        });
    };

    let record = match decode_row(&row) {
        Ok(record) => record,
        Err(e) => {
            return Ok((
                StoredFence::Unavailable {
                    detail: decode_detail(&e),
                    reason: format!("the fence record cannot be read: {e}"),
                    marker: marker_record,
                },
                MarkerStatus::Conflicting,
            ))
        }
    };

    if record.namespace != *namespace {
        return Ok((
            StoredFence::Unavailable {
                detail: FenceDetail::CorruptRecord,
                reason: format!("the fence record names namespace `{}`", record.namespace),
                marker: marker_record,
            },
            MarkerStatus::Conflicting,
        ));
    }

    Ok(match marker {
        Some(Ok(m)) if m.record.revision > record.revision => (
            StoredFence::Unavailable {
                detail: FenceDetail::MetastoreBehindMarker,
                reason: format!(
                    "the marker records revision {} but the metastore has revision {}",
                    m.record.revision, record.revision
                ),
                marker: Some(m.record),
            },
            MarkerStatus::Conflicting,
        ),
        Some(Ok(m)) if m.record.revision == record.revision && m.record != record => (
            StoredFence::Unavailable {
                detail: FenceDetail::MetastoreBehindMarker,
                reason: format!(
                    "the marker and the metastore disagree at revision {}",
                    record.revision
                ),
                marker: Some(m.record),
            },
            MarkerStatus::Conflicting,
        ),
        Some(Ok(m)) if m.record == record => (StoredFence::Record(record), MarkerStatus::Current),
        // Missing, older, or unreadable while the metastore has a well-formed record: the
        // metastore is authoritative and the marker is rewritten.
        _ => (StoredFence::Record(record), MarkerStatus::Stale),
    })
}

/// Look up the receipt for `(namespace, operation_id, command_id)`.
pub fn read_receipt(
    conn: &rusqlite::Connection,
    namespace: &NamespaceName,
    operation_id: Uuid,
    command_id: Uuid,
) -> Result<Option<Result<CommandReceipt, FenceDecodeError>>, rusqlite::Error> {
    let row: Option<(i64, Vec<u8>)> = conn
        .query_row(
            "SELECT format_version, receipt FROM namespace_fence_receipts
                WHERE namespace = ?1 AND operation_id = ?2 AND command_id = ?3",
            params![
                namespace.as_str(),
                operation_id.to_string(),
                command_id.to_string()
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    Ok(row.map(|(v, bytes)| decode_receipt(v, &bytes, namespace, operation_id, command_id)))
}

fn decode_receipt(
    format_version: i64,
    bytes: &[u8],
    namespace: &NamespaceName,
    operation_id: Uuid,
    command_id: Uuid,
) -> Result<CommandReceipt, FenceDecodeError> {
    let format_version = u32::try_from(format_version)
        .map_err(|_| FenceDecodeError::UnsupportedFormatVersion(u32::MAX))?;
    let receipt = CommandReceipt::decode(format_version, bytes)?;
    if receipt.namespace != *namespace
        || receipt.operation_id != operation_id
        || receipt.command_id != command_id
    {
        return Err(FenceDecodeError::Invalid("receipt disagrees with its key"));
    }
    Ok(receipt)
}

/// One stored receipt, as read for inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredReceipt {
    pub operation_id: String,
    pub command_id: String,
    pub revision_after: i64,
    pub applied_at_ms: i64,
    pub receipt: Result<CommandReceipt, FenceDecodeError>,
}

/// Every receipt of `namespace`, oldest first.
pub fn read_receipts(
    conn: &rusqlite::Connection,
    namespace: &NamespaceName,
) -> rusqlite::Result<Vec<StoredReceipt>> {
    let mut stmt = conn.prepare(
        "SELECT operation_id, command_id, format_version, revision_after, applied_at, receipt
            FROM namespace_fence_receipts WHERE namespace = ?1
            ORDER BY applied_at, revision_after, operation_id, command_id",
    )?;
    let rows = stmt.query_map([namespace.as_str()], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, Vec<u8>>(5)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (op, cmd, version, revision_after, applied_at, bytes) = row?;
        let receipt = match (Uuid::parse_str(&op), Uuid::parse_str(&cmd)) {
            (Ok(op_id), Ok(cmd_id)) => decode_receipt(version, &bytes, namespace, op_id, cmd_id),
            _ => Err(FenceDecodeError::Invalid("receipt key is not a uuid")),
        };
        out.push(StoredReceipt {
            operation_id: op,
            command_id: cmd,
            revision_after,
            applied_at_ms: applied_at,
            receipt,
        });
    }
    Ok(out)
}

/// Compare-and-swap the fence row of `record.namespace`: it must currently have revision
/// `previous` (`None`: no row). The caller holds the write lock, so this only fails if the
/// caller read something other than what is stored, which is a bug; it is still checked.
pub fn write_record(
    conn: &rusqlite::Connection,
    record: &NamespaceFenceRecord,
    previous: Option<i64>,
) -> Result<(), FenceStoreError> {
    let revision = i64::try_from(record.revision).expect("revision fits in i64");
    let bytes = record.encode();
    let changed = match previous {
        None => conn.execute(
            "INSERT INTO namespace_fences (namespace, format_version, revision, record)
                VALUES (?1, ?2, ?3, ?4)",
            params![
                record.namespace.as_str(),
                FENCE_FORMAT_VERSION,
                revision,
                bytes
            ],
        )?,
        Some(previous) => conn.execute(
            "UPDATE namespace_fences SET format_version = ?2, revision = ?3, record = ?4
                WHERE namespace = ?1 AND revision = ?5",
            params![
                record.namespace.as_str(),
                FENCE_FORMAT_VERSION,
                revision,
                bytes,
                previous
            ],
        )?,
    };
    if changed != 1 {
        return Err(FenceError::new(
            FenceOutcome::FenceRevisionMismatch,
            "the stored fence record changed under the transition",
        )
        .into());
    }
    Ok(())
}

/// Store `receipt`, replacing any receipt with the same key (a finished drain replaces its
/// `DRAINING` receipt).
pub fn write_receipt(
    conn: &rusqlite::Connection,
    receipt: &CommandReceipt,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO namespace_fence_receipts
            (namespace, operation_id, command_id, format_version, revision_after, applied_at, receipt)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            receipt.namespace.as_str(),
            receipt.operation_id.to_string(),
            receipt.command_id.to_string(),
            FENCE_FORMAT_VERSION,
            i64::try_from(receipt.revision_after).expect("revision fits in i64"),
            receipt.applied_at_ms,
            receipt.encode(),
        ],
    )?;
    Ok(())
}

/// Prune receipts of operations other than `owner` that are older than `retention` at
/// `now_ms` (section 5.5). The owner's receipts are never pruned.
pub fn prune_receipts(
    conn: &rusqlite::Connection,
    namespace: &NamespaceName,
    owner: Uuid,
    now_ms: i64,
    retention: Duration,
) -> rusqlite::Result<usize> {
    let cutoff = now_ms.saturating_sub(i64::try_from(retention.as_millis()).unwrap_or(i64::MAX));
    conn.execute(
        "DELETE FROM namespace_fence_receipts
            WHERE namespace = ?1 AND operation_id != ?2 AND applied_at < ?3",
        params![namespace.as_str(), owner.to_string(), cutoff],
    )
}

/// Remove every trace of `namespace`'s fence, for a delete of a namespace whose fence permits
/// it. Returns the number of receipts removed.
pub fn delete_fence(
    conn: &rusqlite::Connection,
    namespace: &NamespaceName,
) -> rusqlite::Result<usize> {
    conn.execute(
        "DELETE FROM namespace_fences WHERE namespace = ?1",
        [namespace.as_str()],
    )?;
    conn.execute(
        "DELETE FROM namespace_fence_receipts WHERE namespace = ?1",
        [namespace.as_str()],
    )
}

/// The config as it is stored while `blocks` is the legacy mirror: `config` with its
/// `block_*` fields replaced (section 13.2).
pub fn with_legacy_blocks(config: &DatabaseConfig, blocks: &LegacyBlocks) -> DatabaseConfig {
    DatabaseConfig {
        block_reads: blocks.block_reads,
        block_writes: blocks.block_writes,
        block_reason: blocks.block_reason.clone(),
        ..config.clone()
    }
}

/// The namespace's own config, given its stored config row `stored` and its fence record: the
/// row with the record's saved `block_*` values in place of the mirror while the record
/// mirrors them, and the row itself once the operation has finished (section 13.2), since
/// config writes after a release or a write enable store the namespace's own values.
pub fn own_config(stored: &DatabaseConfig, record: &NamespaceFenceRecord) -> DatabaseConfig {
    if record.mirrors_legacy_blocks() {
        with_legacy_blocks(stored, &record.legacy_blocks)
    } else {
        stored.clone()
    }
}

/// The `block_*` fields of `config`.
pub fn legacy_blocks_of(config: &DatabaseConfig) -> LegacyBlocks {
    LegacyBlocks {
        block_reads: config.block_reads,
        block_writes: config.block_writes,
        block_reason: config.block_reason.clone(),
    }
}

/// Upsert the config row of `namespace`.
pub fn write_config_row(
    conn: &rusqlite::Connection,
    namespace: &NamespaceName,
    config: &DatabaseConfig,
) -> rusqlite::Result<()> {
    let encoded = metadata::DatabaseConfig::from(config).encode_to_vec();
    conn.execute(
        "INSERT INTO namespace_configs (namespace, config) VALUES (?1, ?2)
            ON CONFLICT(namespace) DO UPDATE SET config = excluded.config",
        params![namespace.as_str(), encoded],
    )?;
    Ok(())
}

/// The namespace config a target is created with, before the legacy mirror is applied.
pub fn target_database_config(config: &TargetConfig) -> Result<DatabaseConfig, FenceError> {
    let invalid = |message: String| {
        FenceError::new(FenceOutcome::FencePreconditionFailed, message)
            .with_detail(FenceDetail::InvalidArgument)
    };
    let mut out = DatabaseConfig::default();
    if let Some(bytes) = config.max_db_size {
        out.max_db_pages = bytes / LIBSQL_PAGE_SIZE;
    }
    out.jwt_key = config.jwt_key.clone();
    if let Some(s) = config.txn_timeout_s {
        out.txn_timeout = Some(Duration::from_secs(s));
    }
    out.allow_attach = config.allow_attach;
    if let Some(mode) = &config.durability_mode {
        out.durability_mode = mode
            .parse::<DurabilityMode>()
            .map_err(|()| invalid(format!("unknown durability mode `{mode}`")))?;
    }
    out.bottomless_db_id = config.bottomless_db_id.clone();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::namespace::fence::record::tests as samples;

    fn conn() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute("PRAGMA foreign_keys=ON", ()).unwrap();
        conn.execute(
            "CREATE TABLE namespace_configs (namespace TEXT NOT NULL PRIMARY KEY, config BLOB NOT NULL)",
            (),
        )
        .unwrap();
        create_tables(&conn).unwrap();
        conn
    }

    fn sample() -> NamespaceFenceRecord {
        samples::sample_record()
    }

    #[test]
    fn tables_are_additive_and_detectable() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        assert!(!tables_exist(&conn).unwrap());
        create_tables(&conn).unwrap();
        assert!(tables_exist(&conn).unwrap());
        // Idempotent.
        create_tables(&conn).unwrap();
    }

    #[test]
    fn record_round_trips_and_cas_checks_revision() {
        let dir = tempfile::tempdir().unwrap();
        let conn = conn();
        let record = sample();
        write_config_row(&conn, &record.namespace, &DatabaseConfig::default()).unwrap();
        write_record(&conn, &record, None).unwrap();
        // A second insert, or an update from the wrong revision, is refused.
        assert!(write_record(&conn, &record, None).is_err());
        let mut next = record.clone();
        next.revision += 1;
        let err = write_record(&conn, &next, Some(1)).unwrap_err();
        assert!(
            matches!(err, FenceStoreError::Fence(e) if e.outcome() == FenceOutcome::FenceRevisionMismatch)
        );
        write_record(&conn, &next, Some(2)).unwrap();

        let (stored, marker) = read_fence(&conn, dir.path(), &record.namespace).unwrap();
        assert_eq!(stored, StoredFence::Record(next));
        assert_eq!(marker, MarkerStatus::Stale);
    }

    #[test]
    fn fence_row_needs_a_config_row() {
        let conn = conn();
        let err = write_record(&conn, &sample(), None).unwrap_err();
        assert!(matches!(err, FenceStoreError::Sqlite(_)), "{err:?}");
    }

    #[test]
    fn delete_of_config_row_is_restricted_by_the_fence_row() {
        let conn = conn();
        let record = sample();
        write_config_row(&conn, &record.namespace, &DatabaseConfig::default()).unwrap();
        write_record(&conn, &record, None).unwrap();
        assert!(conn
            .execute(
                "DELETE FROM namespace_configs WHERE namespace = ?1",
                [record.namespace.as_str()]
            )
            .is_err());
        delete_fence(&conn, &record.namespace).unwrap();
        conn.execute(
            "DELETE FROM namespace_configs WHERE namespace = ?1",
            [record.namespace.as_str()],
        )
        .unwrap();
    }

    #[test]
    fn marker_round_trips_and_is_compared() {
        let dir = tempfile::tempdir().unwrap();
        let conn = conn();
        let record = sample();
        write_config_row(&conn, &record.namespace, &DatabaseConfig::default()).unwrap();
        write_record(&conn, &record, None).unwrap();
        write_marker(dir.path(), &record).unwrap();
        assert!(!dir
            .path()
            .join(record.namespace.as_str())
            .join(".fence.tmp")
            .exists());
        let (stored, status) = read_fence(&conn, dir.path(), &record.namespace).unwrap();
        assert_eq!(stored, StoredFence::Record(record.clone()));
        assert_eq!(status, MarkerStatus::Current);

        // A marker ahead of the metastore: the metastore went backwards.
        let mut ahead = record.clone();
        ahead.revision += 1;
        write_marker(dir.path(), &ahead).unwrap();
        let (stored, status) = read_fence(&conn, dir.path(), &record.namespace).unwrap();
        assert!(matches!(
            stored,
            StoredFence::Unavailable { detail: FenceDetail::MetastoreBehindMarker, marker: Some(ref m), .. } if *m == ahead
        ));
        assert_eq!(status, MarkerStatus::Conflicting);

        // Same revision, different contents.
        let mut forked = record.clone();
        forked.operation_id = Uuid::from_u128(77);
        write_marker(dir.path(), &forked).unwrap();
        let (stored, _) = read_fence(&conn, dir.path(), &record.namespace).unwrap();
        assert_eq!(stored.state(), FenceState::UnknownUnavailable);

        // An undecodable marker beside a good record: the record wins and the marker is stale.
        fs::write(marker_path(dir.path(), &record.namespace), b"garbage").unwrap();
        let (stored, status) = read_fence(&conn, dir.path(), &record.namespace).unwrap();
        assert_eq!(stored, StoredFence::Record(record.clone()));
        assert_eq!(status, MarkerStatus::Stale);

        // Marker without a row.
        delete_fence(&conn, &record.namespace).unwrap();
        write_marker(dir.path(), &record).unwrap();
        let (stored, _) = read_fence(&conn, dir.path(), &record.namespace).unwrap();
        assert!(matches!(
            stored,
            StoredFence::Unavailable {
                detail: FenceDetail::MetastoreBehindMarker,
                ..
            }
        ));
        fs::write(marker_path(dir.path(), &record.namespace), b"garbage").unwrap();
        let (stored, _) = read_fence(&conn, dir.path(), &record.namespace).unwrap();
        assert!(matches!(
            stored,
            StoredFence::Unavailable {
                detail: FenceDetail::CorruptRecord,
                marker: None,
                ..
            }
        ));
    }

    #[test]
    fn corrupt_rows_are_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let conn = conn();
        let record = sample();
        let ns = record.namespace.clone();
        write_config_row(&conn, &ns, &DatabaseConfig::default()).unwrap();
        write_record(&conn, &record, None).unwrap();

        let set = |sql: &str| {
            conn.execute(sql, [ns.as_str()]).unwrap();
        };
        let detail = || match read_fence(&conn, dir.path(), &ns).unwrap().0 {
            StoredFence::Unavailable { detail, .. } => detail,
            other => panic!("expected unavailable, got {other:?}"),
        };

        set("UPDATE namespace_fences SET format_version = 2 WHERE namespace = ?1");
        assert_eq!(detail(), FenceDetail::UnsupportedFormatVersion);
        set("UPDATE namespace_fences SET format_version = 1, revision = 3 WHERE namespace = ?1");
        assert_eq!(detail(), FenceDetail::CorruptRecord);
        set("UPDATE namespace_fences SET revision = 2, record = x'ffff' WHERE namespace = ?1");
        assert_eq!(detail(), FenceDetail::CorruptRecord);
        set("UPDATE namespace_fences SET revision = -1 WHERE namespace = ?1");
        assert_eq!(detail(), FenceDetail::CorruptRecord);

        let stored = read_fence(&conn, dir.path(), &ns).unwrap().0;
        for class in OperationClass::ALL {
            let r = stored.permits(class);
            match class {
                OperationClass::Maintenance | OperationClass::Observability => assert!(r.is_ok()),
                _ => {
                    let e = r.unwrap_err();
                    assert_eq!(e.outcome(), FenceOutcome::FenceStateUnavailable);
                    assert_eq!(e.detail(), Some(FenceDetail::CorruptRecord));
                }
            }
        }
    }

    #[test]
    fn receipts_round_trip_and_prune() {
        let conn = conn();
        let record = sample();
        let ns = record.namespace.clone();
        let base = samples::sample_receipt();
        let owner = base.operation_id;
        let other = Uuid::from_u128(0xbeef);

        let mut r_owner_old = base.clone();
        r_owner_old.applied_at_ms = 10;
        let mut r_other_old = base.clone();
        r_other_old.operation_id = other;
        r_other_old.applied_at_ms = 10;
        let mut r_other_new = base.clone();
        r_other_new.operation_id = other;
        r_other_new.command_id = Uuid::from_u128(0xc0de);
        r_other_new.applied_at_ms = 5_000;
        for r in [&r_owner_old, &r_other_old, &r_other_new] {
            write_receipt(&conn, r).unwrap();
        }
        assert_eq!(
            read_receipt(&conn, &ns, owner, base.command_id)
                .unwrap()
                .unwrap()
                .unwrap(),
            r_owner_old
        );
        assert!(read_receipt(&conn, &ns, owner, Uuid::from_u128(1234))
            .unwrap()
            .is_none());

        // Retention 1s at t=6s: only the other operation's old receipt goes.
        let pruned = prune_receipts(&conn, &ns, owner, 6_000, Duration::from_secs(1)).unwrap();
        assert_eq!(pruned, 1);
        let left: Vec<_> = read_receipts(&conn, &ns)
            .unwrap()
            .into_iter()
            .map(|r| r.receipt.unwrap())
            .collect();
        assert_eq!(left, vec![r_owner_old.clone(), r_other_new]);

        // A receipt stored under the wrong key reads as corrupt.
        conn.execute(
            "UPDATE namespace_fence_receipts SET command_id = ?1 WHERE operation_id = ?2",
            params![Uuid::from_u128(4321).to_string(), owner.to_string()],
        )
        .unwrap();
        assert!(read_receipt(&conn, &ns, owner, Uuid::from_u128(4321))
            .unwrap()
            .unwrap()
            .is_err());
    }

    #[test]
    fn target_config_conversion() {
        let c = target_database_config(&TargetConfig {
            max_db_size: Some(4096 * 10),
            jwt_key: Some("k".into()),
            txn_timeout_s: Some(7),
            allow_attach: true,
            durability_mode: Some("strong".into()),
            bottomless_db_id: Some("b".into()),
        })
        .unwrap();
        assert_eq!(c.max_db_pages, 10);
        assert_eq!(c.jwt_key.as_deref(), Some("k"));
        assert_eq!(c.txn_timeout, Some(Duration::from_secs(7)));
        assert!(c.allow_attach);
        assert_eq!(c.durability_mode, DurabilityMode::Strong);
        assert_eq!(c.bottomless_db_id.as_deref(), Some("b"));
        assert!(!c.block_reads && !c.block_writes);

        let e = target_database_config(&TargetConfig {
            durability_mode: Some("nope".into()),
            ..Default::default()
        })
        .unwrap_err();
        assert_eq!(e.detail(), Some(FenceDetail::InvalidArgument));
    }
}
