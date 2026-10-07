//! Loading a namespace from a SQL dump.
//!
//! Two importers are available and can be selected per request (`dump_importer` in the admin
//! create-namespace body) or server-wide (`--dump-importer`):
//!
//! - [`DumpImporterKind::Buffered`]: the historical importer. Reads the whole dump into memory,
//!   parses it, and executes each statement. Memory usage is proportional to the dump size.
//! - [`DumpImporterKind::Streaming`]: frames complete statements incrementally with
//!   `sqlite3_complete()` and executes them on a dedicated blocking thread while the dump is
//!   still being read. Memory usage is bounded by [`DumpImportConfig`] plus the largest statement.
//!
//! See `docs/STREAMING_DUMP_IMPORT_DESIGN.md` for the full design.

use std::fmt;
use std::str::FromStr;
use std::time::{Duration, Instant};

use sqlite3_parser::lexer::sql::ParserError;

use crate::database::PrimaryConnection;
use crate::error::LoadDumpError;
use crate::namespace::{DumpStream, NamespaceName};

mod buffered;
mod complete;
mod framer;
mod streaming;

/// Which implementation loads a dump into a fresh namespace.
///
/// Deserializes leniently (case-insensitive, surrounding whitespace ignored), like the CLI flag,
/// so `"Streaming"` means the same thing in a request body and in `SQLD_DUMP_IMPORTER`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DumpImporterKind {
    /// Read the entire dump into memory before executing it.
    Buffered,
    /// Execute statements as they are framed from the incoming stream.
    Streaming,
}

impl DumpImporterKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            DumpImporterKind::Buffered => "buffered",
            DumpImporterKind::Streaming => "streaming",
        }
    }
}

impl fmt::Display for DumpImporterKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for DumpImporterKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "buffered" => Ok(DumpImporterKind::Buffered),
            "streaming" => Ok(DumpImporterKind::Streaming),
            other => Err(format!(
                "unknown dump importer `{other}`, expected `buffered` or `streaming`"
            )),
        }
    }
}

impl<'de> serde::Deserialize<'de> for DumpImporterKind {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Server-wide dump import settings.
#[derive(Debug, Clone)]
pub struct DumpImportConfig {
    /// Importer used when the create-namespace request doesn't specify one.
    pub default_importer: DumpImporterKind,
    /// Streaming importer: a single statement larger than this is rejected.
    pub max_statement_bytes: usize,
    /// Streaming importer: maximum bytes of framed statements waiting to be executed.
    pub queue_bytes: usize,
    /// Streaming importer: maximum number of framed statements waiting to be executed.
    pub queue_depth: usize,
}

impl DumpImportConfig {
    pub const DEFAULT_MAX_STATEMENT_BYTES: usize = 64 * 1024 * 1024;
    pub const DEFAULT_QUEUE_BYTES: usize = 16 * 1024 * 1024;
    pub const DEFAULT_QUEUE_DEPTH: usize = 256;

    pub const MIN_MAX_STATEMENT_BYTES: usize = 4 * 1024;
    pub const MIN_QUEUE_BYTES: usize = 64 * 1024;
    pub const MAX_QUEUE_BYTES: usize = 1024 * 1024 * 1024;

    /// Check that the limits are sane and fit the implementation (the byte budget is a
    /// `tokio::sync::Semaphore` acquired with `u32` permit counts).
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.max_statement_bytes >= Self::MIN_MAX_STATEMENT_BYTES,
            "dump import max statement size must be at least {} bytes",
            Self::MIN_MAX_STATEMENT_BYTES
        );
        anyhow::ensure!(
            (Self::MIN_QUEUE_BYTES..=Self::MAX_QUEUE_BYTES).contains(&self.queue_bytes),
            "dump import queue bytes must be between {} and {} bytes",
            Self::MIN_QUEUE_BYTES,
            Self::MAX_QUEUE_BYTES
        );
        anyhow::ensure!(
            self.queue_depth >= 1,
            "dump import queue depth must be at least 1"
        );
        Ok(())
    }
}

impl Default for DumpImportConfig {
    fn default() -> Self {
        Self {
            default_importer: DumpImporterKind::Buffered,
            max_statement_bytes: Self::DEFAULT_MAX_STATEMENT_BYTES,
            queue_bytes: Self::DEFAULT_QUEUE_BYTES,
            queue_depth: Self::DEFAULT_QUEUE_DEPTH,
        }
    }
}

/// What a completed import did.
#[derive(Debug, Default, Clone)]
pub struct DumpImportStats {
    /// Statements handed to SQLite.
    pub statements_executed: u64,
    /// Frames that were not executed: whitespace/comment-only frames and the skipped WASM table.
    pub statements_skipped: u64,
    /// Dump bytes consumed.
    pub bytes: u64,
    /// Size of the largest statement executed.
    pub max_statement_bytes: usize,
    pub elapsed: Duration,
}

/// A failed import, together with how far it got before failing.
pub(super) struct ImportFailure {
    pub error: LoadDumpError,
    pub partial: DumpImportStats,
}

impl From<LoadDumpError> for ImportFailure {
    fn from(error: LoadDumpError) -> Self {
        Self {
            error,
            partial: DumpImportStats::default(),
        }
    }
}

/// Load `stream` into the fresh database behind `conn` using the requested importer.
///
/// On error the dump transaction has been rolled back (or was never started).
pub(crate) async fn load_dump(
    kind: DumpImporterKind,
    stream: DumpStream,
    conn: PrimaryConnection,
    cfg: &DumpImportConfig,
    namespace: &NamespaceName,
) -> Result<DumpImportStats, LoadDumpError> {
    let started = Instant::now();
    tracing::info!(namespace = %namespace, importer = %kind, "loading dump");

    let res = match kind {
        DumpImporterKind::Buffered => buffered::load_dump_buffered(stream, conn)
            .await
            .map_err(ImportFailure::from),
        DumpImporterKind::Streaming => streaming::load_dump_streaming(stream, conn, cfg).await,
    };

    let elapsed = started.elapsed();
    metrics::histogram!(
        "libsql_server_dump_import_duration_seconds",
        elapsed.as_secs_f64(),
        "importer" => kind.as_str()
    );

    match res {
        Ok(mut stats) => {
            stats.elapsed = elapsed;
            metrics::counter!(
                "libsql_server_dump_import_bytes",
                stats.bytes,
                "importer" => kind.as_str()
            );
            metrics::counter!(
                "libsql_server_dump_import_statements",
                stats.statements_executed,
                "importer" => kind.as_str()
            );
            metrics::histogram!(
                "libsql_server_dump_import_max_statement_bytes",
                stats.max_statement_bytes as f64,
                "importer" => kind.as_str()
            );
            tracing::info!(
                namespace = %namespace,
                importer = %kind,
                statements = stats.statements_executed,
                skipped = stats.statements_skipped,
                bytes = stats.bytes,
                max_statement_bytes = stats.max_statement_bytes,
                elapsed_ms = elapsed.as_millis() as u64,
                "dump loaded"
            );
            Ok(stats)
        }
        Err(ImportFailure { error, partial }) => {
            let kind_label = failure_kind(&error);
            metrics::increment_counter!(
                "libsql_server_dump_import_failures",
                "importer" => kind.as_str(),
                "kind" => kind_label
            );
            // The error itself (which may quote dump SQL) is logged by the HTTP layer when the
            // response is built; here we record the category and how far the import got.
            tracing::warn!(
                namespace = %namespace,
                importer = %kind,
                kind = kind_label,
                statements = partial.statements_executed,
                bytes = partial.bytes,
                elapsed_ms = elapsed.as_millis() as u64,
                "dump load failed; transaction rolled back"
            );
            Err(error)
        }
    }
}

fn failure_kind(e: &LoadDumpError) -> &'static str {
    match e {
        LoadDumpError::NoTxn | LoadDumpError::NoCommit => "txn",
        LoadDumpError::InvalidSqlInput(_) => "parse",
        LoadDumpError::StatementTooLarge { .. } => "limit",
        LoadDumpError::Internal(_) => "exec",
        _ => "other",
    }
}

/// Convert a parser error into the user-facing `InvalidSqlInput` error.
///
/// `frame_pos` is the 1-based `(line, column)` of the parsed text within the whole dump; when
/// `None`, positions reported by the parser are already absolute.
pub(super) fn map_parse_error(
    mut e: sqlite3_parser::lexer::sql::Error,
    frame_pos: Option<(u64, usize)>,
) -> LoadDumpError {
    use sqlite3_parser::lexer::sql::Error as E;
    use sqlite3_parser::lexer::ScanError as _;

    if let Some(frame_pos) = frame_pos {
        let rel = match &e {
            E::ParserError(_, pos)
            | E::UnrecognizedToken(pos)
            | E::UnterminatedLiteral(pos)
            | E::UnterminatedBracket(pos)
            | E::UnterminatedBlockComment(pos)
            | E::BadVariableName(pos)
            | E::BadNumber(pos)
            | E::ExpectedEqualsSign(pos)
            | E::MalformedBlobLiteral(pos)
            | E::MalformedHexInteger(pos) => *pos,
            E::Io(_) => None,
            _ => None,
        };
        if let Some(rel) = rel {
            let (line, column) = framer::absolute_position(frame_pos, rel);
            e.position(line, column);
        }
    }

    let msg = match e {
        E::ParserError(ParserError::SyntaxError { token_type, found }, Some((line, col))) => {
            let near_token = found.as_deref().unwrap_or(token_type);
            format!(
                "syntax error near '{}' at line {}, column {}",
                near_token, line, col
            )
        }
        other => format!("parse error: {}", other),
    };

    LoadDumpError::InvalidSqlInput(msg)
}

/// Convert a SQLite execution error into the user-facing error, mirroring the historical format.
pub(super) fn map_exec_error(e: rusqlite::Error, n_stmt: u64) -> LoadDumpError {
    match e {
        rusqlite::Error::SqlInputError {
            msg, sql, offset, ..
        } => LoadDumpError::InvalidSqlInput(format!(
            "msg: {}, sql: {}, offset: {}",
            msg, sql, offset
        )),
        e => LoadDumpError::Internal(format!("statement: {}, error: {}", n_stmt, e)),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn importer_kind_from_str() {
        assert_eq!(
            "buffered".parse::<DumpImporterKind>().unwrap(),
            DumpImporterKind::Buffered
        );
        assert_eq!(
            " Streaming ".parse::<DumpImporterKind>().unwrap(),
            DumpImporterKind::Streaming
        );
        assert!("nope".parse::<DumpImporterKind>().is_err());
    }

    #[test]
    fn importer_kind_serde() {
        assert_eq!(
            serde_json::from_str::<DumpImporterKind>("\"streaming\"").unwrap(),
            DumpImporterKind::Streaming
        );
        // same leniency as the CLI flag
        assert_eq!(
            serde_json::from_str::<DumpImporterKind>("\" Buffered \"").unwrap(),
            DumpImporterKind::Buffered
        );
        assert!(serde_json::from_str::<DumpImporterKind>("\"turbo\"").is_err());
        assert!(serde_json::from_str::<DumpImporterKind>("1").is_err());
        assert_eq!(
            serde_json::to_string(&DumpImporterKind::Streaming).unwrap(),
            "\"streaming\""
        );
    }

    #[test]
    fn config_validation() {
        assert!(DumpImportConfig::default().validate().is_ok());
        let bad = DumpImportConfig {
            queue_bytes: 1,
            ..Default::default()
        };
        assert!(bad.validate().is_err());
        let bad = DumpImportConfig {
            queue_depth: 0,
            ..Default::default()
        };
        assert!(bad.validate().is_err());
        let bad = DumpImportConfig {
            max_statement_bytes: 1,
            ..Default::default()
        };
        assert!(bad.validate().is_err());
    }
}
