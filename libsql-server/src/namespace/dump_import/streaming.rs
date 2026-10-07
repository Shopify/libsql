//! Memory-bounded dump importer.
//!
//! ```text
//!          async (tokio runtime)                                blocking thread (BLOCKING_RT)
//! DumpStream ──chunks──▶ StatementFramer ──frames──▶ mpsc + byte budget ──▶ run_executor ──▶ PrimaryConnection
//! ```
//!
//! The reader task drives the stream, frames statements and hands them to a single executor
//! thread that owns the connection for the whole import. Memory is bounded by the configured
//! queue budget plus the largest single statement; the dump itself is never held in memory.
//!
//! See `docs/STREAMING_DUMP_IMPORT_DESIGN.md` §8–9.

use std::sync::Arc;
use std::time::{Duration, Instant};

use fallible_iterator::FallibleIterator;
use futures::StreamExt;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use sqlite3_parser::ast::{Cmd, Stmt};
use sqlite3_parser::lexer::sql::Parser;
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};

use crate::connection::Connection as _;
use crate::database::PrimaryConnection;
use crate::error::LoadDumpError;
use crate::namespace::DumpStream;
use crate::BLOCKING_RT;

use super::framer::{advance_position, Frame, FrameError, StatementFramer};
use super::{map_exec_error, map_parse_error, DumpImportConfig, DumpImportStats, ImportFailure};

enum Msg {
    Stmt {
        sql: Vec<u8>,
        line: u64,
        column: usize,
        /// Released when the executor drops the message, freeing queue budget.
        _budget: OwnedSemaphorePermit,
    },
    /// The reader reached EOF cleanly (after sending the final unterminated tail, if any).
    End,
}

enum FeedError {
    /// The stream or the framer failed; carries the user-facing error.
    Source(LoadDumpError),
    /// The executor went away (it failed first); its error is the one to report.
    ExecutorGone,
}

impl From<FrameError> for LoadDumpError {
    fn from(e: FrameError) -> Self {
        match e {
            FrameError::NulByte { line, column } => LoadDumpError::InvalidSqlInput(format!(
                "dump contains a NUL byte at line {line}, column {column}"
            )),
            FrameError::StatementTooLarge {
                line,
                column,
                limit,
            } => LoadDumpError::StatementTooLarge {
                line,
                column,
                limit,
            },
        }
    }
}

pub(super) async fn load_dump_streaming(
    mut stream: DumpStream,
    conn: PrimaryConnection,
    cfg: &DumpImportConfig,
) -> Result<DumpImportStats, ImportFailure> {
    // `DumpImportConfig::validate` runs for CLI-built configs only; never panic on a
    // programmatically built one (mpsc::channel(0) and clamp(1, 0) both panic).
    let queue_depth = cfg.queue_depth.max(1);
    let queue_bytes = cfg.queue_bytes.clamp(1, u32::MAX as usize);
    let (tx, rx) = mpsc::channel::<Msg>(queue_depth);
    let budget = Arc::new(Semaphore::new(queue_bytes));
    let executor = BLOCKING_RT.spawn_blocking(move || run_executor(conn, rx));
    let mut framer = StatementFramer::new(cfg.max_statement_bytes);

    let feed: Result<(), FeedError> = async {
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| {
                FeedError::Source(LoadDumpError::Internal(format!(
                    "Failed to read dump content: {e}"
                )))
            })?;
            for frame in framer
                .push(&chunk)
                .map_err(|e| FeedError::Source(e.into()))?
            {
                send_frame(&tx, &budget, queue_bytes, frame).await?;
            }
        }
        if let Some(tail) = framer.finish() {
            send_frame(&tx, &budget, queue_bytes, tail).await?;
        }
        tx.send(Msg::End).await.map_err(|_| FeedError::ExecutorGone)
    }
    .await;

    // Guarantees the executor observes channel closure if we bailed out before sending `End`.
    drop(tx);

    let (exec, mut stats) = executor
        .await
        .map_err(|e| LoadDumpError::Internal(format!("dump executor task failed: {e}")))?;
    stats.bytes = framer.bytes_seen();

    let res = match (feed, exec) {
        (Ok(()), exec) => exec,
        // The executor failed first and closed the channel; report its error.
        (Err(FeedError::ExecutorGone), Err(e)) => Err(e),
        // Can't happen: the executor only returns Ok after receiving `End`.
        (Err(FeedError::ExecutorGone), Ok(())) => Err(LoadDumpError::Internal(
            "dump executor finished before the dump was fully read".to_string(),
        )),
        // A stream or framing error wins over the executor's generic "ended before completion".
        (Err(FeedError::Source(e)), _) => Err(e),
    };
    match res {
        Ok(()) => Ok(stats),
        Err(error) => Err(ImportFailure {
            error,
            partial: stats,
        }),
    }
}

async fn send_frame(
    tx: &mpsc::Sender<Msg>,
    budget: &Arc<Semaphore>,
    queue_bytes: usize,
    frame: Frame,
) -> Result<(), FeedError> {
    // Oversized statements take the whole budget and therefore travel alone.
    let permits = frame.sql.len().clamp(1, queue_bytes) as u32;
    let permit = budget
        .clone()
        .acquire_many_owned(permits)
        .await
        .expect("dump import budget semaphore is never closed");
    tx.send(Msg::Stmt {
        sql: frame.sql,
        line: frame.line,
        column: frame.column,
        _budget: permit,
    })
    .await
    .map_err(|_| FeedError::ExecutorGone)
}

/// How often the executor logs progress while an import is running.
const PROGRESS_LOG_INTERVAL: Duration = Duration::from_secs(10);

struct Executor {
    conn: PrimaryConnection,
    n_stmt: u64,
    skipped_wasm_table: bool,
    stats: DumpImportStats,
    started: Instant,
    last_progress_log: Instant,
}

/// Runs on a blocking thread for the whole import. Never cancelled by tokio: it always reaches
/// its own COMMIT-or-ROLLBACK decision, even if the reader (and the admin request) go away.
/// (Should it panic instead, unwinding drops the connection, and SQLite rolls back an open
/// transaction when a connection is closed.)
///
/// Returns the outcome together with the statistics accumulated so far, so a failure can report
/// how far the import got.
fn run_executor(
    conn: PrimaryConnection,
    mut rx: mpsc::Receiver<Msg>,
) -> (Result<(), LoadDumpError>, DumpImportStats) {
    let now = Instant::now();
    let mut ex = Executor {
        conn,
        n_stmt: 0,
        skipped_wasm_table: false,
        stats: DumpImportStats::default(),
        started: now,
        last_progress_log: now,
    };

    ex.conn.with_raw(|c| {
        c.authorizer(Some(|auth: AuthContext<'_>| match auth.action {
            AuthAction::Attach { .. } | AuthAction::Detach { .. } => Authorization::Deny,
            _ => Authorization::Allow,
        }))
    });

    let res = ex.run(&mut rx);

    if res.is_err() {
        ex.rollback_best_effort();
    }
    ex.conn
        .with_raw(|c| c.authorizer(None::<fn(AuthContext<'_>) -> Authorization>));
    (res, std::mem::take(&mut ex.stats))
}

impl Executor {
    fn run(&mut self, rx: &mut mpsc::Receiver<Msg>) -> Result<(), LoadDumpError> {
        loop {
            match rx.blocking_recv() {
                Some(Msg::Stmt {
                    sql, line, column, ..
                }) => {
                    self.handle_statement(&sql, line, column)?;
                    self.maybe_log_progress();
                }
                Some(Msg::End) => break,
                None => {
                    // Reader dropped the sender without `End`: stream error, framing error or
                    // request cancellation. The reader reports the specific cause if it's alive.
                    return Err(LoadDumpError::Internal(
                        "dump stream ended before completion".to_string(),
                    ));
                }
            }
        }

        if !self.is_autocommit() {
            self.conn.with_raw(|c| c.execute_batch("ROLLBACK"))?;
            return Err(LoadDumpError::NoCommit);
        }

        Ok(())
    }

    fn maybe_log_progress(&mut self) {
        if self.last_progress_log.elapsed() >= PROGRESS_LOG_INTERVAL {
            self.last_progress_log = Instant::now();
            tracing::info!(
                statements = self.stats.statements_executed,
                elapsed_ms = self.started.elapsed().as_millis() as u64,
                "dump import in progress"
            );
        }
    }

    fn is_autocommit(&self) -> bool {
        self.conn.with_raw(|c| c.is_autocommit())
    }

    fn rollback_best_effort(&self) {
        self.conn.with_raw(|c| {
            if !c.is_autocommit() {
                if let Err(e) = c.execute_batch("ROLLBACK") {
                    tracing::warn!("failed to roll back dump transaction: {e}");
                }
            }
        });
    }

    fn handle_statement(
        &mut self,
        sql: &[u8],
        line: u64,
        column: usize,
    ) -> Result<(), LoadDumpError> {
        // 1. UTF-8: the parser converts lossily, so validate first. Frames end at an ASCII `;`,
        //    so a frame is valid UTF-8 iff the dump is valid UTF-8 over that range.
        let sql = std::str::from_utf8(sql).map_err(|e| {
            let (line, column) = advance_position((line, column), &sql[..e.valid_up_to()]);
            LoadDumpError::InvalidSqlInput(format!(
                "dump is not valid UTF-8 at line {line}, column {column}: {e}"
            ))
        })?;

        // 2. Parse (for policy checks and error reporting; the original text is what runs).
        let mut parser = Parser::new(sql.as_bytes());
        let cmd = match parser.next() {
            Ok(Some(cmd)) => cmd,
            Ok(None) => {
                // whitespace / comments / a bare `;`
                self.stats.statements_skipped += 1;
                return Ok(());
            }
            Err(e) => return Err(map_parse_error(e, Some((line, column)))),
        };
        if let Ok(Some(_)) = parser.next() {
            return Err(LoadDumpError::Internal(format!(
                "framing produced more than one statement at line {line}, column {column}"
            )));
        }

        // 3.
        self.n_stmt += 1;

        // 4. Same special case as the buffered importer.
        if !self.skipped_wasm_table {
            if let Cmd::Stmt(Stmt::CreateTable { tbl_name, .. }) = &cmd {
                if tbl_name.name.0 == "libsql_wasm_func_table" {
                    self.skipped_wasm_table = true;
                    self.stats.statements_skipped += 1;
                    tracing::debug!("Skipping WASM table creation");
                    return Ok(());
                }
            }
        }

        // 5. ATTACH policy (the authorizer is the backstop).
        if matches!(
            cmd,
            Cmd::Stmt(Stmt::Attach { .. }) | Cmd::Stmt(Stmt::Detach(_))
        ) {
            return Err(LoadDumpError::InvalidSqlInput(
                "attach statements are not allowed in dumps".to_string(),
            ));
        }

        // 6. Everything after the first two statements must run inside the dump's transaction.
        if self.n_stmt > 2 && self.is_autocommit() {
            return Err(LoadDumpError::NoTxn);
        }

        // 7. Execute the original text.
        let n_stmt = self.n_stmt;
        self.conn
            .with_raw(|c| execute_single(c, sql))
            .map_err(|e| map_exec_error(e, n_stmt))?;

        self.stats.statements_executed += 1;
        self.stats.max_statement_bytes = self.stats.max_statement_bytes.max(sql.len());
        Ok(())
    }
}

/// Run one statement to completion, discarding any rows it returns (EXPLAIN, PRAGMA, a stray
/// SELECT), like the `sqlite3` shell does. Framing guarantees `sql` holds a single statement.
fn execute_single(conn: &mut rusqlite::Connection, sql: &str) -> rusqlite::Result<()> {
    let mut stmt = conn.prepare(sql)?;
    let mut rows = stmt.raw_query();
    while rows.next()?.is_some() {}
    Ok(())
}
