//! The historical dump importer: reads the whole dump in memory, then parses and executes it.
//!
//! This is intentionally kept identical in behavior to the pre-streaming implementation so it
//! can serve as the reference/control implementation when benchmarking and validating the
//! streaming importer.

use bytes::Bytes;
use fallible_iterator::FallibleIterator;
use futures::Stream;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use sqlite3_parser::ast::{Cmd, Stmt};
use sqlite3_parser::lexer::sql::Parser;
use tokio::io::AsyncReadExt;
use tokio_util::io::StreamReader;

use crate::connection::Connection as _;
use crate::database::PrimaryConnection;
use crate::error::LoadDumpError;

use super::{map_exec_error, map_parse_error, DumpImportStats};

pub(super) async fn load_dump_buffered<S>(
    dump: S,
    conn: PrimaryConnection,
) -> crate::Result<DumpImportStats, LoadDumpError>
where
    S: Stream<Item = std::io::Result<Bytes>> + Unpin,
{
    let mut stats = DumpImportStats::default();
    let mut reader = tokio::io::BufReader::new(StreamReader::new(dump));
    let mut dump_content = String::new();
    reader
        .read_to_string(&mut dump_content)
        .await
        .map_err(|e| LoadDumpError::Internal(format!("Failed to read dump content: {}", e)))?;
    stats.bytes = dump_content.len() as u64;

    if dump_content.to_lowercase().contains("attach") {
        return Err(LoadDumpError::InvalidSqlInput(
            "attach statements are not allowed in dumps".to_string(),
        ));
    }

    let mut parser = Box::new(Parser::new(dump_content.as_bytes()));
    let mut skipped_wasm_table = false;
    let mut n_stmt = 0;

    loop {
        match parser.next() {
            Ok(Some(cmd)) => {
                n_stmt += 1;

                if !skipped_wasm_table {
                    if let Cmd::Stmt(Stmt::CreateTable { tbl_name, .. }) = &cmd {
                        if tbl_name.name.0 == "libsql_wasm_func_table" {
                            skipped_wasm_table = true;
                            stats.statements_skipped += 1;
                            tracing::debug!("Skipping WASM table creation");
                            continue;
                        }
                    }
                }

                if n_stmt > 2 && conn.is_autocommit().await.unwrap() {
                    return Err(LoadDumpError::NoTxn);
                }

                let stmt_sql = cmd.to_string();
                stats.max_statement_bytes = stats.max_statement_bytes.max(stmt_sql.len());
                tokio::task::spawn_blocking({
                    let conn = conn.clone();
                    move || -> crate::Result<(), LoadDumpError> {
                        conn.with_raw(|conn| {
                            conn.authorizer(Some(|auth: AuthContext<'_>| match auth.action {
                                AuthAction::Attach { filename: _ } => Authorization::Deny,
                                _ => Authorization::Allow,
                            }));
                            conn.execute(&stmt_sql, ())
                        })
                        .map_err(|e| map_exec_error(e, n_stmt))?;
                        Ok(())
                    }
                })
                .await??;
                stats.statements_executed += 1;
            }
            Ok(None) => break,
            Err(e) => return Err(map_parse_error(e, None)),
        }
    }

    if !conn.is_autocommit().await.unwrap() {
        tokio::task::spawn_blocking({
            let conn = conn.clone();
            move || -> crate::Result<(), LoadDumpError> {
                conn.with_raw(|conn| conn.execute("rollback", ()))?;
                Ok(())
            }
        })
        .await??;
        return Err(LoadDumpError::NoCommit);
    }

    Ok(stats)
}
