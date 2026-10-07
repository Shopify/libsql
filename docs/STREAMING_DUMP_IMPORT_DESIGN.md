# Design: memory-bounded streaming SQL dump importer for libsql-server

Status: implemented (see `libsql-server/src/namespace/dump_import/`) · Target: `Shopify/libsql`, branch `v0.9.30-shopify-patches` · Related: Retail #35846, LibSQL DB Mover P0

Sections marked *as built* record where the implementation refined the original proposal, including the changes made after the adversarial review of PR #51 (§18).

This document is written so that an implementer can follow it step by step without re-deriving decisions. Every file, type, flag, error and test is named. Section 16 is the ordered implementation plan; sections 7–9 are the normative specifications.

---

## 1. Goals

1. Import a SQLite SQL dump into a **new** namespace with peak importer memory that does **not** grow with total dump size. Memory is bounded by configuration plus the size of the single largest statement.
2. Keep the existing importer (hereafter **buffered**) byte-for-byte intact and selectable, so both importers can be run on the **same** `libsql-server` instance for benchmarking and validation.
3. Select the importer at runtime:
   - per request: `"dump_importer": "buffered" | "streaming"` in the `POST /v1/namespaces/:ns/create` body;
   - server default: `--dump-importer` / `SQLD_DUMP_IMPORTER` (default `buffered`, so behavior is unchanged until opted in).
4. Preserve the Admin API contract, HTTP status codes and — where practical — the exact error messages, so existing insta snapshots can be reused.
5. Fail closed: any malformed, truncated, or cancelled dump leaves **no committed partial data**; the SQL transaction is rolled back and an HTTP error is returned.

## 2. Non-goals

- Enormous single statements / large BLOBs. A per-statement size cap exists purely as a safety valve; dumps exceeding it are rejected, not supported.
- Fixing pre-existing namespace lifecycle issues (metastore row kept after a failed create; directory not cleaned when the request is cancelled). Documented in §13; owned by the DB Mover fence/quarantine work.
- Binary SQLite file ingestion, bottomless memory behavior, Admin request timeouts, export-side changes.
- Changing what the buffered importer does. It is moved, not modified.

---

## 3. Baseline: what exists today

| Concern | Location |
|---|---|
| Admin request parsing, `dump_url` → `DumpStream` | `libsql-server/src/http/admin/mod.rs` — `CreateNamespaceReq`, `handle_create_namespace`, `dump_stream_from_url` |
| `RestoreOption::Dump(DumpStream)` | `libsql-server/src/namespace/mod.rs` |
| Namespace creation (stores config in metastore **before** loading) | `libsql-server/src/namespace/store.rs` — `NamespaceStore::create` → `load_namespace` → `make_namespace` |
| Primary setup, dir cleanup on failure | `libsql-server/src/namespace/configurator/primary.rs` — `PrimaryConfigurator::setup` |
| Dump loading | `libsql-server/src/namespace/configurator/helpers.rs` — `make_primary_connection_maker` (match on `restore_option`), `load_dump`, `check_fresh_db` |
| Errors / HTTP mapping | `libsql-server/src/error.rs` — `LoadDumpError`, `IntoResponse for &LoadDumpError` |
| Tests | `libsql-server/tests/namespaces/dumps.rs` + `snapshots/` |

Current `load_dump` sequence (helpers.rs:293–395):

1. `StreamReader` → `BufReader` → `read_to_string(&mut dump_content)`: **whole dump in one `String`**. Invalid UTF-8 → `LoadDumpError::Internal` (HTTP 500).
2. `dump_content.to_lowercase().contains("attach")` → rejects the **entire** dump if the substring appears anywhere, including inside data (`'attachment'`). Also allocates a second lowercase copy of the whole dump.
3. `sqlite3_parser::Parser::new(dump_content.as_bytes())`, loop `parser.next()`:
   - `Ok(Some(cmd))`: count `n_stmt`; skip the first `CREATE TABLE libsql_wasm_func_table`; if `n_stmt > 2` and connection is in autocommit → `NoTxn`; **execute `cmd.to_string()`** (AST re-serialized, not the original text) via `tokio::task::spawn_blocking` **per statement**, installing the ATTACH-denying authorizer each time.
   - `Ok(None)`: end of input. (The parser absorbs empty statements such as `;;` and comment-only input — verified against the vendored parser — so this is only reached at EOF.)
   - `Err(e)`: `InvalidSqlInput("syntax error near '…' at line L, column C")` or `"parse error: …"`.
4. After the loop, if not autocommit → `ROLLBACK` → `NoCommit`.

Where the WAL bytes go during the import transaction: `ReplicationLoggerWalWrapper::insert_frames` flushes every page batch SQLite spills to the replication log file immediately (`replication_logger_wal.rs:101–110`), so the replication layer does **not** buffer the transaction in memory. The importer's `String` is the only size-proportional allocation. This is what we remove.

---

## 4. Architecture

```
            async (tokio runtime)                                 blocking thread (BLOCKING_RT)
DumpStream ──chunks──▶ StatementFramer ──frames──▶ mpsc(depth) + byte budget ──▶ StatementExecutor ──▶ PrimaryConnection
(hyper body /          memchr(';') +                (Semaphore permits               UTF-8 check → sqlite3_parser →
 tokio file)           sqlite3_complete()            travel with each frame)         policy checks → execute original SQL
                                                                                      → ROLLBACK on any failure
```

Three components, each independently testable:

- **`StatementFramer`** (sync, pure): accumulates bytes, emits complete SQL statements with their 1-based `(line, column)` in the original dump. Uses SQLite's own `sqlite3_complete()` so semicolons inside strings, comments and `CREATE TRIGGER … END` bodies are handled exactly as the `sqlite3` shell does.
- **Reader task** (async): drives the stream, feeds the framer, pushes frames into a bounded channel, sends an explicit `End` marker.
- **`StatementExecutor`** (blocking, one thread for the whole import): owns the `PrimaryConnection`, validates/parses/executes each frame in order inside the dump's own transaction, enforces the transaction rules, rolls back on abort.

Why a dedicated blocking thread instead of `spawn_blocking` per statement: it removes a thread-pool handoff per row, keeps the connection on one thread, and lets network I/O overlap with execution.

---

## 5. Interface changes

### 5.1 Admin API

`POST /v1/namespaces/:namespace/create` body gains one optional field:

```json
{
  "dump_url": "file:///abs/path/dump.sql",
  "dump_importer": "streaming"
}
```

- Allowed values: `"buffered"`, `"streaming"` (serde `rename_all = "snake_case"`). Unknown value → serde rejection → HTTP **422** (axum's `JsonRejection` for deserialization errors; *as built*).
- Omitted → server default (`DumpImportConfig::default_importer`).
- Present without `dump_url` → HTTP 400 `LoadDumpError::ImporterWithoutDumpUrl` ("`dump_importer` requires `dump_url`").
- Existing rule unchanged: `shared_schema_name` + `dump_url` → 400.

Document in `docs/ADMIN_API.md`.

### 5.2 CLI flags / environment (`libsql-server/src/main.rs`, `struct Cli`)

| Flag | Env | Type / default | Meaning |
|---|---|---|---|
| `--dump-importer` | `SQLD_DUMP_IMPORTER` | `DumpImporterKind`, `buffered` | Importer used when the request omits `dump_importer`. |
| `--dump-import-max-statement-size` | `SQLD_DUMP_IMPORT_MAX_STATEMENT_SIZE` | `bytesize::ByteSize`, `64MiB` | Streaming only. A single statement larger than this is rejected (HTTP 413), whether it arrives terminated in one chunk or grows past the limit unterminated. Safety valve, not a sizing target. |
| `--dump-import-queue-bytes` | `SQLD_DUMP_IMPORT_QUEUE_BYTES` | `ByteSize`, `16MiB` | Streaming only. Max bytes of framed-but-not-yet-executed statements in flight. |
| `--dump-import-queue-depth` | `SQLD_DUMP_IMPORT_QUEUE_DEPTH` | `usize`, `256` | Streaming only. Max number of statements in flight. |

Validation in `make_db_config`: `max_statement_size ≥ 4 KiB`, `64 KiB ≤ queue_bytes ≤ 1 GiB` (must fit `u32` for `Semaphore::acquire_many`), `queue_depth ≥ 1`. Fail startup with a clear `anyhow` error otherwise.

### 5.3 Config plumbing

```rust
// libsql-server/src/namespace/dump_import/mod.rs  (new)
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DumpImporterKind { Buffered, Streaming }

impl std::str::FromStr for DumpImporterKind { /* "buffered" | "streaming", case-insensitive; used by clap */ }
impl std::fmt::Display for DumpImporterKind { /* "buffered" / "streaming" — used as metric label */ }

#[derive(Debug, Clone)]
pub struct DumpImportConfig {
    pub default_importer: DumpImporterKind,  // Buffered
    pub max_statement_bytes: usize,          // 64 MiB
    pub queue_bytes: usize,                  // 16 MiB
    pub queue_depth: usize,                  // 256
}
impl Default for DumpImportConfig { /* values above */ }
```

- `config.rs`: `DbConfig` gets `pub dump_import: DumpImportConfig` (add to `Default`).
- `main.rs::make_db_config`: fill it from the flags.
- `namespace/configurator/mod.rs`: `BaseNamespaceConfig` gets `pub(crate) dump_import: DumpImportConfig`; `lib.rs` (~line 593) copies `self.db_config.dump_import.clone()`. Also update the two test constructors of `BaseNamespaceConfig` in `schema/scheduler.rs` tests (`..` is not available there; add the field with `Default::default()`).
- `namespace/mod.rs`:

```rust
pub struct DumpSource {
    pub stream: DumpStream,
    /// `None` → use `BaseNamespaceConfig::dump_import.default_importer`.
    pub importer: Option<DumpImporterKind>,
}

pub enum RestoreOption {
    #[default] Latest,
    Dump(DumpSource),          // was Dump(DumpStream)
    Generation(Uuid),
    PointInTime(NaiveDateTime),
}
```

Every existing `RestoreOption::Dump(_)` pattern still compiles; only `helpers.rs:204` destructures the payload (see §6).

---

## 6. Module layout and call flow

```
libsql-server/src/namespace/dump_import/
├── mod.rs        DumpImporterKind, DumpImportConfig, DumpImportStats, pub(crate) async fn load_dump(...) dispatcher,
│                 shared error-mapping helpers (map_parse_error, map_exec_error), metrics/logging
├── buffered.rs   legacy load_dump moved verbatim (renamed load_dump_buffered), returns DumpImportStats
├── framer.rs     StatementFramer + is_complete_statement() + position helpers + unit tests
└── streaming.rs  load_dump_streaming (reader task) + run_executor (blocking) + Msg type
```

Register `pub(crate) mod dump_import;` in `namespace/mod.rs`. Add `memchr = "2"` to `libsql-server/Cargo.toml` (already in the lockfile via `sqlite3-parser`).

`helpers.rs` after the change (only the `match restore_option` block changes):

```rust
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
```

Dispatcher:

```rust
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
        DumpImporterKind::Buffered => buffered::load_dump_buffered(stream, conn).await,
        DumpImporterKind::Streaming => streaming::load_dump_streaming(stream, conn, cfg).await,
    };
    // metrics + one info!/warn! line (see §12), then return res
}

#[derive(Debug, Default, Clone)]
pub struct DumpImportStats {
    pub statements_executed: u64,
    pub statements_skipped: u64,   // empty frames + the wasm table
    pub bytes: u64,                // dump bytes consumed
    pub max_statement_bytes: usize,
    pub elapsed: Duration,
}
```

`buffered.rs`: cut/paste the existing `load_dump` body unchanged; set `stats.bytes = dump_content.len()`, `statements_executed = n_stmt` (minus the skipped wasm table), return stats. **No other edits** — this is the control arm of the benchmark.

---

## 7. `StatementFramer` — normative spec (`framer.rs`)

### 7.1 Purpose

Turn an arbitrary sequence of byte chunks into complete SQL statements, each ending at the `;` that terminates it, without ever holding more than one unfinished statement in memory.

### 7.2 Completeness oracle

> *As built:* the FFI call below was the first implementation. Because `sqlite3_complete` has no resumable form, calling it for every candidate `;` costs O(statement length) each time, which is quadratic for statements with many interior semicolons (measured: a 1 MiB text value with 50k semicolons took 20 s of CPU on a tokio worker). The shipped framer instead uses `complete.rs`, a resumable Rust port of complete.c's tokenizer and 8×8 state machine (`CompletionScanner::find_statement_end`), so a dump is scanned exactly once. `sqlite3_complete` is kept only as the reference in a differential unit test (`framing_matches_sqlite3_complete`: random token soups × chunkings must frame identically). The rest of this section describes the semantics both implementations share.

```rust
use rusqlite::ffi::sqlite3_complete;   // re-exported libsql_ffi binding: fn(*const c_char) -> c_int

/// `buf[start..=end]` is a candidate statement whose last byte is b';'.
/// sqlite3_complete needs a NUL-terminated string, so a terminator is temporarily placed at end+1.
fn is_complete_statement(buf: &mut Vec<u8>, start: usize, end: usize) -> bool {
    debug_assert_eq!(buf[end], b';');
    let pushed = if end + 1 == buf.len() { buf.push(0); true } else { false };
    let saved = buf[end + 1];
    buf[end + 1] = 0;
    // SAFETY: buf[start..] is a NUL-terminated byte string; sqlite3_complete only reads it.
    let complete = unsafe { sqlite3_complete(buf[start..].as_ptr() as *const _) } != 0;
    buf[end + 1] = saved;
    if pushed { buf.pop(); }
    complete
}
```

Semantics of `sqlite3_complete` (sqlite3.h:2770–2805): returns non-zero iff the string ends with a semicolon token that is not inside a string/identifier/comment and the text is not an unfinished `CREATE TRIGGER … BEGIN … END`. It does not parse; it tokenizes only. Verified against the bundled SQLite (probe run on this branch):

| input | result |
|---|---|
| `SELECT 1;`, `;`, ` \n ;`, `PRAGMA foreign_keys=OFF;`, `EXPLAIN SELECT 1;` | complete |
| `SELECT 'a;b';`, `SELECT "a;b";`, `SELECT [a;b];`, `CREATE TABLE t(x CHECK(x <> ';'));`, `INSERT INTO t VALUES(X'00ff');` | complete (interior `;` ignored) |
| `/* a; */ SELECT 1;`, `-- c;\nSELECT 1;` | complete |
| `SELECT ';`, `-- c;`, `COMMIT` | **not** complete |
| `CREATE [TEMP] TRIGGER t AFTER INSERT ON x BEGIN SELECT 1;` | **not** complete; `... END;` complete |

Embedded NUL bytes would truncate the view, hence §7.4 rule 1.

### 7.3 State

```rust
pub struct StatementFramer {
    buf: Vec<u8>,          // bytes after the last emitted frame; starts with the next statement's leading whitespace/comments
    scan_from: usize,      // offset in buf from which to look for the next ';' (avoids re-testing rejected candidates)
    line: u64,             // 1-based line of buf[0] in the whole dump
    column: usize,         // 1-based byte column of buf[0]
    max_statement_bytes: usize,
    bytes_seen: u64,
}

pub struct Frame { pub sql: Vec<u8>, pub line: u64, pub column: usize }

#[derive(Debug)]
pub enum FrameError {
    NulByte { line: u64, column: usize },
    StatementTooLarge { line: u64, column: usize, limit: usize },
}
```

`new(max_statement_bytes)` → `line = 1, column = 1`, empty buffer.

### 7.4 `push(&mut self, chunk: &[u8]) -> Result<Vec<Frame>, FrameError>`

1. If `memchr(0, chunk)` finds a NUL at offset `k`: compute its position (advance a copy of `(line, column)` over `buf[..]` then `chunk[..k]`) and return `NulByte`. Nothing is appended.
2. `bytes_seen += chunk.len()`; `buf.extend_from_slice(chunk)`.
3. `let mut start = 0; let mut frames = Vec::new();`
4. Loop: `let Some(rel) = memchr(b';', &buf[scan_from..]) else break; let end = scan_from + rel;`
   - If `is_complete_statement(&mut buf, start, end)`:
     - *as built:* if `end + 1 - start > max_statement_bytes` → `StatementTooLarge` (position = first non-whitespace byte of the statement, via `statement_start`)
     - `frames.push(Frame { sql: buf[start..=end].to_vec(), line: self.line, column: self.column })`
     - advance position over `buf[start..=end]` (§7.6)
     - `start = end + 1; scan_from = start;`
   - else `scan_from = end + 1;`
5. After the loop: `buf.drain(..start)` (one memmove per push, not per frame); `scan_from -= start`.
6. If `buf.len() > max_statement_bytes` → `StatementTooLarge { line, column, limit }` where `(line, column)` is the first non-whitespace byte of the pending statement (*as built*: `statement_start`, so the message points at the statement rather than at the end of the previous line).
7. Return `frames`.

Complexity: each candidate `;` costs one `sqlite3_complete` scan from the statement start, so a statement containing *k* interior semicolons (trigger bodies, string literals) costs O(k·len). Normal dumps have k ≤ a few. A frame is emitted at the first terminating `;`, so a frame contains exactly one statement plus any leading whitespace/comments.

### 7.5 `finish(&mut self) -> Option<Frame>`

Called at EOF. If `buf` is empty → `None`. Otherwise return the remaining bytes as a frame (with current `line, column`) and clear the buffer. The **executor** decides what the tail means (§8.5 step 2): only whitespace/comments → ignored; a complete statement without a trailing `;` (e.g. `COMMIT` at EOF) → executed, matching the buffered importer, whose parser appends a virtual `;` at EOF; anything else → parse error.

### 7.6 Position tracking

After emitting a frame `f`:

```rust
match memchr::memrchr(b'\n', &f) {
    Some(last) => { self.line += memchr::memchr_iter(b'\n', &f).count() as u64; self.column = f.len() - last; }
    None       => { self.column += f.len(); }
}
```

(`f.len() - last` = 1-based column of the byte that follows the frame.)

Absolute position of a parser error reported at `(rel_line, rel_col)` relative to a frame starting at `(line, column)`:

```rust
pub fn absolute_position(frame: (u64, usize), rel: (u64, usize)) -> (u64, usize) {
    if rel.0 <= 1 { (frame.0, frame.1 + rel.1.saturating_sub(1)) } else { (frame.0 + rel.0 - 1, rel.1) }
}
```

Worked example (existing snapshot `load_dump_with_invalid_sql`: `syntax error near 'COMMIT' at line 7, column 11`): the frame is `"\n    SELECT abs(-9223372036854775808) \n    COMMIT;"` starting at (5, 33) right after the `;` of line 5; the parser reports (3, 11); `absolute_position` → (5+3−1, 11) = (7, 11). Snapshot preserved.

### 7.7 Invariants

- `buf` never contains bytes of an already-emitted frame.
- Frames are emitted in input order and concatenating all frames plus the final `finish()` tail reproduces the input byte-for-byte.
- Frame boundaries are ASCII `;`, so if the whole dump is valid UTF-8, every frame is valid UTF-8 on its own (no multibyte char can straddle a frame boundary).
- Memory held by the framer ≤ `max_statement_bytes + len(last chunk)`.

---

## 8. `StatementExecutor` — normative spec (`streaming.rs`)

### 8.1 Message type

```rust
enum Msg {
    Stmt {
        sql: Vec<u8>,
        line: u64,
        column: usize,
        _budget: tokio::sync::OwnedSemaphorePermit,  // released when the executor drops the message
    },
    End,   // reader reached EOF cleanly and sent the finish() tail (if any)
}
```

### 8.2 Entry point

```rust
fn run_executor(conn: PrimaryConnection, mut rx: mpsc::Receiver<Msg>) -> Result<DumpImportStats, LoadDumpError>
```

Spawned once with `crate::BLOCKING_RT.spawn_blocking(move || run_executor(conn, rx))`. Receives with `rx.blocking_recv()`. Holds the only clone of the connection; drops it on return.

### 8.3 Setup

Install the authorizer **once**:

```rust
conn.with_raw(|c| c.authorizer(Some(|auth: AuthContext<'_>| match auth.action {
    AuthAction::Attach { .. } | AuthAction::Detach { .. } => Authorization::Deny,
    _ => Authorization::Allow,
})));
```

State: `n_stmt: u64 = 0`, `skipped_wasm_table = false`, `stats: DumpImportStats`.

### 8.4 Main loop

```
loop {
  match rx.blocking_recv() {
    Some(Msg::Stmt{sql,line,column,..}) => if let Err(e) = handle_statement(...) { rollback_best_effort(); clear_authorizer(); return Err(e) }
    Some(Msg::End) => break,
    None => { rollback_best_effort(); clear_authorizer();
              return Err(LoadDumpError::Internal("dump stream ended before completion".into())) }
  }
}
// End received
if !conn.with_raw(|c| c.is_autocommit()) {
    conn.with_raw(|c| c.execute_batch("ROLLBACK"))?;   // propagate error like the buffered importer
    clear_authorizer();
    return Err(LoadDumpError::NoCommit);
}
clear_authorizer();
Ok(stats)
```

`None` (channel closed without `End`) means the reader died — stream error, framer error, or request cancellation. The reader (if still alive) replaces this generic error with the real cause (§9.3).

`rollback_best_effort`: `conn.with_raw(|c| if !c.is_autocommit() { if let Err(e) = c.execute_batch("ROLLBACK") { tracing::warn!(...) } })`.
`clear_authorizer`: `conn.with_raw(|c| c.authorizer(None::<fn(AuthContext<'_>) -> Authorization>))`.

### 8.5 `handle_statement(sql: &[u8], line, column)` — in this exact order

1. **UTF-8**: `std::str::from_utf8(sql)` → on error `InvalidSqlInput("dump is not valid UTF-8 at line L, column C: …")` where `(L, C)` is the exact position of the offending byte (*as built*: `advance_position(frame_pos, &sql[..e.valid_up_to()])`). The vendored parser does *lossy* conversion internally — commit 4feb2b2e46 — so validation must happen here, before parsing.
2. **Parse** with `sqlite3_parser::lexer::sql::Parser::new(sql.as_bytes())`:
   - `Ok(None)` → frame holds only whitespace/comments (or a bare `;`) → `stats.statements_skipped += 1`; return `Ok(())`. (Per-frame parsing makes empty frames explicit; the buffered importer absorbs them inside one parser instance. Net behavior is identical.)
   - `Err(e)` → `map_parse_error(e, (line, column))` → `InvalidSqlInput` (§8.6).
   - `Ok(Some(cmd))` → continue. Then call `parser.next()` once more; if it is `Ok(Some(_))`, return `Internal("framing produced more than one statement")` — must never happen; guards against oracle/parser disagreement.
3. `n_stmt += 1`.
4. **WASM table skip** (identical to buffered): if `!skipped_wasm_table` and `cmd` is `Cmd::Stmt(Stmt::CreateTable { tbl_name, .. })` with `tbl_name.name.0 == "libsql_wasm_func_table"` → set flag, `statements_skipped += 1`, return `Ok(())`.
5. **ATTACH policy**: if `cmd` is `Cmd::Stmt(Stmt::Attach { .. })` or `Cmd::Stmt(Stmt::Detach(_))` → `InvalidSqlInput("attach statements are not allowed in dumps".into())` (same text as the buffered importer's snapshot). The authorizer remains as defense in depth (e.g. ATTACH reached through a trigger body).
6. **Transaction rule** (identical to buffered): `if n_stmt > 2 && conn.with_raw(|c| c.is_autocommit()) { return Err(LoadDumpError::NoTxn) }`.
7. **Execute the original text**, not `cmd.to_string()`:

```rust
fn execute_single(c: &mut rusqlite::Connection, sql: &str) -> rusqlite::Result<()> {
    let mut stmt = c.prepare(sql)?;        // single statement guaranteed by framing + step 2 guard (rusqlite's own tail check
                                           // needs the `extra_check` feature, which this workspace does not enable — do not rely on it)
    let mut rows = stmt.raw_query();
    while rows.next()?.is_some() {}        // tolerate row-returning statements (EXPLAIN, PRAGMA x, stray SELECT) like the sqlite3 shell
    Ok(())
}
```

   Errors → `map_exec_error(e, n_stmt)` (§8.6). Update `stats.statements_executed`, `stats.max_statement_bytes`.

Rationale for executing original text: the AST round-trip is a known source of fidelity bugs in this code path (commits abd0b525fe "parse dumps with triggers correctly", fcfde9edcc) and silently alters the text (probe: `VALUES(1.0e10, 'a''b', X'00ff')` is re-emitted as `VALUES (1.0e10, 'a''b', X'00ff')` — harmless here, but it demonstrates the two texts differ). SQLite itself is the authority on its own dump format. The parser is still needed for the policy checks (steps 4–5), for empty-frame detection, and to report parse errors in the same format as before. Equivalence between the two importers is verified by diffing `GET /dump` output (§15).

### 8.6 Error mapping (shared in `mod.rs`)

```rust
fn map_parse_error(mut e: sqlite3_parser::lexer::sql::Error, frame_pos: (u64, usize)) -> LoadDumpError {
    use sqlite3_parser::lexer::sql::Error as E;
    // 1. extract relative position (every variant except Io carries Option<(u64, usize)>)
    let rel = match &e { E::ParserError(_, p) | E::UnrecognizedToken(p) | E::UnterminatedLiteral(p) | /* …all others… */ => *p, E::Io(_) => None, _ => None };
    // 2. rewrite it to absolute using framer::absolute_position and ScanError::position
    if let Some(rel) = rel { let (l, c) = absolute_position(frame_pos, rel); sqlite3_parser::lexer::ScanError::position(&mut e, l, c); }  // `lexer::ScanError` is the public re-export (`lexer::scan` is private)
    // 3. format exactly like the buffered importer
    let msg = match e {
        E::ParserError(ParserError::SyntaxError { token_type, found }, Some((line, col))) => {
            let near = found.as_deref().unwrap_or(&token_type);
            format!("syntax error near '{near}' at line {line}, column {col}")
        }
        other => format!("parse error: {other}"),
    };
    LoadDumpError::InvalidSqlInput(msg)
}

fn map_exec_error(e: rusqlite::Error, n_stmt: u64) -> LoadDumpError {
    match e {
        rusqlite::Error::SqlInputError { msg, sql, offset, .. } =>
            LoadDumpError::InvalidSqlInput(format!("msg: {msg}, sql: {sql}, offset: {offset}")),
        e => LoadDumpError::Internal(format!("statement: {n_stmt}, error: {e}")),
    }
}
```

`Error` is `#[non_exhaustive]`; keep a `_ => None` arm.

---

## 9. Reader / pipeline — normative spec (`streaming.rs`)

### 9.1 Signature

```rust
pub(super) async fn load_dump_streaming(
    mut stream: DumpStream,
    conn: PrimaryConnection,
    cfg: &DumpImportConfig,
) -> Result<DumpImportStats, LoadDumpError>
```

### 9.2 Body

```rust
let (tx, rx) = tokio::sync::mpsc::channel::<Msg>(cfg.queue_depth);
let budget = Arc::new(tokio::sync::Semaphore::new(cfg.queue_bytes));
let executor = crate::BLOCKING_RT.spawn_blocking(move || run_executor(conn, rx));
let mut framer = StatementFramer::new(cfg.max_statement_bytes);

enum FeedError { Stream(LoadDumpError), ExecutorGone }

let feed: Result<(), FeedError> = async {
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| FeedError::Stream(LoadDumpError::Internal(format!("Failed to read dump content: {e}"))))?;
        for frame in framer.push(&chunk).map_err(|e| FeedError::Stream(e.into()))? {
            send_frame(&tx, &budget, cfg.queue_bytes, frame).await?;
        }
    }
    if let Some(tail) = framer.finish() { send_frame(&tx, &budget, cfg.queue_bytes, tail).await?; }
    tx.send(Msg::End).await.map_err(|_| FeedError::ExecutorGone)
}.await;

drop(tx);                                    // guarantees the executor observes closure if we failed before End
let exec = executor.await
    .map_err(|e| LoadDumpError::Internal(format!("dump executor task failed: {e}")))?;

match (feed, exec) {
    (Ok(()), exec)                      => exec,          // normal path: executor's verdict (Ok / NoCommit / …)
    (Err(FeedError::ExecutorGone), Err(e)) => Err(e),     // executor failed first; report its error
    (Err(FeedError::ExecutorGone), Ok(s)) => Err(LoadDumpError::Internal("executor finished before the dump was fully read".into())), // impossible, defensive
    (Err(FeedError::Stream(e)), _)      => Err(e),        // I/O or framing error wins over the executor's generic "ended before completion"
}
```

```rust
async fn send_frame(tx, budget: &Arc<Semaphore>, queue_bytes: usize, f: Frame) -> Result<(), FeedError> {
    let permits = f.sql.len().clamp(1, queue_bytes) as u32;          // oversized statements take the whole budget → alone in flight
    let permit = budget.clone().acquire_many_owned(permits).await.expect("semaphore never closed");
    tx.send(Msg::Stmt { sql: f.sql, line: f.line, column: f.column, _budget: permit })
      .await.map_err(|_| FeedError::ExecutorGone)
}
```

`From<FrameError> for LoadDumpError`: `NulByte` → `InvalidSqlInput("dump contains a NUL byte at line L, column C")`; `StatementTooLarge` → `LoadDumpError::StatementTooLarge { line, limit }` (new variant, HTTP 413).

### 9.3 Failure and cancellation semantics

| Event | Reader | Executor | Result |
|---|---|---|---|
| Stream yields `Err` | stops, drops `tx` | sees `None` → ROLLBACK | `Internal("Failed to read dump content: …")` → 500 (same as buffered) |
| Framer error (NUL / too large) | stops, drops `tx` | `None` → ROLLBACK | 400 / 413 |
| Executor error (parse/exec/NoTxn) | `send` fails → `ExecutorGone` | returns `Err(e)` after ROLLBACK | `e` → 400/500 as today |
| EOF without `COMMIT` | sends `End` | not autocommit → ROLLBACK → `NoCommit` | 400 (same as buffered) |
| Admin HTTP request dropped (client timeout) | future dropped → `tx` dropped | `None` → ROLLBACK, drops connection, exits | no response; SQLite state clean. Directory/metastore cleanup is **not** run (pre-existing, §13) |
| Executor panics | `executor.await` → `JoinError` | — | `Internal(...)` → 500; connection dropped by unwinding → SQLite rolls back on close |

The executor is never cancelled by tokio; it always reaches a ROLLBACK or COMMIT decision itself. That is the robustness win over the buffered importer, whose per-statement `spawn_blocking` can be orphaned mid-loop.

### 9.4 Stream chunking

In `dump_stream_from_url` change `ReaderStream::new(f)` to `ReaderStream::with_capacity(f, 64 * 1024)`. Hyper bodies arrive as they come (typically 8–64 KiB). The framer is chunk-size agnostic; this is only an efficiency tweak and benefits both importers.

---

## 10. Behavior parity matrix

| Case | Buffered (unchanged) | Streaming | Snapshot reuse |
|---|---|---|---|
| Valid `sqlite3 .dump` / `GET /dump` output | 200 | 200 | — |
| `BEGIN`/`COMMIT` missing (`NoTxn`, `NoCommit`) | 400, same messages | 400, same messages | yes |
| Syntax error | 400 `syntax error near 'X' at line L, column C` (absolute) | identical (absolute via §7.6) | yes |
| `ATTACH 'f' AS x;` as a statement | 400 "attach statements are not allowed in dumps" (substring check) | 400, same message (AST check) | yes |
| standalone `DETACH x;` | passes the substring check, fails at execution → 500 | 400 (AST check) | documented |
| Word "attach" inside data (`'attachment'`) | **400** (false positive) | 200 | new test, streaming only |
| `ATTACH foo/bar.sql` without `;` (existing test) | 400 "attach statements are not allowed" | 400 `syntax error near 'COMMIT' …` | keep legacy test; add streaming test with a well-formed ATTACH |
| Empty statement `;;`, comment-only segments | absorbed by the parser | empty frame skipped | new test, both |
| `COMMIT` without trailing `;` at EOF | executed | executed | new test, both |
| Invalid UTF-8 | 500 `Internal` | 400 `InvalidSqlInput` | document |
| NUL byte in dump | 500 (`read_to_string` fails) | 400 | document |
| Statement > `max_statement_bytes` | accepted (unbounded) | 413 | new test, streaming only |
| Row-returning statement (stray `SELECT`) | 500 (`ExecuteReturnedResults`) | executed, rows discarded | document |
| Executed SQL text | `cmd.to_string()` | original bytes | §8.5 (7). *As built:* the equivalence test showed the two `/dump` outputs differ in **DDL text only** — buffered stores the parser's normalized rendering (`ON plain (a)`, multi-line trigger body), streaming stores the dump's DDL verbatim. Data rows are identical, so validation compares `INSERT`/`DELETE` lines and asserts the streaming DDL matches the source. |
| Trigger / CASE / nested CASE (existing tests) | 200 | 200 | yes |
| Peak memory | O(dump size) | O(config + largest statement) | §15 |

---

## 11. Memory model (streaming)

| Component | Bound | Default |
|---|---|---|
| Last stream chunk | chunk size | ≤ 64 KiB |
| Framer pending buffer | `max_statement_bytes` (+ one chunk transiently) | 64 MiB cap; typically a few KiB |
| Channel payload | `min(queue_bytes + one statement, queue_depth × stmt)` | 16 MiB |
| Per-statement parse AST | O(statement) | transient |
| SQLite page cache | `cache_size` pragma, independent of importer | unchanged |
| Replication log / WAL | on disk, flushed per spill (`replication_logger_wal.rs`) | disk ≈ 2× DB size during import |

Expected steady-state importer RSS: < 32 MiB regardless of dump size, versus ≈ 2× dump size for buffered (`String` + lowercase copy during the ATTACH check).

Disk: the single dump transaction means the SQLite WAL and the replication log each grow to roughly the database size before `COMMIT`; the auto-checkpoint runs after commit. Identical for both importers; worth stating in the runbook.

---

## 12. Observability

Logging (in the dispatcher, `tracing`):

- start: `info!(namespace, importer, "loading dump")`
- success: `info!(namespace, importer, statements, skipped, bytes, max_statement_bytes, elapsed_ms, "dump loaded")`
- failure: `warn!(namespace, importer, error = %e, elapsed_ms, "dump load failed; transaction rolled back")`

Metrics (`libsql-server/src/metrics.rs` style; `metrics` 0.21 macros with labels):

- `libsql_server_dump_import_duration_seconds{importer}` histogram
- `libsql_server_dump_import_bytes{importer}` counter
- `libsql_server_dump_import_statements{importer}` counter
- `libsql_server_dump_import_failures{importer, kind}` counter, `kind ∈ {stream, parse, exec, txn, limit}`
- `libsql_server_dump_import_max_statement_bytes{importer}` histogram

---

## 13. Pre-existing issues this design does not fix (state them in the PR)

1. `NamespaceStore::create` stores the namespace config in the metastore **before** loading. On import failure the directory is removed (`PrimaryConfigurator::setup`) but the metastore row stays, so a later request to the namespace lazily creates an **empty** database. Existing tests rely on this (`select … from test` errors because the table is missing, not because the namespace is missing).
2. If the Admin HTTP request is cancelled mid-import, `setup`'s cleanup does not run (the future is dropped). The streaming executor still rolls back SQLite state, but the directory and `.sentinel` remain.
3. No server-side timeout exists for dump imports; the Admin HTTP request stays open for the whole import. Clients must not time out, or must tolerate (2).
4. Bottomless, if enabled, has its own frame buffering/backpressure outside this design.

These are tracked by the DB Mover quarantine/fence work (Retail #35846/#35848).

---

## 14. Testing

### 14.1 Unit tests — `framer.rs`

Use a helper that feeds a dump in every chunk size from 1 to N (`for cs in 1..=input.len()`) and asserts identical frames. Cases:

1. Two simple statements; `;` at the very end of a chunk; `;` as the first byte of a chunk.
2. `;` inside a string literal `'a;b'`, inside `"quoted;ident"`, inside `-- comment;\n`, inside `/* block ; comment */`.
3. `CREATE TRIGGER … BEGIN INSERT …; UPDATE …; END;` → one frame.
4. Multibyte UTF-8 (`'żółć'`, emoji) split across chunk boundaries → frames are valid UTF-8.
5. Empty statements `;;` and `;\n;` → frames emitted; concatenation reproduces input.
6. `finish()` returns `None` after a trailing `;`, returns the tail for `COMMIT` without `;` and for `-- trailing comment\n`.
7. NUL byte → `NulByte` with correct line/column.
8. Oversized pending statement → `StatementTooLarge` at the correct position; a statement exactly at the limit passes.
9. Position tracking: construct a multi-line dump, assert each frame's `(line, column)`; assert `absolute_position` on the §7.6 worked example.
10. `is_complete_statement` directly: `"SELECT 1;"` true, `"SELECT ';"` false, `"CREATE TRIGGER t AFTER INSERT ON x BEGIN SELECT 1;"` false, `"… END;"` true, `";"` true.

### 14.2 Integration tests — `libsql-server/tests/namespaces/dumps.rs`

Add helper:

```rust
async fn create_from_dump(client: &Client, ns: &str, dump_url: String, importer: Option<&str>) -> Response {
    let mut body = json!({ "dump_url": dump_url });
    if let Some(i) = importer { body["dump_importer"] = json!(i); }
    client.post(&format!("http://primary:9090/v1/namespaces/{ns}/create"), body).await.unwrap()
}
```

Refactor each existing test body into `fn <name>_with(importer: Option<&str>)` and keep the existing `#[test] fn <name>()` calling `_with(None)` (snapshots untouched), plus `#[test] fn <name>_streaming()` calling `_with(Some("streaming"))`. Streaming variants that need a snapshot use `insta::assert_snapshot!("<legacy_name>", value)` (named snapshot) when the message is identical, otherwise a new snapshot.

New tests (streaming unless noted):

- `streaming_chunked_http_delivery`: the turmoil `dump-store` host serves the dump as `hyper::Body::wrap_stream(futures::stream::iter(chunks))` with 1-, 3- and 7-byte chunks; assert 200 and row count. End-to-end framing test.
- `streaming_truncated_http_body`: body stream yields half the dump then `Err(io::Error)` → 500; `select count(*) from test` fails.
- `streaming_empty_statements`, `streaming_commit_without_semicolon`, `streaming_semicolon_in_string_and_comment`.
- `streaming_attach_statement_rejected` (`ATTACH 'x.db' AS x;`) → 400 with the legacy message; `streaming_word_attach_in_data_accepted`.
- `streaming_statement_too_large` → 413, requires a server with `DbConfig { dump_import: DumpImportConfig { max_statement_bytes: 1024, .. } }` — add `make_primary_with_db_config(sim, path, DbConfig)` beside `make_primary`.
- `dump_importer_without_dump_url` → 400; `dump_importer_unknown_value` → 400.
- `server_default_streaming`: server started with `default_importer: Streaming`, request omits `dump_importer`, dump whose data contains the word `'attachment'` succeeds (buffered would reject it with 400 — proves streaming was used).
- `importers_produce_identical_databases`: same dump (triggers, views, indexes, `sqlite_sequence`, text with quotes/newlines, blobs, REAL values like `1.0e10`, a `WITHOUT ROWID` table, a table whose rowid must be preserved) into `ns_buffered` and `ns_streaming`; `GET /dump?preserve_row_ids=true` on both; assert identical data lines, assert the streaming output contains the source DDL verbatim, snapshot the streaming output (*as built*; see §10 for why not byte-equal).
- `streaming_large_dump`: generate 200k single-row INSERTs into a temp file; assert count. Guards against accidental O(n²) in framing.

### 14.3 Lints

`cargo clippy -p libsql-server -- -D warnings` and `cargo fmt` (toolchain 1.98.1, workspace enforces `-D warnings`).

---

## 15. Benchmark and validation on one instance

1. Start one server: `sqld --enable-namespaces --admin-listen-addr 127.0.0.1:9090 --dump-importer buffered` (defaults). Record `PID`.
2. Dataset: export a representative namespace with `GET /dump?preserve_row_ids=true` (or `sqlite3 x.db .dump`) into `/tmp/dump.sql`; sizes 100 MB, 1 GB, 4 GB.
3. For `imp in streaming buffered` (streaming first — `VmHWM` is a lifetime high-water mark):
   - background sampler: every 200 ms append `date +%s%3N, $(grep VmRSS /proc/$PID/status)` to `rss_$imp.csv`;
   - `time curl -sS -X POST localhost:9090/v1/namespaces/ns_$imp/create -H 'content-type: application/json' -d "{\"dump_url\":\"file:///tmp/dump.sql\",\"dump_importer\":\"$imp\"}"`;
   - stop sampler; record `max(VmRSS) − baseline`, wall time, `du -sh data.sqld/dbs/ns_$imp`.
4. Validation:
   - `curl -H 'x-namespace: ns_buffered' localhost:8080/dump?preserve_row_ids=true > a.sql`; same for `ns_streaming` → the `INSERT`/`DELETE` lines must be identical (DDL text legitimately differs, §10);
   - `PRAGMA integrity_check` via hrana (`POST /v2/pipeline`) on both → `ok`;
   - compare `libsql_server_dump_import_*` metrics from `/metrics`.
5. Acceptance: streaming peak RSS delta plateaus (< 64 MiB) across the three sizes while buffered scales ≈ 2× dump; streaming wall time ≤ buffered wall time; dumps byte-identical.

The script is `scripts/bench-dump-import.sh`; it implements steps 3–4 against a running server and prints a results table.

First run (*as built*; debug build, macOS arm64, 36 MB dump, 300 007 statements, one `sqld` instance, importers run back to back):

| importer | HTTP | wall | RSS before → peak | Δ RSS |
|---|---|---|---|---|
| streaming | 200 | 15.2 s | 38 MB → 54 MB | **+15 MB** |
| buffered | 200 | 19.7 s | 56 MB → 195 MB | **+135 MB** (≈ 3.7× the dump) |

Both namespaces: `PRAGMA integrity_check` = `ok`, 300 300 identical data rows. The buffered importer had earlier rejected a variant of the same dump whose data contained the word "attachment" (§10).

After the review fixes (§18), a 10 MB dump of 50 rows holding 200 KB CSS-like values (~5 000 interior semicolons each — the shape that was quadratic): streaming 0.56 s / +21 MB RSS, buffered 0.53 s / +32 MB RSS, identical data, `integrity_check` ok. The pre-fix framer needed ≈ 0.36 s *per row* for this shape.

---

## 16. Implementation plan (ordered; each step compiles and passes tests)

**Step 1 — refactor, no behavior change**
- Create `namespace/dump_import/{mod.rs,buffered.rs}`; move `load_dump` verbatim to `buffered::load_dump_buffered`, returning `DumpImportStats`.
- Add `DumpImporterKind`, `DumpImportConfig`, `DumpImportStats`, dispatcher `load_dump` (streaming arm temporarily `unimplemented!()`-free: return `Internal("streaming importer not available")`).
- `DumpSource`, `RestoreOption::Dump(DumpSource)`; update `helpers.rs` match; `admin/mod.rs` builds `DumpSource { stream, importer: req.dump_importer }`.
- `DbConfig.dump_import`, `BaseNamespaceConfig.dump_import`, `lib.rs` plumbing, `scheduler.rs` test constructors, CLI flags in `main.rs`, `make_db_config` validation.
- New `LoadDumpError` variants: `ImporterWithoutDumpUrl` (400), `StatementTooLarge { line: u64, limit: usize }` (413, `StatusCode::PAYLOAD_TOO_LARGE`). Update `IntoResponse for &LoadDumpError`.
- `ReaderStream::with_capacity(f, 64 * 1024)`.
- Run the existing dump tests: all green, snapshots unchanged.

**Step 2 — framer**
- `framer.rs` per §7 with the unit tests of §14.1. Add `memchr` dependency.

**Step 3 — streaming importer**
- `streaming.rs` per §8–9; wire the dispatcher arm; `From<FrameError> for LoadDumpError`.
- Integration tests of §14.2; `make_primary_with_db_config`.
- Metrics + logging (§12).
- Docs: `docs/ADMIN_API.md` (`dump_importer`), `docs/USER_GUIDE.md` or `docs/BUILD-RUN.md` (flags), note the parity matrix differences.

**Step 4 — benchmark**
- Script + results table in the PR; decide whether to flip `--dump-importer` default to `streaming` in a follow-up. Removal of the buffered importer is a later, separate change after production soak.

File change list:

| File | Change |
|---|---|
| `libsql-server/Cargo.toml` | `memchr = "2"` |
| `libsql-server/src/namespace/dump_import/{mod,buffered,framer,streaming}.rs` | new |
| `libsql-server/src/namespace/mod.rs` | `pub(crate) mod dump_import;`, `DumpSource`, `RestoreOption::Dump(DumpSource)` |
| `libsql-server/src/namespace/configurator/helpers.rs` | remove `load_dump` + its imports; new match arm |
| `libsql-server/src/namespace/configurator/mod.rs` | `BaseNamespaceConfig.dump_import` |
| `libsql-server/src/config.rs` | `DbConfig.dump_import` |
| `libsql-server/src/lib.rs` | copy into `BaseNamespaceConfig` |
| `libsql-server/src/main.rs` | 4 flags, `make_db_config`, validation |
| `libsql-server/src/http/admin/mod.rs` | `dump_importer` field, check, `DumpSource`, `ReaderStream::with_capacity` |
| `libsql-server/src/error.rs` | 2 variants + response mapping |
| `libsql-server/src/metrics.rs` | 5 metrics |
| `libsql-server/src/schema/scheduler.rs` | test `BaseNamespaceConfig` literals |
| `libsql-server/tests/namespaces/{mod,dumps}.rs` + snapshots | helpers, variants, new tests |
| `docs/ADMIN_API.md`, `docs/USER_GUIDE.md` | docs |

---

## 17. Risks and open questions

- **Oracle/parser disagreement.** `sqlite3_complete` and `sqlite3_parser` are two tokenizers. If they ever disagree on where a statement ends, the result is a parse error (fail closed) or the §8.5 step 2 guard, never silent corruption. Known shared rules: strings, quoted identifiers, `--`/`/* */` comments, `CREATE [TEMP] TRIGGER … END`.
- **Per-statement `Parser` allocation.** `Parser::new` allocates a lemon stack per call. If profiling shows it matters, reuse via `Parser::reset` behind a small wrapper; not needed for correctness.
- **Original-text execution vs AST text.** Deliberate (§8.5). If an A/B shows a divergence, the `/dump` diff in §15 will surface it; the fix belongs in the parser, not in the importer.
- **`EXPLAIN`/row-returning statements** are executed and their rows discarded; the buffered importer fails on them. Acceptable and documented.
- **413 vs 400 for oversized statements.** Chosen 413 so operators can tell "raise the cap" from "fix the dump". Revisit if admin clients treat 413 specially.
- **Default flip timing.** Keep `buffered` as default until the §15 acceptance criteria are met on production-shaped data (settings and catalog schemas, FTS tables included).

---

## 18. Adversarial review of PR #51 — findings and resolutions

Independent reviewers (scope, correctness, security, performance, testing, architecture, operations) plus a manual pass. Verdict before fixes: **NEEDS CHANGES** (one HIGH, several MEDIUM). All items below are resolved in the PR unless marked *deferred*.

| Sev | Finding | Resolution |
|---|---|---|
| HIGH | Framing was O(n²) in interior semicolons and ran on a tokio worker: 1 MiB/50k `;` → 20 s CPU; a 200 KB CSS-like value → 0.36 s per row (perf, security, architecture reviewers; measured). | Resumable port of `sqlite3_complete` (`complete.rs`), differential-tested against the FFI; `semicolon_dense_statement_is_linear` test. Framing is now a single linear pass. |
| MEDIUM | Peak memory ≈ 2× largest statement: `to_vec()` copy while `buf` still held the bytes until `drain`. | Frames ≥ 1 MiB are handed over with `split_off`/`mem::replace` (no copy); `large_frames_are_handed_over_without_copy` test. |
| MEDIUM | `DumpImportConfig { queue_bytes: 0 }` / `{ queue_depth: 0 }` built without `validate()` panicked (`clamp(1, 0)`, `mpsc::channel(0)`). | Clamped at the point of use in `load_dump_streaming`. |
| MEDIUM | Failure log repeated the full error (which may quote dump SQL) at WARN, duplicating the HTTP layer's ERROR log. | WARN now logs the failure *category* plus partial progress (statements, bytes); the error text stays in the HTTP-layer log/response. |
| MEDIUM | No progress visibility or partial stats for multi-minute imports. | Executor logs `dump import in progress` every 10 s; failures report statements/bytes processed. |
| MEDIUM | `dump_importer` JSON value was case-sensitive while the CLI flag was lenient. | `Deserialize` now delegates to `FromStr` (case-insensitive, trimmed). |
| MEDIUM | Untested: WASM-table skip, empty dump, EOF without `;`, executor failure under backpressure, request cancellation. | Tests added for all five (cancellation test tolerates the pre-existing "namespace may or may not be registered" nondeterminism). |
| MEDIUM | Bench script: macOS `date +%N` prints garbage silently; hard `bc`/`python3` dependencies; bare `$(curl …)` under `set -e`; caller-supplied PID not verified. | `python3` for timestamps, `awk` arithmetic, explicit tool check, curl/`integrity_check` failures reported, PID must be a `sqld` process. |
| LOW | 413 message dropped the computed column. | `StatementTooLarge` carries `column`. |
| LOW | Bare `DETACH` is 400 (streaming) vs 500 (buffered) — undocumented difference. | Documented in ADMIN_API.md and §10. |
| LOW | Executor panic bypasses `rollback_best_effort`. | Not a correctness gap: unwinding drops the connection and SQLite rolls back on close; documented on `run_executor`. |
| *deferred* | Per-statement policy (WASM skip, `n_stmt > 2` rule) duplicated between importers. | Keep until the buffered importer is removed; the parameterized tests pin both. |
| *deferred* | `BLOCKING_RT` hosts one long-lived thread per concurrent streaming import with no admission control. | 50 000-thread pool and low create concurrency today; revisit with bulk provisioning. |
| *deferred* | Splitting the PR (refactor vs feature). | Commit 1 is the pure refactor and can be reviewed in isolation. |
