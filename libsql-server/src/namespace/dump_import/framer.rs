//! Incremental SQL statement framing.
//!
//! [`StatementFramer`] turns an arbitrary sequence of byte chunks into complete SQL statements,
//! each ending at the `;` that terminates it, while only ever holding one unfinished statement
//! in memory. Statement boundaries are decided by SQLite's own `sqlite3_complete()`, so
//! semicolons inside string literals, quoted identifiers, comments and `CREATE TRIGGER ... END`
//! bodies are handled exactly like the `sqlite3` shell does.
//!
//! See `docs/STREAMING_DUMP_IMPORT_DESIGN.md` §7.

use std::ffi::c_char;

use memchr::{memchr, memchr_iter, memrchr};
use rusqlite::ffi::sqlite3_complete;

/// One complete statement (plus any whitespace/comments that preceded it in the dump), with the
/// 1-based position of its first byte in the whole dump.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Frame {
    pub sql: Vec<u8>,
    pub line: u64,
    pub column: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum FrameError {
    /// Dumps are text; a NUL byte can't be part of valid SQL and would confuse the C framing
    /// oracle, so it is rejected outright.
    NulByte { line: u64, column: usize },
    /// The statement starting at `(line, column)` grew past the configured limit without
    /// terminating.
    StatementTooLarge {
        line: u64,
        column: usize,
        limit: usize,
    },
}

pub(super) struct StatementFramer {
    /// Bytes after the last emitted frame; starts with the next statement's leading
    /// whitespace/comments.
    buf: Vec<u8>,
    /// Offset in `buf` from which to look for the next `;`. Semicolons before it were already
    /// tested and found not to terminate the statement.
    scan_from: usize,
    /// 1-based line of `buf[0]` in the whole dump.
    line: u64,
    /// 1-based byte column of `buf[0]` in the whole dump.
    column: usize,
    max_statement_bytes: usize,
    bytes_seen: u64,
}

impl StatementFramer {
    pub fn new(max_statement_bytes: usize) -> Self {
        Self {
            buf: Vec::new(),
            scan_from: 0,
            line: 1,
            column: 1,
            max_statement_bytes,
            bytes_seen: 0,
        }
    }

    /// Total number of bytes accepted by [`push`](Self::push).
    pub fn bytes_seen(&self) -> u64 {
        self.bytes_seen
    }

    /// Append a chunk and return every statement completed by it, in input order.
    ///
    /// On error, the framer must not be used further.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<Frame>, FrameError> {
        if let Some(k) = memchr(0, chunk) {
            let (line, column) = advance_position((self.line, self.column), &self.buf);
            let (line, column) = advance_position((line, column), &chunk[..k]);
            return Err(FrameError::NulByte { line, column });
        }

        self.bytes_seen += chunk.len() as u64;
        self.buf.extend_from_slice(chunk);

        let mut frames = Vec::new();
        let mut start = 0;
        while let Some(rel) = memchr(b';', &self.buf[self.scan_from..]) {
            let end = self.scan_from + rel;
            if is_complete_statement(&mut self.buf, start, end) {
                let sql = self.buf[start..=end].to_vec();
                frames.push(Frame {
                    sql,
                    line: self.line,
                    column: self.column,
                });
                (self.line, self.column) =
                    advance_position((self.line, self.column), &self.buf[start..=end]);
                start = end + 1;
            }
            self.scan_from = end + 1;
        }

        if start > 0 {
            self.buf.drain(..start);
            self.scan_from -= start;
        }

        if self.buf.len() > self.max_statement_bytes {
            return Err(FrameError::StatementTooLarge {
                line: self.line,
                column: self.column,
                limit: self.max_statement_bytes,
            });
        }

        Ok(frames)
    }

    /// Signal end of input. Returns whatever follows the last terminated statement: possibly
    /// nothing, possibly whitespace/comments only, possibly a final statement without a trailing
    /// `;`. The caller decides what that tail means.
    pub fn finish(&mut self) -> Option<Frame> {
        if self.buf.is_empty() {
            return None;
        }
        let frame = Frame {
            sql: std::mem::take(&mut self.buf),
            line: self.line,
            column: self.column,
        };
        self.scan_from = 0;
        (self.line, self.column) = advance_position((self.line, self.column), &frame.sql);
        Some(frame)
    }
}

/// Does `buf[start..=end]` (whose last byte is `;`) look like a complete SQL statement?
///
/// `sqlite3_complete` needs a NUL-terminated string, so a terminator is temporarily placed right
/// after the `;`. The function only tokenizes; it does not parse or touch any database.
fn is_complete_statement(buf: &mut Vec<u8>, start: usize, end: usize) -> bool {
    debug_assert_eq!(buf[end], b';');
    let pushed = if end + 1 == buf.len() {
        buf.push(0);
        true
    } else {
        false
    };
    let saved = buf[end + 1];
    buf[end + 1] = 0;
    // SAFETY: `buf[start..]` is NUL-terminated at `end + 1`, which is within bounds, and
    // `sqlite3_complete` only reads the string.
    let complete = unsafe { sqlite3_complete(buf[start..].as_ptr() as *const c_char) } != 0;
    buf[end + 1] = saved;
    if pushed {
        buf.pop();
    }
    complete
}

/// Position of the byte following `bytes`, given the position of its first byte.
fn advance_position((line, column): (u64, usize), bytes: &[u8]) -> (u64, usize) {
    match memrchr(b'\n', bytes) {
        Some(last) => (
            line + memchr_iter(b'\n', bytes).count() as u64,
            bytes.len() - last,
        ),
        None => (line, column + bytes.len()),
    }
}

/// Translate a position reported relative to a frame into a position in the whole dump.
///
/// `frame` is the 1-based `(line, column)` of the frame's first byte; `rel` is the 1-based
/// position within the frame.
pub(super) fn absolute_position(frame: (u64, usize), rel: (u64, usize)) -> (u64, usize) {
    if rel.0 <= 1 {
        (frame.0, frame.1 + rel.1.saturating_sub(1))
    } else {
        (frame.0 + rel.0 - 1, rel.1)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const LIMIT: usize = 1 << 20;

    /// Feed `input` in chunks of `chunk_size` and collect frames plus the final tail.
    fn frame_all(input: &[u8], chunk_size: usize) -> (Vec<Frame>, Option<Frame>) {
        let mut framer = StatementFramer::new(LIMIT);
        let mut frames = Vec::new();
        for chunk in input.chunks(chunk_size) {
            frames.extend(framer.push(chunk).unwrap());
        }
        assert_eq!(framer.bytes_seen(), input.len() as u64);
        (frames, framer.finish())
    }

    fn sqls(frames: &[Frame]) -> Vec<String> {
        frames
            .iter()
            .map(|f| String::from_utf8(f.sql.clone()).unwrap())
            .collect()
    }

    /// Framing must not depend on chunk boundaries, and frames + tail must reproduce the input.
    fn assert_chunk_invariant(input: &str, expected: &[&str], expected_tail: Option<&str>) {
        let reference = frame_all(input.as_bytes(), input.len().max(1));
        assert_eq!(sqls(&reference.0), expected, "input: {input:?}");
        assert_eq!(
            reference
                .1
                .as_ref()
                .map(|f| String::from_utf8(f.sql.clone()).unwrap()),
            expected_tail.map(str::to_owned),
            "tail for input: {input:?}"
        );
        for chunk_size in 1..=input.len().max(1) {
            let got = frame_all(input.as_bytes(), chunk_size);
            assert_eq!(
                got, reference,
                "chunk size {chunk_size} for input {input:?}"
            );
            let mut rebuilt: Vec<u8> = got.0.iter().flat_map(|f| f.sql.clone()).collect();
            if let Some(tail) = &got.1 {
                rebuilt.extend_from_slice(&tail.sql);
            }
            assert_eq!(rebuilt, input.as_bytes());
        }
    }

    #[test]
    fn simple_statements() {
        assert_chunk_invariant(
            "PRAGMA foreign_keys=OFF;\nBEGIN TRANSACTION;\nCREATE TABLE t(x);\nCOMMIT;\n",
            &[
                "PRAGMA foreign_keys=OFF;",
                "\nBEGIN TRANSACTION;",
                "\nCREATE TABLE t(x);",
                "\nCOMMIT;",
            ],
            Some("\n"),
        );
    }

    #[test]
    fn semicolons_inside_tokens_do_not_terminate() {
        assert_chunk_invariant(
            "INSERT INTO t VALUES('a;b');INSERT INTO t VALUES(\"q;i\");SELECT [b;r];",
            &[
                "INSERT INTO t VALUES('a;b');",
                "INSERT INTO t VALUES(\"q;i\");",
                "SELECT [b;r];",
            ],
            None,
        );
        assert_chunk_invariant(
            "-- comment; with semicolon\nSELECT 1;/* block ; comment */SELECT 2;",
            &[
                "-- comment; with semicolon\nSELECT 1;",
                "/* block ; comment */SELECT 2;",
            ],
            None,
        );
        assert_chunk_invariant(
            "CREATE TABLE t(x CHECK(x <> ';'));",
            &["CREATE TABLE t(x CHECK(x <> ';'));"],
            None,
        );
    }

    #[test]
    fn trigger_body_is_one_frame() {
        let trigger = "CREATE TRIGGER tr AFTER INSERT ON t BEGIN\n  INSERT INTO u VALUES(1);\n  UPDATE u SET x = 2;\nEND;";
        assert_chunk_invariant(
            &format!("{trigger}\nINSERT INTO t VALUES(1);"),
            &[trigger, "\nINSERT INTO t VALUES(1);"],
            None,
        );
        let temp = "CREATE TEMP TRIGGER tr AFTER INSERT ON t BEGIN SELECT 1; END;";
        assert_chunk_invariant(temp, &[temp], None);
    }

    #[test]
    fn multibyte_utf8_across_chunks() {
        let input = "INSERT INTO t VALUES('żółć 🎉; nie koniec');INSERT INTO t VALUES('日本語');";
        assert_chunk_invariant(
            input,
            &[
                "INSERT INTO t VALUES('żółć 🎉; nie koniec');",
                "INSERT INTO t VALUES('日本語');",
            ],
            None,
        );
        for f in frame_all(input.as_bytes(), 1).0 {
            assert!(std::str::from_utf8(&f.sql).is_ok());
        }
    }

    #[test]
    fn empty_statements_are_frames() {
        assert_chunk_invariant(
            "SELECT 1;;\n;SELECT 2;",
            &["SELECT 1;", ";", "\n;", "SELECT 2;"],
            None,
        );
    }

    #[test]
    fn finish_returns_tail() {
        assert_chunk_invariant("SELECT 1;", &["SELECT 1;"], None);
        assert_chunk_invariant("SELECT 1;\nCOMMIT", &["SELECT 1;"], Some("\nCOMMIT"));
        assert_chunk_invariant(
            "SELECT 1;\n-- trailing comment\n",
            &["SELECT 1;"],
            Some("\n-- trailing comment\n"),
        );
        assert_chunk_invariant("", &[], None);
        let mut framer = StatementFramer::new(LIMIT);
        assert!(framer.push(b"SELECT 1;").unwrap().len() == 1);
        assert_eq!(framer.finish(), None);
        assert_eq!(framer.finish(), None);
    }

    #[test]
    fn nul_byte_is_rejected_with_position() {
        let mut framer = StatementFramer::new(LIMIT);
        framer.push(b"SELECT 1;\nSELECT ").unwrap();
        assert_eq!(
            framer.push(b"2\0;"),
            Err(FrameError::NulByte { line: 2, column: 9 })
        );
    }

    #[test]
    fn statement_too_large() {
        let mut framer = StatementFramer::new(16);
        // exactly at the limit is fine as long as it terminates
        assert_eq!(framer.push(b"SELECT 1234567;").unwrap().len(), 1);
        // a pending statement longer than the limit is rejected at the start position
        framer.push(b"\n").unwrap();
        assert_eq!(
            framer.push(b"SELECT 'this is too long"),
            Err(FrameError::StatementTooLarge {
                line: 1,
                column: 16,
                limit: 16
            })
        );
        // a terminated statement longer than the limit arriving in one chunk is accepted:
        // it never needs to be buffered unterminated
        let mut framer = StatementFramer::new(16);
        assert_eq!(
            framer
                .push(b"SELECT 'this is longer than sixteen bytes';")
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn position_tracking() {
        let input =
            "PRAGMA x;\n\nBEGIN;\n  INSERT INTO t\n  VALUES(1); INSERT INTO t VALUES(2);\nCOMMIT;";
        let (frames, tail) = frame_all(input.as_bytes(), 3);
        let positions: Vec<_> = frames.iter().map(|f| (f.line, f.column)).collect();
        assert_eq!(
            positions,
            vec![(1, 1), (1, 10), (3, 7), (5, 13), (5, 38)],
            "{:?}",
            sqls(&frames)
        );
        assert_eq!(tail, None);
    }

    #[test]
    fn absolute_position_mapping() {
        // Worked example from the design doc: the frame starts right after the `;` on line 5,
        // column 32; the parser reports (3, 11) relative to the frame.
        assert_eq!(absolute_position((5, 33), (3, 11)), (7, 11));
        // Error on the frame's first line: columns add up.
        assert_eq!(absolute_position((5, 33), (1, 4)), (5, 36));
        assert_eq!(absolute_position((1, 1), (1, 1)), (1, 1));
    }

    #[test]
    fn completeness_oracle() {
        fn complete(s: &str) -> bool {
            let mut buf = s.as_bytes().to_vec();
            let end = buf.len() - 1;
            is_complete_statement(&mut buf, 0, end)
        }
        assert!(complete("SELECT 1;"));
        assert!(complete(";"));
        assert!(complete(" \n ;"));
        assert!(complete("PRAGMA foreign_keys=OFF;"));
        assert!(complete("EXPLAIN SELECT 1;"));
        assert!(complete("SELECT 'a;b';"));
        assert!(complete("/* a; */ SELECT 1;"));
        assert!(complete("-- c;\nSELECT 1;"));
        assert!(complete(
            "CREATE TRIGGER t AFTER INSERT ON x BEGIN SELECT 1; END;"
        ));
        assert!(!complete("SELECT ';"));
        assert!(!complete("-- c;"));
        assert!(!complete(
            "CREATE TRIGGER t AFTER INSERT ON x BEGIN SELECT 1;"
        ));
        assert!(!complete(
            "CREATE TEMP TRIGGER t AFTER INSERT ON x BEGIN SELECT 1;"
        ));

        // the oracle only looks at `buf[start..=end]`
        let mut buf = b"SELECT 1;SELECT ';".to_vec();
        assert!(is_complete_statement(&mut buf, 0, 8));
        assert!(!is_complete_statement(&mut buf, 9, 17));
        assert_eq!(buf, b"SELECT 1;SELECT ';");
    }
}
