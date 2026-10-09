//! Incremental SQL statement framing.
//!
//! [`StatementFramer`] turns an arbitrary sequence of byte chunks into complete SQL statements,
//! each ending at the `;` that terminates it, while only ever holding one unfinished statement
//! in memory. Statement boundaries follow the rules of SQLite's `sqlite3_complete()` (via the
//! resumable port in [`super::complete`]), so semicolons inside string literals, quoted
//! identifiers, comments and `CREATE TRIGGER ... END` bodies are handled exactly like the
//! `sqlite3` shell does, in a single linear pass over the dump.
//!
//! See `docs/STREAMING_DUMP_IMPORT_DESIGN.md` §7.

use memchr::{memchr, memchr_iter, memrchr};

use super::complete::CompletionScanner;

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
    /// The statement starting at `(line, column)` is larger than the configured limit (or grew
    /// past it without terminating).
    StatementTooLarge {
        line: u64,
        column: usize,
        limit: usize,
    },
}

/// Frames at least this large are handed over without copying (see `push`).
const LARGE_FRAME_BYTES: usize = 1024 * 1024;

pub(super) struct StatementFramer {
    /// Bytes after the last emitted frame; starts with the next statement's leading
    /// whitespace/comments.
    buf: Vec<u8>,
    /// Number of leading bytes of `buf` the scanner has already consumed.
    fed: usize,
    scanner: CompletionScanner,
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
            fed: 0,
            scanner: CompletionScanner::new(),
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
        // `start` is the offset in `buf` of the statement being scanned; frames before it are
        // removed from `buf` in one `drain` at the end rather than one per frame.
        let mut start = 0;
        while let Some(rel) = self.scanner.find_statement_end(&self.buf[self.fed..]) {
            let end = self.fed + rel;
            self.fed = end + 1;
            let len = end + 1 - start;
            if len > self.max_statement_bytes {
                return Err(self.too_large(&self.buf[start..=end]));
            }
            let (line, column) = (self.line, self.column);
            (self.line, self.column) = advance_position((line, column), &self.buf[start..=end]);
            let sql = if start == 0 && len >= LARGE_FRAME_BYTES {
                // A statement that spanned several pushes always starts at 0 (everything before
                // it was drained by an earlier push). Hand its buffer over instead of copying it,
                // so the peak is one copy of the largest statement, not two.
                let rest = self.buf.split_off(end + 1);
                self.fed -= end + 1;
                std::mem::replace(&mut self.buf, rest)
            } else {
                start = end + 1;
                self.buf[start - len..start].to_vec()
            };
            frames.push(Frame { sql, line, column });
        }
        // Everything in `buf` has now been fed to the scanner exactly once.
        self.fed = self.buf.len();

        if start > 0 {
            self.buf.drain(..start);
            self.fed -= start;
        }

        if self.buf.len() > self.max_statement_bytes {
            return Err(self.too_large(&self.buf));
        }

        Ok(frames)
    }

    /// `pending` starts at the framer's current position; report the statement's first
    /// non-whitespace byte so the message points at the statement rather than at the end of
    /// the previous line.
    fn too_large(&self, pending: &[u8]) -> FrameError {
        let (line, column) = statement_start((self.line, self.column), pending);
        FrameError::StatementTooLarge {
            line,
            column,
            limit: self.max_statement_bytes,
        }
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
        self.fed = 0;
        (self.line, self.column) = advance_position((self.line, self.column), &frame.sql);
        Some(frame)
    }
}

/// Position of the byte following `bytes`, given the position of its first byte.
pub(super) fn advance_position((line, column): (u64, usize), bytes: &[u8]) -> (u64, usize) {
    match memrchr(b'\n', bytes) {
        Some(last) => (
            line + memchr_iter(b'\n', bytes).count() as u64,
            bytes.len() - last,
        ),
        None => (line, column + bytes.len()),
    }
}

/// Position of the first non-whitespace byte of `frame`, whose first byte is at `pos`.
pub(super) fn statement_start(pos: (u64, usize), frame: &[u8]) -> (u64, usize) {
    let ws = frame.iter().take_while(|b| b.is_ascii_whitespace()).count();
    advance_position(pos, &frame[..ws])
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
        // a pending statement longer than the limit is rejected; the position points at the
        // statement itself, not at the whitespace that precedes it
        framer.push(b"\n").unwrap();
        assert_eq!(
            framer.push(b"SELECT 'this is too long"),
            Err(FrameError::StatementTooLarge {
                line: 2,
                column: 1,
                limit: 16
            })
        );
        // a terminated statement longer than the limit is rejected too, even when it arrives
        // in one chunk
        let mut framer = StatementFramer::new(16);
        assert_eq!(framer.push(b"SELECT 1;\n").unwrap().len(), 1);
        assert_eq!(
            framer.push(b"  SELECT 'this is longer than sixteen bytes';"),
            Err(FrameError::StatementTooLarge {
                line: 2,
                column: 3,
                limit: 16
            })
        );
    }

    #[test]
    fn statement_start_skips_leading_whitespace() {
        assert_eq!(statement_start((5, 33), b"\n    SELECT 1;"), (6, 5));
        assert_eq!(statement_start((5, 33), b"SELECT 1;"), (5, 33));
        assert_eq!(statement_start((5, 33), b"  \n"), (6, 1));
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

    /// The reference: SQLite's own `sqlite3_complete()` applied to `buf[start..=end]` for every
    /// candidate `;`, i.e. the quadratic algorithm the resumable scanner replaces.
    fn reference_frames(input: &[u8]) -> Vec<Vec<u8>> {
        use std::ffi::{c_char, CString};
        let mut frames = Vec::new();
        let mut start = 0;
        for end in memchr_iter(b';', input) {
            let candidate = CString::new(&input[start..=end]).unwrap();
            // SAFETY: `candidate` is a valid NUL-terminated string that outlives the call.
            let complete =
                unsafe { rusqlite::ffi::sqlite3_complete(candidate.as_ptr() as *const c_char) };
            if complete != 0 {
                frames.push(input[start..=end].to_vec());
                start = end + 1;
            }
        }
        frames
    }

    /// Tiny deterministic PRNG so the differential test needs no extra dependencies.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0 >> 33
        }
        fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
            &items[(self.next() as usize) % items.len()]
        }
    }

    /// Differential test: frame boundaries must match `sqlite3_complete` for random token soups
    /// built from everything the state machine cares about, under every chunking.
    #[test]
    fn framing_matches_sqlite3_complete() {
        const PIECES: &[&str] = &[
            ";",
            ";",
            ";",
            " ",
            "\n",
            "\t",
            "\r",
            "\x0c",
            "\x0b",
            "/",
            "*",
            "-",
            "--",
            "/*",
            "*/",
            "[",
            "]",
            "'",
            "\"",
            "`",
            "''",
            "CREATE",
            "create",
            "TEMP",
            "Temporary",
            "TRIGGER",
            "END",
            "end",
            "EXPLAIN",
            "BEGIN",
            "SELECT",
            "x",
            "1",
            "_a",
            "$b",
            "ends",
            "temps",
            "\u{17c}",
            "é",
            "(",
            ")",
            ",",
            "=",
            "+",
            ".",
            "CASE",
            "WHEN",
            "THEN",
        ];
        let mut rng = Lcg(0x5eed);
        for case in 0..2000 {
            let n = 1 + (rng.next() as usize) % 40;
            let mut input = String::new();
            for _ in 0..n {
                input.push_str(rng.pick(PIECES));
            }
            // make sure something terminates so the interesting path is exercised often
            if case % 2 == 0 {
                input.push(';');
            }
            let bytes = input.as_bytes();
            let expected = reference_frames(bytes);
            for chunk in [1usize, 2, 3, 7, bytes.len().max(1)] {
                let mut framer = StatementFramer::new(LIMIT);
                let mut got = Vec::new();
                for piece in bytes.chunks(chunk) {
                    got.extend(framer.push(piece).unwrap().into_iter().map(|f| f.sql));
                }
                assert_eq!(got, expected, "input {input:?} chunk {chunk}");
            }
        }
    }

    /// A statement full of interior semicolons is scanned once, not once per semicolon.
    #[test]
    fn semicolon_dense_statement_is_linear() {
        let semis = 200_000;
        let mut s = String::from("INSERT INTO t VALUES('");
        for _ in 0..semis {
            s.push_str("abc;");
        }
        s.push_str("');");
        let mut framer = StatementFramer::new(1 << 30);
        let started = std::time::Instant::now();
        let mut frames = 0;
        for chunk in s.as_bytes().chunks(64 * 1024) {
            frames += framer.push(chunk).unwrap().len();
        }
        assert_eq!(frames, 1);
        // ~800 KB; the quadratic version needed tens of seconds for this shape.
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "framing took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn large_frames_are_handed_over_without_copy() {
        let big = format!("INSERT INTO t VALUES('{}');", "x".repeat(LARGE_FRAME_BYTES));
        let mut framer = StatementFramer::new(1 << 30);
        let mut frames = Vec::new();
        for chunk in big.as_bytes().chunks(64 * 1024) {
            frames.extend(framer.push(chunk).unwrap());
        }
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].sql, big.as_bytes());
        // the pending buffer was replaced, not drained in place
        assert!(framer.buf.capacity() < LARGE_FRAME_BYTES);
        // and framing continues correctly afterwards
        assert_eq!(framer.push(b"SELECT 1;").unwrap().len(), 1);
        assert_eq!(framer.push(b"-- tail").unwrap().len(), 0);
        assert_eq!(framer.finish().unwrap().sql, b"-- tail");
    }
}
