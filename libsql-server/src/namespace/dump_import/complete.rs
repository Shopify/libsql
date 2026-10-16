//! Resumable port of SQLite's `sqlite3_complete()` (complete.c).
//!
//! `sqlite3_complete()` decides whether a string "appears to be a complete SQL statement": it
//! ends with a `;` token that is not inside a string, quoted identifier or comment, and is not
//! the interior of a `CREATE [TEMP] TRIGGER ... BEGIN ... END;` body. The C function tokenizes its
//! whole input on every call and has no resumable form, so calling it once per candidate `;`
//! of a growing statement is quadratic. [`CompletionScanner`] keeps the tokenizer and state
//! machine state across calls instead, so a dump is scanned exactly once.
//!
//! The token classes, keyword detection, comment/quote/bracket handling and the transition
//! table are copied from complete.c; `find_statement_end` must agree with
//! `sqlite3_complete(&buf[start..=semicolon])` for every candidate `;` (see the differential
//! test in `framer.rs`).

// Token classes (indices into TRANS rows).
const SEMI: usize = 0;
const WS: usize = 1;
const OTHER: usize = 2;
const EXPLAIN: usize = 3;
const CREATE: usize = 4;
const TEMP: usize = 5;
const TRIGGER: usize = 6;
const END: usize = 7;

/// `START`: at the beginning or end of a statement. The scanner reports a terminating `;` when
/// the transition on it lands here.
const STATE_START: u8 = 1;

/// Transition table from complete.c (states: 0 INVALID, 1 START, 2 NORMAL, 3 EXPLAIN,
/// 4 CREATE, 5 TRIGGER, 6 SEMI, 7 END).
const TRANS: [[u8; 8]; 8] = [
    //  SEMI WS OTHER EXPLAIN CREATE TEMP TRIGGER END
    [1, 0, 2, 3, 4, 2, 2, 2], // 0 INVALID
    [1, 1, 2, 3, 4, 2, 2, 2], // 1 START
    [1, 2, 2, 2, 2, 2, 2, 2], // 2 NORMAL
    [1, 3, 3, 2, 4, 2, 2, 2], // 3 EXPLAIN
    [1, 4, 2, 2, 2, 4, 5, 2], // 4 CREATE
    [6, 5, 5, 5, 5, 5, 5, 5], // 5 TRIGGER
    [6, 6, 5, 5, 5, 5, 5, 7], // 6 SEMI
    [1, 7, 5, 5, 5, 5, 5, 5], // 7 END
];

/// Longest keyword the state machine cares about (`temporary`).
const MAX_KEYWORD_LEN: usize = 9;

/// Where the tokenizer is inside a multi-byte construct that may span chunk boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lex {
    Normal,
    /// Saw `/`; a following `*` opens a block comment, anything else makes `/` an OTHER token.
    Slash,
    /// Saw `-`; a following `-` opens a line comment, anything else makes `-` an OTHER token.
    Dash,
    /// Inside `-- ...`, until `\n`.
    LineComment,
    /// Inside `/* ... */`.
    BlockComment,
    /// Inside a block comment, just saw `*`.
    BlockCommentStar,
    /// Inside `[...]`.
    Bracket,
    /// Inside a quoted string/identifier delimited by this byte (`'`, `"` or `` ` ``).
    Quote(u8),
    /// Inside an identifier/keyword run.
    Ident,
}

#[derive(Debug, Clone)]
pub(super) struct CompletionScanner {
    state: u8,
    lex: Lex,
    /// Bytes of the identifier being scanned, only kept while it could still be a keyword.
    ident: [u8; MAX_KEYWORD_LEN],
    /// Length of the current identifier; `MAX_KEYWORD_LEN + 1` once it is too long to be a
    /// keyword.
    ident_len: usize,
}

impl Default for CompletionScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl CompletionScanner {
    pub fn new() -> Self {
        Self {
            state: 0,
            lex: Lex::Normal,
            ident: [0; MAX_KEYWORD_LEN],
            ident_len: 0,
        }
    }

    /// Consume `bytes`. If a `;` that completes a statement is found, stop right after it and
    /// return its index within `bytes`; the scanner is then positioned at the start of the next
    /// statement and the caller must continue with `bytes[index + 1..]`. Otherwise all of
    /// `bytes` is consumed and `None` is returned.
    pub fn find_statement_end(&mut self, bytes: &[u8]) -> Option<usize> {
        for (i, &b) in bytes.iter().enumerate() {
            if self.step(b) {
                return Some(i);
            }
        }
        None
    }

    /// Feed one byte. Returns `true` iff `b` is a `;` that completes a statement.
    fn step(&mut self, b: u8) -> bool {
        loop {
            match self.lex {
                Lex::Ident => {
                    if is_id_char(b) {
                        self.push_ident(b);
                        return false;
                    }
                    self.flush_ident();
                    // fall through: `b` still has to be processed in the Normal state
                }
                Lex::Slash => {
                    self.lex = Lex::Normal;
                    if b == b'*' {
                        self.lex = Lex::BlockComment;
                        return false;
                    }
                    self.transition(OTHER);
                    // reprocess `b`
                }
                Lex::Dash => {
                    self.lex = Lex::Normal;
                    if b == b'-' {
                        self.lex = Lex::LineComment;
                        return false;
                    }
                    self.transition(OTHER);
                    // reprocess `b`
                }
                Lex::LineComment => {
                    if b == b'\n' {
                        self.lex = Lex::Normal;
                        self.transition(WS);
                    }
                    return false;
                }
                Lex::BlockComment => {
                    if b == b'*' {
                        self.lex = Lex::BlockCommentStar;
                    }
                    return false;
                }
                Lex::BlockCommentStar => {
                    if b == b'/' {
                        self.lex = Lex::Normal;
                        self.transition(WS);
                    } else if b != b'*' {
                        self.lex = Lex::BlockComment;
                    }
                    return false;
                }
                Lex::Bracket => {
                    if b == b']' {
                        self.lex = Lex::Normal;
                        self.transition(OTHER);
                    }
                    return false;
                }
                Lex::Quote(q) => {
                    if b == q {
                        self.lex = Lex::Normal;
                        self.transition(OTHER);
                    }
                    return false;
                }
                Lex::Normal => {
                    return match b {
                        b';' => {
                            self.transition(SEMI);
                            self.state == STATE_START
                        }
                        b' ' | b'\r' | b'\t' | b'\n' | 0x0c => {
                            self.transition(WS);
                            false
                        }
                        b'/' => {
                            self.lex = Lex::Slash;
                            false
                        }
                        b'-' => {
                            self.lex = Lex::Dash;
                            false
                        }
                        b'[' => {
                            self.lex = Lex::Bracket;
                            false
                        }
                        b'`' | b'"' | b'\'' => {
                            self.lex = Lex::Quote(b);
                            false
                        }
                        c if is_id_char(c) => {
                            self.lex = Lex::Ident;
                            self.ident_len = 0;
                            self.push_ident(c);
                            false
                        }
                        _ => {
                            self.transition(OTHER);
                            false
                        }
                    };
                }
            }
        }
    }

    fn transition(&mut self, token: usize) {
        self.state = TRANS[self.state as usize][token];
    }

    fn push_ident(&mut self, b: u8) {
        if self.ident_len < MAX_KEYWORD_LEN {
            self.ident[self.ident_len] = b;
            self.ident_len += 1;
        } else {
            self.ident_len = MAX_KEYWORD_LEN + 1;
        }
    }

    fn flush_ident(&mut self) {
        let token = if self.ident_len <= MAX_KEYWORD_LEN {
            classify_keyword(&self.ident[..self.ident_len])
        } else {
            OTHER
        };
        self.ident_len = 0;
        self.lex = Lex::Normal;
        self.transition(token);
    }
}

/// `IdChar()` from tokenize.c: alphanumerics, `_`, `$` and every non-ASCII byte.
#[inline]
fn is_id_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$' || b >= 0x80
}

fn classify_keyword(ident: &[u8]) -> usize {
    if ident.eq_ignore_ascii_case(b"create") {
        CREATE
    } else if ident.eq_ignore_ascii_case(b"trigger") {
        TRIGGER
    } else if ident.eq_ignore_ascii_case(b"temp") || ident.eq_ignore_ascii_case(b"temporary") {
        TEMP
    } else if ident.eq_ignore_ascii_case(b"end") {
        END
    } else if ident.eq_ignore_ascii_case(b"explain") {
        EXPLAIN
    } else {
        OTHER
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// Feed `sql` and report whether its final byte is a terminating `;` (and nothing earlier
    /// was): the single-statement question `sqlite3_complete` answers.
    fn complete(sql: &str) -> bool {
        let mut s = CompletionScanner::new();
        match s.find_statement_end(sql.as_bytes()) {
            Some(i) => i + 1 == sql.len(),
            None => false,
        }
    }

    #[test]
    fn mirrors_sqlite3_complete_on_known_inputs() {
        for ok in [
            "SELECT 1;",
            ";",
            " \n ;",
            "PRAGMA foreign_keys=OFF;",
            "EXPLAIN SELECT 1;",
            "SELECT 'a;b';",
            "SELECT \"a;b\";",
            "SELECT [a;b];",
            "SELECT `a;b`;",
            "CREATE TABLE t(x CHECK(x <> ';'));",
            "INSERT INTO t VALUES(X'00ff');",
            "/* a; */ SELECT 1;",
            "-- c;\nSELECT 1;",
            "CREATE TRIGGER t AFTER INSERT ON x BEGIN SELECT 1; END;",
            "create temp trigger t after insert on x begin select 1; end;",
            "CREATE TEMPORARY TRIGGER t AFTER INSERT ON x BEGIN SELECT 1; UPDATE y SET z = 1; END;",
            "EXPLAIN CREATE TRIGGER t AFTER INSERT ON x BEGIN SELECT 1; END;",
            // CASE ... END inside the body does not end the trigger (END must follow a `;`)
            "CREATE TRIGGER t AFTER INSERT ON x BEGIN UPDATE y SET z = CASE WHEN 1 THEN 1 END; END;",
            // a trigger body statement ending in END right before `;` still needs ;END;
            "CREATE TRIGGER t AFTER INSERT ON x BEGIN SELECT CASE WHEN 1 THEN 1 END; END;",
            // `END` is only special in a trigger
            "SELECT CASE WHEN 1 THEN 1 END;",
            "CREATE TABLE end(x);",
            "CREATE TABLE trigger_log(x);",
            "/**/SELECT 1;",
            "/* ** */SELECT 1;",
            "SELECT 1 -- trailing\n;",
            "SELECT 1/2;",
            "SELECT 1-2;",
        ] {
            assert!(complete(ok), "expected complete: {ok:?}");
        }
        for not in [
            "SELECT ';",
            "SELECT \";",
            "SELECT [;",
            "-- c;",
            "/* c;",
            "/* c; *",
            "/*/ c;",
            "COMMIT",
            "CREATE TRIGGER t AFTER INSERT ON x BEGIN SELECT 1;",
            "CREATE TEMP TRIGGER t AFTER INSERT ON x BEGIN SELECT 1;",
            "CREATE TRIGGER t AFTER INSERT ON x BEGIN SELECT 1; END",
            "CREATE TRIGGER t AFTER INSERT ON x BEGIN SELECT 1; END x;",
            "SELECT 1;SELECT 2;", // two statements: the first `;` terminates
        ] {
            assert!(!complete(not), "expected incomplete: {not:?}");
        }
    }

    #[test]
    fn resumes_across_arbitrary_splits() {
        let sql = "CREATE TRIGGER t AFTER INSERT ON x BEGIN /* ; */ SELECT 'a;b' -- ;\n; END; -- done\nSELECT 1;";
        let ends: Vec<usize> = sql
            .bytes()
            .enumerate()
            .filter(|(_, b)| *b == b';')
            .map(|(i, _)| i)
            .collect();
        // semicolons: block comment, string, line comment, body statement, "END;", "SELECT 1;"
        assert_eq!(ends.len(), 6);
        let expected = vec![ends[4], ends[5]];
        for chunk in 1..=sql.len() {
            let mut s = CompletionScanner::new();
            let mut found = Vec::new();
            let mut offset = 0;
            for piece in sql.as_bytes().chunks(chunk) {
                let mut from = 0;
                while let Some(i) = s.find_statement_end(&piece[from..]) {
                    found.push(offset + from + i);
                    from += i + 1;
                }
                offset += piece.len();
            }
            assert_eq!(found, expected, "chunk size {chunk}");
        }
    }

    #[test]
    fn identifier_classification() {
        assert_eq!(classify_keyword(b"CREATE"), CREATE);
        assert_eq!(classify_keyword(b"Trigger"), TRIGGER);
        assert_eq!(classify_keyword(b"temp"), TEMP);
        assert_eq!(classify_keyword(b"TEMPORARY"), TEMP);
        assert_eq!(classify_keyword(b"end"), END);
        assert_eq!(classify_keyword(b"explain"), EXPLAIN);
        assert_eq!(classify_keyword(b"ends"), OTHER);
        assert_eq!(classify_keyword(b"temporarily"), OTHER);
        assert_eq!(classify_keyword(b""), OTHER);
        assert!(is_id_char(b'$') && is_id_char(b'_') && is_id_char(0xc3) && is_id_char(b'9'));
        assert!(!is_id_char(b';') && !is_id_char(b' ') && !is_id_char(0x0b));
    }
}
