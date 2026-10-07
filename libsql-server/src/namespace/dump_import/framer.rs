//! Incremental SQL statement framing (see `docs/STREAMING_DUMP_IMPORT_DESIGN.md` §7).

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
