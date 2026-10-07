//! Memory-bounded dump importer (see `docs/STREAMING_DUMP_IMPORT_DESIGN.md` §8–9).

use crate::database::PrimaryConnection;
use crate::error::LoadDumpError;
use crate::namespace::DumpStream;

use super::{DumpImportConfig, DumpImportStats};

pub(super) async fn load_dump_streaming(
    _stream: DumpStream,
    _conn: PrimaryConnection,
    _cfg: &DumpImportConfig,
) -> Result<DumpImportStats, LoadDumpError> {
    Err(LoadDumpError::Internal(
        "streaming dump importer is not available".to_string(),
    ))
}
