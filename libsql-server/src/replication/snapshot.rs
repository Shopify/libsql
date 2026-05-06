use std::collections::HashSet;
use std::io::SeekFrom;
use std::mem::size_of;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use anyhow::{bail, Context};
use futures::TryStreamExt;
use libsql_replication::frame::FrameMut;
use libsql_replication::snapshot::{SnapshotFile, SnapshotFileHeader};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_stream::{Stream, StreamExt};
use tokio_util::sync::ReusableBoxFuture;
use uuid::Uuid;
use zerocopy::AsBytes;

use crate::namespace::NamespaceName;
use crate::replication::primary::logger::LogFileHeader;

use super::primary::logger::{FrameEncryptor, LogFile};
use super::script_backup_manager::ScriptBackupManager;
use super::FrameNo;

/// This is the ratio of the space required to store snapshot vs size of the actual database.
/// When this ratio is exceeded, compaction is triggered.
///
/// Used only when `SQLD_MAX_SNAPSHOT_SIZE` is unset (legacy behavior).
const SNAPHOT_SPACE_AMPLIFICATION_FACTOR: u64 = 2;
/// The default maximum number of snapshot files allowed before a compaction is required.
/// Overridable via `SQLD_MAX_SNAPSHOT_COUNT`.
const MAX_SNAPSHOT_NUMBER: usize = 32;

/// Group an ordered list of accumulated snapshots into contiguous batches for merging,
/// ensuring no batch's cumulative frame count exceeds `max_frames`.
///
/// Returns ranges into `snapshots`. With `max_frames = None`, returns a single range
/// covering the whole input (legacy single-file merge). An input snapshot whose own
/// frame count is already strictly larger than `max_frames` is placed in a singleton
/// batch so the merger can leave it as-is rather than produce an even larger file.
///
/// Both bound checks use the same comparator (`>`) for symmetry: a snapshot whose count
/// equals `max_frames` exactly is allowed to fill a batch by itself but is not flagged as
/// oversized.
fn group_snapshots_for_merge(
    snapshots: &[(String, u64)],
    max_frames: Option<u64>,
) -> Vec<Range<usize>> {
    if snapshots.is_empty() {
        return Vec::new();
    }
    let Some(max) = max_frames else {
        return vec![0..snapshots.len()];
    };

    let mut batches: Vec<Range<usize>> = Vec::new();
    let mut start = 0usize;
    let mut acc: u64 = 0;
    for (i, (_, count)) in snapshots.iter().enumerate() {
        // Pre-existing oversized file: flush any pending batch and emit this one as its
        // own singleton so the merger leaves it untouched.
        if *count > max {
            if i > start {
                batches.push(start..i);
            }
            batches.push(i..i + 1);
            start = i + 1;
            acc = 0;
            continue;
        }
        if acc.saturating_add(*count) > max && i > start {
            batches.push(start..i);
            start = i;
            acc = 0;
        }
        acc = acc.saturating_add(*count);
    }
    if start < snapshots.len() {
        batches.push(start..snapshots.len());
    }
    batches
}

/// Returns true iff at least one batch in the proposed grouping would actually combine
/// 2+ input files. When false, running the merger is a no-op (every batch is a
/// passthrough singleton) and `should_compact` must return false to avoid spinning a hot
/// merge loop on every snapshot registration.
fn merge_makes_progress(batches: &[Range<usize>]) -> bool {
    batches.iter().any(|b| b.end - b.start > 1)
}

/// Read `SQLD_MAX_SNAPSHOT_SIZE` (in MB) and convert to a frame count. Mirrors the unit
/// convention in `replication/primary/logger.rs:max_log_frame_count` (decimal MB,
/// `mb * 1_000_000 / FRAME_SIZE`). Returns `None` on unset, empty, unparseable,
/// zero, or arithmetic overflow — in all those cases the merger falls back to legacy
/// behavior rather than picking a pathologically small cap.
///
/// `OnceLock`-cached for the lifetime of the process: changing the env var after the
/// first read has no effect (no SIGHUP-style reload).
fn read_max_snapshot_frames_from_env() -> Option<u64> {
    static CACHED: OnceLock<Option<u64>> = OnceLock::new();
    *CACHED.get_or_init(|| {
        parse_max_snapshot_frames(std::env::var("SQLD_MAX_SNAPSHOT_SIZE").ok().as_deref())
    })
}

fn parse_max_snapshot_frames(raw: Option<&str>) -> Option<u64> {
    let mb = raw?.parse::<u64>().ok()?;
    if mb == 0 {
        return None;
    }
    let bytes = mb.checked_mul(1_000_000)?;
    Some(bytes / LogFile::FRAME_SIZE as u64)
}

/// Read `SQLD_MAX_SNAPSHOT_COUNT`; falls back to `MAX_SNAPSHOT_NUMBER` (32) when unset.
///
/// When pairing a low `SQLD_MAX_SNAPSHOT_SIZE` with a low `SQLD_MAX_LOG_SIZE` (so that
/// each `.snap` file stays small on disk), this count needs to be raised in lockstep,
/// otherwise the count-trigger fires and undoes the chunking by merging many small files
/// into one large one. Lower bounds an operator should respect:
///
///   SQLD_MAX_SNAPSHOT_COUNT >= expected_total_snapshot_bytes / SQLD_MAX_LOG_SIZE
///   SQLD_MAX_SNAPSHOT_COUNT >= expected_total_snapshot_bytes / SQLD_MAX_SNAPSHOT_SIZE
///
/// (the latter because the count is checked post-merge too: a successful chunked merge
/// produces about `total / cap` files).
fn read_max_snapshot_count_from_env() -> usize {
    static CACHED: OnceLock<usize> = OnceLock::new();
    *CACHED.get_or_init(|| {
        std::env::var("SQLD_MAX_SNAPSHOT_COUNT")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(MAX_SNAPSHOT_NUMBER)
    })
}

/// returns (db_id, start_frame_no, end_frame_no) for the given snapshot name
fn parse_snapshot_name(name: &str) -> Option<(Uuid, u64, u64)> {
    let (db_id_str, remaining) = name.split_at(36);
    let mut split = remaining.split("-");
    split.next()?;
    let start_index: u64 = split.next()?.parse().ok()?;
    let end_index: u64 = split.next()?.trim_end_matches(".snap").parse().ok()?;

    Some((Uuid::from_str(db_id_str).ok()?, start_index, end_index))
}

fn snapshot_list(db_path: &Path) -> impl Stream<Item = anyhow::Result<String>> + '_ {
    async_stream::try_stream! {
        let mut entries = tokio::fs::read_dir(snapshot_dir_path(db_path)).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let Some(name) = path.file_name() else {
                continue;
            };
            let Some(name_str) = name.to_str() else {
                continue;
            };

            yield name_str.to_string();
        }
    }
}

/// Return snapshot file containing "logically" frame_no
pub async fn find_snapshot_file(
    db_path: &Path,
    frame_no: FrameNo,
    encryptor: Option<FrameEncryptor>,
) -> anyhow::Result<Option<SnapshotFile>> {
    let snapshot_dir_path = snapshot_dir_path(db_path);
    let snapshots = snapshot_list(db_path);
    tokio::pin!(snapshots);
    while let Some(name) = snapshots.next().await.transpose()? {
        let Some((_, start_frame_no, end_frame_no)) = parse_snapshot_name(&name) else {
            continue;
        };
        // we're looking for the frame right after the last applied frame on the replica
        if (start_frame_no..=end_frame_no).contains(&frame_no) {
            let snapshot_path = snapshot_dir_path.join(&name);
            tracing::debug!("found snapshot for frame {frame_no} at {snapshot_path:?}");
            let snapshot_file = SnapshotFile::open(&snapshot_path, encryptor).await?;
            return Ok(Some(snapshot_file));
        }
    }

    Ok(None)
}

#[derive(Clone, Debug)]
pub struct LogCompactor {
    sender: mpsc::Sender<(LogFile, PathBuf)>,
}

async fn compact(
    db_path: &Path,
    to_compact_file: LogFile,
    log_id: Uuid,
    merger: &mut SnapshotMerger,
    to_compact_path: &Path,
    scripted_backup: Option<ScriptBackupManager>,
    namespace: NamespaceName,
) -> anyhow::Result<()> {
    let before = Instant::now();
    match perform_compaction(db_path, to_compact_file, log_id, namespace, scripted_backup).await {
        Ok((snapshot_name, snapshot_frame_count, size_after)) => {
            tracing::info!(
                "snapshot `{snapshot_name}` successfully created, in {:?}",
                before.elapsed()
            );

            if let Err(e) = merger
                .register_snapshot(snapshot_name, snapshot_frame_count, size_after)
                .await
            {
                bail!("failed to register snapshot with snapshot merger: {e}");
            }

            if let Err(e) = std::fs::remove_file(to_compact_path) {
                bail!("failed to remove old log file `{to_compact_path:?}`: {e}",);
            }
        }
        Err(e) => {
            bail!("fatal error creating snapshot: {e}");
        }
    }

    Ok(())
}

/// Returns a list of pending snapshots to compact by reading the `to_compact` directory. Those
/// snapshots should be processed before any other.
fn pending_snapshots_list(compact_queue_dir: &Path) -> anyhow::Result<Vec<(LogFile, PathBuf)>> {
    let dir = std::fs::read_dir(compact_queue_dir)?;
    let mut to_compact = Vec::new();
    for entry in dir {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            let to_compact_path = entry.path();
            let file = std::fs::File::open(&to_compact_path)?;
            let size = file.metadata()?.len();
            // ignore empty log files
            if size == size_of::<LogFileHeader>() as u64 {
                if let Err(e) = std::fs::remove_file(&to_compact_path) {
                    tracing::warn!("failed to remove empty pending log: {e}");
                }
                continue;
            }
            // max log duration and frame number don't  matter, we compact the file and discard it
            // immediately.
            let to_compact_file = LogFile::new(file, u64::MAX, None, None)?;
            to_compact.push((to_compact_file, to_compact_path));
        }
    }

    // sort the logs by start frame_no, so that they are registered with the merger in the right
    // order.
    to_compact.sort_unstable_by_key(|(log, _)| log.header().start_frame_no.get());

    Ok(to_compact)
}

impl LogCompactor {
    pub(crate) fn new(
        db_path: &Path,
        log_id: Uuid,
        scripted_backup: Option<ScriptBackupManager>,
        namespace: NamespaceName,
    ) -> anyhow::Result<Self> {
        tracing::debug!("creating new log compactor");
        // a directory containing logs that need compaction
        let compact_queue_dir = db_path.join("to_compact");
        std::fs::create_dir_all(&compact_queue_dir)?;

        // setup the tmp dir
        let tmp_path = db_path.join("tmp");
        if tmp_path.try_exists()? {
            std::fs::remove_dir_all(&tmp_path)?;
        }
        std::fs::create_dir_all(&tmp_path)?;

        let (sender, mut receiver) = mpsc::channel::<(LogFile, PathBuf)>(8);

        tracing::debug!("making snapshot merger");

        let mut merger =
            SnapshotMerger::new(db_path, log_id, scripted_backup.clone(), namespace.clone())?;
        let db_path = db_path.to_path_buf();

        tracing::debug!("gathering snapshots");

        // We gather pending snapshots here, so new snapshots don't interfere.
        let pending = pending_snapshots_list(&compact_queue_dir)?;
        // FIXME(marin): we somehow need to make this code more robust. How to deal with a
        // compaction error?
        tokio::task::spawn(async move {
            // process pending snapshots if any.
            for (to_compact_file, to_compact_path) in pending {
                if let Err(e) = compact(
                    &db_path,
                    to_compact_file,
                    log_id,
                    &mut merger,
                    &to_compact_path,
                    scripted_backup.clone(),
                    namespace.clone(),
                )
                .await
                {
                    tracing::error!("fatal error while compacting pending logs: {e}");
                    return;
                }
            }

            while let Some((to_compact_file, to_compact_path)) = receiver.recv().await {
                if let Err(e) = compact(
                    &db_path,
                    to_compact_file,
                    log_id,
                    &mut merger,
                    &to_compact_path,
                    scripted_backup.clone(),
                    namespace.clone(),
                )
                .await
                {
                    tracing::error!("fatal compactor error: {e}");
                    break;
                }
            }
        });

        tracing::debug!("completed log compactor creation");

        Ok(Self { sender })
    }

    /// Sends a compaction task to the background compaction thread. Blocks if a compaction task is
    /// already ongoing.
    pub fn compact(&self, file: LogFile, path: PathBuf) -> anyhow::Result<()> {
        self.sender
            .blocking_send((file, path))
            .context("failed to compact log: log compactor thread exited")?;

        Ok(())
    }
}

/// Snapshot policy: caps used by `should_compact` / `merge_snapshots`.
///
/// Carried as a struct so the merger does not depend on process-global state and so the
/// pure decision functions can be unit-tested with arbitrary values. The single env-read
/// happens in `SnapshotPolicy::from_env` at `SnapshotMerger::new` time.
#[derive(Clone, Copy, Debug)]
struct SnapshotPolicy {
    /// `Some(max_frames)` enforces the user-configured cap; `None` selects the legacy
    /// `SNAPHOT_SPACE_AMPLIFICATION_FACTOR * db_page_count` rule.
    max_frames: Option<u64>,
    /// File-count cap. Always >= 1.
    max_count: usize,
}

impl SnapshotPolicy {
    fn from_env() -> Self {
        Self {
            max_frames: read_max_snapshot_frames_from_env(),
            max_count: read_max_snapshot_count_from_env(),
        }
    }

    /// Decide whether to spawn a merge job for `snapshots`.
    ///
    /// Returns false when the merger has nothing actionable to do (every batch would be
    /// a passthrough singleton). Without this guard the merger spins a hot loop
    /// re-spawning no-op merge jobs on every snapshot registration once the working set
    /// crosses the cap.
    fn should_compact(&self, snapshots: &[(String, u64)], db_page_count: u32) -> bool {
        let snapshots_size: u64 = snapshots.iter().map(|(_, s)| *s).sum();
        let size_trigger = match self.max_frames {
            Some(max) => snapshots_size >= max,
            None => snapshots_size >= SNAPHOT_SPACE_AMPLIFICATION_FACTOR * db_page_count as u64,
        };
        let count_trigger = snapshots.len() > self.max_count;
        if !(size_trigger || count_trigger) {
            return false;
        }
        // No merge would actually combine anything (all singletons / oversized passthroughs).
        // Triggering anyway costs a tokio::spawn + N file opens per registration forever.
        let batches = group_snapshots_for_merge(snapshots, self.max_frames);
        merge_makes_progress(&batches)
    }
}

struct SnapshotMerger {
    /// Sending part of a channel of (snapshot_name, snapshot_frame_count, db_page_count) to the merger thread
    sender: mpsc::Sender<(String, u64, u32)>,
    handle: Option<tokio::task::JoinHandle<anyhow::Result<()>>>,
}

impl SnapshotMerger {
    fn new(
        db_path: &Path,
        log_id: Uuid,
        scripted_backup: Option<ScriptBackupManager>,
        namespace: NamespaceName,
    ) -> anyhow::Result<Self> {
        let (sender, receiver) = mpsc::channel(1);

        let db_path = db_path.to_path_buf();
        let policy = SnapshotPolicy::from_env();
        let handle = tokio::task::spawn(async move {
            Self::run_snapshot_merger_loop(
                receiver,
                &db_path,
                log_id,
                scripted_backup,
                namespace,
                policy,
            )
            .await
        });

        Ok(Self {
            sender,
            handle: Some(handle),
        })
    }

    async fn run_snapshot_merger_loop(
        mut receiver: mpsc::Receiver<(String, u64, u32)>,
        db_path: &Path,
        log_id: Uuid,
        scripted_backup: Option<ScriptBackupManager>,
        namespace: NamespaceName,
        policy: SnapshotPolicy,
    ) -> anyhow::Result<()> {
        let mut snapshots = Self::init_snapshot_info_list(db_path).await?;
        let mut working = false;
        let mut job = ReusableBoxFuture::<anyhow::Result<_>>::new(std::future::pending());
        let db_path: Arc<Path> = db_path.to_path_buf().into();
        loop {
            tokio::select! {
                Some((name, size, db_page_count)) = receiver.recv() => {
                    snapshots.push((name, size));
                    if !working && policy.should_compact(&snapshots, db_page_count) {
                        let snapshots = std::mem::take(&mut snapshots);
                        let db_path = db_path.clone();
                        let handle = tokio::spawn({
                            let scripted_backup = scripted_backup.clone();
                            let namespace = namespace.clone();
                            async move {
                                let compacted_snapshot_info =
                                    Self::merge_snapshots(snapshots, db_path.as_ref(), log_id, scripted_backup, namespace, policy.max_frames).await?;
                                anyhow::Result::<_, anyhow::Error>::Ok(compacted_snapshot_info)
                            }
                        });
                        job.set(async move { Ok(handle.await?) });
                        working = true;
                    }
                }
                ret = &mut job, if working => {
                    working = false;
                    job.set(std::future::pending());
                    let ret = ret??;
                    // The merged snapshot(s) cover the oldest frames. `merge_snapshots`
                    // returns them in chronological (oldest-first) order, and at this
                    // point any item still in `snapshots` arrived during the merge job
                    // (post `mem::take`) and is therefore strictly newer than every
                    // returned item. We prepend with `splice` (single shift, O(n)) instead
                    // of repeated `insert(i, _)` (O(n·k)).
                    debug_assert!(
                        ret.windows(2).all(|w| {
                            let a = parse_snapshot_name(&w[0].0).map(|(_, s, _)| s).unwrap_or(0);
                            let b = parse_snapshot_name(&w[1].0).map(|(_, s, _)| s).unwrap_or(u64::MAX);
                            a < b
                        }),
                        "merge_snapshots must return batches in ascending start_frame_no order"
                    );
                    snapshots.splice(0..0, ret);
                }
                else => return Ok(())
            }
        }
    }

    /// Reads the snapshot dir and returns the list of snapshots along with their size, sorted in
    /// chronological order.
    ///
    /// TODO: if the process was kill in the midst of merging snapshot, then the compacted snapshot
    /// can exist alongside the snapshots it's supposed to have compacted. This is the place to
    /// perform the cleanup.
    async fn init_snapshot_info_list(db_path: &Path) -> anyhow::Result<Vec<(String, u64)>> {
        let snapshot_dir_path = snapshot_dir_path(db_path);
        if !snapshot_dir_path.exists() {
            return Ok(Vec::new());
        }

        let mut temp = Vec::new();

        let snapshots = snapshot_list(db_path);
        tokio::pin!(snapshots);
        while let Some(snapshot_name) = snapshots.next().await.transpose()? {
            let snapshot_path = snapshot_dir_path.join(&snapshot_name);
            // NOTICE: no encryptor needed for reading unencrypted headers
            let snapshot = SnapshotFile::open(&snapshot_path, None).await?;
            temp.push((
                snapshot_name,
                snapshot.header().frame_count,
                snapshot.header().start_frame_no,
            ))
        }

        temp.sort_by_key(|(_, _, id)| id.get());

        Ok(temp
            .into_iter()
            .map(|(name, count, _)| (name, count.get()))
            .collect())
    }

    /// Merge accumulated snapshots according to the configured `max_frames` cap.
    ///
    /// **Returned ordering contract**: output is in chronological (oldest-first) order,
    /// and the start_frame_no of each returned item is strictly less than the next.
    /// `run_snapshot_merger_loop` relies on this to prepend the result with a single
    /// `splice` while preserving the global frame-no ordering. Do not reorder.
    ///
    /// **Failure semantics**: on per-batch I/O error, batches `0..K` have already merged
    /// successfully and their input files have been deleted from disk. The orphaned
    /// merged outputs for `0..K` and the un-merged inputs for `K+1..N` will be discovered
    /// and re-registered by `init_snapshot_info_list` on the next process restart. This
    /// matches upstream's pre-existing failure mode (single-file scope), just with a
    /// larger blast radius. Tracked separately; not addressed in this patch.
    async fn merge_snapshots(
        snapshots: Vec<(String, u64)>,
        db_path: &Path,
        log_id: Uuid,
        scripted_backup: Option<ScriptBackupManager>,
        namespace: NamespaceName,
        max_frames: Option<u64>,
    ) -> anyhow::Result<Vec<(String, u64)>> {
        // When `max_frames` is `Some`, group input snapshots greedily into batches whose
        // summed frame count fits under the cap. Each batch becomes one output `.snap`
        // file, ensuring no merger-produced file ever exceeds the cap. A batch of size 1
        // is left as-is (skip the merge copy). When `None`, fall back to the legacy
        // behavior: collapse everything into a single file.
        let batches = group_snapshots_for_merge(&snapshots, max_frames);
        tracing::debug!(
            "merging {} snapshots for {log_id} into {} batch(es) (max_frames={:?})",
            snapshots.len(),
            batches.len(),
            max_frames,
        );

        let snapshot_dir_path = snapshot_dir_path(db_path);
        let mut out: Vec<(String, u64)> = Vec::with_capacity(batches.len());
        for batch in batches {
            let batch = &snapshots[batch];
            if batch.len() == 1 {
                // Single oversized or stand-alone snapshot — leave it in place untouched
                // so that we never produce a merged file larger than the configured cap.
                out.push(batch[0].clone());
                continue;
            }

            let mut builder =
                SnapshotBuilder::new(db_path, log_id, scripted_backup.clone(), namespace.clone())
                    .await?;
            let mut size_after = None;
            for (name, _) in batch.iter().rev() {
                // NOTICE: no encryptor passed in order to read frames as is, still encrypted
                let snapshot = SnapshotFile::open(&snapshot_dir_path.join(name), None).await?;
                // The size after the merged snapshot is the size after the first snapshot to be merged
                if size_after.is_none() {
                    size_after.replace(snapshot.header().size_after);
                }
                builder
                    .append_frames(snapshot.into_stream_mut().map_err(|e| anyhow::anyhow!(e)))
                    .await?;
            }

            let (_, start_frame_no, _) = parse_snapshot_name(&batch[0].0).unwrap();
            let (_, _, end_frame_no) = parse_snapshot_name(&batch.last().unwrap().0).unwrap();

            tracing::debug!(
                "created merged snapshot for {log_id} from frame {start_frame_no} to {end_frame_no}"
            );

            builder.header.start_frame_no = start_frame_no.into();
            builder.header.end_frame_no = end_frame_no.into();
            builder.header.size_after = size_after.unwrap();

            let meta = builder.finish().await?;

            for (name, _) in batch.iter() {
                tokio::fs::remove_file(&snapshot_dir_path.join(name)).await?;
            }

            out.push((meta.0, meta.1));
        }

        Ok(out)
    }

    async fn register_snapshot(
        &mut self,
        snapshot_name: String,
        snapshot_frame_count: u64,
        db_page_count: u32,
    ) -> anyhow::Result<()> {
        if self
            .sender
            .send((snapshot_name, snapshot_frame_count, db_page_count))
            .await
            .is_err()
        {
            if let Some(handle) = self.handle.take() {
                handle.await??;
            }

            anyhow::bail!("failed to register snapshot with log merger: thread exited");
        }

        Ok(())
    }
}

/// An utility to build a snapshots from log frames
struct SnapshotBuilder {
    seen_pages: HashSet<u32>,
    header: SnapshotFileHeader,
    snapshot_file: tokio::io::BufWriter<async_tempfile::TempFile>,
    db_path: PathBuf,
    last_seen_frame_no: u64,
    scripted_backup: Option<ScriptBackupManager>,
    namespace: NamespaceName,
}

fn snapshot_dir_path(db_path: &Path) -> PathBuf {
    db_path.join("snapshots")
}

impl SnapshotBuilder {
    async fn new(
        db_path: &Path,
        log_id: Uuid,
        scripted_backup: Option<ScriptBackupManager>,
        namespace: NamespaceName,
    ) -> anyhow::Result<Self> {
        let snapshot_dir_path = snapshot_dir_path(db_path);
        std::fs::create_dir_all(&snapshot_dir_path)?;
        let mut f =
            tokio::io::BufWriter::new(async_tempfile::TempFile::new_in(db_path.join("tmp")).await?);
        // reserve header space
        f.write_all(&[0; size_of::<SnapshotFileHeader>()]).await?;

        Ok(Self {
            seen_pages: HashSet::new(),
            header: SnapshotFileHeader {
                log_id: log_id.as_u128().into(),
                start_frame_no: u64::MAX.into(),
                end_frame_no: u64::MIN.into(),
                frame_count: 0.into(),
                size_after: 0.into(),
                _pad: Default::default(),
            },
            snapshot_file: f,
            db_path: db_path.to_path_buf(),
            last_seen_frame_no: u64::MAX,
            scripted_backup,
            namespace,
        })
    }

    /// append frames to the snapshot. Frames must be in decreasing frame_no order.
    async fn append_frames(
        &mut self,
        frames: impl Stream<Item = anyhow::Result<FrameMut>>,
    ) -> anyhow::Result<()> {
        // We iterate on the frames starting from the end of the log and working our way backward. We
        // make sure that only the most recent version of each file is present in the resulting
        // snapshot.
        //
        // The snapshot file contains the most recent version of each page, in descending frame
        // number order. That last part is important for when we read it later on.
        tokio::pin!(frames);
        while let Some(frame) = frames.next().await {
            let mut frame = frame?;
            assert!(frame.header().frame_no.get() < self.last_seen_frame_no);
            self.last_seen_frame_no = frame.header().frame_no.get();
            if frame.header().frame_no.get() < self.header.start_frame_no.get() {
                self.header.start_frame_no = frame.header().frame_no;
            }

            if frame.header().frame_no.get() >= self.header.end_frame_no.get() {
                self.header.end_frame_no = frame.header().frame_no;
                self.header.size_after = frame.header().size_after;
            }

            // set all frames as non-commit frame in a snapshot, and let the client decide when to
            // commit. This is ok because the client will stream frames backward until caught up,
            // and then commit.
            frame.header_mut().size_after = 0.into();

            if !self.seen_pages.contains(&frame.header().page_no.get()) {
                self.seen_pages.insert(frame.header().page_no.get());
                let data = frame.as_bytes();
                self.snapshot_file.write_all(data).await?;
                self.header.frame_count = (self.header.frame_count.get() + 1).into();
            }
        }

        Ok(())
    }

    /// Persist the snapshot, and returns the name and size is frame on the snapshot.
    async fn finish(mut self) -> anyhow::Result<(String, u64, u32)> {
        self.snapshot_file.flush().await?;
        let mut file = self.snapshot_file.into_inner();
        file.seek(SeekFrom::Start(0)).await?;
        file.write_all(self.header.as_bytes()).await?;
        let snapshot_name = format!(
            "{}-{}-{}.snap",
            Uuid::from_u128(self.header.log_id.get()),
            self.header.start_frame_no,
            self.header.end_frame_no,
        );

        file.sync_all().await?;

        if let Some(manager) = self.scripted_backup {
            manager
                .register(
                    self.namespace,
                    self.header.start_frame_no.into(),
                    self.header.end_frame_no.into(),
                    file.file_path(),
                    Uuid::from_u128(self.header.log_id.get()),
                )
                .await?;
        }
        tokio::fs::rename(
            file.file_path(),
            snapshot_dir_path(&self.db_path).join(&snapshot_name),
        )
        .await?;

        Ok((
            snapshot_name,
            self.header.frame_count.get(),
            self.header.size_after.get(),
        ))
    }
}

async fn perform_compaction(
    db_path: &Path,
    file_to_compact: LogFile,
    log_id: Uuid,
    namespace: NamespaceName,
    scripted_backup: Option<ScriptBackupManager>,
) -> anyhow::Result<(String, u64, u32)> {
    let header = file_to_compact.header();
    tracing::info!(
        "attempting to compact {} frame from logfile {}, starting at frame no {}",
        header.frame_count,
        Uuid::from_u128(header.log_id.get()),
        header.start_frame_no,
    );
    let mut builder = SnapshotBuilder::new(db_path, log_id, scripted_backup, namespace).await?;
    builder
        .append_frames(file_to_compact.into_not_decrypted_rev_stream_mut())
        .await?;
    builder.finish().await
}

#[cfg(test)]
mod test {
    use std::fs::read;
    use std::time::Duration;

    use bytes::Bytes;
    use libsql_replication::frame::Frame;
    use tempfile::tempdir;
    use zerocopy::FromBytes;

    use super::*;
    use crate::replication::primary::logger::WalPage;
    use crate::replication::snapshot::SnapshotFile;
    use crate::LIBSQL_PAGE_SIZE;

    fn entry(name: &str, count: u64) -> (String, u64) {
        (name.to_string(), count)
    }

    // ---------- group_snapshots_for_merge ----------

    #[test]
    fn group_snapshots_legacy_no_max_returns_single_batch() {
        let snaps = vec![entry("a", 10), entry("b", 20), entry("c", 5)];
        assert_eq!(group_snapshots_for_merge(&snaps, None), vec![0..3]);
    }

    #[test]
    fn group_snapshots_empty_input() {
        assert!(group_snapshots_for_merge(&[], Some(100)).is_empty());
        assert!(group_snapshots_for_merge(&[], None).is_empty());
    }

    #[test]
    fn group_snapshots_packs_under_max() {
        // max = 25, sequence 10,10,10,10 → (10+10) (10+10)
        let snaps = vec![
            entry("a", 10),
            entry("b", 10),
            entry("c", 10),
            entry("d", 10),
        ];
        assert_eq!(
            group_snapshots_for_merge(&snaps, Some(25)),
            vec![0..2, 2..4]
        );
    }

    #[test]
    fn group_snapshots_acc_plus_count_equal_to_max_packs() {
        // Boundary: acc(10)+count(10)=20 == max → must pack together (uses `>` not `>=`).
        let snaps = vec![entry("a", 10), entry("b", 10), entry("c", 5)];
        assert_eq!(
            group_snapshots_for_merge(&snaps, Some(20)),
            vec![0..2, 2..3]
        );
    }

    #[test]
    fn group_snapshots_count_exactly_at_max_is_not_oversized() {
        // Boundary: count == max must not be flagged as oversized singleton (uses `>`).
        // The file fills its own batch but goes through the regular packing path: it
        // arrives with acc=0, then `acc + count(=max) > max` is false, so it joins a
        // batch alone; the next file would overflow and start a new batch.
        let snaps = vec![entry("exact", 25), entry("after", 10)];
        // Both items singleton-by-overflow; neither is the oversized passthrough kind.
        assert_eq!(
            group_snapshots_for_merge(&snaps, Some(25)),
            vec![0..1, 1..2]
        );
    }

    #[test]
    fn group_snapshots_strictly_oversized_input_is_passthrough_singleton() {
        // count > max: oversized passthrough, isolated as its own batch.
        let snaps = vec![
            entry("a", 10),
            entry("big", 50),
            entry("c", 10),
            entry("d", 10),
        ];
        assert_eq!(
            group_snapshots_for_merge(&snaps, Some(25)),
            vec![0..1, 1..2, 2..4]
        );
    }

    #[test]
    fn group_snapshots_consecutive_oversized_inputs() {
        // Run of oversized files at the start, middle, and end. Each must be its own
        // singleton; the small files between must pack normally.
        let snaps = vec![
            entry("big1", 100),
            entry("big2", 100),
            entry("a", 5),
            entry("b", 5),
            entry("big3", 100),
            entry("c", 5),
        ];
        assert_eq!(
            group_snapshots_for_merge(&snaps, Some(20)),
            vec![0..1, 1..2, 2..4, 4..5, 5..6]
        );
    }

    #[test]
    fn group_snapshots_each_under_cap_but_sum_over() {
        // max=15, sequence 10,10,10 → each fits alone (10<15), pairs do not (20>15).
        let snaps = vec![entry("a", 10), entry("b", 10), entry("c", 10)];
        assert_eq!(
            group_snapshots_for_merge(&snaps, Some(15)),
            vec![0..1, 1..2, 2..3]
        );
    }

    #[test]
    fn group_snapshots_property_no_batch_exceeds_cap() {
        // Property check: for any grouping, sum(counts in batch) <= max OR batch.len()==1.
        let snaps = vec![
            entry("a", 7),
            entry("b", 12),
            entry("c", 3),
            entry("big", 99),
            entry("d", 8),
            entry("e", 8),
            entry("f", 8),
        ];
        let max = 20u64;
        let batches = group_snapshots_for_merge(&snaps, Some(max));
        for b in &batches {
            let sum: u64 = snaps[b.clone()].iter().map(|(_, c)| *c).sum();
            assert!(
                sum <= max || b.end - b.start == 1,
                "batch {:?} sum={} exceeds cap={} and is not a passthrough singleton",
                b,
                sum,
                max
            );
        }
    }

    // ---------- merge_makes_progress ----------

    #[test]
    fn merge_makes_progress_all_singletons_returns_false() {
        // After grouping, every batch is len==1 → nothing to merge.
        let batches = vec![0..1, 1..2, 2..3];
        assert!(!merge_makes_progress(&batches));
    }

    #[test]
    fn merge_makes_progress_any_multi_batch_returns_true() {
        let batches = vec![0..1, 1..3, 3..4];
        assert!(merge_makes_progress(&batches));
    }

    #[test]
    fn merge_makes_progress_empty_returns_false() {
        assert!(!merge_makes_progress(&[]));
    }

    // ---------- SnapshotPolicy::should_compact ----------

    fn legacy_policy() -> SnapshotPolicy {
        SnapshotPolicy { max_frames: None, max_count: MAX_SNAPSHOT_NUMBER }
    }
    fn cap_policy(max_frames: u64, max_count: usize) -> SnapshotPolicy {
        SnapshotPolicy { max_frames: Some(max_frames), max_count }
    }

    #[test]
    fn should_compact_legacy_amplification_trigger() {
        // Legacy: total >= 2 * db_page_count fires.
        let snaps = vec![entry("a", 100), entry("b", 100)]; // total 200
        assert!(legacy_policy().should_compact(&snaps, 80));      // 200 >= 160
        assert!(!legacy_policy().should_compact(&snaps, 200));    // 200 <  400
    }

    #[test]
    fn should_compact_legacy_count_trigger() {
        // Legacy: count > MAX_SNAPSHOT_NUMBER fires regardless of size.
        let snaps: Vec<_> = (0..(MAX_SNAPSHOT_NUMBER + 1))
            .map(|i| entry(&format!("s{i}"), 1))
            .collect();
        // With db_page_count enormous, size trigger does NOT fire — only count does.
        // But group_snapshots_for_merge with max_frames=None returns one batch
        // covering all, so merge_makes_progress is true (len > 1) → should_compact true.
        assert!(legacy_policy().should_compact(&snaps, u32::MAX));
    }

    #[test]
    fn should_compact_cap_size_trigger_with_progress() {
        // Cap mode: total >= cap fires when batches actually combine something.
        let snaps = vec![entry("a", 10), entry("b", 10), entry("c", 10)]; // total 30
        let policy = cap_policy(25, 100);
        // Total 30 >= cap 25 → size trigger fires. Grouping = [0..2, 2..3] → one
        // multi-batch → progress → should_compact true.
        assert!(policy.should_compact(&snaps, 0));
    }

    #[test]
    fn should_compact_cap_below_threshold_returns_false() {
        let snaps = vec![entry("a", 10), entry("b", 10)]; // total 20
        let policy = cap_policy(25, 100);
        // Below cap and well below count → false.
        assert!(!policy.should_compact(&snaps, 0));
    }

    #[test]
    fn should_compact_cap_no_progress_avoids_hot_loop() {
        // Critical: every snapshot is at-or-above cap, so grouping yields all singletons.
        // Even though `total >= cap` and `count > max_count`, should_compact must return
        // false to avoid spawning useless merge jobs forever.
        let snaps = vec![
            entry("big1", 100),
            entry("big2", 100),
            entry("big3", 100),
            entry("big4", 100),
        ];
        let policy = cap_policy(20, 2); // cap exceeded; count exceeded
        assert!(!policy.should_compact(&snaps, 0));
    }

    #[test]
    fn should_compact_cap_count_override() {
        // SQLD_MAX_SNAPSHOT_COUNT raises the count trigger above the legacy 32.
        let snaps: Vec<_> = (0..50).map(|i| entry(&format!("s{i}"), 1)).collect(); // total 50
        // cap=10000 (size never trips), max_count=100 (count never trips), 50 small files.
        let policy = cap_policy(10_000, 100);
        assert!(!policy.should_compact(&snaps, 0));
        // Now drop max_count below 50 → count trigger fires AND grouping packs them all
        // into one big batch (50 files of size 1, sum=50 <= cap=10000) → progress.
        let policy = cap_policy(10_000, 25);
        assert!(policy.should_compact(&snaps, 0));
    }

    // ---------- parse_max_snapshot_frames ----------

    #[test]
    fn parse_max_snapshot_frames_handles_inputs() {
        // unset / empty / non-numeric / zero → None (legacy fallback)
        assert_eq!(parse_max_snapshot_frames(None), None);
        assert_eq!(parse_max_snapshot_frames(Some("")), None);
        assert_eq!(parse_max_snapshot_frames(Some("abc")), None);
        assert_eq!(parse_max_snapshot_frames(Some("0")), None);
        // Valid: 20 MB → frames = 20_000_000 / FRAME_SIZE.
        let expected = 20u64 * 1_000_000 / LogFile::FRAME_SIZE as u64;
        assert_eq!(parse_max_snapshot_frames(Some("20")), Some(expected));
        // Overflow on mb * 1_000_000 → None (fail-safe to legacy).
        assert_eq!(parse_max_snapshot_frames(Some("99999999999999999")), None);
    }

    async fn dir_is_empty(p: &Path) -> bool {
        // there is nothing left in the to_compact directory
        if p.try_exists().unwrap() {
            let mut dir = tokio::fs::read_dir(p).await.unwrap();
            let mut count = 0;
            while let Some(entry) = dir.next_entry().await.unwrap() {
                if entry.file_type().await.unwrap().is_file() {
                    count += 1;
                }
            }

            count == 0
        } else {
            true
        }
    }

    /// On startup, there may be uncompacted log leftover in the `to_compact` directory.
    /// These should be processed before any other logs.
    #[tokio::test]
    async fn process_pending_logs_on_startup() {
        let tmp = tempdir().unwrap();
        let log_id = Uuid::now_v7();
        let to_compact_path = tmp.path().join("to_compact");
        tokio::fs::create_dir_all(&to_compact_path).await.unwrap();
        let mut current_fno = 0;
        let mut make_logfile = {
            let to_compact_path = to_compact_path.clone();
            move || {
                let logfile_path = to_compact_path.join(Uuid::new_v4().to_string());
                let file = std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .read(true)
                    .open(&logfile_path)
                    .unwrap();
                let mut logfile = LogFile::new(file, u64::MAX, None, None).unwrap();
                let header = LogFileHeader {
                    log_id: log_id.as_u128().into(),
                    start_frame_no: current_fno.into(),
                    ..*logfile.header()
                };

                logfile.header = header;
                logfile.write_header().unwrap();

                logfile
                    .push_page(&WalPage {
                        page_no: 0,
                        size_after: 1,
                        data: Bytes::from_static(&[0; LIBSQL_PAGE_SIZE as _]),
                    })
                    .unwrap();
                logfile.commit().unwrap();
                current_fno =
                    logfile.header().start_frame_no.get() + logfile.header().frame_count.get();
                (logfile, logfile_path)
            }
        };
        // write a couple of pages to the pending compact list.
        for _ in 0..3 {
            make_logfile();
        }

        // nothing has been compacted yet
        assert!(!tmp.path().join("snapshots").exists());

        // we make a last logfile that we'll send through to the compactor. This one should be
        // processed after the pending one. We can't guarantee that it will be received _before_ we
        // start processing pending logs, but a correct implementation should always processs the
        // log _after_ the pending logs have been processed. A failure to do so will trigger
        // assertions in the merger code.
        let compactor = LogCompactor::new(tmp.path(), log_id, None, "test".into()).unwrap();
        let compactor_clone = compactor.clone();
        tokio::task::spawn_blocking(move || {
            let (logfile, logfile_path) = make_logfile();
            compactor_clone.compact(logfile, logfile_path).unwrap();
        })
        .await
        .unwrap();

        // wait a bit for snapshot to be compated
        tokio::time::sleep(Duration::from_millis(1500)).await;

        // no error occured: the loop is still running.
        assert!(!compactor.sender.is_closed());
        assert!(tmp.path().join("snapshots").exists());
        let mut dir = tokio::fs::read_dir(tmp.path().join("snapshots"))
            .await
            .unwrap();
        let mut start_idx = u64::MAX;
        let mut end_idx = u64::MIN;
        while let Some(entry) = dir.next_entry().await.unwrap() {
            if entry.file_type().await.unwrap().is_file() {
                let (_, start, end) =
                    parse_snapshot_name(entry.file_name().to_str().unwrap()).unwrap();
                start_idx = start_idx.min(start);
                end_idx = end_idx.max(end);
            }
        }

        // assert that all indexes are covered
        assert_eq!((start_idx, end_idx), (0, 3));
        assert!(dir_is_empty(&to_compact_path).await);
    }

    /// Simulate an empty pending snapshot left by the logger if the logswapping operation was
    /// interupted after the new log was created, but before it was swapped with the old log.
    #[tokio::test]
    async fn empty_pending_log_is_ignored() {
        let tmp = tempdir().unwrap();
        let to_compact_path = tmp.path().join("to_compact");
        tokio::fs::create_dir_all(&to_compact_path).await.unwrap();
        let logfile_path = to_compact_path.join(Uuid::new_v4().to_string());
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .open(&logfile_path)
            .unwrap();
        let mut logfile = LogFile::new(file, u64::MAX, None, None).unwrap();
        logfile.write_header().unwrap();

        let _compactor =
            LogCompactor::new(tmp.path(), Uuid::new_v4(), None, "test".into()).unwrap();
        tokio::time::sleep(Duration::from_millis(1000)).await;

        // emtpy snapshot was discarded
        assert!(dir_is_empty(&tmp.path().join("to_compact")).await);
        assert!(dir_is_empty(&tmp.path().join("snapshots")).await);
    }

    /// In this test, we send a bunch of snapshot to the compactor, and see if it handles it
    /// correctly.
    ///
    /// This test is similar to process_pending_logs_on_startup, except that all the logs are sent
    /// over the compactor channel.
    #[tokio::test]
    async fn compact_many() {
        let tmp = tempdir().unwrap();
        let log_id = Uuid::now_v7();
        let to_compact_path = tmp.path().join("to_compact");
        tokio::fs::create_dir_all(&to_compact_path).await.unwrap();
        let mut current_fno = 0;
        let mut make_logfile = {
            let to_compact_path = to_compact_path.clone();
            move || {
                let logfile_path = to_compact_path.join(Uuid::new_v4().to_string());
                let file = std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .read(true)
                    .open(&logfile_path)
                    .unwrap();
                let mut logfile = LogFile::new(file, u64::MAX, None, None).unwrap();
                let header = LogFileHeader {
                    log_id: log_id.as_u128().into(),
                    start_frame_no: current_fno.into(),
                    ..*logfile.header()
                };

                logfile.header = header;
                logfile.write_header().unwrap();

                logfile
                    .push_page(&WalPage {
                        page_no: 0,
                        size_after: 1,
                        data: Bytes::from_static(&[0; LIBSQL_PAGE_SIZE as _]),
                    })
                    .unwrap();
                logfile.commit().unwrap();
                current_fno =
                    logfile.header().start_frame_no.get() + logfile.header().frame_count.get();
                (logfile, logfile_path)
            }
        };

        // nothing has been compacted yet
        assert!(!tmp.path().join("snapshots").exists());

        // we make a last logfile that we'll send through to the compactor. This one should be
        // processed after the pending one. We can't guarantee that it will be received _before_ we
        // start processing pending logs, but a correct implementation should always processs the
        // log _after_ the pending logs have been processed. A failure to do so will trigger
        // assertions in the merger code.
        let compactor = LogCompactor::new(tmp.path(), log_id, None, "test".into()).unwrap();
        let compactor_clone = compactor.clone();
        tokio::task::spawn_blocking(move || {
            for _ in 0..10 {
                let (logfile, logfile_path) = make_logfile();
                compactor_clone.compact(logfile, logfile_path).unwrap();
            }
        })
        .await
        .unwrap();

        // no error occured: the loop is still running.
        assert!(!compactor.sender.is_closed());
        assert!(tmp.path().join("snapshots").exists());
        let mut start_idx = u64::MAX;
        let mut end_idx = u64::MIN;
        while end_idx != 9 {
            let mut dir = tokio::fs::read_dir(tmp.path().join("snapshots"))
                .await
                .unwrap();
            while let Some(entry) = dir.next_entry().await.unwrap() {
                if entry.file_type().await.unwrap().is_file() {
                    let name = entry.file_name();
                    let name = name.to_str().unwrap();
                    let (_, start, end) = parse_snapshot_name(name).unwrap();
                    start_idx = start_idx.min(start);
                    end_idx = end_idx.max(end);
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // assert that all indexes are covered
        assert_eq!(start_idx, 0);

        while !dir_is_empty(&to_compact_path).await {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    #[tokio::test]
    async fn compact_file_create_snapshot() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        let mut log_file =
            LogFile::new(temp.as_file().try_clone().unwrap(), 0, None, None).unwrap();
        let log_id = Uuid::new_v4();
        log_file.header.log_id = log_id.as_u128().into();
        log_file.write_header().unwrap();

        // add 50 pages, each one in two versions
        for _ in 0..2 {
            for i in 0..25 {
                let data = std::iter::repeat(0).take(4096).collect::<Bytes>();
                let page = WalPage {
                    page_no: i,
                    size_after: i + 1,
                    data,
                };
                log_file.push_page(&page).unwrap();
            }
        }

        log_file.commit().unwrap();

        let dump_dir = tempdir().unwrap();
        let compactor = LogCompactor::new(dump_dir.path(), log_id, None, "test".into()).unwrap();
        tokio::task::spawn_blocking({
            let compactor = compactor.clone();
            move || {
                compactor
                    .compact(log_file, temp.path().to_path_buf())
                    .unwrap()
            }
        })
        .await
        .unwrap();

        tokio::time::sleep(Duration::from_secs(1)).await;

        let snapshot_path =
            snapshot_dir_path(dump_dir.path()).join(format!("{}-{}-{}.snap", log_id, 0, 49));
        let snapshot = read(&snapshot_path).unwrap();
        let header = SnapshotFileHeader::read_from_prefix(
            &snapshot[..std::mem::size_of::<SnapshotFileHeader>()],
        )
        .unwrap();

        assert_eq!(header.start_frame_no.get(), 0);
        assert_eq!(header.end_frame_no.get(), 49);
        assert_eq!(header.frame_count.get(), 25);
        assert_eq!(header.log_id.get(), log_id.as_u128());
        assert_eq!(header.size_after.get(), 25);

        let mut seen_frames = HashSet::new();
        let mut seen_page_no = HashSet::new();
        let data = &snapshot[std::mem::size_of::<SnapshotFileHeader>()..];
        data.chunks(LogFile::FRAME_SIZE).for_each(|f| {
            let frame = Frame::try_from(f).unwrap();
            assert!(!seen_frames.contains(&frame.header().frame_no));
            assert!(!seen_page_no.contains(&frame.header().page_no));
            seen_page_no.insert(frame.header().page_no);
            seen_frames.insert(frame.header().frame_no);
            assert!(frame.header().frame_no.get() >= 25);
        });

        assert_eq!(seen_frames.len(), 25);
        assert_eq!(seen_page_no.len(), 25);

        let snapshot_file = SnapshotFile::open(&snapshot_path, None).await.unwrap();

        let frames = snapshot_file.into_stream_mut_from(0);
        tokio::pin!(frames);
        let mut expected_frame_no = 49;
        while let Some(frame) = frames.next().await {
            let frame = frame.unwrap();
            assert_eq!(frame.header().frame_no.get(), expected_frame_no);
            expected_frame_no -= 1;
        }

        assert_eq!(expected_frame_no, 24);
    }
}
