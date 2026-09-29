//! Read leases for streams that serve namespace data outside SQL programs: `/dump` and the
//! replication `log_entries`, `batch_log_entries` and `snapshot` calls (`docs/NAMESPACE_FENCE.md`
//! section 9).
//!
//! A [`FencedStream`] holds a read lease of the stream's kind for as long as it can produce
//! items. A watcher task ends it when the gate stops admitting streams, or when the read drain
//! cancels it at its deadline: the watcher drops the inner stream and the lease itself, so the
//! lease is released even if the peer never polls the stream again, and the next poll yields
//! one terminal error carrying the typed fence code and then ends.
//!
//! A dump is not a stream of this kind (its data is produced by a blocking export on a
//! connection), so it holds its lease in the export itself and uses a [`StreamCancel`] to stop
//! it ([`crate::http::user::dump`]).

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::task::AtomicWaker;
use futures::Stream;
use parking_lot::Mutex;
use tokio::sync::{oneshot, Notify};

use super::controller::{FenceController, LeaseKind, ReadLease};
use super::outcome::{FenceError, FenceOutcome};
use super::state::OperationClass;

/// How the read drain stops a stream at its deadline: a flag for code that polls it, and a
/// notification for code that waits. Setting it never blocks.
#[derive(Debug, Default)]
pub struct StreamCancel {
    cancelled: AtomicBool,
    notify: Notify,
}

impl StreamCancel {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        // `notify_one` keeps a permit when nobody waits yet, so a waiter that arrives later
        // still wakes.
        self.notify.notify_one();
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    /// Resolves once [`cancel`](Self::cancel) has been called.
    pub async fn cancelled(&self) {
        while !self.is_cancelled() {
            self.notify.notified().await;
        }
    }
}

/// The error a stream ends with when the read drain cancels it at its deadline.
pub fn cancelled_by_read_fence(kind: LeaseKind) -> FenceError {
    FenceError::new(
        FenceOutcome::MigrationReadFenced,
        format!("the {kind:?} stream was ended by the namespace read fence"),
    )
}

/// Admit a stream of `kind` and hold a read lease for it; the returned cancel is what the read
/// drain uses at its deadline.
pub fn acquire_stream_lease(
    fence: &Arc<FenceController>,
    kind: LeaseKind,
) -> Result<(ReadLease, Arc<StreamCancel>), FenceError> {
    let cancel = Arc::new(StreamCancel::default());
    let lease = fence.acquire_read_lease(OperationClass::Stream, kind, {
        let cancel = cancel.clone();
        move || cancel.cancel()
    })?;
    Ok((lease, cancel))
}

/// Resolves with the gate's refusal once the gate stops admitting streams.
async fn gate_denies_streams(fence: &FenceController) -> FenceError {
    let mut gate = fence.subscribe();
    loop {
        if let Err(e) = gate.borrow_and_update().permits(OperationClass::Stream) {
            return e;
        }
        if gate.changed().await.is_err() {
            // The controller is gone, which only happens when the namespace is destroyed: end
            // the stream rather than serve it without a gate.
            return FenceError::new(
                FenceOutcome::FenceStateUnavailable,
                "the namespace fence controller is gone",
            );
        }
    }
}

enum Slot<S> {
    Live {
        stream: S,
        _lease: ReadLease,
        /// Dropped with the stream, which stops the watcher.
        _stop_watcher: oneshot::Sender<()>,
    },
    /// Ended by the fence; the error is yielded once.
    Terminated(Option<FenceError>),
    /// Ended on its own.
    Finished,
}

struct Shared<S> {
    slot: Mutex<Slot<S>>,
    waker: AtomicWaker,
}

impl<S> Shared<S> {
    /// End the stream with `error`: drop the inner stream and the lease now, and wake the
    /// consumer so that it sees the error when it next polls.
    fn terminate(&self, error: FenceError) {
        let ended = {
            let mut slot = self.slot.lock();
            match &*slot {
                Slot::Live { .. } => std::mem::replace(&mut *slot, Slot::Terminated(Some(error))),
                _ => return,
            }
        };
        // Drop the inner stream and release the lease outside the slot lock.
        drop(ended);
        self.waker.wake();
    }
}

/// A stream that holds a read lease and ends with a typed fence error when the gate stops
/// admitting streams or the read drain cancels it (see the module documentation).
pub struct FencedStream<S, F> {
    shared: Arc<Shared<S>>,
    map_err: F,
}

impl<S, T, E, F> FencedStream<S, F>
where
    S: Stream<Item = Result<T, E>> + Unpin + Send + 'static,
    F: Fn(FenceError) -> E + Unpin,
{
    /// Admit `stream` as a stream of `kind` on `fence`. Refused, with the gate's error, when the
    /// gate does not admit streams. `map_err` turns the terminal fence error into the stream's
    /// error type. Must be called within a Tokio runtime (the watcher is a task).
    pub fn new(
        fence: &Arc<FenceController>,
        kind: LeaseKind,
        stream: S,
        map_err: F,
    ) -> Result<Self, FenceError> {
        let (lease, cancel) = acquire_stream_lease(fence, kind)?;
        let (stop_tx, stop_rx) = oneshot::channel();
        let shared = Arc::new(Shared {
            slot: Mutex::new(Slot::Live {
                stream,
                _lease: lease,
                _stop_watcher: stop_tx,
            }),
            waker: AtomicWaker::new(),
        });
        let watched = Arc::downgrade(&shared);
        let fence = fence.clone();
        tokio::spawn(async move {
            let error = tokio::select! {
                e = gate_denies_streams(&fence) => e,
                _ = cancel.cancelled() => cancelled_by_read_fence(kind),
                _ = stop_rx => return,
            };
            if let Some(shared) = watched.upgrade() {
                tracing::debug!(
                    namespace = %fence.namespace(),
                    "{kind:?} stream ended by the namespace fence: {error}"
                );
                shared.terminate(error);
            }
        });
        Ok(Self { shared, map_err })
    }
}

impl<S, T, E, F> Stream for FencedStream<S, F>
where
    S: Stream<Item = Result<T, E>> + Unpin,
    F: Fn(FenceError) -> E + Unpin,
{
    type Item = Result<T, E>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        this.shared.waker.register(cx.waker());
        let mut slot = this.shared.slot.lock();
        match &mut *slot {
            Slot::Live { stream, .. } => match Pin::new(stream).poll_next(cx) {
                Poll::Ready(None) => {
                    // Release the lease as soon as the stream has nothing more to serve.
                    let ended = std::mem::replace(&mut *slot, Slot::Finished);
                    drop(slot);
                    drop(ended);
                    Poll::Ready(None)
                }
                other => other,
            },
            Slot::Terminated(error) => match error.take() {
                Some(error) => Poll::Ready(Some(Err((this.map_err)(error)))),
                None => Poll::Ready(None),
            },
            Slot::Finished => Poll::Ready(None),
        }
    }
}

/// The gRPC status of a fence error on a replication call.
pub fn fence_status(error: FenceError) -> tonic::Status {
    error
        .to_grpc_status()
        .unwrap_or_else(|| tonic::Status::failed_precondition(error.to_string()))
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use futures::stream::BoxStream;
    use futures::{Stream, StreamExt};
    use libsql_replication::rpc::replication::replication_log_server::ReplicationLog;
    use libsql_replication::rpc::replication::{
        Frame, HelloRequest, LogOffset, NAMESPACE_METADATA_KEY, SESSION_TOKEN_KEY,
    };
    use tonic::metadata::{AsciiMetadataValue, BinaryMetadataValue};

    use super::*;
    use crate::error::Error;
    use crate::http::user::dump::dump_stream;
    use crate::namespace::fence::drain::tests::{fence_outcome, raw, Source, LONG, OP, PROMPT};
    use crate::namespace::fence::read::tests::{fenced_source, read_fence, NOW};
    use crate::namespace::fence::state::FenceState;
    use crate::rpc::replication::replication_log::ReplicationLogService;

    /// A write-fenced source whose table holds one row of a megabyte (two in the dump's hex),
    /// far more than the dump pipe buffers, so a dump whose peer stops reading blocks in the
    /// middle of writing that row, where only the pipe's cancel can stop it.
    async fn large_fenced_source() -> Source {
        let s = Source::new().await;
        raw(
            &s.conn().await,
            "insert into t values (randomblob(1000000))",
        )
        .await
        .unwrap();
        let acquired = s.execute(s.acquire(OP, 1, LONG)).await.unwrap();
        assert_eq!(fence_outcome(&acquired), FenceOutcome::Applied);
        s
    }

    async fn dump(s: &Source) -> crate::Result<impl Stream<Item = Result<Bytes, Error>>> {
        let maker = s
            .store
            .with("ns".into(), |ns| ns.db.connection_maker())
            .await
            .unwrap();
        dump_stream(&s.fence, maker, false).await
    }

    /// Read `stream` to its end: the bytes, and the error it ended with, if any.
    async fn read_to_end(
        mut stream: impl Stream<Item = Result<Bytes, Error>> + Unpin,
    ) -> (Vec<u8>, Option<Error>) {
        let mut out = Vec::new();
        while let Some(chunk) = tokio::time::timeout(PROMPT, stream.next())
            .await
            .expect("the dump stream stalled")
        {
            match chunk {
                Ok(bytes) => out.extend_from_slice(&bytes),
                Err(e) => return (out, Some(e)),
            }
        }
        (out, None)
    }

    fn assert_read_fenced(e: &Error) {
        match e {
            Error::NamespaceFence(f) => assert_eq!(f.outcome(), FenceOutcome::MigrationReadFenced),
            other => panic!("expected MIGRATION_READ_FENCED, got {other:?}"),
        }
    }

    fn ends_with_commit(dump: &[u8]) -> bool {
        String::from_utf8_lossy(dump)
            .trim_end()
            .ends_with("COMMIT;")
    }

    /// A dump whose peer has stopped reading is cancelled at the read drain's deadline: its
    /// lease is released without the peer reading anything more, the fence is acknowledged,
    /// and the body ends with the fence error, never with `COMMIT;`.
    #[tokio::test(flavor = "multi_thread")]
    async fn dump_lease_released_on_cancel() {
        let s = large_fenced_source().await;
        let mut stream = Box::pin(dump(&s).await.unwrap());
        // Read until the row has begun: the export is then inside the write of a row that does
        // not fit in the pipe, and blocked on it.
        let mut head = Vec::new();
        while !String::from_utf8_lossy(&head).contains("INSERT INTO") {
            head.extend_from_slice(&stream.next().await.unwrap().unwrap());
        }
        assert_eq!(s.fence.read_lease_counts().dump, 1);

        let fenced = tokio::time::timeout(PROMPT, s.execute(read_fence(&s, 2, NOW)))
            .await
            .expect("the dump's lease was never released")
            .unwrap();
        assert_eq!(fence_outcome(&fenced), FenceOutcome::Applied);
        assert_eq!(s.fence.gate().state(), FenceState::SourceReadFenced);
        assert_eq!(s.fence.read_lease_counts().total(), 0);

        let (rest, error) = read_to_end(stream).await;
        assert_read_fenced(&error.expect("a cancelled dump must end with an error"));
        let mut body = head;
        body.extend_from_slice(&rest);
        assert!(!ends_with_commit(&body));
        assert!(!String::from_utf8_lossy(&body).contains("COMMIT;"));
    }

    /// The read drain waits for a running dump rather than for time: the fence is acknowledged
    /// only once the dump has completed and released its lease.
    #[tokio::test(flavor = "multi_thread")]
    async fn read_fence_waits_for_dump() {
        let s = large_fenced_source().await;
        let mut stream = Box::pin(dump(&s).await.unwrap());
        let first = stream.next().await.unwrap().unwrap();

        let fencing = s.execute(read_fence(&s, 2, LONG));
        s.until_state(FenceState::SourceReadDraining).await;
        assert!(!fencing.is_finished());
        assert_eq!(s.fence.read_lease_counts().dump, 1);
        // New dumps are refused while the drain waits for this one.
        assert_read_fenced(&dump(&s).await.err().unwrap());

        let (rest, error) = read_to_end(stream).await;
        assert!(error.is_none(), "{error:?}");
        let mut body = first.to_vec();
        body.extend_from_slice(&rest);
        assert!(ends_with_commit(&body));

        let fenced = tokio::time::timeout(PROMPT, fencing)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fence_outcome(&fenced), FenceOutcome::Applied);
        assert_eq!(s.fence.read_lease_counts().total(), 0);
    }

    /// A dump requested while reads are fenced is refused before any connection is created.
    #[tokio::test]
    async fn dump_refused_while_read_fenced() {
        let s = fenced_source().await;
        let fenced = s.execute(read_fence(&s, 2, LONG)).await.unwrap();
        assert_eq!(fence_outcome(&fenced), FenceOutcome::Applied);
        assert_read_fenced(&dump(&s).await.err().unwrap());
        assert_eq!(s.fence.read_lease_counts().total(), 0);
    }

    struct Replication {
        service: ReplicationLogService,
        token: Option<AsciiMetadataValue>,
    }

    impl Replication {
        /// The internal replication service on `s`, after a `hello`.
        async fn new(s: &Source) -> Self {
            let mut this = Self {
                service: ReplicationLogService::new(
                    s.store.clone(),
                    None,
                    None,
                    false,
                    false,
                    true,
                ),
                token: None,
            };
            let hello = this
                .service
                .hello(this.request(HelloRequest {
                    handshake_version: Some(1),
                }))
                .await
                .unwrap()
                .into_inner();
            this.token = Some(AsciiMetadataValue::try_from(&hello.session_token[..]).unwrap());
            this
        }

        fn request<T>(&self, msg: T) -> tonic::Request<T> {
            let mut req = tonic::Request::new(msg);
            req.metadata_mut().insert_bin(
                NAMESPACE_METADATA_KEY,
                BinaryMetadataValue::from_bytes(b"ns"),
            );
            if let Some(token) = &self.token {
                req.metadata_mut().insert(SESSION_TOKEN_KEY, token.clone());
            }
            req
        }

        fn offset(&self, next_offset: u64) -> tonic::Request<LogOffset> {
            self.request(LogOffset {
                next_offset,
                wal_flavor: None,
            })
        }
    }

    fn assert_read_fenced_status(status: &tonic::Status) {
        assert_eq!(status.code(), tonic::Code::FailedPrecondition, "{status:?}");
        assert_eq!(
            FenceError::outcome_from_grpc_status(status),
            Some(FenceOutcome::MigrationReadFenced),
            "{status:?}"
        );
    }

    async fn next_frame(
        stream: &mut (impl Stream<Item = Result<Frame, tonic::Status>> + Unpin),
    ) -> Option<Result<Frame, tonic::Status>> {
        tokio::time::timeout(PROMPT, stream.next())
            .await
            .expect("the replication stream stalled")
    }

    async fn until_released(fence: &FenceController) {
        tokio::time::timeout(PROMPT, async {
            loop {
                let released = fence.read_released().notified();
                if fence.read_lease_counts().total() == 0 {
                    break;
                }
                released.await;
            }
        })
        .await
        .expect("the stream's lease was never released")
    }

    /// A tailing `log_entries` stream on a write-fenced source is served, holds a replication
    /// lease, and is ended by the read fence with a typed terminal status, without the drain
    /// having to wait for its deadline.
    #[tokio::test(flavor = "multi_thread")]
    async fn log_entries_stream_ends_typed() {
        let s = fenced_source().await;
        let r = Replication::new(&s).await;
        let mut stream = r
            .service
            .log_entries(r.offset(1))
            .await
            .unwrap()
            .into_inner();
        assert!(next_frame(&mut stream).await.unwrap().is_ok());
        assert_eq!(s.fence.read_lease_counts().replication, 1);

        let fenced = tokio::time::timeout(PROMPT, s.execute(read_fence(&s, 2, LONG)))
            .await
            .expect("the tailing stream kept the drain waiting")
            .unwrap();
        assert_eq!(fence_outcome(&fenced), FenceOutcome::Applied);
        assert_eq!(s.fence.read_lease_counts().total(), 0);

        let last = next_frame(&mut stream).await.unwrap();
        assert_read_fenced_status(&last.unwrap_err());
        assert!(next_frame(&mut stream).await.is_none());
    }

    /// A stream whose peer never reads again (a dead peer) releases its lease anyway: the
    /// watcher drops the inner stream and the lease without the stream being polled.
    #[tokio::test(flavor = "multi_thread")]
    async fn stream_lease_released_without_peer_read() {
        let s = fenced_source().await;
        let r = Replication::new(&s).await;
        let stream = r
            .service
            .log_entries(r.offset(1))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(s.fence.read_lease_counts().replication, 1);

        let fenced = tokio::time::timeout(PROMPT, s.execute(read_fence(&s, 2, LONG)))
            .await
            .expect("the unread stream kept the drain waiting")
            .unwrap();
        assert_eq!(fence_outcome(&fenced), FenceOutcome::Applied);
        until_released(&s.fence).await;

        // The frames the stream had not yet produced are never served.
        let mut stream = stream;
        assert_read_fenced_status(&next_frame(&mut stream).await.unwrap().unwrap_err());
        assert!(next_frame(&mut stream).await.is_none());
    }

    /// A `snapshot` stream is ended by the read fence the same way.
    #[tokio::test(flavor = "multi_thread")]
    async fn snapshot_stream_ends_typed() {
        // Compact at once, so the log's frames are in a snapshot.
        let s = Source::with_max_log_size(0).await;
        raw(&s.conn().await, "insert into t values (1), (2)")
            .await
            .unwrap();
        // The periodic compaction may already have run; either way there is nothing left to
        // compact once this returns.
        let logger = s.logger.clone();
        tokio::task::spawn_blocking(move || logger.maybe_compact())
            .await
            .unwrap()
            .unwrap();
        let acquired = s.execute(s.acquire(OP, 1, LONG)).await.unwrap();
        assert_eq!(fence_outcome(&acquired), FenceOutcome::Applied);

        let r = Replication::new(&s).await;
        let stream = open_snapshot_stream(&s, &r).await;
        assert_eq!(s.fence.read_lease_counts().replication, 1);

        let fenced = tokio::time::timeout(PROMPT, s.execute(read_fence(&s, 2, LONG)))
            .await
            .expect("the snapshot stream kept the drain waiting")
            .unwrap();
        assert_eq!(fence_outcome(&fenced), FenceOutcome::Applied);
        until_released(&s.fence).await;

        let mut stream = stream;
        assert_read_fenced_status(&next_frame(&mut stream).await.unwrap().unwrap_err());
        assert!(next_frame(&mut stream).await.is_none());
    }

    /// Opens a `snapshot` stream from frame 1 once the compactor has written a snapshot.
    ///
    /// The snapshot is written, and possibly merged with the previous one, by the compactor's
    /// own tasks, concurrently with this call. The server looks a snapshot up by listing the
    /// snapshot directory and then opening the file it chose, so while the directory does not
    /// exist yet, or while a merge removes the files it replaced, the call can fail with
    /// "snapshot not found" or with the `NotFound` of the vanished file. Those two failures,
    /// and only those, mean "not yet": any other status (a fence refusal in particular) fails
    /// the test. A stream that was opened holds its file open, so a later merge cannot affect it.
    async fn open_snapshot_stream(
        s: &Source,
        r: &Replication,
    ) -> BoxStream<'static, Result<Frame, tonic::Status>> {
        tokio::time::timeout(PROMPT, async {
            loop {
                match r.service.snapshot(r.offset(1)).await {
                    Ok(stream) => break stream.into_inner(),
                    Err(status) => {
                        let not_yet = match status.code() {
                            tonic::Code::Unavailable => status.message() == "snapshot not found",
                            tonic::Code::Internal => status.message().contains("os error 2"),
                            _ => false,
                        };
                        assert!(not_yet, "unexpected snapshot status: {status:?}");
                        assert_eq!(s.fence.read_lease_counts().total(), 0);
                        // A polling interval, not evidence: the loop ends on the condition.
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                }
            }
        })
        .await
        .expect("the snapshot was never written")
    }

    /// While reads are fenced every replication call is refused at its start with the typed
    /// status (never `UNAVAILABLE`), and no lease is taken.
    #[tokio::test]
    async fn replication_calls_denied_while_read_fenced() {
        let s = fenced_source().await;
        let r = Replication::new(&s).await;
        let fenced = s.execute(read_fence(&s, 2, LONG)).await.unwrap();
        assert_eq!(fence_outcome(&fenced), FenceOutcome::Applied);

        let hello = r
            .service
            .hello(r.request(HelloRequest {
                handshake_version: Some(1),
            }))
            .await;
        assert_read_fenced_status(&hello.unwrap_err());
        assert_read_fenced_status(&r.service.log_entries(r.offset(1)).await.err().unwrap());
        assert_read_fenced_status(
            &r.service
                .batch_log_entries(r.offset(1))
                .await
                .err()
                .unwrap(),
        );
        assert_read_fenced_status(&r.service.snapshot(r.offset(1)).await.err().unwrap());
        assert_eq!(s.fence.read_lease_counts().total(), 0);
    }

    /// The deadline cancel of a stream (the backstop when the gate has not ended it) also ends
    /// it with the typed status and releases the lease without the stream being polled.
    #[tokio::test]
    async fn read_fence_forced_termination() {
        let s = fenced_source().await;
        let (_tx, rx) = tokio::sync::mpsc::channel::<Result<u32, tonic::Status>>(1);
        let mut stream = FencedStream::new(
            &s.fence,
            LeaseKind::Replication,
            tokio_stream::wrappers::ReceiverStream::new(rx),
            fence_status as fn(FenceError) -> tonic::Status,
        )
        .unwrap();
        assert_eq!(s.fence.cancel_read_leases(), 1);
        until_released(&s.fence).await;
        let status = tokio::time::timeout(PROMPT, stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_read_fenced_status(&status);
        assert!(stream.next().await.is_none());
    }
}
