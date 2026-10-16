use std::path::PathBuf;

use tokio::time::Duration;
use tokio_stream::{Stream, StreamExt};
use tokio_util::sync::CancellationToken;
use tonic::{Code, Status};

use crate::frame::{Frame, FrameNo};
use crate::injector::{Injector, SqliteInjector};
use crate::rpc::replication::{
    Frame as RpcFrame, NAMESPACE_DOESNT_EXIST, NEED_SNAPSHOT_ERROR_MSG, NO_HELLO_ERROR_MSG,
};

pub use tokio_util::either::Either;

const HANDSHAKE_MAX_RETRIES: usize = 100;

type BoxError = Box<dyn std::error::Error + Sync + Send + 'static>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Internal error: {0}")]
    Internal(BoxError),
    #[error("Injector error: {0}")]
    Injector(#[from] crate::injector::Error),
    #[error("Replicator client error: {0}")]
    Client(BoxError),
    #[error("Fatal replicator error: {0}")]
    Fatal(BoxError),
    #[error("Timeout performing handshake with primary")]
    PrimaryHandshakeTimeout,
    #[error("Replicator needs to load from snapshot")]
    NeedSnapshot,
    #[error("Snapshot not ready yet")]
    SnapshotPending,
    #[error("Replication meta error: {0}")]
    Meta(#[from] super::meta::Error),
    #[error("Handshake required")]
    NoHandshake,
    #[error("Requested namespace doesn't exist")]
    NamespaceDoesntExist,
    #[error("sync cancelled for terminal shutdown")]
    SyncCancelledForShutdown,
}

impl From<Status> for Error {
    fn from(status: Status) -> Self {
        if status.code() == Code::FailedPrecondition {
            match status.message() {
                NEED_SNAPSHOT_ERROR_MSG => Error::NeedSnapshot,
                NO_HELLO_ERROR_MSG => Error::NoHandshake,
                NAMESPACE_DOESNT_EXIST => Error::NamespaceDoesntExist,
                _ => Error::Client(status.into()),
            }
        } else {
            Error::Client(status.into())
        }
    }
}

impl From<tokio::task::JoinError> for Error {
    fn from(value: tokio::task::JoinError) -> Self {
        Self::Internal(value.into())
    }
}

#[async_trait::async_trait]
pub trait ReplicatorClient {
    type FrameStream: Stream<Item = Result<RpcFrame, Error>> + Unpin + Send;

    /// Perform handshake with remote
    async fn handshake(&mut self) -> Result<(), Error>;
    /// Perform handshake with remote, cooperatively observing terminal sync cancellation.
    async fn handshake_with_cancellation(
        &mut self,
        token: &CancellationToken,
    ) -> Result<(), Error> {
        tokio::select! {
            result = self.handshake() => result,
            _ = token.cancelled() => Err(Error::SyncCancelledForShutdown),
        }
    }
    /// Return a stream of frames to apply to the database
    async fn next_frames(&mut self) -> Result<Self::FrameStream, Error>;
    /// Return a stream of frames to apply to the database, cooperatively observing terminal sync cancellation.
    async fn next_frames_with_cancellation(
        &mut self,
        token: &CancellationToken,
    ) -> Result<Self::FrameStream, Error> {
        tokio::select! {
            result = self.next_frames() => result,
            _ = token.cancelled() => Err(Error::SyncCancelledForShutdown),
        }
    }
    /// Return a snapshot for the current replication index. Called after next_frame has returned a
    /// NeedSnapshot error
    async fn snapshot(&mut self) -> Result<Self::FrameStream, Error>;
    /// Return a snapshot for the current replication index, cooperatively observing terminal sync cancellation.
    async fn snapshot_with_cancellation(
        &mut self,
        token: &CancellationToken,
    ) -> Result<Self::FrameStream, Error> {
        tokio::select! {
            result = self.snapshot() => result,
            _ = token.cancelled() => Err(Error::SyncCancelledForShutdown),
        }
    }
    /// set the new commit frame_no
    async fn commit_frame_no(&mut self, frame_no: FrameNo) -> Result<(), Error>;
    /// Returns the currently committed replication index
    fn committed_frame_no(&self) -> Option<FrameNo>;
    /// rollback the client to previously committed index.
    fn rollback(&mut self);
}

#[async_trait::async_trait]
impl<A, B> ReplicatorClient for Either<A, B>
where
    A: ReplicatorClient + Send,
    B: ReplicatorClient + Send,
{
    type FrameStream = Either<A::FrameStream, B::FrameStream>;

    async fn handshake(&mut self) -> Result<(), Error> {
        match self {
            Either::Left(a) => a.handshake().await,
            Either::Right(b) => b.handshake().await,
        }
    }

    async fn handshake_with_cancellation(
        &mut self,
        token: &CancellationToken,
    ) -> Result<(), Error> {
        match self {
            Either::Left(a) => a.handshake_with_cancellation(token).await,
            Either::Right(b) => b.handshake_with_cancellation(token).await,
        }
    }

    /// Return a stream of frames to apply to the database
    async fn next_frames(&mut self) -> Result<Self::FrameStream, Error> {
        match self {
            Either::Left(a) => a.next_frames().await.map(Either::Left),
            Either::Right(b) => b.next_frames().await.map(Either::Right),
        }
    }

    async fn next_frames_with_cancellation(
        &mut self,
        token: &CancellationToken,
    ) -> Result<Self::FrameStream, Error> {
        match self {
            Either::Left(a) => a
                .next_frames_with_cancellation(token)
                .await
                .map(Either::Left),
            Either::Right(b) => b
                .next_frames_with_cancellation(token)
                .await
                .map(Either::Right),
        }
    }

    /// Return a snapshot for the current replication index. Called after next_frame has returned a
    /// NeedSnapshot error
    async fn snapshot(&mut self) -> Result<Self::FrameStream, Error> {
        match self {
            Either::Left(a) => a.snapshot().await.map(Either::Left),
            Either::Right(b) => b.snapshot().await.map(Either::Right),
        }
    }

    async fn snapshot_with_cancellation(
        &mut self,
        token: &CancellationToken,
    ) -> Result<Self::FrameStream, Error> {
        match self {
            Either::Left(a) => a.snapshot_with_cancellation(token).await.map(Either::Left),
            Either::Right(b) => b.snapshot_with_cancellation(token).await.map(Either::Right),
        }
    }
    /// set the new commit frame_no
    async fn commit_frame_no(&mut self, frame_no: FrameNo) -> Result<(), Error> {
        match self {
            Either::Left(a) => a.commit_frame_no(frame_no).await,
            Either::Right(b) => b.commit_frame_no(frame_no).await,
        }
    }

    fn committed_frame_no(&self) -> Option<FrameNo> {
        match self {
            Either::Left(a) => a.committed_frame_no(),
            Either::Right(b) => b.committed_frame_no(),
        }
    }

    fn rollback(&mut self) {
        match self {
            Either::Left(a) => a.rollback(),
            Either::Right(b) => b.rollback(),
        }
    }
}

/// The `Replicator`'s duty is to download frames from the primary, and pass them to the injector at
/// transaction boundaries.
pub struct Replicator<C, I> {
    client: C,
    injector: I,
    state: ReplicatorState,
    frames_synced: usize,
    max_handshake_retries: usize,
}

const INJECTOR_BUFFER_CAPACITY: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplicatorState {
    NeedFrames,
    NeedHandshake,
    NeedSnapshot,
    Exit,
}

impl<C> Replicator<C, SqliteInjector>
where
    C: ReplicatorClient + Send,
{
    /// Creates a replicator for the db file pointed at by `db_path`
    pub async fn new_sqlite(
        client: C,
        db_path: PathBuf,
        auto_checkpoint: u32,
        encryption_config: Option<libsql_sys::EncryptionConfig>,
    ) -> Result<Self, Error> {
        let injector = SqliteInjector::new(
            db_path.clone(),
            INJECTOR_BUFFER_CAPACITY,
            auto_checkpoint,
            encryption_config,
        )
        .await?;

        Ok(Self::new(client, injector))
    }
}

impl<C, I> Replicator<C, I>
where
    C: ReplicatorClient + Send,
    I: Injector,
{
    pub fn new(client: C, injector: I) -> Self {
        Self {
            client,
            injector,
            state: ReplicatorState::NeedHandshake,
            frames_synced: 0,
            max_handshake_retries: HANDSHAKE_MAX_RETRIES,
        }
    }

    /// force a handshake on next call to replicate.
    pub fn force_handshake(&mut self) {
        self.state = ReplicatorState::NeedHandshake;
    }

    /// configure number of handshake retries.
    pub fn set_primary_handshake_retries(&mut self, retries: usize) {
        self.max_handshake_retries = retries;
    }

    pub fn client_mut(&mut self) -> &mut C {
        &mut self.client
    }

    /// Runs replicate in a loop until an error is returned
    pub async fn run(&mut self) -> Error {
        loop {
            if let Err(e) = self.replicate().await {
                return e;
            }
        }
    }

    pub async fn try_perform_handshake(&mut self) -> Result<(), Error> {
        let mut error_printed = false;
        for _ in 0..self.max_handshake_retries {
            tracing::debug!("Attempting to perform handshake with primary.");
            match self.client.handshake().await {
                Ok(_) => {
                    self.state = ReplicatorState::NeedFrames;
                    return Ok(());
                }
                Err(Error::Client(e)) if !error_printed => {
                    if e.downcast_ref::<uuid::Error>().is_some() {
                        tracing::warn!("error connecting to primary. retrying. Verify that the libsql server version is `>=0.22` error: {e}");
                    } else {
                        tracing::warn!("error connecting to primary. retrying. error: {e}");
                    }

                    error_printed = true;
                }
                Err(Error::Client(_)) if error_printed => (),
                Err(e) => return Err(e),
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        Err(Error::PrimaryHandshakeTimeout)
    }

    pub async fn replicate(&mut self) -> Result<(), Error> {
        loop {
            self.try_replicate_step().await?;
            if self.state == ReplicatorState::Exit {
                self.state = ReplicatorState::NeedFrames;
                return Ok(());
            }
        }
    }

    pub async fn replicate_with_cancellation(
        &mut self,
        token: &CancellationToken,
    ) -> Result<(), Error> {
        loop {
            self.try_replicate_step_with_cancellation(token).await?;
            if self.state == ReplicatorState::Exit {
                self.state = ReplicatorState::NeedFrames;
                return Ok(());
            }
        }
    }

    async fn try_replicate_step(&mut self) -> Result<(), Error> {
        self.try_replicate_step_inner(None).await
    }

    async fn try_replicate_step_with_cancellation(
        &mut self,
        token: &CancellationToken,
    ) -> Result<(), Error> {
        self.try_replicate_step_inner(Some(token)).await
    }

    async fn try_replicate_step_inner(
        &mut self,
        token: Option<&CancellationToken>,
    ) -> Result<(), Error> {
        let state = self.state;
        let ret = match (state, token) {
            (ReplicatorState::NeedHandshake, Some(token)) => {
                self.try_perform_handshake_with_cancellation(token).await
            }
            (ReplicatorState::NeedHandshake, None) => self.try_perform_handshake().await,
            (ReplicatorState::NeedFrames, Some(token)) => {
                self.try_replicate_with_cancellation(token).await
            }
            (ReplicatorState::NeedFrames, None) => self.try_replicate().await,
            (ReplicatorState::NeedSnapshot, Some(token)) => {
                self.load_snapshot_with_cancellation(token).await
            }
            (ReplicatorState::NeedSnapshot, None) => self.load_snapshot().await,
            (ReplicatorState::Exit, _) => unreachable!("trying to step replicator on exit"),
        };

        // in case of error we rollback the current injector transaction, and start over.
        if ret.is_err() {
            if matches!(ret, Err(Error::SyncCancelledForShutdown)) {
                tracing::info!("sync_cancellation_rollback_started");
            }
            self.client.rollback();
            self.injector.rollback().await;
            if matches!(ret, Err(Error::SyncCancelledForShutdown)) {
                tracing::info!("sync_cancellation_rollback_finished");
            }
        }

        self.state = match ret {
            // perform normal operation state transition
            Ok(()) => match state {
                ReplicatorState::Exit => unreachable!(),
                ReplicatorState::NeedFrames => ReplicatorState::Exit,
                ReplicatorState::NeedSnapshot | ReplicatorState::NeedHandshake => {
                    ReplicatorState::NeedFrames
                }
            },
            Err(Error::NoHandshake) => {
                if state == ReplicatorState::NeedHandshake {
                    return Err(Error::Fatal(
                        "Received handshake error while performing handshake".into(),
                    ));
                }
                ReplicatorState::NeedHandshake
            }
            Err(Error::NeedSnapshot) => ReplicatorState::NeedSnapshot,
            Err(e) => {
                // an error here could be due to a disconnection, it's safe to rollback to a
                // NeedHandshake state again, to avoid entering a busy loop.
                self.state = ReplicatorState::NeedHandshake;
                return Err(e);
            }
        };

        Ok(())
    }

    async fn try_perform_handshake_with_cancellation(
        &mut self,
        token: &CancellationToken,
    ) -> Result<(), Error> {
        let mut error_printed = false;
        for _ in 0..self.max_handshake_retries {
            if token.is_cancelled() {
                tracing::info!("sync_cancelled_during_handshake");
                return Err(Error::SyncCancelledForShutdown);
            }

            tracing::debug!("Attempting to perform handshake with primary.");
            match self.client.handshake_with_cancellation(token).await {
                Ok(_) => {
                    self.state = ReplicatorState::NeedFrames;
                    return Ok(());
                }
                Err(Error::Client(e)) if !error_printed => {
                    if e.downcast_ref::<uuid::Error>().is_some() {
                        tracing::warn!("error connecting to primary. retrying. Verify that the libsql server version is `>=0.22` error: {e}");
                    } else {
                        tracing::warn!("error connecting to primary. retrying. error: {e}");
                    }

                    error_printed = true;
                }
                Err(Error::Client(_)) if error_printed => (),
                Err(Error::SyncCancelledForShutdown) => {
                    tracing::info!("sync_cancelled_during_handshake");
                    return Err(Error::SyncCancelledForShutdown);
                }
                Err(e) => return Err(e),
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(1)) => {},
                _ = token.cancelled() => {
                    tracing::info!("sync_cancelled_during_handshake");
                    return Err(Error::SyncCancelledForShutdown);
                }
            }
        }

        Err(Error::PrimaryHandshakeTimeout)
    }

    async fn try_replicate(&mut self) -> Result<(), Error> {
        let mut stream = self.client.next_frames().await?;

        while let Some(frame) = stream.next().await.transpose()? {
            self.inject_frame(frame).await?;
        }

        Ok(())
    }

    async fn try_replicate_with_cancellation(
        &mut self,
        token: &CancellationToken,
    ) -> Result<(), Error> {
        if token.is_cancelled() {
            tracing::info!("sync_cancelled_during_frame_fetch");
            return Err(Error::SyncCancelledForShutdown);
        }
        let mut stream = self.client.next_frames_with_cancellation(token).await?;

        loop {
            let next = tokio::select! {
                next = stream.next() => next,
                _ = token.cancelled() => {
                    tracing::info!("sync_cancelled_during_frame_fetch");
                    return Err(Error::SyncCancelledForShutdown);
                }
            };

            let Some(frame) = next.transpose()? else {
                if token.is_cancelled() {
                    tracing::info!("sync_cancelled_during_frame_fetch");
                    return Err(Error::SyncCancelledForShutdown);
                }
                break;
            };
            self.inject_frame_with_cancellation(frame, token).await?;
        }

        if token.is_cancelled() {
            tracing::info!("sync_cancelled_during_frame_fetch");
            return Err(Error::SyncCancelledForShutdown);
        }

        Ok(())
    }

    async fn load_snapshot(&mut self) -> Result<(), Error> {
        self.client.rollback();
        self.injector.rollback().await;
        loop {
            match self.client.snapshot().await {
                Ok(mut stream) => {
                    while let Some(frame) = stream.next().await {
                        let frame = frame?;
                        self.inject_frame(frame).await?;
                    }
                    return Ok(());
                }
                Err(Error::SnapshotPending) => {
                    tracing::info!("snapshot not ready yet, waiting 1s...");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Err(e) => return Err(e),
            }
        }
    }

    async fn load_snapshot_with_cancellation(
        &mut self,
        token: &CancellationToken,
    ) -> Result<(), Error> {
        self.client.rollback();
        self.injector.rollback().await;
        loop {
            if token.is_cancelled() {
                tracing::info!("sync_cancelled_during_snapshot_fetch");
                return Err(Error::SyncCancelledForShutdown);
            }

            match self.client.snapshot_with_cancellation(token).await {
                Ok(mut stream) => loop {
                    let next = tokio::select! {
                        next = stream.next() => next,
                        _ = token.cancelled() => {
                            tracing::info!("sync_cancelled_during_snapshot_stream");
                            return Err(Error::SyncCancelledForShutdown);
                        }
                    };

                    let Some(frame) = next else {
                        if token.is_cancelled() {
                            tracing::info!("sync_cancelled_during_snapshot_stream");
                            return Err(Error::SyncCancelledForShutdown);
                        }
                        return Ok(());
                    };
                    self.inject_frame_with_cancellation(frame?, token).await?;
                },
                Err(Error::SnapshotPending) => {
                    tracing::info!("snapshot not ready yet, waiting 1s...");
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(1)) => {},
                        _ = token.cancelled() => {
                            tracing::info!("sync_cancelled_during_snapshot_fetch");
                            return Err(Error::SyncCancelledForShutdown);
                        }
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    async fn inject_frame(&mut self, frame: RpcFrame) -> Result<(), Error> {
        self.frames_synced += 1;

        if let Some(frame_no) = frame.durable_frame_no {
            self.injector.durable_frame_no(frame_no);
        }

        if let Some(commit_fno) = self.injector.inject_frame(frame).await? {
            self.client.commit_frame_no(commit_fno).await?;
        }

        Ok(())
    }

    async fn inject_frame_with_cancellation(
        &mut self,
        frame: RpcFrame,
        token: &CancellationToken,
    ) -> Result<(), Error> {
        if token.is_cancelled() {
            tracing::info!("sync_cancelled_during_injection");
            return Err(Error::SyncCancelledForShutdown);
        }

        self.frames_synced += 1;

        if let Some(frame_no) = frame.durable_frame_no {
            self.injector.durable_frame_no(frame_no);
        }

        match self
            .injector
            .inject_frame_with_cancellation(frame, token)
            .await
        {
            Ok(Some(commit_fno)) => {
                self.client.commit_frame_no(commit_fno).await?;
            }
            Ok(None) => (),
            Err(crate::injector::Error::SyncCancelledForShutdown) => {
                tracing::info!("sync_cancelled_during_injection");
                return Err(Error::SyncCancelledForShutdown);
            }
            Err(e) => return Err(e.into()),
        }

        if token.is_cancelled() {
            tracing::info!("sync_cancelled_during_injection");
            return Err(Error::SyncCancelledForShutdown);
        }

        Ok(())
    }

    pub async fn flush(&mut self) -> Result<(), Error> {
        if let Some(commit_fno) = self.injector.flush().await? {
            self.client.commit_frame_no(commit_fno).await?;
        }

        Ok(())
    }

    pub fn frames_synced(&self) -> usize {
        self.frames_synced
    }
}

/// Helper function to convert rpc frames results to replicator frames
pub fn map_frame_err(f: Result<RpcFrame, Status>) -> Result<Frame, Error> {
    let frame = f?;
    Frame::try_from(&*frame.data).map_err(|e| Error::Client(e.into()))
}

#[cfg(test)]
mod test {
    use std::{
        mem::size_of,
        pin::Pin,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        },
    };

    use async_stream::stream;

    use crate::frame::{FrameBorrowed, FrameMut};
    use crate::rpc::replication::Frame as RpcFrame;

    use super::*;

    struct BlockingInjector {
        inject_called: Arc<AtomicBool>,
        rolled_back: Arc<AtomicBool>,
    }

    impl BlockingInjector {
        fn new() -> Self {
            Self {
                inject_called: Arc::new(AtomicBool::new(false)),
                rolled_back: Arc::new(AtomicBool::new(false)),
            }
        }
    }

    impl Injector for BlockingInjector {
        async fn inject_frame(
            &mut self,
            _frame: RpcFrame,
        ) -> std::result::Result<Option<FrameNo>, crate::injector::Error> {
            Ok(None)
        }

        async fn inject_frame_with_cancellation(
            &mut self,
            _frame: RpcFrame,
            token: &CancellationToken,
        ) -> std::result::Result<Option<FrameNo>, crate::injector::Error> {
            self.inject_called.store(true, Ordering::SeqCst);
            token.cancelled().await;
            Err(crate::injector::Error::SyncCancelledForShutdown)
        }

        async fn rollback(&mut self) {
            self.rolled_back.store(true, Ordering::SeqCst);
        }

        async fn flush(&mut self) -> std::result::Result<Option<FrameNo>, crate::injector::Error> {
            Ok(None)
        }

        fn durable_frame_no(&mut self, _frame_no: u64) {}
    }

    #[tokio::test]
    async fn cancellation_while_waiting_for_handshake_rolls_back() {
        struct Client {
            rolled_back: Arc<AtomicBool>,
        }

        #[async_trait::async_trait]
        impl ReplicatorClient for Client {
            type FrameStream =
                Pin<Box<dyn Stream<Item = Result<RpcFrame, Error>> + Send + 'static>>;

            async fn handshake(&mut self) -> Result<(), Error> {
                std::future::pending().await
            }

            async fn next_frames(&mut self) -> Result<Self::FrameStream, Error> {
                unreachable!()
            }

            async fn snapshot(&mut self) -> Result<Self::FrameStream, Error> {
                unreachable!()
            }

            async fn commit_frame_no(&mut self, _frame_no: FrameNo) -> Result<(), Error> {
                unreachable!()
            }

            fn committed_frame_no(&self) -> Option<FrameNo> {
                None
            }

            fn rollback(&mut self) {
                self.rolled_back.store(true, Ordering::SeqCst);
            }
        }

        let token = CancellationToken::new();
        let client_rolled_back = Arc::new(AtomicBool::new(false));
        let injector = BlockingInjector::new();
        let injector_rolled_back = injector.rolled_back.clone();
        let mut replicator = Replicator::new(
            Client {
                rolled_back: client_rolled_back.clone(),
            },
            injector,
        );
        replicator.state = ReplicatorState::NeedHandshake;

        let cancel = token.clone();
        let (result, _) = tokio::join!(
            async {
                replicator
                    .try_replicate_step_with_cancellation(&token)
                    .await
            },
            async {
                tokio::task::yield_now().await;
                cancel.cancel();
            }
        );

        assert!(matches!(
            result.unwrap_err(),
            Error::SyncCancelledForShutdown
        ));
        assert!(client_rolled_back.load(Ordering::SeqCst));
        assert!(injector_rolled_back.load(Ordering::SeqCst));
        assert_eq!(replicator.state, ReplicatorState::NeedHandshake);
    }

    #[tokio::test]
    async fn cancellation_during_injection_waits_and_rolls_back() {
        struct Client {
            rolled_back: Arc<AtomicBool>,
        }

        #[async_trait::async_trait]
        impl ReplicatorClient for Client {
            type FrameStream =
                Pin<Box<dyn Stream<Item = Result<RpcFrame, Error>> + Send + 'static>>;

            async fn handshake(&mut self) -> Result<(), Error> {
                Ok(())
            }

            async fn next_frames(&mut self) -> Result<Self::FrameStream, Error> {
                Ok(Box::pin(tokio_stream::iter([Ok(RpcFrame {
                    data: Vec::new().into(),
                    timestamp: None,
                    durable_frame_no: None,
                })])))
            }

            async fn snapshot(&mut self) -> Result<Self::FrameStream, Error> {
                unreachable!()
            }

            async fn commit_frame_no(&mut self, _frame_no: FrameNo) -> Result<(), Error> {
                Ok(())
            }

            fn committed_frame_no(&self) -> Option<FrameNo> {
                None
            }

            fn rollback(&mut self) {
                self.rolled_back.store(true, Ordering::SeqCst);
            }
        }

        let token = CancellationToken::new();
        let client_rolled_back = Arc::new(AtomicBool::new(false));
        let injector = BlockingInjector::new();
        let inject_called = injector.inject_called.clone();
        let injector_rolled_back = injector.rolled_back.clone();
        let mut replicator = Replicator::new(
            Client {
                rolled_back: client_rolled_back.clone(),
            },
            injector,
        );
        replicator.state = ReplicatorState::NeedFrames;

        let cancel = token.clone();
        let (result, _) = tokio::join!(
            async {
                replicator
                    .try_replicate_step_with_cancellation(&token)
                    .await
            },
            async {
                tokio::time::timeout(Duration::from_secs(5), async {
                    while !inject_called.load(Ordering::SeqCst) {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("inject_frame_with_cancellation was not called");
                cancel.cancel();
            }
        );

        assert!(matches!(
            result.unwrap_err(),
            Error::SyncCancelledForShutdown
        ));
        assert!(client_rolled_back.load(Ordering::SeqCst));
        assert!(injector_rolled_back.load(Ordering::SeqCst));
        assert_eq!(replicator.state, ReplicatorState::NeedHandshake);
    }

    struct SuccessfulAfterCancelInjector {
        inject_called: Arc<AtomicBool>,
        rolled_back: Arc<AtomicBool>,
    }

    impl SuccessfulAfterCancelInjector {
        fn new() -> Self {
            Self {
                inject_called: Arc::new(AtomicBool::new(false)),
                rolled_back: Arc::new(AtomicBool::new(false)),
            }
        }
    }

    impl Injector for SuccessfulAfterCancelInjector {
        async fn inject_frame(
            &mut self,
            _frame: RpcFrame,
        ) -> std::result::Result<Option<FrameNo>, crate::injector::Error> {
            Ok(None)
        }

        async fn inject_frame_with_cancellation(
            &mut self,
            _frame: RpcFrame,
            token: &CancellationToken,
        ) -> std::result::Result<Option<FrameNo>, crate::injector::Error> {
            self.inject_called.store(true, Ordering::SeqCst);
            token.cancel();
            Ok(None)
        }

        async fn rollback(&mut self) {
            self.rolled_back.store(true, Ordering::SeqCst);
        }

        async fn flush(&mut self) -> std::result::Result<Option<FrameNo>, crate::injector::Error> {
            Ok(None)
        }

        fn durable_frame_no(&mut self, _frame_no: u64) {}
    }

    #[tokio::test]
    async fn cancellation_after_successful_injection_is_not_swallowed() {
        struct Client {
            rolled_back: Arc<AtomicBool>,
        }

        #[async_trait::async_trait]
        impl ReplicatorClient for Client {
            type FrameStream =
                Pin<Box<dyn Stream<Item = Result<RpcFrame, Error>> + Send + 'static>>;

            async fn handshake(&mut self) -> Result<(), Error> {
                Ok(())
            }

            async fn next_frames(&mut self) -> Result<Self::FrameStream, Error> {
                Ok(Box::pin(tokio_stream::iter([Ok(RpcFrame {
                    data: Vec::new().into(),
                    timestamp: None,
                    durable_frame_no: None,
                })])))
            }

            async fn snapshot(&mut self) -> Result<Self::FrameStream, Error> {
                unreachable!()
            }

            async fn commit_frame_no(&mut self, _frame_no: FrameNo) -> Result<(), Error> {
                Ok(())
            }

            fn committed_frame_no(&self) -> Option<FrameNo> {
                None
            }

            fn rollback(&mut self) {
                self.rolled_back.store(true, Ordering::SeqCst);
            }
        }

        let token = CancellationToken::new();
        let client_rolled_back = Arc::new(AtomicBool::new(false));
        let injector = SuccessfulAfterCancelInjector::new();
        let inject_called = injector.inject_called.clone();
        let injector_rolled_back = injector.rolled_back.clone();
        let mut replicator = Replicator::new(
            Client {
                rolled_back: client_rolled_back.clone(),
            },
            injector,
        );
        replicator.state = ReplicatorState::NeedFrames;

        let result = replicator
            .try_replicate_step_with_cancellation(&token)
            .await;

        assert!(inject_called.load(Ordering::SeqCst));
        assert!(matches!(
            result.unwrap_err(),
            Error::SyncCancelledForShutdown
        ));
        assert!(client_rolled_back.load(Ordering::SeqCst));
        assert!(injector_rolled_back.load(Ordering::SeqCst));
        assert_eq!(replicator.state, ReplicatorState::NeedHandshake);
    }

    #[tokio::test]
    async fn cancellation_while_waiting_for_frame_fetch_rolls_back() {
        struct Client {
            rolled_back: Arc<AtomicBool>,
        }

        #[async_trait::async_trait]
        impl ReplicatorClient for Client {
            type FrameStream =
                Pin<Box<dyn Stream<Item = Result<RpcFrame, Error>> + Send + 'static>>;

            async fn handshake(&mut self) -> Result<(), Error> {
                Ok(())
            }

            async fn next_frames(&mut self) -> Result<Self::FrameStream, Error> {
                std::future::pending().await
            }

            async fn snapshot(&mut self) -> Result<Self::FrameStream, Error> {
                unreachable!()
            }

            async fn commit_frame_no(&mut self, _frame_no: FrameNo) -> Result<(), Error> {
                unreachable!()
            }

            fn committed_frame_no(&self) -> Option<FrameNo> {
                None
            }

            fn rollback(&mut self) {
                self.rolled_back.store(true, Ordering::SeqCst);
            }
        }

        let token = CancellationToken::new();
        let client_rolled_back = Arc::new(AtomicBool::new(false));
        let injector = BlockingInjector::new();
        let injector_rolled_back = injector.rolled_back.clone();
        let mut replicator = Replicator::new(
            Client {
                rolled_back: client_rolled_back.clone(),
            },
            injector,
        );
        replicator.state = ReplicatorState::NeedFrames;

        let cancel = token.clone();
        let (result, _) = tokio::join!(
            async {
                replicator
                    .try_replicate_step_with_cancellation(&token)
                    .await
            },
            async {
                tokio::task::yield_now().await;
                cancel.cancel();
            }
        );

        assert!(matches!(
            result.unwrap_err(),
            Error::SyncCancelledForShutdown
        ));
        assert!(client_rolled_back.load(Ordering::SeqCst));
        assert!(injector_rolled_back.load(Ordering::SeqCst));
        assert_eq!(replicator.state, ReplicatorState::NeedHandshake);
    }

    #[tokio::test]
    async fn cancellation_while_snapshot_request_pending_rolls_back() {
        struct Client {
            rolled_back: Arc<AtomicBool>,
        }

        #[async_trait::async_trait]
        impl ReplicatorClient for Client {
            type FrameStream =
                Pin<Box<dyn Stream<Item = Result<RpcFrame, Error>> + Send + 'static>>;

            async fn handshake(&mut self) -> Result<(), Error> {
                unreachable!()
            }

            async fn next_frames(&mut self) -> Result<Self::FrameStream, Error> {
                unreachable!()
            }

            async fn snapshot(&mut self) -> Result<Self::FrameStream, Error> {
                std::future::pending().await
            }

            async fn commit_frame_no(&mut self, _frame_no: FrameNo) -> Result<(), Error> {
                unreachable!()
            }

            fn committed_frame_no(&self) -> Option<FrameNo> {
                None
            }

            fn rollback(&mut self) {
                self.rolled_back.store(true, Ordering::SeqCst);
            }
        }

        let token = CancellationToken::new();
        let client_rolled_back = Arc::new(AtomicBool::new(false));
        let injector = BlockingInjector::new();
        let injector_rolled_back = injector.rolled_back.clone();
        let mut replicator = Replicator::new(
            Client {
                rolled_back: client_rolled_back.clone(),
            },
            injector,
        );
        replicator.state = ReplicatorState::NeedSnapshot;

        let cancel = token.clone();
        let (result, _) = tokio::join!(
            async {
                replicator
                    .try_replicate_step_with_cancellation(&token)
                    .await
            },
            async {
                tokio::task::yield_now().await;
                cancel.cancel();
            }
        );

        assert!(matches!(
            result.unwrap_err(),
            Error::SyncCancelledForShutdown
        ));
        assert!(client_rolled_back.load(Ordering::SeqCst));
        assert!(injector_rolled_back.load(Ordering::SeqCst));
        assert_eq!(replicator.state, ReplicatorState::NeedHandshake);
    }

    #[tokio::test]
    async fn cancellation_while_snapshot_pending_sleep_rolls_back() {
        struct Client {
            rolled_back: Arc<AtomicBool>,
            calls: Arc<AtomicUsize>,
        }

        #[async_trait::async_trait]
        impl ReplicatorClient for Client {
            type FrameStream =
                Pin<Box<dyn Stream<Item = Result<RpcFrame, Error>> + Send + 'static>>;

            async fn handshake(&mut self) -> Result<(), Error> {
                unreachable!()
            }

            async fn next_frames(&mut self) -> Result<Self::FrameStream, Error> {
                unreachable!()
            }

            async fn snapshot(&mut self) -> Result<Self::FrameStream, Error> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Err(Error::SnapshotPending)
            }

            async fn commit_frame_no(&mut self, _frame_no: FrameNo) -> Result<(), Error> {
                unreachable!()
            }

            fn committed_frame_no(&self) -> Option<FrameNo> {
                None
            }

            fn rollback(&mut self) {
                self.rolled_back.store(true, Ordering::SeqCst);
            }
        }

        let token = CancellationToken::new();
        let client_rolled_back = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(AtomicUsize::new(0));
        let injector = BlockingInjector::new();
        let injector_rolled_back = injector.rolled_back.clone();
        let mut replicator = Replicator::new(
            Client {
                rolled_back: client_rolled_back.clone(),
                calls: calls.clone(),
            },
            injector,
        );
        replicator.state = ReplicatorState::NeedSnapshot;

        let cancel = token.clone();
        let (result, _) = tokio::join!(
            async {
                replicator
                    .try_replicate_step_with_cancellation(&token)
                    .await
            },
            async {
                tokio::time::timeout(Duration::from_secs(5), async {
                    while calls.load(Ordering::SeqCst) == 0 {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("snapshot was not requested");
                cancel.cancel();
            }
        );

        assert!(matches!(
            result.unwrap_err(),
            Error::SyncCancelledForShutdown
        ));
        assert!(client_rolled_back.load(Ordering::SeqCst));
        assert!(injector_rolled_back.load(Ordering::SeqCst));
        assert_eq!(replicator.state, ReplicatorState::NeedHandshake);
    }

    #[tokio::test]
    async fn cancellation_while_snapshot_stream_pending_rolls_back() {
        struct Client {
            rolled_back: Arc<AtomicBool>,
        }

        #[async_trait::async_trait]
        impl ReplicatorClient for Client {
            type FrameStream =
                Pin<Box<dyn Stream<Item = Result<RpcFrame, Error>> + Send + 'static>>;

            async fn handshake(&mut self) -> Result<(), Error> {
                unreachable!()
            }

            async fn next_frames(&mut self) -> Result<Self::FrameStream, Error> {
                unreachable!()
            }

            async fn snapshot(&mut self) -> Result<Self::FrameStream, Error> {
                Ok(Box::pin(stream! {
                    std::future::pending::<()>().await;
                    yield Ok(RpcFrame {
                        data: Vec::new().into(),
                        timestamp: None,
                        durable_frame_no: None,
                    });
                }))
            }

            async fn commit_frame_no(&mut self, _frame_no: FrameNo) -> Result<(), Error> {
                unreachable!()
            }

            fn committed_frame_no(&self) -> Option<FrameNo> {
                None
            }

            fn rollback(&mut self) {
                self.rolled_back.store(true, Ordering::SeqCst);
            }
        }

        let token = CancellationToken::new();
        let client_rolled_back = Arc::new(AtomicBool::new(false));
        let injector = BlockingInjector::new();
        let injector_rolled_back = injector.rolled_back.clone();
        let mut replicator = Replicator::new(
            Client {
                rolled_back: client_rolled_back.clone(),
            },
            injector,
        );
        replicator.state = ReplicatorState::NeedSnapshot;

        let cancel = token.clone();
        let (result, _) = tokio::join!(
            async {
                replicator
                    .try_replicate_step_with_cancellation(&token)
                    .await
            },
            async {
                tokio::task::yield_now().await;
                cancel.cancel();
            }
        );

        assert!(matches!(
            result.unwrap_err(),
            Error::SyncCancelledForShutdown
        ));
        assert!(client_rolled_back.load(Ordering::SeqCst));
        assert!(injector_rolled_back.load(Ordering::SeqCst));
        assert_eq!(replicator.state, ReplicatorState::NeedHandshake);
    }

    #[tokio::test]
    async fn handshake_error_namespace_doesnt_exist() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        struct Client;

        #[async_trait::async_trait]
        impl ReplicatorClient for Client {
            type FrameStream =
                Pin<Box<dyn Stream<Item = Result<RpcFrame, Error>> + Send + 'static>>;

            /// Perform handshake with remote
            async fn handshake(&mut self) -> Result<(), Error> {
                Err(Error::NamespaceDoesntExist)
            }
            /// Return a stream of frames to apply to the database
            async fn next_frames(&mut self) -> Result<Self::FrameStream, Error> {
                unreachable!()
            }
            /// Return a snapshot for the current replication index. Called after next_frame has returned a
            /// NeedSnapshot error
            async fn snapshot(&mut self) -> Result<Self::FrameStream, Error> {
                unreachable!()
            }
            /// set the new commit frame_no
            async fn commit_frame_no(&mut self, _frame_no: FrameNo) -> Result<(), Error> {
                unreachable!()
            }
            /// Returns the currently committed replication index
            fn committed_frame_no(&self) -> Option<FrameNo> {
                unreachable!()
            }

            fn rollback(&mut self) {}
        }

        let mut replicator = Replicator::new_sqlite(Client, tmp.path().to_path_buf(), 10000, None)
            .await
            .unwrap();

        assert!(matches!(
            replicator.try_replicate_step().await.unwrap_err(),
            Error::NamespaceDoesntExist
        ));
    }

    #[tokio::test]
    async fn no_handshake_error_in_next_frame() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        struct Client;

        #[async_trait::async_trait]
        impl ReplicatorClient for Client {
            type FrameStream =
                Pin<Box<dyn Stream<Item = Result<RpcFrame, Error>> + Send + 'static>>;

            /// Perform handshake with remote
            async fn handshake(&mut self) -> Result<(), Error> {
                unimplemented!()
            }
            /// Return a stream of frames to apply to the database
            async fn next_frames(&mut self) -> Result<Self::FrameStream, Error> {
                Err(Error::NoHandshake)
            }
            /// Return a snapshot for the current replication index. Called after next_frame has returned a
            /// NeedSnapshot error
            async fn snapshot(&mut self) -> Result<Self::FrameStream, Error> {
                unreachable!()
            }
            /// set the new commit frame_no
            async fn commit_frame_no(&mut self, _frame_no: FrameNo) -> Result<(), Error> {
                unreachable!()
            }
            /// Returns the currently committed replication index
            fn committed_frame_no(&self) -> Option<FrameNo> {
                unreachable!()
            }
            fn rollback(&mut self) {}
        }

        let mut replicator = Replicator::new_sqlite(Client, tmp.path().to_path_buf(), 10000, None)
            .await
            .unwrap();
        // we assume that we already received the handshake and the handshake is not valid anymore
        replicator.state = ReplicatorState::NeedFrames;
        replicator.try_replicate_step().await.unwrap();
        assert_eq!(replicator.state, ReplicatorState::NeedHandshake);
    }

    #[tokio::test]
    async fn stream_frame_returns_handshake_error() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        struct Client;

        #[async_trait::async_trait]
        impl ReplicatorClient for Client {
            type FrameStream =
                Pin<Box<dyn Stream<Item = Result<RpcFrame, Error>> + Send + 'static>>;

            /// Perform handshake with remote
            async fn handshake(&mut self) -> Result<(), Error> {
                unimplemented!()
            }
            /// Return a stream of frames to apply to the database
            async fn next_frames(&mut self) -> Result<Self::FrameStream, Error> {
                Ok(Box::pin(stream! {
                    yield Err(Error::NoHandshake);
                }))
            }
            /// Return a snapshot for the current replication index. Called after next_frame has returned a
            /// NeedSnapshot error
            async fn snapshot(&mut self) -> Result<Self::FrameStream, Error> {
                unreachable!()
            }
            /// set the new commit frame_no
            async fn commit_frame_no(&mut self, _frame_no: FrameNo) -> Result<(), Error> {
                unreachable!()
            }
            /// Returns the currently committed replication index
            fn committed_frame_no(&self) -> Option<FrameNo> {
                unreachable!()
            }
            fn rollback(&mut self) {}
        }

        let mut replicator = Replicator::new_sqlite(Client, tmp.path().to_path_buf(), 10000, None)
            .await
            .unwrap();
        // we assume that we already received the handshake and the handshake is not valid anymore
        replicator.state = ReplicatorState::NeedFrames;
        replicator.try_replicate_step().await.unwrap();
        assert_eq!(replicator.state, ReplicatorState::NeedHandshake);
    }

    #[tokio::test]
    async fn stream_frame_returns_need_snapshot() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        struct Client;

        #[async_trait::async_trait]
        impl ReplicatorClient for Client {
            type FrameStream =
                Pin<Box<dyn Stream<Item = Result<RpcFrame, Error>> + Send + 'static>>;

            /// Perform handshake with remote
            async fn handshake(&mut self) -> Result<(), Error> {
                unimplemented!()
            }
            /// Return a stream of frames to apply to the database
            async fn next_frames(&mut self) -> Result<Self::FrameStream, Error> {
                Ok(Box::pin(stream! {
                    yield Err(Error::NeedSnapshot);
                }))
            }
            /// Return a snapshot for the current replication index. Called after next_frame has returned a
            /// NeedSnapshot error
            async fn snapshot(&mut self) -> Result<Self::FrameStream, Error> {
                unreachable!()
            }
            /// set the new commit frame_no
            async fn commit_frame_no(&mut self, _frame_no: FrameNo) -> Result<(), Error> {
                unreachable!()
            }
            /// Returns the currently committed replication index
            fn committed_frame_no(&self) -> Option<FrameNo> {
                unreachable!()
            }
            fn rollback(&mut self) {}
        }

        let mut replicator = Replicator::new_sqlite(Client, tmp.path().to_path_buf(), 10000, None)
            .await
            .unwrap();
        // we assume that we already received the handshake and the handshake is not valid anymore
        replicator.state = ReplicatorState::NeedFrames;
        replicator.try_replicate_step().await.unwrap();
        assert_eq!(replicator.state, ReplicatorState::NeedSnapshot);
    }

    #[tokio::test]
    async fn next_frames_returns_need_snapshot() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        struct Client;

        #[async_trait::async_trait]
        impl ReplicatorClient for Client {
            type FrameStream =
                Pin<Box<dyn Stream<Item = Result<RpcFrame, Error>> + Send + 'static>>;

            /// Perform handshake with remote
            async fn handshake(&mut self) -> Result<(), Error> {
                unimplemented!()
            }
            /// Return a stream of frames to apply to the database
            async fn next_frames(&mut self) -> Result<Self::FrameStream, Error> {
                Err(Error::NeedSnapshot)
            }
            /// Return a snapshot for the current replication index. Called after next_frame has returned a
            /// NeedSnapshot error
            async fn snapshot(&mut self) -> Result<Self::FrameStream, Error> {
                unreachable!()
            }
            /// set the new commit frame_no
            async fn commit_frame_no(&mut self, _frame_no: FrameNo) -> Result<(), Error> {
                unreachable!()
            }
            /// Returns the currently committed replication index
            fn committed_frame_no(&self) -> Option<FrameNo> {
                unreachable!()
            }
            fn rollback(&mut self) {}
        }

        let mut replicator = Replicator::new_sqlite(Client, tmp.path().to_path_buf(), 10000, None)
            .await
            .unwrap();
        // we assume that we already received the handshake and the handshake is not valid anymore
        replicator.state = ReplicatorState::NeedFrames;
        replicator.try_replicate_step().await.unwrap();
        assert_eq!(replicator.state, ReplicatorState::NeedSnapshot);
    }

    #[tokio::test]
    async fn load_snapshot_returns_need_handshake() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        struct Client;

        #[async_trait::async_trait]
        impl ReplicatorClient for Client {
            type FrameStream =
                Pin<Box<dyn Stream<Item = Result<RpcFrame, Error>> + Send + 'static>>;

            /// Perform handshake with remote
            async fn handshake(&mut self) -> Result<(), Error> {
                unimplemented!()
            }
            /// Return a stream of frames to apply to the database
            async fn next_frames(&mut self) -> Result<Self::FrameStream, Error> {
                unimplemented!()
            }
            /// Return a snapshot for the current replication index. Called after next_frame has returned a
            /// NeedSnapshot error
            async fn snapshot(&mut self) -> Result<Self::FrameStream, Error> {
                Err(Error::NoHandshake)
            }
            /// set the new commit frame_no
            async fn commit_frame_no(&mut self, _frame_no: FrameNo) -> Result<(), Error> {
                unreachable!()
            }
            /// Returns the currently committed replication index
            fn committed_frame_no(&self) -> Option<FrameNo> {
                unreachable!()
            }
            fn rollback(&mut self) {}
        }

        let mut replicator = Replicator::new_sqlite(Client, tmp.path().to_path_buf(), 10000, None)
            .await
            .unwrap();
        replicator.state = ReplicatorState::NeedSnapshot;
        replicator.try_replicate_step().await.unwrap();
        assert_eq!(replicator.state, ReplicatorState::NeedHandshake);
    }

    #[tokio::test]
    async fn load_snapshot_stream_returns_need_handshake() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        struct Client;

        #[async_trait::async_trait]
        impl ReplicatorClient for Client {
            type FrameStream =
                Pin<Box<dyn Stream<Item = Result<RpcFrame, Error>> + Send + 'static>>;

            /// Perform handshake with remote
            async fn handshake(&mut self) -> Result<(), Error> {
                unimplemented!()
            }
            /// Return a stream of frames to apply to the database
            async fn next_frames(&mut self) -> Result<Self::FrameStream, Error> {
                unimplemented!()
            }
            /// Return a snapshot for the current replication index. Called after next_frame has returned a
            /// NeedSnapshot error
            async fn snapshot(&mut self) -> Result<Self::FrameStream, Error> {
                Ok(Box::pin(stream! {
                    yield Err(Error::NoHandshake)
                }))
            }
            /// set the new commit frame_no
            async fn commit_frame_no(&mut self, _frame_no: FrameNo) -> Result<(), Error> {
                unreachable!()
            }
            /// Returns the currently committed replication index
            fn committed_frame_no(&self) -> Option<FrameNo> {
                unreachable!()
            }
            fn rollback(&mut self) {}
        }

        let mut replicator = Replicator::new_sqlite(Client, tmp.path().to_path_buf(), 10000, None)
            .await
            .unwrap();
        // we assume that we already received the handshake and the handshake is not valid anymore
        replicator.state = ReplicatorState::NeedSnapshot;
        replicator.try_replicate_step().await.unwrap();

        assert_eq!(replicator.state, ReplicatorState::NeedHandshake);
    }

    #[tokio::test]
    async fn receive_handshake_error_while_handshaking() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        struct Client;

        #[async_trait::async_trait]
        impl ReplicatorClient for Client {
            type FrameStream =
                Pin<Box<dyn Stream<Item = Result<RpcFrame, Error>> + Send + 'static>>;

            /// Perform handshake with remote
            async fn handshake(&mut self) -> Result<(), Error> {
                Err(Error::NoHandshake)
            }
            /// Return a stream of frames to apply to the database
            async fn next_frames(&mut self) -> Result<Self::FrameStream, Error> {
                unimplemented!()
            }
            /// Return a snapshot for the current replication index. Called after next_frame has returned a
            /// NeedSnapshot error
            async fn snapshot(&mut self) -> Result<Self::FrameStream, Error> {
                unimplemented!()
            }
            /// set the new commit frame_no
            async fn commit_frame_no(&mut self, _frame_no: FrameNo) -> Result<(), Error> {
                unreachable!()
            }
            /// Returns the currently committed replication index
            fn committed_frame_no(&self) -> Option<FrameNo> {
                unreachable!()
            }
            fn rollback(&mut self) {}
        }

        let mut replicator = Replicator::new_sqlite(Client, tmp.path().to_path_buf(), 10000, None)
            .await
            .unwrap();
        replicator.state = ReplicatorState::NeedHandshake;
        assert!(matches!(
            replicator.try_replicate_step().await.unwrap_err(),
            Error::Fatal(_)
        ));
    }

    #[tokio::test]
    async fn transaction_interupted_by_error_and_resumed() {
        /// this this is generated by creating a table test, inserting 5 rows into it, and then
        /// truncating the wal file of it's header.
        const WAL: &[u8] = include_bytes!("../assets/test/test_wallog");

        fn make_wal_log() -> Vec<Frame> {
            let mut frames = WAL
                .chunks(size_of::<FrameBorrowed>())
                .map(|b| FrameMut::try_from(b).unwrap())
                .map(|mut f| {
                    f.header_mut().size_after.set(0);
                    f
                })
                .collect::<Vec<_>>();

            let size_after = frames.len();
            frames.last_mut().unwrap().header_mut().size_after = (size_after as u32).into();

            frames.into_iter().map(Into::into).collect()
        }

        let tmp = tempfile::NamedTempFile::new().unwrap();

        struct Client {
            frames: Vec<Frame>,
            should_error: bool,
            committed_frame_no: Option<FrameNo>,
        }

        #[async_trait::async_trait]
        impl ReplicatorClient for Client {
            type FrameStream =
                Pin<Box<dyn Stream<Item = Result<RpcFrame, Error>> + Send + 'static>>;

            /// Perform handshake with remote
            async fn handshake(&mut self) -> Result<(), Error> {
                Ok(())
            }
            /// Return a stream of frames to apply to the database
            async fn next_frames(&mut self) -> Result<Self::FrameStream, Error> {
                if self.should_error {
                    let frames = self
                        .frames
                        .iter()
                        .map(|f| RpcFrame {
                            data: f.bytes(),
                            timestamp: None,
                            durable_frame_no: None,
                        })
                        .take(2)
                        .map(Ok)
                        .chain(Some(Err(Error::Client("some client error".into()))))
                        .collect::<Vec<_>>();
                    Ok(Box::pin(tokio_stream::iter(frames)))
                } else {
                    let iter = self
                        .frames
                        .iter()
                        .map(|f| RpcFrame {
                            data: f.bytes(),
                            timestamp: None,
                            durable_frame_no: None,
                        })
                        .map(Ok)
                        .collect::<Vec<_>>();
                    Ok(Box::pin(tokio_stream::iter(iter)))
                }
            }
            /// Return a snapshot for the current replication index. Called after next_frame has returned a
            /// NeedSnapshot error
            async fn snapshot(&mut self) -> Result<Self::FrameStream, Error> {
                unimplemented!()
            }
            /// set the new commit frame_no
            async fn commit_frame_no(&mut self, frame_no: FrameNo) -> Result<(), Error> {
                self.committed_frame_no = Some(frame_no);
                Ok(())
            }
            /// Returns the currently committed replication index
            fn committed_frame_no(&self) -> Option<FrameNo> {
                unimplemented!()
            }
            fn rollback(&mut self) {}
        }

        let client = Client {
            frames: make_wal_log(),
            should_error: true,
            committed_frame_no: None,
        };

        let mut replicator = Replicator::new_sqlite(client, tmp.path().to_path_buf(), 10000, None)
            .await
            .unwrap();

        replicator.try_replicate_step().await.unwrap();
        assert_eq!(replicator.state, ReplicatorState::NeedFrames);

        assert!(matches!(
            replicator.try_replicate_step().await.unwrap_err(),
            Error::Client(_)
        ));
        assert!(!replicator.injector.inner.lock().is_txn());
        assert!(replicator.client_mut().committed_frame_no.is_none());
        assert_eq!(replicator.state, ReplicatorState::NeedHandshake);

        replicator.try_replicate_step().await.unwrap();
        assert_eq!(replicator.state, ReplicatorState::NeedFrames);

        replicator.client_mut().should_error = false;

        replicator.try_replicate_step().await.unwrap();
        assert!(!replicator.injector.inner.lock().is_txn());
        assert_eq!(replicator.state, ReplicatorState::Exit);
        assert_eq!(replicator.client_mut().committed_frame_no, Some(6));
    }
}
