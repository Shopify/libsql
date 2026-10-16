use std::future::Future;

use super::rpc::replication::Frame as RpcFrame;
pub use sqlite_injector::SqliteInjector;
use tokio_util::sync::CancellationToken;

use crate::frame::FrameNo;

pub use error::Error;
use error::Result;

mod error;
mod sqlite_injector;

pub trait Injector {
    /// Inject a singular frame.
    fn inject_frame(
        &mut self,
        frame: RpcFrame,
    ) -> impl Future<Output = Result<Option<FrameNo>>> + Send;

    /// Inject a singular frame, cooperatively observing terminal sync cancellation.
    ///
    /// Cancellation is a best-effort capability for injectors. The default
    /// implementation preserves the base `Injector` contract and does not
    /// interrupt in-flight work; injectors that can safely interrupt their
    /// backend should override this method and return
    /// [`Error::SyncCancelledForShutdown`] only for cancellation-caused
    /// interruptions.
    fn inject_frame_with_cancellation(
        &mut self,
        frame: RpcFrame,
        _token: &CancellationToken,
    ) -> impl Future<Output = Result<Option<FrameNo>>> + Send {
        self.inject_frame(frame)
    }

    /// Discard any uncommintted frames.
    fn rollback(&mut self) -> impl Future<Output = ()> + Send;

    /// Flush the buffer to libsql WAL.
    /// Trigger a dummy write, and flush the cache to trigger a call to xFrame. The buffer's frame
    /// are then injected into the wal.
    fn flush(&mut self) -> impl Future<Output = Result<Option<FrameNo>>> + Send;

    fn durable_frame_no(&mut self, frame_no: u64);
}
