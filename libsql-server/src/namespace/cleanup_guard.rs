//! Cancellation-safe, runtime-neutral cleanup scheduling. This module has no
//! database dependencies so its current-thread tests can run independently of
//! the server's native SQLite linkage.
use std::future::Future;
use std::pin::Pin;

use tokio::task::JoinHandle;

pub(crate) type CleanupFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

pub(crate) struct DeferredCleanup<State: Send + 'static> {
    state: Option<State>,
    cleanup: fn(State, bool) -> CleanupFuture,
}

impl<State: Send + 'static> DeferredCleanup<State> {
    pub(crate) fn new(state: State, cleanup: fn(State, bool) -> CleanupFuture) -> Self {
        Self {
            state: Some(state),
            cleanup,
        }
    }

    pub(crate) fn disarm(&mut self) -> Option<State> {
        self.state.take()
    }

    fn start(&mut self, remove_directory: bool) -> Option<JoinHandle<()>> {
        let state = self.state.take()?;
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => Some(runtime.spawn((self.cleanup)(state, remove_directory))),
            Err(e) => {
                // Dropping state must be non-destructive. The caller retains
                // metadata/files for repair if no runtime can run the barrier.
                tracing::error!("namespace cleanup quarantined without runtime: {e}");
                None
            }
        }
    }

    pub(crate) async fn finish(mut self) {
        if let Some(task) = self.start(true) {
            if let Err(e) = task.await {
                tracing::error!("namespace cleanup task failed: {e}");
            }
        }
    }
}

impl<State: Send + 'static> Drop for DeferredCleanup<State> {
    fn drop(&mut self) {
        // Never block a current-thread runtime. Dropping a request after
        // scheduling cleanup detaches its waiter, not the cleanup worker.
        let _ = self.start(false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use std::time::Duration;
    use tokio::sync::{Mutex, Notify, OwnedMutexGuard};

    struct State {
        operation: OwnedMutexGuard<()>,
        proceed: Arc<Notify>,
        started: Arc<Notify>,
        removed: Arc<AtomicBool>,
    }

    fn cleanup(state: State, remove_directory: bool) -> CleanupFuture {
        Box::pin(async move {
            state.started.notify_one();
            state.proceed.notified().await;
            state.removed.store(remove_directory, Ordering::SeqCst);
            drop(state.operation);
        })
    }

    async fn async_fixture() -> (
        DeferredCleanup<State>,
        Arc<Mutex<()>>,
        Arc<Notify>,
        Arc<Notify>,
        Arc<AtomicBool>,
    ) {
        let operation = Arc::new(Mutex::new(()));
        let proceed = Arc::new(Notify::new());
        let started = Arc::new(Notify::new());
        let removed = Arc::new(AtomicBool::new(false));
        let guard = operation.clone().lock_owned().await;
        let cleanup = DeferredCleanup::new(
            State {
                operation: guard,
                proceed: proceed.clone(),
                started: started.clone(),
                removed: removed.clone(),
            },
            cleanup,
        );
        (cleanup, operation, proceed, started, removed)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn error_cleanup_awaits_on_current_thread_without_blocking() {
        let (cleanup, operation, proceed, _started, removed) = async_fixture().await;
        proceed.notify_one();
        cleanup.finish().await;
        assert!(removed.load(Ordering::SeqCst));
        assert!(operation.try_lock().is_ok());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn disarmed_success_never_runs_cleanup() {
        let (mut cleanup, operation, _proceed, _started, removed) = async_fixture().await;
        let committed = cleanup.disarm().unwrap();
        drop(cleanup);
        drop(committed);
        assert!(operation.try_lock().is_ok());
        assert!(!removed.load(Ordering::SeqCst));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_operation_keeps_reservation_until_worker_finishes() {
        let (cleanup, operation, proceed, _started, removed) = async_fixture().await;
        drop(cleanup);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), operation.lock())
                .await
                .is_err()
        );
        proceed.notify_one();
        let _new_owner = tokio::time::timeout(Duration::from_secs(2), operation.lock())
            .await
            .unwrap();
        assert!(!removed.load(Ordering::SeqCst));
    }

    async fn cancelled_waiter_keeps_reservation() {
        let (cleanup, operation, proceed, started, removed) = async_fixture().await;
        let waiting = tokio::spawn(cleanup.finish());
        started.notified().await;
        waiting.abort();
        assert!(waiting.await.is_err());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), operation.lock())
                .await
                .is_err()
        );
        proceed.notify_one();
        let _new_owner = tokio::time::timeout(Duration::from_secs(2), operation.lock())
            .await
            .unwrap();
        assert!(removed.load(Ordering::SeqCst));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_cleanup_waiter_on_current_thread_is_ordered() {
        cancelled_waiter_keeps_reservation().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_cleanup_waiter_on_multithread_is_ordered() {
        cancelled_waiter_keeps_reservation().await;
    }
}
