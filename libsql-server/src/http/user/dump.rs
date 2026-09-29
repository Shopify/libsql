use std::future::Future;
use std::io::Write;
use std::pin::Pin;
use std::sync::Arc;
use std::task;

use axum::extract::{Query, State as AxumState};
use futures::StreamExt;
use hyper::HeaderMap;
use pin_project_lite::pin_project;
use serde::Deserialize;

use crate::auth::Authenticated;
use crate::connection::dump::exporter::export_dump_cancellable;
use crate::connection::{Connection as _, MakeConnection};
use crate::database::Connection;
use crate::error::Error;
use crate::namespace::fence::controller::{FenceController, LeaseKind};
use crate::namespace::fence::stream::{
    acquire_stream_lease, cancelled_by_read_fence, StreamCancel,
};
use crate::BLOCKING_RT;

use super::db_factory::namespace_from_headers;
use super::AppState;

pin_project! {
    struct DumpStream<S> {
        join_handle: Option<tokio::task::JoinHandle<Result<(), Error>>>,
        #[pin]
        stream: S,
    }
}

impl<S> futures::Stream for DumpStream<S>
where
    S: futures::stream::TryStream + futures::stream::FusedStream,
    S::Error: Into<Error>,
{
    type Item = Result<S::Ok, Error>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Option<Self::Item>> {
        let this = self.as_mut().project();

        if !this.stream.is_terminated() {
            match futures::ready!(this.stream.try_poll_next(cx)) {
                Some(item) => task::Poll::Ready(Some(item.map_err(Into::into))),
                None => {
                    // poll join_handle
                    self.poll_next(cx)
                }
            }
        } else {
            // The stream was closed but we need to check if the dump task failed and forward the
            // error
            this.join_handle
                .take()
                .map_or(task::Poll::Ready(None), |mut join_handle| {
                    match Pin::new(&mut join_handle).poll(cx) {
                        task::Poll::Pending => {
                            *this.join_handle = Some(join_handle);
                            task::Poll::Pending
                        }
                        task::Poll::Ready(Ok(Err(err))) => {
                            tracing::error!("error creating dump: {err}");
                            task::Poll::Ready(Some(Err(err)))
                        }
                        task::Poll::Ready(Err(err)) => {
                            task::Poll::Ready(Some(Err(anyhow::anyhow!(err)
                                .context("Dump task crashed")
                                .into())))
                        }
                        task::Poll::Ready(Ok(Ok(_))) => task::Poll::Ready(None),
                    }
                })
        }
    }
}

#[derive(Deserialize)]
pub struct DumpQuery {
    preserve_row_ids: Option<bool>,
}

pub(super) async fn handle_dump(
    auth: Authenticated,
    AxumState(state): AxumState<AppState>,
    headers: HeaderMap,
    query: Query<DumpQuery>,
) -> crate::Result<axum::body::StreamBody<impl futures::Stream<Item = Result<bytes::Bytes, Error>>>>
{
    let namespace = namespace_from_headers(
        &headers,
        state.disable_default_namespace,
        state.disable_namespaces,
    )?;

    if !auth.is_namespace_authorized(&namespace) {
        return Err(Error::NamespaceDoesntExist(namespace.to_string()));
    }

    let (conn_maker, fence) = state
        .namespaces
        .with(namespace, |ns| {
            if !ns.db.is_primary() {
                return Err(Error::NotAPrimary);
            }

            Ok::<_, crate::Error>((ns.db.connection_maker(), ns.fence().clone()))
        })
        .await??;

    let stream = dump_stream(&fence, conn_maker, query.preserve_row_ids.unwrap_or(false)).await?;

    Ok(axum::body::StreamBody::new(stream))
}

/// The dump of one namespace as a byte stream (`docs/NAMESPACE_FENCE.md` section 9).
///
/// The dump is admitted by the namespace's fence gate before any connection is created, and
/// holds a `Dump` read lease until the export has stopped. When the read drain cancels it, the
/// export stops before its next row, and also if it is blocked because the peer is not reading,
/// so the lease is released without the peer's help; the stream then ends with the fence error
/// instead of ending cleanly, so the response body is aborted and the client never receives a
/// dump that looks complete.
pub(crate) async fn dump_stream(
    fence: &Arc<FenceController>,
    conn_maker: Arc<dyn MakeConnection<Connection = Connection>>,
    preserve_row_ids: bool,
) -> crate::Result<impl futures::Stream<Item = Result<bytes::Bytes, Error>>> {
    let (lease, cancel) =
        acquire_stream_lease(fence, LeaseKind::Dump).map_err(Error::NamespaceFence)?;

    let conn = conn_maker.create().await?;

    let (reader, writer) = tokio::io::duplex(8 * 1024);
    let writer = CancellableWriter {
        inner: writer,
        cancel: cancel.clone(),
        handle: tokio::runtime::Handle::current(),
    };

    let join_handle = BLOCKING_RT.spawn_blocking(move || {
        // Released once the export has stopped and its read transaction is gone.
        let _lease = lease;
        let result = conn.with_raw(|conn| {
            export_dump_cancellable(conn, writer, preserve_row_ids, &|| cancel.is_cancelled())
        });
        match result {
            Ok(()) => Ok(()),
            Err(_) if cancel.is_cancelled() => Err(Error::NamespaceFence(cancelled_by_read_fence(
                LeaseKind::Dump,
            ))),
            Err(e) => Err(e.into()),
        }
    });

    let stream = tokio_util::io::ReaderStream::new(reader);

    Ok(DumpStream {
        stream: stream.fuse(),
        join_handle: Some(join_handle),
    })
}

/// The export's side of the dump pipe. A write waits for the reader (the HTTP body), unless
/// the dump is cancelled, in which case it fails at once.
struct CancellableWriter {
    inner: tokio::io::DuplexStream,
    cancel: Arc<StreamCancel>,
    handle: tokio::runtime::Handle,
}

impl CancellableWriter {
    fn cancelled() -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::Other, "dump cancelled")
    }
}

impl Write for CancellableWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        use tokio::io::AsyncWriteExt as _;
        let Self {
            inner,
            cancel,
            handle,
        } = self;
        handle.block_on(async {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => Err(Self::cancelled()),
                r = inner.write(buf) => r,
            }
        })
    }

    fn flush(&mut self) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt as _;
        let Self {
            inner,
            cancel,
            handle,
        } = self;
        handle.block_on(async {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => Err(Self::cancelled()),
                r = inner.flush() => r,
            }
        })
    }
}
