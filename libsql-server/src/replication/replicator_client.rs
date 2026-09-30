use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures::TryStreamExt;
use libsql_replication::meta::WalIndexMeta;
use libsql_replication::replicator::{Error, ReplicatorClient};
use libsql_replication::rpc::replication::log_offset::WalFlavor;
use libsql_replication::rpc::replication::replication_log_client::ReplicationLogClient;
use libsql_replication::rpc::replication::{
    verify_session_token, Frame as RpcFrame, HelloRequest, HelloResponse, LogOffset,
    NAMESPACE_METADATA_KEY, SESSION_TOKEN_KEY,
};
use tokio::sync::watch;
use tokio_stream::Stream;

use tonic::metadata::{AsciiMetadataValue, BinaryMetadataValue};
use tonic::transport::Channel;
use tonic::{Code, Request, Status};

use crate::connection::config::DatabaseConfig;
use crate::metrics::{
    REPLICATION_LATENCY, REPLICATION_LATENCY_CACHE_MISS, REPLICATION_LATENCY_OUT_OF_SYNC,
};
use crate::namespace::fence::controller::FenceController;
use crate::namespace::fence::outcome::FenceError;
use crate::namespace::fence::replica::{self, PrimaryFenceRefusal};
use crate::namespace::meta_store::MetaStoreHandle;
use crate::namespace::{NamespaceName, NamespaceStore};
use crate::replication::FrameNo;

pub enum WalImpl {
    SqliteWal {
        meta: WalIndexMeta,
        current_frame_no_notifier: watch::Sender<Option<FrameNo>>,
    },
}

impl WalImpl {
    pub async fn new_sqlite(
        path: &Path,
        sender: watch::Sender<Option<FrameNo>>,
    ) -> Result<Self, Error> {
        let meta = WalIndexMeta::open(path).await?;
        Ok(Self::SqliteWal {
            meta,
            current_frame_no_notifier: sender,
        })
    }

    fn next_frame_no(&self, _first_since_handshake: bool) -> FrameNo {
        match self {
            WalImpl::SqliteWal {
                current_frame_no_notifier,
                ..
            } => match *current_frame_no_notifier.borrow() {
                Some(fno) => fno + 1,
                None => 0,
            },
        }
    }

    fn handle_hello(&mut self, hello: HelloResponse) -> Result<(), Error> {
        match self {
            WalImpl::SqliteWal {
                meta,
                current_frame_no_notifier,
            } => {
                meta.init_from_hello(hello)?;
                current_frame_no_notifier.send_replace(meta.current_frame_no());
                Ok(())
            }
        }
    }

    async fn set_commit_frame_no(&mut self, frame_no: FrameNo) -> Result<(), Error> {
        match self {
            WalImpl::SqliteWal {
                meta,
                current_frame_no_notifier,
            } => {
                current_frame_no_notifier.send_replace(Some(frame_no));
                meta.set_commit_frame_no(frame_no).await?;
                Ok(())
            }
        }
    }

    fn commit_frame_no(&self) -> Option<FrameNo> {
        match self {
            WalImpl::SqliteWal { meta, .. } => meta.current_frame_no(),
        }
    }

    fn flavor(&self) -> WalFlavor {
        match self {
            WalImpl::SqliteWal { .. } => WalFlavor::Sqlite,
        }
    }
}

pub struct Client {
    client: ReplicationLogClient<Channel>,
    namespace: NamespaceName,
    session_token: Option<Bytes>,
    meta_store_handle: MetaStoreHandle,
    // the primary current replication index, as reported by the last handshake
    pub primary_replication_index: Option<FrameNo>,
    store: NamespaceStore,
    wal_impl: WalImpl,
    first_sync_since_handshake: bool,
    /// The namespace's fence controller on this replica server, on which the primary's fence
    /// is published as a local read denial (`docs/NAMESPACE_FENCE.md` section 6.2).
    fence: Arc<FenceController>,
    /// Replication calls the primary's fence refused since the last `hello` it answered. Shared
    /// with active frame streams so a refusal delivered as their terminal status is counted too.
    fence_refusals: Arc<AtomicU32>,
}

impl Client {
    pub async fn new(
        namespace: NamespaceName,
        client: ReplicationLogClient<Channel>,
        meta_store_handle: MetaStoreHandle,
        store: NamespaceStore,
        wal_flavor: WalImpl,
        fence: Arc<FenceController>,
    ) -> crate::Result<Self> {
        Ok(Self {
            namespace,
            client,
            session_token: None,
            meta_store_handle,
            primary_replication_index: None,
            store,
            wal_impl: wal_flavor,
            first_sync_since_handshake: true,
            fence,
            fence_refusals: Arc::new(AtomicU32::new(0)),
        })
    }

    /// Replication calls the primary's fence refused in a row, since the last `hello` it
    /// answered. The replica's replication loop paces its reconnects by it.
    pub(crate) fn fence_refusals(&self) -> u32 {
        self.fence_refusals.load(Ordering::Relaxed)
    }

    /// Publish what the primary said of its fence as this replica's local read denial, logging
    /// when that changes.
    fn observe_primary_fence(&self, denial: Option<FenceError>) {
        let denies = denial.as_ref().map(|d| d.outcome());
        if self.fence.observe_primary(denial) {
            match denies {
                Some(code) => tracing::warn!(
                    namespace = %self.namespace,
                    "the primary's namespace fence denies reads ({code}): local reads of this \
                     replica are refused until the primary admits replication again"
                ),
                None => tracing::info!(
                    namespace = %self.namespace,
                    "the primary admits replication again: local reads are served"
                ),
            }
        }
    }

    /// Map a status of a replication call: a fence refusal is published as the local read
    /// denial, counted, and returned as a [`PrimaryFenceRefusal`].
    fn status_error(&mut self, status: Status) -> Error {
        let error = replica::replicator_error(status);
        if let Some(refusal) = PrimaryFenceRefusal::of(&error) {
            self.fence_refusals
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                    Some(count.saturating_add(1))
                })
                .ok();
            metrics::increment_counter!(
                "libsql_server_replica_fence_refusals_total",
                "code" => refusal.0.outcome().as_str(),
            );
            tracing::debug!(namespace = %self.namespace, "{refusal}");
            self.observe_primary_fence(Some(refusal.local_denial()));
        }
        error
    }

    /// A stream of the primary's that ends with a fence refusal publishes it as the local read
    /// denial.
    fn fenced_frames(
        &self,
        stream: tonic::Streaming<RpcFrame>,
    ) -> impl Stream<Item = Result<RpcFrame, Error>> + Send + 'static {
        let fence = self.fence.clone();
        let fence_refusals = self.fence_refusals.clone();
        let namespace = self.namespace.clone();
        stream.map_err(move |status| {
            let error = replica::replicator_error(status);
            if let Some(refusal) = PrimaryFenceRefusal::of(&error) {
                fence_refusals
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                        Some(count.saturating_add(1))
                    })
                    .ok();
                metrics::increment_counter!(
                    "libsql_server_replica_fence_refusals_total",
                    "code" => refusal.0.outcome().as_str(),
                );
                if fence.observe_primary(Some(refusal.local_denial())) {
                    tracing::warn!(
                        namespace = %namespace,
                        "the primary ended replication because its namespace fence denies \
                         reads ({}): local reads of this replica are refused until the primary \
                         admits replication again",
                        refusal.0.outcome()
                    );
                }
            }
            error
        })
    }

    fn make_request<T>(&self, msg: T) -> Request<T> {
        let mut req = Request::new(msg);
        req.metadata_mut().insert_bin(
            NAMESPACE_METADATA_KEY,
            BinaryMetadataValue::from_bytes(self.namespace.as_slice()),
        );

        if let Some(token) = self.session_token.clone() {
            // SAFETY: we always check the session token
            req.metadata_mut().insert(SESSION_TOKEN_KEY, unsafe {
                AsciiMetadataValue::from_shared_unchecked(token)
            });
        }

        req
    }

    fn next_frame_no(&self) -> FrameNo {
        self.wal_impl.next_frame_no(self.first_sync_since_handshake)
    }

    pub(crate) fn reset_token(&mut self) {
        self.session_token = None;
    }
}

#[async_trait::async_trait]
impl ReplicatorClient for Client {
    type FrameStream = Pin<Box<dyn Stream<Item = Result<RpcFrame, Error>> + Send + 'static>>;

    #[tracing::instrument(skip(self))]
    async fn handshake(&mut self) -> Result<(), Error> {
        self.first_sync_since_handshake = true;
        tracing::debug!("Attempting to perform handshake with primary.");
        let req = self.make_request(HelloRequest::new());
        let resp = match self.client.hello(req).await {
            Ok(resp) => resp,
            Err(status) => return Err(self.status_error(status)),
        };
        let hello = resp.into_inner();
        verify_session_token(&hello.session_token).map_err(Error::Client)?;
        // The primary answers `hello` only where its fence admits replication.
        self.fence_refusals.store(0, Ordering::Relaxed);
        self.observe_primary_fence(replica::denial_from_hello(
            hello.config.as_ref().and_then(|c| c.fence.as_ref()),
        ));
        self.primary_replication_index = hello.current_replication_index;
        self.session_token.replace(hello.session_token.clone());

        if let Some(config) = &hello.config {
            // HACK: if we load a shared schema db before the main schema is replicated,
            // inserting the new database in the meta store will cause a foreign constraint Error
            // because we have a constraint check that ensure shared schema dbs point to a valid
            // main schema. To prevent that, we load the main schema first.
            if let Some(ref name) = config.shared_schema_name {
                let name = NamespaceName::from_string(name.clone())
                    .map_err(|_| Status::new(Code::InvalidArgument, "invalid namespace name"))?;
                self.store
                    .with(name, |_| ())
                    .await
                    .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
            }

            self.meta_store_handle
                .store(DatabaseConfig::from(config))
                .await
                .map_err(|e| Error::Internal(e.into()))?;

            tracing::debug!("replica config has been updated");
        } else {
            tracing::debug!("no config passed in handshake");
        }

        self.wal_impl.handle_hello(hello)?;
        tracing::trace!("handshake completed");

        Ok(())
    }

    async fn next_frames(&mut self) -> Result<Self::FrameStream, Error> {
        let offset = LogOffset {
            next_offset: self.next_frame_no(),
            wal_flavor: Some(self.wal_impl.flavor().into()),
        };

        let req = self.make_request(offset);
        let stream = match self.client.log_entries(req).await {
            Ok(resp) => resp.into_inner(),
            Err(status) => return Err(self.status_error(status)),
        };
        let stream = self.fenced_frames(stream).inspect_ok(|f| {
            match f.timestamp {
                Some(ts_millis) => {
                    if let Some(commited_at) = DateTime::from_timestamp_millis(ts_millis) {
                        let lat = Utc::now() - commited_at;
                        match lat.to_std() {
                            Ok(lat) => {
                                // we can record negative values if the clocks are out-of-sync. There is not
                                // point in recording those values.
                                REPLICATION_LATENCY.record(lat);
                            }
                            Err(_) => {
                                REPLICATION_LATENCY_OUT_OF_SYNC.increment(1);
                            }
                        }
                    }
                }
                None => REPLICATION_LATENCY_CACHE_MISS.increment(1),
            }
        });

        Ok(Box::pin(stream))
    }

    async fn snapshot(&mut self) -> Result<Self::FrameStream, Error> {
        let offset = LogOffset {
            next_offset: self.next_frame_no(),
            wal_flavor: Some(self.wal_impl.flavor().into()),
        };
        let req = self.make_request(offset);
        match self.client.snapshot(req).await {
            Ok(resp) => {
                let stream = self.fenced_frames(resp.into_inner());
                Ok(Box::pin(stream))
            }
            Err(e) if e.code() == Code::Unavailable => Err(Error::SnapshotPending),
            Err(e) => Err(self.status_error(e)),
        }
    }

    async fn commit_frame_no(
        &mut self,
        frame_no: libsql_replication::frame::FrameNo,
    ) -> Result<(), Error> {
        self.wal_impl.set_commit_frame_no(frame_no).await?;
        self.first_sync_since_handshake = false;
        Ok(())
    }

    fn committed_frame_no(&self) -> Option<FrameNo> {
        self.wal_impl.commit_frame_no()
    }

    fn rollback(&mut self) {}
}
