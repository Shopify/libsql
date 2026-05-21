use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::Context as _;
use http::Uri;
use libsql_replication::rpc::proxy::{
    proxy_client::ProxyClient, DescribeRequest, DescribeResult, ExecuteResults, ProgramReq,
};
use libsql_replication::rpc::replication::replication_log_client::ReplicationLogClient;
use tonic::{
    body::BoxBody,
    codegen::InterceptedService,
    metadata::{AsciiMetadataValue, BinaryMetadataValue},
    service::Interceptor,
};
use tonic_web::{GrpcWebCall, GrpcWebClientService};
use tower::{Service, ServiceBuilder};
use tower_http::{
    classify::{self, GrpcCode, GrpcErrorsAsFailures, SharedClassifier},
    trace::{self, TraceLayer},
};
use uuid::Uuid;

use crate::util::{ConnectorService, HttpRequestCallback};

use crate::util::box_clone_service::BoxCloneService;

type ResponseBody = trace::ResponseBody<
    GrpcWebCall<hyper::Body>,
    classify::GrpcEosErrorsAsFailures,
    trace::DefaultOnBodyChunk,
    trace::DefaultOnEos,
    trace::DefaultOnFailure,
>;

#[derive(Debug, Clone)]
pub struct Client {
    client_id: Uuid,
    pub(crate) replication: ReplicationLogClient<InterceptedService<GrpcChannel, GrpcInterceptor>>,
    proxy: ProxyClient<InterceptedService<GrpcChannel, GrpcInterceptor>>,
}

impl Client {
    pub fn new(
        connector: ConnectorService,
        origin: Uri,
        auth_token: impl AsRef<str>,
        version: Option<&str>,
        http_request_callback: Option<HttpRequestCallback>,
        maybe_namespace: Option<String>,
    ) -> anyhow::Result<Self> {
        let ver = version.unwrap_or(env!("CARGO_PKG_VERSION"));

        let version: AsciiMetadataValue = format!("libsql-rpc-{ver}")
            .try_into()
            .context("Invalid client version")?;

        let auth_token: AsciiMetadataValue = format!("Bearer {}", auth_token.as_ref())
            .try_into()
            .context("Invalid auth token must be ascii")?;

        let ns = if let Some(ns_from_arg) = maybe_namespace {
            ns_from_arg
        } else if let Ok(ns_from_host) = split_namespace(origin.host().unwrap()) {
            ns_from_host
        } else {
            "default".to_string()
        };
        
        let namespace = BinaryMetadataValue::from_bytes(ns.as_bytes());

        let channel = GrpcChannel::new(connector, http_request_callback);

        let interceptor = GrpcInterceptor {
            auth_token,
            namespace,
            version,
        };

        let replication = ReplicationLogClient::with_origin(
            InterceptedService::new(channel.clone(), interceptor.clone()),
            origin.clone(),
        );

        let proxy = ProxyClient::with_origin(InterceptedService::new(channel, interceptor), origin);

        // Remove default tonic `8mb` message limits since fly may buffer
        // messages causing the msg len to be longer.
        let replication = replication.max_decoding_message_size(usize::MAX);
        let proxy = proxy.max_decoding_message_size(usize::MAX);

        let client_id = Uuid::new_v4();

        Ok(Self {
            client_id,
            replication,
            proxy,
        })
    }

    pub fn new_client_id(&mut self) {
        self.client_id = Uuid::new_v4();
    }

    pub fn client_id(&self) -> String {
        self.client_id.to_string()
    }

    pub async fn execute_program(&self, program: ProgramReq) -> anyhow::Result<ExecuteResults> {
        // TODO(lucio): Map errors correctly
        self.proxy
            .clone()
            .execute(program)
            .await
            .map(|r| r.into_inner())
            .map_err(Into::into)
    }

    pub async fn describe(&self, describe_req: DescribeRequest) -> anyhow::Result<DescribeResult> {
        self.proxy
            .clone()
            .describe(describe_req)
            .await
            .map(|r| r.into_inner())
            .map_err(Into::into)
    }
}

#[derive(Debug, Clone)]
pub struct GrpcChannel {
    client: BoxCloneService<http::Request<BoxBody>, http::Response<ResponseBody>, hyper::Error>,
}

impl GrpcChannel {
    pub fn new(
        connector: ConnectorService,
        http_request_callback: Option<HttpRequestCallback>,
    ) -> Self {
        let client = hyper::Client::builder()
            .pool_idle_timeout(None)
            .pool_max_idle_per_host(3)
            .build(connector);
        let client = DiagnosticResponseService::new(client);
        let client = GrpcWebClientService::new(client);

        let classifier = GrpcErrorsAsFailures::new().with_success(GrpcCode::FailedPrecondition);

        let svc = ServiceBuilder::new()
            .layer(TraceLayer::new(SharedClassifier::new(classifier)))
            .map_request(move |request: http::Request<BoxBody>| {
                if let Some(cb) = &http_request_callback {
                    let (parts, body) = request.into_parts();
                    let mut req_copy = http::Request::from_parts(parts, ());
                    cb(&mut req_copy);

                    let (parts, _) = req_copy.into_parts();

                    http::Request::from_parts(parts, body)
                } else {
                    request
                }
            })
            .service(client);

        let client = BoxCloneService::new(svc);

        Self { client }
    }
}

impl Service<http::Request<BoxBody>> for GrpcChannel {
    type Response = http::Response<ResponseBody>;
    type Error = hyper::Error;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<BoxBody>) -> Self::Future {
        let fut = self.client.call(req);
        Box::pin(fut)
    }
}

/// Diagnostic middleware that intercepts raw HTTP responses before gRPC-web
/// framing. When the response status is not 200 or the content-type is not
/// grpc-web, it buffers and logs the response body so we can diagnose
/// "Invalid header bit N" errors from tonic-web.
#[derive(Clone)]
struct DiagnosticResponseService<S> {
    inner: S,
}

impl<S> DiagnosticResponseService<S> {
    fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S, ReqBody> Service<http::Request<ReqBody>> for DiagnosticResponseService<S>
where
    S: Service<http::Request<ReqBody>, Response = http::Response<hyper::Body>, Error = hyper::Error>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = http::Response<hyper::Body>;
    type Error = hyper::Error;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<ReqBody>) -> Self::Future {
        let uri = req.uri().clone();
        let fut = self.inner.call(req);
        Box::pin(async move {
            let resp = fut.await?;
            let status = resp.status();
            let content_type = resp
                .headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("<none>")
                .to_string();
            let is_grpc = content_type.contains("grpc");

            // Diagnostic branch: buffer every response before tonic-web parses
            // grpc-web frames, then re-create the body for normal consumption.
            // This lets us catch malformed 200 OK grpc-looking responses whose
            // first frame byte would otherwise only surface as "Invalid header bit".
            let (parts, body) = resp.into_parts();
            let body_bytes = hyper::body::to_bytes(body).await.unwrap_or_default();
            let first_body_byte = body_bytes.first().copied();
            let first_body_byte_hex = first_body_byte.map(|byte| format!("0x{byte:02x}"));
            let first_body_byte_ascii = first_body_byte.map(|byte| {
                if byte.is_ascii_graphic() || byte == b' ' {
                    (byte as char).to_string()
                } else {
                    format!("\\x{byte:02x}")
                }
            });
            let valid_grpc_web_first_byte = matches!(first_body_byte, None | Some(0 | 1 | 128));

            if status != http::StatusCode::OK || !is_grpc || !valid_grpc_web_first_byte {
                let preview_len = std::cmp::min(body_bytes.len(), 1024);
                let body_preview = String::from_utf8_lossy(&body_bytes[..preview_len]);
                tracing::warn!(
                    status = %status,
                    uri = %uri,
                    content_type = %content_type,
                    body_len = body_bytes.len(),
                    first_body_byte = ?first_body_byte,
                    first_body_byte_hex = ?first_body_byte_hex,
                    first_body_byte_ascii = ?first_body_byte_ascii,
                    body_preview = %body_preview,
                    "[libsql diagnostic] raw HTTP response may fail grpc-web framing"
                );
            } else {
                tracing::trace!(
                    status = %status,
                    uri = %uri,
                    content_type = %content_type,
                    body_len = body_bytes.len(),
                    first_body_byte = ?first_body_byte,
                    "[libsql diagnostic] raw HTTP response has valid grpc-web first byte"
                );
            }

            Ok(http::Response::from_parts(parts, hyper::Body::from(body_bytes)))
        })
    }
}

#[derive(Clone)]
/// Contains token and namespace headers to append to every request.
pub struct GrpcInterceptor {
    auth_token: AsciiMetadataValue,
    namespace: BinaryMetadataValue,
    version: AsciiMetadataValue,
}

impl Interceptor for GrpcInterceptor {
    fn call(&mut self, mut req: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
        req.metadata_mut()
            .insert("x-authorization", self.auth_token.clone());
        req.metadata_mut()
            .insert_bin("x-namespace-bin", self.namespace.clone());
        req.metadata_mut()
            .insert("x-libsql-client-version", self.version.clone());
        Ok(req)
    }
}

fn split_namespace(host: &str) -> anyhow::Result<String> {
    let (ns, _) = host
        .split_once('.')
        .ok_or_else(|| anyhow::anyhow!("host header should be in the format <namespace>.<...>"))?;

    if ns.is_empty() {
        anyhow::bail!("Invalid namespace as its empty");
    }

    let ns = ns.to_owned();
    Ok(ns)
}
