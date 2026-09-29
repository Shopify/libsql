use crate::broadcaster::BroadcastMsg;
use crate::error::Error;
use crate::metrics::{LISTEN_EVENTS_DROPPED, LISTEN_EVENTS_SENT};
use crate::namespace::fence::controller::{FenceController, GateSnapshot};
use crate::namespace::fence::outcome::FenceError;
use crate::namespace::fence::state::OperationClass;
use crate::{
    auth::Authenticated,
    namespace::{NamespaceName, NamespaceStore},
};
use axum::extract::State as AxumState;
use axum::http::Uri;
use axum::response::{
    sse::{Event, Sse},
    IntoResponse, Redirect,
};
use axum_extra::extract::Query;
use futures::{Stream, StreamExt};
use hyper::HeaderMap;
use serde::{Deserialize, Serialize};
use std::boxed::Box;
use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;

use super::db_factory::namespace_from_headers;
use super::AppState;

const LAGGED_MSG: &str = "some changes were lost";
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);
const KEEP_ALIVE_TEXT: &str = "keep-alive";

type SseStream = Pin<Box<dyn Stream<Item = Result<Event, Infallible>> + Send>>;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    UNKNOWN,
    DELETE,
    INSERT,
    UPDATE,
}

#[derive(Deserialize)]
pub struct ListenQuery {
    table: String,
    action: Option<Vec<Action>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum AggregatorEvent {
    Error(&'static str),
    #[serde(untagged)]
    Changes(BroadcastMsg),
}

enum ListenResponse {
    SSE(Sse<SseStream>),
    Redirect(Redirect),
}

impl IntoResponse for ListenResponse {
    fn into_response(self) -> axum::response::Response {
        match self {
            ListenResponse::SSE(sse) => sse.into_response(),
            ListenResponse::Redirect(redirect) => redirect.into_response(),
        }
    }
}

pub(super) async fn handle_listen(
    auth: Authenticated,
    AxumState(state): AxumState<AppState>,
    headers: HeaderMap,
    uri: Uri,
    query: Query<ListenQuery>,
) -> crate::Result<impl IntoResponse> {
    let namespace = namespace_from_headers(
        &headers,
        state.disable_default_namespace,
        state.disable_namespaces,
    )?;

    if !auth.is_namespace_authorized(&namespace) {
        return Err(Error::NamespaceDoesntExist(namespace.to_string()));
    }

    if let Some(primary_url) = state.primary_url.as_ref() {
        let url = format!(
            "{}{}",
            primary_url,
            uri.path_and_query().map_or("", |x| x.as_str())
        );
        return Ok(ListenResponse::Redirect(Redirect::temporary(&url)));
    }

    // Change notifications are a read of the namespace: refused where reads are denied, and
    // ended when the namespace's reads are fenced (`docs/NAMESPACE_FENCE.md` section 9).
    let fence = state.namespaces.fence_gate(&namespace).await?;
    if let Some(fence) = &fence {
        fence.permits(OperationClass::NormalRead)?;
    }

    let stream = sse_stream(
        state.namespaces.clone(),
        namespace,
        query.table.clone(),
        query.action.clone(),
        fence,
    )
    .await;

    Ok(ListenResponse::SSE(
        Sse::new(stream).keep_alive(
            axum::response::sse::KeepAlive::new()
                .interval(KEEP_ALIVE_INTERVAL)
                .text(KEEP_ALIVE_TEXT),
        ),
    ))
}

async fn sse_stream(
    store: NamespaceStore,
    namespace: NamespaceName,
    table: String,
    actions: Option<Vec<Action>>,
    fence: Option<Arc<FenceController>>,
) -> SseStream {
    Box::pin(
        listen_stream(store, namespace, table, actions, fence)
            .await
            .map(|result| {
                Ok(match result {
                    Ok(AggregatorEvent::Error(msg)) => Event::default().event("error").data(msg),
                    Ok(AggregatorEvent::Changes(msg)) => {
                        Event::default().event("changes").json_data(msg).unwrap()
                    }
                    Err(e) => Event::default().event("error").data(e.to_string()),
                })
            }),
    )
}

async fn listen_stream(
    store: NamespaceStore,
    namespace: NamespaceName,
    table: String,
    actions: Option<Vec<Action>>,
    fence: Option<Arc<FenceController>>,
) -> impl Stream<Item = crate::Result<AggregatorEvent>> {
    async_stream::try_stream! {
        let _sub = Subscription::new(store.clone(), namespace.clone(), table.clone());
        let mut stream = store.subscribe(namespace.clone(), table.clone());
        let mut gate = fence.as_ref().map(|fence| fence.subscribe());

        loop {
            let item = tokio::select! {
                item = stream.next() => Ok(item),
                denied = read_denied(&mut gate) => Err(Error::NamespaceFence(denied)),
            };
            let Some(item) = item? else { break };
            match item {
                Ok(msg) => if filter_actions(&msg, &actions) {
                    LISTEN_EVENTS_SENT.increment(1);
                    yield AggregatorEvent::Changes(msg);
                },
                Err(BroadcastStreamRecvError::Lagged(n)) => {
                    LISTEN_EVENTS_DROPPED.increment(n as u64);
                    yield AggregatorEvent::Error(LAGGED_MSG);
                },
            }
        }
    }
}

/// Resolves once the gate denies normal reads, with the denial; never without a gate.
async fn read_denied(gate: &mut Option<watch::Receiver<GateSnapshot>>) -> FenceError {
    let Some(gate) = gate else {
        return std::future::pending().await;
    };
    loop {
        if let Err(e) = gate.borrow_and_update().permits(OperationClass::NormalRead) {
            return e;
        }
        if gate.changed().await.is_err() {
            return std::future::pending().await;
        }
    }
}

fn filter_actions(msg: &BroadcastMsg, actions: &Option<Vec<Action>>) -> bool {
    actions.as_ref().map_or(true, |actions| {
        actions.iter().any(|action| {
            let count = match action {
                Action::DELETE => msg.delete,
                Action::INSERT => msg.insert,
                Action::UPDATE => msg.update,
                Action::UNKNOWN => msg.unknown,
            };
            count > 0
        })
    })
}

struct Subscription {
    store: NamespaceStore,
    namespace: NamespaceName,
    table: String,
}

impl Subscription {
    fn new(store: NamespaceStore, namespace: NamespaceName, table: String) -> Self {
        Self {
            store,
            namespace,
            table,
        }
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.store.unsubscribe(self.namespace.clone(), &self.table);
    }
}
