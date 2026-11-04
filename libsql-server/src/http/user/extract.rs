use axum::extract::FromRequestParts;

use crate::connection::RequestContext;

use super::{authenticate_for_namespace, db_factory, AppState};

/// Request context for header-routed endpoints: the namespace comes from the
/// `x-namespace` / `Host` headers. Path-routed endpoints must use
/// [`db_factory::PathNamespaceRequest`] instead, so the authorized namespace is the one in
/// the URL.
#[async_trait::async_trait]
impl FromRequestParts<AppState> for RequestContext {
    type Rejection = crate::error::Error;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &AppState,
    ) -> std::result::Result<Self, Self::Rejection> {
        let namespace = db_factory::namespace_from_headers(
            &parts.headers,
            state.disable_default_namespace,
            state.disable_namespaces,
        )?;
        let auth = authenticate_for_namespace(parts, state, &namespace).await?;

        Ok(Self::new(
            auth,
            namespace,
            state.namespaces.meta_store().clone(),
        ))
    }
}
