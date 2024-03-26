use axum::extract::FromRequestParts;

use crate::{
    auth::{Auth, AuthError, Jwt, UserAuthContext},
    connection::RequestContext,
};

use super::{db_factory, AppState};

#[async_trait::async_trait]
impl FromRequestParts<AppState> for RequestContext {
    type Rejection = crate::error::Error;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &AppState,
    ) -> std::result::Result<Self, Self::Rejection> {
        // DUPL2 START
        let namespace = db_factory::namespace_from_headers(
            &parts.headers,
            state.disable_default_namespace,
            state.disable_namespaces,
        )?;
        let ns_store = &state.namespaces;
        let context = parts
            .headers
            .get(hyper::header::AUTHORIZATION)
            .ok_or(AuthError::AuthHeaderNotFound)
            .and_then(|h| h.to_str().map_err(|_| AuthError::AuthHeaderNonAscii))
            .and_then(|t| UserAuthContext::from_auth_str(t));
        // DUPL2 END
        // todo dupe #auth
        // DUPL1 START

        let decoding_key = ns_store
            .with(namespace.clone(), |ns| ns.jwt_key())
            .await??;

        let auth_strat = decoding_key
            .map(Jwt::new)
            .map(Auth::new)
            .unwrap_or_else(|| state.user_auth_strategy.clone());

        let auth = auth_strat.authenticate(context)?;
        // DUPL1 END

        Ok(Self::new(
            auth,
            namespace,
            state.namespaces.meta_store().clone(),
        ))
    }
}
