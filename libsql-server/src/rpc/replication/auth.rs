use tonic::{Code, Status};

use crate::auth::parsers::parse_grpc_auth_header;
use crate::auth::{Auth, Jwt};
use crate::namespace::{NamespaceName, NamespaceStore};

pub async fn authenticate<T>(
    namespaces: &NamespaceStore,
    req: &tonic::Request<T>,
    namespace: NamespaceName,
    user_auth_strategy: &Option<Auth>,
    allow_user_auth_fallback: bool,
) -> Result<(), Status> {
    // todo dupe #auth
    let namespace_jwt_keys = namespaces.with(namespace.clone(), |ns| ns.jwt_keys()).await;

    let auth = match namespace_jwt_keys {
        Ok(Ok(Some(key))) => Some(Auth::new(Jwt::new(key))),
        Ok(Ok(None)) => user_auth_strategy.clone(),
        Err(e) => {
            // `namespace_error_status` is the one place that classifies the
            // store's errors: `FAILED_PRECONDITION` is a missing namespace,
            // `UNAVAILABLE` one that exists but cannot be served right now.
            // Only a missing namespace may fall back to the user strategy.
            let status = crate::rpc::namespace_error_status(&e);
            match status.code() {
                Code::FailedPrecondition if allow_user_auth_fallback => user_auth_strategy.clone(),
                Code::FailedPrecondition | Code::Unavailable => return Err(status),
                _ => Err(Status::internal(format!(
                    "Error fetching jwt key for a namespace: {}",
                    e
                )))?,
            }
        }
        Ok(Err(e)) => Err(Status::internal(format!(
            "Error fetching jwt key for a namespace: {}",
            e
        )))?,
    };

    if let Some(auth) = auth {
        let context = parse_grpc_auth_header(req.metadata(), &auth.user_strategy.required_fields())
            .map_err(|e| tonic::Status::internal(format!("Error parsing auth header: {}", e)))?;
        auth.authenticate(context)?;
    }

    Ok(())
}
