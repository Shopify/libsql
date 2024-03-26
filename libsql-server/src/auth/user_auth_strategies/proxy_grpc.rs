use tonic::{metadata::MetadataMap, Status};

use super::{UserAuthContext, UserAuthStrategy};
use crate::auth::{constants::GRPC_PROXY_AUTH_HEADER, AuthError, Authenticated};

pub struct ProxyGrpc {
    metadata: MetadataMap,
}

impl UserAuthStrategy for ProxyGrpc {
    fn authenticate(
        &self,
        _context: Result<UserAuthContext, AuthError>,
    ) -> Result<Authenticated, AuthError> {
        tracing::trace!("proxy grpc auth");

        let auth = self
            .metadata
            .get(GRPC_PROXY_AUTH_HEADER)
            .map(|v| v.to_str())
            .ok_or(AuthError::AuthProxyHeaderNotFound)?
            .map(|s| serde_json::from_str::<Authenticated>(s).unwrap())
            .map_err(|_| AuthError::AuthHeaderNonAscii)?;

        Ok(auth)
    }
}

impl ProxyGrpc {
    pub fn new(metadata: MetadataMap) -> Self {
        Self { metadata }
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn authenticates() {
//         let strategy = Disabled::new();
//         let context = Ok(UserAuthContext::empty());

//         assert!(matches!(
//             strategy.authenticate(context).unwrap(),
//             Authenticated::FullAccess
//         ))
//     }
// }
