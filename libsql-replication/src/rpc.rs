pub mod proxy {
    #![allow(clippy::all)]
    include!("generated/proxy.rs");

    use rusqlite::types::ValueRef;

    impl From<ValueRef<'_>> for RowValue {
        fn from(value: ValueRef<'_>) -> Self {
            use row_value::Value;

            let value = Some(match value {
                ValueRef::Null => Value::Null(true),
                ValueRef::Integer(i) => Value::Integer(i),
                ValueRef::Real(x) => Value::Real(x),
                ValueRef::Text(s) => Value::Text(String::from_utf8(s.to_vec()).unwrap()),
                ValueRef::Blob(b) => Value::Blob(b.to_vec()),
            });

            RowValue { value }
        }
    }
}

pub mod replication {
    #![allow(clippy::all)]
    use std::pin::Pin;

    use tokio_stream::Stream;
    use uuid::Uuid;

    pub type BoxStream<'a, T> = Pin<Box<dyn Stream<Item = T> + Send + 'a>>;

    use self::replication_log_server::ReplicationLog;
    include!("generated/wal_log.rs");

    pub const NO_HELLO_ERROR_MSG: &str = "NO_HELLO";
    pub const NEED_SNAPSHOT_ERROR_MSG: &str = "NEED_SNAPSHOT";
    /// A tonic error code to signify that a namespace doesn't exist.
    pub const NAMESPACE_DOESNT_EXIST: &str = "NAMESPACE_DOESNT_EXIST";

    pub const SESSION_TOKEN_KEY: &str = "x-session-token";
    pub const NAMESPACE_METADATA_KEY: &str = "x-namespace-bin";

    // Verify that the session token is valid
    pub fn verify_session_token(
        token: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Sync + Send + 'static>> {
        let s = std::str::from_utf8(token)?;
        s.parse::<Uuid>()?;

        Ok(())
    }

    impl HelloRequest {
        pub fn new() -> Self {
            Self {
                handshake_version: Some(1),
            }
        }
    }

    pub type BoxReplicationService = Box<
        dyn ReplicationLog<
            LogEntriesStream = BoxStream<'static, Result<Frame, tonic::Status>>,
            SnapshotStream = BoxStream<'static, Result<Frame, tonic::Status>>,
        >,
    >;

    #[tonic::async_trait]
    impl ReplicationLog for BoxReplicationService {
        type LogEntriesStream = BoxStream<'static, Result<Frame, tonic::Status>>;
        type SnapshotStream = BoxStream<'static, Result<Frame, tonic::Status>>;

        async fn log_entries(
            &self,
            req: tonic::Request<LogOffset>,
        ) -> Result<tonic::Response<Self::LogEntriesStream>, tonic::Status> {
            self.as_ref().log_entries(req).await
        }

        async fn batch_log_entries(
            &self,
            req: tonic::Request<LogOffset>,
        ) -> Result<tonic::Response<Frames>, tonic::Status> {
            self.as_ref().batch_log_entries(req).await
        }

        async fn hello(
            &self,
            req: tonic::Request<HelloRequest>,
        ) -> Result<tonic::Response<HelloResponse>, tonic::Status> {
            self.as_ref().hello(req).await
        }

        async fn snapshot(
            &self,
            req: tonic::Request<LogOffset>,
        ) -> Result<tonic::Response<Self::SnapshotStream>, tonic::Status> {
            self.as_ref().snapshot(req).await
        }
    }
}

pub mod metadata {
    #![allow(clippy::all)]
    include!("generated/metadata.rs");
}

#[cfg(test)]
mod test {
    use prost::Message;

    use super::metadata::{DatabaseConfig, ReplicatedFence};
    use super::proxy::{error::ErrorCode, Error};

    /// `proxy.Error` as a peer built before `stable_code` existed knows it.
    #[derive(Clone, PartialEq, ::prost::Message)]
    struct ErrorWithoutStableCode {
        #[prost(enumeration = "ErrorCode", tag = "1")]
        code: i32,
        #[prost(string, tag = "2")]
        message: String,
        #[prost(int32, tag = "3")]
        extended_code: i32,
    }

    /// The legacy part of `metadata.DatabaseConfig`, as a peer built before `fence` existed
    /// knows it (the fields in between are skipped the same way as `fence` is).
    #[derive(Clone, PartialEq, ::prost::Message)]
    struct DatabaseConfigWithoutFence {
        #[prost(bool, tag = "1")]
        block_reads: bool,
        #[prost(bool, tag = "2")]
        block_writes: bool,
        #[prost(string, optional, tag = "3")]
        block_reason: Option<String>,
        #[prost(uint64, tag = "4")]
        max_db_pages: u64,
    }

    fn error(stable_code: Option<&str>) -> Error {
        Error {
            code: ErrorCode::SqlError as i32,
            message: "writes are fenced".into(),
            extended_code: 23,
            stable_code: stable_code.map(Into::into),
        }
    }

    #[test]
    fn proxy_error_stable_code_is_additive() {
        // A newer server's error, read by an older replica: the known fields are intact and
        // the stable code is skipped.
        let new = error(Some("MIGRATION_WRITE_FENCED"));
        let old = ErrorWithoutStableCode::decode(&new.encode_to_vec()[..]).unwrap();
        assert_eq!(
            old,
            ErrorWithoutStableCode {
                code: ErrorCode::SqlError as i32,
                message: "writes are fenced".into(),
                extended_code: 23,
            }
        );

        // An older server's error, read by a newer replica: no typed outcome.
        let decoded = Error::decode(&old.encode_to_vec()[..]).unwrap();
        assert_eq!(decoded, error(None));

        // Without a stable code the encoding is exactly the older one, so an error that has no
        // typed outcome is unchanged on the wire.
        assert_eq!(error(None).encode_to_vec(), old.encode_to_vec());

        // And the field round-trips between newer peers.
        assert_eq!(Error::decode(&new.encode_to_vec()[..]).unwrap(), new);
    }

    fn config(fence: Option<ReplicatedFence>) -> DatabaseConfig {
        DatabaseConfig {
            block_reads: true,
            block_writes: true,
            block_reason: Some("namespace fence".into()),
            max_db_pages: 1024,
            fence,
            ..Default::default()
        }
    }

    #[test]
    fn replicated_fence_is_additive() {
        let fence = ReplicatedFence {
            state: "SOURCE_READ_FENCED".into(),
            revision: 3,
        };

        // A newer primary's config, read by an older replica: the legacy block fields are
        // intact, so the older replica still applies the legacy mirror of the fence.
        let new = config(Some(fence.clone()));
        let old = DatabaseConfigWithoutFence::decode(&new.encode_to_vec()[..]).unwrap();
        assert_eq!(
            old,
            DatabaseConfigWithoutFence {
                block_reads: true,
                block_writes: true,
                block_reason: Some("namespace fence".into()),
                max_db_pages: 1024,
            }
        );

        // An older primary's config, read by a newer replica: no fence.
        let decoded = DatabaseConfig::decode(&old.encode_to_vec()[..]).unwrap();
        assert_eq!(decoded.fence, None);
        assert_eq!(decoded, config(None));

        // Without a fence the encoding is exactly the older one: a stored configuration, which
        // never carries a fence, is unchanged.
        assert_eq!(config(None).encode_to_vec(), old.encode_to_vec());

        // And the fence round-trips between newer peers.
        let round_trip = DatabaseConfig::decode(&new.encode_to_vec()[..]).unwrap();
        assert_eq!(round_trip.fence, Some(fence));
    }
}
