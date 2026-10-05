//! The fence registry (`docs/NAMESPACE_FENCE.md` section 7.1).
//!
//! One [`FenceController`] per namespace, held outside the namespace cache so that eviction and
//! lazy reload hand a reloaded namespace the controller it had, with the same gate, revision
//! and write generation. The registry is seeded from the metastore before the namespace store
//! serves anything, and namespaces without fence state get an `UNFENCED` controller on first
//! use.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;

use crate::namespace::NamespaceName;

use super::controller::FenceController;
use super::outcome::FenceError;
use super::state::OperationClass;
use super::store::StoredFence;

#[derive(Debug, Default)]
pub struct FenceRegistry {
    controllers: Mutex<HashMap<NamespaceName, Arc<FenceController>>>,
}

impl FenceRegistry {
    /// A registry holding a controller for every namespace with fence state, as returned by
    /// `MetaStore::load_fences` (which includes the namespaces startup could not recover).
    pub fn seeded(fences: impl IntoIterator<Item = (NamespaceName, StoredFence)>) -> Self {
        let controllers = fences
            .into_iter()
            .map(|(ns, fence)| {
                if let StoredFence::Unavailable { detail, reason, .. } = &fence {
                    tracing::error!(
                        namespace = %ns,
                        %detail,
                        "namespace fence state is unavailable; the namespace is not served: {reason}"
                    );
                }
                let controller = FenceController::new(ns.clone(), fence);
                (ns, controller)
            })
            .collect();
        Self {
            controllers: Mutex::new(controllers),
        }
    }

    /// The controller of `namespace`, creating an `UNFENCED` one if it has none yet.
    pub fn controller(&self, namespace: &NamespaceName) -> Arc<FenceController> {
        self.controllers
            .lock()
            .entry(namespace.clone())
            .or_insert_with(|| FenceController::unfenced(namespace.clone()))
            .clone()
    }

    /// The controller of `namespace`, if it has one.
    pub fn get(&self, namespace: &NamespaceName) -> Option<Arc<FenceController>> {
        self.controllers.lock().get(namespace).cloned()
    }

    /// Forget `namespace`'s controller. Only for a namespace that was deleted together with its
    /// fence state.
    pub fn remove(&self, namespace: &NamespaceName) -> Option<Arc<FenceController>> {
        self.controllers.lock().remove(namespace)
    }

    /// Refuse a namespace whose fence state is `UNKNOWN_UNAVAILABLE`, before any work is done
    /// to serve it.
    pub fn check_available(&self, namespace: &NamespaceName) -> Result<(), FenceError> {
        match self.get(namespace) {
            Some(controller) => {
                let gate = controller.gate();
                if gate.is_unavailable() {
                    gate.permits(OperationClass::NormalRead)
                } else {
                    Ok(())
                }
            }
            None => Ok(()),
        }
    }

    pub fn len(&self) -> usize {
        self.controllers.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;
    use uuid::Uuid;

    use super::*;
    use crate::config::MetaStoreConfig;
    use crate::connection::config::DatabaseConfig;
    use crate::database::DatabaseKind;
    use crate::namespace::fence::command::{FenceCommand, FenceRequest};
    use crate::namespace::fence::outcome::{FenceDetail, FenceOutcome};
    use crate::namespace::fence::record::ServerIdentity;
    use crate::namespace::fence::state::FenceState;
    use crate::namespace::fence::store as fence_store;
    use crate::namespace::meta_store::{metastore_connection_maker, FenceContext, MetaStore};

    const LOG: Uuid = Uuid::from_u128(0x10);
    const OP: Uuid = Uuid::from_u128(0xa);

    async fn open(dir: &std::path::Path) -> MetaStore {
        let (maker, manager) = metastore_connection_maker(None, dir).await.unwrap();
        let conn = maker().unwrap();
        MetaStore::new(
            MetaStoreConfig {
                namespace_fence: true,
                ..Default::default()
            },
            dir,
            conn,
            manager,
            DatabaseKind::Primary,
        )
        .await
        .unwrap()
    }

    fn ctx() -> FenceContext {
        FenceContext::now(
            ServerIdentity {
                build: "test".into(),
                instance_id: Uuid::from_u128(0x99),
            },
            Some(LOG),
        )
    }

    #[tokio::test]
    async fn seeded_from_load_fences_including_recovered_names() {
        let tmp = tempdir().unwrap();
        {
            let meta = open(tmp.path()).await;
            for ns in ["fenced", "plain"] {
                meta.handle(ns.into())
                    .await
                    .unwrap()
                    .store(DatabaseConfig::default())
                    .await
                    .unwrap();
            }
            let controller = FenceController::unfenced("fenced".into());
            controller
                .apply_command(
                    &meta,
                    FenceRequest {
                        namespace: "fenced".into(),
                        operation_id: OP,
                        command_id: Uuid::from_u128(1),
                        expected_state: FenceState::Unfenced,
                        expected_revision: 0,
                        command: FenceCommand::AcquireSourceWriteFence {
                            expected_log_id: LOG,
                            drain_policy: None,
                        },
                    },
                    ctx(),
                )
                .await
                .unwrap();
            meta.shutdown().await.unwrap();
        }
        // A directory with an unreadable marker and no config: startup cannot recover it.
        let lost = tmp.path().join("dbs").join("lost");
        std::fs::create_dir_all(&lost).unwrap();
        std::fs::write(lost.join(fence_store::MARKER_FILE_NAME), b"garbage").unwrap();

        // Restart.
        let meta = open(tmp.path()).await;
        let registry = FenceRegistry::seeded(meta.load_fences().await.unwrap());
        assert_eq!(registry.len(), 2);

        let fenced = registry.get(&"fenced".into()).unwrap();
        let gate = fenced.gate();
        assert_eq!(gate.state(), FenceState::SourceDraining);
        assert_eq!(gate.revision(), 1);
        assert_eq!(gate.operation_id(), Some(OP));
        assert_eq!(
            fenced
                .permits(OperationClass::NormalWrite)
                .unwrap_err()
                .outcome(),
            FenceOutcome::MigrationWriteFenced
        );
        assert!(registry.check_available(&"fenced".into()).is_ok());

        let lost = registry.get(&"lost".into()).unwrap();
        assert!(lost.gate().is_unavailable());
        let e = registry.check_available(&"lost".into()).unwrap_err();
        assert_eq!(e.outcome(), FenceOutcome::FenceStateUnavailable);
        assert_eq!(e.detail(), Some(FenceDetail::CorruptRecord));
        for class in [OperationClass::NormalRead, OperationClass::NormalWrite] {
            assert!(lost.permits(class).is_err());
        }

        // An ordinary namespace has no controller until it is used, then an UNFENCED one.
        assert!(registry.get(&"plain".into()).is_none());
        let plain = registry.controller(&"plain".into());
        assert_eq!(plain.gate().state(), FenceState::Unfenced);
        assert!(plain.permits(OperationClass::NormalWrite).is_ok());
        assert_eq!(registry.len(), 3);
    }

    #[test]
    fn controller_is_stable_until_removed() {
        let registry = FenceRegistry::default();
        let a = registry.controller(&"ns".into());
        let b = registry.controller(&"ns".into());
        assert!(Arc::ptr_eq(&a, &b));
        assert!(Arc::ptr_eq(&registry.get(&"ns".into()).unwrap(), &a));
        assert!(registry.remove(&"ns".into()).is_some());
        assert!(!Arc::ptr_eq(&registry.controller(&"ns".into()), &a));
    }
}
