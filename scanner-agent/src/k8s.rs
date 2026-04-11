use crate::error::ScannerError;
use k8s_openapi::api::core::v1::Pod;
use kube::{Api, Client, ResourceExt};
use scanner_common::RuntimeIdentity;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Default)]
pub struct PodCache {
    by_container_id: Arc<RwLock<BTreeMap<String, RuntimeIdentity>>>,
}

impl PodCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn refresh(&self, client: Client, node_name: &str) -> Result<(), ScannerError> {
        let pods: Api<Pod> = Api::all(client);
        let list = pods.list(&Default::default()).await?;
        let mut index = BTreeMap::new();

        for pod in list.items.into_iter().filter(|pod| {
            pod.spec
                .as_ref()
                .and_then(|spec| spec.node_name.clone())
                .as_deref()
                == Some(node_name)
        }) {
            if let Some(status) = pod.status.as_ref() {
                for container in status.container_statuses.clone().unwrap_or_default() {
                    if let Some(container_id) = container.container_id {
                        index.insert(
                            normalize_container_id(&container_id),
                            RuntimeIdentity {
                                node_name: node_name.to_string(),
                                namespace: pod.namespace().unwrap_or_default(),
                                pod_name: pod.name_any(),
                                container_name: container.name,
                                image: container.image,
                                workload: owner_name(&pod),
                                labels: pod.labels().clone().into_iter().collect(),
                            },
                        );
                    }
                }
            }
        }

        *self.by_container_id.write().await = index;
        Ok(())
    }

    pub async fn lookup(&self, container_id: &str) -> Option<RuntimeIdentity> {
        self.by_container_id.read().await.get(container_id).cloned()
    }
}

fn normalize_container_id(raw: &str) -> String {
    raw.rsplit('/').next().unwrap_or(raw).to_string()
}

fn owner_name(pod: &Pod) -> String {
    pod.metadata
        .owner_references
        .as_ref()
        .and_then(|owners| owners.first())
        .map(|owner| owner.name.clone())
        .unwrap_or_else(|| pod.name_any())
}
