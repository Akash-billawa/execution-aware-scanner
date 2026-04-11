use crate::error::ScannerError;
use scanner_common::{RuntimeDisposition, SbomComponent};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use tokio::fs;

#[derive(Clone, Default)]
pub struct SbomStore {
    by_image: BTreeMap<String, Vec<SbomComponent>>,
}

impl SbomStore {
    pub async fn load_from_dir(path: impl AsRef<Path>) -> Result<Self, ScannerError> {
        let mut store = BTreeMap::new();
        let mut entries = fs::read_dir(path).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let content = fs::read_to_string(&path).await?;
            let image = path
                .file_stem()
                .and_then(|name| name.to_str())
                .unwrap_or("unknown")
                .replace('_', ":");
            let components = serde_json::from_str::<Vec<SbomComponent>>(&content)?;
            store.insert(image, components);
        }

        Ok(Self { by_image: store })
    }

    pub fn components_for_image(&self, image: &str) -> Vec<SbomComponent> {
        self.by_image.get(image).cloned().unwrap_or_default()
    }

    pub fn classify_runtime_paths(
        &self,
        image: &str,
        observed_paths: &BTreeSet<String>,
    ) -> Vec<(SbomComponent, RuntimeDisposition)> {
        self.components_for_image(image)
            .into_iter()
            .map(|component| {
                let reachable = component
                    .paths
                    .iter()
                    .any(|path| observed_paths.contains(path));
                let state = if reachable {
                    RuntimeDisposition::Reachable
                } else {
                    RuntimeDisposition::Dormant
                };
                (component, state)
            })
            .collect()
    }
}
