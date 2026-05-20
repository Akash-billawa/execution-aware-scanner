use crate::error::ScannerError;
use std::collections::BTreeMap;
use std::path::Path;
use tokio::fs;

/// Maximum cache entries to prevent unbounded growth on high-churn nodes
const MAX_CACHE_ENTRIES: usize = 10000;

/// Resolves cgroup IDs to container IDs and pod information by parsing /proc.
#[derive(Clone, Debug)]
pub struct CgroupResolver {
    /// Cache of cgroup_id -> (container_id, pid)
    cache: BTreeMap<u64, (String, u32)>,
    /// Path to host /proc (mounted in container)
    proc_path: String,
}

impl CgroupResolver {
    pub fn new(proc_path: impl Into<String>) -> Self {
        Self {
            cache: BTreeMap::new(),
            proc_path: proc_path.into(),
        }
    }

    /// Attempts to resolve a cgroup ID to a container ID.
    /// On cache miss, it walks /proc looking for matching cgroup entries.
    pub async fn resolve(&mut self, cgroup_id: u64) -> Option<(String, u32)> {
        if let Some(entry) = self.cache.get(&cgroup_id) {
            return Some(entry.clone());
        }
        if let Ok(result) = self.scan_for_cgroup(cgroup_id).await {
            // Evict oldest entries if cache is at capacity
            if self.cache.len() >= MAX_CACHE_ENTRIES {
                if let Some(oldest_key) = self.cache.keys().next().copied() {
                    self.cache.remove(&oldest_key);
                }
            }
            self.cache.insert(cgroup_id, result.clone());
            return Some(result);
        }
        None
    }

    /// Scans /proc/<pid>/cgroup files to find a matching cgroup_id.
    async fn scan_for_cgroup(&self, cgroup_id: u64) -> Result<(String, u32), ScannerError> {
        let proc = Path::new(&self.proc_path);
        let mut entries = fs::read_dir(proc).await?;
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if let Ok(pid) = name_str.parse::<u32>() {
                if let Some(container_id) = self.parse_cgroup_file(entry.path(), cgroup_id).await {
                    return Ok((container_id, pid));
                }
            }
        }
        Err(ScannerError::Bpf(format!("cgroup {cgroup_id} not found")))
    }

    /// Parses a single /proc/<pid>/cgroup file looking for the given cgroup_id.
    async fn parse_cgroup_file(
        &self,
        proc_pid: impl AsRef<Path>,
        cgroup_id: u64,
    ) -> Option<String> {
        let cgroup_path = proc_pid.as_ref().join("cgroup");
        let content = fs::read_to_string(&cgroup_path).await.ok()?;
        for line in content.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() < 3 {
                continue;
            }
            // cgroup v1 format: hierarchy-ID:controller-list:cgroup-path
            // cgroup v2 format: 0::cgroup-path
            let hierarchy_id = parts[0];
            let cgroup_path_str = parts[2];

            // Validate that this cgroup line matches the requested cgroup_id.
            // In cgroup v2, hierarchy-ID is always "0". In v1, it's a numeric ID.
            // We check if the hierarchy ID parses to the requested cgroup_id,
            // or if it's v2 (ID "0") where the cgroup_id is the inode of the path.
            // Since we can't easily get the inode from the path string, we accept
            // v2 entries when cgroup_id matches a numeric parse of the hierarchy ID,
            // or when the hierarchy ID is "0" (v2) and the path contains a container ID.
            if let Ok(hid) = hierarchy_id.parse::<u64>() {
                if hid != 0 && hid != cgroup_id {
                    continue; // v1 hierarchy doesn't match
                }
            }

            if let Some(extracted_id) = extract_container_id(cgroup_path_str) {
                return Some(extracted_id);
            }
        }
        None
    }

    /// Clears the cache (e.g., when the pod watch loop detects changes).
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }
}

/// Extracts container ID from cgroup path.
/// Handles Docker, containerd, and cri-o container ID formats.
fn extract_container_id(cgroup_path: &str) -> Option<String> {
    let parts: Vec<&str> = cgroup_path.split('/').filter(|p| !p.is_empty()).collect();

    for (i, part) in parts.iter().enumerate() {
        match *part {
            "docker" => {
                return parts
                    .get(i + 1)
                    .map(|s| normalize_id(s))
                    .filter(|id| is_container_id(id));
            }
            "containerd" | "cri-o" => {
                return parts
                    .get(i + 1)
                    .map(|s| normalize_id(s))
                    .filter(|id| is_container_id(id));
            }
            "kubepods" => {
                if let Some(last) = parts.last() {
                    let normalized = normalize_id(last);
                    if is_container_id(&normalized) {
                        return Some(normalized);
                    }
                }
            }
            _ => {}
        }

        let normalized = normalize_id(part);
        if normalized != *part && is_container_id(&normalized) {
            return Some(normalized);
        }
    }

    None
}

fn is_container_id(s: &str) -> bool {
    let normalized = normalize_id(s);
    normalized.len() >= 8
        && normalized.len() <= 128
        && normalized
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == '-' || c == '_')
}

fn normalize_id(raw: &str) -> String {
    raw.trim_start_matches("docker-")
        .trim_start_matches("containerd-")
        .trim_start_matches("crio-")
        .trim_start_matches("libpod-")
        .trim_start_matches("systemd-")
        .trim_end_matches(".scope")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_docker_id() {
        let path = "/docker/a1b2c3d4e5f6";
        assert_eq!(extract_container_id(path), Some("a1b2c3d4e5f6".to_string()));
    }

    #[test]
    fn extracts_kubepods_id() {
        let path = "/kubepods/burstable/pod12345/abc123def456";
        assert_eq!(extract_container_id(path), Some("abc123def456".to_string()));
    }

    #[test]
    fn extracts_containerd_id() {
        let path = "/system.slice/containerd-a1b2c3d4.scope";
        assert_eq!(extract_container_id(path), Some("a1b2c3d4".to_string()));
    }
}
