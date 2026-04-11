use crate::error::ScannerError;
use std::collections::BTreeMap;
use std::path::Path;
use tokio::fs;

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
            let cgroup_path_str = parts[2];
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
    // Docker: .../docker/<container_id>
    // containerd: .../containerd/<container_id>
    // cri-o: .../cri-o/<container_id>
    // k8s: .../kubepods/burstable/<pod_uid>/<container_id>

    let parts: Vec<&str> = cgroup_path.split('/').collect();

    for (i, part) in parts.iter().enumerate() {
        match *part {
            "docker" => {
                return parts.get(i + 1).map(|s| normalize_id(s));
            }
            "containerd" | "cri-o" => {
                return parts.get(i + 1).map(|s| normalize_id(s));
            }
            "kubepods" => {
                // Look for container ID at end of path
                if let Some(last) = parts.last() {
                    if is_container_id(last) {
                        return Some(normalize_id(last));
                    }
                }
            }
            _ => {}
        }
    }

    None
}

fn is_container_id(s: &str) -> bool {
    let normalized = normalize_id(s);
    normalized.len() == 64
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
