use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const ARGS_LEN: usize = 256;
pub const PATH_LEN: usize = 256;

#[repr(u8)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventKind {
    Exec = 1,
    Mmap = 2,
    Open = 3,
    Connect = 4,
    Bind = 5,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExecEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub gid: u32,
    pub cgroup_id: u64,
    pub ppid: u32,
    pub command: [u8; 16],
    pub argv: [u8; ARGS_LEN],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FileEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub cgroup_id: u64,
    pub command: [u8; 16],
    pub path: [u8; PATH_LEN],
    pub kind: EventKind,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NetEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub cgroup_id: u64,
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub family: u16,
    pub protocol: u8,
    pub kind: EventKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeIdentity {
    pub node_name: String,
    pub namespace: String,
    pub pod_name: String,
    pub container_name: String,
    pub image: String,
    pub workload: String,
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SbomComponent {
    pub package: String,
    pub version: String,
    pub purl: Option<String>,
    pub cves: Vec<CveRecord>,
    pub paths: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CveRecord {
    pub id: String,
    pub cvss: f32,
    pub severity: Severity,
    pub description: Option<String>,
    pub cwe: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RuntimeDisposition {
    Reachable,
    Dormant,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RiskSignal {
    pub cve: String,
    pub cvss: f32,
    pub epss: f32,
    pub kev: bool,
    pub runtime: RuntimeDisposition,
    pub package: String,
    pub observed_paths: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    pub id: String,
    pub detected_at: DateTime<Utc>,
    pub identity: RuntimeIdentity,
    pub signal: RiskSignal,
    pub score: f32,
    pub priority: Priority,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Priority {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

// Manual serde implementations for event types with large arrays
impl serde::Serialize for ExecEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("ExecEvent", 10)?;
        state.serialize_field("timestamp_ns", &self.timestamp_ns)?;
        state.serialize_field("pid", &self.pid)?;
        state.serialize_field("tgid", &self.tgid)?;
        state.serialize_field("uid", &self.uid)?;
        state.serialize_field("gid", &self.gid)?;
        state.serialize_field("cgroup_id", &self.cgroup_id)?;
        state.serialize_field("ppid", &self.ppid)?;
        state.serialize_field("command", &self.command.as_slice())?;
        state.serialize_field("argv", &self.argv.as_slice())?;
        state.end()
    }
}

impl<'de> serde::Deserialize<'de> for ExecEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct ExecEventHelper {
            timestamp_ns: u64,
            pid: u32,
            tgid: u32,
            uid: u32,
            gid: u32,
            cgroup_id: u64,
            ppid: u32,
            #[serde(with = "serde_bytes")]
            command: Vec<u8>,
            #[serde(with = "serde_bytes")]
            argv: Vec<u8>,
        }

        let helper = ExecEventHelper::deserialize(deserializer)?;
        let mut event = ExecEvent {
            timestamp_ns: helper.timestamp_ns,
            pid: helper.pid,
            tgid: helper.tgid,
            uid: helper.uid,
            gid: helper.gid,
            cgroup_id: helper.cgroup_id,
            ppid: helper.ppid,
            command: [0u8; 16],
            argv: [0u8; ARGS_LEN],
        };

        if helper.command.len() == 16 {
            event.command.copy_from_slice(&helper.command);
        }
        if helper.argv.len() == ARGS_LEN {
            event.argv.copy_from_slice(&helper.argv);
        }

        Ok(event)
    }
}

impl serde::Serialize for FileEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("FileEvent", 7)?;
        state.serialize_field("timestamp_ns", &self.timestamp_ns)?;
        state.serialize_field("pid", &self.pid)?;
        state.serialize_field("tgid", &self.tgid)?;
        state.serialize_field("cgroup_id", &self.cgroup_id)?;
        state.serialize_field("command", &self.command.as_slice())?;
        state.serialize_field("path", &self.path.as_slice())?;
        state.serialize_field("kind", &self.kind)?;
        state.end()
    }
}

impl<'de> serde::Deserialize<'de> for FileEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct FileEventHelper {
            timestamp_ns: u64,
            pid: u32,
            tgid: u32,
            cgroup_id: u64,
            #[serde(with = "serde_bytes")]
            command: Vec<u8>,
            #[serde(with = "serde_bytes")]
            path: Vec<u8>,
            kind: EventKind,
        }

        let helper = FileEventHelper::deserialize(deserializer)?;
        let mut event = FileEvent {
            timestamp_ns: helper.timestamp_ns,
            pid: helper.pid,
            tgid: helper.tgid,
            cgroup_id: helper.cgroup_id,
            command: [0u8; 16],
            path: [0u8; PATH_LEN],
            kind: helper.kind,
        };

        if helper.command.len() == 16 {
            event.command.copy_from_slice(&helper.command);
        }
        if helper.path.len() == PATH_LEN {
            event.path.copy_from_slice(&helper.path);
        }

        Ok(event)
    }
}

impl serde::Serialize for NetEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("NetEvent", 11)?;
        state.serialize_field("timestamp_ns", &self.timestamp_ns)?;
        state.serialize_field("pid", &self.pid)?;
        state.serialize_field("tgid", &self.tgid)?;
        state.serialize_field("cgroup_id", &self.cgroup_id)?;
        state.serialize_field("saddr", &self.saddr)?;
        state.serialize_field("daddr", &self.daddr)?;
        state.serialize_field("sport", &self.sport)?;
        state.serialize_field("dport", &self.dport)?;
        state.serialize_field("family", &self.family)?;
        state.serialize_field("protocol", &self.protocol)?;
        state.serialize_field("kind", &self.kind)?;
        state.end()
    }
}

impl<'de> serde::Deserialize<'de> for NetEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct NetEventHelper {
            timestamp_ns: u64,
            pid: u32,
            tgid: u32,
            cgroup_id: u64,
            saddr: u32,
            daddr: u32,
            sport: u16,
            dport: u16,
            family: u16,
            protocol: u8,
            kind: EventKind,
        }

        let helper = NetEventHelper::deserialize(deserializer)?;
        Ok(NetEvent {
            timestamp_ns: helper.timestamp_ns,
            pid: helper.pid,
            tgid: helper.tgid,
            cgroup_id: helper.cgroup_id,
            saddr: helper.saddr,
            daddr: helper.daddr,
            sport: helper.sport,
            dport: helper.dport,
            family: helper.family,
            protocol: helper.protocol,
            kind: helper.kind,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SeccompProfile {
    pub default_action: String,
    pub architectures: Vec<String>,
    pub syscalls: Vec<SeccompRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SeccompRule {
    pub names: Vec<String>,
    pub action: String,
}

pub fn c_string(buf: &[u8]) -> String {
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::c_string;

    #[test]
    fn trims_zeroes() {
        let mut raw = [0u8; 8];
        raw[..4].copy_from_slice(b"bash");
        assert_eq!(c_string(&raw), "bash");
    }
}
