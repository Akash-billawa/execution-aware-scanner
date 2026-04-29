use crate::state::{SignalType, WorkloadState};
use crate::vuln_detector::Vulnerability;
use scanner_common::RuntimeDisposition;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeMatch {
    pub disposition: RuntimeDisposition,
    pub observed_paths: BTreeSet<String>,
    pub signal_weight: f32,
    pub evidence: Vec<RuntimeEvidence>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeEvidence {
    pub signal_type: String,
    pub timestamp_ns: u64,
    pub details: String,
    pub confidence: f32,
}

pub fn correlate_vulnerability(workload: &WorkloadState, vuln: &Vulnerability) -> RuntimeMatch {
    let mut observed_paths = BTreeSet::new();
    let mut evidence = Vec::new();
    let mut signal_weight = 0.0_f32;

    for path in workload
        .loaded_libraries
        .iter()
        .chain(workload.observed_paths.iter())
    {
        if library_matches_package(path, &vuln.package) {
            observed_paths.insert(path.clone());
        }
    }

    if !observed_paths.is_empty() {
        for signal in &workload.signals {
            let directly_related = match signal.signal_type {
                SignalType::LibraryLoaded => observed_paths
                    .iter()
                    .any(|path| signal.details.contains(path)),
                SignalType::LargeDataTransfer => !workload.network_flows.is_empty(),
                SignalType::MprotectExec
                | SignalType::MaliciousIP
                | SignalType::SensitiveFileAccess
                | SignalType::SuspiciousExec => true,
            };

            if directly_related {
                signal_weight += signal.weight;
                evidence.push(RuntimeEvidence {
                    signal_type: format!("{:?}", signal.signal_type),
                    timestamp_ns: signal.timestamp_ns,
                    details: signal.details.clone(),
                    confidence: signal.weight.min(1.0),
                });
            }
        }
    }

    RuntimeMatch {
        disposition: if observed_paths.is_empty() {
            RuntimeDisposition::Dormant
        } else {
            RuntimeDisposition::Reachable
        },
        observed_paths,
        signal_weight,
        evidence,
    }
}

pub fn library_matches_package(path: &str, package: &str) -> bool {
    let path_lc = path.to_ascii_lowercase();
    let package_lc = normalize_package_name(package);
    let file_name = path_lc.rsplit('/').next().unwrap_or(&path_lc);
    let lib_stem = file_name
        .trim_start_matches("lib")
        .split(".so")
        .next()
        .unwrap_or(file_name);

    let aliases = package_aliases(&package_lc);
    path_lc.contains(&package_lc)
        || package_lc.contains(file_name)
        || package_lc.contains(lib_stem)
        || aliases
            .iter()
            .any(|alias| path_lc.contains(alias) || file_name.contains(alias) || lib_stem == *alias)
}

fn normalize_package_name(package: &str) -> String {
    package
        .to_ascii_lowercase()
        .trim_start_matches("lib")
        .trim_end_matches("-dev")
        .trim_end_matches("-libs")
        .to_string()
}

fn package_aliases(package: &str) -> Vec<&'static str> {
    match package {
        "openssl" | "ssl" | "ssl1.1" | "ssl3" => vec!["ssl", "crypto", "openssl"],
        "glibc" | "c6" => vec!["c", "pthread", "dl", "m"],
        "zlib" | "z1g" => vec!["z"],
        "curl" => vec!["curl"],
        "nginx" => vec!["nginx"],
        "php" | "php-fpm" => vec!["php", "php-fpm"],
        "mysql" | "mariadb" => vec!["mysql", "mariadb"],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::RuntimeSignal;
    use crate::vuln_detector::Severity;

    fn vuln(package: &str) -> Vulnerability {
        Vulnerability {
            package: package.to_string(),
            version: "1.0".to_string(),
            cve: "CVE-2026-0001".to_string(),
            severity: Severity::High,
            cvss_score: 8.0,
            description: String::new(),
            fixed_version: None,
        }
    }

    #[test]
    fn matches_openssl_to_libssl() {
        assert!(library_matches_package(
            "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
            "openssl"
        ));
    }

    #[test]
    fn unrelated_vulnerability_stays_dormant() {
        let mut workload = WorkloadState::default();
        workload
            .loaded_libraries
            .insert("/usr/lib/libssl.so.1.1".to_string());
        workload.signals.push(RuntimeSignal {
            signal_type: SignalType::LibraryLoaded,
            weight: 2.0,
            timestamp_ns: 100,
            details: "Library loaded: /usr/lib/libssl.so.1.1".to_string(),
        });

        let result = correlate_vulnerability(&workload, &vuln("mysql"));
        assert_eq!(result.disposition, RuntimeDisposition::Dormant);
        assert!(result.observed_paths.is_empty());
        assert_eq!(result.signal_weight, 0.0);
    }

    #[test]
    fn matching_library_is_reachable() {
        let mut workload = WorkloadState::default();
        workload
            .loaded_libraries
            .insert("/usr/lib/libssl.so.1.1".to_string());
        workload.signals.push(RuntimeSignal {
            signal_type: SignalType::LibraryLoaded,
            weight: 2.0,
            timestamp_ns: 100,
            details: "Library loaded: /usr/lib/libssl.so.1.1".to_string(),
        });

        let result = correlate_vulnerability(&workload, &vuln("openssl"));
        assert_eq!(result.disposition, RuntimeDisposition::Reachable);
        assert_eq!(result.signal_weight, 2.0);
        assert_eq!(result.evidence.len(), 1);
    }
}
