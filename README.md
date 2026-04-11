# Execution-Aware eBPF Scanner

[![CI](https://github.com/example/execution-aware-scanner/actions/workflows/ci.yaml/badge.svg)](https://github.com/example/execution-aware-scanner/actions/workflows/ci.yaml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)

A production-grade eBPF-based security scanner that correlates runtime execution with SBOM vulnerabilities to identify truly exploitable threats.

## Features

- **Real-time eBPF Monitoring**: Traces process execution, file access, and network connections
- **Execution-Aware Risk Scoring**: Combines CVSS, EPSS, CISA KEV, and runtime reachability
- **Auto-Generated Seccomp**: Creates least-privilege syscall profiles from observed behavior
- **Threat Intelligence**: Integrates CISA KEV and EPSS for exploitability assessment
- **Kubernetes Native**: Full K8s metadata correlation and automated remediation
- **XDP/TC Enforcement**: Kernel-level network filtering for C2 traffic

## Quick Start

### Prerequisites

- Linux kernel 5.8+ with BTF support
- Kubernetes 1.25+ (for K8s deployment)
- Rust 1.70+ (for building from source)

### Docker (Quickest)

```bash
docker run -d \
  --name scanner \
  --privileged \
  --pid=host \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /proc:/host/proc:ro \
  -v /var/lib/scanner:/var/lib/scanner \
  ghcr.io/example/execution-aware-scanner:latest
```

### Kubernetes (Recommended)

```bash
# Add Helm repository
helm repo add execution-aware-scanner \
  https://example.github.io/execution-aware-scanner

# Install
helm install scanner execution-aware-scanner/execution-aware-scanner \
  --namespace execution-aware-scanner \
  --create-namespace

# Verify
kubectl get pods -n execution-aware-scanner
kubectl logs -n execution-aware-scanner -l app.kubernetes.io/name=execution-aware-scanner
```

### Build from Source

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Install eBPF toolchain
rustup target add bpfel-unknown-none
cargo install bpf-linker

# Clone and build
git clone https://github.com/example/execution-aware-scanner.git
cd execution-aware-scanner
cargo build --release

# Run
sudo ./target/release/scanner-agent
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    User Space                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │   Scanner    │  │    Risk      │  │ Enforcement  │    │
│  │   Agent      │◄─┤   Engine     │◄─┤  Controller  │    │
│  └──────┬───────┘  └──────────────┘  └──────────────┘    │
│         │                                                   │
│    Ring │ Buffers                                           │
│         ▼                                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │   K8s      │  │    Intel     │  │   Metrics    │    │
│  │   Cache    │  │    Feed      │  │   Server     │    │
│  └──────────────┘  └──────────────┘  └──────────────┘    │
└─────────────────────────────────────────────────────────────┘
                            │
                    ┌───────┴───────┐
                    │  eBPF Programs  │
                    │  (Kernel Space) │
                    └───────────────┘
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `RUST_LOG` | Log level (error, warn, info, debug, trace) | `info` |
| `SCANNER__METRICS__BIND_ADDR` | Metrics server bind address | `0.0.0.0:9898` |
| `SCANNER__RISK__MINIMUM_CVSS` | Minimum CVSS score for findings | `4.0` |
| `SCANNER__RISK__MINIMUM_EPSS` | Minimum EPSS score for findings | `0.1` |
| `SCANNER__INTEL__REFRESH_INTERVAL_SECS` | Threat intel refresh interval | `21600` |
| `SCANNER__REMEDIATOR__ENABLED` | Enable auto-remediation | `true` |
| `SCANNER__REMEDIATOR__AUTO_SECCOMP` | Auto-generate seccomp profiles | `true` |

### Config File

Create `scanner.yaml`:

```yaml
scanner:
  sbom_dir: "/var/lib/scanner/sboms"
  seccomp_output_dir: "/var/lib/scanner/seccomp"
  bpf_object_path: "/opt/scanner/scanner-ebpf.o"

risk:
  min_cvss: 4.0
  min_epss: 0.1
  weights:
    cvss: 0.45
    epss: 0.25
    kev: 0.15
    runtime: 0.15

intel:
  kev_url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
  epss_url: "https://api.first.org/data/v1/epss"

webhook:
  enabled: true
  endpoints:
    - name: siem
      url: "https://siem.company.com/webhook"
      min_priority: High
```

## Usage

### Generate SBOMs

```bash
# Install Syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b /usr/local/bin

# Generate SBOM
sudo syft nginx:latest -o spdx-json=/var/lib/scanner/sboms/nginx.json

# Generate for your images
for image in app:v1.0 api:v2.0 db:v1.0; do
    name=$(echo $image | tr '/:' '_')
    sudo syft $image -o spdx-json=/var/lib/scanner/sboms/${name}.json
done
```

### Monitor Metrics

```bash
# Port-forward metrics (K8s)
kubectl port-forward -n execution-aware-scanner \
  svc/execution-aware-scanner-metrics 9898:9898 &

# View metrics
curl http://localhost:9898/metrics

# Check health
curl http://localhost:9898/health
curl http://localhost:9898/ready
```

### Prometheus Queries

```promql
# Event rate
rate(scanner_events_total[5m])

# Critical findings
scanner_findings_total{priority="Critical"}

# Event drop rate
rate(scanner_dropped_events[5m]) / rate(scanner_events_total[5m])
```

## Documentation

- [Production Deployment Guide](docs/DEPLOYMENT_GUIDE.md) - Complete deployment instructions
- [Operations Guide](docs/OPERATIONS.md) - Day-to-day operations
- [Architecture](docs/ARCHITECTURE.md) - System design and components
- [Contributing](CONTRIBUTING.md) - Contribution guidelines

## Project Structure

```
execution-aware-scanner/
├── scanner-common/          # Shared types and utilities
├── scanner-ebpf/            # Kernel-space eBPF programs
├── scanner-agent/           # User-space daemon
├── deploy/                  # Kubernetes manifests
├── helm/                    # Helm charts
├── docs/                    # Documentation
├── examples/                # Example configurations
└── .github/workflows/       # CI/CD pipelines
```

## Security

- The scanner requires privileged access to load eBPF programs
- Generated seccomp profiles should be reviewed before deployment
- Webhook tokens should be stored in Kubernetes secrets
- Network policies are included for egress control

See [SECURITY.md](SECURITY.md) for security policies and reporting vulnerabilities.

## License

This project is licensed under the Apache License 2.0 - see [LICENSE](LICENSE) for details.

## Support

- GitHub Issues: https://github.com/example/execution-aware-scanner/issues
- Discussions: https://github.com/example/execution-aware-scanner/discussions
- Slack: [#execution-aware-scanner](https://example.slack.com)

## Acknowledgments

- [Aya](https://aya-rs.dev/) - eBPF library for Rust
- [Tokio](https://tokio.rs/) - Async runtime
- [Kube-rs](https://kube.rs/) - Kubernetes client for Rust

---

**Status**: Production Ready | **Version**: 1.0.0 | **Last Updated**: 2024
