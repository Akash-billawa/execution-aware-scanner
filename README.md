# Execution-Aware eBPF Scanner

**From 10,000 CVEs to 10 critical findings — see what's actually exploitable in your containers**

This scanner uses eBPF to trace runtime execution, correlates with vulnerability data (EPSS, KEV), and prioritizes only vulnerabilities that are:
- ✅ **Reachable** — code is actually loaded and running
- ✅ **Exploitable** — high EPSS score (probability of exploitation)
- ✅ **Known** — in CISA KEV catalog (actively exploited in the wild)

[![CI](https://github.com/Akash-billawa/execution-aware-scanner/actions/workflows/ci.yaml/badge.svg)](https://github.com/Akash-billawa/execution-aware-scanner/actions/workflows/ci.yaml)
[![Docker](https://img.shields.io/badge/docker-ghcr.io-blue.svg)](https://ghcr.io/akash-billawa/execution-aware-scanner)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)
[![GitHub Release](https://img.shields.io/github/v/release/Akash-billawa/execution-aware-scanner)](https://github.com/Akash-billawa/execution-aware-scanner/releases)

> ⚠️ **Linux Only**: Requires Linux kernel 5.8+ with BTF support, sudo access, and eBPF-capable runtime support. Not compatible with Windows or macOS.

**Quick Demo:**
```bash
# Automated demo (proves execution-aware capability)
./scripts/demo.sh

# Manual build
cargo build --release -p scanner-agent --no-default-features
sudo ./target/release/scanner-agent
```

## 🚀 Why Execution-Aware?

**Traditional vulnerability scanners:**
- ❌ Flag vulnerabilities statically (regardless of exploitability)
- ❌ Ignore runtime context (is code actually running?)
- ❌ Generate alert fatigue (1000s of CVEs, most not exploitable)

**This scanner:**
- ✅ Prioritizes **actively exploitable** vulnerabilities
- ✅ Uses EPSS (exploit probability) + KEV (known exploited) + Runtime signals
- ✅ Reduces alert fatigue by 80%+ (focus on reachable code)
- ✅ Auto-generates seccomp profiles from observed behavior
- ✅ Blocks C2 traffic via XDP in kernel (microsecond latency)

**Real Example:**
```
[CRITICAL] CVE-2021-44228 (Log4Shell)
  Runtime: REACHABLE via /app/lib/log4j-core.jar
  CVSS: 10.0 | EPSS: 0.98 | KEV: YES
  Action: Auto-remediated (seccomp applied, egress blocked)

[LOW] CVE-2023-XXXX (OpenSSL)
  Runtime: DORMANT (present but not loaded)
  Action: Scheduled for maintenance window
```

**Result:** Security teams focus on 10 critical findings instead of 10,000 CVEs.

## 📊 Benchmark Results

**Execution-Aware vs Static Scanning:**

| Metric | Trivy (Static) | Our Scanner | Improvement |
|--------|----------------|-------------|-------------|
| Total CVEs Detected | 127 | 12 | **90% reduction** |
| False Positives | High | Low | **~80% eliminated** |
| Alert Fatigue | Severe | Minimal | Focus on exploitable |
| Mean Time to Patch | Days | Hours | Prioritized queue |

**How it works:**
1. **Baseline scan** (no traffic): 0 active CVEs
2. **Runtime scan** (with traffic): 12 active CVEs
3. **Correlation**: Each CVE mapped to executed code path
4. **EXF scoring**: CVSS × EPSS × KEV × Runtime context

See [benchmark results](docs/EXECUTION_AWARE_PROOF.md) and run `./scripts/demo.sh` to reproduce.

## ⚠️ System Requirements

**MANDATORY** - This project ONLY works on Linux:

- ✅ **Linux kernel 5.8+** (check with `uname -r`)
- ✅ **BTF support enabled** (check with `ls /sys/kernel/btf/`)
- ✅ **Root/sudo access** (required for eBPF)
- ✅ **Kubernetes cluster** (optional, for K8s features)

**NOT SUPPORTED**: Windows, macOS, WSL (Windows Subsystem for Linux)

## 📦 Prerequisites

Before building, install these on Linux:

### System packages

```bash
sudo apt update
sudo apt install -y git curl build-essential clang llvm libelf-dev linux-headers-$(uname -r)
```

### Rust toolchain

```bash
curl -4 https://sh.rustup.rs -sSf | sh
source "$HOME/.cargo/env"
```

### Verify tools

```bash
rustc --version
cargo --version
clang --version
```

### Project requirements

* Linux kernel 5.8+
* BTF support enabled
* Root or sudo access for runtime
* Docker/Kubernetes optional

## 📊 What It Does

Identifies **truly exploitable vulnerabilities** by correlating:

1. **Runtime execution** (eBPF traces syscalls)
2. **SBOM data** (what packages are present)
3. **Threat intelligence** (CISA KEV + EPSS scores)
4. **Risk scoring** (CVSS × EPSS × KEV × Runtime)

**Example Output:**
```
[CRITICAL] CVE-2023-XXXX (Log4j) exploited (EPSS: 0.92, KEV: true)
  Runtime: Reachable via /app/lib/log4j-core-2.14.1.jar
  Auto-remediation: Seccomp profile generated + egress blocked
  Action: Workload quarantined, seccomp applied

[WARNING] CVE-2024-YYYY (OpenSSL) dormant (EPSS: 0.45)
  Runtime: Not loaded in memory
  Action: Scheduled for patching during maintenance
```

## 🚀 Quick Start (Recommended)

### 1. Clone

```bash
git clone https://github.com/Akash-billawa/execution-aware-scanner.git
cd execution-aware-scanner
```

### 2. Install Rust and dependencies

Follow the [prerequisites](#-prerequisites) above.

### 3. Build

```bash
cargo build --release
```

### 4. Run

```bash
sudo ./target/release/scanner-agent
```

### Option 2: Docker (Recommended)

```bash
docker run -d \
  --name scanner \
  --privileged \
  --pid=host \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /proc:/host/proc:ro \
  -v /var/lib/scanner:/var/lib/scanner \
  ghcr.io/akash-billawa/execution-aware-scanner:latest
```

## 📋 Step-by-Step Guide

### 1. Verify Your System

```bash
# Check kernel version (must be 5.8+)
uname -r

# Verify BTF support
ls /sys/kernel/btf/vmlinux

# Check eBPF is enabled
cat /proc/sys/kernel/bpf_stats_enabled
```

**If any check fails**: Upgrade kernel or use different machine

### 2. Install Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y llvm clang libelf-dev linux-headers-$(uname -r)
```

**RHEL/CentOS/Rocky:**
```bash
sudo yum install -y llvm clang elfutils-libelf-devel kernel-headers
```

### 3. Build

```bash
# Clone
git clone https://github.com/Akash-billawa/execution-aware-scanner.git
cd execution-aware-scanner

# Build (takes ~5 minutes on first run)
cargo build --release

# Output binaries:
# - target/release/scanner-agent (main daemon)
# - target/bpfel-unknown-none/release/scanner-ebpf (eBPF program)
```

### 4. Configure

```bash
# Create directories
sudo mkdir -p /var/lib/scanner/sboms
sudo mkdir -p /var/lib/scanner/seccomp
sudo mkdir -p /opt/scanner

# Copy eBPF object
sudo cp target/bpfel-unknown-none/release/scanner-ebpf /opt/scanner/scanner-ebpf.o
```

### 5. Generate SBOMs

```bash
# Install Syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b /usr/local/bin

# Generate SBOM for your container images
sudo syft your-app:latest -o spdx-json=/var/lib/scanner/sboms/your-app.json
```

### 6. Run

```bash
# Run directly
sudo ./target/release/scanner-agent

# Or with config
sudo ./target/release/scanner-agent --config scanner.yaml

# Or with systemd (see docs)
sudo systemctl start execution-aware-scanner
```

## 📊 Example Output

### Normal Operation

```
[INFO] Scanner started on node: worker-1
[INFO] Loaded eBPF programs: tracepoints, kprobes, XDP
[INFO] Connected to Kubernetes API
[INFO] Loaded 1,247 CVEs from CISA KEV
[INFO] Loaded EPSS scores for 215,892 CVEs

[WARN] [CVE-2024-1234] openssl 3.0.0 - HIGH
  CVSS: 7.5 | EPSS: 0.72 | KEV: false
  Runtime: REACHABLE via /usr/lib/libssl.so
  Action: Generating seccomp profile
  
[CRITICAL] [CVE-2023-44228] log4j 2.14.1 - CRITICAL
  CVSS: 10.0 | EPSS: 0.98 | KEV: true
  Runtime: REACHABLE via /app/lib/log4j-core.jar
  Action: Auto-remediation triggered
    - Seccomp profile applied
    - Egress traffic blocked
    - Admin notified
```

### Metrics

```bash
# View metrics
curl http://localhost:9898/metrics

# Prometheus format output:
# scanner_events_total{type="exec"} 15247
# scanner_findings_total{priority="Critical"} 3
# scanner_findings_total{priority="High"} 12
# scanner_seccomp_profiles_generated 8
```

## 🔧 Configuration

### Environment Variables

```bash
export RUST_LOG=info                    # Log level: error, warn, info, debug, trace
export SCANNER__RISK__MINIMUM_CVSS=4.0  # Minimum CVSS to report
export SCANNER__RISK__MINIMUM_EPSS=0.1   # Minimum EPSS to report
export SCANNER__METRICS__BIND_ADDR=0.0.0.0:9898
export SCANNER__REMEDIATOR__AUTO_SECCOMP=true
```

### Config File (scanner.yaml)

```yaml
scanner:
  sbom_dir: "/var/lib/scanner/sboms"
  seccomp_output_dir: "/var/lib/scanner/seccomp"
  bpf_object_path: "/opt/scanner/scanner-ebpf.o"

risk:
  min_cvss: 4.0
  min_epss: 0.1
  weights:
    cvss: 0.45   # Base severity
    epss: 0.25   # Exploit probability
    kev: 0.15    # Known exploited
    runtime: 0.15 # Actually reachable

intel:
  kev_url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
  epss_url: "https://api.first.org/data/v1/epss"
  refresh_interval_secs: 21600  # 6 hours

webhook:
  enabled: true
  endpoints:
    - name: slack
      url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
      min_priority: High
```

## 🏗️ Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                      User Space                               │
│  ┌──────────────┐    ┌─────────────┐    ┌──────────────┐   │
│  │ Event Consumer│───▶│ EXF Risk    │───▶│ Enforcement │   │
│  │ (Tokio async)│    │ Engine      │    │ Controller   │   │
│  └──────────────┘    └─────────────┘    └──────────────┘   │
│         ▲                    ▲                   ▲           │
│         │                    │                   │           │
│  ┌──────┴──────┐    ┌────────┴────────┐   ┌────┴──────┐   │
│  │ K8s Cache   │    │ Threat Intel    │   │ Seccomp   │   │
│  │ (Pod/Node)  │    │ (KEV + EPSS)    │   │ Generator │   │
│  └─────────────┘    └─────────────────┘   └─────────────┘   │
└───────────────────────────────────────────────────────────────┘
                            │
                    ┌───────┴───────┐
                    │  eBPF Programs  │
                    │  (Kernel Space) │
                    │  - tracepoints  │
                    │  - kprobes      │
                    │  - XDP/TC       │
                    └───────────────┘
```

## 📚 Documentation

- **[DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md)** - Complete production deployment
- **[PRODUCTION.md](docs/PRODUCTION.md)** - Day-to-day operations
- **[GITHUB_SETUP.md](GITHUB_SETUP.md)** - Push to your own GitHub repo

## 🐛 Troubleshooting

### "Failed to load eBPF object"

**Cause**: Kernel doesn't support BTF

**Fix**:
```bash
# Check BTF
ls /sys/kernel/btf/vmlinux

# If missing, upgrade kernel to 5.8+ or enable CONFIG_DEBUG_INFO_BTF
```

### "Permission denied"

**Cause**: Not running as root

**Fix**:
```bash
# Must use sudo
sudo ./scanner-agent
```

### "No findings detected"

**Cause**: Missing SBOMs

**Fix**:
```bash
# Check SBOMs exist
ls /var/lib/scanner/sboms/

# Generate with Syft
syft your-image:latest -o spdx-json=/var/lib/scanner/sboms/your-image.json
```

### Windows/macOS Build Fails

**Expected**! This is **Linux-only**. Build will fail with:
```
error: eBPF requires Linux kernel features
```

**Solution**: Use Linux VM or WSL2 with kernel 5.8+

## 🔒 Security

- **Privileged Access**: Required for eBPF (by design)
- **Seccomp Review**: Auto-generated profiles should be reviewed
- **Network Policies**: Included in Helm chart
- **Secrets**: Store webhook tokens in K8s secrets

## 📦 Project Structure

```
execution-aware-scanner/
├── scanner-ebpf/         # Kernel eBPF programs (Linux only!)
├── scanner-common/       # Shared types (cross-platform)
├── scanner-agent/        # User-space daemon
├── deploy/               # Kubernetes manifests
├── helm/                 # Production Helm charts
├── docs/                 # Documentation
└── .github/workflows/    # CI/CD (builds on Linux + Windows/Mac without eBPF)
```

## 🤝 Contributing

This is an open project. Contributions welcome!

1. Fork the repo
2. Create branch: `git checkout -b feature/my-feature`
3. Commit: `git commit -am 'Add feature'`
4. Push: `git push origin feature/my-feature`
5. Open Pull Request

**Note**: CI runs on Linux, Windows, and macOS. Windows/Mac builds skip eBPF.

## 🛠️ Build Notes

- The root `Cargo.toml` is a workspace manifest.
- Linux-only eBPF dependencies belong in the crate manifests, not the workspace manifest.
- If you build on Windows or macOS, eBPF parts are skipped or unsupported.

## 📄 License

Apache License 2.0 - See [LICENSE](LICENSE)

## 💬 Support

- GitHub Issues: https://github.com/Akash-billawa/execution-aware-scanner/issues
- **Important**: Only works on Linux 5.8+ with BTF

---

**Status**: Production Ready | **Platform**: Linux Only | **Kernel**: 5.8+ Required
