# Execution-Aware Scanner - Complete Deployment Guide

## Overview

This guide provides step-by-step instructions for deploying the Execution-Aware eBPF Scanner on Linux Kubernetes clusters.

## Prerequisites

### System Requirements

- **Operating System**: Linux (Ubuntu 20.04+, RHEL 8+, Debian 11+, CentOS 8+)
- **Kernel**: Linux 5.8+ with BTF (BPF Type Format) support
- **Kubernetes**: 1.25+ cluster
- **Architecture**: x86_64 or ARM64
- **Memory**: 2GB+ RAM per node
- **Storage**: 10GB+ available space

### Kernel Verification

Run these commands on your Linux nodes to verify compatibility:

```bash
# Check kernel version
uname -r
# Output should be 5.8.0 or higher

# Verify BTF support
ls /sys/kernel/btf/
# Should show: vmlinux

# Check eBPF support
cat /proc/sys/kernel/bpf_stats_enabled
# Should return: 1

# Verify BPF filesystem is mounted
mount | grep bpf
# Should show: /sys/fs/bpf type bpf
```

### Required Kernel Config

Verify these kernel options are enabled:

```bash
# Check kernel config
cat /boot/config-$(uname -r) | grep -E "CONFIG_BPF|CONFIG_DEBUG_INFO_BTF"

# Should see:
# CONFIG_BPF=y
# CONFIG_BPF_SYSCALL=y
# CONFIG_DEBUG_INFO_BTF=y
# CONFIG_BPF_EVENTS=y
```

## Installation

### Method 1: Binary Release (Quickest)

#### Step 1: Download Release

```bash
# Download latest release
wget https://github.com/example/execution-aware-scanner/releases/latest/download/scanner-agent-x86_64-unknown-linux-gnu.tar.gz

# Extract
tar -xzf scanner-agent-x86_64-unknown-linux-gnu.tar.gz
cd execution-aware-scanner

# Make executable
chmod +x scanner-agent
```

#### Step 2: Download eBPF Object

```bash
# Download pre-compiled eBPF program
wget https://github.com/example/execution-aware-scanner/releases/latest/download/scanner-ebpf.o

# Place in correct location
sudo mkdir -p /opt/scanner
sudo cp scanner-ebpf.o /opt/scanner/
sudo chmod 644 /opt/scanner/scanner-ebpf.o
```

#### Step 3: Configure

```bash
# Create configuration directory
sudo mkdir -p /etc/scanner

# Create configuration file
sudo tee /etc/scanner/scanner.yaml <<EOF
scanner:
  sbom_dir: "/var/lib/scanner/sboms"
  seccomp_output_dir: "/var/lib/scanner/seccomp"
  bpf_object_path: "/opt/scanner/scanner-ebpf.o"

risk:
  minimum_cvss: 4.0
  minimum_epss: 0.1

intel:
  kev_url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
  epss_url: "https://api.first.org/data/v1/epss"
  refresh_interval_secs: 21600

metrics:
  bind_addr: "0.0.0.0:9898"

enforcement:
  auto:
    seccomp: true
    quarantine: false
    block_egress: true
EOF
```

#### Step 4: Create Directories

```bash
# Create required directories
sudo mkdir -p /var/lib/scanner/sboms
sudo mkdir -p /var/lib/scanner/seccomp
sudo mkdir -p /var/log/scanner

# Set permissions
sudo chmod 755 /var/lib/scanner
sudo chmod 755 /var/lib/scanner/sboms
sudo chmod 755 /var/lib/scanner/seccomp
```

#### Step 5: Run

```bash
# Run directly
sudo ./scanner-agent --config /etc/scanner/scanner.yaml

# Or with systemd (see below)
```

### Method 2: Docker (Recommended)

#### Step 1: Pull Image

```bash
# Pull from GitHub Container Registry
docker pull ghcr.io/example/execution-aware-scanner:latest

# Or specific version
docker pull ghcr.io/example/execution-aware-scanner:v1.0.0
```

#### Step 2: Prepare SBOMs

```bash
# Create SBOM directory
sudo mkdir -p /var/lib/scanner/sboms

# Generate SBOMs for your images (using Syft)
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b /usr/local/bin

# Generate SBOM for an image
sudo syft nginx:latest -o spdx-json=/var/lib/scanner/sboms/nginx_latest.json

# Generate for multiple images
for image in nginx:1.21 redis:6.2 postgres:13; do
    name=$(echo $image | tr '/:' '_')
    sudo syft $image -o spdx-json=/var/lib/scanner/sboms/${name}.json
done
```

#### Step 3: Run Container

```bash
# Run scanner
docker run -d \
  --name execution-aware-scanner \
  --privileged \
  --pid=host \
  --network=host \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /proc:/host/proc:ro \
  -v /var/lib/scanner:/var/lib/scanner \
  -e RUST_LOG=info \
  -e SCANNER__RUNTIME__NODE_NAME=$(hostname) \
  ghcr.io/example/execution-aware-scanner:latest

# Check logs
docker logs -f execution-aware-scanner
```

### Method 3: Build from Source

#### Step 1: Install Rust

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Verify installation
rustc --version
cargo --version
```

#### Step 2: Install Dependencies

```bash
# Install system dependencies (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    llvm \
    clang \
    libelf-dev \
    linux-headers-$(uname -r) \
    linux-tools-$(uname -r) \
    pkg-config

# Install bpf-linker
cargo install bpf-linker

# Add eBPF target
rustup target add bpfel-unknown-none
```

#### Step 3: Clone Repository

```bash
# Clone the repository
git clone https://github.com/example/execution-aware-scanner.git
cd execution-aware-scanner

# Checkout specific version (optional)
git checkout v1.0.0
```

#### Step 4: Build

```bash
# Build eBPF program
export CARGO_TARGET_DIR="$(pwd)/target"
cargo +nightly build --manifest-path scanner-ebpf/Cargo.toml --target bpfel-unknown-none --release -Z build-std=core

# Copy eBPF object
sudo mkdir -p /opt/scanner
sudo cp target/bpfel-unknown-none/release/libscanner_ebpf.so /opt/scanner/scanner-ebpf.o

# Build userspace agent with Linux eBPF support
cargo build --release -p scanner-agent --features ebpf

# Install binary
sudo cp target/release/scanner-agent /usr/local/bin/
sudo chmod +x /usr/local/bin/scanner-agent
```

### Method 4: Kubernetes (Production)

#### Step 1: Add Helm Repository

```bash
# Add Helm repository
helm repo add execution-aware-scanner \
  https://example.github.io/execution-aware-scanner

helm repo update
```

#### Step 2: Create Values File

```bash
# Create custom values
cat > scanner-values.yaml <<EOF
scanner:
  resources:
    requests:
      cpu: 500m
      memory: 512Mi
    limits:
      cpu: 2000m
      memory: 2Gi

risk:
  minCvss: 4.0
  minEpss: 0.1

enforcement:
  auto:
    seccomp: true
    quarantine: false
    blockEgress: true

webhook:
  enabled: true
  endpoints:
    - name: siem
      url: https://siem.yourcompany.com/webhook
      token: "${WEBHOOK_TOKEN}"
      minPriority: High
      batchSize: 50

metrics:
  enabled: true
  prometheusRule:
    enabled: true
EOF
```

#### Step 3: Deploy

```bash
# Create namespace
kubectl create namespace execution-aware-scanner

# Create secret for webhook token (if using)
kubectl create secret generic webhook-token \
  --namespace execution-aware-scanner \
  --from-literal=token="your-webhook-token"

# Install with Helm
helm install execution-aware-scanner \
  execution-aware-scanner/execution-aware-scanner \
  --namespace execution-aware-scanner \
  --values scanner-values.yaml \
  --wait

# Verify deployment
kubectl get pods -n execution-aware-scanner
kubectl logs -n execution-aware-scanner -l app.kubernetes.io/name=execution-aware-scanner
```

#### Step 4: Verify Metrics

```bash
# Port-forward metrics
kubectl port-forward -n execution-aware-scanner \
  svc/execution-aware-scanner-metrics 9898:9898 &

# Check metrics
curl http://localhost:9898/metrics | grep scanner

# Check health
curl http://localhost:9898/health
curl http://localhost:9898/ready
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `RUST_LOG` | Log level | `info` |
| `SCANNER__RUNTIME__NODE_NAME` | Node name | auto-detected |
| `SCANNER__RISK__MINIMUM_CVSS` | Minimum CVSS score | 4.0 |
| `SCANNER__RISK__MINIMUM_EPSS` | Minimum EPSS score | 0.1 |
| `SCANNER__INTEL__REFRESH_INTERVAL_SECS` | Intel refresh interval | 21600 |
| `SCANNER__REMEDIATOR__ENABLED` | Enable remediation | true |
| `SCANNER__REMEDIATOR__AUTO_SECCOMP` | Auto-generate seccomp | true |
| `SCANNER__METRICS__BIND_ADDR` | Metrics bind address | `0.0.0.0:9898` |

### SBOM Configuration

The scanner requires SBOMs to perform vulnerability matching:

```bash
# Generate SBOMs with Syft
syft <image> -o spdx-json=/var/lib/scanner/sboms/<name>.json

# Or with Trivy
trivy image --format spdx-json --output /var/lib/scanner/sboms/<name>.json <image>

# File naming convention
# Replace colons and slashes with underscores
# nginx:1.21.0-alpine -> nginx_1.21.0-alpine.json
```

## Verification

### Check Scanner Status

```bash
# Binary deployment
systemctl status execution-aware-scanner

# Docker
docker ps | grep execution-aware-scanner
docker logs execution-aware-scanner

# Kubernetes
kubectl get pods -n execution-aware-scanner
kubectl logs -n execution-aware-scanner -l app.kubernetes.io/name=execution-aware-scanner
```

### Verify eBPF Programs

```bash
# Check loaded BPF programs
sudo bpftool prog list | grep scanner

# Check BPF maps
sudo bpftool map list | grep scanner

# Check ring buffer usage
sudo bpftool map show name EXEC_EVENTS
```

### Verify Event Flow

```bash
# Port-forward metrics (Kubernetes)
kubectl port-forward -n execution-aware-scanner \
  svc/execution-aware-scanner-metrics 9898:9898 &

# Watch events
curl -s http://localhost:9898/metrics | grep scanner_events_total

# Watch findings
curl -s http://localhost:9898/metrics | grep scanner_findings_total
```

## Monitoring

### Prometheus Metrics

```prometheus
# Event processing rates
rate(scanner_events_total[5m])

# Findings by priority
scanner_findings_total{priority="Critical"}

# Event drop rate
rate(scanner_dropped_events[5m]) / rate(scanner_events_total[5m])

# Intel freshness
(time() - scanner_intel_last_refresh_timestamp) / 3600
```

### Grafana Dashboard

Import the provided dashboard:

```bash
# Port-forward Grafana (if using Helm with Grafana)
kubectl port-forward -n monitoring svc/grafana 3000:3000 &

# Open dashboard
open http://localhost:3000
# Import dashboard ID: execution-aware-scanner
```

## Troubleshooting

### Common Issues

#### Issue: "Failed to load eBPF object"

**Cause**: Kernel doesn't support BTF or eBPF

**Solution**:
```bash
# Verify kernel supports BTF
ls /sys/kernel/btf/vmlinux

# If missing, use CO-RE with vmlinux
# Download vmlinux for your kernel
sudo wget -O /opt/scanner/vmlinux \
  https://github.com/openSUSE/vmlinux-to-elf/raw/master/vmlinux-$(uname -r)

# Or upgrade kernel to 5.8+ with BTF
```

#### Issue: "Permission denied"

**Cause**: Missing capabilities

**Solution**:
```bash
# Run with required capabilities
sudo ./scanner-agent

# Or with Docker --privileged
docker run --privileged ...

# Or Kubernetes with proper capabilities
```

#### Issue: "High event drop rate"

**Cause**: Scanner can't keep up with event volume

**Solution**:
```bash
# Increase CPU/memory limits
# Edit values.yaml:
scanner:
  resources:
    limits:
      cpu: 4000m
      memory: 4Gi

# Or adjust batch size in code
# Rebuild with larger ring buffers
```

#### Issue: "No findings detected"

**Cause**: Missing SBOMs

**Solution**:
```bash
# Check SBOM directory
ls -la /var/lib/scanner/sboms/

# Generate SBOMs
syft <your-image> -o spdx-json=/var/lib/scanner/sboms/<name>.json

# Verify scanner can read them
kubectl exec -n execution-aware-scanner \
  daemonset/execution-aware-scanner -- \
  ls -la /var/lib/scanner/sboms/
```

### Debug Mode

Enable debug logging:

```bash
# Binary
RUST_LOG=debug ./scanner-agent

# Docker
docker run -e RUST_LOG=debug ...

# Kubernetes
kubectl set env -n execution-aware-scanner \
  daemonset/execution-aware-scanner \
  RUST_LOG=debug
```

### Collect Debug Info

```bash
# Kubernetes
kubectl exec -n execution-aware-scanner \
  daemonset/execution-aware-scanner -- \
  sh -c "cat /proc/self/status; ls -la /sys/fs/bpf/; bpftool prog list"

# Save logs
kubectl logs -n execution-aware-scanner \
  daemonset/execution-aware-scanner > scanner.log
```

## Maintenance

### Updating

#### Binary

```bash
# Download new version
wget https://github.com/example/execution-aware-scanner/releases/latest/download/scanner-agent-x86_64-unknown-linux-gnu.tar.gz
tar -xzf scanner-agent-x86_64-unknown-linux-gnu.tar.gz

# Stop current
sudo systemctl stop execution-aware-scanner

# Replace binary
sudo cp scanner-agent /usr/local/bin/

# Start
sudo systemctl start execution-aware-scanner
```

#### Docker

```bash
# Pull new image
docker pull ghcr.io/example/execution-aware-scanner:latest

# Stop and restart
docker stop execution-aware-scanner
docker rm execution-aware-scanner
docker run -d ... (same options as before)
```

#### Kubernetes

```bash
# Update Helm chart
helm repo update
helm upgrade execution-aware-scanner \
  execution-aware-scanner/execution-aware-scanner \
  --namespace execution-aware-scanner

# Verify rollout
kubectl rollout status daemonset/execution-aware-scanner \
  -n execution-aware-scanner
```

### Backup

```bash
# Backup configuration
sudo tar -czf scanner-backup-$(date +%Y%m%d).tar.gz \
  /etc/scanner/ \
  /var/lib/scanner/seccomp/ \
  /var/log/scanner/
```

## Security Considerations

1. **Privileged Access**: The scanner requires privileged access to load eBPF programs
2. **Seccomp Profiles**: Generated profiles should be reviewed before deployment
3. **Network Policies**: Ensure scanner can reach threat intelligence APIs
4. **Secrets**: Store webhook tokens and API keys in Kubernetes secrets

## Support

- GitHub Issues: https://github.com/example/execution-aware-scanner/issues
- Documentation: https://example.github.io/execution-aware-scanner/
- Slack: #execution-aware-scanner
