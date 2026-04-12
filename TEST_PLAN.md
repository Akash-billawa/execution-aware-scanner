# Execution-Aware eBPF Scanner - Remote Test Plan

## Overview
Test the production scanner on a Linux VM to validate end-to-end functionality.

---

## Environment Requirements

### VM Specifications
- **OS**: Ubuntu 22.04 LTS (or any Linux 5.8+)
- **Kernel**: `uname -r` must show 5.8 or higher
- **BTF**: Check with `ls /sys/kernel/btf/vmlinux`
- **Resources**: 2 CPU, 4GB RAM, 20GB disk
- **Privileges**: Root/sudo access required
- **Network**: Internet access for Docker images

### Cloud Options
1. **AWS EC2**: t3.medium with Ubuntu 22.04 AMI
2. **GCP**: e2-medium with Ubuntu 22.04
3. **Azure**: B2s with Ubuntu 22.04
4. **Local**: VirtualBox/VMware with Ubuntu ISO

---

## Pre-Flight Checks

```bash
# SSH into your VM
ssh user@your-vm-ip

# Verify kernel version
uname -r
# Expected: 5.8.0 or higher

# Check BTF support
ls /sys/kernel/btf/vmlinux
# Expected: File exists

# Check eBPF support
ls /sys/fs/bpf/
# Expected: Directory exists

# Install dependencies
sudo apt update && sudo apt install -y \
  docker.io \
  cargo \
  rustc \
  llvm \
  clang \
  libelf-dev \
  linux-headers-$(uname -r)
```

---

## Test Execution

### Phase 1: Build Scanner
```bash
# Clone repository
git clone https://github.com/akash-billawa/execution-aware-scanner.git
cd execution-aware-scanner

# Build with eBPF support
cargo build --release

# Verify binary
ls -la target/release/scanner-agent
# Expected: Binary exists (~10-20MB)
```

### Phase 2: Deploy Vulnerable App
```bash
# Start Juice Shop
docker run -d -p 3000:3000 --name juice-shop \
  bkimminich/juice-shop

# Verify it's running
curl http://localhost:3000
# Expected: HTML response with "OWASP Juice Shop"
```

### Phase 3: Generate SBOM
```bash
# Install Trivy if not present
sudo apt install -y trivy || \
  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

# Generate SBOM for Juice Shop
trivy image --format json -o sbom.json bkimminich/juice-shop

# Verify SBOM created
ls -la sbom.json
# Expected: File exists, ~50KB+
```

### Phase 4: Run Scanner (Baseline - No Traffic)
```bash
# Run scanner in background
sudo ./target/release/scanner-agent --config config.yaml &
SCANNER_PID=$!

# Wait 30 seconds for initialization
sleep 30

# Check initial output
journalctl -u scanner-agent -n 50
# Expected: No "ACTIVE" vulnerabilities (no traffic yet)
```

### Phase 5: Trigger Runtime Activity
```bash
# Open Juice Shop in browser (from local machine)
# http://your-vm-ip:3000

# Or use curl to simulate traffic
curl http://localhost:3000
curl http://localhost:3000/api/Products
curl http://localhost:3000/rest/user/whoami

# Wait 10 seconds for scanner to process
sleep 10
```

### Phase 6: Verify Detection
```bash
# Check scanner logs
tail -100 /var/log/scanner-agent.log

# Expected output patterns:
# [INFO] Process: node
# [INFO] Loaded: libssl.so, libc.so
# [WARN] CVE-2023-XXXX detected
# [INFO] EPSS: 0.72
# [INFO] Runtime: ACTIVE
# [WARN] Risk: HIGH
# [ALERT] Action: ALERT
```

---

## Test Cases

### Test Case 1: Baseline (No Traffic)
**Setup**: Scanner running, Juice Shop running, NO browser interaction
**Expected**: No active CVEs, "Runtime: INACTIVE" or no detection
**Pass Criteria**: No HIGH/CRITICAL alerts triggered

### Test Case 2: Active Exploitation
**Setup**: Scanner running, interact with Juice Shop
**Actions**: 
- Browse product catalog
- Attempt login
- Access search functionality
**Expected**: Active CVEs detected with "Runtime: ACTIVE"
**Pass Criteria**: Risk scores calculated, alerts triggered

### Test Case 3: Risk Scoring Accuracy
**Setup**: Multiple CVEs in SBOM
**Expected**: 
- CVSS-based initial scoring
- EPSS adjustment
- Runtime multiplier applied
**Pass Criteria**: Score increases when code executes

### Test Case 4: Enforcement Modes
**Setup**: Configure enforcement: mode: enforce
**Expected**: Blocking actions on high-risk processes
**Pass Criteria**: Process restricted without system crash

---

## Success Criteria

| Criteria | Target | Measurement |
|----------|--------|-------------|
| CVE Detection | 100% | All SBOM CVEs detected |
| Runtime Correlation | 90%+ | Correct process/CVE mapping |
| Alert Reduction | 80%+ | Fewer alerts vs static scanning |
| False Positive Rate | <10% | Validation accuracy |
| Latency | <100ms | Event processing time |

---

## Troubleshooting

### Issue: "BTF not found"
**Solution**: Use newer kernel or disable BTF in eBPF
```bash
# Check kernel
uname -r  # Must be 5.8+

# Alternative: Use CO-RE (Compile Once, Run Everywhere)
```

### Issue: "Permission denied" loading eBPF
**Solution**: Run as root with required capabilities
```bash
sudo ./target/release/scanner-agent
# OR
docker run --privileged ...
```

### Issue: "No events detected"
**Solution**: Check eBPF probes are attached
```bash
sudo bpftool prog list
# Should show scanner-ebpf programs
```

---

## Cleanup

```bash
# Stop scanner
kill $SCANNER_PID

# Stop Juice Shop
docker stop juice-shop && docker rm juice-shop

# Remove logs
sudo rm -rf /var/log/scanner-agent.log

# Optional: Destroy VM if cloud-based
```

---

## Results Template

Copy this template to record your test:

```markdown
## Test Results - YYYY-MM-DD

### Environment
- VM: [AWS/GCP/Azure/Local]
- Kernel: [uname -r output]
- Docker: [docker --version]

### Phase 1: Build
- Status: [PASS/FAIL]
- Notes: [Any issues]

### Phase 2: Vulnerable App
- Status: [PASS/FAIL]
- App: Juice Shop v[X.X.X]

### Phase 3: SBOM Generation
- CVEs Found: [Number]
- Critical: [Number]
- High: [Number]

### Phase 4: Baseline Scan
- Active CVEs: [Number]
- Expected: 0
- Status: [PASS/FAIL]

### Phase 5: Runtime Detection
- Active CVEs: [Number]
- Risk Scores: [Sample outputs]
- Alerts Triggered: [Number]

### Phase 6: Risk Accuracy
- EPSS Integration: [Working/Not Working]
- Runtime Multiplier: [Applied/Not Applied]
- False Positives: [Number]

### Overall Result: [PASS/FAIL]
```

---

## Quick Start Script

Save as `run-test.sh` on your VM:

```bash
#!/bin/bash
set -e

echo "=== Execution-Aware Scanner Test ==="

# Check prerequisites
echo "[1/6] Checking prerequisites..."
[ $(uname -r | cut -d. -f1) -ge 5 ] || { echo "Kernel 5.8+ required"; exit 1; }
[ -f /sys/kernel/btf/vmlinux ] || { echo "BTF not available"; exit 1; }

# Build
echo "[2/6] Building scanner..."
cargo build --release 2>&1 | tail -5

# Start Juice Shop
echo "[3/6] Starting Juice Shop..."
docker run -d -p 3000:3000 --name juice-shop \
  bkimminich/juice-shop 2>/dev/null || docker start juice-shop

# Generate SBOM
echo "[4/6] Generating SBOM..."
trivy image --format json -o sbom.json bkimminich/juice-shop 2>&1 | tail -3
CVE_COUNT=$(cat sbom.json | grep -o '"VulnerabilityID"' | wc -l)
echo "Found $CVE_COUNT CVEs"

# Run scanner
echo "[5/6] Running scanner (60 seconds)..."
timeout 60 sudo ./target/release/scanner-agent || true

# Cleanup
echo "[6/6] Cleanup..."
docker stop juice-shop 2>/dev/null || true
docker rm juice-shop 2>/dev/null || true

echo "=== Test Complete ==="
```

---

## Next Steps After Success

1. **Record Demo**: Capture terminal output for GitHub
2. **Performance Benchmark**: Test with large SBOMs
3. **K8s Deployment**: Deploy to real cluster
4. **Optional Features**: Add ML detection (Phase 8)

---

*Test Plan Version: 1.0*
*Last Updated: 2024*
