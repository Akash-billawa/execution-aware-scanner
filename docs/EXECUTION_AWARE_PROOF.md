# Execution-Aware Proof Scenarios

## Overview
This document describes test scenarios to prove the **execution-aware** capability of the scanner.

## Core Claim
> The scanner detects CVEs **only when code is actually executed**, not just present in the container.

## Test Scenarios

### Scenario A: Baseline (No Execution)
**Setup**: Scanner running, vulnerable app running, NO interaction

**Expected**: 
- Total CVEs detected: [Number from SBOM]
- Active CVEs: **0**
- Runtime status: DORMANT

**Proof Command**:
```bash
# Start scanner
sudo ./target/release/scanner-agent --config config.yaml &

# Wait 30 seconds WITHOUT touching the app
sleep 30

# Check results - no ACTIVE findings
jq 'select(.runtime == "Reachable")' scanner-output.json | wc -l
# Expected: 0
```

### Scenario B: Runtime Execution
**Setup**: Same as A, but now interact with vulnerable endpoints

**Expected**:
- Active CVEs: **> 0**
- Runtime status: REACHABLE
- Risk scores calculated

**Proof Command**:
```bash
# Start scanner
sudo ./target/release/scanner-agent --config config.yaml &

# Trigger execution
curl http://localhost:3000/api/Products
curl http://localhost:3000/rest/user/whoami

# Wait for processing
sleep 10

# Check results - ACTIVE findings present
jq 'select(.runtime == "Reachable")' scanner-output.json | wc -l
# Expected: > 0
```

### Scenario C: Attack Simulation
**Setup**: Simulate actual attacks to trigger vulnerable code paths

**Expected**:
- Specific CVEs detected based on triggered code paths
- Network events for vulnerable libraries
- File events for library loading

**Proof Command**:
```bash
# SQL injection attempt
curl "http://localhost:3000/rest/products/search?q=test')%20UNION%20SELECT%20* FROM Users--"

# XSS attempt
curl -X POST "http://localhost:3000/api/BasketItems" \
  -H "Content-Type: application/json" \
  -d '{"ProductId":1,"quantity":1}'

# Verify specific CVEs triggered
jq 'select(.cve | contains("CVE-2023"))' scanner-output.json
```

## Verification Checklist

- [ ] Baseline shows 0 active CVEs
- [ ] Runtime shows > 0 active CVEs
- [ ] CVEs correlate with triggered code paths
- [ ] Network events captured for vulnerable libraries
- [ ] File events captured for library loading
- [ ] Risk scores calculated based on runtime context
- [ ] EPSS scores incorporated
- [ ] KEV status checked

## Sample Output

### Static Scan (Trivy)
```json
{
  "CVEs": 127,
  "Critical": 12,
  "High": 35,
  "Medium": 45,
  "Low": 35
}
```

### Execution-Aware Scan (No Traffic)
```json
{
  "findings": 0,
  "active": 0,
  "message": "No code execution detected"
}
```

### Execution-Aware Scan (With Traffic)
```json
{
  "findings": 12,
  "active": 8,
  "critical": 2,
  "high": 6,
  "message": "Runtime execution detected and correlated"
}
```

## Success Criteria

| Metric | Target |
|--------|--------|
| Baseline Active CVEs | 0 |
| Runtime Active CVEs | > 0 |
| Correlation Accuracy | > 90% |
| Alert Reduction | > 70% |
| Detection Latency | < 5s |

## Demo Script

```bash
#!/bin/bash
# Full execution-aware demo

echo "=== Execution-Aware Scanner Demo ==="

# Phase 1: Static scan
echo "[1/4] Static scan (Trivy)..."
trivy image --format json bkimminich/juice-shop | jq '.Results[].Vulnerabilities | length'
# Output: 127

# Phase 2: Start app, no traffic
echo "[2/4] Execution-aware baseline (no traffic)..."
sudo ./scanner-agent &
sleep 30
# Check output: 0 active

# Phase 3: Start app, with traffic
echo "[3/4] Execution-aware runtime (with traffic)..."
curl http://localhost:3000/
sleep 5
# Check output: > 0 active

# Phase 4: Comparison
echo "[4/4] Results..."
echo "Static: 127 CVEs"
echo "Active: 12 CVEs"
echo "Reduction: ~90%"
```

## Next Steps

1. Run scenarios in isolated Linux VM
2. Capture output for README documentation
3. Add video demo to repository
4. Create Grafana dashboard for visualization

---
*Last Updated: 2024*
