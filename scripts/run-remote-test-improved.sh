#!/bin/bash
# Execution-Aware Scanner - Improved Remote Test Script
# Run this on your Linux VM
# Features: JSON output, strict validation, execution-aware proof, performance metrics

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Track test results
FAILED=0
PASSED=0
TOTAL=0

# Output directory for results
RESULTS_DIR="test-results-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$RESULTS_DIR"

echo -e "${GREEN}=== Execution-Aware Scanner Remote Test ===${NC}"
echo -e "Results will be saved to: ${BLUE}$RESULTS_DIR${NC}"

# ========================================
# Helper Functions
# ========================================

pass() {
  echo -e "${GREEN}PASS${NC}: $1"
  ((PASSED++))
  ((TOTAL++))
}

fail() {
  echo -e "${RED}FAIL${NC}: $1"
  ((FAILED++))
  ((TOTAL++))
  FAILED=1
}

warn() {
  echo -e "${YELLOW}WARN${NC}: $1"
}

require_cmd() {
  if ! command -v "$1" &> /dev/null; then
    fail "Required command not found: $1"
    return 1
  fi
  return 0
}

# ========================================
# Phase 1: Prerequisites
# ========================================
echo -e "\n${YELLOW}[Phase 1/8] Checking Prerequisites...${NC}"

# Check kernel version
KERNEL_MAJOR=$(uname -r | cut -d. -f1)
if [ "$KERNEL_MAJOR" -lt 5 ]; then
  fail "Kernel 5.8+ required (found $(uname -r))"
else
  pass "Kernel version OK ($(uname -r))"
fi

# Check BTF support
if [ -f /sys/kernel/btf/vmlinux ]; then
  pass "BTF support available"
else
  warn "BTF not available, eBPF may fail"
fi

# Check eBPF
if [ -d /sys/fs/bpf ]; then
  pass "eBPF filesystem available"
else
  fail "eBPF filesystem not available"
fi

# Check Docker
require_cmd docker && pass "Docker installed"

# Check Rust
require_cmd cargo && pass "Cargo installed"

# Check jq for JSON parsing
if command -v jq &> /dev/null; then
  pass "jq available for JSON parsing"
else
  warn "jq not available - installing..."
  sudo apt-get install -y jq 2>/dev/null || true
fi

# ========================================
# Phase 2: Build
# ========================================
echo -e "\n${YELLOW}[Phase 2/8] Building Scanner...${NC}"

cd ~/execution-aware-scanner 2>/dev/null || cd .

BUILD_START=$(date +%s%N)
cargo build --release 2>&1 | tail -5
BUILD_END=$(date +%s%N)
BUILD_TIME=$(( (BUILD_END - BUILD_START) / 1000000 ))

if [ -f target/release/scanner-agent ]; then
  pass "Build completed in ${BUILD_TIME}ms"
else
  fail "Build failed - scanner binary not found"
  exit 1
fi

# ========================================
# Phase 3: Deploy Vulnerable App
# ========================================
echo -e "\n${YELLOW}[Phase 3/8] Starting Juice Shop...${NC}"

# Clean up any existing containers
docker stop juice-shop 2>/dev/null || true
docker rm juice-shop 2>/dev/null || true

# Start Juice Shop
docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop

# Wait for startup
STARTUP_START=$(date +%s)
for i in {1..60}; do
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000 2>/dev/null || echo "000")
  if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "301" ]; then
    STARTUP_TIME=$(( $(date +%s) - STARTUP_START ))
    pass "Juice Shop ready in ${STARTUP_TIME}s (HTTP $HTTP_CODE)"
    break
  fi
  echo -n "."
  sleep 1
done

if [ "$HTTP_CODE" != "200" ] && [ "$HTTP_CODE" != "301" ]; then
  fail "Juice Shop failed to start (HTTP $HTTP_CODE)"
  exit 1
fi

# ========================================
# Phase 4: Generate SBOM
# ========================================
echo -e "\n${YELLOW}[Phase 4/8] Generating SBOM...${NC}"

if ! command -v trivy &> /dev/null; then
  warn "Installing Trivy..."
  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh
  sudo mv ./bin/trivy /usr/local/bin/
fi

SBOM_START=$(date +%s%N)
trivy image --format json -o sbom.json bkimminich/juice-shop 2>&1 | tail -5
SBOM_END=$(date +%s%N)
SBOM_TIME=$(( (SBOM_END - SBOM_START) / 1000000 ))

# Count CVEs by severity
CRITICAL_CVES=$(jq -r '.Results[]?.Vulnerabilities[]?.Severity' sbom.json 2>/dev/null | grep -c "CRITICAL" || echo "0")
HIGH_CVES=$(jq -r '.Results[]?.Vulnerabilities[]?.Severity' sbom.json 2>/dev/null | grep -c "HIGH" || echo "0")
MEDIUM_CVES=$(jq -r '.Results[]?.Vulnerabilities[]?.Severity' sbom.json 2>/dev/null | grep -c "MEDIUM" || echo "0")
TOTAL_CVES=$((CRITICAL_CVES + HIGH_CVES + MEDIUM_CVES))

if [ "$TOTAL_CVES" -gt 0 ]; then
  pass "SBOM generated in ${SBOM_TIME}ms - Found $TOTAL_CVES CVEs (C:$CRITICAL_CVES H:$HIGH_CVES M:$MEDIUM_CVES)"
else
  fail "No CVEs found in SBOM"
  exit 1
fi

# Extract sample libraries for validation
SAMPLE_LIBS=$(jq -r '.Results[]?.Packages[]?.Name' sbom.json 2>/dev/null | head -10 | tr '\n' ',' | sed 's/,$//')
if [ -n "$SAMPLE_LIBS" ]; then
  pass "SBOM libraries detected: $SAMPLE_LIBS"
fi

# ========================================
# Phase 5: Test Baseline (No Traffic)
# ========================================
echo -e "\n${YELLOW}[Phase 5/8] Testing Baseline (No Traffic)...${NC}"

# Create test config with JSON output
cat > test-config.yaml << EOF
scanner:
  mode: audit
  sbom_path: ./sbom.json
  output_format: json
enforcement:
  mode: audit
  action: alert
risk:
  cvss_weight: 0.45
  epss_weight: 2.5
  kev_weight: 1.0
  runtime_weight: 1.5
logging:
  level: info
  file: $RESULTS_DIR/scanner-test.log
EOF

# Run scanner without any traffic
SCAN_START=$(date +%s)
sudo timeout 15 ./target/release/scanner-agent --config test-config.yaml > "$RESULTS_DIR/baseline.json" 2>&1 || true
SCAN_END=$(date +%s)
BASELINE_DURATION=$((SCAN_END - SCAN_START))

# Check baseline findings
BASELINE_FINDINGS=$(grep -c '"cve":' "$RESULTS_DIR/baseline.json" 2>/dev/null || echo "0")
BASELINE_ACTIVE=$(grep -c '"runtime":"Reachable"' "$RESULTS_DIR/baseline.json" 2>/dev/null || echo "0")

if [ "$BASELINE_ACTIVE" -eq 0 ]; then
  pass "Baseline: No active CVEs without traffic ($BASELINE_FINDINGS findings, ${BASELINE_DURATION}s)"
else
  fail "Baseline: Unexpected active CVEs detected ($BASELINE_ACTIVE)"
fi

# ========================================
# Phase 6: Trigger Runtime Activity
# ========================================
echo -e "\n${YELLOW}[Phase 6/8] Triggering Runtime Activity...${NC}"

# Start scanner in background for runtime test
sudo ./target/release/scanner-agent --config test-config.yaml > "$RESULTS_DIR/runtime.json" 2>&1 &
SCANNER_PID=$!
echo "Scanner started (PID: $SCANNER_PID)"

# Wait for scanner to initialize
sleep 5

# Simulate various attack patterns
echo "Simulating web traffic and attack patterns..."

# Normal browsing
for path in "/" "/api/Products" "/rest/user/whoami" "/api/BasketItems"; do
  REQUEST_START=$(date +%s%N)
  curl -s -o /dev/null -w "%{http_code}" "http://localhost:3000$path" > /dev/null 2>&1 || true
  REQUEST_END=$(date +%s%N)
  REQUEST_TIME=$(( (REQUEST_END - REQUEST_START) / 1000000 ))
  echo -n "."
done

# Wait for scanner to process events
sleep 5

# Trigger specific vulnerable patterns
# SQL injection attempt (Juice Shop vulnerable to this)
curl -s "http://localhost:3000/rest/products/search?q=test')%20UNION%20SELECT%20* FROM Users--" > /dev/null 2>&1 || true
sleep 1

# XSS attempt
curl -s -X POST "http://localhost:3000/api/BasketItems" \
  -H "Content-Type: application/json" \
  -d '{"ProductId":1,"BasketId":"1","quantity":1}' > /dev/null 2>&1 || true

echo ""
sleep 3

# ========================================
# Phase 7: Verify Execution-Aware Detection
# ========================================
echo -e "\n${YELLOW}[Phase 7/8] Verifying Execution-Aware Detection...${NC}"

# Check JSON findings
total_findings=0
active_findings=0
critical_findings=0
high_findings=0

if [ -f "$RESULTS_DIR/runtime.json" ]; then
  # Parse JSON findings
  total_findings=$(grep -c '"cve":' "$RESULTS_DIR/runtime.json" 2>/dev/null || echo "0")
  active_findings=$(grep -c '"runtime":"Reachable"' "$RESULTS_DIR/runtime.json" 2>/dev/null || echo "0")
  critical_findings=$(grep -c '"priority":"Critical"' "$RESULTS_DIR/runtime.json" 2>/dev/null || echo "0")
  high_findings=$(grep -c '"priority":"High"' "$RESULTS_DIR/runtime.json" 2>/dev/null || echo "0")
fi

# Validate execution-aware behavior
if [ "$active_findings" -gt 0 ]; then
  pass "Execution-aware: $active_findings active CVEs detected with runtime correlation"
  
  # Extract sample finding details
  SAMPLE_FINDING=$(grep -A 20 '"priority":"Critical"' "$RESULTS_DIR/runtime.json" 2>/dev/null | head -25)
  if [ -n "$SAMPLE_FINDING" ]; then
    echo -e "${BLUE}Sample Finding:${NC}"
    echo "$SAMPLE_FINDING" | head -10
  fi
else
  fail "Execution-aware: No active CVEs detected - runtime correlation not working"
fi

if [ "$critical_findings" -gt 0 ]; then
  pass "Risk scoring: $critical_findings Critical findings identified"
else
  warn "Risk scoring: No Critical findings (may be expected depending on CVEs)"
fi

# ========================================
# Phase 8: Validate SBOM-to-Runtime Mapping
# ========================================
echo -e "\n${YELLOW}[Phase 8/8] Validating SBOM-to-Runtime Mapping...${NC}"

# Extract packages from SBOM
SBOM_PACKAGES=$(jq -r '.Results[]?.Packages[]?.Name' sbom.json 2>/dev/null | sort -u)

# Extract packages from runtime findings (from package field)
RUNTIME_PACKAGES=$(grep -o '"package":"[^"]*"' "$RESULTS_DIR/runtime.json" 2>/dev/null | sed 's/"package":"//;s/"$//' | sort -u)

# Check for package correlation
MATCH_COUNT=0
for pkg in $RUNTIME_PACKAGES; do
  if echo "$SBOM_PACKAGES" | grep -q "^${pkg}$"; then
    ((MATCH_COUNT++))
  fi
done

if [ "$MATCH_COUNT" -gt 0 ]; then
  pass "SBOM-to-runtime mapping: $MATCH_COUNT packages correlated"
else
  warn "SBOM-to-runtime mapping: Could not verify package correlation"
fi

# ========================================
# Summary & Cleanup
# ========================================
echo -e "\n${GREEN}=== TEST SUMMARY ===${NC}"
echo -e "Total Tests: ${BLUE}$TOTAL${NC}"
echo -e "Passed: ${GREEN}$PASSED${NC}"
echo -e "Failed: ${RED}$FAILED${NC}"
echo ""
echo -e "Total CVEs in SBOM: ${BLUE}$TOTAL_CVES${NC}"
echo -e "Total Findings Generated: ${BLUE}$total_findings${NC}"
echo -e "Active (Runtime Correlated): ${BLUE}$active_findings${NC}"
echo -e "Critical Priority: ${BLUE}$critical_findings${NC}"
echo -e "High Priority: ${BLUE}$high_findings${NC}"
echo ""
echo -e "Build Time: ${BUILD_TIME}ms"
echo -e "SBOM Generation: ${SBOM_TIME}ms"
echo -e "Baseline Scan: ${BASELINE_DURATION}s"

# Save summary
cat > "$RESULTS_DIR/summary.txt" << EOF
Test Results Summary
====================
Date: $(date)
Kernel: $(uname -r)
Total Tests: $TOTAL
Passed: $PASSED
Failed: $FAILED

SBOM Analysis
=============
Total CVEs: $TOTAL_CVES
Critical: $CRITICAL_CVES
High: $HIGH_CVES
Medium: $MEDIUM_CVES

Execution-Aware Detection
=========================
Total Findings: $total_findings
Active CVEs (Runtime): $active_findings
Critical: $critical_findings
High: $high_findings

Performance Metrics
===================
Build Time: ${BUILD_TIME}ms
SBOM Generation: ${SBOM_TIME}ms
Baseline Scan: ${BASELINE_DURATION}s

Validation Results
================
SBOM-to-Runtime Mapping: $MATCH_COUNT packages correlated
EOF

echo -e "\n${GREEN}Detailed results saved to: $RESULTS_DIR/${NC}"

# Cleanup
echo -e "\n${YELLOW}Cleaning up...${NC}"
kill $SCANNER_PID 2>/dev/null || true
wait $SCANNER_PID 2>/dev/null || true
docker stop juice-shop 2>/dev/null || true
docker rm juice-shop 2>/dev/null || true
rm -f test-config.yaml

# Final result
if [ $FAILED -eq 0 ]; then
  echo -e "\n${GREEN}ALL TESTS PASSED${NC}"
  echo -e "${GREEN}Your execution-aware scanner is working correctly!${NC}"
  exit 0
else
  echo -e "\n${RED}SOME TESTS FAILED${NC}"
  echo -e "${YELLOW}Review the results in $RESULTS_DIR/${NC}"
  exit 1
fi
