#!/bin/bash
# Execution-Aware Scanner Remote Test Script
# Run this on your Linux VM

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Execution-Aware Scanner Remote Test ===${NC}"

# === Phase 1: Prerequisites ===
echo -e "\n${YELLOW}[Phase 1/6] Checking Prerequisites...${NC}"

KERNEL_MAJOR=$(uname -r | cut -d. -f1)
if [ "$KERNEL_MAJOR" -lt 5 ]; then
    echo -e "${RED}ERROR: Kernel 5.8+ required (found $(uname -r))${NC}"
    exit 1
fi

if [ ! -f /sys/kernel/btf/vmlinux ]; then
    echo -e "${YELLOW}WARNING: BTF not available, eBPF may fail${NC}"
fi

if ! command -v docker &> /dev/null; then
    echo -e "${RED}ERROR: Docker not installed${NC}"
    exit 1
fi

if ! command -v cargo &> /dev/null; then
    echo -e "${RED}ERROR: Rust/Cargo not installed${NC}"
    exit 1
fi

echo -e "${GREEN}Prerequisites OK${NC}"

# === Phase 2: Build ===
echo -e "\n${YELLOW}[Phase 2/6] Building Scanner...${NC}"

cd ~/execution-aware-scanner 2>/dev/null || cd .

cargo build --release 2>&1 | tail -3

if [ ! -f target/release/scanner-agent ]; then
    echo -e "${RED}ERROR: Build failed - scanner binary not found${NC}"
    exit 1
fi

echo -e "${GREEN}Build OK${NC}"

# === Phase 3: Deploy Vulnerable App ===
echo -e "\n${YELLOW}[Phase 3/6] Starting Juice Shop...${NC}"

# Clean up any existing containers
docker stop juice-shop 2>/dev/null || true
docker rm juice-shop 2>/dev/null || true

# Start Juice Shop
docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop

# Wait for startup
for i in {1..30}; do
    if curl -s http://localhost:3000 > /dev/null 2>&1; then
        echo -e "${GREEN}Juice Shop is ready${NC}"
        break
    fi
    echo -n "."
    sleep 1
done

if ! curl -s http://localhost:3000 > /dev/null 2>&1; then
    echo -e "${RED}ERROR: Juice Shop failed to start${NC}"
    exit 1
fi

# === Phase 4: Generate SBOM ===
echo -e "\n${YELLOW}[Phase 4/6] Generating SBOM...${NC}"

if ! command -v trivy &> /dev/null; then
    echo -e "${YELLOW}Installing Trivy...${NC}"
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh
    sudo mv ./bin/trivy /usr/local/bin/
fi

trivy image --format json -o sbom.json bkimminich/juice-shop 2>&1 | tail -5

CVE_COUNT=$(grep -o '"VulnerabilityID"' sbom.json 2>/dev/null | wc -l)
echo -e "${GREEN}Found $CVE_COUNT CVEs in SBOM${NC}"

if [ "$CVE_COUNT" -eq 0 ]; then
    echo -e "${RED}WARNING: No CVEs found - check SBOM generation${NC}"
fi

# === Phase 5: Run Scanner (Baseline - No Traffic) ===
echo -e "\n${YELLOW}[Phase 5/6] Testing Baseline (No Traffic)...${NC}"

# Create test config
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
  file: /tmp/scanner-test.log
EOF

# Start scanner in background
sudo ./target/release/scanner-agent --config test-config.yaml &
SCANNER_PID=$!

# Wait for initialization
echo "Waiting 10 seconds for scanner to initialize..."
sleep 10

# Check baseline - no active CVEs expected
echo "Baseline check complete"

# === Phase 6: Trigger Runtime Activity ===
echo -e "\n${YELLOW}[Phase 6/6] Triggering Runtime Activity...${NC}"

echo "Simulating web traffic..."
for i in {1..5}; do
    curl -s http://localhost:3000 > /dev/null
    curl -s http://localhost:3000/api/Products > /dev/null
    echo -n "."
    sleep 1
done
echo ""

# Wait for processing
sleep 5

# Check results
if [ -f /tmp/scanner-test.log ]; then
    echo -e "\n${GREEN}=== SCANNER OUTPUT ===${NC}"
    grep -E "(Process|CVE|EPSS|Runtime|Risk|Action)" /tmp/scanner-test.log | tail -20
    
    ACTIVE_CVES=$(grep -c "Runtime: ACTIVE" /tmp/scanner-test.log 2>/dev/null || echo "0")
    ALERTS=$(grep -c "Action: ALERT\|Action: BLOCK" /tmp/scanner-test.log 2>/dev/null || echo "0")
    
    echo -e "\n${GREEN}=== TEST SUMMARY ===${NC}"
    echo -e "Active CVEs Detected: ${YELLOW}$ACTIVE_CVES${NC}"
    echo -e "Alerts Triggered: ${YELLOW}$ALERTS${NC}"
    
    if [ "$ACTIVE_CVES" -gt 0 ]; then
        echo -e "${GREEN}SUCCESS: Scanner detected runtime activity!${NC}"
    else
        echo -e "${YELLOW}WARNING: No active CVEs detected - check scanner configuration${NC}"
    fi
    
    if [ "$ALERTS" -gt 0 ]; then
        echo -e "${GREEN}SUCCESS: Enforcement actions triggered!${NC}"
    fi
else
    echo -e "${RED}ERROR: Scanner log not created${NC}"
fi

# Cleanup
echo -e "\n${YELLOW}Cleaning up...${NC}"
kill $SCANNER_PID 2>/dev/null || true
wait $SCANNER_PID 2>/dev/null || true
docker stop juice-shop 2>/dev/null || true
docker rm juice-shop 2>/dev/null || true
rm -f test-config.yaml

echo -e "${GREEN}=== Test Complete ===${NC}"
echo "Results saved to: /tmp/scanner-test.log"
