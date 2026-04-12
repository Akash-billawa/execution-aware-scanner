#!/bin/bash
# Execution-Aware Scanner Demo Runner
# Automates the proof-of-concept demonstration

set -e

BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

OUTPUT_DIR="demo-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTPUT_DIR"

echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     Execution-Aware Vulnerability Scanner Demo          ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "This demo proves that the scanner detects CVEs ONLY when code executes."
echo "Output directory: $OUTPUT_DIR"
echo ""

# Phase 1: Build
echo -e "${YELLOW}[Phase 1/5] Building Scanner...${NC}"
if [ ! -f target/release/scanner-agent ]; then
    cargo build -p scanner-agent --release --no-default-features
fi
echo -e "${GREEN}✓ Build complete${NC}"
echo ""

# Phase 2: Static Trivy Scan
echo -e "${YELLOW}[Phase 2/5] Phase A: Static Scan (Baseline)...${NC}"
if ! command -v trivy &> /dev/null; then
    echo "Installing Trivy..."
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh
    sudo mv ./bin/trivy /usr/local/bin/
fi

echo "Running Trivy scan of Juice Shop..."
trivy image --format json -o "$OUTPUT_DIR/trivy-baseline.json" bkimminich/juice-shop 2>&1 | tail -3

TRIVY_TOTAL=$(jq '[.Results[].Vulnerabilities[]?] | length' "$OUTPUT_DIR/trivy-baseline.json" 2>/dev/null || echo "0")
echo -e "${GREEN}✓ Static scan complete: $TRIVY_TOTAL CVEs detected${NC}"
echo ""

# Phase 3: Baseline (No Traffic)
echo -e "${YELLOW}[Phase 3/5] Phase B: Execution-Aware Baseline (No Traffic)...${NC}"
echo "Starting scanner WITHOUT any application traffic..."

# Create config
cat > "$OUTPUT_DIR/demo-config.yaml" << EOF
scanner:
  mode: audit
  sbom_path: $OUTPUT_DIR/trivy-baseline.json
  output_format: json
enforcement:
  mode: audit
risk:
  cvss_weight: 0.45
  epss_weight: 2.5
  kev_weight: 1.0
  runtime_weight: 1.5
logging:
  level: info
EOF

# Run scanner briefly
sudo timeout 10 ./target/release/scanner-agent --config "$OUTPUT_DIR/demo-config.yaml" > "$OUTPUT_DIR/baseline-output.json" 2>&1 || true

BASELINE_ACTIVE=$(grep -c '"runtime":"Reachable"' "$OUTPUT_DIR/baseline-output.json" 2>/dev/null || echo "0")
if [ "$BASELINE_ACTIVE" -eq 0 ]; then
    echo -e "${GREEN}✓ Baseline shows 0 active CVEs (no execution detected)${NC}"
else
    echo -e "${YELLOW}⚠ Warning: $BASELINE_ACTIVE active CVEs in baseline${NC}"
fi
echo ""

# Phase 4: Runtime (With Traffic)
echo -e "${YELLOW}[Phase 4/5] Phase C: Execution-Aware Runtime (With Traffic)...${NC}"

echo "Starting Juice Shop..."
docker run -d -p 3000:3000 --name juice-shop-demo bkimminich/juice-shop 2>/dev/null || docker start juice-shop-demo 2>/dev/null || true

# Wait for startup
echo -n "Waiting for app to start"
for i in {1..30}; do
    if curl -s http://localhost:3000 > /dev/null 2>&1; then
        echo " ready!"
        break
    fi
    echo -n "."
    sleep 1
done
echo ""

# Start scanner
sudo ./target/release/scanner-agent --config "$OUTPUT_DIR/demo-config.yaml" > "$OUTPUT_DIR/runtime-output.json" 2>&1 &
SCANNER_PID=$!
sleep 5

echo "Generating application traffic..."
echo "  - Normal browsing"
curl -s http://localhost:3000/ > /dev/null
curl -s http://localhost:3000/api/Products > /dev/null
curl -s http://localhost:3000/rest/user/whoami > /dev/null

echo "  - Application usage"
curl -s http://localhost:3000/api/BasketItems > /dev/null
curl -s http://localhost:3000/rest/products/search?q=test > /dev/null

echo "  - Attack simulation"
curl -s "http://localhost:3000/rest/products/search?q=test')%20UNION%20SELECT%20* FROM Users--" > /dev/null
curl -s -X POST http://localhost:3000/api/BasketItems \
    -H "Content-Type: application/json" \
    -d '{"ProductId":1,"quantity":1}' > /dev/null

sleep 5

kill $SCANNER_PID 2>/dev/null || true
wait $SCANNER_PID 2>/dev/null || true

RUNTIME_ACTIVE=$(grep -c '"runtime":"Reachable"' "$OUTPUT_DIR/runtime-output.json" 2>/dev/null || echo "0")
RUNTIME_CRITICAL=$(grep -c '"priority":"Critical"' "$OUTPUT_DIR/runtime-output.json" 2>/dev/null || echo "0")
RUNTIME_HIGH=$(grep -c '"priority":"High"' "$OUTPUT_DIR/runtime-output.json" 2>/dev/null || echo "0")

if [ "$RUNTIME_ACTIVE" -gt 0 ]; then
    echo -e "${GREEN}✓ Runtime scan shows $RUNTIME_ACTIVE active CVEs${NC}"
else
    echo -e "${YELLOW}⚠ Runtime scan shows 0 active CVEs${NC}"
fi

# Cleanup
docker stop juice-shop-demo 2>/dev/null || true
docker rm juice-shop-demo 2>/dev/null || true

echo ""

# Phase 5: Results
echo -e "${YELLOW}[Phase 5/5] Results Summary${NC}"

if [ "$TRIVY_TOTAL" -gt 0 ]; then
    REDUCTION=$(( ((TRIVY_TOTAL - RUNTIME_ACTIVE) * 100) / TRIVY_TOTAL ))
else
    REDUCTION=0
fi

echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}                     DEMONSTRATION                          ${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "Scenario A - Static Trivy Scan:"
echo "  Total CVEs:        $TRIVY_TOTAL"
echo ""
echo "Scenario B - Execution-Aware (No Traffic):"
echo "  Active CVEs:       $BASELINE_ACTIVE"
echo "  Expected:          0"
echo ""
echo "Scenario C - Execution-Aware (With Traffic):"
echo "  Active CVEs:       $RUNTIME_ACTIVE"
echo "  Critical:          $RUNTIME_CRITICAL"
echo "  High:              $RUNTIME_HIGH"
echo ""
echo -e "${GREEN}┌─────────────────────────────────────────────────────────┐${NC}"
echo -e "${GREEN}│                       IMPACT                            │${NC}"
echo -e "${GREEN}├─────────────────────────────────────────────────────────┤${NC}"
printf "${GREEN}│${NC} %-55s ${GREEN}│${NC}\n" " "
printf "${GREEN}│${NC} Static Scan:       %-5d CVEs                       ${GREEN}│${NC}\n" "$TRIVY_TOTAL"
printf "${GREEN}│${NC} Active Detection:  %-5d CVEs                       ${GREEN}│${NC}\n" "$RUNTIME_ACTIVE"
printf "${GREEN}│${NC} Alert Reduction:   %-3d%%                            ${GREEN}│${NC}\n" "$REDUCTION"
printf "${GREEN}│${NC}                                                         ${GREEN}│${NC}\n"
if [ "$RUNTIME_ACTIVE" -gt 0 ] && [ "$BASELINE_ACTIVE" -eq 0 ]; then
    printf "${GREEN}│${NC} ${GREEN}✓ EXECUTION-AWARE PROVEN${NC}                               ${GREEN}│${NC}\n"
else
    printf "${GREEN}│${NC} ${YELLOW}⚠ Review scanner configuration${NC}                         ${GREEN}│${NC}\n"
fi
printf "${GREEN}│${NC}                                                         ${GREEN}│${NC}\n"
echo -e "${GREEN}└─────────────────────────────────────────────────────────┘${NC}"

echo ""
echo -e "${GREEN}Results saved to:${NC}"
echo "  $OUTPUT_DIR/trivy-baseline.json"
echo "  $OUTPUT_DIR/baseline-output.json"
echo "  $OUTPUT_DIR/runtime-output.json"
echo ""
echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                    Demo Complete                        ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
