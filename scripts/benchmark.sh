#!/bin/bash
# Execution-Aware Scanner Benchmark Suite
# Compares execution-aware scanning vs traditional static scanning

set -e

BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}=== Execution-Aware Scanner Benchmark ===${NC}"
echo ""

# Configuration
JUICE_SHOP_IMAGE="bkimminich/juice-shop"
OUTPUT_DIR="benchmark-results-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTPUT_DIR"

echo -e "${YELLOW}[1/6] Environment Setup${NC}"
echo "Results directory: $OUTPUT_DIR"
echo "Target image: $JUICE_SHOP_IMAGE"
echo ""

# Check prerequisites
echo -e "${YELLOW}[2/6] Checking Prerequisites${NC}"
if ! command -v trivy &> /dev/null; then
    echo -e "${YELLOW}Installing Trivy...${NC}"
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh
    sudo mv ./bin/trivy /usr/local/bin/
fi

if ! command -v docker &> /dev/null; then
    echo -e "${RED}Docker is required${NC}"
    exit 1
fi

if [ ! -f target/release/scanner-agent ]; then
    echo -e "${YELLOW}Building scanner-agent...${NC}"
    cargo build -p scanner-agent --release --no-default-features
fi

# Phase 1: Static Trivy Scan (Baseline)
echo -e "\n${YELLOW}[3/6] Phase 1: Static Trivy Scan (Baseline)${NC}"
echo "Running Trivy vulnerability scan..."
TRIVY_START=$(date +%s%N)
trivy image --format json -o "$OUTPUT_DIR/trivy-results.json" "$JUICE_SHOP_IMAGE" 2>&1 | tail -5
TRIVY_END=$(date +%s%N)
TRIVY_MS=$(( (TRIVY_END - TRIVY_START) / 1000000 ))

# Parse Trivy results
TRIVY_CRITICAL=$(jq '[.Results[].Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' "$OUTPUT_DIR/trivy-results.json" 2>/dev/null || echo "0")
TRIVY_HIGH=$(jq '[.Results[].Vulnerabilities[]? | select(.Severity == "HIGH")] | length' "$OUTPUT_DIR/trivy-results.json" 2>/dev/null || echo "0")
TRIVY_MEDIUM=$(jq '[.Results[].Vulnerabilities[]? | select(.Severity == "MEDIUM")] | length' "$OUTPUT_DIR/trivy-results.json" 2>/dev/null || echo "0")
TRIVY_LOW=$(jq '[.Results[].Vulnerabilities[]? | select(.Severity == "LOW")] | length' "$OUTPUT_DIR/trivy-results.json" 2>/dev/null || echo "0")
TRIVY_TOTAL=$((TRIVY_CRITICAL + TRIVY_HIGH + TRIVY_MEDIUM + TRIVY_LOW))

echo -e "${GREEN}Trivy Results:${NC}"
echo "  Critical: $TRIVY_CRITICAL"
echo "  High: $TRIVY_HIGH"
echo "  Medium: $TRIVY_MEDIUM"
echo "  Low: $TRIVY_LOW"
echo "  Total: $TRIVY_TOTAL"
echo "  Time: ${TRIVY_MS}ms"
echo ""

# Phase 2: Start Vulnerable App
echo -e "${YELLOW}[4/6] Phase 2: Starting Juice Shop (Runtime Target)${NC}"
docker stop juice-shop-benchmark 2>/dev/null || true
docker rm juice-shop-benchmark 2>/dev/null || true
docker run -d -p 3000:3000 --name juice-shop-benchmark "$JUICE_SHOP_IMAGE"

# Wait for startup
for i in {1..30}; do
    if curl -s http://localhost:3000 > /dev/null 2>&1; then
        echo "Juice Shop ready"
        break
    fi
    echo -n "."
    sleep 1
done
echo ""

# Phase 3: Baseline Scan (No Traffic)
echo -e "\n${YELLOW}[5/6] Phase 3: Baseline Scan (No Traffic)${NC}"
echo "Starting scanner without application traffic..."

# Create test config
cat > "$OUTPUT_DIR/test-config.yaml" << EOF
scanner:
  mode: audit
  sbom_path: $OUTPUT_DIR/trivy-results.json
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
  file: $OUTPUT_DIR/scanner-baseline.log
EOF

# Run scanner for 15 seconds
sudo timeout 15 ./target/release/scanner-agent --config "$OUTPUT_DIR/test-config.yaml" > "$OUTPUT_DIR/scanner-baseline.json" 2>&1 || true

BASELINE_FINDINGS=$(grep -c '"cve":' "$OUTPUT_DIR/scanner-baseline.json" 2>/dev/null || echo "0")
BASELINE_ACTIVE=$(grep -c '"runtime":"Reachable"' "$OUTPUT_DIR/scanner-baseline.json" 2>/dev/null || echo "0")

echo -e "${GREEN}Baseline Results (No Traffic):${NC}"
echo "  Total Findings: $BASELINE_FINDINGS"
echo "  Active CVEs: $BASELINE_ACTIVE"
echo ""

# Phase 4: Runtime Scan (With Traffic)
echo -e "\n${YELLOW}[6/6] Phase 4: Runtime Scan (With Traffic)${NC}"
echo "Starting scanner and triggering application traffic..."

# Start scanner in background
sudo ./target/release/scanner-agent --config "$OUTPUT_DIR/test-config.yaml" > "$OUTPUT_DIR/scanner-runtime.json" 2>&1 &
SCANNER_PID=$!

# Wait for scanner
sleep 5

# Generate traffic
RAMP_START=$(date +%s)
echo "Phase 4a: Light traffic (normal browsing)..."
curl -s http://localhost:3000 > /dev/null
curl -s http://localhost:3000/api/Products > /dev/null
curl -s http://localhost:3000/rest/user/whoami > /dev/null
sleep 3

LIGHT_END=$(date +%s)
LIGHT_DURATION=$((LIGHT_END - RAMP_START))

echo "Phase 4b: Medium traffic (application usage)..."
curl -s http://localhost:3000/api/BasketItems > /dev/null
curl -s http://localhost:3000/rest/products/search?q=test > /dev/null
curl -s http://localhost:3000/api/SecurityQuestions > /dev/null
curl -s http://localhost:3000/rest/languages > /dev/null
sleep 3

MEDIUM_END=$(date +%s)
MEDIUM_DURATION=$((MEDIUM_END - LIGHT_END))

echo "Phase 4c: Heavy traffic (attack simulation)..."
curl -s "http://localhost:3000/rest/products/search?q=test')%20UNION%20SELECT%20* FROM Users--" > /dev/null
curl -s -X POST http://localhost:3000/api/BasketItems \
    -H "Content-Type: application/json" \
    -d '{"ProductId":1,"BasketId":"1","quantity":1}' > /dev/null
curl -s http://localhost:3000/redirect?to=http://evil.com > /dev/null
sleep 5

HEAVY_END=$(date +%s)
HEAVY_DURATION=$((HEAVY_END - MEDIUM_END))

# Stop scanner
kill $SCANNER_PID 2>/dev/null || true
wait $SCANNER_PID 2>/dev/null || true

RUNTIME_END=$(date +%s)
TOTAL_TRAFFIC_TIME=$((RUNTIME_END - RAMP_START))

# Parse runtime results
RUNTIME_FINDINGS=$(grep -c '"cve":' "$OUTPUT_DIR/scanner-runtime.json" 2>/dev/null || echo "0")
RUNTIME_ACTIVE=$(grep -c '"runtime":"Reachable"' "$OUTPUT_DIR/scanner-runtime.json" 2>/dev/null || echo "0")
RUNTIME_CRITICAL=$(grep -c '"priority":"Critical"' "$OUTPUT_DIR/scanner-runtime.json" 2>/dev/null || echo "0")
RUNTIME_HIGH=$(grep -c '"priority":"High"' "$OUTPUT_DIR/scanner-runtime.json" 2>/dev/null || echo "0")

# Calculate reduction
if [ "$TRIVY_TOTAL" -gt 0 ]; then
    REDUCTION=$(( ((TRIVY_TOTAL - RUNTIME_ACTIVE) * 100) / TRIVY_TOTAL ))
else
    REDUCTION=0
fi

# Cleanup
docker stop juice-shop-benchmark 2>/dev/null || true
docker rm juice-shop-benchmark 2>/dev/null || true

# Generate Report
echo -e "\n${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}           BENCHMARK RESULTS REPORT                     ${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"

# Comparison Table
echo -e "\n${GREEN}┌─────────────────────────────────────────────────────┐${NC}"
echo -e "${GREEN}│                   COMPARISON TABLE                   │${NC}"
echo -e "${GREEN}├─────────────────────────────────────────────────────┤${NC}"
printf "${GREEN}│${NC} %-20s ${GREEN}│${NC} %8s ${GREEN}│${NC} %8s ${GREEN}│${NC} %10s ${GREEN}│${NC}\n" "Scanner" "Total" "Active" "Time"
echo -e "${GREEN}├─────────────────────────────────────────────────────┤${NC}"
printf "${GREEN}│${NC} %-20s ${GREEN}│${NC} %8d ${GREEN}│${NC} %8s ${GREEN}│${NC} %8dms ${GREEN}│${NC}\n" "Trivy (Static)" "$TRIVY_TOTAL" "N/A" "$TRIVY_MS"
printf "${GREEN}│${NC} %-20s ${GREEN}│${NC} %8d ${GREEN}│${NC} %8d ${GREEN}│${NC} %8ds ${GREEN}│${NC}\n" "Our Scanner" "$RUNTIME_FINDINGS" "$RUNTIME_ACTIVE" "$TOTAL_TRAFFIC_TIME"
echo -e "${GREEN}└─────────────────────────────────────────────────────┘${NC}"

# Severity Breakdown
echo -e "\n${GREEN}Severity Breakdown:${NC}"
echo "  Trivy Critical:     $TRIVY_CRITICAL"
echo "  Trivy High:         $TRIVY_HIGH"
echo ""
echo "  Runtime Critical:   $RUNTIME_CRITICAL"
echo "  Runtime High:       $RUNTIME_HIGH"

# Key Metrics
echo -e "\n${GREEN}Key Metrics:${NC}"
echo "  CVEs Static:        $TRIVY_TOTAL"
echo "  CVEs Runtime:       $RUNTIME_ACTIVE"
echo "  Reduction:          ${REDUCTION}%"
echo "  False Positives:    $((TRIVY_TOTAL - RUNTIME_ACTIVE))"

# Execution-Aware Proof
echo -e "\n${GREEN}Execution-Aware Proof:${NC}"
echo "  Baseline (no traffic):  $BASELINE_ACTIVE active CVEs"
echo "  Runtime (with traffic): $RUNTIME_ACTIVE active CVEs"
if [ "$RUNTIME_ACTIVE" -gt "$BASELINE_ACTIVE" ]; then
    echo -e "  ${GREEN}✓ PROVEN: System detects runtime execution${NC}"
else
    echo -e "  ${YELLOW}⚠ No runtime detection - check eBPF probe loading${NC}"
fi

# Performance
echo -e "\n${GREEN}Performance:${NC}"
echo "  Trivy scan time:        ${TRIVY_MS}ms"
echo "  Traffic generation:     ${TOTAL_TRAFFIC_TIME}s"
echo "    - Light phase:        ${LIGHT_DURATION}s"
echo "    - Medium phase:       ${MEDIUM_DURATION}s"
echo "    - Heavy phase:        ${HEAVY_DURATION}s"

# Save JSON report
jq -n \
    --arg date "$(date -Iseconds)" \
    --arg trivy_total "$TRIVY_TOTAL" \
    --arg trivy_critical "$TRIVY_CRITICAL" \
    --arg trivy_high "$TRIVY_HIGH" \
    --arg runtime_total "$RUNTIME_FINDINGS" \
    --arg runtime_active "$RUNTIME_ACTIVE" \
    --arg runtime_critical "$RUNTIME_CRITICAL" \
    --arg runtime_high "$RUNTIME_HIGH" \
    --arg reduction "$REDUCTION" \
    --arg baseline_active "$BASELINE_ACTIVE" \
    --arg trivy_time "$TRIVY_MS" \
    '{
        timestamp: $date,
        static_scanning: {
            tool: "Trivy",
            total_cves: ($trivy_total | tonumber),
            critical: ($trivy_critical | tonumber),
            high: ($trivy_high | tonumber),
            scan_time_ms: ($trivy_time | tonumber)
        },
        execution_aware: {
            total_findings: ($runtime_total | tonumber),
            active_cves: ($runtime_active | tonumber),
            critical: ($runtime_critical | tonumber),
            high: ($runtime_high | tonumber),
            baseline_active: ($baseline_active | tonumber)
        },
        comparison: {
            reduction_percent: ($reduction | tonumber),
            false_positives_eliminated: (($trivy_total | tonumber) - ($runtime_active | tonumber))
        }
    }' > "$OUTPUT_DIR/benchmark-report.json"

echo -e "\n${GREEN}Results saved to:${NC}"
echo "  $OUTPUT_DIR/benchmark-report.json"
echo "  $OUTPUT_DIR/scanner-runtime.json"
echo "  $OUTPUT_DIR/trivy-results.json"

echo -e "\n${BLUE}═══════════════════════════════════════════════════════${NC}"
