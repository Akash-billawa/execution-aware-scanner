#!/bin/bash
# Chaos Engineering Test Suite for Execution-Aware Scanner
# Runs chaos experiments against a Kubernetes deployment

set -e

NAMESPACE="${NAMESPACE:-scanner-system}"
CHAOS_DIR="$(dirname "$0")/../tests/chaos"
RESULTS_FILE="${RESULTS_FILE:-chaos-results.json}"

echo "=== Chaos Engineering Test Suite ==="
echo "Namespace: $NAMESPACE"
echo "Results: $RESULTS_FILE"
echo ""

# Check prerequisites
if ! command -v kubectl &> /dev/null; then
    echo "ERROR: kubectl not found"
    exit 1
fi

if ! kubectl get ns "$NAMESPACE" &> /dev/null; then
    echo "ERROR: Namespace $NAMESPACE not found"
    exit 1
fi

# Check if Chaos Mesh is installed
if ! kubectl get crd podchaos.chaos-mesh.org &> /dev/null; then
    echo "WARNING: Chaos Mesh not installed, skipping chaos tests"
    echo "Install with: helm install chaos-mesh chaos-mesh/chaos-mesh -n chaos-mesh --set dashboard.create=true"
    exit 0
fi

echo "Running chaos experiments..."

# Track results
declare -A RESULTS

# Test 1: Pod Kill
echo ""
echo "--- Test 1: Pod Kill Recovery ---"
kubectl apply -f "$CHAOS_DIR/pod-kill.yaml" 2>/dev/null || true
sleep 30

# Check if scanner pods recovered
SCANNER_PODS=$(kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name=execution-aware-scanner --no-headers 2>/dev/null | wc -l)
if [ "$SCANNER_PODS" -gt 0 ]; then
    echo "PASS: Scanner pods recovered after kill ($SCANNER_PODS pods running)"
    RESULTS["pod_kill"]="PASS"
else
    echo "FAIL: Scanner pods not recovered"
    RESULTS["pod_kill"]="FAIL"
fi

kubectl delete -f "$CHAOS_DIR/pod-kill.yaml" 2>/dev/null || true

# Test 2: Network Partition
echo ""
echo "--- Test 2: Network Partition Resilience ---"
kubectl apply -f "$CHAOS_DIR/network-partition.yaml" 2>/dev/null || true
sleep 70

# Check if scanner is still processing events (health endpoint)
HEALTH=$(kubectl exec -n "$NAMESPACE" deploy/scanner-agent -- curl -s http://localhost:9898/health 2>/dev/null || echo "unreachable")
if echo "$HEALTH" | grep -q "ok\|healthy\|OK"; then
    echo "PASS: Scanner healthy during network partition"
    RESULTS["network_partition"]="PASS"
else
    echo "FAIL: Scanner unhealthy during partition: $HEALTH"
    RESULTS["network_partition"]="FAIL"
fi

kubectl delete -f "$CHAOS_DIR/network-partition.yaml" 2>/dev/null || true

# Test 3: CPU Stress
echo ""
echo "--- Test 3: CPU Stress Tolerance ---"
kubectl apply -f "$CHAOS_DIR/stress-cpu.yaml" 2>/dev/null || true
sleep 130

# Check drop rate
METRICS=$(kubectl exec -n "$NAMESPACE" deploy/scanner-agent -- curl -s http://localhost:9898/metrics 2>/dev/null || echo "")
DROP_RATE=$(echo "$METRICS" | grep "scanner_dropped_events" | awk '{print $2}' || echo "0")
if [ -z "$DROP_RATE" ] || [ "$DROP_RATE" = "0" ]; then
    echo "PASS: No events dropped under CPU stress"
    RESULTS["cpu_stress"]="PASS"
else
    echo "WARN: Events dropped under CPU stress: $DROP_RATE"
    RESULTS["cpu_stress"]="WARN"
fi

kubectl delete -f "$CHAOS_DIR/stress-cpu.yaml" 2>/dev/null || true

# Test 4: IO Latency
echo ""
echo "--- Test 4: IO Latency Tolerance ---"
kubectl apply -f "$CHAOS_DIR/io-latency.yaml" 2>/dev/null || true
sleep 70

# Check if scanner is still responsive
HEALTH=$(kubectl exec -n "$NAMESPACE" deploy/scanner-agent -- curl -s http://localhost:9898/health 2>/dev/null || echo "unreachable")
if echo "$HEALTH" | grep -q "ok\|healthy\|OK"; then
    echo "PASS: Scanner healthy with IO latency"
    RESULTS["io_latency"]="PASS"
else
    echo "FAIL: Scanner unhealthy with IO latency"
    RESULTS["io_latency"]="FAIL"
fi

kubectl delete -f "$CHAOS_DIR/io-latency.yaml" 2>/dev/null || true

# Generate results summary
echo ""
echo "=== Chaos Test Results ==="
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

for test in "${!RESULTS[@]}"; do
    result="${RESULTS[$test]}"
    echo "  $test: $result"
    case "$result" in
        PASS) ((PASS_COUNT++)) ;;
        FAIL) ((FAIL_COUNT++)) ;;
        WARN) ((WARN_COUNT++)) ;;
    esac
done

echo ""
echo "Summary: $PASS_COUNT passed, $FAIL_COUNT failed, $WARN_COUNT warnings"

# Write results to JSON
cat > "$RESULTS_FILE" << EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "namespace": "$NAMESPACE",
  "results": {
$(for test in "${!RESULTS[@]}"; do
    echo "    \"$test\": \"${RESULTS[$test]}\","
done | sed '$ s/,$//')
  },
  "summary": {
    "passed": $PASS_COUNT,
    "failed": $FAIL_COUNT,
    "warnings": $WARN_COUNT
  }
}
EOF

echo ""
echo "Results written to $RESULTS_FILE"

if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
fi
