#!/bin/bash
# Production Performance Benchmark Script
# Measures: CPU, Memory, Event Rate, Drop Rate, Latency
#
# Usage: ./scripts/benchmark-perf.sh [duration_seconds]

set -e

DURATION=${1:-300}
NAMESPACE="execution-aware-scanner"
POD_SELECTOR="app.kubernetes.io/name=execution-aware-scanner"

echo "========================================"
echo "Execution-Aware Scanner Performance Test"
echo "Duration: ${DURATION}s"
echo "========================================"
echo ""

# Create test namespace if not exists
kubectl create namespace load-test --dry-run=client -o yaml | kubectl apply -f - 2>/dev/null || true

# Deploy load generator
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: load-generator
  namespace: load-test
spec:
  replicas: 5
  selector:
    matchLabels:
      app: load-generator
  template:
    metadata:
      labels:
        app: load-generator
    spec:
      containers:
      - name: nginx
        image: nginx:alpine
        resources:
          requests:
            cpu: 100m
            memory: 128Mi
      - name: stress
        image: polinux/stress
        command: ["stress"]
        args: ["--cpu", "2", "--io", "2", "--vm", "2", "--vm-bytes", "128M", "--timeout", "${DURATION}s"]
        resources:
          requests:
            cpu: 500m
            memory: 256Mi
EOF

echo "Waiting for load generator..."
sleep 5

# Get scanner pod
SCANNER_POD=$(kubectl get pods -n $NAMESPACE -l $POD_SELECTOR -o jsonpath='{.items[0].metadata.name}')
echo "Monitoring scanner: $SCANNER_POD"

# Create results directory
mkdir -p benchmark-results
echo "timestamp,cpu_percent,memory_rss_mb,events_total,events_dropped,drop_rate,paths_detected" > benchmark-results/metrics.csv

# Collect metrics
echo ""
echo "Collecting metrics..."
for i in $(seq 1 $((DURATION / 5))); do
    TIMESTAMP=$(date +%s)
    
    # Get CPU and Memory
    METRICS=$(kubectl top pod -n $NAMESPACE $SCANNER_POD --containers 2>/dev/null || echo "0 0")
    CPU=$(echo "$METRICS" | grep scanner-agent | awk '{print $2}' | sed 's/m//')
    MEM=$(echo "$METRICS" | grep scanner-agent | awk '{print $3}' | sed 's/Mi//')
    
    # Get Prometheus metrics
    PROMETHEUS=$(kubectl exec -n $NAMESPACE $SCANNER_POD -- wget -qO- http://localhost:9898/metrics 2>/dev/null || echo "")
    
    EVENTS=$(echo "$PROMETHEUS" | grep "^events_total" | awk '{print $2}' || echo "0")
    DROPPED=$(echo "$PROMETHEUS" | grep "^events_dropped" | awk '{print $2}' || echo "0")
    PATHS=$(echo "$PROMETHEUS" | grep "^paths_detected" | awk '{print $2}' || echo "0")
    
    # Calculate drop rate
    if [ "$EVENTS" -gt 0 ]; then
        DROP_RATE=$(echo "scale=4; $DROPPED / $EVENTS * 100" | bc)
    else
        DROP_RATE="0"
    fi
    
    echo "$TIMESTAMP,$CPU,$MEM,$EVENTS,$DROPPED,$DROP_RATE,$PATHS" >> benchmark-results/metrics.csv
    
    echo -ne "\rProgress: $((i * 5))/${DURATION}s | CPU: ${CPU}m | MEM: ${MEM}Mi | Drop Rate: ${DROP_RATE}%"
    
    sleep 5
done

echo ""
echo ""

# Calculate summary
echo "========================================"
echo "Performance Summary"
echo "========================================"

# Parse CSV for stats
CPU_AVG=$(tail -n +2 benchmark-results/metrics.csv | awk -F',' '{sum+=$2; count++} END {printf "%.1f", sum/count}')
CPU_MAX=$(tail -n +2 benchmark-results/metrics.csv | awk -F',' 'BEGIN{max=0} {if($2>max) max=$2} END {print max}')
MEM_AVG=$(tail -n +2 benchmark-results/metrics.csv | awk -F',' '{sum+=$3; count++} END {printf "%.1f", sum/count}')
MEM_MAX=$(tail -n +2 benchmark-results/metrics.csv | awk -F',' 'BEGIN{max=0} {if($3>max) max=$3} END {print max}')
DROP_AVG=$(tail -n +2 benchmark-results/metrics.csv | awk -F',' '{sum+=$6; count++} END {printf "%.2f", sum/count}')
DROP_MAX=$(tail -n +2 benchmark-results/metrics.csv | awk -F',' 'BEGIN{max=0} {if($6>max) max=$6} END {print max}')
EVENTS_TOTAL=$(tail -1 benchmark-results/metrics.csv | cut -d',' -f4)
PATHS_TOTAL=$(tail -1 benchmark-results/metrics.csv | cut -d',' -f7)

echo ""
echo "Resource Usage:"
echo "  CPU Average:     ${CPU_AVG}m (${CPU_AVG}%)"
echo "  CPU Max:         ${CPU_MAX}m"
echo "  Memory Average:  ${MEM_AVG}Mi"
echo "  Memory Max:      ${MEM_MAX}Mi"
echo ""
echo "Event Processing:"
echo "  Total Events:    $EVENTS_TOTAL"
echo "  Drop Rate Avg:  ${DROP_AVG}%"
echo "  Drop Rate Max:  ${DROP_MAX}%"
echo "  Paths Detected: $PATHS_TOTAL"
echo ""

# Pass/Fail criteria
echo "Validation Results:"
echo "  CPU < 1000m (1 core):      $( [ "${CPU_AVG%.*}" -lt 1000 ] && echo "✅ PASS" || echo "❌ FAIL" )"
echo "  Memory < 512Mi:           $( [ "${MEM_AVG%.*}" -lt 512 ] && echo "✅ PASS" || echo "❌ FAIL" )"
echo "  Drop Rate < 5%:           $( [ "${DROP_AVG%.*}" -lt 5 ] && echo "✅ PASS" || echo "❌ FAIL" )"
echo ""

# Cleanup
echo "Cleaning up..."
kubectl delete deployment load-generator -n load-test 2>/dev/null || true
kubectl delete namespace load-test --wait=false 2>/dev/null || true

echo ""
echo "Results saved to: benchmark-results/metrics.csv"
echo "========================================"
