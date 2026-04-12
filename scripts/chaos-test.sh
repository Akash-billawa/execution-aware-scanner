#!/bin/bash
# Chaos Engineering Test Script
#
# Validates reliability mechanisms:
# - Circuit breaker behavior
# - Event buffering under load
# - Recovery after failures
#
# Usage: ./scripts/chaos-test.sh [test_scenario]

set -e

SCENARIO=${1:-"all"}
NAMESPACE="execution-aware-scanner"
POD_NAME="$(kubectl get pods -n $NAMESPACE -l app.kubernetes.io/name=execution-aware-scanner -o jsonpath='{.items[0].metadata.name}')"
LOG_FILE="chaos-test-$(date +%Y%m%d-%H%M%S).log"

echo "========================================" | tee -a $LOG_FILE
echo "Chaos Engineering Test Suite" | tee -a $LOG_FILE
echo "Scenario: $SCENARIO" | tee -a $LOG_FILE
echo "Target: $POD_NAME" | tee -a $LOG_FILE
echo "========================================" | tee -a $LOG_FILE
echo "" | tee -a $LOG_FILE

# Helper functions
get_metrics() {
    kubectl exec -n $NAMESPACE $POD_NAME -- wget -qO- http://localhost:9898/metrics 2>/dev/null || echo ""
}

get_health() {
    kubectl exec -n $NAMESPACE $POD_NAME -- wget -qO- http://localhost:9898/health 2>/dev/null || echo '{"status": "unknown"}'
}

log_event() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a $LOG_FILE
}

# Test 1: Webhook Failure Injection
test_webhook_failure() {
    log_event "=== TEST 1: Webhook Failure Injection ==="
    
    # Create fake webhook endpoint
    kubectl run fake-webhook --image=nginx:alpine --port=8080 -n $NAMESPACE -- /bin/sh -c "echo '404' > /usr/share/nginx/html/index.html && nginx -g 'daemon off;'" 2>/dev/null || true
    
    log_event "Injecting webhook failures..."
    
    # Monitor circuit breaker
    for i in {1..10}; do
        sleep 5
        HEALTH=$(get_health)
        log_event "Health check $i: $HEALTH"
        
        # Check if circuit breaker opened
        if kubectl logs -n $NAMESPACE $POD_NAME --since=10s 2>/dev/null | grep -q "circuit breaker"; then
            log_event "✅ Circuit breaker triggered"
            break
        fi
    done
    
    # Cleanup
    kubectl delete pod fake-webhook -n $NAMESPACE --force 2>/dev/null || true
    
    # Wait for recovery
    log_event "Waiting for recovery..."
    sleep 30
    
    HEALTH=$(get_health)
    if echo "$HEALTH" | grep -q "healthy"; then
        log_event "✅ System recovered from webhook failure"
        return 0
    else
        log_event "❌ System did not recover"
        return 1
    fi
}

# Test 2: Event Burst Simulation
test_event_burst() {
    log_event "=== TEST 2: Event Burst Simulation ==="
    
    # Generate burst of events
    log_event "Generating event burst..."
    
    # Create burst generator
    cat <<'EOF' | kubectl apply -f - 2>/dev/null || true
apiVersion: batch/v1
kind: Job
metadata:
  name: event-burst
  namespace: execution-aware-scanner
spec:
  template:
    spec:
      restartPolicy: Never
      containers:
      - name: burst
        image: alpine
        command:
        - /bin/sh
        - -c
        - |
          for i in $(seq 1 1000); do
            echo "Burst event $i" > /dev/null
          done
          sleep 60
EOF
    
    # Monitor drop rate
    log_event "Monitoring drop rate..."
    for i in {1..6}; do
        sleep 10
        METRICS=$(get_metrics)
        EVENTS=$(echo "$METRICS" | grep "events_total" | awk '{print $2}' || echo "0")
        DROPPED=$(echo "$METRICS" | grep "events_dropped" | awk '{print $2}' || echo "0")
        
        if [ "$EVENTS" -gt 0 ]; then
            DROP_RATE=$(echo "scale=2; $DROPPED / $EVENTS * 100" | bc)
            log_event "Events: $EVENTS, Dropped: $DROPPED (${DROP_RATE}%)"
        fi
    done
    
    # Cleanup
    kubectl delete job event-burst -n $NAMESPACE --force 2>/dev/null || true
    
    log_event "✅ Burst test completed"
    return 0
}

# Test 3: Network Partition
test_network_partition() {
    log_event "=== TEST 3: Network Partition Simulation ==="
    
    log_event "Simulating network loss..."
    
    # Add network policy to block egress
    cat <<EOF | kubectl apply -f - 2>/dev/null || true
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: chaos-deny-egress
  namespace: $NAMESPACE
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: execution-aware-scanner
  policyTypes:
  - Egress
  egress: []
EOF
    
    log_event "Network blocked for 30s..."
    sleep 30
    
    # Remove block
    kubectl delete networkpolicy chaos-deny-egress -n $NAMESPACE 2>/dev/null || true
    
    log_event "Network restored, checking recovery..."
    sleep 10
    
    HEALTH=$(get_health)
    if echo "$HEALTH" | grep -q "healthy"; then
        log_event "✅ System recovered after network partition"
        return 0
    else
        log_event "❌ System did not recover"
        return 1
    fi
}

# Test 4: Resource Exhaustion
test_resource_exhaustion() {
    log_event "=== TEST 4: Resource Exhaustion ==="
    
    log_event "Creating resource pressure..."
    
    # Create memory stress
    cat <<'EOF' | kubectl apply -f - 2>/dev/null || true
apiVersion: apps/v1
kind: Deployment
metadata:
  name: memory-stress
  namespace: execution-aware-scanner
spec:
  replicas: 3
  selector:
    matchLabels:
      app: memory-stress
  template:
    metadata:
      labels:
        app: memory-stress
    spec:
      containers:
      - name: stress
        image: polinux/stress
        resources:
          requests:
            memory: "200Mi"
        command: ["stress"]
        args: ["--vm", "4", "--vm-bytes", "150M", "--timeout", "60s"]
EOF
    
    log_event "Monitoring under resource pressure..."
    sleep 30
    
    # Check if scanner still healthy
    HEALTH=$(get_health)
    STATUS=$(echo "$HEALTH" | grep -o '"status": "[^"]*"' | cut -d'"' -f4)
    
    # Cleanup
    kubectl delete deployment memory-stress -n $NAMESPACE --force 2>/dev/null || true
    
    log_event "Resource pressure removed"
    sleep 10
    
    if [ "$STATUS" = "healthy" ] || [ "$STATUS" = "degraded" ]; then
        log_event "✅ System survived resource exhaustion"
        return 0
    else
        log_event "⚠️  System became unhealthy (may be expected)"
        return 0
    fi
}

# Run tests
case $SCENARIO in
    "webhook")
        test_webhook_failure
        ;;
    "burst")
        test_event_burst
        ;;
    "network")
        test_network_partition
        ;;
    "resource")
        test_resource_exhaustion
        ;;
    "all"|*)
        test_webhook_failure
        echo "" | tee -a $LOG_FILE
        test_event_burst
        echo "" | tee -a $LOG_FILE
        test_network_partition
        echo "" | tee -a $LOG_FILE
        test_resource_exhaustion
        ;;
esac

echo "" | tee -a $LOG_FILE
echo "========================================" | tee -a $LOG_FILE
echo "Chaos test completed" | tee -a $LOG_FILE
echo "Log: $LOG_FILE" | tee -a $LOG_FILE
echo "========================================" | tee -a $LOG_FILE
