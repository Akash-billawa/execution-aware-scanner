# Production Deployment Guide

Deploy the Execution-Aware Vulnerability Scanner as a Kubernetes DaemonSet for cluster-wide visibility.

## Quick Start

```bash
# Apply all manifests
kubectl apply -f deploy/kubernetes/

# Verify deployment
kubectl get daemonsets -n execution-aware-scanner
kubectl get pods -n execution-aware-scanner -o wide

# View logs
kubectl logs -f -n execution-aware-scanner -l app.kubernetes.io/name=execution-aware-scanner
```

## Prerequisites

- Kubernetes cluster 1.21+
- eBPF-capable nodes (kernel 5.8+ with BTF)
- Container runtime with cgroup v2 support
- Node-level privileges for eBPF

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Kubernetes Cluster                    │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│  │   Node 1    │  │   Node 2    │  │   Node 3    │    │
│  │ ┌─────────┐ │  │ ┌─────────┐ │  │ ┌─────────┐ │    │
│  │ │Scanner │ │  │ │Scanner │ │  │ │Scanner │ │    │
│  │ │Daemon  │ │  │ │Daemon  │ │  │ │Daemon  │ │    │
│  │ │eBPF    │ │  │ │eBPF    │ │  │ │eBPF    │ │    │
│  │ └────┬────┘ │  │ └────┬────┘ │  │ └────┬────┘ │    │
│  └──────┼──────┘  └──────┼──────┘  └──────┼──────┘    │
│         │                │                │             │
│         └────────────────┴────────────────┘             │
│                          │                              │
│                    ┌─────┴─────┐                        │
│                    │  SIEM    │                        │
│                    │ (Webhook) │                        │
│                    └───────────┘                        │
└─────────────────────────────────────────────────────────┘
```

## Resource Requirements

| Resource | Request | Limit |
|----------|---------|-------|
| CPU | 100m | 1000m |
| Memory | 256Mi | 512Mi |
| eBPF | Required | Required |

## Configuration

### Webhook Integration

Create a ConfigMap for webhook settings:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: scanner-config
  namespace: execution-aware-scanner
data:
  webhook.url: "http://your-siem:9000/alerts"
  webhook.type: "elastic"  # or slack, splunk, generic
```

### Reliability Settings

Environment variables for production tuning:

```yaml
env:
  - name: SCANNER__RELIABILITY__CHANNEL_BUFFER_SIZE
    value: "10000"  # Events before backpressure
  
  - name: SCANNER__RELIABILITY__WATCHDOG_TIMEOUT_SECS
    value: "60"  # Restart if no heartbeat
  
  - name: SCANNER__RELIABILITY__MAX_CONSECUTIVE_ERRORS
    value: "5"  # Restart threshold
```

## Security Context

The scanner requires elevated privileges for eBPF:

```yaml
securityContext:
  privileged: false
  allowPrivilegeEscalation: false
  capabilities:
    add:
      - BPF          # Load eBPF programs
      - PERFMON      # Performance monitoring
      - NET_ADMIN    # Network tracing
      - SYS_ADMIN    # System operations
      - SYS_RESOURCE # Resource limits
```

## Monitoring

### Health Endpoints

- `/health` - Liveness probe
- `/ready` - Readiness probe
- `/metrics` - Prometheus metrics

### Key Metrics

| Metric | Description |
|--------|-------------|
| `events_total` | Total events processed |
| `events_dropped` | Events dropped (backpressure) |
| `drop_rate` | Percentage of events dropped |
| `paths_detected` | Attack paths detected |
| `alerts_sent` | Webhooks sent successfully |

### Prometheus ServiceMonitor

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: scanner-metrics
  namespace: execution-aware-scanner
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: execution-aware-scanner
  endpoints:
    - port: metrics
      path: /metrics
      interval: 30s
```

## Troubleshooting

### Pod CrashLoopBackOff

```bash
# Check logs
kubectl logs -n execution-aware-scanner <pod-name> --previous

# Check kernel version (requires 5.8+)
kubectl get node <node> -o json | jq '.status.nodeInfo.kernelVersion'

# Check eBPF support
kubectl exec -it <pod-name> -- cat /sys/kernel/debug/tracing/available_events
```

### High Event Drop Rate

Symptoms: `/metrics` shows `drop_rate > 0.01`

Solutions:
1. Increase `SCANNER__RELIABILITY__CHANNEL_BUFFER_SIZE`
2. Add more CPU resources
3. Reduce `SCANNER__RUNTIME__ANALYSIS_INTERVAL_SECS`

### Webhook Failures

Symptoms: `alerts_sent` not increasing

```bash
# Test webhook connectivity
kubectl exec -it <pod-name> -- curl -v $WEBHOOK_URL

# Check circuit breaker status
kubectl logs <pod-name> | grep "circuit breaker"
```

## Multi-Node Intelligence

With cluster-wide deployment, the scanner provides:

- **Node-level visibility**: Per-node attack path detection
- **Cross-node correlation**: Track attacks spanning nodes
- **Centralized alerts**: Single SIEM integration point

### Example Alert with Node Context

```json
{
  "event_type": "ATTACK_PATH_ALERT",
  "severity": "CRITICAL",
  "confidence": 0.88,
  "metadata": {
    "scanner_id": "scanner-xxx",
    "node_name": "k8s-worker-1",
    "namespace": "production",
    "pod_name": "nginx-5d4f8b9c-xyz"
  },
  "attack_path": [
    "proc:1234:nginx",
    "lib:libssl.so",
    "vuln:CVE-2023-XXXX",
    "net:10.0.0.1:443"
  ]
}
```

## Rollout Strategy

### Canary Deployment

```bash
# Label subset of nodes
kubectl label nodes node-1 node-2 scanner=canary

# Deploy canary
kubectl apply -f deploy/kubernetes/daemonset-canary.yaml

# Monitor
kubectl logs -f -n execution-aware-scanner -l scanner=canary

# Full rollout
kubectl apply -f deploy/kubernetes/daemonset-prod.yaml
```

### Rolling Update

```bash
# Update image
kubectl set image daemonset/execution-aware-scanner \
  scanner-agent=ghcr.io/akash-billawa/execution-aware-scanner:v0.2.0 \
  -n execution-aware-scanner

# Monitor rollout
kubectl rollout status daemonset/execution-aware-scanner -n execution-aware-scanner
```

## Production Checklist

- [ ] Nodes running kernel 5.8+ with BTF
- [ ] RBAC configured correctly
- [ ] Webhook endpoint reachable
- [ ] Resource limits set
- [ ] Health probes configured
- [ ] Monitoring in place
- [ ] Log aggregation configured
- [ ] Alert routing tested
- [ ] Runbook documented
