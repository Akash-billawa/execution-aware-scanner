# Production Deployment Guide

## Overview

This guide covers production deployment of the Execution-Aware Scanner on Kubernetes clusters.

## Prerequisites

### Kubernetes Requirements

- **Version**: 1.25+ with `CONFIG_BPF=y` and `CONFIG_DEBUG_INFO_BTF=y`
- **Kernel**: 5.8+ with BTF support
- **Nodes**: Linux nodes only (x86_64 or ARM64)
- **Network**: CNI must support NetworkPolicy

### Node Requirements

```bash
# Verify kernel version
uname -r

# Verify BTF support
ls /sys/kernel/btf/

# Verify eBPF capabilities
cat /proc/sys/kernel/unprivileged_bpf_disabled
# Should be 0
```

### RBAC Requirements

The scanner requires these permissions:
- `pods` - get, list, watch
- `nodes` - get, list, watch
- `configmaps` - get, list, create (for seccomp profiles)
- `securitycontextconstraints` (OpenShift only)

## Installation

### Option 1: Helm (Recommended)

```bash
# Add Helm repository
helm repo add execution-aware-scanner \
  https://example.github.io/execution-aware-scanner
helm repo update

# Install with default values
helm install execution-aware-scanner \
  execution-aware-scanner/execution-aware-scanner \
  --namespace execution-aware-scanner \
  --create-namespace

# Install with custom values
helm install execution-aware-scanner \
  execution-aware-scanner/execution-aware-scanner \
  --namespace execution-aware-scanner \
  --create-namespace \
  --values custom-values.yaml
```

### Option 2: kubectl (Manifests)

```bash
# Apply manifests
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl apply -f deploy/kubernetes/rbac.yaml
kubectl apply -f deploy/kubernetes/configmap.yaml
kubectl apply -f deploy/kubernetes/daemonset.yaml
kubectl apply -f deploy/kubernetes/networkpolicy.yaml
kubectl apply -f deploy/kubernetes/service.yaml
kubectl apply -f deploy/kubernetes/servicemonitor.yaml
```

### Option 3: Operator (Advanced)

```bash
# Install operator
kubectl apply -f https://github.com/example/execution-aware-scanner/releases/latest/download/operator.yaml

# Create Scanner custom resource
cat <<EOF | kubectl apply -f -
apiVersion: scanner.example.com/v1
kind: Scanner
metadata:
  name: production
spec:
  nodeSelector:
    security-scanning: enabled
  risk:
    minCvss: 4.0
  enforcement:
    auto:
      seccomp: true
      quarantine: false
EOF
```

## Configuration

### High-Value Configuration Options

```yaml
# values-production.yaml
scanner:
  nodeSelector:
    node-type: worker
  tolerations:
    - key: "dedicated"
      operator: "Equal"
      value: "security"
      effect: "NoSchedule"
  resources:
    requests:
      cpu: "1000m"
      memory: "1Gi"
    limits:
      cpu: "4000m"
      memory: "4Gi"

risk:
  minCvss: 4.0
  weights:
    cvss: 0.45
    epss: 0.25
    kev: 0.15
    runtime: 0.15

enforcement:
  auto:
    seccomp: true
    quarantine: false
    blockEgress: true

webhook:
  enabled: true
  endpoints:
    - name: siem
      url: https://siem.company.com/webhook
      minPriority: High
      batchSize: 50
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SCANNER__RISK__MINIMUM_CVSS` | Minimum CVSS score | 4.0 |
| `SCANNER__RISK__MINIMUM_EPSS` | Minimum EPSS score | 0.1 |
| `SCANNER__REMEDIATOR__ENABLED` | Enable auto-remediation | true |
| `SCANNER__REMEDIATOR__ENFORCE_CRITICAL` | Enforce critical findings | true |
| `SCANNER__REMEDIATOR__AUTO_SECCOMP` | Auto-generate seccomp | true |

## Monitoring

### Prometheus Metrics

The scanner exposes these metrics on `:9898/metrics`:

```prometheus
# Event processing
scanner_events_total{type="exec"}
scanner_events_total{type="file"}
scanner_events_total{type="net"}
scanner_dropped_events
scanner_batches_processed

# Findings
scanner_findings_total{priority="Critical"}
scanner_findings_total{priority="High"}
scanner_findings_total{priority="Medium"}

# Enforcement
scanner_seccomp_profiles_generated
scanner_ips_blocked
scanner_workloads_quarantined

# Intel
scanner_intel_cves_tracked
scanner_intel_last_refresh_timestamp
```

### Grafana Dashboards

Import dashboards from `grafana/dashboards/`:

```bash
kubectl create configmap scanner-dashboards \
  --from-file=grafana/dashboards/ \
  --namespace monitoring
```

### Alerting Rules

```yaml
groups:
  - name: scanner.rules
    rules:
      - alert: ScannerHighEventDropRate
        expr: |
          rate(scanner_dropped_events[5m]) / rate(scanner_events_total[5m]) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Scanner dropping events"
      
      - alert: ScannerCriticalFinding
        expr: |
          scanner_findings_total{priority="Critical"} > 0
        for: 1m
        labels:
          severity: critical
```

## Troubleshooting

### Common Issues

**Issue**: Scanner pods in CrashLoopBackOff

```bash
# Check kernel compatibility
kubectl logs -n execution-aware-scanner daemonset/execution-aware-scanner | grep -i "kernel"

# Verify BPF support
cat /sys/kernel/debug/tracing/README
```

**Issue**: No findings detected

```bash
# Check SBOM mounting
kubectl exec -n execution-aware-scanner daemonset/execution-aware-scanner -- ls /var/lib/scanner/sboms

# Verify events are flowing
kubectl port-forward -n execution-aware-scanner daemonset/execution-aware-scanner 9898:9898
curl http://localhost:9898/metrics | grep scanner_events_total
```

**Issue**: High memory usage

```bash
# Check ring buffer sizes
kubectl exec -n execution-aware-scanner daemonset/execution-aware-scanner -- ls -la /sys/fs/bpf/

# Adjust in values.yaml
scanner:
  resources:
    limits:
      memory: "8Gi"
```

### Performance Tuning

For high-traffic clusters:

```yaml
scanner:
  resources:
    limits:
      cpu: "4"
      memory: "8Gi"
  securityContext:
    # Increase for faster event processing
    capabilities:
      add: ["BPF", "PERFMON", "NET_ADMIN", "SYS_ADMIN", "SYS_RESOURCE"]
```

## Security Hardening

### Pod Security Standards

The chart supports `restricted` Pod Security Standards:

```yaml
podSecurityContext:
  enforce: restricted
  audit: restricted
  warn: restricted
```

### Network Policies

Default network policy blocks all ingress except metrics:

```yaml
networkPolicy:
  enabled: true
  ingress:
    - from:
        - namespaceSelector: {}
      ports:
        - protocol: TCP
          port: 9898
  egress:
    - to:
        - namespaceSelector: {}
      ports:
        - protocol: TCP
          port: 443  # Threat intel APIs
```

### Seccomp Profiles

Auto-generated seccomp profiles are stored in:

```bash
/var/lib/scanner/seccomp/
├── web-app.json
├── api-gateway.json
└── database.json
```

Apply to workloads:

```yaml
securityContext:
  seccompProfile:
    type: Localhost
    localhostProfile: web-app.json
```

## Upgrading

### Helm Upgrade

```bash
# Update chart
helm repo update

# Upgrade with dry run
helm upgrade execution-aware-scanner \
  execution-aware-scanner/execution-aware-scanner \
  --namespace execution-aware-scanner \
  --dry-run \
  --debug

# Perform upgrade
helm upgrade execution-aware-scanner \
  execution-aware-scanner/execution-aware-scanner \
  --namespace execution-aware-scanner

# Verify rollout
kubectl rollout status daemonset/execution-aware-scanner -n execution-aware-scanner
```

### Rollback

```bash
# Rollback to previous version
helm rollback execution-aware-scanner 0 -n execution-aware-scanner

# Verify
kubectl get pods -n execution-aware-scanner -o wide
```

## Support

### Debug Mode

Enable verbose logging:

```yaml
logging:
  level: debug
```

### Collect Logs

```bash
kubectl logs -n execution-aware-scanner -l app.kubernetes.io/name=execution-aware-scanner --all-containers > scanner.log
```

### Report Issues

- GitHub Issues: https://github.com/example/execution-aware-scanner/issues
- Security: security@example.com
