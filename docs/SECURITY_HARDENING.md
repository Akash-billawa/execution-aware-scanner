# Security Hardening Guide

## Overview

This guide describes how to deploy the execution-aware scanner with minimal privileges while maintaining full functionality.

## The Problem: Privileged Containers

❌ **DON'T: Full privileged mode**
```yaml
securityContext:
  privileged: true  # ❌ Grants full host access
```

This violates:
- Principle of least privilege
- Kubernetes Pod Security Standards (PSS)
- CIS benchmarks

## The Solution: Capability-Based Deployment

✅ **DO: Minimal capabilities**

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: execution-aware-scanner
spec:
  template:
    spec:
      hostPID: true        # Required for process tracking
      hostNetwork: true    # Required for network visibility
      containers:
      - name: scanner
        image: ghcr.io/akash-billawa/execution-aware-scanner:main
        securityContext:
          privileged: false           # ❌ No full privilege
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 65532            # scanner user
          capabilities:
            add:
              - CAP_BPF               # eBPF programs
              - CAP_PERFMON           # Performance monitoring
              - CAP_NET_ADMIN         # Network visibility
              - CAP_NET_RAW           # Raw sockets
              - CAP_IPC_LOCK          # Memory locking
              - CAP_SYS_PTRACE        # Process tracing
              - CAP_SYS_ADMIN         # Required for eBPF loading (limited scope)
            drop:
              - ALL                    # Drop all other capabilities
        resources:
          limits:
            cpu: "1000m"
            memory: "512Mi"
          requests:
            cpu: "100m"
            memory: "128Mi"
        volumeMounts:
        - name: debug
          mountPath: /sys/kernel/debug
          readOnly: true
        - name: cgroup
          mountPath: /host/proc
          readOnly: true
        - name: tmp
          mountPath: /tmp
      volumes:
      - name: debug
        hostPath:
          path: /sys/kernel/debug
      - name: cgroup
        hostPath:
          path: /proc
      - name: tmp
        emptyDir: {}
```

## Required Capabilities Explained

| Capability | Purpose | Risk Level |
|-----------|---------|------------|
| `CAP_BPF` | Load and run eBPF programs | Medium |
| `CAP_PERFMON` | Access perf events | Low |
| `CAP_NET_ADMIN` | Network interface access | Medium |
| `CAP_NET_RAW` | Raw socket access | Medium |
| `CAP_IPC_LOCK` | Lock memory (prevent swaps) | Low |
| `CAP_SYS_PTRACE` | Process tracing | Medium |
| `CAP_SYS_ADMIN` | Mount namespaces (eBPF) | High |

## Pod Security Standards Compliance

### PSS Profile: Restricted

The scanner requires `privileged: false` with specific capabilities, which is allowed under the "baseline" profile but NOT "restricted".

**Mitigation:** Use dedicated security namespace:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: security-monitoring
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

## Seccomp Profile

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: scanner-seccomp
data:
  scanner.json: |
    {
      "defaultAction": "SCMP_ACT_ERRNO",
      "architectures": ["SCMP_ARCH_X86_64"],
      "syscalls": [
        {
          "names": [
            "openat", "read", "write", "close",
            "mmap", "munmap", "mprotect",
            "socket", "connect", "bind", "listen",
            "bpf", "perf_event_open",
            "getpid", "gettid", "getuid", "getgid"
          ],
          "action": "SCMP_ACT_ALLOW"
        }
      ]
    }
```

## AppArmor Profile

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: scanner-apparmor
data:
  profile: |
    #include <tunables/global>

    profile scanner-agent flags=(complain) {
      #include <abstractions/base>

      capability bpf,
      capability perfmon,
      capability net_admin,
      capability net_raw,
      capability ipc_lock,
      capability sys_ptrace,
      capability sys_admin,

      /sys/kernel/debug/** r,
      /host/proc/** r,
      /tmp/** rw,

      deny /etc/passwd w,
      deny /etc/shadow rw,
      deny /root/** rw,
    }
```

## Network Policies

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: scanner-policy
spec:
  podSelector:
    matchLabels:
      app: execution-aware-scanner
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: monitoring
    ports:
    - protocol: TCP
      port: 9898  # Metrics
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: TCP
      port: 443  # K8s API
  - to:
    - namespaceSelector:
        matchLabels:
          name: webhook
    ports:
    - protocol: TCP
      port: 8080  # Alerting
```

## RBAC Minimal Permissions

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: scanner
rules:
# Read pods and nodes (for enrichment)
- apiGroups: [""]
  resources: ["pods", "nodes"]
  verbs: ["get", "list", "watch"]
# Read deployments (for workload identification)
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets", "daemonsets"]
  verbs: ["get", "list"]
# Read security contexts (for policy validation)
- apiGroups: ["policy"]
  resources: ["podsecuritypolicies"]
  verbs: ["get", "list"]
  resourceNames: ["baseline", "restricted"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: scanner
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: scanner
subjects:
- kind: ServiceAccount
  name: scanner
  namespace: security-monitoring
```

## Audit Logging

Enable audit logging for scanner operations:

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
# Log all scanner pod creation
- level: RequestResponse
  resources:
  - group: ""
    resources: ["pods"]
  namespaces: ["security-monitoring"]
  verbs: ["create", "delete", "update"]
  
# Log eBPF-related syscalls
- level: Metadata
  resources:
  - group: ""
    resources: ["pods"]
  namespaces: ["security-monitoring"]
```

## Verification Commands

```bash
# Check capabilities
kubectl exec -n security-monitoring scanner-pod -- cat /proc/self/status | grep Cap

# Verify read-only root
kubectl exec -n security-monitoring scanner-pod -- touch /test 2>&1
# Expected: Read-only file system

# Check seccomp
kubectl exec -n security-monitoring scanner-pod -- cat /proc/self/status | grep Seccomp
# Expected: Seccomp: 2

# Verify no privileged access
kubectl get pod scanner-pod -n security-monitoring -o jsonpath='{.spec.containers[0].securityContext.privileged}'
# Expected: <no output> or "false"
```

## Security Checklist

- [ ] Container runs as non-root (UID 65532)
- [ ] Read-only root filesystem
- [ ] No privilege escalation allowed
- [ ] Only required capabilities added
- [ ] All other capabilities dropped
- [ ] Seccomp profile applied
- [ ] AppArmor profile configured
- [ ] Network policies restrict traffic
- [ ] RBAC follows least privilege
- [ ] Audit logging enabled
- [ ] Resource limits set
- [ ] PSS baseline profile enforced

## Threat Model

### Assets Protected
1. eBPF programs (kernel code)
2. Process event data
3. Network flow information
4. Vulnerability data

### Threats Mitigated

| Threat | Mitigation |
|--------|------------|
| Container escape | No privileged mode, minimal capabilities |
| Data exfiltration | Network policies, no write access to host |
| Privilege escalation | `allowPrivilegeEscalation: false` |
| DoS | Resource limits (CPU/memory) |
| Kernel exploit | Seccomp, AppArmor profiles |

### Residual Risks

- `CAP_SYS_ADMIN` required for eBPF (high privilege)
- `CAP_BPF` is relatively new (kernel 5.8+)
- Host network access for traffic monitoring

**Mitigation:** Run in dedicated security namespace with restricted access.

## References

- [Kubernetes Security Contexts](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Linux Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [eBPF Security](https://ebpf.io/what-is-ebpf#security)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)

---

*Last Updated: 2024-04-14*
*Version: v1.0*
