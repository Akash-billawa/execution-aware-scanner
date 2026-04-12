# Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    Execution-Aware Scanner                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │   eBPF      │    │   Runtime   │    │    Risk     │         │
│  │   Kernel    │───▶│   Mapper    │───▶│   Engine    │         │
│  │  (15 Probes)│    │ (Process/Lib│    │(EXF Scoring)│         │
│  └─────────────┘    │  Tracking)  │    └──────┬──────┘         │
│         │           └─────────────┘           │                  │
│         │                  │                  │               │
│         ▼                  ▼                  ▼               │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │   Event     │    │   Vuln      │    │    Safe     │         │
│  │   Ring      │    │   Detector  │    │   Enforcer  │         │
│  │   Buffers   │    │  (Trivy)    │    │(Audit/Block)│         │
│  └─────────────┘    └─────────────┘    └─────────────┘         │
│         │                  │                  │               │
│         └──────────────────┴──────────────────┘               │
│                            │                                    │
│                            ▼                                    │
│                   ┌─────────────┐                              │
│                   │   Attack    │                              │
│                   │   Graph     │                              │
│                   │(Chain Detect)│                              │
│                   └─────────────┘                              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Data Flow

```
┌─────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│  eBPF   │    │  Runtime   │    │   Risk   │    │Enforcement│
│ Events  │───▶│  Mapper    │───▶│  Engine  │───▶│ Decision  │
└─────────┘    └──────────┘    └──────────┘    └──────────┘
      │              │               │               │
      │              │               │               │
      ▼              ▼               ▼               ▼
┌─────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│ Process │    │ Library  │    │  EXF     │    │  Audit   │
│ Start   │    │ Loaded   │    │  Score   │    │  Warn    │
│ Network │    │ CVE Match│    │ Priority │    │  Block   │
└─────────┘    └──────────┘    └──────────┘    └──────────┘
```

## Pipeline Stages

### Stage 1: Event Capture (eBPF)
```
┌──────────────────────────────────────────┐
│  Kernel Probes (15 total)                  │
├──────────────────────────────────────────┤
│  • execve/execveat    → Process start    │
│  • openat/openat2     → File access      │
│  • mmap/mprotect      → Library load     │
│  • tcp_connect        → Network connect  │
│  • udp_send/recv      → UDP traffic      │
│  • LSM hooks          → Security enforce │
│  • XDP                → Packet filter    │
└──────────────────────────────────────────┘
```

### Stage 2: Runtime Correlation
```
┌──────────────────────────────────────────┐
│  Process Tracking                          │
├──────────────────────────────────────────┤
│  PID: 1234                                 │
│  ├─ Command: nginx                         │
│  ├─ Libraries:                             │
│  │   • libssl.so.1.1  ← CVE-2023-XXXX    │
│  │   • libcrypto.so.1.1                   │
│  └─ Network: 10.0.0.1:443               │
└──────────────────────────────────────────┘
```

### Stage 3: Vulnerability Detection
```
┌──────────────────────────────────────────┐
│  Trivy Scan Results                      │
├──────────────────────────────────────────┤
│  Image: nginx:alpine                     │
│  ├─ CVE-2023-XXXX (openssl)              │
│  │   CVSS: 7.5 (HIGH)                    │
│  │   EPSS: 0.85                          │
│  │   KEV: YES                            │
│  │   Status: REACHABLE                   │
│  └─ ...                                  │
└──────────────────────────────────────────┘
```

### Stage 4: Risk Scoring (EXF)
```
┌──────────────────────────────────────────┐
│  EXF Score Calculation                    │
├──────────────────────────────────────────┤
│  CVSS × 0.45        = 3.375                │
│  EPSS × 10 × 0.25   = 2.125                │
│  KEV Bonus          = 1.500                │
│  Runtime Bonus      = 1.500                │
│  ──────────────────────────────────       │
│  TOTAL SCORE        = 8.5 / 10          │
│  PRIORITY           = CRITICAL            │
└──────────────────────────────────────────┘
```

### Stage 5: Safe Enforcement
```
┌──────────────────────────────────────────┐
│  Enforcement Decision                     │
├──────────────────────────────────────────┤
│  Mode: ENFORCE                             │
│  ├─ ✓ Runtime proven                     │
│  ├─ ✓ EPSS threshold met                 │
│  ├─ ✓ KEV confirmed                      │
│  ├─ ✓ Rollback available                │
│  └─ ✓ Production safe                    │
│                                            │
│  ACTION: Seccomp profile applied         │
│  ROLLBACK: kubectl delete ...            │
└──────────────────────────────────────────┘
```

## Modes

### Audit Mode (Default)
```
[2024-01-15 10:30:45] INFO: CVE-2023-XXXX detected in nginx (PID: 1234)
[2024-01-15 10:30:45] INFO: Risk Score: 8.5 (CRITICAL)
[2024-01-15 10:30:45] INFO: Action: Would enforce (audit mode)
```

### Warn Mode
```
[2024-01-15 10:30:45] WARN: ACTIVE EXPLOITATION DETECTED
[2024-01-15 10:30:45] WARN: CVE-2023-XXXX - openssl - HIGH
[2024-01-15 10:30:45] WARN: Process: nginx (PID: 1234)
[2024-01-15 10:30:45] WARN: Action: Alert sent, no enforcement
```

### Enforce Mode
```
[2024-01-15 10:30:45] CRITICAL: Enforcement triggered
[2024-01-15 10:30:45] INFO: Applied seccomp profile to nginx
[2024-01-15 10:30:45] INFO: Blocked egress to 192.168.1.100:4444
[2024-01-15 10:30:46] INFO: Rollback command: kubectl delete seccompprofile nginx-profile
```

## BPF Maps

```
┌──────────────────────────────────────────┐
│  Ring Buffers (Event Output)              │
├──────────────────────────────────────────┤
│  EXEC_EVENTS       → Process events      │
│  FILE_EVENTS       → File events         │
│  NET_EVENTS        → Network events      │
│  SECURITY_EVENTS   → Security alerts     │
└──────────────────────────────────────────┘

┌──────────────────────────────────────────┐
│  Policy Maps                              │
├──────────────────────────────────────────┤
│  ALLOWLIST         → Bypass monitoring   │
│  DENYLIST          → Block cgroup        │
│  BLOCKED_IPS       → Network blocks      │
│  CGROUP_SYSCALLS   → Seccomp policies    │
└──────────────────────────────────────────┘

┌──────────────────────────────────────────┐
│  State Maps                               │
├──────────────────────────────────────────┤
│  CONNECTIONS       → TCP tracking        │
│  FILE_CACHE         → Integrity monitor  │
│  CGROUP_STATS       → Statistics         │
│  PROCESS_PARENT     → Process tree       │
└──────────────────────────────────────────┘
```

## Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: scanner-agent
spec:
  template:
    spec:
      hostPID: true          # Required for eBPF
      containers:
      - name: scanner
        securityContext:
          capabilities:
            add:
            - BPF           # Load eBPF programs
            - PERFMON       # Performance monitoring
            - NET_ADMIN     # Network control
            - SYS_ADMIN     # System administration
        volumeMounts:
        - name: sys-fs-bpf
          mountPath: /sys/fs/bpf
        - name: proc
          mountPath: /host/proc
```

## Performance

| Metric | Target | Current |
|--------|--------|---------|
| Event Latency | < 1ms | ~0.5ms |
| Memory Usage | < 100MB | ~50MB |
| CPU Overhead | < 5% | ~2% |
| Event Drop Rate | < 0.1% | ~0.01% |
