# Testing Guide - Execution-Aware Scanner

## Quick Test

```bash
# Pull the image
docker pull ghcr.io/akash-billawa/execution-aware-scanner:main

# Test help/usage
docker run --rm ghcr.io/akash-billawa/execution-aware-scanner:main --help

# Check version
docker run --rm ghcr.io/akash-billawa/execution-aware-scanner:main --version
```

## Local Testing with eBPF (Linux)

```bash
# Validate host prerequisites first
./scripts/validate-linux-ebpf-runtime.sh

# Run with privileged mode (required for eBPF)
docker run --rm --privileged \
  --pid=host \
  --network=host \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  ghcr.io/akash-billawa/execution-aware-scanner:main
```

If you are building locally instead of using the published image:

```bash
./scripts/build-ebpf.sh
sudo ./target/release/scanner-agent
```

## Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: execution-aware-scanner
spec:
  selector:
    matchLabels:
      app: execution-aware-scanner
  template:
    metadata:
      labels:
        app: execution-aware-scanner
    spec:
      hostPID: true
      hostNetwork: true
      containers:
      - name: scanner
        image: ghcr.io/akash-billawa/execution-aware-scanner:main
        securityContext:
          capabilities:
            add:
              - SYS_ADMIN
              - SYS_RESOURCE
              - NET_ADMIN
              - BPF
        volumeMounts:
        - name: debugfs
          mountPath: /sys/kernel/debug
          readOnly: true
        - name: cgroup
          mountPath: /sys/fs/cgroup
          readOnly: true
      volumes:
      - name: debugfs
        hostPath:
          path: /sys/kernel/debug
      - name: cgroup
        hostPath:
          path: /sys/fs/cgroup
```

## Verify Image Contents

```bash
# Check image layers
docker inspect ghcr.io/akash-billawa/execution-aware-scanner:main

# Verify eBPF object exists
docker run --rm --entrypoint /bin/sh \
  ghcr.io/akash-billawa/execution-aware-scanner:main \
  -c "ls -la /opt/scanner/"

# Expected output:
# scanner-ebpf.o
# /usr/local/bin/scanner-agent
```

## Image Details

- **Repository**: `ghcr.io/akash-billawa/execution-aware-scanner`
- **Tag**: `main` (latest commit)
- **Architecture**: `linux/amd64`
- **Base**: `debian:bookworm-slim`
- **User**: `65532:65532` (non-root)
- **Size**: ~150MB

## Verify Build Provenance

The image includes SLSA provenance attestation. Verify with:

```bash
docker buildx imagetools inspect \
  ghcr.io/akash-billawa/execution-aware-scanner:main \
  --format "{{ json .Provenance }}"
```
