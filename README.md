# Execution-Aware eBPF Scanner

**From 10,000 CVEs to 10 critical findings by ranking what is actually active at runtime.**

[![CI](https://github.com/Akash-billawa/execution-aware-scanner/actions/workflows/ci.yaml/badge.svg)](https://github.com/Akash-billawa/execution-aware-scanner/actions/workflows/ci.yaml)
[![Docker](https://img.shields.io/docker/pulls/ghcr.io/akash-billawa/execution-aware-scanner)](https://ghcr.io/akash-billawa/execution-aware-scanner)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)
[![Release](https://img.shields.io/github/v/release/Akash-billawa/execution-aware-scanner)](https://github.com/Akash-billawa/execution-aware-scanner/releases)

> Linux is required for eBPF runtime tracing.
>
> Windows and macOS are supported for no-eBPF development and testing.

## What It Does

The scanner combines:

1. Runtime signals from eBPF
2. Image or SBOM vulnerability data
3. EPSS and CISA KEV threat intelligence
4. Risk scoring and attack-path correlation

It is designed to distinguish:

- Reachable vulnerabilities: the package or library is actually observed at runtime
- Dormant vulnerabilities: present in the image but not currently exercised
- Higher-priority findings: active runtime evidence plus strong threat intel

## Current Status

- Verified now: `cargo test --workspace --no-default-features`
- Verified path: Windows and macOS development flow without eBPF
- Implemented: Linux eBPF runtime event emission, loader wiring, and unified userspace consumption
- Pending external validation: live Linux host smoke test with eBPF permissions
- Not yet claimed: production readiness for Linux runtime enforcement

Detailed status is in [docs/VALIDATION_RESULTS.md](docs/VALIDATION_RESULTS.md).

## Quick Start

### Development build without eBPF

```bash
cargo build --release -p scanner-agent --no-default-features
```

### Run tests without eBPF

```bash
cargo test --workspace --no-default-features
```

### Linux build with eBPF support

Install Linux prerequisites first, then:

```bash
cargo build --release -p scanner-agent --features ebpf
```

## Linux Runtime Requirements

- Linux kernel `5.8+`
- BTF available at `/sys/kernel/btf/vmlinux`
- Root or equivalent capabilities to load eBPF programs
- `clang`, `llvm`, `libelf`, and matching kernel headers

Example Ubuntu/Debian setup:

```bash
sudo apt update
sudo apt install -y git curl build-essential clang llvm libelf-dev linux-headers-$(uname -r)
```

## Linux Validation Steps

To validate the eBPF runtime on a Linux host:

1. Build with eBPF features: `cargo build --release -p scanner-agent --features ebpf`
2. Run the scanner: `sudo ./target/release/scanner-agent --features ebpf`
3. Verify eBPF programs loaded: `sudo bpftool prog list | grep -E "execve|tracepoint|kprobe"`
4. Generate test traffic (e.g., curl from a container with known CVE)
5. Check logs for REACHABLE findings with correct library paths
6. Validate cleanup: After shutdown, `sudo bpftool prog list` should show only system programs

See [docs/VALIDATION_RESULTS.md](docs/VALIDATION_RESULTS.md) for detailed validation results and procedures.

## Runtime Model

The Linux runtime now supports the actual unified kernel event schema emitted by the eBPF crate:

- Kernel side emits `SECURITY_EVENTS`
- Userspace loader attaches syscall tracepoints and TCP/UDP kprobes present in `scanner-ebpf`
- Userspace event consumer translates unified security events into the existing runtime pipeline
- Runtime correlation marks CVEs reachable only when package or library evidence matches observed runtime paths
- Runtime probes currently emit exec, openat, mmap, mprotect, IPv4 connect, sendto, recvfrom, and TCP/UDP transfer events

This keeps the existing risk engine, state store, attack graph, and webhook path intact while aligning the Linux runtime with the current eBPF crate.

## Example Finding

```text
[CRITICAL] CVE-2023-XXXX
  Package: openssl
  Runtime: REACHABLE via /usr/lib/libssl.so.1.1
  EPSS: 0.85
  KEV: true
  Action: audit or enforce depending mode
```

## Metrics

The agent exposes:

- `/metrics`
- `/metrics/kernel`
- `/health`
- `/ready`

Default metrics bind address:

```bash
http://localhost:9898/metrics
```

## Configuration

Example environment variables:

```bash
export RUST_LOG=info
export SCANNER__RISK__MINIMUM_CVSS=4.0
export SCANNER__RISK__MINIMUM_EPSS=0.1
export SCANNER__METRICS__BIND_ADDR=0.0.0.0:9898
```

Key risk weights currently used by the agent:

```yaml
risk:
  min_cvss: 4.0
  min_epss: 0.1
  weights:
    cvss: 0.50
    epss: 0.30
    kev: 1.50
    runtime: 2.00
```

## Repository Layout

```text
scanner-agent/     userspace daemon
scanner-common/    shared event and finding types
scanner-ebpf/      Linux eBPF programs
configs/           config examples
deploy/            Kubernetes manifests
helm/              Helm chart
docs/              deployment and operations docs
```

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md)
- [docs/OPERATIONS.md](docs/OPERATIONS.md)
- [docs/SECURITY_HARDENING.md](docs/SECURITY_HARDENING.md)
- [docs/VALIDATION_RESULTS.md](docs/VALIDATION_RESULTS.md)
- [GITHUB_SETUP.md](GITHUB_SETUP.md)

## Notes

- Auto-generated seccomp output still requires review before production use.
- The Linux eBPF path should be validated on a real Linux host or VM before enabling enforcement.
- The workspace deliberately excludes `scanner-ebpf` from normal cross-platform test runs.

## License

Apache License 2.0. See [LICENSE](LICENSE).