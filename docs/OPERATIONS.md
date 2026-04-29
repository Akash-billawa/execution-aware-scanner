# Operations

## Recommended production controls

- Run the agent on Linux nodes only.
- Mount `/sys/fs/bpf` and `/proc` read-only where possible.
- Pin SBOM snapshots per image digest rather than mutable tags.
- Refresh K8s pod cache on a watch loop instead of per-event API calls.
- Ship findings to a gRPC remediator behind mTLS.

## Build notes

- Build the eBPF object on a Linux builder with BTF support.
- Keep Aya crate versions aligned between user space and eBPF crates.
- Validate the generated seccomp profiles in audit mode before enforcement.
- Use `scripts/build-ebpf.sh` for the Linux build and `scripts/validate-linux-ebpf-runtime.sh` for the host-level runtime smoke check.

## Known follow-up work

- Add TC/XDP program loading for active egress blocking.
- Add IPv6 socket address enrichment for network events; IPv4 syscall destinations and transfer counters are emitted now.
