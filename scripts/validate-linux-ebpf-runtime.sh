#!/bin/bash
# Validate Linux eBPF runtime prerequisites and basic scanner runtime wiring.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

fail() {
  echo "[FAIL] $1" >&2
  exit 1
}

pass() {
  echo "[PASS] $1"
}

info() {
  echo "[INFO] $1"
}

[[ "$(uname -s)" == "Linux" ]] || fail "This validation script must run on Linux."

KERNEL="$(uname -r)"
info "Kernel: $KERNEL"

if [[ ! -e /sys/kernel/btf/vmlinux ]]; then
  fail "BTF not found at /sys/kernel/btf/vmlinux."
fi
pass "BTF detected"

command -v clang >/dev/null 2>&1 || fail "clang is required"
command -v cargo >/dev/null 2>&1 || fail "cargo is required"
command -v bpftool >/dev/null 2>&1 || fail "bpftool is required"
pass "Required build tools detected"

if [[ ! -r /proc/sys/kernel/bpf_stats_enabled ]]; then
  info "bpf_stats_enabled is not readable; continuing"
else
  info "bpf_stats_enabled=$(cat /proc/sys/kernel/bpf_stats_enabled)"
fi

info "Building eBPF object and userspace agent"
"$ROOT_DIR/scripts/build-ebpf.sh"

EBPF_OBJ="$ROOT_DIR/target/bpfel-unknown-none/release/libscanner_ebpf.so"
AGENT_BIN="$ROOT_DIR/target/release/scanner-agent"

[[ -f "$EBPF_OBJ" ]] || fail "Missing eBPF object: $EBPF_OBJ"
[[ -f "$AGENT_BIN" ]] || fail "Missing agent binary: $AGENT_BIN"
pass "Build artifacts present"

info "Inspecting eBPF object"
llvm-objdump -h "$EBPF_OBJ" >/dev/null 2>&1 || fail "llvm-objdump could not read eBPF object"
pass "eBPF object is readable"

info "Checking agent CLI"
"$AGENT_BIN" --help >/dev/null 2>&1 || fail "Agent binary did not start"
pass "Agent CLI responds"

echo
echo "Linux eBPF runtime prerequisites look good."
echo "Next step: run the agent as root on a Linux host with the eBPF object available in the configured path."
