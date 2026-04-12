#!/bin/bash
# Build eBPF programs for Linux

set -e

echo "=== Building eBPF Scanner ==="

# Ensure we're on the right toolchain
rustup override set 1.88.0 2>/dev/null || true

# Install required components
rustup component add rust-src 2>/dev/null || true

# Add BPF target
rustup target add bpfel-unknown-none 2>/dev/null || true

echo "[1/2] Building scanner-ebpf..."
cargo build -p scanner-ebpf --release --target bpfel-unknown-none

echo "[2/2] Building scanner-agent..."
cargo build -p scanner-agent --release

echo "=== Build Complete ==="
echo "eBPF binary: target/bpfel-unknown-none/release/scanner-ebpf"
echo "Agent binary: target/release/scanner-agent"
