#!/bin/bash
# Build eBPF programs for Linux
# Production-grade: Uses nightly with -Z build-std=core

set -e

echo "=== Building eBPF Scanner (Production) ==="

# Install nightly + rust-src (REQUIRED for build-std)
echo "Installing nightly toolchain + rust-src..."
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly

# Optimize eBPF binary size
export RUSTFLAGS="-C panic=abort"

# Build eBPF with nightly and build-std
echo "[1/2] Building scanner-ebpf (nightly + build-std=core)..."
cargo +nightly build -p scanner-ebpf \
    --release \
    --target bpfel-unknown-none \
    -Z build-std=core

echo "[2/2] Building scanner-agent (stable)..."
cargo build -p scanner-agent --release

echo "=== Build Complete ==="
echo "eBPF binary: target/bpfel-unknown-none/release/scanner-ebpf"
echo "Agent binary: target/release/scanner-agent"
