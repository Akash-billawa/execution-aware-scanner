#!/bin/bash
# Build eBPF programs for Linux
# Uses nightly with -Z build-std=core for the kernel crate.

set -e

echo "=== Building eBPF Scanner (Production) ==="

# Install nightly + rust-src (REQUIRED for build-std)
echo "Installing nightly toolchain + rust-src..."
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
rustup target add bpfel-unknown-none --toolchain nightly

# Optimize eBPF binary size
export RUSTFLAGS="-C panic=abort"

# Build eBPF with nightly and build-std
echo "[1/2] Building scanner-ebpf (nightly + build-std=core)..."
cargo +nightly build \
    --manifest-path scanner-ebpf/Cargo.toml \
    --release \
    --target bpfel-unknown-none \
    -Z build-std=core

echo "[2/2] Building scanner-agent (stable)..."
cargo build -p scanner-agent --release --features ebpf

echo "=== Build Complete ==="
echo "eBPF binary: target/bpfel-unknown-none/release/scanner-ebpf"
echo "Agent binary: target/release/scanner-agent"
