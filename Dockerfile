# Multi-stage build for execution-aware-scanner
# Production build with eBPF support (REQUIRED)

FROM rust:1.90-bookworm AS builder

WORKDIR /src
COPY . .

ENV CARGO_TARGET_DIR=/src/target

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler \
    clang \
    llvm \
    && rm -rf /var/lib/apt/lists/*

# Install nightly toolchain with rust-src
RUN rustup toolchain install nightly \
    && rustup component add rust-src --toolchain nightly

# Install bpf-linker (eBPF linker)
RUN cargo +nightly install bpf-linker

# Build eBPF programs
# Note: bpfel-unknown-none is tier 3, so we use -Z build-std=core
# This compiles core library from source
RUN cargo +nightly build \
    --manifest-path scanner-ebpf/Cargo.toml \
    --release \
    --target bpfel-unknown-none \
    -Z build-std=core

# Verify eBPF object was created
RUN ls -la /src/target/bpfel-unknown-none/release/ && \
    test -f /src/target/bpfel-unknown-none/release/libscanner_ebpf.so

# Build the agent with eBPF support
RUN cargo build --release -p scanner-agent --features ebpf

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libelf1 curl \
    && rm -rf /var/lib/apt/lists/*

# Copy agent binary
COPY --from=builder /src/target/release/scanner-agent /usr/local/bin/scanner-agent

# Copy eBPF object (REQUIRED)
COPY --from=builder /src/target/bpfel-unknown-none/release/libscanner_ebpf.so /opt/scanner/scanner-ebpf.so

# Copy SBOMs and data
COPY examples/sboms /var/lib/scanner/sboms

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:9898/health || exit 1

ENTRYPOINT ["/usr/local/bin/scanner-agent"]
