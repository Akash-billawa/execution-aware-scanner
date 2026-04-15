# Multi-stage build for execution-aware-scanner
# Production build: Uses nightly for eBPF (if available), stable for agent

FROM rust:1.90-bookworm AS builder

WORKDIR /src
COPY . .

# Install protobuf compiler
RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler && rm -rf /var/lib/apt/lists/*

# Build agent WITHOUT eBPF first (always works)
# The agent has stub modules for non-eBPF builds
RUN cargo build --release -p scanner-agent --no-default-features && \
    cp /src/target/release/scanner-agent /tmp/scanner-agent

# Try to build eBPF (optional - may fail)
RUN rustup toolchain install nightly 2>/dev/null || echo "Nightly install failed"
RUN rustup component add rust-src --toolchain nightly 2>/dev/null || echo "rust-src failed"
RUN rustup target add bpfel-unknown-none --toolchain nightly 2>/dev/null || echo "target add failed"

# Try to install bpf-linker and build eBPF
RUN cargo +nightly install bpf-linker 2>/dev/null && \
    cargo +nightly build -p scanner-ebpf --release --target bpfel-unknown-none -Z build-std=core 2>/dev/null && \
    echo "eBPF build succeeded" || \
    echo "eBPF build failed - will run in degraded mode"

# Final binary is already built above
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libelf1 curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --uid 65532 scanner

# Copy agent binary
COPY --from=builder /tmp/scanner-agent /usr/local/bin/scanner-agent

# Copy eBPF object if it exists (otherwise scanner runs in degraded mode)
COPY --from=builder /src/target/bpfel-unknown-none/release/*.so /opt/scanner/ 2>/dev/null || echo "No eBPF object found"

# Copy SBOMs and data
COPY examples/sboms /var/lib/scanner/sboms

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:9898/health || exit 1

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/scanner-agent"]
