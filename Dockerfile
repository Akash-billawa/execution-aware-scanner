# Multi-stage build for execution-aware-scanner
# Production build: Uses nightly for eBPF, stable for agent

FROM rust:1.90-bookworm AS builder

WORKDIR /src
COPY . .

# Install nightly toolchain with rust-src for eBPF
RUN rustup toolchain install nightly \
    && rustup component add rust-src --toolchain nightly

# Build eBPF with nightly
RUN cargo +nightly build -p scanner-ebpf \
    --release \
    --target bpfel-unknown-none \
    -Z build-std=core

# Build agent (stable)
RUN cargo build --release -p scanner-agent --no-default-features

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libelf1 curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --uid 65532 scanner

# Copy binaries
COPY --from=builder /src/target/release/scanner-agent /usr/local/bin/scanner-agent
COPY --from=builder /src/target/bpfel-unknown-none/release/scanner-ebpf /opt/scanner/scanner-ebpf.o

# Copy SBOMs and data
COPY examples/sboms /var/lib/scanner/sboms

# Health check on metrics endpoint
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:9898/health || exit 1

# Note: Running as non-root requires CAP_BPF which is added via Kubernetes
# For local Docker testing, run with --privileged
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/scanner-agent"]
