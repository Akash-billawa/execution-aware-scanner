# Multi-stage build for execution-aware-scanner
# Production build: Uses nightly for eBPF, stable for agent

FROM rust:1.90-bookworm AS builder

WORKDIR /src
COPY . .

# Install nightly + rust-src (REQUIRED for build-std)
RUN rustup toolchain install nightly \
    && rustup component add rust-src --toolchain nightly

# Optimize eBPF binary size
ENV RUSTFLAGS="-C panic=abort"

# Build eBPF with nightly and build-std (PRODUCTION WAY)
RUN cargo +nightly build -p scanner-ebpf \
    --release \
    --target bpfel-unknown-none \
    -Z build-std=core

# Build agent (stable is fine for user-space)
RUN cargo build --release -p scanner-agent --no-default-features

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libelf1 curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --uid 65532 scanner

COPY --from=builder /src/target/release/scanner-agent /usr/local/bin/scanner-agent
COPY --from=builder /src/target/bpfel-unknown-none/release/scanner-ebpf /opt/scanner/scanner-ebpf.o
COPY examples/sboms /var/lib/scanner/sboms

# Health check on metrics endpoint
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:9898/health || exit 1

# Note: Running as non-root requires CAP_BPF which is added via Kubernetes
# For local Docker testing, run with --privileged
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/scanner-agent"]
