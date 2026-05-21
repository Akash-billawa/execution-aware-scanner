# Multi-stage build for execution-aware-scanner
# Production build with eBPF support (REQUIRED)
# Supports linux/amd64 and linux/arm64 via docker buildx

# ── Stage 1: Build ───────────────────────────────────────────────────────────

# Use BUILDPLATFORM for the builder (native compilation speed)
FROM --platform=$BUILDPLATFORM rust:1.88-bookworm AS builder

ARG TARGETPLATFORM
ARG TARGETARCH

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

# Install cross-compilation toolchain for ARM64 when building on amd64
RUN if [ "$TARGETARCH" = "arm64" ]; then \
        dpkg --add-architecture arm64 && \
        apt-get update && \
        apt-get install -y --no-install-recommends \
            gcc-aarch64-linux-gnu \
            libc6-dev-arm64-cross \
            libelf-dev:arm64 \
            zlib1g-dev:arm64 && \
        rm -rf /var/lib/apt/lists/* && \
        rustup target add aarch64-unknown-linux-gnu; \
    fi

# Build eBPF programs
# bpfel-unknown-none is architecture-neutral (BPF bytecode is portable)
RUN cargo +nightly build \
    --manifest-path scanner-ebpf/Cargo.toml \
    --release \
    --target bpfel-unknown-none \
    -Z build-std=core

# Verify eBPF object was created
RUN ls -la /src/target/bpfel-unknown-none/release/ && \
    test -f /src/target/bpfel-unknown-none/release/libscanner_ebpf.so

# Build the agent with eBPF support
# Cross-compile for ARM64 when TARGETARCH is arm64
RUN if [ "$TARGETARCH" = "arm64" ]; then \
        cargo build --release -p scanner-agent --features ebpf \
            --target aarch64-unknown-linux-gnu && \
        BINARY_PATH=/src/target/aarch64-unknown-linux-gnu/release/scanner-agent; \
    else \
        cargo build --release -p scanner-agent --features ebpf && \
        BINARY_PATH=/src/target/release/scanner-agent; \
    fi && \
    cp "$BINARY_PATH" /src/scanner-agent-binary

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────

FROM --platform=$TARGETPLATFORM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libelf1 curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --uid 65532 scanner

# Copy agent binary
COPY --from=builder /src/scanner-agent-binary /usr/local/bin/scanner-agent

# Copy eBPF object (REQUIRED)
COPY --from=builder /src/target/bpfel-unknown-none/release/libscanner_ebpf.so /opt/scanner/scanner-ebpf.so

# Copy SBOMs and data
COPY examples/sboms /var/lib/scanner/sboms

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:9898/health || exit 1

# Note: The Kubernetes manifest must grant capabilities (CAP_BPF, CAP_PERFMON, CAP_NET_ADMIN)
# or run in privileged mode to allow eBPF attachment despite running as non-root.
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/scanner-agent"]
