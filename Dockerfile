# Multi-stage build for execution-aware-scanner
FROM rust:1.90-bookworm AS builder

WORKDIR /src
COPY . .

# Build without eBPF for now (eBPF requires special build setup)
RUN cargo build --release -p scanner-common --no-default-features
RUN cargo build --release -p scanner-agent --no-default-features

FROM debian:bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates libelf1 curl protobuf-compiler \
  && rm -rf /var/lib/apt/lists/* \
  && useradd --system --no-create-home --uid 65532 scanner

COPY --from=builder /src/target/release/scanner-agent /usr/local/bin/scanner-agent
COPY examples/sboms /var/lib/scanner/sboms

# Health check on metrics endpoint
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:9898/health || exit 1

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/scanner-agent"]
