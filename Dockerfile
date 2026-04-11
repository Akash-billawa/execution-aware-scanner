FROM rust:1.86-bookworm AS builder

RUN rustup target add bpfel-unknown-none && cargo install bpf-linker
WORKDIR /src
COPY . .

RUN cargo build --release -p scanner-common
RUN cargo build --release -p scanner-agent

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libelf1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --uid 65532 scanner

COPY --from=builder /src/target/release/scanner-agent /usr/local/bin/scanner-agent
COPY examples/sboms /var/lib/scanner/sboms

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/scanner-agent"]
