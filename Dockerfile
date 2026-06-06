FROM rust:1.75-bookworm AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/cy-tls /usr/local/bin/cy-tls
ENTRYPOINT ["/usr/local/bin/cy-tls"]
CMD ["--help"]
