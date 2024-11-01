FROM rust:1.78 as build

WORKDIR /opt/gateway/rencrypt/

RUN apt-get update && apt-get install -y protobuf-compiler

COPY Cargo.toml Cargo.lock .
COPY compute compute
COPY recrypt recrypt

RUN mkdir -p target/release && \
    cargo build --release

# Use debian slim instead of alpine for glibc compatibility
FROM debian:bookworm-slim as final

# Copy the binary
COPY --from=build /opt/gateway/rencrypt/target/release/server /usr/bin/server

CMD ["/usr/bin/server"]