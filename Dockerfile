# fetch the vendor with the builder platform to do it once only
FROM --platform=$BUILDPLATFORM rust:1-alpine AS vendor

ENV USER=root

WORKDIR /code
RUN cargo init --lib --name bluebox
COPY Cargo.toml /code/Cargo.toml
COPY Cargo.lock /code/Cargo.lock

# https://docs.docker.com/engine/reference/builder/#run---mounttypecache
RUN --mount=type=cache,target=$CARGO_HOME/git,sharing=locked \
    --mount=type=cache,target=$CARGO_HOME/registry,sharing=locked \
    mkdir -p /code/.cargo \
    && cargo vendor > /code/.cargo/config.toml

FROM rust:1-alpine AS builder

RUN apk add --no-cache curl musl-dev

ENV USER=root

WORKDIR /code

COPY Cargo.toml /code/Cargo.toml
COPY Cargo.lock /code/Cargo.lock
COPY benches /code/benches
COPY src /code/src
COPY --from=vendor /code/.cargo /code/.cargo
COPY --from=vendor /code/vendor /code/vendor

RUN cargo build --release --offline --bin bluebox

FROM alpine:3.23

ENV RUST_LOG=info
ENV CONFIG_PATH=/etc/bluebox/config.toml

COPY config.toml /etc/bluebox/config.toml
COPY --from=builder /code/target/release/bluebox /usr/bin/bluebox

EXPOSE 3000

ENTRYPOINT [ "/usr/bin/bluebox" ]
