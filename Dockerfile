# SPDX-License-Identifier: MIT

FROM rust:slim-trixie AS planner
COPY --from=nresare/cargo-chef:binonly /cargo-chef /bin/cargo-chef
WORKDIR /build
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM rust:slim-trixie AS builder
WORKDIR /build
RUN apt-get update \
    && apt-get install -y --no-install-recommends make perl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=planner /bin/cargo-chef /bin/cargo-chef
COPY --from=planner /build/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --locked --release

FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=builder /build/target/release/digital-membership /
ENTRYPOINT ["/digital-membership"]
