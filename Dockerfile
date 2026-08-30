# SPDX-License-Identifier: MIT

FROM rust:slim-trixie AS planner
COPY --from=nresare/cargo-chef:binonly /cargo-chef /bin/cargo-chef
WORKDIR /build
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM rust:slim-trixie AS builder
WORKDIR /build
RUN apt-get update \
    && apt-get install -y --no-install-recommends make perl curl
COPY --from=planner /bin/cargo-chef /bin/cargo-chef
COPY --from=planner /build/recipe.json recipe.json
RUN curl -LO https://github.com/nresare/namecompress/releases/download/v0.1.1/uk-0.1.1.ncmp.xz
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --locked --release

FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=builder /build/target/release/digital-membership /
COPY --from=builder /build/uk-0.1.1.ncmp.xz /
ENTRYPOINT ["/digital-membership"]
