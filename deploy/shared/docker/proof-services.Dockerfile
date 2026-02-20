FROM golang:1.22-bookworm AS go-builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/proof-requestor ./cmd/proof-requestor
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/proof-funder ./cmd/proof-funder

FROM rust:1.91-bookworm AS boundless-builder

ARG BOUNDLESS_CLI_VERSION=1.2.0
ARG BOUNDLESS_REF_TAG=v1.2.1
ARG BOUNDLESS_RELEASE_BRANCH=release-1.2
ENV CARGO_BUILD_JOBS=1
ENV CARGO_PROFILE_RELEASE_LTO=false
ENV CARGO_PROFILE_RELEASE_DEBUG=0
ENV CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16
ENV CARGO_PROFILE_RELEASE_STRIP=symbols
ENV RUSTFLAGS="-C debuginfo=0"

RUN apt-get update -y && \
  apt-get install -y --no-install-recommends ca-certificates git pkg-config libssl-dev perl && \
  rm -rf /var/lib/apt/lists/*

RUN set -eux; \
  if cargo install boundless-cli --version "${BOUNDLESS_CLI_VERSION}" --locked --root /opt/boundless; then \
    exit 0; \
  fi; \
  if cargo install boundless-cli --git https://github.com/boundless-xyz/boundless --tag "${BOUNDLESS_REF_TAG}" --locked --root /opt/boundless; then \
    exit 0; \
  fi; \
  git clone --depth 1 --branch "${BOUNDLESS_RELEASE_BRANCH}" https://github.com/boundless-xyz/boundless /tmp/boundless; \
  perl -0pi -e 's/\{combined_sol_contents\}/\{combined_sol_contents\}\n            enum __BOUNDLESS_DUMMY__ {{ __BOUNDLESS_DUMMY_VALUE__ }}/s' /tmp/boundless/crates/boundless-market/build.rs; \
  cargo install --path /tmp/boundless/crates/boundless-cli --locked --root /opt/boundless

FROM debian:bookworm-slim

RUN apt-get update -y && \
  apt-get install -y --no-install-recommends ca-certificates libgcc-s1 libssl3 libstdc++6 && \
  rm -rf /var/lib/apt/lists/*

COPY --from=go-builder /out/proof-requestor /usr/local/bin/proof-requestor
COPY --from=go-builder /out/proof-funder /usr/local/bin/proof-funder
COPY --from=boundless-builder /opt/boundless/bin/boundless /usr/local/bin/boundless

RUN chmod +x /usr/local/bin/proof-requestor /usr/local/bin/proof-funder /usr/local/bin/boundless

CMD ["/usr/local/bin/proof-requestor", "--help"]
