FROM golang:1.22-bookworm AS go-builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/proof-requestor ./cmd/proof-requestor
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/proof-funder ./cmd/proof-funder

FROM rust:1.91-bookworm AS sp1-builder

ENV CARGO_BUILD_JOBS=1
ENV CARGO_PROFILE_RELEASE_LTO=false
ENV CARGO_PROFILE_RELEASE_DEBUG=0
ENV CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16
ENV CARGO_PROFILE_RELEASE_STRIP=symbols
ENV RUSTFLAGS="-C debuginfo=0"

RUN apt-get update -y && \
  apt-get install -y --no-install-recommends ca-certificates clang libclang-dev protobuf-compiler libprotobuf-dev pkg-config libssl-dev && \
  rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY zk /src/zk
RUN cargo build --release --manifest-path /src/zk/sp1_prover_adapter/cli/Cargo.toml && \
  mkdir -p /out && \
  cp /src/zk/target/release/sp1-prover-adapter /out/sp1-prover-adapter

FROM debian:bookworm-slim

RUN apt-get update -y && \
  apt-get install -y --no-install-recommends ca-certificates libgcc-s1 libssl3 libstdc++6 && \
  rm -rf /var/lib/apt/lists/*

COPY --from=go-builder /out/proof-requestor /usr/local/bin/proof-requestor
COPY --from=go-builder /out/proof-funder /usr/local/bin/proof-funder
COPY --from=sp1-builder /out/sp1-prover-adapter /usr/local/bin/sp1-prover-adapter

RUN ln -sf /usr/local/bin/sp1-prover-adapter /usr/local/bin/boundless && \
  chmod +x /usr/local/bin/proof-requestor /usr/local/bin/proof-funder /usr/local/bin/sp1-prover-adapter /usr/local/bin/boundless

CMD ["/usr/local/bin/proof-requestor", "--help"]
