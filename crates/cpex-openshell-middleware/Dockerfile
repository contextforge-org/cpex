# Location: ./crates/cpex-openshell-middleware/Dockerfile
# Copyright 2026
# SPDX-License-Identifier: Apache-2.0
#
# Container image for the CPEX OpenShell middleware service.
# CPEX builds with its own toolchain here and never links into OpenShell — the
# whole point of running as a remote, out-of-process middleware. Build from the
# cpex repo root:
#
#   docker build -f crates/cpex-openshell-middleware/Dockerfile \
#     -t cpex/openshell-middleware:dev .
#
# Run (bundle baked in; override with -e CPEX_BUNDLE_PATH / a mount):
#
#   docker run --rm -p 50051:50051 cpex/openshell-middleware:dev

FROM rust:1.96-slim AS build
WORKDIR /src
# protoc for the vendored contract is supplied by the protoc-bin-vendored crate,
# so no system protoc is needed. A C toolchain is needed for ring/aws-lc-rs.
RUN apt-get update && apt-get install -y --no-install-recommends \
      pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY . .
RUN cargo build --release -p cpex-openshell-middleware

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/cpex-openshell-middleware /usr/local/bin/cpex-openshell-middleware
# Bake the CEL example bundle in by default (DEMO ONLY: dev issuer over plaintext HTTP).
COPY crates/cpex-openshell-middleware/bundle/examples/bundle-cel.yaml /etc/cpex/bundle.yaml
ENV CPEX_BUNDLE_PATH=/etc/cpex/bundle.yaml
EXPOSE 50051
ENTRYPOINT ["/usr/local/bin/cpex-openshell-middleware", "--listen", "0.0.0.0:50051"]
