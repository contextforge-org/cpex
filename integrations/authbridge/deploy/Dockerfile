# Location: ./integrations/authbridge/deploy/Dockerfile
# Copyright 2025
# SPDX-License-Identifier: Apache-2.0
# Authors: Teryl Taylor
#
# cpex-authbridge-envoy — drop-in replacement for upstream authbridge-envoy
# that ships the cpex-runtime plugin (with bundled Rust CPEX sub-plugins).
#
# Build context: the contextforge-plugins-framework repo root, because:
#   - Rust workspace lives at <root>/Cargo.toml
#   - cpex-runtime go.mod replace-directs at ../../../go/cpex and
#     ../../../kagenti-extensions/authbridge/authlib (both need to be in
#     the build context for the Go stage to resolve them)
#
# Build:
#   docker build -t cpex-authbridge-envoy:demo \
#     -f integrations/authbridge/deploy/Dockerfile .
#
# Load into Kind:
#   kind load docker-image cpex-authbridge-envoy:demo --name kagenti

# ============================================================================
# Stage 1 — Rust FFI staticlib.
# Debian-based image gives us glibc-compatible .a that matches the runtime
# image's libc (UBI9-micro is glibc). Building against musl in this stage
# and linking against glibc in stage 2 would produce link-time symbol
# mismatches.
# ============================================================================
FROM rust:1.85-bookworm AS rust-builder

WORKDIR /src

# Copy the Cargo workspace. We need every workspace member listed in
# Cargo.toml's `members` array — Cargo refuses to build if any are missing.
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
COPY examples/go-demo/ffi/ ./examples/go-demo/ffi/
COPY integrations/authbridge/ffi/ ./integrations/authbridge/ffi/

# Build both FFI staticlibs:
#   - libkagenti_cpex_ffi.a — registers our scope-tool-gate + llm-pii-redactor
#     (linked by cpex-runtime/plugin.go via cgo)
#   - libcpex_ffi.a         — core FFI symbols (linked by go/cpex/ffi.go via cgo)
# `--release` strips debug info; resulting .a files are ~10 MB each.
RUN cargo build --release -p kagenti-cpex-ffi -p cpex-ffi


# ============================================================================
# Stage 2 — Go binary with cgo linking to the Rust .a.
# CGO_ENABLED=1 because our cpex-runtime package binds the FFI symbols.
# Debian-based golang image matches the libc the .a was built against.
# ============================================================================
FROM golang:1.25-bookworm AS go-builder

# Install build essentials for cgo (gcc + libc-dev).
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Bring in everything our Go module's `replace` directives reference,
# plus our own Go code. Paths mirror the repo layout.
COPY go/cpex/                                              ./go/cpex/
COPY kagenti-extensions/authbridge/authlib/                ./kagenti-extensions/authbridge/authlib/
COPY integrations/authbridge/cpex-runtime/                 ./integrations/authbridge/cpex-runtime/

# Pull the Rust .a out of stage 1 into the location cpex-runtime's cgo
# block expects (workspace target/release/ relative to the cpex-runtime
# source dir is ../../../target/release/).
RUN mkdir -p target/release
COPY --from=rust-builder /src/target/release/libkagenti_cpex_ffi.a target/release/
COPY --from=rust-builder /src/target/release/libcpex_ffi.a        target/release/

# Build the binary. CGO_LDFLAGS gets the workspace-relative path; the
# linker resolves the same .a at link time.
WORKDIR /src/integrations/authbridge/cpex-runtime/cmd/cpex-authbridge-envoy

ENV GOWORK=off
ENV CGO_ENABLED=1
ENV GOOS=linux

# -ldflags="-s -w" drops symbols + DWARF (matches upstream's flags).
RUN go mod download && \
    go build -ldflags="-s -w" -o /cpex-authbridge-envoy .


# ============================================================================
# Stage 3 — Runtime image. Base on upstream's authbridge-envoy image so we
# inherit Envoy, spiffe-helper, entrypoint.sh, and proper user/permissions.
# We only overwrite the binary at /usr/local/bin/authbridge-envoy.
# ============================================================================
FROM ghcr.io/kagenti/kagenti-extensions/authbridge-envoy:v0.5.0-rc.2

# Drop our binary into the same path as upstream's. The entrypoint script
# already invokes /usr/local/bin/authbridge by name (the image is named
# authbridge-envoy but the binary itself is just `authbridge`).
COPY --from=go-builder --chmod=755 /cpex-authbridge-envoy /usr/local/bin/authbridge

# Same user, same ports, same entrypoint as upstream. Drop-in replacement.
