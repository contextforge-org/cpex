#!/usr/bin/env bash
# Location: ./scripts/release/build-artifact.sh
# Copyright 2025
# SPDX-License-Identifier: Apache-2.0
#
# Build one libcpex_ffi.a for a given Rust target triple and stage it
# into a release tarball under dist/.
#
# Invoked once per matrix tuple by .github/workflows/release-ffi.yaml.
# Safe to run locally for the host tuple to validate the bundle shape.
#
# Inputs (env):
#   TARGET       Required. Rust target triple, e.g. x86_64-unknown-linux-gnu.
#   VERSION      Required in CI. Git tag, e.g. v0.9.0. Falls back to
#                `git describe --tags --dirty` for local invocations.
#   DIST_DIR     Optional. Output dir for tarball + .sha256. Defaults to ./dist.
#   USE_CROSS    Optional. If "1", build with `cross` instead of `cargo`.
#                Required for cross-compiling musl/arm targets without a
#                pre-installed sysroot.
#
# Outputs:
#   ${DIST_DIR}/cpex-ffi-${VERSION}-${TUPLE}.tar.gz
#   ${DIST_DIR}/cpex-ffi-${VERSION}-${TUPLE}.tar.gz.sha256

set -euo pipefail

err() { echo "build-artifact: error: $*" >&2; exit 1; }
info() { echo "build-artifact: $*"; }

: "${TARGET:?TARGET is required (e.g. x86_64-unknown-linux-gnu)}"
DIST_DIR="${DIST_DIR:-./dist}"
USE_CROSS="${USE_CROSS:-0}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

# Version resolution. CI sets VERSION from the tag; locally fall back
# to git-describe so dev iterations get a sensible bundle name.
if [[ -z "${VERSION:-}" ]]; then
    VERSION="$(git describe --tags --dirty --always 2>/dev/null || echo "v0.0.0-dev")"
    info "VERSION not set; using git-describe fallback: $VERSION"
fi

# Map Rust target triple → our tuple naming. This is the contract
# downstream consumers' download-ffi-artifact.sh inverts via uname.
case "$TARGET" in
    x86_64-unknown-linux-gnu)   TUPLE="linux-amd64-gnu" ;;
    aarch64-unknown-linux-gnu)  TUPLE="linux-arm64-gnu" ;;
    x86_64-unknown-linux-musl)  TUPLE="linux-amd64-musl" ;;
    aarch64-unknown-linux-musl) TUPLE="linux-arm64-musl" ;;
    aarch64-apple-darwin)       TUPLE="darwin-arm64" ;;
    x86_64-apple-darwin)        TUPLE="darwin-amd64" ;;
    *) err "unsupported TARGET: $TARGET (add a case in build-artifact.sh)" ;;
esac

# Read FFI_ABI_VERSION from the crate source. Single source of truth —
# bumps in lib.rs flow into the bundle without a separate config edit.
ABI_LINE="$(grep -E '^pub const FFI_ABI_VERSION: u32 = [0-9]+;' \
    crates/cpex-ffi/src/lib.rs || true)"
[[ -n "$ABI_LINE" ]] || err "could not find FFI_ABI_VERSION in crates/cpex-ffi/src/lib.rs"
FFI_ABI="$(echo "$ABI_LINE" | sed -E 's/.*= ([0-9]+);.*/\1/')"
[[ "$FFI_ABI" =~ ^[0-9]+$ ]] || err "extracted FFI_ABI is not an integer: $FFI_ABI"

info "TARGET=$TARGET TUPLE=$TUPLE VERSION=$VERSION FFI_ABI=$FFI_ABI"

# Build. `cross` swaps in a containerized toolchain with the right
# sysroot/glibc/musl for the target — used for arm and musl from x86_64
# linux runners. Local host builds use plain cargo.
if [[ "$USE_CROSS" == "1" ]]; then
    command -v cross >/dev/null || err "USE_CROSS=1 but cross is not installed"
    info "building with cross"
    cross build --release --locked --target "$TARGET" -p cpex-ffi
else
    info "building with cargo"
    cargo build --release --locked --target "$TARGET" -p cpex-ffi
fi

ARTIFACT_PATH="target/${TARGET}/release/libcpex_ffi.a"
[[ -f "$ARTIFACT_PATH" ]] || err "expected artifact missing: $ARTIFACT_PATH"

# Stage into a temp dir, tar from there so the archive has no leading
# directory and tools like the download script can `tar xzf` flat into
# any destination.
STAGE_DIR="$(mktemp -d)"
trap 'rm -rf "$STAGE_DIR"' EXIT

cp "$ARTIFACT_PATH" "$STAGE_DIR/libcpex_ffi.a"
cp LICENSE "$STAGE_DIR/LICENSE"

GIT_SHA="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
cat > "$STAGE_DIR/VERSION" <<EOF
version=$VERSION
git_sha=$GIT_SHA
build_date=$BUILD_DATE
tuple=$TUPLE
rust_target=$TARGET
EOF
echo "$FFI_ABI" > "$STAGE_DIR/FFI_ABI"

mkdir -p "$DIST_DIR"
TARBALL_NAME="cpex-ffi-${VERSION}-${TUPLE}.tar.gz"
TARBALL_PATH="${DIST_DIR}/${TARBALL_NAME}"

# tar -C ${STAGE_DIR} . produces a flat archive (no leading dir).
# --owner / --group / --mtime would help reproducibility but BSD/GNU
# tar flag divergence makes that finicky; --locked + cargo gives us
# the most important reproducibility guarantee.
tar -czf "$TARBALL_PATH" -C "$STAGE_DIR" .

# sha256 companion. Recompute on the consumer side as the integrity gate.
# Use coreutils sha256sum if present (linux), shasum -a 256 otherwise (macOS).
if command -v sha256sum >/dev/null; then
    (cd "$DIST_DIR" && sha256sum "$TARBALL_NAME" > "${TARBALL_NAME}.sha256")
else
    (cd "$DIST_DIR" && shasum -a 256 "$TARBALL_NAME" > "${TARBALL_NAME}.sha256")
fi

info "wrote $TARBALL_PATH"
info "wrote ${TARBALL_PATH}.sha256"
