#!/usr/bin/env bash
# Verify a local host tarball, then link the Go SDK against only its staticlib.
# Local bundles are unsigned; CI signs them after the build/verification matrix.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"
: "${TARGET:?TARGET is required}"
VERSION="${VERSION:-v$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "cpex"))')}"
[[ "$VERSION" == v* ]] || VERSION="v$VERSION"
DIST_DIR="$(cd "${DIST_DIR:-dist}" && pwd)"
GO="${GO:-go}"

case "$TARGET" in
    x86_64-unknown-linux-gnu)   TUPLE=linux-amd64-gnu ;;
    aarch64-unknown-linux-gnu)  TUPLE=linux-arm64-gnu ;;
    x86_64-unknown-linux-musl)  TUPLE=linux-amd64-musl ;;
    aarch64-unknown-linux-musl) TUPLE=linux-arm64-musl ;;
    aarch64-apple-darwin)       TUPLE=darwin-arm64 ;;
    x86_64-apple-darwin)        TUPLE=darwin-amd64 ;;
    *) echo "unsupported TARGET: $TARGET" >&2; exit 1 ;;
esac

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
ARTIFACT_DIR="$(CPEX_FFI_VERSION="$VERSION" CPEX_FFI_TARGET="$TUPLE" \
    CPEX_FFI_BASE_URL="file://$DIST_DIR" CPEX_FFI_DEST="$WORK_DIR/artifact" \
    CPEX_FFI_SKIP_COSIGN=1 bash scripts/download-ffi-artifact.sh)"
test -s "$ARTIFACT_DIR/libcpex_ffi.a"
test -s "$ARTIFACT_DIR/LICENSE"
grep -Fx "version=$VERSION" "$ARTIFACT_DIR/VERSION"
grep -Fx "rust_target=$TARGET" "$ARTIFACT_DIR/VERSION"
grep -Fx "tuple=$TUPLE" "$ARTIFACT_DIR/VERSION"
EXPECTED_ABI="$(sed -nE 's/^pub const FFI_ABI_VERSION: u32 = ([0-9]+);/\1/p' crates/cpex-ffi/src/lib.rs)"
test "$(cat "$ARTIFACT_DIR/FFI_ABI")" = "$EXPECTED_ABI"

# Cross/libc matrix legs can validate the bundle without executing host Go.
if [[ "${VERIFY_GO:-1}" == "0" ]]; then
    echo "FFI archive verified: $VERSION $TUPLE (ABI $EXPECTED_ABI); Go tests disabled"
    exit 0
fi

# A copy removes the SDK's relative target/release search path. The only
# libcpex_ffi available to this test is the archive extracted above.
cp -R go/cpex "$WORK_DIR/sdk"
cd "$WORK_DIR/sdk"
export CGO_ENABLED=1
export CGO_LDFLAGS="-L$ARTIFACT_DIR"
export GOWORK=off
"$GO" vet ./...
"$GO" test -count=1 -race ./...
echo "FFI artifact verified: $VERSION $TUPLE (ABI $EXPECTED_ABI)"
