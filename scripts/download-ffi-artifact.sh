#!/usr/bin/env bash
# Location: ./scripts/download-ffi-artifact.sh
# Copyright 2025
# SPDX-License-Identifier: Apache-2.0
#
# Consumer-facing script. Downloads a published libcpex_ffi.a
# release tarball from the CPEX GitHub Releases, verifies its
# sha256 + cosign signature, and unpacks it into a directory ready
# for cgo to link from.
#
# Intended for use in downstream Dockerfiles and CI jobs that don't
# want a Rust toolchain. Vendor this file (or fetch it pinned by tag
# from raw.githubusercontent.com) and call it before `go build`.
#
# Inputs (env or flag-equivalent CLI args):
#   CPEX_FFI_VERSION   Required. Tag of the release, e.g. v0.9.0.
#   CPEX_FFI_TARGET    Optional. Tuple name (linux-amd64-gnu,
#                      linux-arm64-gnu, linux-amd64-musl,
#                      linux-arm64-musl, darwin-arm64). Auto-detected
#                      from `uname -s` / `uname -m` + libc probe if unset.
#   CPEX_FFI_DEST      Optional. Destination directory. Defaults to
#                      ./.cpex-ffi/${CPEX_FFI_VERSION}/${CPEX_FFI_TARGET}/.
#   CPEX_FFI_REPO      Optional. GitHub owner/repo override. Defaults
#                      to contextforge-org/cpex.
#   CPEX_FFI_BASE_URL  Optional. Full URL prefix override (skips the
#                      github.com/releases/download URL construction).
#                      Used for local file:// dry-runs.
#   CPEX_FFI_SKIP_COSIGN
#                      Optional. Set to "1" to skip cosign verification.
#                      sha256 verification is never skipped. Only for
#                      air-gapped / offline environments where cosign
#                      cannot reach Sigstore. Document the risk.
#
# Output:
#   Prints the absolute destination directory to stdout on success.
#   Consumers capture it with $(bash download-ffi-artifact.sh) and
#   pass to CGO_LDFLAGS as `-L${dir} -lcpex_ffi`.
#
# Idempotency:
#   If ${dest}/VERSION exists and its first "version=..." line matches
#   CPEX_FFI_VERSION, the script exits 0 without re-downloading.

set -euo pipefail

err() { echo "download-ffi-artifact: error: $*" >&2; exit 1; }
info() { echo "download-ffi-artifact: $*" >&2; }  # stderr — stdout is the dest path

: "${CPEX_FFI_VERSION:?CPEX_FFI_VERSION is required (e.g. v0.9.0)}"
CPEX_FFI_REPO="${CPEX_FFI_REPO:-contextforge-org/cpex}"

# Detect target tuple if not provided. Inverse of the mapping in
# build-artifact.sh.
detect_tuple() {
    local os arch libc=""
    os="$(uname -s)"
    arch="$(uname -m)"
    case "$os" in
        Linux)
            # Probe for musl vs gnu. ldd --version writes to stderr;
            # musl's ldd prints "musl libc" on stderr too, gnu prints
            # "GLIBC". Fallback heuristic: presence of /lib/ld-musl-*.
            if (ldd --version 2>&1 || true) | grep -qi musl; then
                libc="musl"
            elif compgen -G "/lib/ld-musl-*" >/dev/null; then
                libc="musl"
            else
                libc="gnu"
            fi
            case "$arch" in
                x86_64)  echo "linux-amd64-${libc}" ;;
                aarch64) echo "linux-arm64-${libc}" ;;
                *) err "unsupported linux arch: $arch" ;;
            esac
            ;;
        Darwin)
            case "$arch" in
                arm64)   echo "darwin-arm64" ;;
                x86_64)  echo "darwin-amd64" ;;
                *) err "unsupported darwin arch: $arch" ;;
            esac
            ;;
        *) err "unsupported OS: $os" ;;
    esac
}

CPEX_FFI_TARGET="${CPEX_FFI_TARGET:-$(detect_tuple)}"
CPEX_FFI_DEST="${CPEX_FFI_DEST:-./.cpex-ffi/${CPEX_FFI_VERSION}/${CPEX_FFI_TARGET}}"

info "version=$CPEX_FFI_VERSION target=$CPEX_FFI_TARGET dest=$CPEX_FFI_DEST"

# Idempotency: a successful prior run leaves a VERSION file whose
# first line is "version=<tag>". If it matches, we're done.
if [[ -f "${CPEX_FFI_DEST}/VERSION" ]]; then
    existing="$(head -n1 "${CPEX_FFI_DEST}/VERSION" | sed -E 's/^version=//')"
    if [[ "$existing" == "$CPEX_FFI_VERSION" ]]; then
        info "already present at $CPEX_FFI_DEST (version=$existing); skipping download"
        cd "$CPEX_FFI_DEST" && pwd
        exit 0
    fi
    info "existing VERSION ($existing) != requested ($CPEX_FFI_VERSION); re-downloading"
fi

TARBALL_NAME="cpex-ffi-${CPEX_FFI_VERSION}-${CPEX_FFI_TARGET}.tar.gz"
BASE_URL="${CPEX_FFI_BASE_URL:-https://github.com/${CPEX_FFI_REPO}/releases/download/${CPEX_FFI_VERSION}}"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

fetch() {
    local name="$1"
    local url="${BASE_URL}/${name}"
    info "  GET $url"
    if [[ "$url" == file://* ]]; then
        cp "${url#file://}" "${WORK_DIR}/${name}" \
            || err "failed to copy from $url"
    else
        curl -fsSL --retry 3 --retry-delay 2 -o "${WORK_DIR}/${name}" "$url" \
            || err "failed to download $url"
    fi
}

info "downloading release assets"
fetch "$TARBALL_NAME"
fetch "${TARBALL_NAME}.sha256"

# sha256 verification — non-negotiable. The .sha256 file contains
# "<hex>  <filename>"; sha256sum -c reads it and checks. macOS's
# shasum -a 256 -c uses the same format.
info "verifying sha256"
if command -v sha256sum >/dev/null; then
    (cd "$WORK_DIR" && sha256sum -c "${TARBALL_NAME}.sha256")
else
    (cd "$WORK_DIR" && shasum -a 256 -c "${TARBALL_NAME}.sha256")
fi

# cosign verification — opt-out only. The certificate identity is the
# workflow path; the regex permits any tag ref so re-tagged releases
# still verify. The issuer is pinned to GitHub's OIDC issuer to
# prevent Sigstore certs from other providers from passing.
if [[ "${CPEX_FFI_SKIP_COSIGN:-0}" == "1" ]]; then
    info "WARN: skipping cosign verification (CPEX_FFI_SKIP_COSIGN=1)"
else
    command -v cosign >/dev/null || err "cosign is required for signature verification (or set CPEX_FFI_SKIP_COSIGN=1 to bypass — not recommended)"
    fetch "${TARBALL_NAME}.sig"
    fetch "${TARBALL_NAME}.crt"
    info "verifying cosign signature"
    cosign verify-blob \
        --certificate "${WORK_DIR}/${TARBALL_NAME}.crt" \
        --signature "${WORK_DIR}/${TARBALL_NAME}.sig" \
        --certificate-identity-regexp "^https://github.com/${CPEX_FFI_REPO}/\.github/workflows/release-ffi\.yaml@refs/tags/" \
        --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
        "${WORK_DIR}/${TARBALL_NAME}" \
        >/dev/null \
        || err "cosign verification failed"
fi

# Unpack into the destination, replacing any prior contents at that
# version (the idempotency check above already handled the
# already-present case).
info "unpacking into $CPEX_FFI_DEST"
mkdir -p "$CPEX_FFI_DEST"
# Clear stale files from a partial earlier run; safe because we only
# touch our own version-stamped dir.
find "$CPEX_FFI_DEST" -mindepth 1 -delete
tar xzf "${WORK_DIR}/${TARBALL_NAME}" -C "$CPEX_FFI_DEST"

# Print the absolute destination so consumer scripts can capture it.
(cd "$CPEX_FFI_DEST" && pwd)
info "done"
