#!/usr/bin/env bash
# Location: ./scripts/release/sign-artifact.sh
# Copyright 2025
# SPDX-License-Identifier: Apache-2.0
#
# Sign every tarball + SHA256SUMS file in DIST_DIR with cosign keyless
# (Sigstore Fulcio + Rekor). Produces a .sig and .crt next to each
# signed file so downstream consumers can verify without fetching keys.
#
# Invoked once by the sign-and-release job in release-ffi.yaml after
# all matrix-built tarballs are downloaded into dist/. Requires the
# workflow to have `id-token: write` so cosign can obtain the GitHub
# Actions OIDC token for keyless signing.
#
# Inputs (env):
#   DIST_DIR   Optional. Directory containing .tar.gz / SHA256SUMS files
#              to sign. Defaults to ./dist.
#
# Outputs:
#   For every cpex-ffi-*.tar.gz or cpex-ffi-*-SHA256SUMS in DIST_DIR:
#     <file>.sig
#     <file>.crt

set -euo pipefail

err() { echo "sign-artifact: error: $*" >&2; exit 1; }
info() { echo "sign-artifact: $*"; }

DIST_DIR="${DIST_DIR:-./dist}"
[[ -d "$DIST_DIR" ]] || err "DIST_DIR does not exist: $DIST_DIR"

command -v cosign >/dev/null || err "cosign is required (install before running)"

# Sign tarballs and the aggregate SHA256SUMS bundle (if present). The
# per-tarball .sha256 companions are not signed individually — the
# SHA256SUMS file is the signed integrity manifest. The download
# script verifies the tarball's own signature directly, so the
# per-tarball .sha256 is convenience-only.
shopt -s nullglob
TO_SIGN=( "$DIST_DIR"/cpex-ffi-*.tar.gz "$DIST_DIR"/cpex-ffi-*-SHA256SUMS )
shopt -u nullglob

[[ ${#TO_SIGN[@]} -gt 0 ]] || err "no files to sign in $DIST_DIR"

info "signing ${#TO_SIGN[@]} file(s) with cosign keyless"

for f in "${TO_SIGN[@]}"; do
    [[ -f "$f" ]] || continue
    info "  signing $(basename "$f")"
    # --yes skips the interactive "open browser?" prompt — required for
    # CI. The OIDC token is sourced automatically from the GHA env
    # (ACTIONS_ID_TOKEN_REQUEST_URL / _TOKEN). --output-* writes the
    # detached signature + cert so verifiers don't need Rekor lookups
    # for the basics, though Rekor is still queried for transparency.
    cosign sign-blob --yes \
        --output-signature "${f}.sig" \
        --output-certificate "${f}.crt" \
        "$f"
done

info "done; signed ${#TO_SIGN[@]} file(s)"
