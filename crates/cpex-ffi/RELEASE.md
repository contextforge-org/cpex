# `libcpex_ffi.a` — Release Artifacts

CPEX publishes pre-built `libcpex_ffi.a` static libraries as signed
GitHub Release artifacts. Downstream consumers (Go bindings,
language bindings, anyone embedding CPEX) link against these
without needing a Rust toolchain.

This document covers what is published, how to consume and verify
an artifact, and the FFI ABI policy that makes the contract durable.

## What is published

Every CPEX release tagged `vMAJOR.MINOR.PATCH` (or
`vMAJOR.MINOR.PATCH-<prerelease>`) attaches one tarball per
supported target tuple to the GitHub Release, along with checksums
and signatures.

### Naming and layout

For release `vX.Y.Z` and tuple `<os>-<arch>[-<libc>]`:

```
cpex-ffi-vX.Y.Z-<os>-<arch>[-<libc>].tar.gz
cpex-ffi-vX.Y.Z-<os>-<arch>[-<libc>].tar.gz.sha256
cpex-ffi-vX.Y.Z-<os>-<arch>[-<libc>].tar.gz.sig
cpex-ffi-vX.Y.Z-<os>-<arch>[-<libc>].tar.gz.crt
```

Plus one aggregate integrity manifest for the whole release:

```
cpex-ffi-vX.Y.Z-SHA256SUMS
cpex-ffi-vX.Y.Z-SHA256SUMS.sig
cpex-ffi-vX.Y.Z-SHA256SUMS.crt
```

Each tarball, when extracted, contains:

| File              | Contents                                          |
|-------------------|---------------------------------------------------|
| `libcpex_ffi.a`   | Static library — the actual deliverable.          |
| `VERSION`         | Plain text. Keys: `version`, `git_sha`, `build_date`, `tuple`, `rust_target`. |
| `FFI_ABI`         | Single integer line — FFI ABI version. See policy below. |
| `LICENSE`         | Copy of CPEX's Apache-2.0 license.                |

Tarballs are flat (no leading directory). `tar xzf <tarball> -C <dest>` drops the four files directly into `<dest>`.

### Target matrix

| Tuple                | Rust target triple              | Runner          |
|----------------------|---------------------------------|-----------------|
| `linux-amd64-gnu`    | `x86_64-unknown-linux-gnu`      | `ubuntu-latest` |
| `linux-arm64-gnu`    | `aarch64-unknown-linux-gnu`     | `ubuntu-22.04-arm` |
| `linux-amd64-musl`   | `x86_64-unknown-linux-musl`     | `ubuntu-latest` |
| `linux-arm64-musl`   | `aarch64-unknown-linux-musl`    | `ubuntu-22.04-arm` |
| `darwin-arm64`       | `aarch64-apple-darwin`          | `macos-14`      |

`darwin-amd64` and Windows targets are not built in v1. Open an
issue if you need one — adding to the matrix is mechanical.

### Signing

Tarballs and the aggregate `SHA256SUMS` are signed with
[cosign](https://github.com/sigstore/cosign) **keyless** via
Sigstore (Fulcio for cert issuance, Rekor for transparency). There
is no long-lived signing key — each release produces short-lived
certs bound to the GitHub Actions OIDC identity of the
`release-ffi.yaml` workflow on the canonical repo. Verification
checks both the cert subject and the OIDC issuer.

## How to consume

### One-shot: the helper script

The repo ships `scripts/download-ffi-artifact.sh` — vendor it
into your build (or fetch via `raw.githubusercontent.com` pinned to
a tag) and call it before `go build` / `cargo build` / etc.

```sh
export CPEX_FFI_VERSION=v0.9.0
ARTIFACT_DIR=$(bash scripts/download-ffi-artifact.sh)
export CGO_LDFLAGS="-L${ARTIFACT_DIR} -lcpex_ffi"
go build ./...
```

What it does:

1. Auto-detects your tuple from `uname -s` / `uname -m` (override
   with `CPEX_FFI_TARGET`).
2. Downloads the tarball, `.sha256`, `.sig`, `.crt`.
3. Verifies the SHA256 — non-skippable.
4. Verifies the cosign signature against the canonical workflow
   identity and OIDC issuer — skippable via
   `CPEX_FFI_SKIP_COSIGN=1` only for air-gapped environments.
5. Unpacks to `${CPEX_FFI_DEST}` (default
   `./.cpex-ffi/${CPEX_FFI_VERSION}/${CPEX_FFI_TARGET}/`).
6. Prints the absolute destination to stdout.

Subsequent runs against the same version + dest are no-ops.

### Manual: cosign + tar

If you want to do it by hand:

```sh
VER=v0.9.0
TUPLE=linux-amd64-gnu
BASE="https://github.com/contextforge-org/cpex/releases/download/${VER}"
NAME="cpex-ffi-${VER}-${TUPLE}.tar.gz"

curl -fsSLO "${BASE}/${NAME}"
curl -fsSLO "${BASE}/${NAME}.sha256"
curl -fsSLO "${BASE}/${NAME}.sig"
curl -fsSLO "${BASE}/${NAME}.crt"

sha256sum -c "${NAME}.sha256"

cosign verify-blob \
    --certificate "${NAME}.crt" \
    --signature   "${NAME}.sig" \
    --certificate-identity-regexp "^https://github.com/contextforge-org/cpex/\.github/workflows/release-ffi\.yaml@refs/tags/" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "${NAME}"

mkdir -p ./libcpex
tar xzf "${NAME}" -C ./libcpex
```

After this, `./libcpex/libcpex_ffi.a` is your link target.

### Using with the in-tree Go binding

`go/cpex/ffi.go` links via `#cgo LDFLAGS: -L${SRCDIR}/../../target/release -lcpex_ffi`
relative to the cpex repo layout. For downstream Go consumers that
pull `go/cpex` via `go get`, set `CGO_LDFLAGS` to point at the
unpacked artifact directory and the cgo `-L` from `LDFLAGS` will be
augmented by the env var:

```sh
ARTIFACT_DIR=$(CPEX_FFI_VERSION=v0.9.0 bash scripts/download-ffi-artifact.sh)
CGO_LDFLAGS="-L${ARTIFACT_DIR}" go build ./...
```

## FFI ABI policy

The `FFI_ABI` integer in each bundle declares the wire-level C
contract version that `libcpex_ffi.a` exposes. Language bindings
must record the ABI version they were generated against and check
it at runtime — the Go binding does this in `go/cpex/abi.go`'s
`init()` and panics on mismatch. Every other binding **must do the
same**; silent acceptance of an ABI mismatch produces undefined
behavior on every subsequent FFI call.

### What counts as an ABI break

A bump of `FFI_ABI_VERSION` is **required** for any of:

- Adding, removing, or renaming an `extern "C"` function.
- Changing argument count, argument type, or return type of an
  existing extern function.
- Changing the layout of a struct that crosses the boundary.
- Changing the ownership or lifetime contract of a pointer
  returned from / accepted by an extern function.
- Changing the semantics of a return code for a previously-success
  case (e.g. a function that used to return `RC_OK` now returns a
  new code on the same input).

A bump is **not** required for:

- Adding a new `RC_*` code at the end of the existing range.
  Existing wire codes are stable; consumers should treat unknown
  codes as generic failure.
- Internal Rust refactors that leave the C surface unchanged.
- Documentation / comment changes.

### Process

1. The Rust author bumps `FFI_ABI_VERSION` in
   `crates/cpex-ffi/src/lib.rs` in the same PR as the breaking
   change.
2. All in-tree language bindings (today: `go/cpex/abi.go`'s
   `expectedFFIABIVersion`) are bumped to match in the same PR.
3. `CHANGELOG.md` records the bump under **Changed** with the
   from→to integers and a one-line description of what moved.
4. The release tag that ships the breaking change is a new
   `MINOR` (or `MAJOR`) — never a `PATCH`.

## Versioning

The artifact tag matches the CPEX repo tag exactly. There is no
separate "FFI version" — `vX.Y.Z` of CPEX produces `cpex-ffi-vX.Y.Z-*`
artifacts. Prereleases (`vX.Y.Z-rc1`, `vX.Y.Z-beta.1`,
`vX.Y.Z-ffi.test.1`, etc.) publish too and land as GitHub Releases
flagged "prerelease" — they don't surface as "latest".

The FFI ABI version is independent: a release that doesn't touch
the C surface keeps the same `FFI_ABI`, even across minor / major
CPEX bumps.

## Reproducibility caveats

Builds use `cargo build --release --locked`, which pins the
`Cargo.lock` resolution. Beyond that, no guarantees:

- Timestamps in the built `.a` differ between runs.
- Compiler / OS image patch versions on the runner can shift.
- macOS code-signing metadata varies per build.

Consumers care about `FFI_ABI` (contract stability) and SHA + cosign
(integrity + authenticity), not bit-identical reproducibility.
Adding `cargo-zigbuild` or a sysroot-pinning toolchain to harden
reproducibility is a v2 ask.

## When something is wrong

| Symptom                          | Likely cause / fix                                                         |
|----------------------------------|----------------------------------------------------------------------------|
| `cosign verify-blob` fails       | Wrong `--certificate-identity-regexp` (must point at the canonical repo's `release-ffi.yaml`), or the artifact came from a fork rather than the canonical workflow. |
| sha256 mismatch                  | The download was corrupted or the upstream release was rewritten. Open an issue. |
| Go `init` panics with ABI mismatch | The linked `.a` and the Go binding were generated against different ABI versions. Pin both to the same CPEX tag. |
| Unsupported tuple                | Your platform isn't in the matrix. Either add it (PR welcome) or build the `.a` locally from source. |
| `tar` complains about absolute paths | Bundles are flat (no leading dir). Extract with `tar xzf -C <dest>`, not into the current dir. |
