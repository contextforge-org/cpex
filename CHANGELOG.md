# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/).

> **Types of changes:**
>
> - **Added**: for new features.
> - **Changed**: for changes in existing functionality.
> - **Deprecated**: for soon-to-be removed features.
> - **Removed**: for now removed features.
> - **Fixed**: for any bug fixes.
> - **Security**: in case of vulnerabilities.

## [Unreleased]

### Added

- Publish `libcpex_ffi.a` as signed GitHub Release artifacts on
  every semver tag push (`linux-amd64-gnu`, `linux-arm64-gnu`,
  `linux-amd64-musl`, `linux-arm64-musl`, `darwin-arm64`). Cosign
  keyless signatures + SHA256 checksums; see
  `crates/cpex-ffi/RELEASE.md` for the schema and the verify-and-
  consume recipe.
- FFI ABI versioning: `cpex_ffi_abi_version()` extern C accessor
  exposes `FFI_ABI_VERSION` (currently `1`). The Go binding checks
  this in `init()` and panics on mismatch. Other language bindings
  must replicate the check.

## [0.1.0] - 2026-05-05

### Added

- Initial release

[Unreleased]: https://github.com/contextforge-org/contextforge-plugins-framework/compare/0.1.0...HEAD
[0.1.0]: https://github.com/contextforge-org/contextforge-plugins-framework/releases/tag/0.1.0