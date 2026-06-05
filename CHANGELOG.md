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

- APL (Attribute Policy Language) governance is now bundled into
  `libcpex_ffi.a`. New `cpex_apl_install` extern C entry point registers
  the standard APL plugin/PDP factories (`validator/pii-scan`,
  `audit/logger`, `identity/jwt`, `delegator/oauth`, `cedar-direct`) and
  installs the APL config visitor on a manager. Call it after
  `cpex_manager_new_default` and before `cpex_load_config`. Go hosts use
  `PluginManager.EnableAPL()`. The optional `cedarling` cargo feature adds
  the Cedarling-backed identity + PDP seams (off by default; the released
  `.a` stays lean).
- Publish `libcpex_ffi.a` as signed GitHub Release artifacts on
  every semver tag push (`linux-amd64-gnu`, `linux-arm64-gnu`,
  `linux-amd64-musl`, `linux-arm64-musl`, `darwin-arm64`). Cosign
  keyless signatures + SHA256 checksums; see
  `crates/cpex-ffi/RELEASE.md` for the schema and the verify-and-
  consume recipe.
- FFI ABI versioning: `cpex_ffi_abi_version()` extern C accessor
  exposes `FFI_ABI_VERSION`. The Go binding checks this in `init()`
  and panics on mismatch. Other language bindings must replicate the
  check.

### Changed

- FFI `FFI_ABI_VERSION` bumped `1 → 2`: added the `cpex_apl_install`
  extern C function and changed `cpex_load_config` to run registered
  config visitors (it now calls `load_config_yaml` internally so `apl:`
  blocks are walked). The Go binding's `expectedFFIABIVersion` is bumped
  in lockstep.

## [0.1.1] - 2026-06-04

### Added

- Plugin bundling, catalog, installation and versioning ([#31](https://github.com/contextforge-org/cpex/pull/31))

### Fixed

- Implement `__eq__` and `__ne__` for CopyOnWriteDict ([#55](https://github.com/contextforge-org/cpex/pull/55))
- Respect `PLUGINS_LOG_LEVEL` environment variable in all runtime.py files ([#48](https://github.com/contextforge-org/cpex/pull/48))

## [0.1.0] - 2026-05-05

### Added

- Initial release

[Unreleased]: https://github.com/contextforge-org/cpex/compare/0.1.1...HEAD
[0.1.1]: https://github.com/contextforge-org/cpex/compare/0.1.0...0.1.1
[0.1.0]: https://github.com/contextforge-org/cpex/releases/tag/0.1.0