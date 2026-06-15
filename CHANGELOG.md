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
- Size-first `[profile.release]`: `opt-level = "z"`, `lto = true`,
  `codegen-units = 1`, `strip = true`. `libcpex_ffi.a` is linked statically
  into host binaries, so this flows straight into their image size — a
  representative statically-linked consumer shrank ~21%. `panic = "abort"`
  is intentionally not set (the FFI relies on `catch_unwind` at its
  `#[no_mangle]` boundary). No API or ABI change.
- Trimmed the workspace `tokio` feature floor from `["full"]` to
  `["rt", "rt-multi-thread", "sync", "time", "macros"]` — the union of what
  the crates actually use; `reqwest`/`hyper` still pull `net`/`io` where they
  need them via feature unification. Drops the unused `fs`/`process`/`signal`
  surface (and the `signal-hook-registry` dependency).

### Fixed

- Cedar evaluation no longer fails with "recursion limit reached" on hosts
  that give the FFI a small thread stack (notably musl, whose default is
  128 KiB). `cedar-policy` aborts when `stacker::remaining_stack()` is below
  its 100 KiB floor; the cedar dispatch in `apl-pdp-cedar-direct` is now
  wrapped in `stacker::maybe_grow`, so it runs on an adequately sized stack
  regardless of the host (a no-op when there is already headroom, e.g.
  glibc's 8 MiB threads). Regression test exercises a real evaluation on a
  128 KiB stack.

## [0.1.0] - 2026-05-05

### Added

- Initial release

[Unreleased]: https://github.com/contextforge-org/cpex/compare/0.1.1...HEAD
[0.1.1]: https://github.com/contextforge-org/cpex/compare/0.1.0...0.1.1
[0.1.0]: https://github.com/contextforge-org/cpex/releases/tag/0.1.0