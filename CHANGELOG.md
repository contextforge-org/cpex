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

- APL (Attribute Policy Language) governance is now bundled into `libcpex_ffi.a`. New `cpex_apl_install` extern C entry point registers the standard APL plugin/PDP factories (`validator/pii-scan`, `audit/logger`, `identity/jwt`, `delegator/oauth`, `cedar-direct`) and installs the APL config visitor on a manager. Call it after `cpex_manager_new_default` and before `cpex_load_config`. Go hosts use `PluginManager.EnableAPL()`. (#60)
- Publish `libcpex_ffi.a` as signed GitHub Release artifacts on every semver tag push (`linux-amd64-gnu`, `linux-arm64-gnu`, `linux-amd64-musl`, `linux-arm64-musl`, `darwin-arm64`). Cosign keyless signatures + SHA256 checksums; see `crates/cpex-ffi/RELEASE.md` for the schema and the verify-and-consume recipe. (#60)
- FFI ABI versioning: `cpex_ffi_abi_version()` extern C accessor exposes `FFI_ABI_VERSION`. The Go binding checks this in `init()` and panics on mismatch. Other language bindings must replicate the check. (#60)
- CEL (Common Expression Language) policy decision backend. A new `apl-pdp-cel` crate registers `kind: cel`, letting authors write inline boolean predicates (`cel: { expr: ... }`) over the common attribute vocabulary (`subject.id`, `delegation.depth`, `session.labels`, ...), evaluated through the existing `PdpResolver` seam alongside Cedar, OPA, and AuthZen. Expressions compile once and cache by source; compile errors, undeclared-variable references, and non-boolean results fail closed (deny), overridable with `on_error: allow`. No change to APL evaluation semantics. (#68)
- APL authoring ergonomics (backwards-compatible). The `apl:` wrapper is now optional — recognized APL terms (`policy`, `post_policy`, `args`, `result`, `pdp`, `session_store`) written directly on a section are honored, with the explicit `apl:` form still taking precedence. `run(name)` is accepted as an alias for `plugin(name)` in both policy steps and field pipelines. Unconditional `deny('reason')` / `deny('reason', 'code')` now parses as a bare action (e.g. in `on_deny:` lists), so a reason/code can be attached without a conditional. (#71)
- Valkey-backed `SessionStore` for cross-node and cross-restart session label propagation. Selectable via a `kind: valkey` block under `global.apl.session_store` (factory pattern mirroring `pdp`), shipped in the `apl-session-valkey` crate and wired into `cpex-ffi` behind the optional `valkey` cargo feature (the default build and `.a` artifact are unaffected). Labels live in a Redis SET so appends are an atomic server-side union (`SADD`); the store is fail-closed (a load/append error denies the request rather than under-labeling), serves primary-only reads, supports an optional sliding TTL, requires TLS for non-localhost endpoints, and SHA-256s session ids out of the keyspace. When no block is configured the default remains the in-process memory store. See the operator runbook at `docs/operations/valkey-session-store.md`. (#74)
- `cpex` host facade crate: a single dependency that re-exports the host runtime (`PluginManager`, `AplOptions`, `register_apl`) and the bundled plugin factories, each behind a cargo feature (`jwt`, `oauth`, `pii`, `audit`, `cedar`, `cel`, `valkey`). Hosts depend on `cpex` and enable the plugins they want instead of pinning `apl-cmf` / `apl-cpex` / `apl-pdp-*` / `apl-session-*` individually. `install_builtins(&mgr)` registers every enabled factory and installs the APL config visitor in one call; `register_builtin_plugins`, `builtin_pdp_factories`, and `builtin_session_store_factories` expose the pieces for hosts that assemble `AplOptions` themselves. (#77)
- `cpex-builtins` aggregator crate: the bundled extension set (plugins, PDPs, session stores) behind a 1:1 cargo-feature map, with a declarative `register_builtins!` macro that expands to explicit, `#[cfg]`-gated `register_factory` calls (kept explicit rather than `inventory`/`linkme` so factory symbols survive the linker GC inside `libcpex_ffi.a`). `register_builtins`, `builtin_pdps`, `builtin_session_store_factories`, and `install_builtins` are the single source of truth that both the `cpex` facade and `cpex-ffi` now delegate to. (#72)

### Changed

- The `cpex` facade is now **engine-only by default**: `cpex = "0.2"` compiles no builtin plugins. The bundled set is opt-in via the new `builtins` feature (the common in-process set) or `full` (everything, incl. Valkey), with the granular plugin features (`jwt`, `oauth`, `pii`, `audit`, `cedar`, `cel`, `valkey`) preserved as passthroughs. The registration helpers and concrete factory types are re-exported from `cpex-builtins` and appear only when a builtins feature is enabled. `cpex-ffi` keeps its prior bundled set (four hook plugins + `cedar-direct`) by selecting that exact `cpex-builtins` feature subset. No FFI ABI change. (#72)
- `PluginFactoryRegistry::register` now logs a `tracing::warn!` when a registration overwrites an existing `kind` (last-writer-wins is unchanged, but silent override was a footgun). (#72)
- Builtin extension crates moved out of the flat `crates/` directory into a `builtins/` tree (`builtins/plugins/`, `builtins/pdps/`, `builtins/session/`, `builtins/cedarling/`) and renamed off the `apl-` prefix, since they are CPEX plugins that *use* APL hooks rather than APL itself: `apl-pii-scanner` → `cpex-plugin-pii-scanner`, `apl-audit-logger` → `cpex-plugin-audit-logger`, `apl-identity-jwt` → `cpex-plugin-identity-jwt`, `apl-delegator-oauth` → `cpex-plugin-delegator-oauth`, `apl-delegator-biscuit` → `cpex-plugin-delegator-biscuit`, `apl-pdp-cedar-direct` → `cpex-pdp-cedar-direct`, `apl-pdp-cel` → `cpex-pdp-cel`, `apl-session-valkey` → `cpex-session-valkey`, `apl-cedarling` → `cpex-cedarling`. The policy crates (`apl-core`, `apl-cmf`, `apl-cpex`) keep their names. Config-facing `kind:` strings and the FFI C ABI are unchanged. (#72)
- FFI `FFI_ABI_VERSION` bumped `1 → 2`: added the `cpex_apl_install` extern C function and changed `cpex_load_config` to run registered config visitors (it now calls `load_config_yaml` internally so `apl:` blocks are walked). The Go binding's `expectedFFIABIVersion` is bumped in lockstep. (#60)
- Size-first `[profile.release]`: `opt-level = "z"`, `lto = true`, `codegen-units = 1`, `strip = true`. `libcpex_ffi.a` is linked statically into host binaries, so this flows straight into their image size — a representative statically-linked consumer shrank ~21%. `panic = "abort"` is intentionally not set (the FFI relies on `catch_unwind` at its `#[no_mangle]` boundary). No API or ABI change. (#69)
- Trimmed the workspace `tokio` feature floor from `["full"]` to `["rt", "rt-multi-thread", "sync", "time", "macros"]` — the union of what the crates actually use; `reqwest`/`hyper` still pull `net`/`io` where they need them via feature unification. Drops the unused `fs`/`process`/`signal` surface (and the `signal-hook-registry` dependency). (#69)
- `SessionStore` trait methods (`load_labels` / `append_labels`) now return `Result` so backend failures propagate to callers — the error channel fail-closed requires. `MemorySessionStore` is infallible and adapts trivially; the CMF invoker (`for_request` / `persist_session`) and the route handler propagate the error and fail the request closed on a load/append failure. This is part of the shared `SessionStore` contract that future bridges inherit. (#74)

### Removed

- Removed the `cpex-cedarling` crate (a Sub-step A stub with no real Cedarling calls), its `cpex-ffi` optional dependency + `cedarling` cargo feature, and the `cedarling` PDP dialect from the APL grammar (`PdpDialect::Cedarling` and `cedarling:` step recognition). This drops the only `git` dependency in the workspace (the Janssen `cedarling` crate, ~200 transitive deps), making every crate publishable to crates.io. Cedarling was wired nowhere — no config, host, or Go binding referenced it — so there is no functional change; the remaining PDP `kind:` strings (`cedar-direct`, `cel`) and the FFI C ABI are unchanged. A `cedarling`-backed PDP can still be supplied out-of-tree (it degrades to `PdpDialect::Custom`, alongside the resolver-less `opa` / `authzen` / `nemo` dialects).

### Fixed

- Cedar evaluation no longer fails with "recursion limit reached" on hosts that give the FFI a small thread stack (notably musl, whose default is 128 KiB). `cedar-policy` aborts when `stacker::remaining_stack()` is below its 100 KiB floor; the cedar dispatch in `apl-pdp-cedar-direct` is now wrapped in `stacker::maybe_grow`, so it runs on an adequately sized stack regardless of the host (a no-op when there is already headroom, e.g. glibc's 8 MiB threads). Regression test exercises a real evaluation on a 128 KiB stack. (#69)

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
