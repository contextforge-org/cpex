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

## [0.1.3] - 2026-08-06

### Changed

- `CopyOnWriteDict` / `CopyOnWriteList` now snapshot the wrapped container at construction instead of reading through to it lazily ([#152](https://github.com/contextforge-org/cpex/issues/152))
  - Mutating the original *after* wrapping is no longer visible through the wrapper — isolation is now symmetric. The lazy implementation leaked such mutations in
  - The wrapper no longer retains a reference to the original container
  - Small construction cost: snapshotting up front measures 0.26 us vs 0.17 us (100-item list) and 0.43 us vs 0.20 us (100-key dict) against the lazy wrapper. Still ~38-45x cheaper than the `copy.deepcopy()` it exists to avoid, so the isolation path stays sub-microsecond per wrap
- Capped the `mcp` dependency below 2.0 ([#148](https://github.com/contextforge-org/cpex/pull/148))
  - mcp 2.0.0 renamed `McpError` to `MCPError`, breaking `cpex/framework/external/mcp/client.py`. The 0.1.x line stays on mcp 1.x

### Fixed

- CopyOnWrite containers no longer lose or duplicate data in inherited methods ([#152](https://github.com/contextforge-org/cpex/issues/152))
  - `model_dump()` / `model_dump_json()` / `json.dumps()` of a CoW-isolated payload returned empty containers, silently stripping `items` / `args` / headers — this reached external (gRPC/Unix-socket) plugins, which receive payloads via `model_dump()`
  - `copy.deepcopy()` and `model_copy(deep=True)` duplicated every element of a `CopyOnWriteList`
  - `CopyOnWriteList`: fixed `<`, `<=`, `>`, `>=`, `+`, `*`, `+=`, `*=`, `index()`, `count()` and `reversed()`; `+=` was a silent no-op
  - `CopyOnWriteDict`: fixed `|`, `|=`, `popitem()` and `reversed()`
- Implement `__eq__` and `__ne__` for CopyOnWriteList ([#136](https://github.com/contextforge-org/cpex/pull/136))
- Execution records are now emitted for the denying plugin when a violation raises ([#147](https://github.com/contextforge-org/cpex/issues/147))
  - With `violations_as_exceptions=True`, `PluginViolationError` carries the accumulated records via a new `executions` attribute — previously only plugins that ran *before* the denial were observable, so telemetry could not identify which control blocked the invocation
  - Covers SEQUENTIAL, TRANSFORM, AUDIT and CONCURRENT modes; concurrent denials also no longer leak sibling tasks (they are cancelled before the re-raise)

## [0.1.2] - 2026-07-29

### Added

- Structured control execution records for enforcement observability ([#141](https://github.com/contextforge-org/cpex/issues/141))
  - `ControlExecutionStatus` enum and `ControlExecutionRecord` Pydantic model in `cpex.framework.models`
  - `PluginResult.executions: list[ControlExecutionRecord]` — one record per plugin evaluated, always present
  - All five execution phases instrumented: Sequential, Transform, Audit, Concurrent, Fire-and-forget
  - Identity fields (`plugin_id`, `plugin_name`, `plugin_kind`, `mode`) sourced from trusted `PluginRef` config — plugins cannot forge these
  - Monotonic per-plugin timing (`duration_ns`); fire-and-forget records use `duration_ns=0` at spawn time
  - Security bounds: string fields capped at 256 bytes, config key lists capped at 64 entries, config values never stored
  - `ControlExecutionRecord` and `ControlExecutionStatus` exported from `cpex.framework`

## [0.1.1] - 2026-06-04

### Added

- Plugin bundling, catalog, installation and versioning ([#31](https://github.com/contextforge-org/cpex/pull/31))

### Fixed

- Implement `__eq__` and `__ne__` for CopyOnWriteDict ([#55](https://github.com/contextforge-org/cpex/pull/55))
- Respect `PLUGINS_LOG_LEVEL` environment variable in all runtime.py files ([#48](https://github.com/contextforge-org/cpex/pull/48))

## [0.1.0] - 2026-05-05

### Added

- Initial release

[Unreleased]: https://github.com/contextforge-org/cpex/compare/0.1.3...HEAD
[0.1.3]: https://github.com/contextforge-org/cpex/compare/0.1.2...0.1.3
[0.1.2]: https://github.com/contextforge-org/cpex/compare/0.1.1...0.1.2
[0.1.1]: https://github.com/contextforge-org/cpex/compare/0.1.0...0.1.1
[0.1.0]: https://github.com/contextforge-org/cpex/releases/tag/0.1.0