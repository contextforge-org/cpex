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

[Unreleased]: https://github.com/contextforge-org/cpex/compare/0.1.2...HEAD
[0.1.2]: https://github.com/contextforge-org/cpex/compare/0.1.1...0.1.2
[0.1.1]: https://github.com/contextforge-org/cpex/compare/0.1.0...0.1.1
[0.1.0]: https://github.com/contextforge-org/cpex/releases/tag/0.1.0