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

## [0.1.4] - 2026-08-07

### Added

- Auto-conversion of "bare-FQN" plugins: a plugin whose manifest `kind` is a Python class
  path (e.g. `package.module.ClassName`) instead of a known kind is now converted to an
  `isolated_venv` plugin at install time (the FQN is moved into `default_config.class_name`),
  so it runs out-of-process in a per-plugin virtual environment ([#113](https://github.com/contextforge-org/cpex/pull/113)).
- `--no-convert` flag on `cpex plugin install` to opt out of the conversion above and keep
  the plugin's declared FQN `kind` (loaded in-process). `--no-convert` also softens an
  unknown/unsupported `kind` from a hard error to a warning. Applies to pypi/test-pypi/git/local
  installs ([#113](https://github.com/contextforge-org/cpex/pull/113)).
- **Credential delivery to isolated workers.** Credential-bearing hooks
  (`identity_resolve`, `token_delegate`) cross the process boundary with the credential
  redacted by `SecretStr` serialization. The worker now reconstructs the live credential from
  the task's `credential` field before invoking the hook, so an out-of-process plugin sees the
  same payload an in-process one would ([#113](https://github.com/contextforge-org/cpex/pull/113)).
- **Credential leak scrubbing on the isolated-worker boundary.** For credential-bearing hooks,
  the worker scrubs the token from log records, exception text, and captured stdout/stderr
  before any of it leaves the subprocess, and fails the task closed if the plugin's own result
  echoes the token back. Log scrubbing installs a `logging.setLogRecordFactory` wrapper and
  stream capture uses `contextlib.redirect_stdout`/`redirect_stderr` — both process-global,
  both scoped to the hook call and restored afterward. Tokens shorter than
  `MIN_SCRUBBABLE_TOKEN_LENGTH` (12) are still delivered to the plugin but are not used as a
  substring needle, since a short needle matches unrelated text and would fail tasks closed
  spuriously ([#113](https://github.com/contextforge-org/cpex/pull/113)).
- **`Extensions` support for `isolated_venv` plugins.** The worker reconstructs a frozen
  `Extensions` from the task's `extensions` field and passes it to the plugin, and returns a
  plugin's modified extensions on `modified_extensions`. The inbound dict is the host's
  capability-filtered view — slot visibility is not re-derived in the worker — and unknown
  slots are dropped rather than raising, so a host that grows a slot ahead of the worker does
  not take every plugin on the channel down ([#113](https://github.com/contextforge-org/cpex/pull/113)).
- **Spawn-time `capabilities` handshake.** A worker answers a `capabilities` task with its
  wire-protocol version and the feature names it actually implements (`credential`,
  `extensions`, `modified_extensions`), letting the host refuse to run a plugin whose declared
  needs the worker would otherwise silently drop. The host gates on the feature list, not on
  the reported `cpex` version, because two builds have shipped as the same version with
  different worker protocols ([#113](https://github.com/contextforge-org/cpex/pull/113)).

### Changed

- **Runtime model of existing FQN-declared Python plugins.** On 0.1.x, declaring a plugin
  `kind` as a Python class path was how in-process Python plugins were declared. Because
  conversion is now **on by default**, upgrading changes such plugins from in-process to the
  out-of-process `isolated_venv` model unless installed with `--no-convert`. Conversion also
  runs during `cpex plugin catalog update` and persists the converted form to
  `plugin-manifest.yaml` / `plugins/config.yaml` ([#113](https://github.com/contextforge-org/cpex/pull/113)).

### Fixed

- **Isolated worker: error responses could carry a stale `request_id`.** The worker reused a
  `main()`-local `request_id` across loop iterations, so an error raised before the next task
  parsed could be tagged with the previous request's id — misdelivering the error to the wrong
  caller's queue or hanging the real caller until timeout. The id is now reset per iteration
  ([#113](https://github.com/contextforge-org/cpex/pull/113)).
- **`cpex plugin install pkg@<constraint>` could wrongly skip.** The repeat-install check
  dropped the version constraint and, for pypi/test-pypi, compared against a possibly stale
  catalog entry. An explicit version constraint now always proceeds with the install
  ([#113](https://github.com/contextforge-org/cpex/pull/113)).
- **Upgrade no longer force-rebuilds every existing `isolated_venv` venv.** The venv cache now
  treats a *missing* manifest version/hash signal (metadata written by an earlier CLI) as "no
  signal" rather than a mismatch, so pre-existing venvs are not wiped and rebuilt on the first
  run after upgrade ([#113](https://github.com/contextforge-org/cpex/pull/113)).
- **Multi-plugin packages no longer thrash the venv cache.** The persisted plugin manifest is
  now keyed on the plugin's full class name instead of the shared package root, so installing
  one plugin in a package no longer invalidates a sibling plugin's cache hash and triggers a
  rebuild loop ([#113](https://github.com/contextforge-org/cpex/pull/113)).
- **test-pypi isolated installs resolve transitive dependencies.** Installing a plugin from
  test.pypi into a fresh isolated venv now also passes `--extra-index-url https://pypi.org/simple/`,
  so transitive dependencies (including `cpex` itself) resolve from real PyPI instead of failing
  when they are absent from test.pypi ([#113](https://github.com/contextforge-org/cpex/pull/113)).
- **A failed package install no longer leaves a valid-looking venv cache.** Venv cache metadata
  was persisted during `initialize()`, before the catalog installed the plugin's package into
  the venv. Converted bare-FQN plugins have no `requirements.txt`, so that package install is
  the only thing making the venv usable — if it failed, the install reported an error but the
  cache read as valid, and at runtime `initialize()` skipped provisioning and the worker could
  not import the plugin class. Metadata is now committed only after the package install
  succeeds, so a failed install rebuilds on the next run instead of needing an explicit
  reinstall ([#113](https://github.com/contextforge-org/cpex/pull/113)).
- **`--no-convert` no longer silently no-ops on monorepo installs.** The catalog manifest is
  already normalized during `catalog update`, so by dispatch there is no unconverted `kind`
  left for the flag to honor. The monorepo path now warns that the flag was ignored and names
  the install types that do honor it (git/pypi/test-pypi/local)
  ([#113](https://github.com/contextforge-org/cpex/pull/113)).
- **A dropped credential on a payload-less hook is no longer silent.** When a credential-bearing
  hook arrived with a credential but no payload, the credential was discarded without a trace,
  unlike every other failure on that path. It now logs a warning naming the hook (never the
  credential) ([#113](https://github.com/contextforge-org/cpex/pull/113)).

### Dependencies

- `uv.lock` resolves `mcp` to 1.29.0 (was 1.27.0). No `pyproject.toml` change: the declared
  constraint stays `mcp>=1.26.0,<2`, and 1.29.0 satisfies it. The 2.0 migration
  (`McpError` → `MCPError`) remains tracked separately and out of the 0.1.x line
  ([#113](https://github.com/contextforge-org/cpex/pull/113)).

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

[Unreleased]: https://github.com/contextforge-org/cpex/compare/0.1.4...HEAD
[0.1.4]: https://github.com/contextforge-org/cpex/compare/0.1.3...0.1.4
[0.1.3]: https://github.com/contextforge-org/cpex/compare/0.1.2...0.1.3
[0.1.2]: https://github.com/contextforge-org/cpex/compare/0.1.1...0.1.2
[0.1.1]: https://github.com/contextforge-org/cpex/compare/0.1.0...0.1.1
[0.1.0]: https://github.com/contextforge-org/cpex/releases/tag/0.1.0