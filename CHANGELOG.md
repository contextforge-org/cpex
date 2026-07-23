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

- Auto-conversion of "bare-FQN" plugins: a plugin whose manifest `kind` is a Python class
  path (e.g. `package.module.ClassName`) instead of a known kind is now converted to an
  `isolated_venv` plugin at install time (the FQN is moved into `default_config.class_name`),
  so it runs out-of-process in a per-plugin virtual environment ([#113](https://github.com/contextforge-org/cpex/pull/113)).
- `--no-convert` flag on `cpex plugin install` to opt out of the conversion above and keep
  the plugin's declared FQN `kind` (loaded in-process). `--no-convert` also softens an
  unknown/unsupported `kind` from a hard error to a warning. Applies to pypi/test-pypi/git/local
  installs ([#113](https://github.com/contextforge-org/cpex/pull/113)).

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