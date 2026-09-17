# Implementation Plan: CPEX Python Bindings (Issue #19)

## Context

CPEX's canonical implementation is the Rust `cpex-core` runtime. Today, non-Rust
hosts reach it only through the C FFI crate (`crates/cpex-ffi`, used by the Go
demo). Python users are stuck on the legacy pure-Python framework at `./cpex/`,
which has diverged conventions (Pydantic payloads, 2-tuple returns,
`GlobalContext`, `violations_as_exceptions`).

Issue #19 (requirements in `docs/dev/issue19_requirements.md`) asks for a **new,
standalone, Rust-backed Python package** at `bindings/python/` that wraps
`cpex_core::PluginManager` via PyO3. It exposes the Rust API *faithfully* (no
bending to legacy conventions), leaves `./cpex/` completely untouched, and ships
a migration guide. A prior attempt (PR #67) failed by trying to match the legacy
API and by calling Python's `json` module from Rust — the requirements doc
codifies those as anti-patterns.

**Key finding (the requirements doc omits this):** the doc's constructor sketch
is incomplete. A `PluginManager` cannot instantiate any config-driven plugin
until its **factories are registered**. The existing `cpex-ffi` crate solves this
in `crates/cpex-ffi/src/apl.rs::cpex_apl_install` by depending on the `apl-*`
crates and registering each `KIND` factory + calling
`apl_cpex::register_apl(...)` *before* `load_config`. The Python binding must do
the same.

**Confirmed decisions:**
- **Mirror `cpex-ffi` exactly** for bundled plugins — the default APL set
  (pii-scanner, audit-logger, identity-jwt, delegator-oauth, cedar-direct PDP),
  with the heavy `cedarling` backend behind an optional Cargo feature.
- **`GenericPayload` fallback** for any hook name outside `cmf.*` /
  `identity_resolve` / `token_delegate` (faithful to the Rust core, where
  `HookType::new` accepts any string; legacy/custom hooks "just work").

**Outcome:** `from cpex import PluginManager` (Rust-backed) works in its own venv;
`await manager.invoke_hook(...)` returns a single `PipelineResult`; the same YAML
configs that drive the Go FFI host drive Python identically.

---

## Reference implementation to mirror

`crates/cpex-ffi/` is the production-grade analog and the single best source of
truth. The PyO3 layer adapts its patterns, swapping the MessagePack/C-ABI wire
for direct PyObject↔serde_json traversal and `block_on` for
`future_into_py`. Key reference points:

- Factory registration + `register_apl`: `crates/cpex-ffi/src/apl.rs:56`
- Construction sequence (default → register → `load_config_yaml` → `initialize`):
  `crates/cpex-ffi/src/lib.rs` (`cpex_manager_new_default`, `cpex_load_config`, `cpex_initialize`)
- Payload INPUT dispatch (`deserialize_payload`): `crates/cpex-ffi/src/lib.rs:321`
- Payload OUTPUT downcast (`serialize_payload`): `crates/cpex-ffi/src/lib.rs:357`
- `PipelineResult` assembly + synthetic FFI error record on payload-serialize
  failure: `crates/cpex-ffi/src/lib.rs:877`
- `GenericPayload` + `impl_plugin_payload!`: `crates/cpex-ffi/src/lib.rs:1357`,
  `crates/cpex-core/src/hooks/payload.rs:118`

Core API signatures confirmed during exploration:
- `PluginManager::default() -> PluginManager` (wrap in `Arc`); `manager.register_factory(kind, Box<dyn Factory>)`
- `load_config_yaml(self: &Arc<Self>, yaml: &str) -> Result<(), Box<PluginError>>` (runs config visitors — required for APL `apl:` blocks; plain `load_config` does not)
- `cpex_core::config::parse_config(yaml)` for upfront validation (good error messages)
- `async initialize(&self) -> Result<(), Box<PluginError>>`; `async shutdown(&self)`
- `async invoke_by_name(&self, hook_name: &str, payload: Box<dyn PluginPayload>, extensions: Extensions, context_table: Option<PluginContextTable>) -> (PipelineResult, BackgroundTasks)`
- `PipelineResult { continue_processing: bool, modified_payload: Option<Box<dyn PluginPayload>>, modified_extensions: Option<Extensions>, violation: Option<PluginViolation>, errors: Vec<PluginErrorRecord>, metadata: Option<serde_json::Value>, context_table: PluginContextTable }`
- `Extensions` and `PluginContextTable` are both `Serialize + Deserialize`.

---

## Implementation

### 1. Workspace + crate scaffolding

- Add `"bindings/python"` to `members` in root `Cargo.toml` `[workspace]`.
- `bindings/python/Cargo.toml`:
  - `[package] name = "cpex-python"` (matches doc's `cargo build -p cpex-python`).
  - `[lib] name = "_lib"`, `crate-type = ["cdylib"]` (maturin `module-name = "cpex._lib"`).
  - Deps: `cpex-core { path = "../../crates/cpex-core" }`, the same APL crates
    `cpex-ffi` bundles (`apl-cpex`, `apl-pii-scanner`, `apl-audit-logger`,
    `apl-identity-jwt`, `apl-delegator-oauth`, `apl-pdp-cedar-direct`;
    `apl-cedarling` optional behind a `cedarling` feature), `serde`/`serde_json`/
    `tokio`/`futures` via `{ workspace = true }`, plus `pyo3` (with `extension-module`
    as a non-default opt-in feature) and `pyo3-async-runtimes` (`tokio-runtime`).
- `bindings/python/build.rs`: on `cfg(target_os = "macos")` emit
  `cargo:rustc-cdylib-link-arg=-undefined` / `dynamic_lookup` so
  `cargo build -p cpex-python` (workspace build, extension-module off) links
  against an absent libpython. (`cpex-ffi` needs no build.rs because it isn't a
  Python extension; this crate does for the standalone cargo build path.)

### 2. Rust PyO3 source (`bindings/python/src/`)

- **`lib.rs`** — `#[pymodule] fn _lib(...)` exporting `PyPluginManager` and
  `PyPipelineResult`. Initialize the `pyo3-async-runtimes` tokio runtime
  (multi-thread, `enable_all`), mirroring `cpex-ffi`'s shared-runtime rationale.
  No work at import time beyond registration (anti-pattern #7: never raise at import).

- **`manager.rs`** — `PyPluginManager { inner: Arc<PluginManager> }`.
  - `#[new] fn new(config_path: &str)`: sync. `PluginManager::default()` → `Arc` →
    `register_builtin_factories(&inner)` (the `apl.rs::cpex_apl_install` sequence:
    `register_factory` for each `apl_*::KIND` + `apl_cpex::register_apl(&inner, AplOptions::in_process()` with cedar-direct `pdp_factory`) → read file to string
    (`std::fs::read_to_string`, IO error → `ValueError`) → `parse_config` validate
    (parse error → `ValueError`) → `inner.load_config_yaml(yaml)` (error → `ValueError`).
  - `fn initialize<'py>(&self, py)` / `fn shutdown<'py>(&self, py)` /
    `fn invoke_hook<'py>(...)`: all return `future_into_py` awaitables.
  - `invoke_hook(hook_name, payload: &Bound<PyDict>, extensions=None, context_table=None)`
    follows the doc's async pattern (convert while holding GIL → release →
    `AssertUnwindSafe(...).catch_unwind()` → re-acquire GIL to build result).
    Optional outer `tokio::time::timeout`; `Elapsed` → `PyTimeoutError`; caught
    panic → `PyRuntimeError` ("Internal error: Rust panic during plugin execution").

- **`conversions.rs`** — NO Python `json` module (anti-pattern #2).
  - `pyobj_to_json_value(py, obj, depth)` — direct `PyBool`/`int`/`float`/`str`/
    `PyList`/`PyDict` traversal → `serde_json::Value`; depth > 128 → `ValueError`
    ("nesting exceeds 128 levels"); unconvertible type → `ValueError` naming the type.
  - `json_value_to_pyobj(py, &Value)` — reverse traversal building `PyDict`/`PyList`.
  - `resolve_payload(hook_name, Value) -> PyResult<Box<dyn PluginPayload>>`:
    `cmf.*` → `MessagePayload`, `identity_resolve` → `IdentityPayload`,
    `token_delegate` → `DelegationPayload`, **else `GenericPayload { value }`**
    (confirmed fallback; `from_value` failures → descriptive `ValueError`).
  - `serialize_payload(&dyn PluginPayload) -> PyResult<serde_json::Value>`:
    `as_any().downcast_ref` in order (MessagePayload, GenericPayload,
    IdentityPayload, DelegationPayload) → `serde_json::to_value`. No match → signal
    so caller records a synthetic error (see `result.rs`), never silently drop
    (anti-pattern #8).
  - `extensions` dict ↔ `Extensions` and `context_table` dict ↔ `PluginContextTable`
    via `serde_json::from_value` / `to_value` (both are serde types).

- **`result.rs`** — `#[pyclass] PyPipelineResult` with read-only getters exactly
  mirroring Rust fields: `continue_processing: bool`, `modified_payload:
  Optional[dict]`, `modified_extensions: Optional[dict]`, `violation:
  Optional[dict]`, `errors: list[dict]`, `metadata: Optional[dict]`,
  `context_table: dict`. `pipeline_result_to_py` builds it; if `modified_payload`
  downcast fails, append a synthetic `{plugin_name:"<ffi>", code:"py_serialize_error", ...}`
  to `errors` (mirrors `cpex-ffi/src/lib.rs:877`). `repr` must never expose
  pointers (anti-pattern #4).

- **`error.rs`** — `PluginError`/`Box<PluginError>` → `PyErr` mapping (C2):
  `Config`/`UnknownHook` → `ValueError`, `Timeout` → `TimeoutError`,
  `Execution`/`Violation` and unexpected → `RuntimeError`. Helper used across modules.

### 3. Python package (`bindings/python/python/cpex/`)

- `__init__.py` — re-export `PluginManager`, `PipelineResult` from `cpex._lib`.
- `_lib.pyi` — stubs matching the Rust signatures exactly; omit anything uncertain
  rather than guess (anti-pattern #5).

### 4. Build config + packaging

- `bindings/python/pyproject.toml` — exactly as doc C5 (maturin backend,
  `module-name = "cpex._lib"`, `features = ["pyo3/extension-module"]`,
  `python-source = "python"`, `requires-python = ">=3.10"`).
- `bindings/python/MIGRATION.md` — the legacy→new mapping table from the doc
  (import path, `invoke_hook` args, hook names, tuple vs single result, dict vs
  Pydantic payloads, context handling, error surfacing).
- `bindings/python/README.md` — install (`maturin develop`) + quickstart.

### 5. Tests (`bindings/python/tests/`)

Mirror legacy conventions (pytest + `pytest-asyncio`; `conftest.py` fixtures, no
module-level `os.environ` mutation — anti-pattern #6). Reuse an existing CMF
config (e.g. `examples/go-demo/cmf_plugins.yaml`) as a fixture so a real bundled
plugin runs.
- `test_conversions.py` — round-trip dicts/nested/empty/None/deep-nesting; >128 → ValueError.
- `test_manager.py` — construct → initialize → `invoke_hook` (CMF) → assert
  `PipelineResult` fields → shutdown.
- `test_errors.py` — missing config file, bad YAML, invalid payload shape, timeout.
- `test_result.py` — all fields accessible; violation present; errors surfaced.

### 6. Makefile

Add `bindings-python-build` / `-build-release` / `-test` targets matching the
existing emoji + `.PHONY` style in the root `Makefile`.

---

## Verification

1. `cargo build -p cpex-python` compiles (workspace build, macOS dynamic_lookup via build.rs).
2. `cd bindings/python && maturin develop` installs the extension into a venv.
3. `python -c "from cpex import PluginManager; print('ok')"`.
4. `cd bindings/python && pytest tests/` passes.
5. Root `pytest tests/` (legacy `cpex`) still passes unchanged — `./cpex/` untouched (C4 / anti-pattern #10).
6. `mypy bindings/python/python/cpex/` passes against the stubs.
7. Spot-check: a `cmf.tool_pre_invoke` invoke with a policy-denying config returns
   `continue_processing == False` with a populated `violation`, and a plugin
   error surfaces in `result.errors` (not swallowed, not raised when non-halting).

## Out of scope / untouched

- `./cpex/` legacy package — zero changes.
- No backend-selection logic — this package is always Rust-backed (anti-pattern #9).
- `cedarling` identity/PDP — present only behind the optional Cargo feature.
