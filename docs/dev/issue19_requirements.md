# Requirements: CPEX Python Bindings (Issue #19)

## Philosophy

**The Rust implementation is the canonical CPEX.** The Python bindings expose the Rust API faithfully — they do not bend to match the legacy Python framework's conventions. The legacy `./cpex/` package remains untouched; users migrate to the new package at their own pace via a migration guide.

## Goal

Create a **new Python package** at `bindings/python/` that wraps `cpex_core::PluginManager` via PyO3. This package:
- Exposes the Rust API contracts directly (not the legacy Python conventions)
- Is a standalone, separately installable package
- Leaves `./cpex/` (legacy pure-Python framework) completely untouched
- Includes a migration guide from legacy Python to the new Rust-backed package

---

## Repository Structure

```
bindings/python/
├── Cargo.toml              # PyO3 cdylib crate (depends on cpex-core)
├── build.rs                # macOS linker flags for extension modules
├── src/                    # Rust PyO3 source
│   ├── lib.rs              # Module definition, exports
│   ├── manager.rs          # PyPluginManager
│   ├── conversions.rs      # Python↔Rust value traversal
│   ├── error.rs            # PluginError → PyErr
│   └── result.rs           # PyPipelineResult
├── python/
│   └── cpex/        # Python package (importable as `import cpex`)
│       ├── __init__.py     # Re-exports from the native module
│       └── _lib.pyi        # Type stubs matching actual Rust signatures
├── pyproject.toml          # maturin-based build system
├── tests/
│   ├── test_manager.py     # End-to-end invoke_hook tests
│   ├── test_conversions.py # Round-trip conversion correctness
│   └── conftest.py         # Shared fixtures
├── MIGRATION.md            # Guide: legacy cpex → cpex
└── README.md               # Package documentation
```

**Key decisions:**
- Package name: `cpex` — same name as the legacy package. When the Rust-backed version is ready, it replaces the legacy on PyPI seamlessly.
- The Rust crate at `bindings/python/` depends on `cpex-core` from the workspace
- Build with `maturin develop` or `maturin build`
- During development, both packages exist (legacy at `./cpex/`, new at `bindings/python/python/cpex/`). They are NOT installed simultaneously — the new one is installed in its own venv or replaces the legacy.

---

## API Contract (Rust-Native)

The Python API mirrors the Rust `PluginManager` directly:

```python
from cpex import PluginManager, PipelineResult  # The new Rust-backed cpex package

# Construction: sync, loads config
manager = PluginManager("plugins/config.yaml")

# Initialization: async, calls plugin.initialize() on all registered plugins
await manager.initialize()

# Invoke a hook — THE CONTRACT (mirrors Rust invoke_by_name)
result: PipelineResult = await manager.invoke_hook(
    hook_name,          # str: "cmf.tool_pre_invoke", "identity_resolve", etc.
    payload,            # dict — converted to Box<dyn PluginPayload> via PayloadRegistry
    extensions=None,    # Optional[dict] — converted to Extensions
    context_table=None, # Optional[dict] — converted to PluginContextTable
)

# Result: single object (mirrors Rust PipelineResult)
result.continue_processing   # bool
result.modified_payload       # Optional[dict]
result.modified_extensions    # Optional[dict]
result.violation              # Optional[dict] with {reason, description, code, details}
result.errors                 # list[dict] — non-halting plugin errors (on_error: ignore/disable)
result.metadata               # Optional[dict]
result.context_table          # dict — pass to next invoke_hook for state continuity

# Shutdown: async
await manager.shutdown()
```

### Hook Names

The new package uses the **Rust canonical names**:

| Category | Hook Name | Notes |
|----------|-----------|-------|
| CMF | `"cmf.tool_pre_invoke"` | CMF Message payload |
| CMF | `"cmf.tool_post_invoke"` | |
| CMF | `"cmf.llm_input"` | CMF-only (no legacy equivalent) |
| CMF | `"cmf.llm_output"` | |
| CMF | `"cmf.prompt_pre_fetch"` | |
| CMF | `"cmf.prompt_post_fetch"` | |
| CMF | `"cmf.resource_pre_fetch"` | |
| CMF | `"cmf.resource_post_fetch"` | |
| Legacy | `"tool_pre_invoke"` | Non-CMF typed payload |
| Legacy | `"tool_post_invoke"` | |
| Legacy | `"prompt_pre_fetch"` | |
| Legacy | `"prompt_post_fetch"` | |
| Legacy | `"resource_pre_fetch"` | |
| Legacy | `"resource_post_fetch"` | |
| Identity | `"identity_resolve"` | IdentityPayload |
| Delegation | `"token_delegate"` | DelegationPayload |

The Rust core's `HookType::new(hook_name)` accepts any string. The PyO3 layer passes through as-is — no normalization, no aliasing.

---

## Hard Constraints

### C1: Faithful Rust API Exposure

Do NOT adapt the API to match the legacy Python `PluginManager`. The Python bindings are a thin layer over the Rust contracts. The legacy Python framework has its own conventions (GlobalContext, 2-tuple returns, violations_as_exceptions, etc.) — those belong to the legacy package.

### C2: No Silent Failures

Every error at the FFI boundary raises a Python exception:
- Unknown hook → `ValueError`
- Config parse failure → `ValueError`
- Plugin execution failure → `RuntimeError`
- Conversion failure → `ValueError` (with descriptive message)
- Timeout → `TimeoutError`

### C3: Safety

- **Panic isolation**: All async blocks crossing FFI wrapped in `catch_unwind`. Panics → `RuntimeError`.
- **Recursion depth**: Value traversal capped at 128 levels. Overflow → `ValueError`.
- **No pointer exposure**: Never `{:p}` in repr/errors.

### C4: Standalone Package

- `./cpex/` is NOT modified. No `__init__.py` changes, no backend selection logic injected.
- The new package is independently installable: `pip install ./bindings/python/` or `maturin develop` from that directory.
- No import-time exceptions.

### C5: Self-Contained Build

```toml
# bindings/python/pyproject.toml
[build-system]
requires = ["maturin>=1.0,<2.0"]
build-backend = "maturin"

[project]
name = "cpex"
version = "0.1.0"
requires-python = ">=3.10"

[tool.maturin]
module-name = "cpex._lib"
features = ["pyo3/extension-module"]
python-source = "python"
```

---

## Conversion Strategy

**Do NOT** call Python's `json` module from Rust.

### Python → Rust (input)

Direct PyDict/PyList/PyString traversal → `serde_json::Value` → `serde_json::from_value::<T>()`:

```rust
fn pyobj_to_json_value(py: Python, obj: &Bound<PyAny>, depth: usize) -> PyResult<serde_json::Value> {
    if depth > 128 {
        return Err(PyValueError::new_err("Payload nesting exceeds 128 levels"));
    }
    if obj.is_none() { return Ok(Value::Null); }
    if let Ok(b) = obj.extract::<bool>() { return Ok(Value::Bool(b)); }
    if let Ok(i) = obj.extract::<i64>() { return Ok(Value::Number(i.into())); }
    if let Ok(f) = obj.extract::<f64>() { return Ok(json!(f)); }
    if let Ok(s) = obj.extract::<String>() { return Ok(Value::String(s)); }
    if let Ok(list) = obj.downcast::<PyList>() { /* recurse with depth+1 */ }
    if let Ok(dict) = obj.downcast::<PyDict>() { /* recurse with depth+1 */ }
    Err(PyValueError::new_err(format!("Cannot convert {} to JSON", obj.get_type().name()?)))
}
```

### Rust → Python (output)

`serde_json::to_value(&rust_struct)` → traverse Value building PyDict/PyList/etc:

```rust
fn json_value_to_pyobj(py: Python, value: &serde_json::Value) -> PyResult<PyObject> {
    match value {
        Value::Null => Ok(py.None()),
        Value::Bool(b) => Ok(b.into_pyobject(py)?.into()),
        Value::Number(n) => /* i64 or f64 */,
        Value::String(s) => Ok(s.into_pyobject(py)?.into()),
        Value::Array(arr) => /* PyList */,
        Value::Object(map) => /* PyDict */,
    }
}
```

### Payload Dispatch

The Rust core's `invoke_by_name` needs a `Box<dyn PluginPayload>`. The PyO3 layer needs a registry mapping hook names → payload types (same concept as the Rust `PluginPayload` trait implementors):

```rust
// Convert input dict to the appropriate Box<dyn PluginPayload> based on hook_name
fn resolve_payload(hook_name: &str, value: serde_json::Value) -> PyResult<Box<dyn PluginPayload>> {
    match hook_name {
        s if s.starts_with("cmf.") => {
            let msg: Message = serde_json::from_value(value)?;
            Ok(Box::new(MessagePayload { message: msg }))
        }
        "identity_resolve" => {
            let p: IdentityPayload = serde_json::from_value(value)?;
            Ok(Box::new(p))
        }
        "token_delegate" => {
            let p: DelegationPayload = serde_json::from_value(value)?;
            Ok(Box::new(p))
        }
        // Legacy hooks (tool_pre_invoke, prompt_pre_fetch, etc.) use typed payloads
        // that mirror the Python Pydantic models
        _ => {
            // For unknown hooks, attempt generic conversion or error
            Err(PyValueError::new_err(format!("Unknown hook: '{}'", hook_name)))
        }
    }
}
```

---

## Async Pattern

```rust
use pyo3_async_runtimes::tokio::future_into_py;
use std::panic::AssertUnwindSafe;
use futures::FutureExt;

#[pymethods]
impl PyPluginManager {
    fn invoke_hook<'py>(
        &self,
        py: Python<'py>,
        hook_name: &str,
        payload: &Bound<'py, PyDict>,
        extensions: Option<&Bound<'py, PyDict>>,
        context_table: Option<&Bound<'py, PyDict>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let manager = Arc::clone(&self.inner);
        let hook_name = hook_name.to_string();

        // Convert while holding GIL
        let payload_value = pyobj_to_json_value(py, payload.as_any(), 0)?;
        let rust_payload = resolve_payload(&hook_name, payload_value)?;
        let rust_extensions = convert_extensions(py, extensions)?;
        let rust_context = convert_context_table(py, context_table)?;

        // Release GIL, run Rust async
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let result = AssertUnwindSafe(async {
                manager.invoke_by_name(&hook_name, rust_payload, rust_extensions, rust_context).await
            })
            .catch_unwind()
            .await;

            match result {
                Ok((pipeline_result, _bg_tasks)) => {
                    Python::with_gil(|py| pipeline_result_to_py(py, pipeline_result))
                }
                Err(_) => Err(PyRuntimeError::new_err(
                    "Internal error: Rust panic during plugin execution"
                ))
            }
        })
    }
}
```

---

## Deliverables

### Required Files

| Path | Purpose |
|------|---------|
| `bindings/python/Cargo.toml` | PyO3 cdylib crate |
| `bindings/python/build.rs` | macOS dynamic_lookup linker flag |
| `bindings/python/src/lib.rs` | Module definition |
| `bindings/python/src/manager.rs` | PyPluginManager |
| `bindings/python/src/conversions.rs` | Value traversal (no json module) |
| `bindings/python/src/error.rs` | PluginError → PyErr |
| `bindings/python/src/result.rs` | PyPipelineResult |
| `bindings/python/python/cpex/__init__.py` | Package re-exports |
| `bindings/python/python/cpex/_lib.pyi` | Stubs matching Rust exactly |
| `bindings/python/pyproject.toml` | maturin build config |
| `bindings/python/tests/` | Python test suite |
| `bindings/python/MIGRATION.md` | Legacy cpex → cpex guide |
| `Cargo.toml` (workspace root) | Add `bindings/python` to members |

### Required Tests

1. **test_conversions.py** — round-trip for dicts, nested structures, edge cases (empty, None, deep nesting)
2. **test_manager.py** — end-to-end: construct, initialize, invoke_hook with a Rust plugin, shutdown
3. **test_errors.py** — unknown hook, invalid payload, timeout, missing config
4. **test_result.py** — PipelineResult fields accessible, violation present, errors surfaced

### Migration Guide (MIGRATION.md)

Document the key differences:

| Aspect | Legacy `cpex` | New `cpex` |
|--------|--------------|-------------------|
| Import | `from cpex.framework.manager import PluginManager` | `from cpex import PluginManager` (new Rust-backed package) |
| invoke_hook args | `(hook_type, payload, global_context, local_contexts, violations_as_exceptions, extensions)` | `(hook_name, payload_dict, extensions, context_table)` |
| Hook names | `"tool_pre_invoke"` | `"cmf.tool_pre_invoke"` (CMF) or `"tool_pre_invoke"` (legacy) |
| Return | `tuple[PluginResult, PluginContextTable]` | `PipelineResult` (single object) |
| Payload input | Pydantic model | dict |
| Context | GlobalContext + PluginContextTable separately | context_table dict (threaded through) |
| Extensions | Pydantic Extensions model | dict |
| Errors | Swallowed or raised depending on violations_as_exceptions | Always in `result.errors` (non-halting) or raised (halting) |

---

## Anti-Patterns to Avoid (Lessons from PR #67)

1. **Never try to match the legacy Python API.** The Rust API is canonical.
2. **Never call Python's json module from Rust.** Direct value traversal only.
3. **Never return sentinel dicts for errors.** Raise exceptions.
4. **Never expose heap addresses in repr/errors.**
5. **Never hand-write stubs that diverge from Rust signatures.** Omit rather than guess.
6. **Never mutate `os.environ` at module level in tests.** Use fixtures.
7. **Never raise at import time.** Defer errors to first use.
8. **Never discard PipelineResult.errors.** Surface them.
9. **This package IS the Rust backend.** No backend selection logic needed — `cpex` (from bindings/python) is always Rust-backed.
10. **Never modify `./cpex/`.** The legacy package is untouched.

---

## Workspace Integration

Add to root `Cargo.toml`:

```toml
[workspace]
members = [
    # ... existing crates ...
    "bindings/python",
]
```

Add Makefile targets:

```makefile
## Python Bindings
bindings-python-build:         ## Build cpex (debug)
	cd bindings/python && maturin develop

bindings-python-build-release: ## Build cpex (release)
	cd bindings/python && maturin develop --release

bindings-python-test:          ## Test cpex
	cd bindings/python && pytest tests/
```

---

## Verification

After implementation:

1. `cargo build -p cpex-python` (or whatever the crate name) compiles
2. `cd bindings/python && maturin develop` installs the extension
3. `python -c "from cpex import PluginManager; print('ok')"` works
4. `cd bindings/python && pytest tests/` passes
5. The existing `pytest tests/` in repo root (legacy cpex tests) passes unchanged
6. `mypy bindings/python/python/cpex/` passes with stubs
