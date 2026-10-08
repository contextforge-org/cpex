# Migration Guide: Legacy `cpex` → Rust-backed `cpex`

This guide maps the legacy pure-Python `cpex` package (at `./cpex/`) to the
new Rust-backed package (at `./bindings/python/`).

## Quick Import Change

```python
# Before (legacy)
from cpex.framework import PluginManager
from cpex.framework.models import PluginResult

# After (Rust-backed)
from cpex import PluginManager, PipelineResult
```

## API Mapping Table

| Concept | Legacy (`./cpex/`) | Rust-backed (`bindings/python/`) |
|---------|-------------------|----------------------------------|
| Import | `from cpex.framework import PluginManager` | `from cpex import PluginManager` |
| Construction | `PluginManager()` (Borg singleton) | `PluginManager(config_path)` (explicit config) |
| Initialize | `await manager.initialize()` | `await manager.initialize()` |
| Shutdown | `await manager.shutdown()` | `await manager.shutdown()` |
| Invoke | `result, violations = await manager.invoke_hook(hook, payload, context)` (2-tuple) | `result = await manager.invoke_hook(hook, payload)` (single result) |
| Result type | `(PluginResult, list[Violation])` 2-tuple | `PipelineResult` single object |
| `continue_processing` | `result.continue_processing` | `result.continue_processing` |
| Violation | Returned as second element of tuple | `result.violation` dict (or `None`) |
| Plugin errors | `result.errors` / `violations_as_exceptions` | `result.errors` list of dicts |
| Payload type | Pydantic models | Plain `dict` (JSON-compatible) |
| Config | `PLUGINS_*` env vars | YAML config file path at construction |
| Extensions | `GlobalContext` | `extensions` kwarg dict |
| Context table | `context` kwarg (Pydantic model) | `context_table` kwarg dict |

## Hook Names

Hook names are identical (`cmf.tool_pre_invoke`, etc.) and any hook name
is accepted. The Rust-backed package picks the payload type from the hook
name: `cmf.*` hooks use typed `MessagePayload`, `identity.resolve` uses
typed `IdentityPayload`, and all other hooks use `GenericPayload`. For the
two typed cases, a dict that doesn't match the schema raises `ValueError`.

## Payload Shape

The Rust-backed package uses plain Python dicts that are converted via
direct `PyObject ↔ serde_json` traversal. There is no Pydantic validation
layer. Dict keys must be strings; values must be JSON-compatible types
(`bool`, `int`, `float`, `str`, `None`, `list`, `dict`). Nesting deeper
than 128 levels raises `ValueError`.

For `cmf.*` hooks the dict must match the `MessagePayload` schema:
```python
payload = {
    "message": {
        "role": "user",
        "content": [{"type": "text", "text": "Hello"}],
    }
}
```

## Result Fields

| Field | Type | Notes |
|-------|------|-------|
| `continue_processing` | `bool` | `False` when a plugin denied |
| `violation` | `dict \| None` | Populated on deny; keys: `code`, `reason`, `description`, `details` |
| `errors` | `list[dict]` | Per-plugin errors from `on_error: ignore` plugins |
| `modified_payload` | `dict \| None` | Payload after transform-phase modifications |
| `modified_extensions` | `dict \| None` | Extensions after modifications |
| `metadata` | `dict \| None` | Optional telemetry metadata |
| `context_table` | `dict` | Per-plugin state for stateful plugins |

## Error Handling

| Scenario | Exception |
|----------|-----------|
| Missing / unreadable config file | `ValueError` |
| Malformed YAML | `ValueError` |
| Payload conversion failure | `ValueError` |
| Nesting > 128 levels | `ValueError` |
| Plugin execution error | `RuntimeError` |
| Wall-clock timeout exceeded | `TimeoutError` |

Policy denials **do not raise** — they surface as
`result.continue_processing == False` with `result.violation` populated.

## Fire-and-Forget Tasks

The legacy framework's `fire_and_forget` plugins behave the same way:
they run asynchronously and their side effects are only guaranteed
**after `await manager.shutdown()`**. If you need to assert audit-log
side effects in tests, always call shutdown first.

## Deferred (v2) Features

The following features from the legacy package are **not available in v1**
of the Rust-backed package:

- **Delegation** (`token_delegate`, now `token.delegate`): inbound tokens
  are never serialized, so a delegator cannot exchange them for a call
  made from Python. `identity.resolve` (formerly `identity_resolve`) does
  take a typed `IdentityPayload` dict; see the README.
- **Dual-mode / backend selection**: this package is always Rust-backed.
  There is no environment variable to switch between backends.

## Isolation Requirement

The Rust-backed `cpex` package and the legacy `cpex` package share the
same top-level import name. They **must never be installed in the same
virtualenv**. Always install the Rust-backed package in its own venv:

```bash
python -m venv .venv-cpex-rust
source .venv-cpex-rust/bin/activate
pip install maturin
cd bindings/python && maturin develop
```
