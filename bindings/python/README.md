# cpex — Rust-backed Python bindings

A native Python extension wrapping the `cpex-core` Rust runtime via PyO3.
Provides the canonical CPEX plugin lifecycle with `await`-based async APIs.

## Requirements

- Python ≥ 3.10
- Rust toolchain (`rustup`)
- [maturin](https://github.com/PyO3/maturin) (`pip install maturin`)

## Install

```bash
# From the bindings/python directory:
cd bindings/python
python -m venv .venv
source .venv/bin/activate
pip install maturin pytest pytest-asyncio
maturin develop
```

## Quick Start

```python
import asyncio
from cpex import PluginManager

async def main():
    mgr = PluginManager("plugins/config.yaml")
    await mgr.initialize()

    result = await mgr.invoke_hook(
        "cmf.tool_pre_invoke",
        {
            "message": {
                "role": "user",
                "content": [{"type": "text", "text": "Hello"}],
            }
        },
    )

    if not result.continue_processing:
        print("Denied:", result.violation)
    else:
        print("Allowed")

    # Always shut down to drain fire-and-forget tasks.
    await mgr.shutdown()

asyncio.run(main())
```

## API

### `PluginManager(config_path: str)`

Synchronous constructor. Reads the YAML config file, registers bundled APL
factories, and loads the config. Raises `ValueError` on missing file,
IO error, or config parse failure.

### `await manager.initialize()`

Initialize all registered plugins. Must be called before `invoke_hook`.

### `await manager.shutdown()`

Shut down all plugins and drain fire-and-forget background tasks.
**Call this before exit if you need fire-and-forget side effects to complete.**

### `await manager.invoke_hook(hook_name, payload, extensions=None, context_table=None)`

Invoke a hook by name. Returns a `PipelineResult`.

- `hook_name` — e.g. `"cmf.tool_pre_invoke"`. Any hook name is accepted;
  `cmf.*` hooks use typed `MessagePayload`, others use `GenericPayload`.
- `payload` — JSON-compatible `dict` (str keys, depth ≤ 128).
- `extensions` — optional `dict` of CPEX extensions fields.
- `context_table` — optional `dict` for stateful plugins.

**Raises:**
- `ValueError` — payload conversion failure or config error.
- `RuntimeError` — plugin execution error.
- `TimeoutError` — wall-clock timeout exceeded (60 s default).

Policy denials **do not raise** — check `result.continue_processing`.

### `PipelineResult`

| Attribute | Type | Description |
|-----------|------|-------------|
| `continue_processing` | `bool` | `False` when a plugin denied |
| `violation` | `dict \| None` | Populated on deny |
| `errors` | `list[dict]` | Per-plugin errors (on_error: ignore/disable) |
| `modified_payload` | `dict \| None` | Payload after transform-phase modifications |
| `modified_extensions` | `dict \| None` | Extensions after modifications |
| `metadata` | `dict \| None` | Optional telemetry metadata |
| `context_table` | `dict` | Per-plugin state |

## Shutdown Contract (Fire-and-Forget Tasks)

Plugins configured with `mode: fire_and_forget` run asynchronously.
Their side effects are **not guaranteed** until `await manager.shutdown()`
completes. In tests always await `shutdown()` before asserting
fire-and-forget side effects:

```python
await mgr.invoke_hook(...)
await mgr.shutdown()          # drain before asserting audit log
assert audit_log_written()
```

## Isolated Virtualenv Requirement

This package and the legacy `./cpex/` package share the import name `cpex`.
They **must not be installed in the same virtualenv**. Always use a
dedicated venv for the Rust-backed package.

## Worker Threads

The tokio runtime thread count is controlled by:

```bash
CPEX_PY_WORKER_THREADS=4  python my_script.py
```

Defaults to tokio's `num_cpus` when unset.

## v1 Deferred Features

- **Identity/delegation hooks** (`identity_resolve`, `token_delegate`):
  routed through `GenericPayload` in v1 — token fields are preserved in
  the raw dict but are not cryptographically validated. Typed constructors
  and token injection are planned for v2.
- **Cedarling PDP**: available behind the `cedarling` Cargo feature
  (`--features cedarling`), off by default.

## Running Tests

```bash
cd bindings/python
maturin develop
pytest tests/ -v
```

## Migration

See [MIGRATION.md](MIGRATION.md) for a mapping from the legacy
pure-Python `cpex` framework to this Rust-backed package.
