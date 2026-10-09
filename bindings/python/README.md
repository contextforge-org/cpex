# cpex: Rust-backed Python bindings

A native Python extension wrapping the Praxis Policy Engine (PPE) Rust
runtime via PyO3. Provides the CPEX policy engine lifecycle with
`await`-based async APIs.

## Requirements

- Python 3.10 or later
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
from cpex import PolicyEngine

async def main():
    engine = PolicyEngine("policy.yaml")
    await engine.initialize()

    result = await engine.invoke_hook(
        "cmf.tool_pre_invoke",
        {
            "message": {
                "role": "assistant",
                "content": [{
                    "content_type": "tool_call",
                    "content": {
                        "tool_call_id": "tc_1",
                        "name": "lookup_person",
                        "arguments": {"name": "Alice"},
                    },
                }],
            }
        },
        # Under the default `dispatch: policy`, meta selects the route.
        {"meta": {"entity_type": "tool", "entity_name": "lookup_person"}},
    )

    if not result.continue_processing:
        print("Denied:", result.violation)
    else:
        print("Allowed")

    # Always shut down to drain fire-and-forget tasks.
    await engine.shutdown()

asyncio.run(main())
```

## API

`cpex` exports `PolicyEngine`, `PipelineResult` and `PluginManager`.
`PluginManager` is the pre-0.3 name, kept as an alias: `PluginManager is
PolicyEngine`.

### `PolicyEngine(config_path: str, *, allow_private_destinations: bool = False)`

Synchronous constructor. Installs the bundled builtins, one outbound HTTP
transport and the secret providers, then reads and loads the YAML config.
Raises `ValueError` on missing file, IO error, or config error (including
an unknown plugin `kind` or a removed hook name).

Bundled builtins: plugin kinds `identity/jwt`, `identity/api-key`,
`delegator/oauth` and `elicitation/ciba`; PDP kinds `cedar-direct`, `cel`
and `opa`; session store kind `valkey`; secret provider kinds `env`,
`file` and `vault`. Builtins that make HTTP calls must declare
`capabilities: [perform_http]`.

`allow_private_destinations` lets those builtins reach private, loopback
and link-local addresses (a JWKS endpoint on localhost, an in-cluster
Vault). It is off by default, which refuses such requests; the builtin
then reports its egress-denied code (`delegation.egress_denied`,
`elicitation.egress_denied`, or `auth.jwks_unavailable` for a JWKS fetch).
It is a host setting: no policy document can turn it on. Keyword only.

### `await engine.initialize()`

Initialize all registered plugins and resolve declared secrets. The call
schedules work immediately; await its result before `invoke_hook`.

Raises `RuntimeError` once `shutdown()` has been called, including when
shutdown races with scheduled initialization. Raises
`TimeoutError` past the wall-clock timeout. A timed-out initialize keeps
running; once it ends, the engine shuts down to stop the plugins it
started. The engine is terminal from the moment the timeout fires, so
build a new `PolicyEngine` to try again.

### `await engine.shutdown()`

Shut down all plugins and drain fire-and-forget background tasks.
**Call this before exit if you need fire-and-forget side effects to complete.**
Calling `shutdown()` starts teardown and immediately refuses new work.
Await its result to know when teardown has finished. The shutdown task
continues if its awaitable is dropped or cancelled. It waits for an
`initialize()` in flight, then tears down the plugins it started.

Shutdown is terminal from the call: later `initialize`,
`invoke_hook` and `refresh_secrets` calls raise `RuntimeError`. A second
`shutdown` after one completed is a no-op. A shutdown that raised
`TimeoutError` can be retried; the retry waits for the first to finish
and reports its outcome.

### `await engine.invoke_hook(hook_name, payload, extensions=None, context_table=None)`

Invoke a hook by name. Returns a `PipelineResult`.

- `hook_name`: e.g. `"cmf.tool_pre_invoke"`. `cmf.*` hooks use typed
  `MessagePayload`, `identity.resolve` uses typed `IdentityPayload`,
  others use `GenericPayload`. A hook name removed in 0.3
  (`tool_pre_invoke`, `identity_resolve` and the rest) raises
  `ValueError` naming its replacement.
- `payload`: JSON-compatible `dict` (str keys, depth at most 128).
- `extensions`: optional `dict` of CPEX extensions fields. Under the
  default `dispatch: policy`, `meta.entity_type` and `meta.entity_name`
  pick the route; a request without them is denied with
  `unidentified_request` when the config declares a policy.
- `context_table`: optional `dict` for stateful plugins.

**Raises:**
- `ValueError`: a hook name removed in 0.3; an `identity.resolve`
  payload that sets a field other than `source`, `source_header`,
  `headers`, `client_host` and `client_port`; payload conversion failure;
  or config error.
- `RuntimeError`: plugin execution error, or a call after `shutdown`.
- `TimeoutError`: wall-clock timeout exceeded (60 s default).

Policy denials **do not raise**; check `result.continue_processing`.

### `await engine.refresh_secrets()`

Re-read every declared secret, renewing a Vault token when due. PPE never
re-reads on its own, so a host that rotates secrets calls this on its own
schedule. Returns a dict with the same fields as the C FFI report:

```python
{
    "updated": ["api_key"],        # values whose bytes changed
    "unchanged": 0,                # values re-read and found unchanged
    "failed": [                    # values that could not be re-read
        {"secret": "...", "provider": "...", "kind": "not_found", "message": "..."},
    ],
}
```

`kind` is one of `config`, `reference`, `not_found`, `malformed`, `backend`
or `other`. A failed value keeps its last-good bytes; failures are listed,
not raised. `message` never contains the secret.

Raises `RuntimeError` after `shutdown()` or when a secret provider
panics, and `TimeoutError` past the wall-clock timeout.

### `engine.secrets_last_success(provider: str) -> datetime | None`

When `provider` last re-read all of its values without a failure, as a
timezone-aware UTC `datetime`. `None` when its most recent refresh failed,
the name is not a declared provider, or secrets are not resolved yet.
Initialization counts as the first success. Synchronous.

### `PipelineResult`

| Attribute | Type | Description |
|-----------|------|-------------|
| `continue_processing` | `bool` | `False` when a plugin or policy denied |
| `violation` | `dict \| None` | Populated on deny |
| `errors` | `list[dict]` | Per-plugin errors (on_error: ignore/disable) |
| `modified_payload` | `dict \| None` | Payload after transform-phase modifications |
| `payload_modified` | `bool` | Whether a modification was accepted |
| `modified_extensions` | `dict \| None` | Extensions after modifications |
| `metadata` | `dict \| None` | Optional telemetry metadata |
| `context_table` | `dict` | Per-plugin state |

## Shutdown Contract (Fire-and-Forget Tasks)

Plugins configured with `mode: fire_and_forget` run asynchronously.
Their side effects are **not guaranteed** until `await engine.shutdown()`
completes. In tests always await `shutdown()` before asserting
fire-and-forget side effects:

```python
await engine.invoke_hook(...)
await engine.shutdown()       # drain before asserting side effects
assert side_effect_happened()
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

## Deferred Features

- **Delegation** (`delegate(...)` steps, `token.delegate`): the inbound
  tokens a delegator exchanges are never serialized, so they cannot cross
  from an `identity.resolve` result into a later tool call. Drive
  delegation from Rust, or from Go with `InvokeResolved`.

### Identity from Python

`identity.resolve` takes a dict shaped like PPE's `IdentityPayload`. Pass
the request's credential headers with lowercased names; the resolved
subject comes back under `modified_payload["subject"]`. Put it in the tool
call's extensions as `security.subject`:

```python
ident = await engine.invoke_hook(
    "identity.resolve",
    {"source": "bearer", "headers": {"authorization": f"Bearer {token}"}},
    {"meta": {"entity_type": "tool", "entity_name": "get_compensation"}},
)
if ident.continue_processing:
    ext = {
        "meta": {"entity_type": "tool", "entity_name": "get_compensation"},
        "security": {"subject": ident.modified_payload["subject"]},
    }
    result = await engine.invoke_hook("cmf.tool_pre_invoke", payload, ext)
```

The input may set only `source`, `source_header`, `headers`,
`client_host` and `client_port`; a resolver output field such as
`subject` raises `ValueError`. `modified_payload` does not echo the
request `headers`, since they carry the inbound token.

The engine trusts the subject it is given, so only pass one that came
from `identity.resolve`.

## Running Tests

```bash
cd bindings/python
maturin develop
pytest tests/ -v
```

Or from the repository root: `make bindings-python-test`.

Wheel smoke test (builds a release wheel, installs it into a fresh venv,
imports `cpex` there and runs a policy):

```bash
python bindings/python/tests/smoke_wheel.py
# or test a wheel built elsewhere:
python bindings/python/tests/smoke_wheel.py --wheel target/wheels/cpex-*.whl
```

## Migration

See [MIGRATION.md](MIGRATION.md) for a mapping from the legacy
pure-Python `cpex` framework to this Rust-backed package.
