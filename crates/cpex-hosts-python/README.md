# cpex-hosts-python

Runs existing Python CPEX plugins out-of-process from the Rust `PluginManager`.
Each plugin gets its own cached virtualenv and a long-lived `worker.py`
subprocess, spoken to over newline-delimited JSON on stdio — the same protocol
the Python CLI already uses, so a plugin that works there works here unchanged.

Registers under the plugin kind **`isolated_venv`**.

## Why out-of-process

The runtime never links libpython, so a plugin crash, a C-extension segfault, or
a dependency conflict cannot take the gateway down. Each plugin's dependencies
live in its own venv, so two plugins can pin incompatible versions of the same
package. This supersedes issue #20's original `python://` in-process (PyO3)
framing.

## Usage

Register the factory before loading config:

```rust
use cpex_core::factory::PluginFactoryRegistry;
use cpex_hosts_python::{IsolatedVenvFactory, KIND};

let mut factories = PluginFactoryRegistry::new();
factories.register(KIND, Box::new(IsolatedVenvFactory));

let manager = PluginManager::from_config(config, &factories)?;
```

## Config schema

Host-specific settings live in the plugin entry's opaque `config:` map, because
`PluginConfig` has no fields for them:

```yaml
plugins:
  - name: pii-filter
    kind: isolated_venv
    hooks: [tool_pre_invoke]
    config:
      # Required — the fully-qualified Python class.
      class_name: my_pkg.filters.PiiFilter

      # Optional. Installed into the venv on a cache miss.
      requirements_file: requirements.txt

      # Optional, with defaults matching the Python reference implementation.
      script_path: cpex/framework/isolated/worker.py
      max_content_size: 10000000   # bytes, per outbound task
      timeout_secs: 30             # per invocation
```

| Key | Required | Default | Notes |
|---|---|---|---|
| `class_name` | yes | — | Fully-qualified Python class. Also keys the venv cache. |
| `requirements_file` | no | none | Relative to the resolved plugin path. |
| `script_path` | no | `cpex/framework/isolated/worker.py` | Resolved inside the venv. |
| `max_content_size` | no | `10000000` | Oversized tasks are rejected before the write. |
| `timeout_secs` | no | `30` | The executor's global timeout also applies. |

### Plugin directories are not configurable

The host always uses **`plugins/` at the project root** — the process working
directory — as the worker's `sys.path` entry and as the directory the venv is
built under. There is no config key for it:

- a `plugin_dirs:` key inside a plugin's `config:` block is **ignored** (the
  factory logs a warning naming the plugin), and
- the top-level `plugin_dirs:` YAML key is **ignored** too — `cpex-core` parses
  it, warns, and discards it.

Both are ignored rather than rejected, so a config carrying either still loads.

This is deliberate. `cpex plugin install` writes the plugin into
`<project root>/plugins/` and builds its venv there, so both sides already agree
on the location; a config key only creates a way for them to disagree, and the
failure mode is an `ImportError` inside the worker at invoke time — far from the
config that caused it. The worker independently restricts plugin dirs to its own
`ALLOWED_PLUGIN_DIRS`, which includes its working directory (inherited from this
host), so the resolved directory is importable by construction.

## Hooks and payloads

Both hook families work. The `cmf.` prefix selects the CMF message payload;
each legacy name maps to its own typed payload; anything unrecognized falls
back to a generic JSON payload.

| Hook | Payload |
|---|---|
| `cmf.*` | `MessagePayload` |
| `tool_pre_invoke` / `tool_post_invoke` | `ToolPreInvokePayload` / `ToolPostInvokePayload` |
| `prompt_pre_fetch` / `prompt_post_fetch` | `PromptPreFetchPayload` / `PromptPostFetchPayload` |
| `resource_pre_fetch` / `resource_post_fetch` | `ResourcePreFetchPayload` / `ResourcePostFetchPayload` |
| `identity_resolve` | `IdentityResolvePayload` |
| `token_delegate` | `TokenDelegatePayload` |
| anything else | `GenericPayload` |

A plugin error is returned to the executor, which applies the plugin's
configured `on_error` policy (fail / ignore / disable). This host does not
interpret that policy itself.

### Extensions

The capability-filtered `Extensions` the executor produced for a plugin is
serialized onto the task under an `extensions` field, so a 3-arg
`(payload, context, extensions)` hook sees out-of-process what its in-process
equivalent would. Slot visibility comes from the filtered view — this host does
not re-derive capability filtering.

Two rules apply in **both** directions:

- `raw_credentials` never rides this channel. Raw tokens travel the
  capability-gated `credential` DTO instead (see below).
- `Authorization`, `Cookie`, and `X-API-Key` are stripped from
  `http.request_headers` and `http.response_headers` (spec §3.5), matched
  case-insensitively.

A plugin's returned extensions come back on the response's
`modified_extensions` field — the field the Python `PluginResult` model already
carries, so returning extensions works the same way in and out of process. The
host rebuilds an `OwnedExtensions` and hands it to the executor's existing
copy-on-write merge, which enforces the mutability tiers. The host adds no tier
logic of its own; what it does add is two structural guarantees the merge relies
on:

| Slot | Tier | Out-of-process behavior |
|---|---|---|
| `request`, `agent`, `mcp`, `completion`, `provenance`, `llm`, `framework`, `meta` | Immutable | The inbound `Arc` is reused, so a forged edit is dropped before the merge sees it |
| `security` (labels) | Monotonic | Applied only with `append_labels`; the executor then enforces `before ⊆ after` |
| `delegation` | Monotonic | Applied only with `append_delegation` |
| `http` | Guarded | Applied only with `write_headers` |
| `custom` | Mutable | Applied as-is |

Reusing the inbound `Arc`s is load-bearing: the executor validates the immutable
tier with `Arc::ptr_eq`, and a JSON round trip allocates a fresh `Arc` for every
slot. Deserializing the whole object from the wire would fail that check on every
immutable slot and get the entire return rejected, even for a plugin that only
touched `custom`.

Write authority comes from the `WriteToken` the executor mints per plugin from
its declared capabilities and carries on the inbound view. `WriteToken::new()` is
`pub(crate)` to `cpex-core`, so this host cannot mint one — a gated write with no
token behind it is dropped rather than honored.

## Credentials

The token fields on the framework's credential types are `#[serde(skip)]`, so no
generic serialization of an `Extensions` carries token bytes — which would leave
identity resolvers and token delegators unable to work out-of-process. This host
adds a narrow, capability-gated exception on a separate channel: raw credential
material **does** reach the worker process, deliberately. `cpex-core`'s
`RawCredentialsExtension` module docs state the same boundary from the other
side.

A plugin declares what it needs:

```yaml
    capabilities: [read_inbound_credentials]   # or read_delegated_tokens
```

Only `identity_resolve` and `token_delegate` are eligible — they are the only
hooks whose Python payload models a raw token (`IdentityPayload.raw_token`,
`DelegationPayload.bearer_token`). For a declaring plugin on one of those hooks,
the host attaches a dedicated `credential` object to the task JSON, built by
reading the in-memory token directly. Production credential types keep their
serde guard and are never serialized; the FFI, Python-bindings, and audit paths
are untouched.

**Fail closed.** A plugin that declared nothing gets no `credential` field and
no token material. A plugin that declared a capability the request cannot honor
gets an error — not a silent no-token dispatch, which a resolver could read as
"no authentication required".

**Worker requirement.** The `credential` field is only consumed by a `worker.py`
that implements `reconstruct_credential_payload`. An older worker silently drops
it. Assert a minimum `cpex` version for credential-bearing plugins.

### Residual exposure

The capability gate controls *which plugin* receives a token. It does not
constrain what happens next: once the plaintext is resident in the worker
process, **every transitively installed dependency in that venv can read it**.
That is a materially larger and less audited trust boundary than the in-process
host, and neither the gate nor the transport closes it. Sending raw credentials
to an out-of-process plugin means accepting that venv's whole dependency tree
into the credential trust boundary.

The transport itself is sound by construction: the `credential` object rides on
the worker's stdin, a private pipe inherited only by the child. There is no
listening socket, and no other local process can read it.

## Venv cache

Reuse is keyed on a SHA256 of the requirements file plus the persisted
manifest's version and content hash. Layout mirrors the Python CLI's: `.venv`
and `.cpex/venv_cache` under `<plugin_dir>/<class_root>`.

Two deliberate behaviors:

- **A missing manifest signal means "no signal", not "mismatch."** Metadata
  written by an older CLI has no `manifest_version` / `manifest_hash` key.
  Treating an absent key as a mismatch would wipe and rebuild every existing
  venv on the first run after an upgrade.
- **Both the manifest and the metadata filename are keyed on the full class
  name.** Plugins sharing a package share one venv directory by design. The
  Python CLI keys only the manifest per class and derives the metadata filename
  from the venv directory name, so those plugins share one metadata file and
  each install invalidates its neighbour's cache — a rebuild loop. Keying both
  closes it, at the cost of one extra rebuild the first time this host meets a
  venv the Python CLI created.

## Testing

Unit tests run against a stub worker and need only `python3`:

```bash
cargo test -p cpex-hosts-python
```

The end-to-end tests need a `cpex` Python source tree, and **skip with a printed
reason** when one is absent rather than failing:

```bash
CPEX_PYTHON_SOURCE=/path/to/cpex-python \
  cargo test -p cpex-hosts-python --features testing --test isolated_venv_e2e --test credential_e2e
```

Two environmental caveats, both upstream of this crate:

- The Python framework's declared dependencies currently have no satisfiable
  resolution — `pyproject.toml` requires `mcp>=1.26`, but the framework imports
  `McpError`, which mcp renamed to `MCPError` in 1.26. The e2e tests therefore
  pre-build the venv in two pip passes (install as declared, then downgrade
  `mcp`) and let the host reuse it via its own cache.
- The Python hook registry registers no `cmf.*` hooks, so a CMF round-trip
  cannot be proven end to end yet. The host's CMF routing is covered by unit
  tests, and the e2e suite asserts that a CMF hook is rejected cleanly rather
  than silently allowed.
