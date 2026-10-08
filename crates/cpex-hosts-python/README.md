# cpex-hosts-python

Runs existing Python CPEX plugins out-of-process from the Rust `PolicyEngine`.
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
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::factory::PluginFactoryRegistry;
use cpex_hosts_python::{IsolatedVenvFactory, KIND};

let mut factories = PluginFactoryRegistry::new();
factories.register(KIND, Box::new(IsolatedVenvFactory));

let engine = PolicyEngine::from_config(config, &factories)?;
```

Through the `cpex` facade, enable the `python-host` feature and register
`cpex::IsolatedVenvFactory` under `cpex::ISOLATED_VENV_KIND`.

## Config schema

Host-specific settings live in the plugin entry's opaque `config:` map, because
`PluginConfig` has no fields for them:

```yaml
engine_settings:
  dispatch: hooks      # or name the plugin from a policy step
plugins:
  - name: pii-filter
    kind: isolated_venv
    hooks: [cmf.tool_pre_invoke]
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
  factory logs a warning naming the plugin), so a config carrying it still
  loads, and
- the top-level `plugin_dirs:` YAML key is **rejected**: PPE's config loader
  refuses unknown document keys. `cpex plugin install` still writes that key, so
  remove it from an installer-written `config.yaml`.

This is deliberate. `cpex plugin install` writes the plugin into
`<project root>/plugins/` and builds its venv there, so both sides already agree
on the location; a config key only creates a way for them to disagree, and the
failure mode is an `ImportError` inside the worker at invoke time — far from the
config that caused it. The worker independently restricts plugin dirs to its own
`ALLOWED_PLUGIN_DIRS`, which includes its working directory (inherited from this
host), so the resolved directory is importable by construction.

## Hooks and payloads

Hook names follow PPE. The host looks each declared name up in a fixed table
that picks the payload type and the name the Python worker knows the hook by.
The Python framework still registers the older spellings, so the host
translates on the wire (the task's `hook_type` and the config's `hooks` list).

| Declared hook (PPE) | Payload | Worker hook name |
|---|---|---|
| `cmf.tool_pre_invoke` / `cmf.tool_post_invoke` | `MessagePayload` | same |
| `cmf.llm_input` / `cmf.llm_output` | `MessagePayload` | same |
| `cmf.prompt_pre_invoke` / `cmf.prompt_post_invoke` | `MessagePayload` | `cmf.prompt_pre_fetch` / `cmf.prompt_post_fetch` |
| `cmf.resource_pre_fetch` / `cmf.resource_post_fetch` | `MessagePayload` | same |
| `identity.resolve` | PPE's `IdentityPayload` (or the legacy `IdentityResolvePayload`) | `identity_resolve` |
| `token.delegate` | PPE's `DelegationPayload` (or the legacy `TokenDelegatePayload`) | `token_delegate` |
| anything else | `GenericPayload` | unchanged |

### Identity and delegation payloads

PPE dispatches `identity.resolve` with `praxis_policy_core::identity::IdentityPayload`
and `token.delegate` with `delegation::DelegationPayload`; its FFI, its Python
bindings and the APL `delegate(...)` step all build those. The host sends each
to the worker as the matching Python model and maps the plugin's
`IdentityResult` / `DelegationResult` back onto a clone of the dispatched
payload, so PPE's `IdentityPayload::from_pipeline_result` and
`DelegationPayload::from_pipeline_result` find it.

| Direction | What happens |
|---|---|
| `IdentityPayload` out | `source`, `client_host`, `client_port`, and the request headers minus every credential-bearing one (the source header, `authorization`, `proxy-authorization`, cookies, `x-api-key`, and any header holding the token). `raw_token` is sent empty. |
| `IdentityResult` back | `subject` and `delegation` are written, `raw_claims` merged. `rejected: true` becomes a deny (`auth.rejected`, with `reject_reason` and `reject_status`). Echoed input fields are ignored, as PPE treats them as canonical. Any other field, or a field PPE's types cannot hold, fails closed. |
| `DelegationPayload` out | Target name, type, audience, permissions, trust domain, enforcement and attenuation. `bearer_token` is not sent. A delegation with an RFC 8693 actor, or for a subject other than `user`, fails closed: the Python model cannot carry either. |
| `DelegationResult` back | `delegated_token` becomes PPE's `delegated_token` for the target audience and required permissions, expiring after `cache_ttl` (60 seconds when unset). `forwarded_headers` may only name the one header carrying the minted token; anything else fails closed. `delegation_update` is written when it is not empty. |

The raw tokens on both payloads reach a plugin only through the
capability-gated `credential` object (see [Credentials](#credentials)).

The `cmf.*` rows apply to a worker that claims the `cmf_hooks` feature in the
spawn-time `capabilities` handshake. No released worker does yet, so in
practice the `cmf.*` hooks go through the legacy payload shim below.

### CMF hooks on workers without `cmf_hooks` (the legacy payload shim)

The released 0.1.x Python SDK registers no `cmf.*` hook in the worker, and its
plugins implement `tool_pre_invoke` and friends with the typed payloads. So for
any worker that does not claim `cmf_hooks`, the host translates each tool,
prompt and resource `cmf.*` hook into the legacy hook and payload the worker
already knows, and maps the result back. A 0.1.x plugin keeps working with no
SDK release: declare `cmf.tool_pre_invoke` and implement `tool_pre_invoke`.

| PPE hook | Built from (CMF part) | Legacy hook and payload sent | Mapped back onto the part |
|---|---|---|---|
| `cmf.tool_pre_invoke` | `tool_call` | `tool_pre_invoke`: `{name, args}` | `name`, `arguments` |
| `cmf.tool_post_invoke` | `tool_result` | `tool_post_invoke`: `{name: tool_name, result: content}` | `tool_name`, `content` |
| `cmf.prompt_pre_invoke` | `prompt_request` | `prompt_pre_fetch`: `{prompt_id: name, args}` | `name`, `arguments` |
| `cmf.prompt_post_invoke` | `prompt_result` | `prompt_post_fetch`: `{prompt_id: prompt_name, result: {messages: [{role, content: {type: "text", text}}], description: null}}` | `prompt_name`, `messages` (role and text; a message keeps its `channel`) |
| `cmf.resource_pre_fetch` | `resource` or `resource_ref` | `resource_pre_fetch`: `{uri}` | `uri` |
| `cmf.resource_post_fetch` | `resource` | `resource_post_fetch`: `{uri, content: {type: "resource", id, uri, mime_type, text}}` | `uri`, `content` (text), `mime_type`; `size_bytes` is recomputed when the text changes |

The worker's `continue_processing` and `violation` pass through unchanged. A
modified legacy payload replaces only the fields in the last column; every
other field of the message and of the part is kept as dispatched. A modified
tool result that sets `"isError": true` also sets the part's `is_error`.

The shim fails closed, with a `legacy_shim_unsupported` error naming the hook
and the plugin, rather than allowing or skipping:

- `cmf.llm_input` and `cmf.llm_output`, which have no legacy hook;
- a message without exactly one content part of the kind in the second column
  (for example a `cmf.tool_pre_invoke` message with no tool call, or with two);
- on a post hook (`cmf.tool_post_invoke`, `cmf.prompt_post_invoke`,
  `cmf.resource_post_fetch`), a message holding any other content part that
  carries text or data (a text or thinking part with text, a media part,
  another tool or resource part): the plugin never sees it, so a filter would
  pass it through unredacted. Empty text and thinking parts are kept. On a pre
  hook such sibling parts pass through unchanged: the plugin authorizes the
  part it sees, and the rest of the message goes back as dispatched;
- a prompt argument that is not a string (the legacy `args` is
  `dict[str, str]`);
- a qualifier a plugin that authorizes by bare name or URI cannot see: a tool
  call `namespace`, a prompt request `server_id`, or a resource `version`
  (each when non-empty);
- a tool result with `is_error` set whose `content` does not carry
  `"isError": true`;
- a prompt result with rendered `content`, an `error_message`, or `is_error`
  set (the legacy result holds only messages, so a plugin could not redact
  that text);
- a prompt result message that is not a single text part;
- a resource with a binary `blob`, or a `resource_ref` on post-fetch;
- a modified payload that sets something the message cannot hold: tool
  `headers`, resource `metadata`, a prompt result `description`, a resource
  `content.blob`, a changed resource `content.id`, a `content.uri` other than
  the original or the returned `uri`, or non-text prompt message content;
- a modified payload that would leave stale data behind: a cleared `isError`
  on an error tool result, or a pre-fetch URI rewrite on a resource that
  already carries `content`, `blob`, `mime_type` or `size_bytes` from the
  original URI.

The field-by-field decision for every CMF part field is the table at the top
of `src/legacy/cmf_shim.rs`.

The shim lives in `src/legacy/cmf_shim.rs`. It goes away once every supported
worker claims `cmf_hooks`.

The unprefixed `tool_pre_invoke`, `tool_post_invoke`, `prompt_pre_fetch`,
`prompt_post_fetch`, `resource_pre_fetch` and `resource_post_fetch` keep their
typed payloads (`ToolPreInvokePayload` and so on). PPE does not dispatch them
and its config loader rejects them, so they only apply to a host that registers
hook metadata for them (`praxis_policy_core::hooks::register_hook_metadata`)
before loading config. The unprefixed `identity_resolve` and `token_delegate`
are not in the table: they get the generic payload and no raw credential.

The adapter reports the hook family of each declared name (`cmf` for the CMF
hooks), so the engine's family check at registration accepts it.

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
`pub(crate)` to `praxis-policy-core`, so this host cannot mint one. A gated write with no
token behind it is dropped rather than honored.

## Credentials

The token fields on the framework's credential types are `#[serde(skip)]`, so no
generic serialization of an `Extensions` carries token bytes — which would leave
identity resolvers and token delegators unable to work out-of-process. This host
adds a narrow, capability-gated exception on a separate channel: raw credential
material **does** reach the worker process, deliberately. `praxis-policy-core`'s
`RawCredentialsExtension` module docs state the same boundary from the other
side.

A plugin declares what it needs:

```yaml
    capabilities: [read_inbound_credentials]   # or read_delegated_tokens
```

Only `identity.resolve` and `token.delegate` are eligible: they are the only
hooks whose Python payload models a raw token (`IdentityPayload.raw_token`,
`DelegationPayload.bearer_token`). For a declaring plugin on one of those hooks,
the host attaches a dedicated `credential` object to the task JSON, built by
reading the in-memory token directly. Production credential types keep their
serde guard and are never serialized; the FFI, Python-bindings, and audit paths
are untouched.

Where the token comes from depends on the payload:

| Hook and payload | Token | Capability |
|---|---|---|
| `identity.resolve`, PPE `IdentityPayload` | `raw_token`, else the source header (a `Bearer ` prefix stripped). The gated object also carries the full header map, which the worker scrubs of the token. | `read_inbound_credentials` |
| `token.delegate`, PPE `DelegationPayload` | `bearer_token`, the caller's inbound credential | `read_inbound_credentials`, as PPE's own OAuth delegator declares |
| `identity.resolve`, legacy payload | the inbound token in `raw_credentials` | `read_inbound_credentials` |
| `token.delegate`, legacy payload | the delegated token in `raw_credentials` for the target audience | `read_delegated_tokens` |

A plugin on the same hook that declared nothing sees no token, and none of the
credential-bearing headers.

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
  cargo test -p cpex-hosts-python --features testing --test isolated_venv_e2e \
  --test credential_e2e --test acceptance_e2e -- --ignored
```

`make test-python-e2e CPEX_PYTHON_SOURCE=...` runs the same suites with skips
turned into failures. `acceptance_e2e` loads a policy with Python plugins on
`identity.resolve` and `token.delegate` plus an APL route, and drives PPE's own
`IdentityPayload` and the route's `delegate(...)` step through `PolicyEngine`.

Two environmental caveats, both upstream of this crate:

- Older Python framework checkouts import `McpError` while declaring
  `mcp>=1.26`, which renamed that symbol to `MCPError`. The e2e tests downgrade
  `mcp` in their pre-built venv only for those older checkouts. Current checkouts
  use the declared version, and the host reuses the cached venv in both cases.
- The 0.1.x Python worker registers no `cmf.*` hooks and does not report the
  `cmf_hooks` feature, so the host translates `cmf.*` tool, prompt and resource
  payloads to the legacy shapes for it (see the legacy worker section above).
  The e2e suite runs 0.1.x plugins on `cmf.tool_pre_invoke` through that
  translation, and checks that a message it cannot represent fails closed.
