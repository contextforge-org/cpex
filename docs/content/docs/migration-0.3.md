---
title: "Migrating to 0.3"
weight: 125
---

# Migrating from 0.2.x to 0.3

CPEX 0.3.0 runs on the praxis-policy engine (PPE) 0.5.0 from crates.io instead of its own engine crates. The API names, hook names, several config keys, defaults and security checks change. This page lists every change a 0.2.x user has to act on, by surface.

Work through it in this order:

1. [Rust](#rust-api), [Python](#python-api), [Go](#go-api) or [C ABI](#c-abi-v3): rename the API calls for your surface.
2. [Hook names](#hook-names): rename `hooks:` entries and hook names your code invokes.
3. [Config keys](#config-keys): rewrite the policy document.
4. [Capabilities](#new-required-capability-perform_http), [dispatch](#dispatch-defaults-to-policy) and [egress](#outbound-http-and-private-destinations): the behavior changes that load fine but act differently.
5. [Builtins](#builtins-added-and-removed) and [secrets](#secret-refresh-is-the-hosts-job): the bundled set changed.

Load the migrated config through your own host. A 0.3.0 load names every key, hook and plugin it rejects, so read the whole error before fixing the first line.

PPE 0.5.0 also validates OAuth token responses more strictly: issued token type, granted scopes and JWT audience/subject are checked by default. Delegated-token keys include the delegator instance and logical target. Review IdP responses and policies that depend on token defaults. Secret assertions add `HttpExtension::secret_headers`; exhaustive Rust literals must initialize it and hosts must preserve its provenance between hooks. JSON float parsing uses `float_roundtrip`, so numeric boundaries and re-serialized audit records can change. See the [PPE 0.5.0 release notes](https://github.com/praxis-proxy/policy/releases/tag/v0.5.0) for the full Rust API changes.

## Rust API

| 0.2.x | 0.3.0 |
|---|---|
| `cpex::PluginManager` | `cpex::PolicyEngine` |
| `ManagerConfig` | `cpex::praxis_policy_core::engine::PolicyEngineConfig` |
| `cpex_sdk::*` | `cpex::prelude::*` |
| `cpex_core::factory`, `cpex_core::hooks::adapter`, `cpex_core::cmf` | `cpex::prelude::*` |
| `cpex_core::executor`, `::extensions`, `::identity`, `::elicitation` | `cpex::praxis_policy_core::executor`, `::extensions`, `::identity`, `::elicitation` |
| `cpex::PipelineResult` | `cpex::praxis_policy_core::executor::PipelineResult` |
| `apl_core`, `apl_cmf`, `apl_cpex` | `cpex::praxis_policy_apl_core`, `cpex::praxis_policy_apl_cmf`, `cpex::praxis_policy_apl_runtime` |
| `PluginSettings`, `PolicyConfig::plugin_settings` | `EngineSettings`, `PolicyConfig::engine_settings` |
| `routing_enabled()` | `dispatch_mode()` |
| `Phase::Policy`, `Phase::PostPolicy` | `Phase::PreInvocation`, `Phase::PostInvocation` |
| `CompiledRoute.policy`, `.post_policy` | `.pre_invocation`, `.post_invocation` |
| `.identity` on `GlobalConfig`, `PolicyGroup`, `RouteEntry` | `.authentication` |
| `compile_config`, `ConfigYaml`, `CompiledConfig` | removed; use `compile_policy_block_value` |
| `HOOK_CMF_HTTP_REQUEST`, `HOOK_CMF_HTTP_RESPONSE` | `praxis_policy_core::http_hook::HOOK_HTTP_REQUEST`, `HOOK_HTTP_RESPONSE` |
| `invoke_named::<CmfHook>` on an HTTP hook | `invoke_named::<HttpHook>` with `HttpPayload` |
| `Subject::claims: HashMap<String, String>` | `HashMap<String, Value>` |

`install_builtins` keeps its name. Two new calls sit beside it, because the builtins that make HTTP calls now borrow a transport from the host:

```rust
use std::sync::Arc;
use cpex::PolicyEngine;

let engine = Arc::new(PolicyEngine::default());
cpex::install_builtins(&engine);
cpex::install_default_http_transport(&engine); // or engine.set_http_transport(...)
engine.load_config_yaml(yaml)?;
engine.initialize().await?;
```

Without a transport, a plugin that needs one fails at `initialize()`, naming the missing host service. See [Outbound HTTP](#outbound-http-and-private-destinations).

Call `install_builtins` exactly once per engine. PPE 0.5.0 appends an APL visitor on every call and discards its handle, so a second install is a Rust host error and can process policy sections twice. `cpex::host::install_host_defaults` has the same once-per-engine requirement. The C/Go and Python bindings retain their own idempotency guards. The [upstream follow-up, PPE #208](https://github.com/praxis-proxy/policy/issues/208) requests an idempotent PPE helper; keep the host guard until that fix ships.

### Facade features

The facade features `builtins`, `full`, `jwt`, `oauth`, `elicitation-ciba`, `cedar`, `cel`, `valkey`, `pii` and `audit` are gone. Every stable builtin is always compiled in. The only feature left is `python-host`.

```toml
# 0.2.x
cpex = { version = "0.2", features = ["builtins"] }
# 0.3.0
cpex = "0.3"
```

### Removed crates

`cpex-core`, `cpex-sdk`, `cpex-orchestration`, `cpex-builtins`, `apl-core`, `apl-cmf`, `apl-cpex`, `cpex-plugin-pii-scanner`, `cpex-plugin-audit-logger`, `cpex-plugin-identity-jwt`, `cpex-plugin-delegator-oauth`, `cpex-plugin-elicitation-ciba`, `cpex-pdp-cedar-direct`, `cpex-pdp-cel`, `cpex-pdp-opa` and `cpex-session-valkey` are no longer built here. Their last release, 0.2.3, stays on crates.io and gets no further updates. Replace each dependency with `cpex` (or with `praxis-policy-core` for a plugin crate). Do not keep one of them beside `cpex` 0.3: the two engines do not share types.

### Plugin errors

A panic in a `sequential` or `transform` plugin is contained and reported as a violation with the code `plugin_panic`, so it denies like any other failed plugin under `on_error: fail`. A panicking `parallel:` branch is a deny.

## Python API

| 0.2.x | 0.3.0 |
|---|---|
| `from cpex import PluginManager` | `from cpex import PolicyEngine` |
| `PluginManager(config_path)` | `PolicyEngine(config_path, *, allow_private_destinations=False)` |
| (none) | `await engine.refresh_secrets()` |
| (none) | `engine.secrets_last_success(provider)` |

`PluginManager` remains as an alias (`PluginManager is PolicyEngine`), so existing imports keep working. New code uses `PolicyEngine`.

The constructor installs the builtins, one HTTP transport and the `env`, `file` and `vault` secret providers, then loads the config. `allow_private_destinations` is keyword-only; see [Outbound HTTP](#outbound-http-and-private-destinations). `invoke_hook` now needs `meta.entity_type` and `meta.entity_name` in its extensions to select a route; see [Dispatch](#dispatch-defaults-to-policy).

`validator/pii-scan` and `audit/logger` no longer resolve in the wheel. A config naming them fails to load with an unknown-kind error. See [Builtins removed](#removed).

`identity.resolve` takes a typed `IdentityPayload` dict: pass `{"source": "bearer", "headers": {"authorization": f"Bearer {token}"}}` with lowercased header names, plus the route's `meta` in the extensions. The resolved subject comes back in `modified_payload["subject"]`; copy it into `extensions["security"]["subject"]` for the tool call. See [Identity input](#identity-input) for the fields an input may set and what the result leaves out. Delegation (`delegate(...)` steps, `token.delegate`) is not available from Python, because inbound tokens do not cross back from an `identity.resolve` result. Drive delegation from Rust, or from Go with `InvokeResolved`.

The lifecycle calls are stricter:

- Calling `shutdown()` starts teardown immediately and refuses new work. Await its result to know when teardown has finished; dropping or cancelling the awaitable does not stop the shutdown task. It waits for an `initialize()` in flight, then tears down the plugins it started. One that raised `TimeoutError` can be retried, and the retry waits for the first to finish.
- An `initialize()` that raises `TimeoutError` keeps running; once it ends, the engine shuts down to stop the plugins it started. The engine is terminal from the timeout on, so build a new `PolicyEngine` to retry.
- `refresh_secrets()` raises `RuntimeError` when a secret provider panics.

## Go API

The Go module and the FFI artifact must come from the same CPEX release. The package checks the ABI version at init and panics on a mismatch, naming both versions.

| 0.2.x | 0.3.0 |
|---|---|
| `cpex.PluginManager` | `cpex.PolicyEngine` |
| `cpex.NewPluginManager(yaml)` | `cpex.NewPolicyEngine(yaml)` |
| `cpex.NewPluginManagerDefault()` | `cpex.NewPolicyEngineDefault()` |
| `mgr.EnableAPL()` | `engine.EnableAPL(opts ...APLOption)` |
| (none) | `cpex.WithPrivateDestinations()` |
| (none) | `engine.RefreshSecrets()` |
| (none) | `engine.SecretsLastSuccess(provider)` |
| `SubjectExtension.Claims map[string]string` | `map[string]any`: a claim keeps its JSON shape, so type-assert to read it |
| `SecurityExtension.Agent *AgentIdentity` | removed; use `ThisWorkload *WorkloadIdentity` (`SpiffeID`, `TrustDomain`, `ClientID`) |
| (none) | `SecurityExtension.Client`, `.CallerWorkload`, `Extensions.CandidateConstraint` |
| `Resource.Blob []byte` | `ByteArray`; a `[]byte` value still assigns, and it matches the Rust wire format |
| `DataPolicy.AllowedActions` empty allowed every action | nil allows every action; an empty non-nil slice allows none |

`EnableAPL` now also installs the HTTP transport and the secret providers. It is idempotent after a success: a second call does nothing, whatever its options. A call that panicked stays failed: it and every later call return an error wrapping `ErrCpexPanic`, because the engine may be half installed. Discard the engine and create a new one. `InvokeByName` callers must pass the new hook names (see [Hook names](#hook-names)), and an `identity.resolve` call must carry the route's `Meta` (entity type and name) like any other hook.

A plugin panic during `Invoke` now returns a nil error and a denied result whose violation code is `plugin_panic`. `ErrCpexPanic` is reserved for a panic in the FFI layer itself.

`LoadConfig` returns a typed error (for example a parse or pipeline error) without the engine's message text. The full message, naming the rejected key, hook or plugin, goes to the `tracing` log, so route the FFI log somewhere you can read while migrating a config.

## C ABI v3

`FFI_ABI_VERSION` is 3. A host built against ABI 2 fails its version check.

| ABI 2 | ABI 3 |
|---|---|
| `cpex_manager_new(yaml, len)` | `cpex_engine_new(yaml, len)` |
| `cpex_manager_new_default()` | `cpex_engine_new_default()` |
| `CpexManagerInner` (`.manager`) | `CpexEngineInner` (`.engine`) |
| `cpex_apl_install(mgr)` | `cpex_apl_install(handle, flags)` |
| (none) | `cpex_refresh_secrets(handle, &report, &len)` |
| (none) | `cpex_secrets_last_success(handle, provider, len, &unix_ms)` |

The other entry points (`cpex_load_config`, `cpex_initialize`, `cpex_invoke`, `cpex_invoke_resolved`, `cpex_shutdown` and the free functions) keep their names and take the engine handle.

A plugin panic inside `cpex_invoke` or `cpex_invoke_resolved` now returns `RC_OK` with a denied result whose violation code is `plugin_panic`. `RC_PANIC` is reserved for a panic in the FFI layer itself.

`cpex_apl_install` installs the builtins, one HTTP transport and the `env`, `file` and `vault` secret providers, with Vault on the same transport. `flags` is a bit set:

| Flag | Value | Meaning |
|---|---|---|
| `CPEX_APL_ALLOW_PRIVATE_DESTINATIONS` | `1` | let builtins reach private, loopback and link-local addresses |

Any other bit returns `RC_INVALID_INPUT`. The call is idempotent per handle after a success: a second call returns `RC_OK` and changes nothing. After a call that panicked, every later call returns `RC_PANIC`; free the handle and create a new one. `cpex_engine_new(yaml)` still registers no builtins and no transport.

`cpex_refresh_secrets` returns a MessagePack map `{updated, unchanged, failed}`; free it with `cpex_free_bytes`. `cpex_secrets_last_success` writes Unix milliseconds, or `0` when the provider has never refreshed successfully or the name is unknown. Failed refreshes retain the last successful timestamp; inspect `failed` to detect an outage.

## Hook names

The legacy unprefixed hook names are removed. A config that names one fails to load, and the error names the replacement.

| 0.2.x | 0.3.0 |
|---|---|
| `tool_pre_invoke` | `cmf.tool_pre_invoke` |
| `tool_post_invoke` | `cmf.tool_post_invoke` |
| `prompt_pre_fetch`, `cmf.prompt_pre_fetch` | `cmf.prompt_pre_invoke` |
| `prompt_post_fetch`, `cmf.prompt_post_fetch` | `cmf.prompt_post_invoke` |
| `resource_pre_fetch` | `cmf.resource_pre_fetch` |
| `resource_post_fetch` | `cmf.resource_post_fetch` |
| `identity_resolve` | `identity.resolve` |
| `token_delegate` | `token.delegate` |
| `cmf.http_request` | `http.request` |
| `cmf.http_response` | `http.response` |

Unchanged: `cmf.tool_pre_invoke`, `cmf.tool_post_invoke`, `cmf.llm_input`, `cmf.llm_output`, `cmf.resource_pre_fetch`, `cmf.resource_post_fetch`, `identity.resolve`, `token.delegate` and `elicit`.

This applies to three places: `hooks:` lists in config, Go `InvokeByName` and Python `invoke_hook` calls, and Python plugins run through the Python host (see [Python plugin host](#python-plugin-host)).

A removed name is also refused at invoke time. It would reach no handler and come back allowed with no policy evaluated, so Go `InvokeByName` and `InvokeResolved` return `ErrCpexInvalidInput`, Python `invoke_hook` raises `ValueError` naming the replacement, and C `cpex_invoke` and `cpex_invoke_resolved` return `RC_INVALID_INPUT`.

### Identity input

An `identity.resolve` input may set only `source`, `source_header`, `headers`, `client_host` and `client_port`. The other fields (`subject`, `client`, `caller_workload`, `delegation`, `raw_credentials`, `resolved_at`, `raw_claims`) are what resolvers fill in, and a caller that pre-filled them could forge the resolved identity. An input that sets one is refused: Python raises `ValueError`, Go returns `ErrCpexInvalidInput`, and the C ABI returns `RC_INVALID_INPUT`. This covers `invoke_hook("identity.resolve", ...)`, `InvokeByName(HookIdentityResolve, ...)`, `cpex_invoke` and the identity payload of `InvokeResolved` / `cpex_invoke_resolved`.

The result does not echo the request `headers`. They carry the credential header, so a host that logged or forwarded the result would leak the inbound token. Read the resolved fields (`subject`, `client`, `raw_claims` and the rest) from the result, and keep the headers you sent if you need them.

## Config keys

A 0.3.0 load rejects every key it does not know, at every scope, and names the replacement where one exists. A config that loads has no inert keys left.

### `global.apl:` is gone

```yaml
# 0.2.x
global:
  apl:
    pdp: [ ... ]
    session_store: { kind: valkey, endpoint: localhost:6379 }
    attribute_files: [ ./data/tenants.yaml ]
```

```yaml
# 0.3.0
global:
  pdp: [ ... ]
  session_store: { kind: valkey, endpoint: localhost:6379 }
  attribute_files: [ ./data/tenants.yaml ]
```

`pdp:`, `session_store:` and `attribute_files:` are valid only under `global:`.

### The `apl:` wrapper is gone everywhere

APL terms sit on the section that carries them: a route, `global:`, `global.defaults.<entity>:` or a group. `apl:` is an unknown key at every scope.

```yaml
# 0.2.x
routes:
  - tool: get_compensation
    apl:
      authorization:
        pre_invocation: ["require(authenticated)"]
      result:
        ssn: "redact(!perm.view_ssn)"
```

```yaml
# 0.3.0
routes:
  - tool: get_compensation
    authorization:
      pre_invocation: ["require(authenticated)"]
    result:
      ssn: "redact(!perm.view_ssn)"
```

### Phase lists nest under `authorization:`

Flat `pre_invocation:` and `post_invocation:` on a route are load errors. Nest them under `authorization:`.

An `authorization:` block that contributes no step also fails the load ("contributes no step"). This covers `authorization: {}` and every phase written as an empty list. An open route says so explicitly:

```yaml
routes:
  - tool: search_repos
    authorization:
      pre_invocation: ["allow"]
```

### Renamed and removed keys

Each key below fails the load and the error names what replaced it.

| 0.2.x key | Scope | 0.3.0 |
|---|---|---|
| `policy:` | any | `authorization.pre_invocation:` |
| `post_policy:` | any | `authorization.post_invocation:` |
| `identity:` | any | `authentication:` |
| `policies:` (`global.policies:`) | `global:` | top-level `groups:` |
| `plugin_settings:` | top level | `engine_settings:` |
| `routing_enabled: true` | `plugin_settings:` | `dispatch: policy` (the default) |
| `when:` | a route | a `when:` / `do:` step under `authorization:` |
| `plugin_dirs:` | top level | `register_factory()` plus a `plugins:` declaration |
| `parallel_execution_within_band` | `plugin_settings:` | `mode: concurrent` on the plugin |
| `fail_on_plugin_error` | `plugin_settings:` | `on_error: fail` on the plugin |
| `on_error:` | an `authentication:` step | `on_error:` on the plugin's own `plugins:` entry |
| `args:`, `result:` | `global:` | write them on the route or on `global.defaults.<entity>:` |

A group written under top-level `groups:` resolves exactly as one under `global.policies:` did.

### `plugin(name)` is `run(name)`

`plugin(name)` is rejected in step and stage position. Write `run(name)`. `plugin:` as a keyword inside `delegate(...)` still parses.

### Route `plugins:` lists

Under the default `dispatch: policy`, a list-form `plugins:` on a route, group, entity default or the `all` bundle is a load error. Name the plugin from a step instead:

```yaml
# 0.2.x
routes:
  - tool: get_compensation
    plugins: [audit-log]
```

```yaml
# 0.3.0
routes:
  - tool: get_compensation
    authorization:
      pre_invocation: ["run(audit-log)"]
```

For a plugin that ran on every request, write one `run(...)` step under `global.authorization:`. A `plugins:` map (per-plugin overrides of `config`, `capabilities` or `on_error`) still works.

### `priority:` and `conditions:` belong to hook dispatch

Under `dispatch: policy`, a per-plugin `priority:` or `conditions:` is a load error, because a step names the one plugin it runs. Order the steps instead. Both stay valid under `engine_settings: { dispatch: hooks }`, where `routes:`, `groups:` and `global:` are load errors in turn.

### Policy text

- A quoted literal processes exactly three escapes: `\\`, `\'` and `\"`. A regex class needs a doubled backslash: `regex("\\d+")`. A single backslash fails the load.
- An empty stage in a pipe chain (`"redact(...) |"`) fails the load.
- Malformed attribute paths (`a..b`, `a.`, `data.t[]`) fail the load instead of reading as absent.
- `not` is reserved (write `!`), and `&&` / `||` fail naming `&` / `|`.
- `require(a, b | c)` now parses as `!(a & (b | c))`. A config that was rejected for mixing `,` and `|` may now load; check what it decides.

PPE's [APL upgrade guide](https://github.com/praxis-proxy/policy/blob/v0.5.0/docs/content/upgrade-apl.md) covers each rule in detail.

## New required capability: `perform_http`

A plugin that reaches outside the process must declare `perform_http`:

- every `identity/jwt` plugin with a `jwks_url` decoding key,
- every `delegator/oauth` plugin,
- every `elicitation/ciba` plugin,
- an `identity/api-key` plugin with an `http` directory.

```yaml
plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks: [identity.resolve]
    capabilities: [perform_http]
    config: { ... }
```

A missing capability passes the load and fails at `initialize()` or on the first request that needs the call, with an error naming the plugin and the capability. Withholding it stops the call; it never degrades to an unchecked token.

## Dispatch defaults to `policy`

`engine_settings.dispatch` defaults to `policy`. Under it, a plugin runs only where a policy reaches it: a `run(name)` step, an `authentication:` list, a `delegate(...)` call or an elicitation verb. What this means in practice:

- **Identity runs only on routes that list it.** A route without `authentication:` (at route, group, entity default or global scope) does not run identity plugins, so no subject, `authenticated` or inbound credential reaches it. In 0.2.3 identity ran on every route. A route that reads `subject.*`, `role.*`, `authenticated` or that delegates must list `authentication:`. The simplest fix is `global: { authentication: [jwt-user] }`.
- **Requests need entity metadata.** Hosts select a route with `meta.entity_type` and `meta.entity_name`. A request without them resolves no route and is denied with `unidentified_request` (a 400-class code), as long as the config declares any policy. Python and Go callers pass them in the extensions; the [quick start]({{< relref "/docs/quickstart" >}}) shows the shape.
- **A config that only declares `plugins:`** and relied on all of them firing must write `engine_settings: { dispatch: hooks }`.

## Load-time failures

0.3.0 refuses at load several configs 0.2.x accepted:

- **Unreached plugins.** Under `dispatch: policy`, a declared plugin no policy reaches fails the load, by name. Reference it or drop it. A plugin reached on fewer hooks than it declares only logs a warning (`plugin_narrowed_by_policy`).
- **Unknown keys** at any scope, including misspellings inside `global:`, groups, `authentication:` steps and the JWT plugin's own config.
- **Unknown or removed hook names** in `hooks:`, with the nearest valid name.
- **An unknown plugin `kind`**, including `validator/pii-scan` and `audit/logger`.
- **A JWT issuer with no `audiences`.** An empty list used to disable the audience check. Set `skip_audience_validation: true` only if you mean it.
- **A delegating route with no identity resolution** is reported (`delegation_without_identity_resolution`) so you can add `authentication:`.

## Outbound HTTP and private destinations

The engine makes no HTTP calls of its own. Builtins that fetch JWKS, exchange tokens, poll CIBA or read Vault borrow one transport from the host. Every CPEX surface installs the bundled transport for you, except the plain Rust facade where you call `install_default_http_transport` or `set_http_transport`.

The bundled transport **refuses private destinations by default**. Each surface has one opt-in, set in host code. No policy document can turn it on.

| Surface | Opt-in |
|---|---|
| Rust | `HyperTransport::new().with_allow_private_destinations()`, installed with `engine.set_http_transport(...)` |
| Python | `PolicyEngine(path, allow_private_destinations=True)` |
| Go | `engine.EnableAPL(cpex.WithPrivateDestinations())` |
| C ABI | `cpex_apl_install(handle, CPEX_APL_ALLOW_PRIVATE_DESTINATIONS)` |

> **Blast radius.** The opt-in is not scoped to one plugin or host name. It permits loopback, RFC 1918 ranges, link-local addresses (including the cloud metadata endpoint at `169.254.169.254`) and CGNAT for every outbound builtin the engine runs: JWKS fetches, token exchange, CIBA and Vault. A policy author who can point a plugin at a URL can then reach anything on the host's network. The tutorial and the demos turn it on so they can reach a local IdP. Those settings are not for production. In production, reach in-cluster services through a host transport with its own egress rules (`set_http_transport`), or keep the default.

The C/Go and Python binding installers emit a startup warning through the host's tracing subscriber, or stderr if none is installed, when the opt-in is enabled. The warning names the shared scope, cloud metadata and CGNAT. The tutorial emits it too. Rust hosts using `HyperTransport` directly can call `cpex::host::warn_private_destinations()`. A private-host allow-list is [deferred upstream in PPE #209](https://github.com/praxis-proxy/policy/issues/209); PPE 0.5.0 has no narrower switch.

What a refused call looks like:

| Builtin | Symptom |
|---|---|
| `delegator/oauth` | `delegation.egress_denied` |
| `elicitation/ciba` | `elicitation.egress_denied` |
| `identity/jwt` (`jwks_url`) | `auth.jwks_unavailable`: the request is denied as if the IdP were down |
| `vault` secret provider | `initialize()` fails with a backend error naming the value |

If a JWT route that worked on 0.2.3 now denies with `auth.jwks_unavailable` and the JWKS URL is on `localhost` or a private address, this is the cause.

## Builtins added and removed

### Added

| Kind | Type | Notes |
|---|---|---|
| `opa` | PDP | Embedded Rego. Now in the Python and Go builds too. |
| `elicitation/ciba` | elicitation channel | Now in the Python and Go builds too. |
| `identity/api-key` | identity resolver | Opaque keys against a file or HTTP directory. New. |
| `vault` | secret provider | Vault KV v2. The Python and Go builds install it. A Rust host calls `cpex::registry_with_vault(transport)` and `engine.set_secret_providers(...)`. |

`env` and `file` secret providers and the top-level `secrets:` block are also new. See [Configuration]({{< relref "/docs/configuration#secrets-and-key-material" >}}).

### Removed

`validator/pii-scan` and `audit/logger` are no longer bundled on any surface. A config that names either fails to load with an unknown-kind error. Replacements:

| 0.2.x | 0.3.0 |
|---|---|
| `run(pii-scan)` in `mode: deny` | a CEL or APL deny step on the arguments you care about (example below) |
| `pii-scan` in `mode: redact` | an APL field pipeline on the field: `"str \| redact"`, or `"str \| redact(!perm.view_ssn)"` to redact by permission |
| `audit/logger` | a host plugin of your own registered under a `kind` you choose; keep the plugin `name` so `run(audit-log)` steps stay unchanged. See [Auditing]({{< relref "/docs/auditing" >}}). |

A deny step that refuses an SSN-shaped value in one argument:

```yaml
global:
  pdp:
    - kind: cel

routes:
  - tool: send_email
    authorization:
      pre_invocation:
        - cel:
            expr: "!has(args.body) || !args.body.matches('[0-9]{3}-[0-9]{2}-[0-9]{4}')"
            on_deny: ["deny('SSN pattern in body', 'pii.detected')"]
```

A regex is not data-loss prevention. For real detection, register a host plugin backed by a detector you trust (Presidio, a cloud DLP API) and call it with `run(...)`.

A Rust host that wants the old behavior can still run PPE's reference implementations. They are `publish = false`, so copy their source into your own workspace and build it against `praxis-policy-core` from crates.io. Do not add them as a git dependency: that builds a second copy of the core crate with types that do not match the one `cpex` links. See [Builtins]({{< relref "/docs/builtins#reference-plugins-in-a-rust-host" >}}). The Python and Go builds cannot load them.

## Secret refresh is the host's job

The engine reads every declared secret once, at `initialize()`, and never re-reads on its own. Now that the bindings ship Vault, a binding host that rotates secrets must call refresh itself:

| Surface | Refresh | Health |
|---|---|---|
| Rust | `engine.refresh_secrets().await` | `engine.secrets_last_success(provider)` |
| Python | `await engine.refresh_secrets()` | `engine.secrets_last_success(provider)` |
| Go | `engine.RefreshSecrets()` | `engine.SecretsLastSuccess(provider)` |
| C ABI | `cpex_refresh_secrets` | `cpex_secrets_last_success` |

Call refresh on an interval and alarm when a provider's last success is older than you can tolerate. A value that fails to re-read keeps its last good bytes and is listed in the report, so a Vault outage degrades to a stale credential, not to none. The interval is the upper bound on how long a revoked credential stays in use.

## Python plugin host

The `isolated_venv` host (`python-host` feature) follows the new hook names. Declare PPE names in config (`cmf.tool_pre_invoke`, `identity.resolve`, `token.delegate`); the host translates them on the wire to the names the Python worker knows.

The released 0.1.x Python worker registers no `cmf.*` hooks. For a worker that does not claim the `cmf_hooks` capability at spawn time, the host translates each tool, prompt and resource `cmf.*` hook into the legacy hook and typed payload the worker expects (`tool_pre_invoke` with `{name, args}`, and so on), then maps the result back. A 0.1.x plugin keeps working with no SDK release: declare `cmf.tool_pre_invoke` in config and keep implementing `tool_pre_invoke` in Python.

The translation fails closed with `legacy_shim_unsupported` when it cannot represent a request faithfully. It never allows or skips. A plugin declaring `cmf.llm_input` or `cmf.llm_output` fails initialization unless the worker reports `cmf_hooks`, because those hooks have no legacy equivalents. Shim refusal cases include a message without exactly one matching content part; on a post hook (`cmf.tool_post_invoke`, `cmf.prompt_post_invoke`, `cmf.resource_post_fetch`), any other part that carries text or data, since the plugin cannot see or redact it; a non-string prompt argument; a qualifier a legacy plugin that authorizes by bare name or URI cannot see (a tool call `namespace`, a prompt `server_id`, a resource `version`); a binary resource; an error result the legacy payload cannot mark; and a modified payload that sets something the message cannot hold or would leave stale data behind. The full list is in the [Python host README](https://github.com/contextforge-org/cpex/tree/main/crates/cpex-hosts-python#cmf-hooks-on-workers-without-cmf_hooks-the-legacy-payload-shim). A worker that claims `cmf_hooks` receives the CMF message directly. On a pre hook (`cmf.tool_pre_invoke`, `cmf.prompt_pre_invoke`, `cmf.resource_pre_fetch`), parts beside the one the legacy payload carries, such as narration text beside a tool call, pass through unchanged: the plugin authorizes the part it sees.

On `identity.resolve` and `token.delegate` the host accepts PPE's `IdentityPayload` and `DelegationPayload`, which PPE's FFI, its Python bindings and the APL `delegate(...)` step build. The plugin keeps reading the Python `IdentityPayload` / `DelegationPayload` it already knows, and its `IdentityResult` / `DelegationResult` maps back onto PPE's payload.

Two credential rules change:

- A delegator on PPE's `DelegationPayload` receives the caller's bearer token only when it declares `read_inbound_credentials`, as PPE's own OAuth delegator does. A plugin that declared only `read_delegated_tokens` now gets an error instead of the token. Add `read_inbound_credentials` to its `capabilities:`.
- A Python worker plugin that does not declare `read_inbound_credentials` receives no raw request header values in the public identity payload. The out-of-process `http` extension also sends empty request and response header maps by default, even with `read_headers`; its request-line fields still cross. A plugin that declares `read_inbound_credentials` receives the full identity header map through the gated credential object.

## What each surface can do

The engine is the same everywhere, but not every feature reaches every surface in 0.3.0:

| Feature | Rust | Python | Go |
|---|---|---|---|
| `http:` routes and the `http.request` / `http.response` hooks | yes | no: the HTTP hooks expect an `HttpPayload` the binding cannot build | no: the FFI has no payload type for the HTTP hooks |
| Delegation (`delegate(...)`, `token.delegate`) | yes | no | yes, with `InvokeResolved` |
| Audit sinks next to `routes:` | no (see below) | no | no |
| Registering your own plugin factories | yes | no | yes, through a linked Rust FFI crate |

**Audit sinks and routes.** Under `dispatch: policy`, PPE 0.5.0 fails the load for a sink no step names, and `run(<sink>)` denies because a sink has no hook handler to call. Until PPE changes this, a config with routes cannot attach an audit sink. Use a hook plugin that a `run(...)` step names, or log the `PipelineResult` each call returns (it carries the verdict and violation code). See [Auditing]({{< relref "/docs/auditing" >}}).

**Host-supplied client identity.** A host can set `security.client` in the extensions it passes, but route rules see `client.*` only when a plugin the route references declares `read_client`. A route whose rules read `client.*` with no such plugin reads absent values. Resolve the client with an `identity/jwt` plugin (`role: client`) on the route, or reference a plugin that declares `read_client`. See [CMF Extensions]({{< relref "/docs/cmf-extensions" >}}).

**JWT deny codes.** `identity/jwt` reports `auth.token_expired`, `auth.signature_invalid`, `auth.malformed*` and `auth.jwks_unavailable`, among others. A route that matched on 0.2.x reason text should match on these codes.

## Intended behavior differences

The parity suite replays 0.2.3 decision snapshots through 0.3.0. Every request reaches the same decision. These differences are expected:

| Difference | Cause |
|---|---|
| Rule-path deny codes drop the `.apl.` segment: `routes.tool:x.apl.pre_invocation[0]` is now `routes.tool:x.pre_invocation[0]` | The `apl:` wrapper is gone. Same decision, same step index. Steps with a custom code are unaffected. |
| An OAuth token-exchange denial reason no longer carries the IdP's `error_description`, only the OAuth `error` code (`token exchange rejected: invalid_target`) | Security fix: an IdP may echo the submitted token in its description. The violation code is unchanged. |
| A token with an unknown `kid` triggers one JWKS refetch, rate limited by `min_refresh_interval_secs` | JWKS refresh is on demand instead of on a timer. The token is still rejected with the same code if the key is not there. |
| A route without `authentication:` does not run identity plugins, so no subject or inbound credential reaches it | The [dispatch default](#dispatch-defaults-to-policy). |

Valkey session labels written by 0.2.3 are read back unchanged: the key layout (`sha256(subject : session id)`) is the same.

Other changes that can alter a decision, from PPE's own changelog:

- `!=` on a missing attribute is true, so `subject.role != "admin": deny` now fires for a caller with no role.
- A non-numeric or non-finite value in an order comparison (`args.amount > 10000`) fails closed instead of skipping the rule.
- A route that joins a group with `groups:` now inherits the group's `authorization:`, not only its `authentication:`.
- `global.defaults.<entity>.authentication:` is now applied.
- OPA and CEL read `args` on `tool:` routes as native JSON: number arrays hold numbers, arrays keep order and duplicates, and an explicit `null` is present. Review every OPA or CEL rule that reads `args`. See [PDP Integration]({{< relref "/docs/apl/pdp#migrating-args-policies" >}}).
- Subject claims keep their JSON shape, so a nested claim such as `realm_access.roles` is a set policy can test.

## CEL notes

PPE 0.5.0 uses `cel` 0.15. Use `in` for list membership; container `.contains()` and the default `min` / `max` functions are not available. String `size()` counts Unicode code points rather than UTF-8 bytes, and `exists()` can return true after another element errors. Review policies depending on byte limits or predicate errors. `CelResolver::with_functions` and its callback now return `Result`; conflicting standard-library overloads fail construction.

## Elicitation approvals are bound and single use

PPE 0.5.0 binds CIBA approvals to the authenticated requester, selected route and tool, and redeems each approval once within the plugin instance. A request with no subject id fails before dispatch. Another subject cannot reuse an approval, and a second redemption is refused. This fixes the approval-reuse limitation present in 0.2.3 and PPE 0.4.1.

Keep approval `timeout` short and return elicitation ids only to the requesting client. The parity fixture records the intended change from allow to deny when a second subject retries a redeemed id.
