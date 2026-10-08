---
title: "Configuration"
weight: 80
---

# Configuration

A CPEX config is one YAML document. It declares the plugins the process can reach, the cross-cutting wiring, and the policy that decides which of them run for a given operation. The engine loads it and the APL visitor wires routes to hooks.

Every key is known. A key the document model does not name fails the load, and where a key was renamed the error names its replacement. If your config loads, every key in it does something. Coming from 0.2.x? The [migration guide]({{< relref "/docs/migration-0.3#config-keys" >}}) maps every removed key.

## Shape

```yaml
engine_settings:  # dispatch mode and runtime limits
global:           # cross-cutting wiring, defaults, and policy
plugins:          # the plugins available, by kind
groups:           # reusable policy bundles routes opt into
routes:           # policy, one entry per operation
secrets:          # secret providers, and the values bound to them
```

Anything else is a load error. All six are optional.

```yaml
plugins:
  - name: ...
    kind: ...
    hooks: [...]
    capabilities: [...]
    config: { ... }

global:
  pdp:
    - kind: ...
  session_store:
    kind: ...

routes:
  - tool: <name>            # or resource: / prompt: / llm: / http:
    authentication: [ ... ] # identity-resolution plugins
    args: { ... }
    authorization:
      pre_invocation: [ ... ]
      post_invocation: [ ... ]
    result: { ... }
```

## Dispatch modes

`engine_settings.dispatch` picks between two mutually exclusive models. A document is legal in one of them only.

| Mode | What selects a plugin | Rejects |
|---|---|---|
| `policy` (default) | a `run(name)` step, an `authentication:` list, a `delegate(...)` call, or an elicitation verb | a per-plugin `conditions:` and `priority:`, and a list-form `plugins:` |
| `hooks` | each plugin's own `hooks:` and `conditions:` | `routes:`, `groups:`, `global:`, `global.defaults:` |

Under `dispatch: policy` a plugin runs only where a policy reaches it. Two consequences:

- The load reports a declared plugin no policy reaches, by name, and warns (`plugin_narrowed_by_policy`) when a plugin is reached on fewer hooks than it declares.
- Identity plugins run only on routes that list them under `authentication:`, at route, group, entity-default or global scope. A route that reads `subject.*` or `authenticated` must list one.

| Setting | Default | Meaning |
|---|---|---|
| `dispatch` | `policy` | which model above |
| `plugin_timeout` | `30` | per-plugin timeout, in seconds |
| `audit_timeout_milliseconds` | `100` | maximum time per audit sink callback |
| `short_circuit_on_deny` | `true` | stop a hook's remaining plugins once one denies |
| `route_cache_max_entries` | `10000` | dispatch-plan cache size |

`engine_settings:` also accepts `effect_log_path`, `effect_log_compaction_threshold`, `capture_content_provenance`, `content_provenance_key` and `audit_stream_namespace`, which configure durable effects and audit.

## What each scope accepts

A key outside its scope's set is a load error naming the scope and the set.

| Scope | Keys |
|---|---|
| the document | `global`, `plugins`, `groups`, `routes`, `secrets`, `engine_settings` |
| `global:` | `defaults`, `authentication`, `assertions`, `response`, `authorization`, `pdp`, `session_store`, `attribute_files` |
| `global.defaults.<entity>:` | `description`, `metadata`, `plugins`, `authentication`, `assertions`, `response`, `authorization`, `args`, `result` |
| `groups.<name>:` | the same set as `global.defaults.<entity>:` |
| `routes[]` | `tool`, `resource`, `prompt`, `llm`, `http`, `meta`, `groups`, `plugins`, `authentication`, `assertions`, `response`, `authorization`, `args`, `result` |
| an `authentication:` block | `steps`, `replace_inherited` |
| an `authentication:` step | `name`, `config` |

`pdp:`, `session_store:` and `attribute_files:` are `global:` only. `args:` and `result:` are not accepted under `global:`: write field pipelines on the route or on `global.defaults.<entity>:`. Under `dispatch: policy`, `plugins:` is a map of per-plugin overrides; the list form is a load error.

## Plugins

Each entry declares how a plugin is identified, where it runs, and what it may see:

| Field | Meaning |
|-------|---------|
| `name` | Instance name, referenced from policy as `run(name)` or `delegate(name, ...)`. |
| `kind` | Which implementation, for example `identity/jwt`. |
| `hooks` | The hook points it registers on. |
| `mode` | `sequential` (default), `transform`, `audit`, `concurrent`, `fire_and_forget`, or `disabled`. See [Plugins & Pipeline]({{< relref "/docs/pipeline" >}}). |
| `priority` | Order within a hook, lower first. `dispatch: hooks` only. |
| `on_error` | `fail` (default), `ignore`, or `disable`. |
| `capabilities` | Declared context access. See [Extensions & Capability-Gating]({{< relref "/docs/extensions" >}}). |
| `config` | Plugin-specific settings. |

```yaml
plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks: [identity.resolve]
    capabilities: [perform_http]
    config:
      role: user
      header: X-User-Token
      trusted_issuers:
        - issuer: "https://idp.example.com/realms/agents"
          audiences: ["cpex-gateway"]
          decoding_key:
            kind: jwks_url
            url: "https://idp.example.com/realms/agents/protocol/openid-connect/certs"

  - name: audit-log
    kind: acme/audit          # a host plugin the embedding program registers
    hooks: [cmf.tool_pre_invoke]
    capabilities: [read_subject, read_client, read_delegation]
```

A plugin that reaches outside the process must declare `perform_http`: an `identity/jwt` with a `jwks_url`, every `delegator/oauth`, every `elicitation/ciba`, and an `identity/api-key` with an HTTP directory. Withholding it stops the call rather than degrading it, because a plugin that quietly skipped its IdP call would fail open. The host must also install an HTTP transport; see [Builtins]({{< relref "/docs/builtins#the-http-transport" >}}).

## Global

```yaml
global:
  pdp:
    - kind: cedar-direct
      policy_text: |
        permit(principal, action == Action::"read", resource is Repo)
        when { principal.roles.contains("security") };
  session_store:
    kind: valkey
    endpoint: localhost:6379
  attribute_files:
    - attributes/tenants.yaml
```

`pdp:` is a sequence, one block per decision point. An entry may carry an optional `cache:` block with a positive `ttl_seconds` and `max_entries`; omitting it leaves evaluation uncached, and an external PDP's policy can go stale until the TTL expires. `session_store:` selects where taint labels live; without it, labels stay in an in-process memory store and do not survive a restart or reach a second replica. `attribute_files:` loads the operator-maintained tree policy reads under `data.*` (see [Static Attributes]({{< relref "/docs/apl/attributes" >}})).

## Routes

Routes carry the APL policy, one entry per operation, selected by `tool:`, `resource:`, `prompt:`, `llm:` or `http:`:

```yaml
plugins:
  - name: workday-oauth
    kind: delegator/oauth
    hooks: [token.delegate]
    capabilities: [perform_http]
    config: { ... }

routes:
  - tool: get_compensation
    authentication: [jwt-user]
    authorization:
      pre_invocation:
        - "require(role.hr)"
        - "delegate(workday-oauth, target: workday-api, audience: workday-api, permissions: [read_compensation])"
        - "taint(secret, session)"
        - "run(audit-log)"
    result:
      ssn: "str | redact(!perm.view_ssn)"
```

Both phase lists nest under `authorization:`. Writing `pre_invocation:` or `post_invocation:` directly on a route is a load error, and an `authorization:` block that contributes no step is rejected. An open route writes `pre_invocation: ["allow"]`. `args:` and `result:` stay directly on the route. See [APL]({{< relref "/docs/apl" >}}) for the policy syntax itself.

A `plugins:` map on a route adjusts a plugin's `capabilities`, `config` or `on_error` for that operation, so a scanner can be granted `read_labels` on one sensitive route without widening its access everywhere.

## Groups

A **group** is a named, reusable bundle of policy (`authentication:` steps, `authorization:` steps, field pipelines) that routes opt into. It is the middle layer between global defaults and per-route policy. Define groups at the top-level `groups:` section, keyed by name:

```yaml
groups:
  hr-tools:
    authentication: [jwt-manager]        # + identity for this group
    authorization:
      pre_invocation:
        - "require(role.hr)"             # + policy for this group
```

A route joins a group with the `groups:` field, a bare string or a list:

```yaml
routes:
  - tool: get_compensation
    groups: hr-tools                     # or: groups: [hr-tools, pii]
```

`groups:` is sugar over tags: `meta: { tags: [hr-tools] }` is exactly equivalent, and a host-injected runtime tag joins a group the same way when its name matches a group. A route that joins a group inherits both its `authentication:` and its `authorization:`. A group no route reaches fails the load.

## Requests with no entity

The host selects a route from the request's entity metadata, `meta.entity_type` and `meta.entity_name`. A request that carries none resolves no route. It is denied with the violation code `unidentified_request` and a 400-class status, distinct from a policy's own deny because no rule was reached. A config that declares no policy at all passes such a request through.

## Secrets and key material

There is no `${ENV}` substitution in config fields. A secret has one shape, and the config names where it comes from rather than carrying it.

### The `secrets:` block

A **provider** reads one backend. A **value** binds a name to one provider and one reference. Everything downstream names the value, never the provider and never a raw reference, so the set of secrets the process can reach is the `values:` map and nothing else.

```yaml
secrets:
  providers:
    local: { kind: file, base_dir: /etc/cpex }
    shell: { kind: env }
  values:
    upstream_api_key: { provider: local, ref: upstream.key }
    session_password: { provider: shell, ref: VALKEY_PASSWORD }
```

| kind | `ref` is | notes |
|---|---|---|
| `file` | a path | With `base_dir`, a reference must be relative and may not contain `..`. One trailing newline is stripped. An empty file is an error. |
| `env` | a variable name | Fixed at process start, so these never rotate without a restart. |
| `vault` | `<mount>/<path>#<field>` | Vault KV v2 over the host's HTTP transport. Kubernetes or AppRole auth. |

`file` covers Kubernetes Secret volumes, CSI-projected secrets and a Vault Agent sidecar writing to disk, so many deployments need no network backend.

Which providers are installed depends on the surface. The Python and Go bindings, and `cpex_apl_install` in the C ABI, install `env`, `file` and `vault`, with Vault on the same transport as the builtins. A Rust host installs them itself before `initialize()`:

```rust
use std::sync::Arc;
use cpex::praxis_policy_core::http::HttpTransport;
use cpex::{HyperTransport, PolicyEngine};

let engine = Arc::new(PolicyEngine::default());
cpex::install_builtins(&engine);
let transport: Arc<dyn HttpTransport> = Arc::new(HyperTransport::new());
engine.set_http_transport(Arc::clone(&transport));
engine.set_secret_providers(cpex::registry_with_vault(transport));
```

### Vault

```yaml
secrets:
  providers:
    vault-prod:
      kind: vault
      address: https://vault.example.com:8200
      auth:
        method: kubernetes
        role: cpex
  values:
    session_password: { provider: vault-prod, ref: secret/cpex#password }
```

The address must be `https://` unless `insecure_http: true`. An optional `namespace` is sent as `X-Vault-Namespace`. AppRole `secret_id` comes from an environment variable or a file. Token renewal is lazy, on the next read; nothing spawns a background ticker. A `403` on a read triggers one reauthentication and one retry.

An in-cluster Vault (Kubernetes service DNS, RFC 1918) is refused by the bundled transport unless the host opts in to private destinations. That opt-in applies to every outbound builtin, not only Vault; read [the warning]({{< relref "/docs/builtins#the-http-transport" >}}) before enabling it.

### Resolution and refresh

Shape is checked at load: a value naming an undeclared provider fails without contacting a backend. Every declared value is read during `initialize()`, before any plugin initializes, and a value that cannot be read stops startup.

After startup, the host decides when to re-read. Nothing in the engine re-reads on its own. Call refresh on an interval and alarm on the last-success time:

| Surface | Refresh | Last success |
|---|---|---|
| Rust | `engine.refresh_secrets().await` | `engine.secrets_last_success(provider)` |
| Python | `await engine.refresh_secrets()` | `engine.secrets_last_success(provider)` |
| Go | `engine.RefreshSecrets()` | `engine.SecretsLastSuccess(provider)` |
| C ABI | `cpex_refresh_secrets` | `cpex_secrets_last_success` |

A value that fails to re-read keeps its last good bytes, and the report names every failure without the secret itself. The interval you pick is the upper bound on how long a revoked credential stays in use.

### Per-plugin secret sources

OAuth and CIBA client secrets also take a typed `client_secret_source`:

```yaml
client_secret_source: { kind: env_var, name: OAUTH_CLIENT_SECRET }  # production-friendly
client_secret_source: { kind: file, path: /run/secrets/oauth }       # mounted secret
client_secret_source: { kind: literal, secret: dev-only }            # never in production
```

JWT signing material uses `decoding_key` on each `identity/jwt` trusted issuer: `jwks_url`, `pem`, `pem_file`, `jwk`, or `secret` (HMAC). A `jwks_url` is fetched at startup and refetched on demand when a token names an unknown `kid`, at most once per `min_refresh_interval_secs`. For a `jwks_url`, `insecure_http` defaults to `false`; set it `true` only to allow `http://` on localhost, never in production.

(The request-time templates like `${args.X}` used inside PDP and predicate steps are a separate mechanism, evaluated per request against the attribute bag, not config interpolation.)

## Resolution order

Under `dispatch: policy`, the steps that run for an operation are assembled in this order, with later layers winning on conflict:

1. always-on global policy,
2. the entity `defaults`,
3. groups the operation joins (via `groups:` or a matching tag),
4. the route itself.

Identity (`authentication:`) stacks the same way: global, entity default, groups, route. `replace_inherited: true` drops the inherited layers when a route needs a clean set.

## Validation

`load_config_yaml` validates on load and fails with an operator-facing message rather than starting in a bad state. Common errors:

- an unknown or renamed key, at any scope;
- a duplicate plugin `name`, or an unknown plugin `kind`;
- an unknown or removed hook name in `hooks:`;
- a declared plugin no policy reaches (under `dispatch: policy`);
- a route with no entity matcher, or with more than one (for example both `tool:` and `resource:`);
- an `authorization:` block with no step;
- a JWT trusted issuer with no `audiences`.

A missing `perform_http`, a missing HTTP transport, and an unreadable secret fail at `initialize()` instead, because they depend on what the host installed.

There is no hot reload or config versioning: load a changed config by rebuilding the engine.
