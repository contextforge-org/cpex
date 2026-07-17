---
title: "Configuration"
weight: 80
---

# Configuration

A CPEX config is a single document that declares the plugins and PDP resolvers available, the global settings, and the APL routes. The runtime loads it and the APL visitor wires routes to hooks.

## Shape

```yaml
plugins:        # the plugins available to policy, by kind
  - name: ...
    kind: ...
    hooks: [...]
    capabilities: [...]
    config: { ... }

global:         # cross-cutting resolvers and stores
  pdp:
    - kind: ...
  session_store:
    kind: ...

routes:         # APL policy, a list of operations
  - tool: <name>            # or resource: / prompt: / llm:
    authentication: [ ... ] # identity-resolution plugins
    args: { ... }
    authorization:
      pre_invocation: [ ... ]
      post_invocation: [ ... ]
    result: { ... }
```

## Plugins

Each plugin entry declares how it is identified, where it runs, and what it may see:

| Field | Meaning |
|-------|---------|
| `name` | Instance name, referenced from APL (`plugin(name)`, `delegate(name, ...)`). |
| `kind` | Which plugin implementation (for example `identity/jwt`, `audit/logger`). |
| `hooks` | The hook points it registers on. |
| `mode` | Execution mode (see [Plugins & Pipeline]({{< relref "/docs/pipeline" >}})). |
| `priority` | Order within a hook; lower runs first. |
| `on_error` | `fail`, `ignore`, or `disable`. |
| `capabilities` | Declared context access (see [Extensions & Capability-Gating]({{< relref "/docs/extensions" >}})). |
| `config` | Plugin-specific settings. |

```yaml
plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks: [identity.resolve]
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
    kind: audit/logger
    hooks: [cmf.tool_pre_invoke]
    priority: 90
    capabilities: [read_subject, read_client, read_delegation]
```

## Global

`global.pdp` registers PDP resolvers; `global.session_store` selects where taint labels live (absent it, the in-process memory store is used).

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
```

## Routes

Routes carry the APL policy. The runtime loads routes as a **list**, one entry per operation, matched by `tool:` (or `resource:` / `prompt:` / `llm:`):

```yaml
routes:
  - tool: get_compensation
    authorization:
      pre_invocation:
        - "require(role.hr)"
        - "delegate(workday-oauth, target: workday-api, audience: workday-api, permissions: [read_compensation])"
        - "taint(secret, session)"
        - "plugin(audit-log)"
    result:
      ssn: "str | redact(!perm.view_ssn)"
```

Within a route, the two authorization phases may be written nested under `authorization:` (as above) or flat, as `pre_invocation:` / `post_invocation:` directly on the route; the two are equivalent.

> **Runtime config vs. apl-core.** The `apl-core` crate also accepts a map-keyed `routes:` form (keyed by route name) through its standalone `compile_config` entry point, used mainly in tests. The runtime host path (`load_config_yaml`) does not: it parses the list form shown here. Write the list form for anything you load into a running CPEX. See [APL]({{< relref "/docs/apl" >}}) for the policy syntax itself.

Route-level overrides can adjust a plugin's `capabilities` or `config` for a specific operation, so a scanner can be granted `read_labels` on one sensitive route without widening its access everywhere.

## Global settings and defaults

Every top-level section (`plugins`, `global`, `routes`, `plugin_dirs`, `plugin_settings`) is optional. `plugin_settings` controls runtime behavior:

| Setting | Default | Meaning |
|---------|---------|---------|
| `routing_enabled` | `false` | `false`: each plugin self-selects via its own `conditions:`. `true`: `routes:` / `global:` drive selection and per-plugin `conditions:` are ignored. Route-based configs set this `true`. |
| `plugin_timeout` | `30` | Per-plugin timeout, in seconds. |
| `short_circuit_on_deny` | `true` | Stop a hook's remaining plugins once one denies. |
| `fail_on_plugin_error` | `false` | Whether a plugin error fails the request (see also per-plugin `on_error`). |
| `parallel_execution_within_band` | `false` | Run same-priority plugins concurrently. |
| `route_cache_max_entries` | `10000` | Dispatch-plan cache size. |

Per-plugin fields default to `mode: sequential`, `on_error: fail`, and a `priority` that orders plugins within a hook (lower runs first).

## Secrets and key material

CPEX does not interpolate environment variables into arbitrary config values; there is no `${ENV}` substitution of config fields. Secrets are injected through typed source enums on the plugins that need them.

OAuth and CIBA client secrets use `client_secret_source`:

```yaml
client_secret_source: { kind: env_var, name: OAUTH_CLIENT_SECRET }  # production-friendly
client_secret_source: { kind: file, path: /run/secrets/oauth }       # mounted secret
client_secret_source: { kind: literal, secret: dev-only }            # never in production
```

JWT signing material uses `decoding_key` on each `identity/jwt` trusted issuer: `jwks_url` (fetched and cached; `refresh_secs` default 600), `pem`, `pem_file`, `jwk`, or `secret` (HMAC). For a `jwks_url`, `insecure_http` defaults to `false`; set it `true` only to allow `http://` on localhost, never in production.

(The request-time templates like `${args.X}` used inside PDP and predicate steps are a separate mechanism, evaluated per request against the attribute bag, not config interpolation.)

## Resolution order

With `routing_enabled: true`, the plugins that run for an operation are assembled and de-duplicated in this order, with later layers winning on conflict:

1. the `all` policy group,
2. the entity `defaults`,
3. policy groups whose tags match the operation,
4. the route itself.

Identity (`authentication:`) plugins stack global → tag bundles → route, with `replace_inherited` to drop inherited layers when a route needs a clean set.

## Validation

`load_config_yaml` validates on load and fails with an operator-facing message rather than starting in a bad state. Common errors:

- a duplicate plugin `name`;
- a route with no entity matcher, or with more than one (for example both `tool:` and `resource:`);
- a route or policy group that references an unknown plugin name;
- the renamed key `identity:` (use `authentication:`).

There is no hot reload or config versioning: load a changed config by rebuilding the manager.
