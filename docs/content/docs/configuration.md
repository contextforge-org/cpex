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

routes:         # APL policy, keyed by operation
  <route>:
    authentication: [ ... ]   # identity-resolution plugins
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

Routes carry the APL policy. The map-keyed form (keyed by route name) is the canonical form for configs loaded into the runtime:

```yaml
routes:
  get_compensation:
    authorization:
      pre_invocation:
        - "require(role.hr)"
        - "delegate(workday-oauth, target: workday-api, audience: workday-api, permissions: [read_compensation])"
        - "taint(secret, session)"
        - "plugin(audit-log)"
    result:
      ssn: "str | redact(!perm.view_ssn)"
```

The two authorization phases may also be written flat — `pre_invocation:` / `post_invocation:` directly on the route — which is equivalent to nesting them under `authorization:`.

Deployment integrations that wrap CPEX (a gateway or sidecar) often express routes as a list of `- tool:` entries instead; that form carries the same `authorization`/`args`/`result` blocks. See [Deployment]({{< relref "/docs/deployment" >}}) for that variant, and [APL]({{< relref "/docs/apl" >}}) for the policy syntax itself.

Route-level overrides can adjust a plugin's `capabilities` or `config` for a specific operation, so a scanner can be granted `read_labels` on one sensitive route without widening its access everywhere.
