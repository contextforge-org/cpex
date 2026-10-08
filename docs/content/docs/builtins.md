---
title: "Builtins"
weight: 70
---

# Builtins

CPEX ships a set of plugins, decision points, a session store and secret providers, all from the praxis-policy engine (PPE) builtins. Every CPEX surface carries the same set: the Rust facade, the Python package, the Go module and the C ABI. A config names a builtin by `kind`.

## The 0.3.0 catalog

| Kind | Type | Purpose |
|------|------|---------|
| `identity/jwt` | identity | Resolve a subject from a verified JWT, with configurable claim mapping (see [Identity]({{< relref "/docs/apl/identity" >}})). |
| `identity/api-key` | identity | Resolve an opaque API key against a file or HTTP directory (see [Identity & Delegation]({{< relref "/docs/identity-delegation#recipe-7-an-opaque-api-key-resolved-against-a-directory" >}})). |
| `delegator/oauth` | delegator | RFC 8693 token exchange and `client_credentials`, with optional caching (see [Delegation]({{< relref "/docs/apl/delegation" >}})). |
| `elicitation/ciba` | elicitation | OIDC CIBA human approval (see [Elicitation]({{< relref "/docs/apl/elicitation" >}})). |
| `cedar-direct` | PDP resolver | Evaluate Cedar policy (dialect `cedar`). |
| `cel` | PDP resolver | Evaluate CEL expressions (dialect `cel`). |
| `opa` | PDP resolver | Evaluate Rego, embedded, no sidecar (dialect `opa`). |
| `valkey` | session store | Persist taint labels across processes (see [Session Tainting]({{< relref "/docs/apl/tainting" >}})). |
| `env`, `file` | secret providers | Read `secrets:` values from the environment or from files. |
| `vault` | secret provider | Read `secrets:` values from Vault KV v2 over the host's HTTP transport. |

The default session store is in-process memory; no `kind` is needed for it, but its labels do not survive a restart or reach a second replica.

CPEX also ships one plugin of its own: the Biscuit delegator (`cpex-plugin-delegator-biscuit`), which a Rust host registers in code. PPE's experimental `quota` plugin is not part of the CPEX build.

## How each surface installs them

| Surface | Call | Installs |
|---|---|---|
| Rust | `cpex::install_builtins(&engine)` | plugin, PDP and session store factories, and the APL visitor |
| Rust | `cpex::install_default_http_transport(&engine)` | the bundled HTTP transport (private destinations refused) |
| Rust | `engine.set_secret_providers(cpex::registry_with_vault(transport))` | `env`, `file` and `vault` |
| Python | `PolicyEngine(path, *, allow_private_destinations=False)` | all of the above, then loads the config |
| Go | `engine.EnableAPL(opts...)` | all of the above |
| C ABI | `cpex_apl_install(handle, flags)` | all of the above |

There are no Cargo features to choose. `cpex = "0.3"` compiles every builtin in. The facade's only feature is `python-host`, which adds the out-of-process Python plugin host.

## The HTTP transport

The engine performs no outbound HTTP of its own. A host installs an `HttpTransport` and the builtins borrow it, so a process embedding CPEX keeps one connection pool, one TLS trust store and one egress path. JWKS fetches, OAuth token exchange, CIBA, API-key HTTP directories and Vault all go through it.

- A Rust host with its own client installs it with `engine.set_http_transport(...)`. A host with none calls `cpex::install_default_http_transport(&engine)`. Install it before `initialize()`. It is set-once: a second install is ignored.
- The Python, Go and C ABI surfaces build one transport per engine and pass the same instance to Vault.

Two mistakes fail `initialize()` with distinct messages: no transport installed (a wiring problem in the host program), and a transport installed but the plugin does not declare `perform_http` (fix the plugin's `capabilities:` list).

### Private destinations

The bundled transport refuses private destinations by default: loopback, RFC 1918 ranges, link-local addresses (including cloud metadata at `169.254.169.254`) and CGNAT. The check applies to the address that would be dialed, so a hostname that resolves only to such an address is refused too. Each surface has one opt-in, set in host code; no policy document can turn it on:

| Surface | Opt-in |
|---|---|
| Rust | `engine.set_http_transport(Arc::new(HyperTransport::new().with_allow_private_destinations()))` |
| Python | `PolicyEngine(path, allow_private_destinations=True)` |
| Go | `engine.EnableAPL(cpex.WithPrivateDestinations())` |
| C ABI | `cpex_apl_install(handle, CPEX_APL_ALLOW_PRIVATE_DESTINATIONS)` |

> **The opt-in is engine-wide.** It permits loopback, RFC 1918, link-local (including cloud metadata) and CGNAT for every outbound builtin, not for one plugin or one host. Anyone who can edit a plugin URL in the policy can then make the engine call internal services or the metadata endpoint. The tutorial and the demos turn it on to reach a local IdP. Do not copy that into production. To reach an in-cluster IdP or Vault in production, install your own transport with explicit egress rules.

A refused call shows up as `delegation.egress_denied` (OAuth), `elicitation.egress_denied` (CIBA), or `auth.jwks_unavailable` for a JWKS fetch, which looks like an unreachable IdP. A refused Vault read fails `initialize()`.

## Not builtins: the PII scanner and audit logger

`validator/pii-scan` and `audit/logger` were bundled in 0.2.x. They are not in 0.3.0 on any surface, and a config that names either fails to load with an unknown-kind error. PPE keeps both as reference plugins: the scanner is plain regexes with no checksum validation, and the logger writes to stderr, so neither is something to ship as a supported control.

What to use instead:

- Redaction: an APL field pipeline, `ssn: "str | redact(!perm.view_ssn)"`, or `mask(N)`.
- A content deny: a `cel:` step or an APL `deny` rule over the arguments.
- Detection you trust: a host plugin backed by a real detector, called with `run(...)`.
- Audit: a host plugin that a `run(...)` step names, like the tutorial's `tutorial/audit-line`. See [Auditing]({{< relref "/docs/auditing" >}}) for what each surface supports.

### Reference plugins in a Rust host

A Rust host can still register PPE's reference implementations. They are `publish = false`, so there is no crates.io package to depend on. Copy their source into your own workspace instead:

1. Copy [`reference/plugins/pii-scanner`](https://github.com/praxis-proxy/policy/tree/v0.4.1/reference/plugins/pii-scanner) or [`reference/plugins/audit-logger`](https://github.com/praxis-proxy/policy/tree/v0.4.1/reference/plugins/audit-logger) from the PPE `v0.4.1` tag into your workspace, for example `plugins/pii-scanner`.
2. In its `Cargo.toml`, replace every inherited `workspace = true` field and dependency with an explicit value (the crates use edition 2024), and depend on `praxis-policy-core = "=0.4.1"` from crates.io, the same version `cpex` pins.
3. Register its factory before loading the config:

```rust
use std::sync::Arc;
use cpex::PolicyEngine;

let engine = Arc::new(PolicyEngine::default());
cpex::install_builtins(&engine);
engine.register_factory(
    praxis_policy_plugin_pii_scanner::KIND,          // "validator/pii-scan"
    Box::new(praxis_policy_plugin_pii_scanner::PiiScannerFactory),
);
engine.register_factory(
    praxis_policy_plugin_audit_logger::KIND,         // "audit/logger"
    Box::new(praxis_policy_plugin_audit_logger::AuditLoggerFactory),
);
engine.load_config_yaml(yaml)?;
```

Do not pull them in as a git dependency on the PPE repository. Cargo would build a second copy of `praxis-policy-core` from git, and its `Plugin` and `PluginFactory` types would not match the ones `cpex` links from crates.io, so the factory would not register.

You may register them under your own `kind` strings. Keep the plugin `name` your policy uses, so `run(pii-scan)` and `run(audit-log)` steps stay unchanged.

The Python and Go builds do not include these plugins and cannot load them: neither binding has a way to register a Rust factory from the host language at runtime. A Go host can link its own Rust FFI crate that registers them (see the [Go package README](https://github.com/contextforge-org/cpex/tree/main/go/cpex#writing-plugins-rust-for-go-callers)).

## Referencing builtins from APL

A registered builtin is referenced by `kind` in the config. Plugins declare their hooks and capabilities; PDP resolvers go under `global.pdp`; the session store under `global.session_store`; secret providers under `secrets.providers`.

```yaml
plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks: [identity.resolve]
    capabilities: [perform_http]
    config:
      role: user
      header: X-User-Token
      trusted_issuers: [ ... ]

global:
  pdp:
    - kind: opa
      policy_text: |
        package cpex
        default allow := false
  session_store:
    kind: valkey
    endpoint: localhost:6379
```

See [Configuration]({{< relref "/docs/configuration" >}}) for the full structure.
