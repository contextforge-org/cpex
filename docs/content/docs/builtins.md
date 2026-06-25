---
title: "Builtins"
weight: 120
---

# Builtins

CPEX ships a set of builtin plugins, PDP resolvers, and a session store, each behind a Cargo feature. With a feature enabled, `cpex::install_builtins` registers its factory and APL can reference it by `kind`.

## The catalog

| Kind | Type | Feature | Purpose |
|------|------|---------|---------|
| `identity/jwt` | identity | `jwt` | Resolve a subject from a verified JWT (see [Identity]({{< relref "/docs/identity" >}})). |
| `delegator/oauth` | delegator | `oauth` | RFC 8693 token exchange (see [Delegation]({{< relref "/docs/delegation" >}})). |
| `validator/pii-scan` | validator | `pii` | Detect and redact PII in content. |
| `audit/logger` | audit | `audit` | Append-only decision logging. |
| `cedar-direct` | PDP resolver | `cedar` | Evaluate Cedar policy (dialect `cedar`). |
| `cel` | PDP resolver | `cel` | Evaluate CEL expressions (dialect `cel`). |
| `valkey` | session store | `valkey` | Persist taint labels across processes (see [Session Tainting]({{< relref "/docs/tainting" >}})). |

The default session store is in-process memory; no feature or `kind` is needed for it.

## Cargo features

```bash
# nothing bundled (engine only)
cargo add cpex

# the common in-process set: jwt, oauth, pii, audit, cedar, cel
cargo add cpex --features builtins

# everything, including the Valkey session store
cargo add cpex --features full

# a granular subset
cargo add cpex --features "jwt,cedar,pii"
```

| Feature | Pulls in |
|---------|----------|
| `builtins` | the six default builtins (jwt, oauth, pii, audit, cedar, cel) |
| `full` | `builtins` plus `valkey` |
| `jwt` | `identity/jwt` |
| `oauth` | `delegator/oauth` |
| `pii` | `validator/pii-scan` |
| `audit` | `audit/logger` |
| `cedar` | `cedar-direct` |
| `cel` | `cel` |
| `valkey` | `valkey` session store |

The default build (`cpex = "0.2"` with no features) is the engine alone, so a host that only needs the runtime and its own plugins compiles nothing extra.

## Referencing builtins from APL

A registered builtin is referenced by `kind` in the config. Plugins declare their hooks and capabilities; PDP resolvers are registered under `global.pdp`; the session store under `global.session_store`. See [Configuration]({{< relref "/docs/configuration" >}}) for the full structure.
