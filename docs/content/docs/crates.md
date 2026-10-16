---
title: "Crate Map"
weight: 122
---

# Crate Map

CPEX runs on the praxis-policy engine (PPE). The engine, the APL compiler and runtime, and the bundled builtins are PPE crates from crates.io. This repository holds what CPEX adds on top: the `cpex` facade, the language bindings, the Python plugin host, and the Biscuit delegator.

Most Rust hosts depend on `cpex` and nothing else.

## CPEX crates and packages

| Crate or package | Published | Role |
|---|---|---|
| [`cpex`](https://github.com/contextforge-org/cpex/tree/main/crates/cpex) | crates.io | Host facade. Re-exports the whole public surface of `praxis-policy`, built with every stable builtin and the bundled hyper HTTP transport. Start here. |
| [`cpex-hosts-python`](https://github.com/contextforge-org/cpex/tree/main/crates/cpex-hosts-python) | crates.io | Runs existing Python CPEX plugins out of process, one cached virtualenv and one worker per plugin, under the `isolated_venv` kind. Reached through the `cpex` feature `python-host`. |
| [`cpex-plugin-delegator-biscuit`](https://github.com/contextforge-org/cpex/tree/main/builtins/plugins/delegator-biscuit) | crates.io | A `token.delegate` handler that attenuates Biscuit capability tokens. A Rust host registers it in code. |
| [`cpex-ffi`](https://github.com/contextforge-org/cpex/tree/main/crates/cpex-ffi) | signed release artifacts | C ABI over the engine (`cdylib` and `staticlib`). The Go package links it. |
| [`cpex-python`](https://github.com/contextforge-org/cpex/tree/main/bindings/python) | crates.io | PyO3 bindings, built with maturin into the Python package `cpex`: the Python `PolicyEngine`. |
| [`go/cpex`](https://github.com/contextforge-org/cpex/tree/main/go/cpex) | Go module | cgo wrapper over `cpex-ffi`: the Go `PolicyEngine`. |

`cpex-ffi` and `cpex-python` share the builtin registration, transport and secret-provider wiring in `cpex::host`.

## PPE crates the facade re-exports

The workspace uses one PPE dependency: `ppe`, an alias for the `praxis-policy` facade pinned to `=0.5.0`. Members access core and APL types through its re-exports. CPEX upgrades the pin deliberately and reruns its parity suite when it does.

| PPE crate | Reached as | Role |
|---|---|---|
| `praxis-policy` | `cpex::*` | PPE's own facade. `cpex` re-exports it whole, so every item on `praxis_policy` is available under the same name: `PolicyEngine`, `install_builtins`, `prelude`, `AplOptions`, `register_apl`, `HyperTransport`, `install_default_http_transport`, the builtin factory types and their `KIND` constants. |
| `praxis-policy-core` | `cpex::praxis_policy_core` | The runtime: engine, phased executor, hook registry, config, extensions, identity, delegation, elicitation, secrets, audit and the HTTP transport seam. |
| `praxis-policy-apl-core` | `cpex::praxis_policy_apl_core` | APL compiler and evaluator: rules, effects, field pipelines, routes. |
| `praxis-policy-apl-cmf` | `cpex::praxis_policy_apl_cmf` | Bridges typed extensions into the flat attribute bag policy reads. See [CMF Extensions]({{< relref "/docs/cmf-extensions" >}}). |
| `praxis-policy-apl-runtime` | `cpex::praxis_policy_apl_runtime` | Wires APL routes to hooks and dispatches plugins and decision points. |
| `praxis-policy-orchestration` | (internal) | Async branch-concurrency primitives the runtime uses. |
| `praxis-policy-builtins` | factory types on `cpex::*` | The bundled extensions, one crate with a feature each. `cpex` turns on all of them. |

The builtins `cpex::install_builtins` registers:

| Kind | Type |
|---|---|
| `identity/jwt` | identity resolver |
| `identity/api-key` | identity resolver |
| `delegator/oauth` | token delegator |
| `elicitation/ciba` | elicitation channel |
| `cedar-direct`, `cel`, `opa` | PDP resolvers |
| `valkey` | session store |

The Vault KV v2 secret provider (`vault`) is compiled in too, but it is not a plugin: a Rust host adds it to its `SecretProviderRegistry` with `cpex::registry_with_vault(transport)` and installs that with `PolicyEngine::set_secret_providers`. The Python and Go bindings install `env`, `file` and `vault` for you, with Vault on the same transport as the builtins. PPE's experimental `quota` plugin is not part of the build.

## Reference plugins

PPE keeps a PII scanner and an audit logger as reference plugins. They are not published and not bundled, so no CPEX surface registers them. A Rust host that wants one copies its source from the PPE repository into its own workspace, builds it against `praxis-policy-core` from crates.io, and registers its factory under a `kind` of its choosing. The Python and Go bindings do not include them. See [Auditing]({{< relref "/docs/auditing" >}}) for what an audit sink needs.

## Writing a plugin

There is no separate SDK crate. The plugin surface is `cpex::prelude`: the `Plugin` and `HookHandler` traits, payloads, results, `PluginFactory`, `TypedHandlerAdapter` and the CMF types. Implement `PluginFactory` against it and register it with `PolicyEngine::register_factory` under the `kind` your policy names. An unknown `kind` fails at load, so a missing registration shows up at startup. [Tutorial module 9]({{< relref "/docs/tutorial/09-custom-plugin" >}}) builds one end to end.

## API docs

- [docs.rs/cpex](https://docs.rs/cpex) for the facade.
- [docs.rs/praxis-policy/0.5.0](https://docs.rs/praxis-policy/0.5.0) and [docs.rs/praxis-policy-core/0.5.0](https://docs.rs/praxis-policy-core/0.5.0) for the engine items the facade re-exports.
- PPE's [crate reference](https://github.com/praxis-proxy/policy/blob/v0.5.0/docs/content/crates.md) for the engine's own layout.
