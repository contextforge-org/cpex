---
title: "Reference"
weight: 170
---

# Crate Reference

CPEX is a Cargo workspace of focused crates. Most hosts depend on `cpex` (the facade); plugin authors depend on `cpex-sdk`.

| Crate | Role |
|-------|------|
| [`cpex`](https://github.com/contextforge-org/cpex/tree/main/crates/cpex) | Host facade. Re-exports the runtime and, with a feature, the builtins. Start here. |
| [`cpex-core`](https://github.com/contextforge-org/cpex/tree/main/crates/cpex-core) | The runtime: `PluginManager`, executor, hooks, config, extensions. |
| [`cpex-sdk`](https://github.com/contextforge-org/cpex/tree/main/crates/cpex-sdk) | Plugin author SDK: the `Plugin` and `HookHandler` traits, payloads, results. Depend on this to write a plugin or PDP resolver. |
| [`cpex-orchestration`](https://github.com/contextforge-org/cpex/tree/main/crates/cpex-orchestration) | Async concurrency primitives shared by the runtime. |
| [`cpex-builtins`](https://github.com/contextforge-org/cpex/tree/main/crates/cpex-builtins) | Feature-gated bundle of builtin plugins, PDP resolvers, and the session store (see [Builtins]({{< relref "/docs/builtins" >}})). |
| [`cpex-ffi`](https://github.com/contextforge-org/cpex/tree/main/crates/cpex-ffi) | C FFI (`cdylib` / `staticlib`) for Go, Python, and WASM host bindings. |
| [`apl-core`](https://github.com/contextforge-org/cpex/tree/main/crates/apl-core) | APL compiler and evaluator: rules, effects, field pipelines, routes. |
| [`apl-cmf`](https://github.com/contextforge-org/cpex/tree/main/crates/apl-cmf) | Bridges typed extensions into the flat attribute bag APL reads. |
| [`apl-cpex`](https://github.com/contextforge-org/cpex/tree/main/crates/apl-cpex) | Runtime adapter: wires APL routes to hooks, dispatches plugins and PDPs. |

Generated API docs are on [docs.rs/cpex](https://docs.rs/cpex).

## Language bindings

The Rust core is exposed to other languages through `cpex-ffi`. Go bindings live in [`go/cpex`](https://github.com/contextforge-org/cpex/tree/main/go/cpex). Python (PyO3) and WASM bindings are planned over the same core.

## Supply-chain integrity

The C FFI is distributed as **signed prebuilt artifacts**. A host that links the FFI rather than building from source verifies the signature on the artifact before use, so the binary boundary between the Rust core and a non-Rust host is not an unverified trust gap. The signing and verification process is documented in [`crates/cpex-ffi/RELEASE.md`](https://github.com/contextforge-org/cpex/blob/main/crates/cpex-ffi/RELEASE.md).

(The 0.1.x Python line had its own package-integrity verification for PyPI and Git installs; that mechanism is specific to the Python distribution and is documented in the [0.1.x docs]({{< relref "/docs/0.1.x" >}}).)
