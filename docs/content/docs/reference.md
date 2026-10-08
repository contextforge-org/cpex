---
title: "Reference"
weight: 120
---

# Reference

CPEX 0.3 runs on the praxis-policy engine (PPE) 0.4.1. Rust hosts depend on the `cpex` facade, which re-exports PPE's public surface; plugin authors use `cpex::prelude`. The [Crate Map]({{< relref "/docs/crates" >}}) lists every crate and what it re-exports.

| Surface | Entry point | Where |
|---|---|---|
| Rust | `cpex::PolicyEngine` | [`crates/cpex`](https://github.com/contextforge-org/cpex/tree/main/crates/cpex), [docs.rs/cpex](https://docs.rs/cpex) |
| Python | `cpex.PolicyEngine` (`PluginManager` is an alias) | [`bindings/python`](https://github.com/contextforge-org/cpex/tree/main/bindings/python) |
| Go | `cpex.PolicyEngine` | [`go/cpex`](https://github.com/contextforge-org/cpex/tree/main/go/cpex) |
| C ABI | `cpex_engine_*`, ABI version 3 | [`crates/cpex-ffi`](https://github.com/contextforge-org/cpex/tree/main/crates/cpex-ffi) |
| Python plugins | `isolated_venv` kind (`python-host` feature) | [`crates/cpex-hosts-python`](https://github.com/contextforge-org/cpex/tree/main/crates/cpex-hosts-python) |

Engine API docs are on [docs.rs/praxis-policy/0.4.1](https://docs.rs/praxis-policy/0.4.1) and [docs.rs/praxis-policy-core/0.4.1](https://docs.rs/praxis-policy-core/0.4.1).

## Language bindings

The Python package and the Go module wrap the same engine and install the same builtins, HTTP transport and secret providers. Both block private destinations by default and expose a host-side opt-in (`allow_private_destinations=True` in Python, `cpex.WithPrivateDestinations()` in Go). Both expose secret refresh (`refresh_secrets` / `RefreshSecrets`) and a last-success query, which a host using Vault calls on an interval. See [Builtins]({{< relref "/docs/builtins" >}}) and [Configuration]({{< relref "/docs/configuration#resolution-and-refresh" >}}).

The Go package links `libcpex_ffi` and checks its ABI version at init. The Go module and the FFI artifact must come from the same CPEX release.

## Supply-chain integrity

The C FFI is distributed as **signed prebuilt artifacts**. A host that links the FFI rather than building from source verifies the signature on the artifact before use, so the binary boundary between the Rust core and a non-Rust host is not an unverified trust gap. The signing and verification process is documented in [`crates/cpex-ffi/RELEASE.md`](https://github.com/contextforge-org/cpex/blob/main/crates/cpex-ffi/RELEASE.md).

(The 0.1.x Python line had its own package-integrity verification for PyPI and Git installs; that mechanism is specific to the Python distribution and is documented in the [0.1.x docs]({{< relref "/docs/0.1.x" >}}).)

## Upgrading

[Migrating to 0.3]({{< relref "/docs/migration-0.3" >}}) maps every 0.2.x API, hook name and config key to its 0.3.0 form.
