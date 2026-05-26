# CPEX WASM Plugin Specification — v0.1.0

**Status:** Draft
**Targets CPEX framework version:** 0.x (current `main`)
**WIT package:** `contextforge:cpex@0.1.0`
**Manifest schema:** [`wasm-plugin-manifest.schema.json`](./wasm-plugin-manifest.schema.json)

---

## 1. Scope

This specification defines a fourth CPEX plugin kind — `wasm` — alongside the existing `native`, `isolated_venv`, and `external` kinds. A WASM plugin is a WebAssembly Component Model artifact (`.wasm`) plus a YAML manifest. The framework loads the manifest, verifies the artifact, instantiates it inside a Wasmtime sandbox with only the host capabilities the manifest declares, and treats it as a peer of every other plugin: same `PluginManager`, same hook dispatch, same `PluginResult` semantics.

This document is the contract. Two things together fully specify a CPEX WASM plugin:

1. The WIT world [`cpex-plugin.wit`](../../cpex/templates/wasm/{{cookiecutter.plugin_slug}}/wit/cpex-plugin.wit) — the function-level interface.
2. The manifest schema [`wasm-plugin-manifest.schema.json`](./wasm-plugin-manifest.schema.json) — the deployment-level contract.

Everything in this document is normative.

---

## 2. Why WASM, why now

CPEX already isolates plugins three ways:

| Kind | Isolation | Performance | Languages |
|------|-----------|-------------|-----------|
| `native` | Python class in the same process | Fastest | Python only |
| `isolated_venv` | Subprocess with cached venv | Process boundary | Python only |
| `external` | Separate service (MCP / gRPC / UDS) | Network or IPC | Any |

The gap: there is no way today to run a plugin that is **(a) untrusted by default**, **(b) language-agnostic**, **(c) cheap to load**, and **(d) portable across host runtimes**. The CPEX [vision doc](../content/docs/vision.md) commits to WASM as the answer: *"Portable, capability-based isolation for third-party plugins. Zero-trust by default: no filesystem, network, or host memory unless explicitly granted."*

This kind closes that gap and intentionally fits the existing plugin lifecycle without changing it.

---

## 3. The plugin contract

Every CPEX WASM plugin MUST export the world `plugin` from package `contextforge:cpex@0.1.0`. The full WIT is in the templates directory; the surface is:

```wit
world plugin {
    export init: func(config-json: string) -> result<_, plugin-error>;
    export manifest: func() -> manifest-info;
    export invoke-hook: func(
        hook-name: string,
        payload-json: string,
        context-json: string,
    ) -> result<string, plugin-error>;
    export shutdown: func();

    import logging;   // always available
    import clock;     // always available
    import http;      // gated by capability
    import kv;        // gated by capability
    import random;    // gated by capability
}
```

### 3.1 Wire format: JSON, not WIT records

Hook payloads and results cross the boundary as **JSON strings**, not as per-hook WIT records. Three reasons:

1. **Consistency with sibling plugin kinds.** `IsolatedVenvPlugin` and `ExternalPlugin` already serialize Pydantic models to JSON before crossing their respective boundaries. The host serializer is shared; the WASM kind reuses it unmodified.
2. **Forward compatibility.** New hooks can be registered in the host without rebuilding `.wasm` artifacts. The WIT contract is stable across CPEX hook additions.
3. **Runtime portability.** The same `.wasm` artifact will work against the planned Rust core and any future host language binding. There is no Python-specific binding baked into the wasm side.

The cost is one JSON parse per call inside the guest, which is negligible compared to the wasm call overhead itself.

### 3.2 Dispatch: single entry point

`invoke-hook` dispatches by `hook-name` (matching the host's registered hook names, e.g. `tool_pre_invoke`). The plugin implements its own internal switch. This mirrors how a native Python `Plugin` class has multiple `async def` methods — one component, many hooks.

A plugin MUST handle every hook listed in its manifest's `hooks` field. Receiving an unknown `hook-name` is an error: the plugin SHOULD return `Err(plugin-error { code: "UNKNOWN_HOOK", ... })`.

### 3.3 Lifecycle

```
load manifest → verify sha256 → verify signature (if present)
              → instantiate wasm with capability-filtered linker
              → call manifest()  ← cross-check against YAML
              → call init(config_json)
              → register with PluginManager
              ⋯ per-request: call invoke-hook(hook, payload, context) ⋯
              → call shutdown()
              → drop instance
```

The `manifest()` cross-check is non-negotiable. If the component reports a different name, version, hooks list, or required-capabilities list than the YAML says, the host MUST refuse to register the plugin. This prevents a malicious or stale `.wasm` from running under a benign-looking YAML.

---

## 4. The capability model

This is the security backbone. CPEX WASM plugins are sandboxed by **construction**, not by permission check.

### 4.1 How it works

When the host instantiates a wasm component, it builds a Wasmtime `Linker` and adds only the host interfaces the manifest's `capabilities:` list grants. A plugin without `http:fetch` in its capabilities has no `host:http/fetch` import linked. The wasm runtime refuses instantiation if the component tries to import an unlinked function. There is no way for the plugin to "ask nicely" later — the function pointer literally does not exist in its address space.

This is strictly stronger than the existing per-plugin permission model used elsewhere in CPEX, which relies on runtime checks. A bug in a runtime check can leak a permission; a missing import can not.

### 4.2 Canonical capabilities

| Capability | Linked import | Notes |
|---|---|---|
| `log` | `contextforge:cpex/logging` | Always granted; safe by definition. |
| `clock` | `contextforge:cpex/clock` | Always granted; host may freeze time for tests. |
| `random` | `contextforge:cpex/random` | Cryptographic randomness via host. |
| `kv:read` | read-only subset of `kv` | Read from the plugin's private namespace. |
| `kv:write` | full `kv` interface | Implies `kv:read`. |
| `http:fetch` | `contextforge:cpex/http` | Unrestricted outbound. **Discouraged**; prefer scoped form. |
| `http:fetch:HOST[:PORT]` | scoped `http` | Host enforces allowlist before each call. May repeat for multiple hosts. |
| `filesystem:read:/PATH` | WASI `preopened` directory, read-only | Path-scoped via WASI. |
| `filesystem:write:/PATH` | WASI `preopened` directory, read-write | Path-scoped via WASI. Implies read. |

Implementers MUST NOT extend this list without bumping the WIT package version.

### 4.3 Worked examples

**A pure CPU plugin** (e.g. PII regex matcher) declares nothing:
```yaml
capabilities: []
```
It can compute, return a result, log, and read the clock. That's it.

**A moderation plugin** that calls one upstream:
```yaml
capabilities:
  - http:fetch:moderation.example.com:443
```
The host installs an HTTP import that rejects any other destination.

**A rate limiter** with shared state:
```yaml
capabilities:
  - kv:read
  - kv:write
```
The plugin reads and writes its own namespace; it cannot see other plugins' keys.

---

## 5. Resource limits

Sandboxing the API surface is not enough; the host MUST also cap resource use. The manifest's `limits:` block sets:

- **`max_memory_mb`** — Wasmtime hard cap on linear memory. Allocations beyond this trap the instance.
- **`max_fuel`** — Wasmtime fuel budget per `invoke-hook` call. Wasmtime decrements fuel on every instruction; exhausting it traps.
- **`call_timeout_ms`** — Wall-clock deadline per `invoke-hook` call. This protects against a plugin blocked inside a host import (e.g. an HTTP call that hangs); fuel alone wouldn't catch that.
- **`max_table_elements`** — caps indirect call tables.
- **`max_payload_bytes`** — host-side check on JSON payload size before crossing the boundary.

The host MAY tighten any of these via deployment policy but MUST NOT loosen them past what the manifest declared.

---

## 6. Manifest cross-check (load-time fail-closed)

At load time the host MUST verify all of:

1. `api_version` is supported.
2. `artifact.sha256` matches the file on disk.
3. `artifact.signature`, if present, verifies against `artifact.public_key`.
4. `manifest().name == manifest_yaml.name`.
5. `manifest().version == manifest_yaml.version`.
6. `manifest().api_version` matches the WIT package version the host knows.
7. `set(manifest().hooks) ⊇ set(manifest_yaml.hooks)` — the wasm must implement every hook the YAML promises.
8. `set(manifest().required_capabilities) ⊆ set(manifest_yaml.capabilities)` — the wasm must not need more than the YAML granted.
9. The plugin's `config` validates against `config_schema` if one is provided.

Any failure is a load-time error; the plugin MUST NOT be registered with the `PluginManager`.

---

## 7. Relationship to existing plugin kinds

The `wasm` kind reuses, not replaces, existing CPEX machinery:

- **HookRegistry** — unchanged. The wasm host wrapper calls `registry.json_to_result(hook_type, json.loads(reply))` exactly like `IsolatedVenvPlugin` does.
- **PluginManager / PluginRef** — unchanged. From the manager's perspective, a `WasmPlugin` is just another `Plugin` subclass.
- **Execution modes** (`sequential`, `transform`, `audit`, `concurrent`, `fire_and_forget`) — unchanged.
- **Conditions** (`tenant_ids`, `server_ids`) — unchanged; evaluated host-side before `invoke-hook` is called.
- **`on_error`** (`fail`, `ignore`, `disable`) — unchanged; applied to plugin-errors and timeouts uniformly.

---

## 8. Non-goals

- **Hot-reloading.** v1 reloads the entire `WasmPlugin` instance on manifest change. Sub-instance reload is a v2 question.
- **WASI Preview 1.** Plugins target WASI Preview 2 / the Component Model. Preview 1 modules require adapter polyfills and are out of scope.
- **WASIX, Spin SDK, or other non-standard extensions.** Plugins MUST be plain Component Model artifacts producible by any toolchain.
- **Synchronous host imports that block on I/O.** The host's `http`, `kv`, etc. implementations are async on the Python side, exposed to wasm as sync calls. The `call_timeout_ms` exists to bound this.

---

## 9. Versioning

The WIT package `contextforge:cpex` is versioned independently of CPEX itself. Compatibility rules:

- **Patch** (0.1.0 → 0.1.1): bug fixes only. All existing plugins keep working.
- **Minor** (0.1 → 0.2): additive only — new optional capabilities, new optional manifest fields. Existing plugins keep working.
- **Major** (0.x → 1.x): breaking. Plugins MUST be rebuilt against the new WIT package. The host SHOULD support the previous major version for one release cycle.

The manifest `api_version` field is the gate: a v0.1 host refuses to load a v0.2 plugin, and vice versa.

---

## 10. Reference: file layout of a WASM plugin

```
my_wasm_filter/
├── plugin-manifest.yaml          # this is the spec entry point
├── build/
│   ├── my_wasm_filter.wasm       # the Component Model artifact
│   └── my_wasm_filter.wasm.sig   # optional cosign signature
├── wit/
│   └── cpex-plugin.wit           # frozen copy of the WIT contract
├── src/                          # plugin source (any language)
│   └── lib.rs
├── Cargo.toml                    # if Rust
├── Makefile                      # cargo component build --release
└── tests/
    └── test_plugin.py            # host-side integration test
```

The cookiecutter template in `cpex/templates/wasm/` produces exactly this layout.
