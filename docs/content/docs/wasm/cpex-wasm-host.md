---
title: "cpex-wasm-host (Host Runtime)"
weight: 40
---

# cpex-wasm-host — Host Runtime

The `cpex-wasm-host` crate is the **host-side runtime** that loads, sandboxes, and invokes WASM plugins compiled from `cpex-wasm-plugin`. It integrates with `cpex-core`'s `PluginManager` so WASM plugins participate in the same hook pipeline as native plugins.

## Purpose

- Load `.wasm` component binaries and compile them with Wasmtime
- Enforce sandbox policies (filesystem, network, env, CPU, memory) per plugin
- Convert between the framework's native Rust types and WIT component-model types
- Validate plugin results against declared capabilities (defense-in-depth)
- Provide a `PayloadSerializerRegistry` for custom payload types crossing the WASM boundary

## Source directory (`src/`)

### `src/lib.rs`

Module root. Re-exports the five public modules:

```rust
pub mod conversions;
pub mod factory;
pub mod payload_registry;
pub mod policy_loader;
pub mod sandbox_manager;
```

### `src/factory.rs`

The main integration point. Contains:

| Component | Role |
|-----------|------|
| `WasmPluginFactory` | Implements `cpex-core`'s `PluginFactory` trait. Parses `"wasm://plugin.wasm"` URIs, extracts sandbox policy from YAML config, and creates `WasmBridgeHandler` instances per hook. |
| `WasmBridgeHandler` | Implements `AnyHookHandler`. Converts native payloads → WIT, invokes the sandbox, converts WIT → native, then validates extensions against capabilities. |
| `validate_extension_modifications` | Post-invocation check: immutable tier integrity, monotonic label enforcement, write authorization against declared capabilities. |
| `classify_wasm_error` | Maps Wasmtime error strings to typed `PluginError` variants (Timeout, FuelExhausted, MemoryLimit, NetworkDenied, WasmTrap). |

### `src/sandbox_manager.rs`

Manages the Wasmtime runtime for a single plugin:

| Component | Role |
|-----------|------|
| `SharedEngine` | Shared Wasmtime `Engine` + `Linker` + epoch-ticker thread. One per factory; all plugins share compilation caches. |
| `SandboxManager` | Owns a compiled `Component` and per-invocation `Store`. Calls `load_wasmplugin()` once, then `invoke()` per hook call (resets fuel + epoch each time). |
| `NetworkPolicy` | Implements `WasiHttpHooks` to intercept outbound HTTP. Filters by host (with wildcard), port, scheme, and method. |
| `WasmPluginState` | Per-plugin store data: WASI context, HTTP context, resource table, store limits. Implements `host-logging::Host`. |

### `src/conversions.rs`

Host-side type conversions between `cpex-core` native types and WIT types:

- `native_payload_to_wit` / `wit_payload_to_native` — MessagePayload
- `native_identity_to_wit` / `wit_identity_to_native` — IdentityPayload
- `native_delegation_to_wit` / `wit_delegation_to_native` — DelegationPayload
- `native_extensions_to_wit` / `wit_extensions_to_native` — all 12 extension types
- `native_context_to_wit` / `wit_context_to_native` — PluginContext

### `src/policy_loader.rs`

Parses sandbox policy from YAML config and builds a WASI context:

| Type | Purpose |
|------|---------|
| `SandboxPolicy` | Top-level: `allowed_filesystem`, `allowed_network`, `allowed_env`, `resources` |
| `FilesystemRule` | Specifies a `dir` or `file` with a named permission level |
| `NetworkRule` | Host (supports `*.` wildcard), ports, schemes, methods |
| `ResourceLimits` | `max_memory_bytes`, `max_fuel`, `max_execution_time_ms`, `max_instances`, `max_tables` |
| `build_wasi_context()` | Constructs `WasiCtx` + `WasiHttpCtx` from a `SandboxPolicy`. Preopens directories, injects env vars, captures network rules. |

### `src/payload_registry.rs`

Type-erased serialization for custom payloads:

```rust
let mut registry = PayloadSerializerRegistry::new();
registry.register::<MyCustomPayload>();  // must impl WasmSerializablePayload

// At runtime:
let (type_name, bytes) = registry.serialize(&payload)?;
let restored: Box<dyn PluginPayload> = registry.deserialize(type_name, &bytes)?;
```

## Configuration

YAML config files live in `config/`. Each plugin entry specifies its sandbox policy:

```yaml
plugins:
  - name: my-plugin
    kind: "wasm://my-plugin.wasm"
    hooks:
      - cmf.tool_pre_invoke
    capabilities:
      - read_labels
      - write_headers
    config:
      sandbox:
        # Filesystem access
        filesystem:
          - dir: "./data/cache"
            permission: full-access
          - dir: "./data/audit"
            permission: drop-box

        # Network access
        network:
          - host: "api.example.com"
            ports: [443]
            schemes: ["https"]
            methods: ["GET", "POST"]
          - host: "*.internal.corp"
            ports: []        # any port
            schemes: ["https"]

        # Environment variables
        env_vars:
          - APP_TOKEN
          - LOG_LEVEL

        # Resource limits
        resources:
          max_fuel: 500_000_000
          max_execution_time_ms: 5000
          max_memory_bytes: 10_485_760   # 10 MB
```

### Default policy (deny-all)

A plugin with no `sandbox` config block gets the most restrictive policy:

- **Filesystem**: no preopened directories
- **Network**: all outbound HTTP blocked
- **Env vars**: none visible
- **Resources**: engine defaults (generous but bounded)

### Capabilities

The `capabilities` list controls which extension fields a plugin can read or write. The host zeros disallowed fields before the call and discards unauthorized modifications on return.

## End-to-end example

Here's how the **capabilities demo** runs from config to result:

**1. Config** (`config/config_capabilities.yaml`):

```yaml
plugins:
  - name: identity-checker
    kind: "wasm://identity-checker.wasm"
    hooks: [cmf.tool_pre_invoke]
    capabilities: [read_labels, read_subject, read_roles]
    config:
      sandbox:
        resources:
          max_fuel: 500_000_000
          max_execution_time_ms: 5000

  - name: header-injector
    kind: "wasm://header-injector.wasm"
    hooks: [cmf.tool_pre_invoke, cmf.tool_post_invoke]
    capabilities: [read_headers, write_headers, append_labels]
    config:
      sandbox:
        resources:
          max_fuel: 500_000_000
          max_execution_time_ms: 5000
```

**2. Host code** (from `examples/wasm_capabilities_demo.rs`):

```rust
use cpex_wasm_host::factory::WasmPluginFactory;
use cpex_core::plugin_manager::PluginManager;

// Create factory with built-in payload support
let factory = WasmPluginFactory::with_builtin_payloads("./wasm");

// Register and load config
let mut mgr = PluginManager::new();
mgr.register_factory("wasm://identity-checker.wasm", Box::new(factory.clone()));
mgr.register_factory("wasm://header-injector.wasm", Box::new(factory));
mgr.load_config("config/config_capabilities.yaml")?;

// Build payload + extensions
let payload = MessagePayload { messages: vec![/* CMF message with ToolCall */] };
let extensions = Extensions::builder()
    .security(SecurityExtension { subject: "user:alice".into(), .. })
    .http(HttpExtension { headers: vec![("x-request-id", "abc123")] })
    .build();

// Invoke — plugins only see extensions matching their capabilities
let result = mgr.invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, extensions, ctx).await?;
```

**3. What happens inside:**

1. `WasmPluginFactory::create()` parses sandbox policy, compiles `.wasm`, creates `SandboxManager`
2. `WasmBridgeHandler` masks extensions based on plugin capabilities before conversion
3. Native types are converted to WIT types (`native_payload_to_wit`, etc.)
4. `SandboxManager::invoke()` resets fuel/epoch, calls `handle-hook` in the sandbox
5. WIT result is converted back to native types
6. `validate_extension_modifications()` checks the plugin didn't write to unauthorized fields
7. Result flows back through the `PluginManager` pipeline

**4. Run it:**

```bash
cd crates/cpex-wasm-host
make run-capabilities-demo
```

## Advantages

- **Drop-in integration** — implements `PluginFactory` / `AnyHookHandler` from `cpex-core`; WASM plugins are transparent to the pipeline
- **Shared compilation** — `SharedEngine` caches compiled modules; multiple plugins share one engine thread
- **Fine-grained policy** — six filesystem permission levels, host/port/scheme/method network rules, explicit env var allowlists
- **Defense-in-depth** — capability validation on the return path catches sandbox escapes at the type level
- **Custom payload extensibility** — `PayloadSerializerRegistry` supports arbitrary domain types without WIT changes
- **Structured error classification** — Wasmtime errors are mapped to typed variants for meaningful error handling

## Limitations

- **Cold start overhead** — first compilation takes ~550ms; subsequent invocations are ~5μs
- **12-120x slower than native** — serialization + sandbox overhead; acceptable for typical LLM pipelines (0.01-0.02% of request time)
- **Single-threaded per invocation** — each `Store` is single-threaded; concurrent plugins need separate `Store` instances (handled by `Arc<Mutex<SandboxManager>>`)
- **WASI P2 only** — requires Wasmtime's component model; legacy WASI P1 modules are not supported
- **Partial extension writeback** — only request, security, http, meta survive the guest→host return; other extension modifications are dropped
- **No raw socket access** — WASI P2 does not expose raw TCP/UDP; only HTTP via `wasi:http/outgoing-handler`
