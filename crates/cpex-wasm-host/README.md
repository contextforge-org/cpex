# cpex-wasm-host

Loads and executes a WASM plugin inside a sandboxed wasmtime environment. Enforces resource limits (fuel, memory, execution time) and network/filesystem policies. Provides a bridge to cpex-core's `PluginManager` for integration into the hook pipeline.

## How It Works

```
┌──────────────────────────────────────────────────────────┐
│  PluginManager (cpex-core)                               │
│    invoke_named::<CmfHook>("cmf.tool_pre_invoke", ...)   │
└──────────────────────┬───────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────┐
│  WasmBridgeHandler (factory.rs)                          │
│    native MessagePayload → WIT MessagePayload            │
│    native Extensions     → WIT Extensions                │
│    native PluginContext   → WIT PluginContext             │
└──────────────────────┬───────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────┐
│  SandboxManager (sandbox_manager.rs)                     │
│    call_handle_hook() inside wasmtime sandbox             │
│    ┌─────────────────────────────────┐                   │
│    │  Sandbox Enforcement            │                   │
│    │  • Fuel budget (session-level)  │                   │
│    │  • Memory limit                 │                   │
│    │  • Execution timeout (per-call) │                   │
│    │  • Network allowlist            │                   │
│    │  • Filesystem permissions       │                   │
│    │  • Environment variable filter  │                   │
│    └─────────────────────────────────┘                   │
└──────────────────────┬───────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────┐
│  WIT PluginResult → native PluginResult                  │
│  returned to PluginManager pipeline                      │
└──────────────────────────────────────────────────────────┘
```

## Project Structure

```
cpex-wasm-host/
├── Cargo.toml
├── config/
│   ├── config.yaml                   # CMF demo config (pre/post invoke + generic)
│   └── config_identity.yaml          # Identity-resolve demo config
├── examples/
│   ├── wasm_plugin_demo.rs           # CMF MessagePayload end-to-end
│   ├── wasm_identity_resolve_demo.rs # IdentityPayload typed dispatch
│   └── wasm_generic_payload_demo.rs  # Custom payload pass-through
├── src/
│   ├── lib.rs                        # Module exports
│   ├── sandbox_manager.rs            # Core: wasmtime engine, plugin loading, invocation
│   ├── policy_loader.rs              # Parses sandbox config (filesystem, network, env, resources)
│   ├── payload_registry.rs           # Type-erased payload serialization registry
│   ├── conversions.rs                # Native cpex-core types ↔ WIT types
│   └── factory.rs                    # PluginFactory bridge for PluginManager integration
├── wasm/
│   └── plugin.wasm                   # Compiled WASM plugin (from cpex-wasm-plugin)
└── wit/
    ├── world.wit                     # Plugin interface definition
    └── deps/                         # WASI interface dependencies
```

## Components

### SandboxManager (`sandbox_manager.rs`)

The core component. Manages a single WASM plugin in an isolated wasmtime environment.

- `new()` — Creates the wasmtime engine, linker, and epoch ticker thread
- `load_wasmplugin(path, config)` — Instantiates a WASM component with sandbox policies applied
- `invoke(payload, extensions, ctx)` — Calls the plugin's `handle-hook` function
- `is_loaded()` — Checks if a plugin is loaded

**Sandbox enforcement:**
- Fuel budget is session-level — set once at load, depletes across all invocations
- Execution timeout is per-invocation — reset each call so no single call hangs
- Network requests are gated by an allowlist of hosts
- Filesystem access is limited to preopened directories with explicit permissions
- Only explicitly listed environment variables are visible to the plugin

### Policy Loader (`policy_loader.rs`)

Parses sandbox configuration from the plugin's `config.sandbox_policy` YAML key:

```yaml
plugins:
  - name: identity-checker
    kind: "wasm://plugin.wasm"
    config:
      sandbox_policy:
        allowed_filesystem:
          - dir: /tmp/data
            permission: "read"
        allowed_network:
          - "httpbin.org"
        allowed_env:
          - "API_KEY"
        resources:
          max_memory_bytes: 10485760
          max_fuel: 1000000000
          max_execution_time_ms: 5000
```

If `sandbox_policy` is absent, deny-by-default applies (no filesystem, no network, no env vars).

### Conversions (`conversions.rs`)

Bidirectional type mappings between native cpex-core types and WIT types:

| Direction | Purpose |
|---|---|
| Native → WIT | Before calling the WASM sandbox (payload, extensions, context) |
| WIT → Native | After the sandbox returns (plugin result, modified payload) |

WIT can't represent `HashMap`, `HashSet`, `Arc`, or `serde_json::Value` directly, so these are serialized to JSON strings or flattened to lists/tuples at the boundary.

### Factory (`factory.rs`)

Bridges cpex-core's `PluginFactory` trait to the `SandboxManager`. Contains:

- `WasmPluginFactory` — implements `PluginFactory::create()`, loads the plugin into the sandbox
- `WasmBridgePlugin` — implements `Plugin` trait (lifecycle)
- `WasmBridgeHandler` — implements `AnyHookHandler`, converts types and routes calls through the sandbox

## Prerequisites

- Rust toolchain (stable)
- `wasm32-wasip2` target installed:
  ```sh
  rustup target add wasm32-wasip2
  ```
- (Optional) `wasm-tools` for validation/inspection:
  ```sh
  cargo install wasm-tools
  ```

## Running the End-to-End Demos

### Prerequisites

```sh
rustup target add wasm32-wasip2
```

### Available Demos

| Demo | Native Equivalent | What It Tests |
|------|-------------------|---------------|
| `wasm_plugin_demo` | `plugin_demo` (cpex-core) | Single WASM plugin, CMF payload, pre/post invoke |
| `wasm_capabilities_demo` | `cmf_capabilities_demo` (cpex-core) | 3 plugins, capability isolation, extension modification |
| `wasm_identity_resolve_demo` | — | Identity resolution via custom typed payload |
| `wasm_generic_payload_demo` | — | Custom payload pass-through (unhandled type → allow) |

### Quick Start (single-plugin demos)

```sh
# Build the default plugin (identity-checker) and stage it
cd crates/cpex-wasm-plugin && make all && cd ../..

# Run the CMF demo (like plugin_demo.rs but via WASM sandbox)
cargo run -p cpex-wasm-host --example wasm_plugin_demo

# Run the identity resolve demo
cargo run -p cpex-wasm-host --example wasm_identity_resolve_demo

# Run the generic payload demo
cargo run -p cpex-wasm-host --example wasm_generic_payload_demo
```

### Capabilities Demo (3 WASM plugins, like cmf_capabilities_demo.rs)

This demo runs **three independent WASM plugins** in the same pipeline, each with different capabilities:

| Plugin | Binary | Capabilities | Behavior |
|--------|--------|--------------|----------|
| identity-checker | `identity-checker.wasm` | `read_labels`, `read_subject`, `read_roles` | Checks PII access |
| header-injector | `header-injector.wasm` | `read_headers`, `write_headers`, `append_labels` | Adds label + injects header |
| audit-logger | `audit-logger.wasm` | `read_headers`, `read_labels` | Read-only audit logging |

```sh
# Build all three plugin binaries and stage them
cd crates/cpex-wasm-plugin && make build-all && cd ../..

# Run the capabilities demo
cargo run -p cpex-wasm-host --example wasm_capabilities_demo
```

Or via the host Makefile:
```sh
cd crates/cpex-wasm-host && make run-capabilities-demo
```

**Expected output:**

```
=== WASM Capabilities Demo ===

=== Phase 1: cmf.tool_pre_invoke ===
[identity-checker] sees labels + subject, HTTP NOT visible → ALLOWED
[header-injector] sees HTTP, subject NOT visible → adds label + header
[audit-logger] logs tool, labels (includes "PROCESSED"), request-id

Pre-invoke result: ALLOWED
  Labels after pre-invoke: ["PROCESSED"]
  Headers after pre-invoke: {"X-Processed-By": "header-injector", ...}

=== Phase 2: cmf.tool_post_invoke ===
[identity-checker] verifies result → ALLOWED
[audit-logger] logs post-invoke

Post-invoke result: ALLOWED
=== Demo complete ===
```

### All demos in one shot

```sh
cd crates/cpex-wasm-plugin && make build-all && make all && cd ../..
cargo run -p cpex-wasm-host --example wasm_plugin_demo
cargo run -p cpex-wasm-host --example wasm_identity_resolve_demo
cargo run -p cpex-wasm-host --example wasm_generic_payload_demo
cargo run -p cpex-wasm-host --example wasm_capabilities_demo
```

### Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `error: target 'wasm32-wasip2' not found` | Target not installed | `rustup target add wasm32-wasip2` |
| `failed to load wasm from .../plugin.wasm` | Missing binary | `cd crates/cpex-wasm-plugin && make all` |
| `failed to load wasm from .../<name>.wasm` | Capabilities demo binaries missing | `cd crates/cpex-wasm-plugin && make build-all` |
| `failed to instantiate plugin` | Stale `.wasm` (WIT mismatch) | Rebuild plugins: `make build-all` |

### Build tests

```sh
cargo test -p cpex-wasm-host
```

## Usage

### Via PluginManager

```rust
use std::path::PathBuf;
use cpex_wasm_host::factory::WasmPluginFactory;
use cpex_core::manager::PluginManager;
use cpex_core::config::parse_config;

let mgr = PluginManager::default();

mgr.register_factory(
    "wasm://plugin.wasm",
    Box::new(WasmPluginFactory::new(PathBuf::from("wasm"))),
);

let config = parse_config(&yaml)?;
mgr.load_config(config)?;
mgr.initialize().await?;

let (result, bg) = mgr
    .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, ext, None)
    .await;
bg.wait_for_background_tasks().await;
```

## Config Format

The `kind` field uses the `wasm://` scheme following cpex-core's convention.
The `sandbox_policy` is nested under the plugin's `config` key:

```yaml
plugins:
  - name: my-plugin
    kind: "wasm://plugin.wasm"
    hooks: [cmf.tool_pre_invoke]
    capabilities: [read_security]
    config:
      sandbox_policy:
        allowed_filesystem:
          - dir: /tmp/data
            permission: "read"
        allowed_network: ["api.example.com"]
        allowed_env: ["API_KEY"]
        resources:
          max_fuel: 500000000
          max_memory_bytes: 5242880
          max_execution_time_ms: 5000
          max_instances: 10
          max_tables: 10
```

If `sandbox_policy` is absent or all lists are empty, deny-by-default applies (no filesystem, no network, no env vars).
