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
├── Makefile                    # Build plugin + host
├── config/
│   └── config.yaml            # Plugin sandbox policy config
├── examples/
│   └── wasm_plugin_demo.rs    # Integration with PluginManager
├── src/
│   ├── lib.rs                 # Module exports
│   ├── sandbox_manager.rs     # Core: wasmtime engine, plugin loading, invocation
│   ├── policy_loader.rs       # Parses sandbox config (filesystem, network, env, resources)
│   ├── conversions.rs         # Native cpex-core types ↔ WIT types
│   └── factory.rs             # PluginFactory bridge for PluginManager integration
├── wasm/
│   └── plugin.wasm            # Compiled WASM plugin (from cpex-wasm-plugin)
└── wit/
    ├── world.wit              # Plugin interface definition
    └── deps/                  # WASI interface dependencies
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

## Building End-to-End

### 1. Build the WASM plugin

The plugin source lives in `../cpex-wasm-plugin`. Build it and copy the artifact:

```sh
make build-plugin
```

This runs `cargo build --target wasm32-wasip2 --release` in the plugin crate and copies the resulting `plugin.wasm` into `wasm/`.

### 2. Build the host

```sh
cargo build --release
```

Or build both in one step:

```sh
make build
```

### 3. Run the demo

```sh
cargo run --example wasm_plugin_demo
```

This loads `config/config.yaml`, registers the WASM plugin factory, and invokes the plugin through cpex-core's `PluginManager` pipeline.

### 4. Run tests

```sh
cargo test
```

## Usage

### Direct (without PluginManager)

```rust
use std::path::Path;
use cpex_wasm_host::policy_loader::SandboxPolicy;
use cpex_wasm_host::sandbox_manager::SandboxManager;

let policy = SandboxPolicy::default(); // deny-all sandbox
let mut manager = SandboxManager::new()?;
manager.load_wasmplugin(Path::new("wasm/plugin.wasm"), Some(&policy)).await?;

let result = manager.invoke(payload, extensions, ctx).await?;
```

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
