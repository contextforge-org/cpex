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

Parses sandbox configuration from YAML:

```yaml
plugins:
  - name: identity-checker
    kind: "wasm://plugin.wasm"
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

- Rust toolchain
- A compiled `plugin.wasm` in the `wasm/` directory (built from `cpex-wasm-plugin`)

To build the plugin:
```sh
make build-plugin
```

## Usage

### Direct (without PluginManager)

```rust
use cpex_wasm_host::policy_loader::load_plugin_sandbox_config;
use cpex_wasm_host::sandbox_manager::SandboxManager;

let mut manager = SandboxManager::new()?;
let config = load_plugin_sandbox_config("config/config.yaml", "identity-checker")?;
manager.load_wasmplugin(Path::new("wasm/plugin.wasm"), config).await?;

let result = manager.invoke(payload, extensions, ctx).await?;
```

### Via PluginManager

```rust
use cpex_wasm_host::factory::WasmPluginFactory;
use cpex_wasm_host::sandbox_manager::SandboxManager;

let sandbox = Arc::new(Mutex::new(SandboxManager::new()?));
let mgr = PluginManager::default();

mgr.register_factory(
    "wasm://plugin.wasm",
    Box::new(WasmPluginFactory::new(sandbox, PathBuf::from("wasm"))),
);

let config = parse_config(yaml)?;
mgr.load_config(config)?;
mgr.initialize().await?;

let (result, bg) = mgr
    .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, ext, None)
    .await;
```

## Running Examples

```sh
# Via PluginManager pipeline
cargo run --example wasm_plugin_demo
```

## Config Format

The `kind` field uses the `wasm://` scheme following cpex-core's convention:

```yaml
plugins:
  - name: my-plugin
    kind: "wasm://plugin.wasm"
    hooks: [cmf.tool_pre_invoke]
    capabilities: [read_security]
    sandbox_policy:
      allowed_network: ["api.example.com"]
      resources:
        max_fuel: 500000000
        max_memory_bytes: 5242880
```
