# cpex-wasm-plugin

A WebAssembly (WASM) component that compiles CPEX plugins into a portable `plugin.wasm` binary. The host (`cpex-wasm-host`) loads and executes this component at runtime, enabling sandboxed plugin execution across platforms.

## How It Works

1. **WIT Interface (`wit/world.wit`)** defines the contract between host and plugin. The plugin exports a single function:

   ```wit
   export handle-hook: func(
     hook-name: string,
     payload: hook-payload,
     extensions: extensions,
     ctx: plugin-context
   ) -> hook-result;
   ```

   `hook-payload` is a variant — either `cmf(message-payload)` for the structured CMF fast-path, or `generic(generic-payload)` for any serializable custom payload type.

2. **`register_wasm_plugin!` macro (`src/lib.rs`)** generates the complete `Guest` impl from a one-liner. Plugin authors implement `HookHandler<H>` from `cpex-core` — identical code to a native plugin — and register it:

   ```rust
   register_wasm_plugin!(MyPlugin, [CmfHook]);
   ```

3. **Plugin implementation (`src/plugin.rs`)** contains the actual plugin logic — `Plugin` trait impl and `HookHandler<H>` impl. No WIT types appear here; the conversion layer is fully handled by the SDK.

4. **Type Conversions (`src/conversions.rs`)** handles bidirectional mapping between WIT-generated types and native `cpex-core` types across all 11 extension types.

## Project Structure

```
cpex-wasm-plugin/
├── Cargo.toml          # Crate config (cdylib target, cpex-core no-default-features)
├── src/
│   ├── lib.rs          # SDK: bindgen, register_wasm_plugin! macro, __block_on, registration call
│   ├── plugin.rs       # Plugin implementation: Plugin + HookHandler<CmfHook> impls
│   └── conversions.rs  # WIT <-> cpex-core type mappings (full extension coverage)
└── wit/
    ├── world.wit       # Plugin interface definition
    └── deps/           # WASI interface dependencies
```

## Prerequisites

- Rust toolchain with the `wasm32-wasip2` target:
  ```sh
  rustup target add wasm32-wasip2
  ```
- `wasm-tools` CLI (optional, for validation and inspection):
  ```sh
  cargo install wasm-tools
  ```

## Building

From this directory:

```sh
cargo build --target wasm32-wasip2
cp target/wasm32-wasip2/debug/cpex_wasm_plugin.wasm ../cpex-wasm-host/wasm/plugin.wasm
```

For a release build:

```sh
cargo build --release --target wasm32-wasip2
cp target/wasm32-wasip2/release/cpex_wasm_plugin.wasm ../cpex-wasm-host/wasm/plugin.wasm
```

## Writing a Plugin

Any plugin you define in `plugin.rs` that implements `HookHandler<H>` compiles to a WASM component automatically. The code you write is **identical to a native plugin** — `cpex-core` (no default features) is WASM-safe, and the `register_wasm_plugin!` macro generates all the WIT glue for you.

### Step 1: Implement your plugin in `plugin.rs`

```rust
use async_trait::async_trait;
use cpex_core::cmf::{CmfHook, MessagePayload};
use cpex_core::context::PluginContext;
use cpex_core::error::{PluginError, PluginViolation};
use cpex_core::extensions::container::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::plugin::{Plugin, PluginConfig};

pub struct MyPlugin;

impl Default for MyPlugin {
    fn default() -> Self { Self }
}

static CONFIG: std::sync::OnceLock<PluginConfig> = std::sync::OnceLock::new();

#[async_trait]
impl Plugin for MyPlugin {
    fn config(&self) -> &PluginConfig {
        CONFIG.get_or_init(|| PluginConfig {
            name: "my-plugin".to_string(),
            kind: "wasm://plugin.wasm".to_string(),
            hooks: vec!["cmf".to_string()],
            ..Default::default()
        })
    }
    async fn initialize(&self) -> Result<(), Box<PluginError>> { Ok(()) }
    async fn shutdown(&self) -> Result<(), Box<PluginError>> { Ok(()) }
}

impl HookHandler<CmfHook> for MyPlugin {
    async fn handle(
        &self,
        payload: &MessagePayload,
        extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        // Your logic here — inspect payload/extensions, return allow or deny.
        // This is the same code you would write for a native plugin.
        PluginResult::allow()
    }
}
```

### Step 2: Register it in `lib.rs`

Change the two lines at the bottom of `lib.rs`:

```rust
use plugin::MyPlugin;
register_wasm_plugin!(MyPlugin, [CmfHook]);
```

### Step 3: Build and stage

```sh
cargo build --target wasm32-wasip2
cp target/wasm32-wasip2/debug/cpex_wasm_plugin.wasm ../cpex-wasm-host/wasm/plugin.wasm
```

That's your WASM component, ready for the host to load.

### Denying a request

Return `PluginResult::deny(...)` with a `PluginViolation` to block processing:

```rust
if security.has_label("PII") && !subject.roles.contains("hr_admin") {
    return PluginResult::deny(PluginViolation::new(
        "insufficient_role",
        "Tool requires 'hr_admin' role for PII data",
    ));
}
```

### Reading extensions

All 11 extension types are available — security, HTTP, request, meta, agent, MCP, completion, provenance, LLM, framework, delegation:

```rust
// Security labels and subject identity
if let Some(ref security) = extensions.security {
    let labels: Vec<_> = security.labels.iter().collect();
    if let Some(ref subject) = security.subject {
        // subject.id, subject.roles, subject.permissions, ...
    }
    if let Some(ref client) = security.client {
        // client.client_id, client.trust_level, client.authorized_scopes, ...
    }
}

// Request tracing
if let Some(ref request) = extensions.request {
    // request.request_id, request.trace_id, request.environment, ...
}

// MCP tool metadata
if let Some(ref mcp) = extensions.mcp {
    if let Some(ref tool) = mcp.tool {
        // tool.name, tool.description, tool.input_schema, ...
    }
}
```

### Modifying payload or context

Return a `PluginResult` with `modified_payload` or use `ctx` for per-invocation state:

```rust
// Store a value in local context for the post-invoke call
ctx.local_state.insert("checked_at".to_string(), serde_json::json!("pre_invoke"));

// Return a modified payload
let mut modified = payload.clone();
modified.message.content.push(ContentPart::Text {
    text: "[audited]".into(),
});
PluginResult::allow_with_payload(modified)
```

---

## Two Constraints to Know

### One export per crate

`register_wasm_plugin!` calls `export!(_WasmGuestImpl)` which is a WIT component export — there can only be one per `.wasm` binary. `plugin.rs` should contain one plugin struct (or compose multiple behaviours into one). If you want multiple fully independent plugins each gets its own crate.

### WASM-compatible dependencies only

Any crate you `use` inside `plugin.rs` must compile to `wasm32-wasip2`. The compiler will tell you immediately if something doesn't compile for WASM.

| Works in WASM | Does not work in WASM |
|---|---|
| `cpex-core` (no default features) | `cpex-core` with `runtime` feature (pulls Tokio) |
| `serde`, `serde_json` | Tokio, `std::thread::spawn` |
| `chrono` | `std::fs`, `std::net` |
| `async-trait` | Any crate that does file I/O or spawns OS threads |

---

## Dependency Notes

This crate depends on `cpex-core` with `default-features = false`. This excludes the `runtime` feature (Tokio, task spawning, orchestration), which is not available in WASM. All types, traits, and extension types are available; only the executor/manager/registry modules are excluded.

`cpex-payload` (the former fork of cpex-core types) has been removed. All types come directly from `cpex-core`.
