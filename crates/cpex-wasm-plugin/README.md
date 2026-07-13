# cpex-wasm-plugin

WASM Plugin SDK and built-in plugins for the CPEX framework. Compiles CPEX plugins into portable `.wasm` components that the host (`cpex-wasm-host`) loads and executes in sandboxed wasmtime environments.

## SDK Architecture

This crate serves as both an **SDK** (WIT bindings, conversions, macro) and a **plugin collection** (feature-gated). Adding a new WASM plugin requires only writing a handler implementation — the SDK generates all WIT glue automatically.

```
cpex-wasm-plugin/
├── Cargo.toml                 # cdylib target, feature flags per plugin
├── Makefile                   # Build targets (single plugin, all plugins)
├── src/
│   ├── lib.rs                 # SDK: wit_bindgen, register_wasm_plugin! macro, helpers
│   ├── conversions.rs         # WIT ↔ cpex-core type mappings (all 11 extension types)
│   └── plugins/
│       ├── mod.rs             # Feature-gated module declarations
│       ├── identity_checker.rs  # Checks PII access via labels + subject roles
│       ├── header_injector.rs   # Modifies extensions: adds label + injects header
│       └── audit_logger.rs      # Read-only audit logging
└── wit/
    ├── world.wit              # Plugin interface definition (shared with host)
    └── deps/                  # WASI interface dependencies
```

## How It Works

1. **WIT Interface (`wit/world.wit`)** defines the contract. The plugin exports a single function:

   ```wit
   export handle-hook: func(
     hook-name: string,
     payload: hook-payload,
     extensions: extensions,
     ctx: plugin-context
   ) -> hook-result;
   ```

2. **`register_wasm_plugin!` macro** generates the complete `Guest` impl. Plugin authors implement `HookHandler<H>` from `cpex-core` — identical code to a native plugin.

3. **Feature-gated registration** — each plugin is a Cargo feature. Only one plugin compiles into each `.wasm` binary:

   ```toml
   [features]
   default = ["identity-checker"]
   identity-checker = []
   header-injector = []
   audit-logger = []
   ```

4. **Type Conversions (`src/conversions.rs`)** handles bidirectional mapping between WIT-generated types and native `cpex-core` types across all 11 extension types.

## Built-in Plugins

| Plugin | Feature Flag | Capabilities | Behavior |
|--------|-------------|--------------|----------|
| `identity-checker` | `identity-checker` | `read_labels`, `read_subject`, `read_roles` | Checks PII access — denies if subject lacks required role |
| `header-injector` | `header-injector` | `read_headers`, `write_headers`, `append_labels` | Adds "PROCESSED" label + "X-Processed-By" header |
| `audit-logger` | `audit-logger` | `read_headers`, `read_labels` | Read-only audit logging of tool invocations |

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

### Single plugin (default: identity-checker)

```sh
make all
```

### All plugins

```sh
make build-all
```

This builds each feature into a separate `.wasm` and stages them in `../cpex-wasm-host/wasm/`:

```
wasm/identity-checker.wasm
wasm/header-injector.wasm
wasm/audit-logger.wasm
```

### Manual build (specific plugin)

```sh
cargo build --target wasm32-wasip2 --release --features header-injector --no-default-features
cp target/wasm32-wasip2/release/cpex_wasm_plugin.wasm ../cpex-wasm-host/wasm/header-injector.wasm
```

## Running the Demos

From the workspace root:

```sh
# Build all plugins + run the capabilities demo (3 plugins, capability isolation)
cd crates/cpex-wasm-plugin && make build-all && cd ../..
cargo run -p cpex-wasm-host --example wasm_capabilities_demo

# Or use the host Makefile:
cd crates/cpex-wasm-host && make run-capabilities-demo
```

Expected output shows three plugins running in the same pipeline with different views of the extensions:
- `identity-checker` sees labels + subject, HTTP NOT visible
- `header-injector` sees HTTP, subject NOT visible, adds label + injects header
- `audit-logger` logs tool name, labels (including "PROCESSED"), request-id

## Writing a New Plugin

Adding a new plugin requires **3 steps** — no WIT knowledge needed:

### Step 1: Create `src/plugins/my_plugin.rs`

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

static PLUGIN_CONFIG: std::sync::OnceLock<PluginConfig> = std::sync::OnceLock::new();

#[async_trait]
impl Plugin for MyPlugin {
    fn config(&self) -> &PluginConfig {
        PLUGIN_CONFIG.get_or_init(|| PluginConfig {
            name: "my-plugin".to_string(),
            kind: "wasm://my-plugin.wasm".to_string(),
            hooks: vec!["cmf.tool_pre_invoke".to_string()],
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
        // Your logic here — identical to a native plugin.
        PluginResult::allow()
    }
}
```

### Step 2: Add the feature flag

In `Cargo.toml`:
```toml
[features]
my-plugin = []
```

In `src/plugins/mod.rs`:
```rust
#[cfg(feature = "my-plugin")]
pub mod my_plugin;
```

In `src/lib.rs` (at the bottom, with the other registrations):
```rust
#[cfg(feature = "my-plugin")]
register_wasm_plugin!(
    plugins::my_plugin::MyPlugin,
    [cpex_core::cmf::CmfHook]
);
```

### Step 3: Build and stage

```sh
cargo build --target wasm32-wasip2 --release --features my-plugin --no-default-features
cp target/wasm32-wasip2/release/cpex_wasm_plugin.wasm ../cpex-wasm-host/wasm/my-plugin.wasm
```

That's it — your WASM component is ready for the host to load.

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

### Modifying extensions (labels, headers)

Use `cow_copy()` to get a mutable workspace, modify it, and return via `PluginResult::modify_extensions`:

```rust
use cpex_core::extensions::guarded::Guarded;

let mut modified = extensions.cow_copy();

// Add a security label (requires append_labels capability on host)
if let Some(ref mut sec) = modified.security {
    sec.add_label("PROCESSED");
}

// Modify HTTP headers (requires write_headers capability on host)
let mut http = extensions.http.as_ref().map(|h| (**h).clone()).unwrap_or_default();
http.set_header("X-Processed-By", "my-plugin");
modified.http = Some(Guarded::new(http));

PluginResult::modify_extensions(modified)
```

The host executor validates modifications against the plugin's declared capabilities — if the plugin lacks `write_headers`, HTTP changes are rejected.

### Modifying payload or context

```rust
ctx.local_state.insert("checked_at".to_string(), serde_json::json!("pre_invoke"));

let mut modified = payload.clone();
modified.message.content.push(ContentPart::Text {
    text: "[audited]".into(),
});
PluginResult::allow_with_payload(modified)
```

### Handling non-CMF hooks (identity_resolve, token_delegate, custom payloads)

Hooks whose payload is not `MessagePayload` cross the boundary via the WIT
`generic` variant: the host serializes the payload with its type
discriminator, and `register_wasm_plugin!` routes it to the matching
`HookHandler<H>` by that discriminator. Implement the handler exactly like a
native plugin and add the hook type to the registration list:

```rust
use cpex_core::identity::{IdentityHook, IdentityPayload};

impl HookHandler<IdentityHook> for MyPlugin {
    async fn handle(
        &self,
        payload: &IdentityPayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<IdentityPayload> {
        // Resolve identity from payload.headers() — the raw token is
        // #[serde(skip)] and never enters the sandbox.
        let mut resolved = payload.clone();
        // ... populate resolved.subject / resolved.client ...
        PluginResult::modify_payload(resolved)
    }
}

register_wasm_plugin!(MyPlugin, [CmfHook, IdentityHook]);
```

Three requirements for a payload type to cross the boundary:

1. It implements `WasmSerializablePayload` — built-ins already do
   (`MessagePayload` = `"cmf.message"`, `IdentityPayload` = `"cpex.identity"`,
   `DelegationPayload` = `"cpex.delegation"`); custom types use
   `impl_wasm_payload!(MyPayload, "my.payload")`.
2. The host registers it in the `PayloadSerializerRegistry`
   (`WasmPluginFactory::with_builtin_payloads` covers the built-ins).
3. Fields carrying secrets are `#[serde(skip)]` if they must stay host-side —
   skipped fields never serialize into the sandbox and never come back.

A generic payload no listed hook handles returns `allow()` (pass-through); a
payload that matches a listed hook but fails to decode returns a deny
violation rather than silently skipping the plugin's check.

---

## Constraints

### One plugin per binary

`register_wasm_plugin!` calls `export!(_WasmGuestImpl)` which is a WIT component export — there can only be one per `.wasm` binary. That's why each plugin is gated behind a Cargo feature — building with `--features header-injector --no-default-features` produces a binary containing only the header-injector plugin.

### WASM-compatible dependencies only

Any crate you `use` inside `plugin.rs` must compile to `wasm32-wasip2`. The compiler will tell you immediately if something doesn't compile for WASM.

| Works in WASM | Does not work in WASM |
|---|---|
| `cpex-core` (no default features) | `cpex-core` with `runtime` feature (pulls Tokio) |
| `serde`, `serde_json` | Tokio, `std::thread::spawn` |
| `chrono` | `std::fs`, `std::net` |
| `async-trait` | Any crate that does file I/O or spawns OS threads |

---

## Makefile Targets

| Target | Description |
|--------|-------------|
| `make all` | Build default plugin (identity-checker) and stage as `plugin.wasm` |
| `make build-all` | Build all three plugins and stage as separate `.wasm` files |
| `make build-debug` | Debug build (faster compile) |
| `make check` | Type-check only (fastest feedback) |
| `make clean` | Remove all artifacts |
| `make run-demo` | Build + stage + run the CMF demo |
| `make run-all-demos` | Build + stage + run all existing demos |
| `make help` | Show all available targets |

---

## Dependency Notes

This crate depends on `cpex-core` with `default-features = false`. This excludes the `runtime` feature (Tokio, task spawning, orchestration), which is not available in WASM. All types, traits, and extension types are available; only the executor/manager/registry modules are excluded.
