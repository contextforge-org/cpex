# Spec: Generalized WIT Interface for Arbitrary Payload Types

## Problem Statement

The current WASM plugin interface (`world.wit`) is hardcoded to `message-payload` (CMF MessagePayload). This means:

1. **Only CMF payloads work** — the host bridge (`WasmBridgeHandler`) hardcodes `downcast_ref::<MessagePayload>()`
2. **No hook-name dispatch** — the guest receives no hook name, so the same function handles everything blindly
3. **Limited extensions** — only 4 of 12+ native extension types cross the WASM boundary
4. **No context writeback** — guest modifications to `PluginContext` are lost
5. **No lifecycle hooks** — WASM plugins cannot run initialize/shutdown logic
6. **Duplicate crate** — `cpex-payload` is a manual fork of cpex-core types that drifts over time

Custom payload types like `ToolInvokePayload` (used in `cpex-core/examples/plugin_demo.rs`) cannot be processed by WASM plugins at all.

## Solution Overview

Two major changes:

1. **Feature-gate cpex-core** so it compiles to `wasm32-wasip2` without runtime modules — eliminating the need for `cpex-payload` as a separate crate. Plugin authors use cpex-core directly, writing identical code for native and WASM targets.

2. **Generalize the WIT interface** to handle any serializable payload type using a variant with a structured CMF fast-path and a generic JSON-bytes fallback, plus hook-name, extensions overflow, and context writeback.

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Backwards compat | Break v1, single world | Early-stage project; no deployed plugins to preserve |
| Hook name delivery | WIT parameter (`hook-name: string`) | Explicit, simple; stored in WasmBridgeHandler as side-channel on host |
| Serialization format | JSON via `list<u8>` | Already used throughout (context, arguments, metadata); serde_json is a dep |
| CMF optimization | Structured WIT variant (no full-payload serialization) | CMF is the majority case; keep existing field-by-field conversion path |
| Extensions overflow | `extra: option<string>` (JSON map) | Future-proof; avoids bloating WIT with 12+ record types |
| Guest SDK approach | Feature-gated cpex-core + registration macro | Plugin code is identical to native; no separate crate or different API |

---

## Phase 0: Feature-Gate cpex-core for WASM Compilation

**Goal:** Make `cpex-core` compilable to `wasm32-wasip2` by gating runtime-heavy modules behind a `runtime` feature, so WASM plugin authors can depend on cpex-core directly instead of the `cpex-payload` fork.

### 0.1 Cargo.toml Changes (`crates/cpex-core/Cargo.toml`)

```toml
[features]
default = ["runtime"]
runtime = ["dep:tokio", "dep:tokio-util", "dep:cpex-orchestration"]

[dependencies]
tokio = { workspace = true, optional = true }
tokio-util = { workspace = true, optional = true }
cpex-orchestration = { path = "../cpex-orchestration", optional = true }

# These remain always-on (WASM-compatible):
serde = { workspace = true }
serde_json = { workspace = true }
serde_yaml = { workspace = true }
async-trait = { workspace = true }
thiserror = { workspace = true }
tracing = { workspace = true }
uuid = { workspace = true }
futures = { workspace = true }
hashbrown = { workspace = true }
arc-swap = { workspace = true }
wildmatch = { workspace = true }
chrono = { workspace = true }
zeroize = "1.8"
```

### 0.2 Module Gating (`crates/cpex-core/src/lib.rs`)

```rust
pub mod cmf;
pub mod config;
pub mod context;
pub mod error;
pub mod extensions;
pub mod hooks;
pub mod plugin;
pub mod plugins;

// Runtime-only modules (need tokio, task spawning, orchestration)
#[cfg(feature = "runtime")]
pub mod executor;
#[cfg(feature = "runtime")]
pub mod manager;
#[cfg(feature = "runtime")]
pub mod registry;

// Factory is available always (trait definition is sync)
// but its full implementation references registry types
pub mod factory;
```

### 0.3 Modules That Need Conditional Compilation

| Module | What to gate | What remains |
|--------|-------------|--------------|
| `executor.rs` | Entire module | — |
| `manager.rs` | Entire module | — |
| `registry.rs` | `AnyHookHandler` trait + impls | Keep `HookEntry` struct definition if needed by factory |
| `hooks/adapter.rs` | `TypedHandlerAdapter` + its `AnyHookHandler` impl | — |
| `config.rs` | `load_config()` fn (uses `std::fs`) | `parse_config()` and all types remain |
| `plugin.rs` | Keep trait as-is | `#[async_trait]` compiles to WASM (just boxes the future); lifecycle methods won't be called across WASM boundary |
| `extensions/filter.rs` | `chrono::Utc::now()` call (line 809, test-only) | Gate behind `#[cfg(test)]` which already only runs on host |

### 0.4 The `Plugin` Trait Decision

Keep `#[async_trait]` on the `Plugin` trait unchanged. Rationale:
- `async-trait` generates `Pin<Box<dyn Future>>` which compiles to WASM
- WASM guest plugins implement `initialize()`/`shutdown()` as trivial no-ops (return `Ok(())`)
- These lifecycle methods are never called across the WASM boundary — the host manages lifecycle
- Avoids bifurcating the trait with `#[cfg]` which would complicate every plugin impl

### 0.5 Impact on cpex-wasm-plugin

Update `cpex-wasm-plugin/Cargo.toml`:

```toml
[dependencies]
cpex-core = { path = "../cpex-core", default-features = false }  # no runtime feature
wit-bindgen = "0.57"
wit-bindgen-rt = "0.44"
serde = { workspace = true }
serde_json = { workspace = true }
```

**Remove the `cpex-payload` dependency entirely.** All types (`MessagePayload`, `Extensions`, `PluginResult`, `PluginContext`, `HookHandler`, `HookTypeDef`, etc.) now come from `cpex-core`.

### 0.6 What This Enables

A WASM plugin author writes **identical code** to a native plugin:

```rust
// crates/my-wasm-plugin/Cargo.toml
[dependencies]
cpex-core = { path = "../cpex-core", default-features = false }
cpex-wasm-plugin = { path = "../cpex-wasm-plugin" }  # for the registration macro

[lib]
crate-type = ["cdylib"]

[package.metadata.component]
package = "cpex:plugin"
```

```rust
// crates/my-wasm-plugin/src/lib.rs
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::hooks::payload::Extensions;
use cpex_core::context::PluginContext;
use cpex_core::cmf::{MessagePayload, CmfHook};
use cpex_core::plugin::{Plugin, PluginConfig};
use cpex_wasm_plugin::register_wasm_plugin;

struct MyPlugin;

impl Plugin for MyPlugin {
    fn config(&self) -> &PluginConfig { todo!() }
}

impl HookHandler<CmfHook> for MyPlugin {
    async fn handle(
        &self,
        payload: &MessagePayload,
        extensions: &Extensions,
        ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        // Exact same code as a native plugin
        PluginResult::allow()
    }
}

register_wasm_plugin!(MyPlugin, [CmfHook]);
```

### 0.7 Deprecation Path for `cpex-payload`

1. Phase 0 makes cpex-core compilable without runtime
2. Update `cpex-wasm-plugin` to depend on cpex-core instead of cpex-payload
3. Update conversion code to use cpex-core types directly
4. Mark `cpex-payload` as deprecated
5. Remove `cpex-payload` once all references are migrated

---

## Phase 1: WIT Interface Redesign

**Files:** `crates/cpex-wasm-plugin/wit/world.wit`, `crates/cpex-wasm-host/wit/world.wit`

### New Types

```wit
record generic-payload {
    payload-type: string,
    payload-data: list<u8>,
}

variant hook-payload {
    cmf(message-payload),
    generic(generic-payload),
}
```

### Modified: `extensions`

```wit
record extensions {
    request: option<request-extension>,
    security: option<security-extension>,
    http: option<http-extension>,
    meta: option<meta-extension>,
    extra: option<string>,  // JSON-serialized map of additional extension types
}
```

### Replaced: `plugin-result` -> `hook-result`

```wit
record hook-result {
    continue-processing: bool,
    modified-payload: option<hook-payload>,
    modified-extensions: option<extensions>,
    modified-context: option<plugin-context>,
    violation: option<plugin-violation>,
    metadata: option<string>,
}
```

### New Export Signature

```wit
/// Known hook names (not exhaustive — hosts may define custom hooks):
///
/// Legacy (typed payloads):
///   "tool_pre_invoke", "tool_post_invoke"
///   "prompt_pre_fetch", "prompt_post_fetch"
///   "resource_pre_fetch", "resource_post_fetch"
///   "identity_resolve", "token_delegate"
///
/// CMF (MessagePayload):
///   "cmf.tool_pre_invoke", "cmf.tool_post_invoke"
///   "cmf.llm_input", "cmf.llm_output"
///   "cmf.prompt_pre_fetch", "cmf.prompt_post_fetch"
///   "cmf.resource_pre_fetch", "cmf.resource_post_fetch"
///
world plugin {
    import wasi:io/poll@0.2.6;
    import wasi:io/error@0.2.6;
    import wasi:io/streams@0.2.6;
    import wasi:clocks/monotonic-clock@0.2.6;
    import wasi:http/types@0.2.6;
    import wasi:http/outgoing-handler@0.2.6;

    use types.{hook-payload, extensions, plugin-context, hook-result};

    export handle-hook: func(
        hook-name: string,
        payload: hook-payload,
        extensions: extensions,
        ctx: plugin-context
    ) -> hook-result;
}
```

---

## Phase 2: `WasmSerializablePayload` Trait

**File:** `crates/cpex-core/src/hooks/payload.rs`

### Trait Definition

```rust
/// Opt-in trait for payloads that can cross the WASM serialization boundary.
/// Requires Serialize + Deserialize in addition to PluginPayload bounds.
pub trait WasmSerializablePayload: PluginPayload {
    /// Type discriminator string used in the WIT generic-payload record.
    fn payload_type_name() -> &'static str where Self: Sized;

    /// Serialize to JSON bytes for WASM transport.
    fn to_wasm_bytes(&self) -> Result<Vec<u8>, serde_json::Error>;

    /// Deserialize from JSON bytes received from WASM.
    fn from_wasm_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> where Self: Sized;
}
```

### Convenience Macro

```rust
#[macro_export]
macro_rules! impl_wasm_payload {
    ($ty:ty, $name:literal) => {
        impl $crate::hooks::payload::WasmSerializablePayload for $ty {
            fn payload_type_name() -> &'static str { $name }
            fn to_wasm_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
                serde_json::to_vec(self)
            }
            fn from_wasm_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
                serde_json::from_slice(bytes)
            }
        }
    };
}
```

### Built-in Implementations

```rust
// In crates/cpex-core/src/cmf/message.rs
impl_wasm_payload!(MessagePayload, "cmf.message");
```

---

## Phase 3: Host-Side Changes (`cpex-wasm-host`)

### 3.1 PayloadSerializerRegistry (new file: `src/payload_registry.rs`)

Maps `TypeId` to serialization/deserialization functions so the host can handle any registered payload type:

```rust
pub struct PayloadSerializerRegistry {
    by_type_id: HashMap<TypeId, PayloadCodec>,
    by_type_name: HashMap<String, PayloadCodec>,
}

struct PayloadCodec {
    type_name: String,
    type_id: TypeId,
    serialize: Arc<dyn Fn(&dyn PluginPayload) -> Result<Vec<u8>> + Send + Sync>,
    deserialize: Arc<dyn Fn(&[u8]) -> Result<Box<dyn PluginPayload>> + Send + Sync>,
}

impl PayloadSerializerRegistry {
    pub fn register<T: WasmSerializablePayload>(&mut self) { ... }
    pub fn serialize(&self, payload: &dyn PluginPayload) -> Result<(String, Vec<u8>)> { ... }
    pub fn deserialize(&self, type_name: &str, bytes: &[u8]) -> Result<Box<dyn PluginPayload>> { ... }
}
```

### 3.2 SandboxManager (`src/sandbox_manager.rs`)

Update `wasmtime::component::bindgen!` for new WIT world. Change invoke signature:

```rust
pub async fn invoke(
    &mut self,
    hook_name: &str,
    payload: types::HookPayload,
    extensions: types::Extensions,
    ctx: types::PluginContext,
) -> Result<types::HookResult>
```

Calls `instance.call_handle_hook(&mut store, hook_name, &payload, &extensions, &ctx)`.

### 3.3 WasmBridgeHandler (`src/factory.rs`)

Store `hook_name: String` per handler instance (set at registration from config). Invoke logic:

```rust
async fn invoke(&self, payload: &dyn PluginPayload, extensions: &Extensions, ctx: &mut PluginContext)
    -> Result<Box<dyn Any + Send + Sync>, Box<PluginError>>
{
    // Build WIT payload: try CMF fast-path first, fall back to generic
    let wit_payload = if let Some(cmf) = payload.as_any().downcast_ref::<MessagePayload>() {
        types::HookPayload::Cmf(native_payload_to_wit(cmf))
    } else {
        let (type_name, bytes) = self.registry.serialize(payload)?;
        types::HookPayload::Generic(types::GenericPayload {
            payload_type: type_name,
            payload_data: bytes,
        })
    };

    let wit_ext = native_extensions_to_wit_v2(extensions);
    let wit_ctx = native_context_to_wit(ctx);

    let result = self.sandbox.lock().await
        .invoke(&self.hook_name, wit_payload, wit_ext, wit_ctx).await?;

    // Context writeback
    if let Some(modified_ctx) = result.modified_context {
        merge_wit_context_into_native(modified_ctx, ctx);
    }

    // Convert result
    let native_result = hook_result_to_native(result, &self.registry)?;
    Ok(erase_result(native_result))
}
```

### 3.4 Conversions (`src/conversions.rs`)

New/modified functions:
- `native_extensions_to_wit_v2()` — populates `extra` with JSON of agent/mcp/completion/llm/framework/provenance extensions
- `wit_extensions_v2_to_native()` — deserializes `extra` back into the appropriate extension slots
- `hook_result_to_native()` — dispatches on `modified-payload` variant (CMF vs Generic)
- `merge_wit_context_into_native()` — context writeback

---

## Phase 4: Guest-Side Changes (`cpex-wasm-plugin`)

### 4.1 Registration Macro — Framework-Driven Dispatch

The guest SDK provides a `register_wasm_plugin!` macro that mirrors cpex-core's `TypedHandlerAdapter` pattern. Plugin authors implement `HookHandler<H>` (from cpex-core) and the macro generates the WIT glue with automatic dispatch:

```rust
/// Register a WASM plugin with its supported hook types.
/// The macro generates the Guest impl that:
/// 1. Receives WIT types from the host
/// 2. Converts to native cpex-core types
/// 3. Routes to the correct HookHandler<H> impl based on payload type
/// 4. Converts the PluginResult back to WIT
#[macro_export]
macro_rules! register_wasm_plugin {
    ($plugin_ty:ty, [$($hook:ty),+ $(,)?]) => {
        struct GuestImpl;

        impl Guest for GuestImpl {
            fn handle_hook(
                hook_name: String,
                payload: WitHookPayload,
                extensions: WitExtensions,
                ctx: WitPluginContext,
            ) -> WitHookResult {
                let plugin = <$plugin_ty>::default();
                let native_ext = wit_extensions_to_native(extensions);
                let mut native_ctx = wit_context_to_native(ctx);

                match payload {
                    WitHookPayload::Cmf(mp) => {
                        let native_payload = wit_payload_to_native(mp);
                        // Dispatch to the HookHandler impl whose Payload = MessagePayload
                        let result = cpex_wasm_plugin::dispatch_cmf(
                            &plugin, &hook_name, &native_payload, &native_ext, &mut native_ctx
                        );
                        native_result_to_hook_result(result, &native_ctx)
                    }
                    WitHookPayload::Generic(gp) => {
                        // Dispatch based on payload_type string
                        let result = cpex_wasm_plugin::dispatch_generic::<$plugin_ty>(
                            &plugin, &hook_name, &gp.payload_type, &gp.payload_data,
                            &native_ext, &mut native_ctx
                        );
                        generic_result_to_hook_result(result, &native_ctx)
                    }
                }
            }
        }
        export!(GuestImpl);
    };
}
```

### 4.2 Plugin Authoring Experience (Identical to Native)

```rust
use cpex_core::prelude::*;  // Plugin, HookHandler, PluginResult, Extensions, etc.
use cpex_wasm_plugin::register_wasm_plugin;

struct MyPlugin;

impl Plugin for MyPlugin {
    fn config(&self) -> &PluginConfig { &DEFAULT_CONFIG }
}

// CMF hook — same impl as a native plugin
impl HookHandler<CmfHook> for MyPlugin {
    async fn handle(
        &self,
        payload: &MessagePayload,
        extensions: &Extensions,
        ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        match ctx.get_local("hook_name").and_then(|v| v.as_str()) {
            Some("cmf.tool_pre_invoke") => { /* pre-invoke logic */ }
            Some("cmf.tool_post_invoke") => { /* post-invoke logic */ }
            _ => {}
        }
        PluginResult::allow()
    }
}

// Custom payload hook — also same pattern as native
impl HookHandler<ToolPreInvoke> for MyPlugin {
    async fn handle(
        &self,
        payload: &ToolInvokePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<ToolInvokePayload> {
        if payload.user.is_empty() {
            return PluginResult::deny(PluginViolation::new("no_identity", "User required"));
        }
        PluginResult::allow()
    }
}

register_wasm_plugin!(MyPlugin, [CmfHook, ToolPreInvoke]);
```

### 4.3 How Dispatch Works Inside the Macro

The `register_wasm_plugin!` macro expands to code that:

1. For **CMF variant**: converts WIT `message-payload` → cpex-core `MessagePayload`, calls `<MyPlugin as HookHandler<CmfHook>>::handle()`
2. For **Generic variant**: looks at `payload_type` string, deserializes bytes using `WasmSerializablePayload::from_wasm_bytes()`, calls the matching `HookHandler<H>::handle()`

The dispatch table for generic payloads is built at compile time from the hook type list in the macro invocation. Each `HookTypeDef` in the list has an associated `Payload` type with a `payload_type_name()` — the macro generates a match arm per entry.

### 4.4 Conversions (`src/conversions.rs`)

Update to use cpex-core types directly (no more cpex-payload):
- `wit_payload_to_native()` → `cpex_core::cmf::MessagePayload`
- `wit_extensions_to_native()` → `cpex_core::hooks::payload::Extensions`
- `wit_context_to_native()` → `cpex_core::context::PluginContext`
- Handle `HookPayload` variant in both directions
- Include `modified-context` in result
- Handle `extra` extensions field

---

## Phase 5: Examples

### 5.1 Update existing demo (`crates/cpex-wasm-host/examples/wasm_plugin_demo.rs`)
- Adapt to new `HookPayload`/`HookResult` types from updated bindgen

### 5.2 New generic payload demo (`crates/cpex-wasm-host/examples/wasm_generic_payload_demo.rs`)

```rust
// Host side — same as plugin_demo.rs but routes through WASM
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ToolInvokePayload {
    tool_name: String,
    user: String,
    arguments: String,
}
impl_plugin_payload!(ToolInvokePayload);
impl_wasm_payload!(ToolInvokePayload, "cpex.tool_invoke");

// Register in PayloadSerializerRegistry, invoke through WASM pipeline
let mut registry = PayloadSerializerRegistry::new();
registry.register::<ToolInvokePayload>();
registry.register::<MessagePayload>();

// The PluginManager invokes as normal — WasmBridgeHandler handles the rest
mgr.invoke::<ToolPreInvoke>(payload, ext, None).await;
```

### 5.3 WASM guest plugin handling both CMF and custom payloads

```rust
// Guest side — uses cpex-core directly
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::cmf::{MessagePayload, CmfHook};

struct DemoPlugin;

impl Plugin for DemoPlugin {
    fn config(&self) -> &PluginConfig { &DEFAULT_CONFIG }
}

impl HookHandler<CmfHook> for DemoPlugin {
    async fn handle(&self, payload: &MessagePayload, ext: &Extensions, ctx: &mut PluginContext)
        -> PluginResult<MessagePayload>
    {
        // Same identity_check logic that currently lives in cpex-payload
        cpex_core::plugins::identity_checker::identity_check(payload, ext, ctx)
    }
}

impl HookHandler<ToolPreInvoke> for DemoPlugin {
    async fn handle(&self, payload: &ToolInvokePayload, _ext: &Extensions, _ctx: &mut PluginContext)
        -> PluginResult<ToolInvokePayload>
    {
        if payload.user.is_empty() {
            return PluginResult::deny(PluginViolation::new("no_identity", "User required"));
        }
        PluginResult::allow()
    }
}

register_wasm_plugin!(DemoPlugin, [CmfHook, ToolPreInvoke]);
```

---

## Phase 6: Verification

1. `cargo build -p cpex-core` — default features, no breakage for native users
2. `cargo build -p cpex-core --no-default-features --target wasm32-wasip2` — WASM compilation works
3. `cargo build -p cpex-wasm-host` — updated bindgen, factory, conversions compile
4. `cargo build -p cpex-wasm-plugin --target wasm32-wasip2` — guest compiles (now uses cpex-core)
5. Run `wasm_plugin_demo` example — CMF payload flows end-to-end
6. Run `wasm_generic_payload_demo` example — custom `ToolInvokePayload` crosses WASM boundary
7. `cargo test -p cpex-core` — all existing tests pass (they use default features)
8. `cargo test -p cpex-wasm-host` — round-trip serialization tests for generic payloads

---

## Files Summary

| File | Action |
|------|--------|
| `crates/cpex-core/Cargo.toml` | Add `runtime` feature, make tokio/tokio-util/cpex-orchestration optional |
| `crates/cpex-core/src/lib.rs` | `#[cfg(feature = "runtime")]` on executor, manager, registry modules |
| `crates/cpex-core/src/hooks/adapter.rs` | Gate `TypedHandlerAdapter` behind `#[cfg(feature = "runtime")]` |
| `crates/cpex-core/src/config.rs` | Gate `load_config()` behind `#[cfg(feature = "runtime")]` |
| `crates/cpex-core/src/hooks/payload.rs` | Add `WasmSerializablePayload` trait + `impl_wasm_payload!` macro |
| `crates/cpex-core/src/cmf/message.rs` | Add `impl_wasm_payload!(MessagePayload, "cmf.message")` |
| `crates/cpex-wasm-plugin/wit/world.wit` | Rewrite — new types + export signature |
| `crates/cpex-wasm-host/wit/world.wit` | Mirror of above |
| `crates/cpex-wasm-host/src/payload_registry.rs` | **New** — PayloadSerializerRegistry |
| `crates/cpex-wasm-host/src/sandbox_manager.rs` | Updated bindgen + invoke signature |
| `crates/cpex-wasm-host/src/factory.rs` | Payload dispatch, hook_name, registry usage |
| `crates/cpex-wasm-host/src/conversions.rs` | Generic payload + extensions overflow + context writeback |
| `crates/cpex-wasm-host/src/lib.rs` | Export payload_registry module |
| `crates/cpex-wasm-plugin/Cargo.toml` | Replace `cpex-payload` dep with `cpex-core` (no default features) |
| `crates/cpex-wasm-plugin/src/lib.rs` | `register_wasm_plugin!` macro + dispatch logic |
| `crates/cpex-wasm-plugin/src/conversions.rs` | Update to use cpex-core types; add HookPayload + context writeback |
| `crates/cpex-wasm-host/examples/wasm_plugin_demo.rs` | Update to new API |
| `crates/cpex-wasm-host/examples/wasm_generic_payload_demo.rs` | **New** — generic payload E2E demo |

---

## Dependency Order

```
Phase 0 (Feature-gate cpex-core)
    │
    ├─> Phase 1 (WIT redesign)          ─┐
    │                                     │
    └─> Phase 2 (WasmSerializablePayload) ─┼─> Phase 3 (Host-side) ─> Phase 4 (Guest-side) ─> Phase 5 (Examples) ─> Phase 6 (Verify)
                                           │
                                           └─> Can proceed in parallel
```

---

## Key Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        HOST PROCESS                              │
│                                                                  │
│  PluginManager                                                   │
│    │                                                             │
│    ├─ invoke::<ToolPreInvoke>(payload, ext, ctx)                │
│    │                                                             │
│    ▼                                                             │
│  WasmBridgeHandler (hook_name = "tool_pre_invoke")              │
│    │                                                             │
│    ├─ payload.downcast::<MessagePayload>()?                      │
│    │   → YES: HookPayload::Cmf(native_payload_to_wit(p))       │
│    │   → NO:  registry.serialize(payload)                        │
│    │          → HookPayload::Generic { type, bytes }            │
│    │                                                             │
│    ▼                                                             │
│  SandboxManager.invoke(hook_name, wit_payload, wit_ext, wit_ctx)│
│    │                                                             │
│════╪═══════════════ WASM BOUNDARY ═══════════════════════════════│
│    ▼                                                             │
│  Guest: handle-hook(hook_name, payload, extensions, ctx)         │
│    │                                                             │
│    ├─ Convert WIT → cpex-core native types                      │
│    ├─ Match on hook-payload variant                              │
│    │   → Cmf: call HookHandler<CmfHook>::handle()              │
│    │   → Generic: deserialize, call HookHandler<H>::handle()    │
│    ├─ Convert PluginResult → WIT hook-result                    │
│    │                                                             │
│════╪═══════════════ WASM BOUNDARY ═══════════════════════════════│
│    ▼                                                             │
│  WasmBridgeHandler                                               │
│    ├─ Context writeback (if modified)                            │
│    ├─ hook_result_to_native() → PluginResult                    │
│    └─ erase_result() → Box<dyn Any>                             │
│                                                                  │
│  PluginManager continues pipeline...                             │
└─────────────────────────────────────────────────────────────────┘
```
