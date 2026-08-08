---
title: "cpex-wasm-plugin (Guest SDK)"
weight: 30
---

# cpex-wasm-plugin — Guest SDK

The `cpex-wasm-plugin` crate is the **guest-side SDK** that plugin authors use to write CPEX plugins compiled to WebAssembly. It provides WIT bindings, type conversions, host logging, and macros that eliminate boilerplate so you can focus on hook logic.

## What it does

1. Generates Rust bindings from the `wit/world.wit` interface definition via `wit-bindgen`
2. Provides a prelude with all the types, traits, and macros needed to write a plugin
3. Handles bidirectional type conversion between WIT component-model types and `cpex-core` native types
4. Routes incoming hook calls to the correct handler based on payload variant (CMF, Identity, Delegation, Custom)
5. Provides structured host logging (`cpex_log!` macro) that routes messages to the host's tracing infrastructure

## Crate structure

### `src/lib.rs`

The SDK glue layer. Responsibilities:

- **WIT binding generation** — calls `wit_bindgen::generate!` for the `"plugin"` world
- **Prelude module** — re-exports traits (`HookHandler`, `Plugin`, `PluginConfig`), payload types (`CmfHook`, `MessagePayload`, `IdentityHook`, `IdentityPayload`, `TokenDelegateHook`, `DelegationPayload`), error types, and macros
- **`register_wasm_plugin!` macro** — the core macro that generates a WIT `Guest` impl. It dispatches incoming `hook-payload` variants to the appropriate `HookHandler<H>` impl on your plugin struct
- **`host_log()` / `cpex_log!`** — structured logging from inside the sandbox, routed to the host's tracing subscriber
- **`__block_on`** — a minimal synchronous async executor (10,000-poll cap) for plugins that need to make outbound HTTP calls via WASI
- **Feature-gated demo registrations** — 17 example plugins selectable via Cargo features

### `src/plugin.rs`

The user-facing plugin template. This is where you write your plugin logic:

```rust
use cpex_wasm_plugin::prelude::*;

pub struct UserPlugin;

impl Plugin for UserPlugin {
    fn config() -> PluginConfig {
        PluginConfig {
            name: "my-plugin".into(),
            kind: "wasm://my-plugin.wasm".into(),
            hooks: vec!["cmf.tool_pre_invoke".into()],
            ..Default::default()
        }
    }
}

impl HookHandler<CmfHook> for UserPlugin {
    fn handle(&self, payload: &MessagePayload, ext: &Extensions, ctx: &PluginContext)
        -> PluginResult<MessagePayload>
    {
        // Your logic here
        PluginResult::allow()
    }
}
```

### `src/conversions.rs`

Bidirectional type conversions (~1900 lines) between WIT-generated types and `cpex-core` native types:

| Direction | Coverage |
|-----------|----------|
| WIT → Native | MessagePayload, IdentityPayload, DelegationPayload, Extensions (all 12 types), PluginContext |
| Native → WIT | HookResult, MessagePayload, IdentityPayload, DelegationPayload, Extensions (request, security, http, meta) |

This file also handles `CustomPayload` serialization via `WasmSerializablePayload::from_wasm_bytes` / `to_wasm_bytes`.

### `src/examples/`

Feature-gated example plugins compiled via Cargo features. Each demonstrates a different hook or sandbox capability:

| Plugin | Feature flag | Purpose |
|--------|-------------|---------|
| `identity_checker` | `identity-checker` | Resolves identity from token/headers |
| `header_injector` | `header-injector` | Adds/modifies HTTP headers |
| `audit_logger` | `audit-logger` | Logs all hook invocations (fire-and-forget) |
| `token_attenuator` | `token-attenuator` | Mints scoped delegation tokens |
| `pii_guard` | `pii-guard` | Blocks PII in tool arguments |
| `remote_authz` | `remote-authz` | Makes outbound HTTP for authorization |
| `noop` | `noop` | Minimal pass-through (benchmarking baseline) |
| `fs_sandbox_demo` | `fs-sandbox-demo` | Exercises filesystem permission levels |
| `env_sandbox_demo` | `env-sandbox-demo` | Tests env variable visibility |
| `net_http_test` | `net-http-test` | Tests outbound HTTP policy enforcement |
| `compute_bench` | `compute-bench` | CPU-intensive work for perf comparison |
| `tool_invoke_checker` | `tool-invoke-checker` | Validates tool call arguments |
| `resource_test` | `resource-test` | Tests resource limit enforcement |

## WIT interface (`wit/world.wit`)

The WIT file defines the contract between host and guest under the `cpex:plugin` package.

### The plugin world

```wit
world plugin {
    // WASI imports available to the guest
    import wasi:io/poll;
    import wasi:io/error;
    import wasi:io/streams;
    import wasi:clocks/monotonic-clock;
    import wasi:http/types;
    import wasi:http/outgoing-handler;
    import host-logging;

    // The single function the guest must export
    export handle-hook: func(
        hook-name: string,
        payload: hook-payload,
        extensions: extensions,
        ctx: plugin-context,
    ) -> hook-result;
}
```

### Key types

**`hook-payload`** — a variant (tagged union) of all payload types:

```wit
variant hook-payload {
    cmf(message-payload),         // Tool calls, LLM I/O, resource fetches
    identity(identity-payload),   // Identity resolution
    delegation(delegation-payload), // Token delegation
    custom(custom-payload),       // User-defined types (opaque bytes)
}
```

**`hook-result`** — tells the framework what to do:

```wit
variant hook-result {
    continue-processing,       // Pass through unchanged
    modified-payload(...),     // Replace payload
    modified-extensions(...),  // Replace extensions
    modified-context(...),     // Update context state
    violation(...),            // Block the request
    metadata(...),             // Attach metadata only
}
```

**`host-logging`** interface — structured logging from guest to host:

```wit
interface host-logging {
    enum log-level { trace, debug, info, warn, error }
    log: func(level: log-level, message: string);
}
```

### WIT dependencies (`wit/deps/`)

Standard WASI interfaces that plugins can import: `io.wit`, `clocks.wit`, `http.wit`, `filesystem.wit`, `sockets.wit`, `cli.wit`, `random.wit`.

## Building a plugin

### Step 1: Write plugin logic

Edit `src/plugin.rs` (or create a new feature-gated file under `src/examples/`):

```rust
use cpex_wasm_plugin::prelude::*;

pub struct MyPlugin;

impl Plugin for MyPlugin {
    fn config() -> PluginConfig {
        PluginConfig {
            name: "my-plugin".into(),
            kind: "wasm://my-plugin.wasm".into(),
            hooks: vec!["cmf.tool_pre_invoke".into()],
            ..Default::default()
        }
    }
}

impl HookHandler<CmfHook> for MyPlugin {
    fn handle(&self, payload: &MessagePayload, ext: &Extensions, ctx: &PluginContext)
        -> PluginResult<MessagePayload>
    {
        cpex_log!(Info, "Processing tool call");

        // Block dangerous tools
        if let Some(tool_name) = payload.messages.first()
            .and_then(|m| m.content.first())
            .and_then(|c| match c { ContentPart::ToolCall(tc) => Some(&tc.name), _ => None })
        {
            if tool_name == "rm_rf" {
                return PluginResult::block("Dangerous tool blocked");
            }
        }

        PluginResult::allow()
    }
}
```

### Step 2: Build to WASM

```bash
cargo build -p cpex-wasm-plugin --target wasm32-wasip2 --release
```

Or use the Makefile (from `crates/cpex-wasm-host/`):

```bash
make build-all-plugins
```

The Makefile builds each plugin with its feature flag and places `.wasm` files in `wasm/`:

```bash
# Single plugin build pattern:
cargo build -p cpex-wasm-plugin \
    --target wasm32-wasip2 \
    --features identity-checker \
    --release

cp target/wasm32-wasip2/release/cpex_wasm_plugin.wasm wasm/identity-checker.wasm
```

### Step 3: Create an example plugin (feature-gated)

To add a new example plugin to the crate:

1. Create `src/examples/my_new_plugin.rs`
2. Add a feature flag in `Cargo.toml`:
   ```toml
   [features]
   my-new-plugin = []
   ```
3. Register it in `src/examples/mod.rs` under the feature gate
4. Add the plugin name to the appropriate list in `crates/cpex-wasm-host/Makefile`

## Advantages

- **Single compilation target** — any language with `wasm32-wasip2` support works (Rust, Go, C/C++, AssemblyScript)
- **Type-safe boundary** — WIT component model provides a schema-enforced contract; no raw byte manipulation
- **Zero-copy prelude** — `register_wasm_plugin!` eliminates boilerplate dispatch logic
- **Structured logging** — `cpex_log!` integrates with the host's tracing infrastructure without filesystem access
- **Custom payload extensibility** — `WasmSerializablePayload` trait lets you define domain-specific payloads without modifying WIT
- **Feature-gated examples** — one crate produces many `.wasm` binaries via feature flags

## Limitations

- **Immutable extension slots cannot be modified** — `agent`, `mcp`, `completion`, `provenance`, `llm`, `framework`, `meta`, and `request` are read-only by design (matching native plugin behavior); changes are discarded by the host via Arc pointer validation. Mutable slots (`security`, `http`, `delegation`, `custom`) are fully persisted
- **Synchronous execution model** — `__block_on` polls a future up to 1,000,000 times; the host's epoch timeout is the primary safeguard against non-completing futures. If the cap is reached, the plugin aborts cleanly (WASM trap) rather than panicking
- **Single-function export** — all hooks route through one `handle-hook` entry point; you cannot export additional functions
- **No shared state between invocations** — each call may get a fresh `Store`; use `PluginContext` or module-level statics (`OnceLock`) for persistence
- **WASI P2 only** — plugins must target `wasm32-wasip2`, not the older `wasm32-wasi` (P1)
- **No raw token access** — `raw_token`, `bearer_token`, and credential bytes never cross the WASM boundary (intentional security design)
- **No standard networking libraries** — plugins use `wasi:http/outgoing-handler` for HTTP; `reqwest`, `std::net`, and raw sockets are unavailable
- **Non-exhaustive enum fallbacks** — `cpex-core` enums are `#[non_exhaustive]`; unrecognized variants are logged and mapped to a safe default rather than causing a compile error
