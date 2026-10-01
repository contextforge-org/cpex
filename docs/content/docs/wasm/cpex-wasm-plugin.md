---
title: "cpex-wasm-plugin (Guest SDK)"
weight: 30
---

# cpex-wasm-plugin — Guest SDK

Write your plugin in Rust the same way you would a native `cpex-core` plugin — then run `make build` and get a portable, sandboxed `.wasm` binary. No WebAssembly knowledge required.

The `cpex-wasm-plugin` crate handles everything between your business logic and the WASM boundary: WIT bindings, type conversions, payload routing, and host logging. You implement `HookHandler<H>`, call `register_wasm_plugin!`, and the crate takes care of the rest.

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
- **`__block_on`** — a minimal synchronous async executor (1,000,000-poll cap) for plugins that need to make outbound HTTP calls via WASI
- **Feature-gated demo registrations** — 14 example plugins selectable via Cargo features

### `src/plugin.rs`

The user-facing plugin template. This is where you write your plugin logic:

```rust
use cpex_wasm_plugin::prelude::*;

#[derive(Default)]
pub struct UserPlugin;

#[async_trait]
impl Plugin for UserPlugin {
    fn config(&self) -> &PluginConfig {
        static CONFIG: OnceLock<PluginConfig> = OnceLock::new();
        CONFIG.get_or_init(|| PluginConfig {
            name: "my-plugin".into(),
            kind: "wasm://my-plugin.wasm".into(),
            hooks: vec!["cmf.tool_pre_invoke".into()],
            ..Default::default()
        })
    }
}

impl HookHandler<CmfHook> for UserPlugin {
    async fn handle(
        &self,
        payload: &MessagePayload,
        extensions: &Extensions,
        ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        // Your logic here
        PluginResult::allow()
    }
}
```

Key points:
- Plugin struct must implement `Default` (the macro constructs it via `Default::default()`)
- `config(&self)` returns a reference (`&PluginConfig`), not an owned value
- `handle()` is async and takes `ctx: &mut PluginContext` (mutable)
- The plugin is registered with `register_wasm_plugin!(UserPlugin, [CmfHook])`

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
| `tool_invoke_checker` | `tool-invoke-checker` | Validates tool call arguments |
| `audit_logger_custom` | `audit-logger-custom` | Custom payload audit logging |
| `compute_bench` | `compute-bench` | CPU-intensive work for fuel limit testing |
| `fs_sandbox_demo` | `fs-sandbox-demo` | Exercises filesystem permission levels |
| `env_sandbox_demo` | `env-sandbox-demo` | Tests env variable visibility |
| `resource_sandbox_demo` | `resource-sandbox-demo` | Tests resource limit enforcement |
| `net_sandbox_demo` | `net-sandbox-demo` | Tests outbound HTTP policy enforcement |

## The `register_wasm_plugin!` macro

This is the core macro that bridges your Rust plugin to the WASM component model. It generates all WIT bindings, payload routing, and export plumbing.

### Usage

```rust
// Single hook type
register_wasm_plugin!(MyPlugin, [CmfHook]);

// Multiple hook types
register_wasm_plugin!(MyPlugin, [CmfHook, IdentityHook]);

// Delegation hook
register_wasm_plugin!(MyPlugin, [TokenDelegateHook]);
```

### What it generates

1. A `_WasmGuestImpl` struct implementing the WIT `Guest` trait
2. Payload routing: dispatches `hook-payload` variants to the correct `HookHandler<H>::handle()` implementation
3. Type conversion: WIT types → native cpex-core types before your handler, native → WIT after
4. Error handling: payloads that fail to decode produce a `deny()` with code `"wasm_payload_decode_error"` (fail-closed)
5. Passthrough: payloads matching no listed hook type produce an `allow()` result (no-op)
6. The `export!(_WasmGuestImpl)` call that wires up the WASM component-model export

### Requirements

- Your plugin struct must implement `Default`
- Your plugin struct must implement `HookHandler<H>` for every `H` listed in the macro
- Each `H`'s `Payload` type must implement `WasmSerializablePayload`

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

**`hook-result`** — a record telling the framework what to do:

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

When `continue-processing` is `false`, the pipeline halts (deny). The optional fields allow modifying the payload, extensions, or context independently.

**`host-logging`** interface — structured logging from guest to host:

```wit
interface host-logging {
    enum log-level { trace, debug, info, warn, error }
    log: func(level: log-level, message: string);
}
```

### WIT dependencies (`wit/deps/`)

Standard WASI interfaces that plugins can import: `io.wit`, `clocks.wit`, `http.wit`, `filesystem.wit`, `sockets.wit`, `cli.wit`, `random.wit`.

## PluginResult — return values

Your handler returns a `PluginResult<P>` that tells the pipeline what to do:

| Constructor | Parameters | Effect |
|-------------|------------|--------|
| `PluginResult::allow()` | None | Continue processing, no modifications |
| `PluginResult::deny(violation)` | `PluginViolation::new("code", "message")` | Halt the pipeline with a reason |
| `PluginResult::modify_payload(payload)` | Modified payload | Continue with a replaced payload |
| `PluginResult::modify_extensions(ext)` | `OwnedExtensions` | Continue with modified extensions |
| `PluginResult::modify(payload, ext)` | Both | Continue with both modified |

### Deny example

```rust
PluginResult::deny(PluginViolation::new(
    "pii_access_denied",
    "PII clearance required to access this tool",
))
```

### Modify extensions example

```rust
let mut modified = extensions.cow_copy();
if let Some(ref mut http) = modified.http {
    http.set_header("X-Processed-By", "my-plugin");
}
PluginResult::modify_extensions(modified)
```

## Cross-invocation state

The Wasmtime Store **persists across invocations** — linear memory, module-level statics, and heap state survive between hook calls. Only fuel and epoch deadline are reset per invocation.

### Using `OnceLock` for initialization

```rust
use std::sync::OnceLock;

static STATE: OnceLock<MyState> = OnceLock::new();

impl HookHandler<CmfHook> for MyPlugin {
    async fn handle(
        &self,
        payload: &MessagePayload,
        extensions: &Extensions,
        ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        let state = STATE.get_or_init(|| {
            // Expensive initialization only runs on first invocation
            MyState::new()
        });
        // Use state across invocations...
        PluginResult::allow()
    }
}
```

### Using `PluginContext` for shared state

`PluginContext` has `local_state` (per-plugin) and `global_state` (cross-plugin) key-value maps that persist and are visible to the host:

```rust
// Write state
ctx.set_local("last_seen_tool", serde_json::json!("get_user"));

// Read state (may have been set by a prior invocation)
if let Some(val) = ctx.get_local("request_count") {
    // ...
}
```

## The async executor (`__block_on`)

WASM plugins cannot use tokio or any standard async runtime. The SDK provides a minimal synchronous poll loop that drives futures:

- Creates a no-op waker and polls the future repeatedly
- Poll cap: **1,000,000 iterations** (deliberately high for real network I/O)
- Most handlers complete on the first poll (they're synchronous internally)
- Outbound HTTP via WASI can yield multiple times while the host drives I/O
- If the cap is reached, the plugin traps cleanly (WASM trap) rather than hanging
- The host's epoch timeout is the primary safeguard against non-completing futures

## Building a plugin

### Step 1: Write plugin logic

Edit `src/plugin.rs` (or create a new feature-gated file under `src/examples/`):

```rust
use cpex_wasm_plugin::prelude::*;

#[derive(Default)]
pub struct MyPlugin;

#[async_trait]
impl Plugin for MyPlugin {
    fn config(&self) -> &PluginConfig {
        static CONFIG: OnceLock<PluginConfig> = OnceLock::new();
        CONFIG.get_or_init(|| PluginConfig {
            name: "my-plugin".into(),
            kind: "wasm://my-plugin.wasm".into(),
            hooks: vec!["cmf.tool_pre_invoke".into()],
            ..Default::default()
        })
    }
}

impl HookHandler<CmfHook> for MyPlugin {
    async fn handle(
        &self,
        payload: &MessagePayload,
        extensions: &Extensions,
        ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        cpex_log!(Info, "Processing tool call");

        // Block dangerous tools
        if let Some(tool_name) = payload.messages.first()
            .and_then(|m| m.content.first())
            .and_then(|c| match c { ContentPart::ToolCall(tc) => Some(&tc.name), _ => None })
        {
            if tool_name == "rm_rf" {
                return PluginResult::deny(PluginViolation::new(
                    "dangerous_tool",
                    "Tool 'rm_rf' is not permitted",
                ));
            }
        }

        PluginResult::allow()
    }
}

register_wasm_plugin!(MyPlugin, [CmfHook]);
```

### Step 2: Build to WASM

Using the Makefile (recommended, from `crates/cpex-wasm-plugin/`):

```bash
make build
```

Or directly:

```bash
cargo build --target wasm32-wasip2 --release
```

Output: `target/wasm32-wasip2/release/cpex_wasm_plugin.wasm`

### Step 3: Validate and inspect

```bash
make validate   # Verify the .wasm binary is a valid component
make inspect    # Print the WIT interface embedded in the binary
```

### Building demo plugins

```bash
# Build a single demo
make build-demo DEMO=pii-guard

# Build all demos
make build-demos
```

Each demo is built with its feature flag and placed in `wasm/`:

```bash
# What happens under the hood:
cargo build --target wasm32-wasip2 --release --features pii-guard --no-default-features
cp target/wasm32-wasip2/release/cpex_wasm_plugin.wasm wasm/pii-guard.wasm
```

### Adding a new example plugin

1. Create `src/examples/my_new_plugin.rs`
2. Add a feature flag in `Cargo.toml`:
   ```toml
   [features]
   my-new-plugin = []
   ```
3. Register it in `src/examples/mod.rs` under the feature gate
4. Add the `register_wasm_plugin!` call gated on the feature
5. Add the plugin name to the Makefile's demo list

## Testing plugins

You can unit-test your plugin handlers **without building to WASM** — tests run as native Rust using your host's tokio runtime. This gives fast iteration with full debugger support.

### Writing tests

Add a `#[cfg(test)]` module in the same file as your plugin:

```rust
#[cfg(test)]
mod tests {
    use cpex_core::cmf::{CmfHook, ContentPart, Message, MessagePayload, Role, ToolCall};
    use cpex_core::cmf::constants::SCHEMA_VERSION;
    use cpex_core::context::PluginContext;
    use cpex_core::extensions::container::Extensions;
    use cpex_core::hooks::trait_def::{HookHandler, PluginResult};

    use super::MyPlugin;

    fn tool_call_payload(name: &str) -> MessagePayload {
        MessagePayload {
            message: Message {
                schema_version: SCHEMA_VERSION.into(),
                role: Role::Assistant,
                content: vec![ContentPart::ToolCall {
                    content: ToolCall {
                        tool_call_id: format!("tc_{name}"),
                        name: name.into(),
                        arguments: Default::default(),
                        namespace: None,
                    },
                }],
                channel: None,
            },
        }
    }

    #[tokio::test]
    async fn test_allows_safe_tool() {
        let payload = tool_call_payload("list_users");
        let ext = Extensions::default();
        let mut ctx = PluginContext::default();

        let result: PluginResult<_> =
            <MyPlugin as HookHandler<CmfHook>>::handle(
                &MyPlugin, &payload, &ext, &mut ctx,
            ).await;

        assert!(result.continue_processing);
        assert!(result.violation.is_none());
    }

    #[tokio::test]
    async fn test_blocks_dangerous_tool() {
        let payload = tool_call_payload("rm_rf");
        let ext = Extensions::default();
        let mut ctx = PluginContext::default();

        let result: PluginResult<_> =
            <MyPlugin as HookHandler<CmfHook>>::handle(
                &MyPlugin, &payload, &ext, &mut ctx,
            ).await;

        assert!(!result.continue_processing);
        assert_eq!(
            result.violation.as_ref().unwrap().code,
            "dangerous_tool"
        );
    }
}
```

Key points:
- Tests call `HookHandler::handle()` directly — no WASM compilation needed
- Use `tokio::test` since the handler is async
- Construct `Extensions::default()` and `PluginContext::default()` for isolation
- Assert on `result.continue_processing` (true = allow, false = deny) and `result.violation`

### Running tests

```bash
# Test your plugin (src/plugin.rs)
make test

# Test all demo plugins
make test-demos

# Test everything (plugin + demos + conversions + integration)
make test-all
```

Under the hood:
- `make test` runs `cargo test --lib plugin::tests`
- `make test-demos` runs `cargo test --features test-demos --lib`
- `make test-all` runs `cargo test --features test-demos` (includes integration tests)

### What you can and cannot test this way

| Can test (native) | Cannot test (requires WASM build) |
|-------------------|-----------------------------------|
| Handler logic (allow/deny/modify) | Fuel limit enforcement |
| Payload parsing and routing | Epoch timeout behavior |
| Extension reading and modification | Filesystem sandbox permissions |
| PluginContext state management | Network policy enforcement |
| Custom payload serialization | Memory limit traps |
| Error handling paths | Host-logging output format |

For sandbox-level testing (resource limits, network policy, filesystem permissions), build to WASM and run the host-side demos: `cd crates/cpex-wasm-host && make run-all-demos`.

## Available `make` targets

| Target | Description |
|--------|-------------|
| `make build` | Build your plugin (release, optimized) |
| `make build-debug` | Build your plugin (debug, fast compile) |
| `make build-demo DEMO=name` | Build a single demo plugin |
| `make build-demos` | Build all demo plugins to `wasm/` |
| `make validate` | Validate the built `.wasm` component |
| `make validate-demos` | Validate all demo `.wasm` files |
| `make inspect` | Print the WIT interface of your plugin |
| `make test` | Run tests for your plugin |
| `make test-demos` | Run inline tests for all demo plugins |
| `make test-all` | Run all tests (plugin + demos + conversions + integration) |
| `make check` | Type-check your plugin (fast feedback) |
| `make clippy` | Run clippy lints |
| `make ci` | Full CI pipeline (fmt + clippy + test + build + validate) |
| `make clean` | Remove all build artifacts |
| `make help` | Show all available targets |

## Advantages

- **Single compilation target** — any language with `wasm32-wasip2` support works (Rust, Go, C/C++, AssemblyScript)
- **Type-safe boundary** — WIT component model provides a schema-enforced contract; no raw byte manipulation
- **Zero boilerplate** — `register_wasm_plugin!` eliminates dispatch logic, type conversion, and WIT export plumbing
- **Structured logging** — `cpex_log!` integrates with the host's tracing infrastructure without filesystem access
- **Custom payload extensibility** — `WasmSerializablePayload` trait lets you define domain-specific payloads without modifying WIT
- **Feature-gated examples** — one crate produces many `.wasm` binaries via feature flags
- **Cross-invocation state** — module-level statics and Store memory persist between calls

## Limitations

- **Immutable extension slots cannot be modified** — `agent`, `mcp`, `completion`, `provenance`, `llm`, `framework`, `meta`, and `request` are read-only; changes are discarded by the host via Arc pointer validation. Mutable slots (`security`, `http`, `delegation`, `custom`) are fully writable with the correct capabilities.
- **Synchronous poll loop** — `__block_on` polls a future up to 1,000,000 times; the host's epoch timeout is the primary safeguard. If the cap is reached, the plugin traps cleanly.
- **Single-function export** — all hooks route through one `handle-hook` entry point; you cannot export additional functions
- **No `initialize()`/`shutdown()` lifecycle** — the host stubs these as no-ops. Use `OnceLock` for lazy initialization; there is no graceful shutdown notification.
- **WASI P2 only** — plugins must target `wasm32-wasip2`, not the older `wasm32-wasi` (P1)
- **No raw token access** — `raw_token`, `bearer_token`, and credential bytes never cross the WASM boundary (intentional security design)
- **No standard networking libraries** — plugins use `wasi:http/outgoing-handler` for HTTP; `reqwest`, `std::net`, and raw sockets are unavailable
- **Non-exhaustive enum fallbacks** — `cpex-core` enums are `#[non_exhaustive]`; unrecognized variants are logged and mapped to a safe default
- **Plugin struct reconstructed per call** — the plugin struct itself is `Default::default()`-constructed on each invocation; only module-level statics persist. Instance fields (`self.x`) do NOT survive across calls.
