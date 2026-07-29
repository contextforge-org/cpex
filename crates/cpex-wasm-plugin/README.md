# cpex-wasm-plugin

WASM plugin SDK for the CPEX framework. Write a plugin in Rust, compile it to WebAssembly, and deploy it to the CPEX host — all without touching WIT files, serialization code, or WASM internals.

## How WASM Plugins Work

Plugins compile to [WebAssembly components](https://component-model.bytecodealliance.org/) targeting **WASI Preview 2** (`wasm32-wasip2`). The host loads each `.wasm` file, instantiates it in a sandboxed runtime (Wasmtime), and calls the exported `handle-hook` function whenever a matching hook fires.

### The WASM Component Model

This crate uses the [WASM Component Model](https://github.com/WebAssembly/component-model) — not raw WASM modules. Components define typed interfaces via **WIT (WebAssembly Interface Types)**:

- **Exports** — functions the host calls into your plugin (`handle-hook`)
- **Imports** — functions your plugin can call on the host (`host-logging`, WASI APIs)
- **Types** — structured records/enums that cross the boundary (`HookPayload`, `HookResult`, `Extensions`)

The WIT definition lives in `wit/world.wit`. You never edit it — the SDK handles everything.

### The WIT → Rust Bridge

`wit_bindgen::generate!` (in `src/lib.rs`) reads `wit/world.wit` at compile time and generates:
- A `Guest` trait with `handle_hook(...)` — the function signature the host expects
- An `export!` macro — produces the `#[no_mangle]` ABI entry points
- Rust structs for all WIT types (flat/serialized forms, not the rich cpex-core types)

The `register_wasm_plugin!` macro generates the `Guest` impl that:
1. Receives flat WIT types from the host
2. Converts them to cpex-core native Rust types (via `conversions.rs`)
3. Calls your `HookHandler::handle()` method
4. Converts your `PluginResult` back to a WIT `HookResult`
5. Returns it to the host

### Build Target: `wasm32-wasip2`

Plugins compile to `wasm32-wasip2` — WebAssembly with WASI Preview 2 support. This provides:
- **Sandboxed I/O** — filesystem, network, env access are capability-gated by the host
- **Component model ABI** — typed function signatures, not raw memory manipulation
- **Outbound HTTP** (optional) — `wasi:http/outgoing-handler` for plugins that need network access

The output `.wasm` is a self-contained component binary (~660KB–900KB) with no external dependencies.

### What Happens at Runtime

```
Host receives a hook event (e.g., tool_pre_invoke)
  → Looks up plugins registered for that hook (from config.yaml)
  → For each plugin (in priority order):
      → Serializes payload/extensions/context to WIT types
      → Calls handle-hook on the WASM instance
      → Plugin runs in sandbox (memory-limited, fuel-limited, time-limited)
      → Reads the HookResult: allow / deny / modify
      → If denied: pipeline stops, violation returned to caller
      → If modified: updated payload passes to next plugin
      → If allowed: unchanged payload passes to next plugin
```

## Prerequisites

```bash
rustup target add wasm32-wasip2
cargo install wasm-tools    # optional, for validation
```

## Quick Start

```bash
# 1. Edit your plugin logic
vim src/plugin.rs

# 2. Build to WASM
make build

# 3. Deploy — copy to host
cp target/wasm32-wasip2/release/cpex_wasm_plugin.wasm /path/to/cpex-wasm-host/wasm/my-plugin.wasm
```

## Writing Your Plugin

Open `src/plugin.rs`. It contains a ready-to-compile template:

```rust
use crate::prelude::*;
use std::sync::OnceLock;

static PLUGIN_CONFIG: OnceLock<PluginConfig> = OnceLock::new();

#[derive(Default)]
pub struct UserPlugin;

#[async_trait]
impl Plugin for UserPlugin {
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

impl HookHandler<CmfHook> for UserPlugin {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        // Your logic here
        PluginResult::allow()
    }
}
```

### What to return from `handle()`

| Return value | Effect |
|---|---|
| `PluginResult::allow()` | Pass through unchanged |
| `PluginResult::deny(violation)` | Block the request with a reason |
| `PluginResult::modify_payload(p)` | Pass through with a modified payload |

### Creating a violation

```rust
PluginResult::deny(PluginViolation::new(
    "my_error_code",
    "Human-readable reason why this was blocked",
))
```

## Hook Types

Your plugin intercepts a specific type of event. Choose the hook that matches your use case:

| Hook type | Payload | Event name | Use case |
|---|---|---|---|
| `CmfHook` | `MessagePayload` | `cmf.tool_pre_invoke` | Intercept tool calls / results |
| `IdentityHook` | `IdentityPayload` | `identity.resolve` | Resolve user identity from headers/tokens |
| `TokenDelegateHook` | `DelegationPayload` | `token.delegate` | Mint scoped outbound credentials |
| Custom | Your struct | Your event name | Any domain-specific hook |

To use a different hook type, change both:
1. The `impl HookHandler<...>` in `src/plugin.rs`
2. The `register_wasm_plugin!` call at the bottom of `src/lib.rs`

## Custom Hook Types

For domain-specific hooks, define your own payload and hook type in `src/plugin.rs`:

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MyPayload {
    pub action: String,
    pub subject: String,
}

impl_plugin_payload!(MyPayload);
impl_wasm_payload!(MyPayload, "my_namespace.pre_invoke");

define_hook! { MyHook, "my_namespace.pre_invoke" => {
    payload: MyPayload,
    result: PluginResult<MyPayload>,
}}
```

Then implement `HookHandler<MyHook>` and update `lib.rs` registration to use `plugin::MyHook`.

See `src/examples/tool_invoke_checker.rs` for a complete working example.

## Testing

### Test your plugin

Add tests at the bottom of `src/plugin.rs` (same pattern as the demo plugins):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use cpex_core::cmf::{ContentPart, Message, Role, ToolCall};
    use cpex_core::cmf::constants::SCHEMA_VERSION;

    #[tokio::test]
    async fn test_allows_request() {
        let payload = MessagePayload {
            message: Message {
                schema_version: SCHEMA_VERSION.into(),
                role: Role::Assistant,
                content: vec![ContentPart::ToolCall {
                    content: ToolCall {
                        tool_call_id: "tc_1".into(),
                        name: "my_tool".into(),
                        arguments: Default::default(),
                        namespace: None,
                    },
                }],
                channel: None,
            },
        };
        let ext = Extensions::default();
        let mut ctx = PluginContext::default();

        let result: PluginResult<_> =
            <UserPlugin as HookHandler<CmfHook>>::handle(
                &UserPlugin, &payload, &ext, &mut ctx,
            ).await;

        assert!(result.continue_processing);
    }
}
```

Run:
```bash
make test               # your plugin tests only
cargo test              # all tests
```

### Test demo plugins

```bash
make test-demos         # runs inline tests for all 17 demo plugins
```

## Logging

Use `cpex_log!` for structured logging to the host's tracing infrastructure:

```rust
cpex_log!(info, "processing tool call '{}'", tool_name);
cpex_log!(warn, "missing required field");
cpex_log!(error, "unexpected payload format");
```

Available levels: `trace`, `debug`, `info`, `warn`, `error`.

## Deploying to the Host

After `make build`, configure the host to load your plugin:

```yaml
# In cpex-wasm-host config.yaml
plugins:
  - name: my-plugin
    kind: wasm://my-plugin.wasm
    hooks: [cmf.tool_pre_invoke]
    priority: 50
    capabilities: [read_labels, read_subject]
    config:
      sandbox_policy:
        allowed_filesystem: []
        allowed_network: []
        allowed_env: []
        resources:
          max_memory_bytes: 10485760
          max_fuel: 1000000000
          max_execution_time_ms: 5000
```

### Sandbox capabilities

Plugins run in a sandboxed WASM environment. By default, they have NO access to:
- Host filesystem
- Outbound network
- Environment variables

Grant access explicitly in `sandbox_policy` if your plugin needs it.

### Plugin capabilities (what data your plugin can see)

| Capability | What it grants |
|---|---|
| `read_labels` | See security labels on the request |
| `read_subject` | See the authenticated user identity |
| `read_roles` | See the user's role assignments |
| `read_inbound_credentials` | See raw auth tokens (sensitive) |

## Project Structure

```
cpex-wasm-plugin/
  src/
    lib.rs              # SDK internals (don't edit)
    plugin.rs           # YOUR PLUGIN — edit this
    conversions.rs      # WIT ↔ native type bridging
    examples/           # 17 demo plugins for reference
  wit/
    world.wit           # WIT world definition (typed WASM boundary)
    deps/               # WASI interface definitions (io, http, clocks, etc.)
  Makefile              # Build targets
```

## Makefile Targets

| Target | Description |
|---|---|
| `make build` | Build your plugin to WASM (release, optimized) |
| `make build-debug` | Build (debug, faster compile — for iteration) |
| `make build-demo DEMO=noop` | Build a specific demo to `wasm/` |
| `make build-demos` | Build all demos to `wasm/` |
| `make test` | Run your plugin's tests |
| `make test-demos` | Run all demo inline tests |
| `make test-all` | Run everything (plugin + demos + conversions + doc-tests) |
| `make check` | Type-check your plugin (fast feedback) |
| `make check-demos` | Type-check all demos |
| `make validate` | Validate your .wasm with wasm-tools |
| `make validate-demos` | Validate all demo .wasm files |
| `make inspect` | Print the WIT interface in your binary |
| `make fmt` | Format source code |
| `make fmt-check` | Check formatting without modifying |
| `make clippy` | Run lints on your plugin |
| `make clippy-demos` | Run lints on all demos |
| `make ci` | Full CI pipeline (fmt + clippy + test + build + validate) |
| `make clean` | Remove all build artifacts |
| `make help` | Show all targets |

## Demo Plugins

Browse `src/examples/` for working reference implementations:

| Demo | Hook | What it demonstrates |
|---|---|---|
| `noop.rs` | CmfHook | Minimal pass-through (good starting point) |
| `audit_logger.rs` | CmfHook | Log all hook invocations |
| `header_injector.rs` | CmfHook | Inject headers + security labels |
| `identity_checker.rs` | CmfHook + IdentityHook | Validate identity claims |
| `pii_guard.rs` | Custom ToolPreInvoke | Detect and block PII |
| `tool_invoke_checker.rs` | Custom ToolPreInvoke/PostInvoke | Enforce tool-call policies |
| `audit_logger_custom.rs` | Custom ToolPreInvoke/PostInvoke | Audit with custom payloads |
| `remote_authz.rs` | Custom ToolPreInvoke | Delegate to external authz |
| `token_attenuator.rs` | TokenDelegateHook | Downscope outbound tokens |
| `fs_test.rs` | CmfHook | Filesystem sandbox testing |
| `net_test.rs` | CmfHook | Network sandbox testing |
| `env_test.rs` | CmfHook | Environment variable access |
| `compute_bench.rs` | CmfHook | CPU computation benchmark |
| `fs_sandbox_demo.rs` | CmfHook | Filesystem sandbox operations |
| `env_sandbox_demo.rs` | CmfHook | Env var sandbox operations |
| `resource_test.rs` | CmfHook | Resource limit testing |
| `net_http_test.rs` | CmfHook | Outbound HTTP requests |

## Advantages

### Security
- **Full sandbox isolation** — each plugin runs in its own WASM sandbox; can't read your filesystem, exfiltrate data, access other plugins' memory, or crash the host
- **Capability-gated data access** — plugins only see the `Extensions` fields their declared capabilities allow
- **Enforced resource limits** — memory caps, fuel limits (instruction count), and execution timeouts prevent runaway plugins

### Developer Experience
- **No WIT/WASM knowledge needed** — edit `src/plugin.rs`, implement `handle()`, run `make build`
- **Same trait as native plugins** — `HookHandler<H>` is identical; prototype natively, deploy as WASM
- **Fast test feedback** — `make test` runs in under a second on your native machine
- **Rich typed boundary** — work with idiomatic Rust types (HashMap, enums, Arc), not raw bytes or JSON

### Operational
- **Language-agnostic deployment** — `.wasm` is a standard component; the host doesn't care what produced it
- **Deterministic builds** — same source → same `.wasm`; no dynamic linking or platform-specific behavior
- **Plugin isolation without process overhead** — isolated like a separate process but with microsecond instantiation, not IPC
- **Composable hook pipeline** — multiple plugins chain on the same hook via priority ordering
- **Hot-swappable** — drop a new `.wasm` and restart the host; no host recompilation needed

### Compared to Alternatives

| vs. | Advantage of WASM plugins |
|---|---|
| Native dynamic libraries (.so/.dylib) | Sandboxed, portable, no ABI compatibility issues |
| gRPC/HTTP sidecar plugins | No network latency, no separate process to manage |
| Embedded scripting (Lua, JS) | Full Rust type safety, compiled performance, IDE support |
| Hardcoded in-process plugins | Isolated, independently deployable, can't crash the host |

## Limitations

### Architectural
- **One plugin per `.wasm` binary** — WIT component model exports a single `handle-hook` function
- **No async runtime** — `tokio`, `reqwest`, `hyper` don't work inside WASM; handlers complete synchronously
- **No cross-invocation state on the struct** — plugin is re-created via `Default::default()` every call; use `static OnceLock<T>` for persistent data
- **Sandbox restrictions are absolute** — `std::fs::read()` compiles but traps at runtime unless the host config grants filesystem access

### SDK-Specific
- **Plugins must live inside this crate** — `export!` is crate-local; external crates can't produce their own `.wasm` without a full SDK/template split (not yet implemented)
- **Feature flags for demo selection** — the Makefile hides them, but enabling two demo features simultaneously is a compile error
- **No hot-reload** — changing logic requires rebuild + redeploy; the host loads `.wasm` at startup

### Testing
- **Tests run on native, not in WASM** — `make test` doesn't test the actual WIT serialization boundary or sandbox enforcement; end-to-end testing requires the host
- **Serialization cost at the boundary** — every `handle()` call deserializes the full payload from WIT types and serializes the result back; large payloads have overhead that native plugins don't pay

## End-to-End Walkthrough

1. **Clone the repo** and navigate to this crate
2. **Install the target**: `rustup target add wasm32-wasip2`
3. **Edit** `src/plugin.rs` — rename the struct, pick your hook, write your logic
4. **Update** `src/lib.rs` bottom — change the hook type in `register_wasm_plugin!` if you're not using `CmfHook`
5. **Test**: `make test`
6. **Build**: `make build`
7. **Validate** (optional): `make validate`
8. **Deploy**: copy the `.wasm` to the host and add a `config.yaml` entry
9. **Run the host** — your plugin intercepts matching hook invocations
