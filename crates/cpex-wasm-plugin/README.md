# cpex-wasm-plugin

Guest SDK for building sandboxed WASM plugins in the CPEX framework. Write your plugin logic in Rust, compile to `wasm32-wasip2`, and let the host runtime execute it in a secure sandbox.

## Prerequisites

- Rust 1.78+
- WASM target: `rustup target add wasm32-wasip2`
- `wasm-tools` (optional, for inspecting components): `cargo install wasm-tools`

## Quick Start

1. Implement your plugin in `src/plugin.rs` (see [Guest SDK Reference](../../docs/content/docs/wasm/cpex-wasm-plugin.md) for the full `register_wasm_plugin!` macro API):

```rust
use cpex_wasm_plugin::prelude::*;
use std::sync::OnceLock;

#[derive(Default)]
pub struct MyPlugin;

#[async_trait]
impl Plugin for MyPlugin {
    fn config(&self) -> &PluginConfig {
        static CFG: OnceLock<PluginConfig> = OnceLock::new();
        CFG.get_or_init(|| PluginConfig {
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
        ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        // Your logic here
        PluginResult::allow()
    }
}

register_wasm_plugin!(MyPlugin, [CmfHook]);
```

2. Build (see [Quick Start Guide](../../docs/content/docs/wasm/quickstart.md) for full setup instructions):

```bash
make build
```

The `.wasm` binary lands in `target/wasm32-wasip2/release/`. Copy it to `cpex-wasm-host/wasm/` for the host to load it.

## Available Hook Types

| Hook | Payload | Event Name | Use Case |
|------|---------|------------|----------|
| `CmfHook` | `MessagePayload` | `cmf.tool_pre_invoke` | Intercept tool calls/results |
| `IdentityHook` | `IdentityPayload` | `identity.resolve` | Resolve user identity |
| `TokenDelegateHook` | `DelegationPayload` | `token.delegate` | Mint scoped outbound credentials |
| Custom | Your own type | Your own name | See `src/examples/tool_invoke_checker.rs` |

## Return Values

Your `handle()` method returns a `PluginResult<Payload>`:

| Method | Behavior |
|--------|----------|
| `PluginResult::allow()` | Pass through unchanged |
| `PluginResult::deny(violation)` | Block the request with a reason |
| `PluginResult::modify_payload(p)` | Pass through with a modified payload |

## Make Targets

| Command | Description |
|---------|-------------|
| `make build` | Build the plugin (release, wasm32-wasip2) |
| `make build-demo DEMO=<name>` | Build a single demo plugin (e.g., `pii-guard`) |
| `make build-demos` | Build all 14 demo plugins |
| `make test` | Run plugin unit tests |
| `make test-demos` | Run all demo unit tests |
| `make test-all` | Run everything (plugin + demos + conversions) |
| `make clean` | Remove build artifacts |

## Available Demo Plugins

Build any demo to see a working example:

```bash
make build-demo DEMO=pii-guard
make build-demo DEMO=identity-checker
make build-demo DEMO=header-injector
make build-demo DEMO=audit-logger
make build-demo DEMO=token-attenuator
```

Source for each is under `src/examples/`. See [Tutorials](../../docs/content/docs/wasm/tutorials/_index.md) for guided walkthroughs.

## Testing

Tests run as native Rust (not compiled to WASM), calling `HookHandler::handle()` directly. See [Architecture Overview](../../docs/content/docs/wasm/architecture.md) for how plugins are invoked at runtime:

```bash
make test
```

## Documentation

For detailed guides on the macro internals, WIT interface, async execution, and plugin lifecycle:

- [Guest SDK Reference](../../docs/content/docs/wasm/cpex-wasm-plugin.md)
- [Quick Start Guide](../../docs/content/docs/wasm/quickstart.md)
- [Architecture Overview](../../docs/content/docs/wasm/architecture.md)
- [Tutorials](../../docs/content/docs/wasm/tutorials/_index.md)
