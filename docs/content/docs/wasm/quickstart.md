---
title: "Quickstart"
weight: 10
---

# WASM Plugin Quickstart

Get a sandboxed WASM plugin running end-to-end in under five minutes.

## Prerequisites

### Toolchain versions

| Dependency | Version | Purpose |
|------------|---------|---------|
| Rust | ≥ 1.78 (edition 2021) | Compiler with `wasm32-wasip2` target support |
| Wasmtime | 46.0 | Host runtime (pulled automatically via `cpex-wasm-host`) |
| WASI | Preview 2 (P2) | System interface standard used by the guest |
| wit-bindgen | 0.57 | WIT code generation (pulled automatically via `cpex-wasm-plugin`) |
| wasm-tools | latest | Optional — for `make validate` and `make inspect` |

### Setup

1. **Add the WASI P2 compilation target:**

```bash
rustup target add wasm32-wasip2
```

2. **Install `wasm-tools`** (optional, for validation and inspection):

```bash
cargo install wasm-tools
```

That's it — Wasmtime, wit-bindgen, and all WASI libraries are Cargo dependencies and will be fetched automatically on first build. No system-level packages or runtime installations needed.

## 1. Write the guest plugin

Your plugin lives in `src/plugin.rs` inside the `cpex-wasm-plugin` crate. Implement the `Plugin` and `HookHandler<H>` traits — the same API as `cpex-core` native plugins:

```rust
use cpex_wasm_plugin::prelude::*;

#[derive(Default)]
struct MyPlugin;

impl Plugin for MyPlugin {
    fn config(&self) -> PluginConfig {
        PluginConfig::new("my-plugin", "1.0.0")
    }
}

impl HookHandler<CmfHook> for MyPlugin {
    async fn handle(
        &self,
        payload: &MessagePayload,
        extensions: &Extensions,
        ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        host_log(LogLevel::Info, &format!("Hook invoked: {:?}", payload));

        // Pass through unmodified
        PluginResult::allow()
    }
}

// This macro generates all WIT bindings and exports handle-hook for you.
// List every hook type your plugin handles.
register_wasm_plugin!(MyPlugin, [CmfHook]);
```

The `register_wasm_plugin!` macro handles all WIT serialization, routing, and export generation. You only write business logic.

### Return values

Your handler returns a `PluginResult` that tells the pipeline what to do:

| Constructor | Effect |
|-------------|--------|
| `PluginResult::allow()` | Continue processing, no modifications |
| `PluginResult::deny(violation)` | Halt the pipeline with a reason |
| `PluginResult::modify_payload(payload)` | Continue with a modified payload |
| `PluginResult::modify_extensions(ext)` | Continue with modified extensions |
| `PluginResult::modify(payload, ext)` | Continue with both modified |

## 2. Build to WASM

Using the Makefile (recommended):

```bash
cd crates/cpex-wasm-plugin
make build
```

Or directly with cargo:

```bash
cargo build --target wasm32-wasip2 --release
```

The compiled component lands at `target/wasm32-wasip2/release/cpex_wasm_plugin.wasm`.

You can validate the binary has a correct WIT interface:

```bash
make validate
```

And inspect what it exports/imports:

```bash
make inspect
```

## 3. Configure the host

Create a YAML config that loads your plugin with a sandbox policy:

```yaml
plugins:
  - name: my-plugin
    kind: "wasm://cpex_wasm_plugin.wasm"
    hooks:
      - tool_pre_invoke
    capabilities: []
    config:
      sandbox:
        filesystem: deny-all
        network: deny-all
        env_vars: deny-all
        fuel_limit: 500_000_000
        epoch_timeout_ms: 5000
```

This policy gives your plugin zero access to the filesystem, network, and environment — the most restrictive default. You can selectively grant access later as needed.

## 4. Run from the host

```rust
use cpex_wasm_host::factory::WasmPluginFactory;
use cpex_core::plugin_manager::PluginManager;

let factory = WasmPluginFactory::with_builtin_payloads("./wasm");
let mut mgr = PluginManager::new();
mgr.register_factory("wasm://cpex_wasm_plugin.wasm", Box::new(factory));
mgr.load_config_file(Path::new("config.yaml"))?;

// Invoke the hook pipeline as normal — WASM plugins are transparent
let result = mgr.invoke("tool_pre_invoke", payload, extensions, context).await?;
```

### Expected output

When your plugin runs, you should see tracing output like:

```
INFO cpex_wasm_host: Loading WASM plugin 'my-plugin' from ./wasm/cpex_wasm_plugin.wasm
INFO cpex_wasm_host: Plugin 'my-plugin' initialized (fuel=500000000, timeout=5000ms)
INFO my-plugin: Hook invoked: MessagePayload { ... }
```

If the plugin returns `allow()`, the pipeline continues to the next plugin. If it returns `deny()`, you'll see:

```
WARN cpex_wasm_host: Plugin 'my-plugin' denied request: <violation message> [<violation_code>]
```

## 5. Run the built-in demos

The crate ships with ready-to-run demos that build plugins and exercise the full pipeline:

```bash
cd crates/cpex-wasm-host
make run-all-demos
```

This compiles all example guest plugins and runs 7 demo scenarios:

```
========== Plugin Demo ==========
  4 plugins, 7 hook scenarios (PII guard, remote authz, tool-invoke checks)

========== Capabilities Demo ==========
  Capability-based extension filtering in action

========== Filesystem Sandbox Demo ==========
  All 6 permission levels (read-only, full-access, drop-box, etc.)

========== Env Sandbox Demo ==========
  Allow/deny environment variable access

========== Token Attenuator Demo ==========
  Token delegation and privilege attenuation

========== Network Policy Demo ==========
  Outbound HTTP allowlist enforcement

========== Resource Limits Demo ==========
  Fuel exhaustion, memory limits, epoch timeouts

========== All demos passed ==========
```

## 6. Try something more interesting

Now that you have a working plugin, try these modifications:

### Block a request

```rust
impl HookHandler<CmfHook> for MyPlugin {
    async fn handle(
        &self,
        payload: &MessagePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        // Block any message containing "DROP TABLE"
        if payload.content.contains("DROP TABLE") {
            return PluginResult::deny(PluginViolation::new(
                "sql_injection_detected",
                "Potential SQL injection blocked",
            ));
        }
        PluginResult::allow()
    }
}
```

### Add a capability and inspect extensions

Update your config to declare `read_headers`:

```yaml
capabilities:
  - read_headers
```

Now your handler can read HTTP extensions:

```rust
if let Some(http) = &extensions.http {
    host_log(LogLevel::Info, &format!("Request path: {}", http.path));
}
```

Without the `read_headers` capability, `extensions.http` will always be `None` — the host strips it before your plugin sees it.

## Available `make` targets

| Target | Description |
|--------|-------------|
| `make build` | Build your plugin (release, optimized) |
| `make build-debug` | Build your plugin (debug, fast compile) |
| `make validate` | Validate the built `.wasm` component |
| `make inspect` | Print the WIT interface of your plugin |
| `make test` | Run tests for your plugin |
| `make clippy` | Run lints |
| `make ci` | Full CI pipeline (fmt + clippy + test + build + validate) |
| `make help` | Show all available targets |

## Next steps

- [Architecture]({{< relref "architecture" >}}) — understand the host/guest boundary and security layers
- [Sandboxing Details]({{< relref "sandboxing-details" >}}) — configure filesystem, network, and resource policies
- [Tutorials]({{< relref "tutorials" >}}) — hands-on walkthroughs with the built-in demo plugins
