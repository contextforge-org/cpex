---
title: "Quickstart"
weight: 10
---

# WASM Plugin Quickstart

Get a sandboxed WASM plugin running end-to-end in under five minutes.

## Prerequisites

Add the WASI P2 compilation target:

```bash
rustup target add wasm32-wasip2
```

## 1. Write the guest plugin

Create a new crate for your plugin:

```bash
cargo new --lib my-plugin
cd my-plugin
```

Add the guest SDK dependency in `Cargo.toml`:

```toml
[lib]
crate-type = ["cdylib"]

[dependencies]
cpex-wasm-plugin = { path = "../crates/cpex-wasm-plugin" }
```

Implement the hook handler in `src/lib.rs`:

```rust
use cpex_wasm_plugin::prelude::*;

struct MyPlugin;

impl Guest for MyPlugin {
    fn handle_hook(
        hook_name: String,
        payload: HookPayload,
        extensions: Extensions,
        ctx: PluginContext,
    ) -> HookResult {
        host_log(LogLevel::Info, &format!("Hook invoked: {hook_name}"));

        // Pass through unmodified
        HookResult::ContinueProcessing
    }
}

export_plugin!(MyPlugin);
```

## 2. Build to WASM

```bash
cargo build --target wasm32-wasip2 --release
```

The compiled module lands at `target/wasm32-wasip2/release/my_plugin.wasm`.

## 3. Configure the host

Create a YAML config that loads your plugin:

```yaml
plugins:
  - name: my-plugin
    kind: "wasm://my_plugin.wasm"
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

## 4. Run from the host

```rust
use cpex_wasm_host::factory::WasmPluginFactory;
use cpex_core::plugin_manager::PluginManager;

let factory = WasmPluginFactory::with_builtin_payloads("./wasm");
let mut mgr = PluginManager::new();
mgr.register_factory("wasm://my_plugin.wasm", Box::new(factory));
mgr.load_config("config.yaml")?;

// Invoke the hook pipeline as normal
let result = mgr.invoke("tool_pre_invoke", payload, extensions, context).await?;
```

## 5. Run the built-in demos

The crate ships with ready-to-run demos that build plugins and exercise the full pipeline:

```bash
cd crates/cpex-wasm-host
make run-demos
```

This compiles all example guest plugins and runs:

- **Plugin demo** — 4 plugins across 7 hook scenarios
- **Capabilities demo** — capability-based extension filtering
- **Filesystem sandbox demo** — all 6 permission levels
- **Env sandbox demo** — allow/deny environment variable access

## Next steps

- [Architecture]({{< relref "architecture" >}}) — understand the host/guest boundary and security layers
