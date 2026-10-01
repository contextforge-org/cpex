# cpex-wasm-host

Host runtime for loading and executing sandboxed WASM plugins in the CPEX framework. Built on Wasmtime with the Component Model, it provides capability-based access control, filesystem, network, environment variables, and resource sandboxing, along with seamless integration with native plugins.

## Prerequisites

- Rust 1.78+
- Pre-built WASM plugins (from `cpex-wasm-plugin`) — place `.wasm` binaries in the `wasm/` directory

## Quick Start

1. Configure your plugin in YAML (e.g., `config.yaml` below). See [Sandboxing Details](../../docs/content/docs/wasm/sandboxing-details.md) for all policy options:

```yaml
plugins:
  - name: my-plugin                  # unique plugin identifier
    kind: wasm://my-plugin.wasm      # wasm:// prefix + filename in wasm/ dir
    hooks: [cmf_message]             # hook types this plugin handles
    mode: sequential                 # sequential | fire_and_forget
    priority: 10                     # lower = runs first in pipeline
    on_error: fail                   # fail | ignore
    config:
      sandbox_policy:
        allowed_filesystem:          # directories/files the plugin can access
          - dir: "/tmp/plugin-data"
            permission: read-write
        allowed_network:             # outbound hosts the plugin can reach
          - host: "api.example.com"
            ports: [443]
            schemes: ["https"]
        allowed_env:                 # environment variables visible to the plugin
          - "API_KEY"
          - "LOG_LEVEL"
        resources:                   # execution limits
          max_memory_bytes: 67108864       # 64 MB
          max_fuel: 1000000000             # wasmtime fuel (instruction budget)
          max_execution_time_ms: 5000      # epoch-based timeout
```

2. Register the WASM factory and load plugins (see [Host Runtime Reference](../../docs/content/docs/wasm/cpex-wasm-host.md) for full API details):

```rust
use std::path::PathBuf;
use std::sync::Arc;
use cpex_wasm_host::factory::WasmPluginFactory;
use cpex_wasm_host::payload_registry::PayloadSerializerRegistry;
use cpex_core::config::parse_config;
use cpex_core::manager::PluginManager;

#[tokio::main]
async fn main() {
    let wasm_dir = PathBuf::from("./wasm");
    let factory = WasmPluginFactory::with_builtin_payloads(wasm_dir);

    let mgr = PluginManager::default();
    mgr.register_factory("wasm://my-plugin.wasm", Box::new(factory));

    let yaml = std::fs::read_to_string("config.yaml").unwrap();
    let config = parse_config(&yaml).unwrap();
    mgr.load_config(config).unwrap();
    mgr.initialize().await.unwrap();

    // Invoke hooks via mgr.invoke() or mgr.invoke_named()
}
```

3. Run your example:

```bash
cargo run --example your_example_name
```
## Supported Payloads

`WasmPluginFactory::with_builtin_payloads()` pre-registers:

- `MessagePayload` — CMF message hooks
- `IdentityPayload` — identity resolution hooks
- `DelegationPayload` — token delegation hooks

For custom payloads, create a `PayloadSerializerRegistry`, register your types with `registry.register::<YourPayload>()`, and pass it to `WasmPluginFactory::new()`. See the [tutorials](../../docs/content/docs/wasm/tutorials/_index.md) for a full walkthrough.

For details on payload serialization across the WASM boundary, see [Architecture Overview](../../docs/content/docs/wasm/architecture.md).

## Make Targets

| Command | Description |
|---------|-------------|
| `make unit-tests` | Run unit tests (no WASM binaries needed) |
| `make integration-tests` | Build plugins + run integration tests |
| `make test` | Full clean build + all tests |
| `make bench-all` | Build plugins + run benchmarks + generate chart |
| `make sync-wit` | Sync WIT definitions from the plugin crate |
| `make clean` | Remove build artifacts |

## Running Examples

Seven host-side examples demonstrate different capabilities:

```bash
cargo run --example wasm_plugin_demo
cargo run --example wasm_capabilities_demo
cargo run --example wasm_fs_sandbox_demo
cargo run --example wasm_env_sandbox_demo
cargo run --example wasm_token_attenuator_demo
cargo run --example wasm_network_policy_demo
cargo run --example wasm_resource_limits_demo
```

Most examples require pre-built demo plugins. Build them first:

```bash
cd ../cpex-wasm-plugin && make build-demos
```

## Testing

```bash
# Unit tests (fast, no WASM needed)
make unit-tests

# Integration tests (requires WASM plugins)
make integration-tests
```

Integration tests are marked `#[ignore]` and need `make build-test-plugins` to have run first. See [Benchmarking](../../docs/content/docs/wasm/benchmarking.md) for performance characteristics.

## Key Components

| Module | Role | Reference |
|--------|------|-----------|
| `factory` | `WasmPluginFactory` -- integrates with CPEX's `PluginFactory` trait | [Host Runtime Reference](../../docs/content/docs/wasm/cpex-wasm-host.md) |
| `sandbox_manager` | `SharedEngine` + `SandboxManager` -- Wasmtime lifecycle | [Architecture Overview](../../docs/content/docs/wasm/architecture.md) |
| `policy_loader` | Parse YAML sandbox configs, build WASI context | [Sandboxing Details](../../docs/content/docs/wasm/sandboxing-details.md) |
| `payload_registry` | Type-erased serialization for custom payloads crossing the boundary | [Tutorials](../../docs/content/docs/wasm/tutorials/_index.md) |
| `conversions` | Host-side WIT <-> native type mapping | [Architecture Overview](../../docs/content/docs/wasm/architecture.md) |

## Documentation

For detailed architecture, sandbox internals, benchmarks, and tutorials:

- [Host Runtime Reference](../../docs/content/docs/wasm/cpex-wasm-host.md)
- [Sandboxing Details](../../docs/content/docs/wasm/sandboxing-details.md)
- [Architecture Overview](../../docs/content/docs/wasm/architecture.md)
- [Benchmarking](../../docs/content/docs/wasm/benchmarking.md)
- [Tutorials](../../docs/content/docs/wasm/tutorials/_index.md)
