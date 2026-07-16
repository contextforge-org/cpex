# cpex-wasm-host

WASM plugin host runtime for the CPEX framework. Loads WebAssembly Component Model plugins into sandboxed wasmtime environments, enforces resource limits and capability-based access control, and bridges to cpex-core's `PluginManager` for seamless integration with native plugins.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  PluginManager::invoke_named::<CmfHook>(...)                │
│    → Executor: group_by_mode, filter extensions, dispatch   │
└────────────────────────────┬────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────┐
│  WasmBridgeHandler                                          │
│    1. Payload → WIT (CMF/Identity/Delegation structured,    │
│       custom via JSON bytes)                                │
│    2. Extensions → WIT (field-by-field conversion)          │
│    3. Sandbox invoke (fuel reset + epoch reset)             │
│    4. WIT result → native (with filtered slot preservation) │
│    5. Post-invocation validation (immutable tier, monotonic │
│       labels, write authorization)                          │
└────────────────────────────┬────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────┐
│  Wasmtime Sandbox                                           │
│    SharedEngine (1 per factory, shared across all plugins)  │
│    Store (1 per plugin, isolated memory/fuel/state)         │
│    Guest: handle-hook(hook_name, payload, ext, ctx)         │
│    Host imports: WASI P2, WASI HTTP, host-logging           │
│    Enforcement: fuel, timeout, memory, network, filesystem  │
└─────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
cpex-wasm-host/
├── Cargo.toml
├── README.md
├── Makefile
├── config/
│   ├── config.yaml                   # Single-plugin demo config
│   ├── config_capabilities.yaml      # 3-plugin capabilities demo
│   └── config_identity.yaml          # Identity-resolve demo
├── examples/
│   ├── wasm_plugin_demo.rs           # CMF MessagePayload end-to-end
│   ├── wasm_capabilities_demo.rs     # 3 plugins, capability isolation
│   ├── wasm_identity_resolve_demo.rs # IdentityPayload typed dispatch
│   └── wasm_generic_payload_demo.rs  # Custom payload pass-through
├── benchmarking/
│   ├── invocation.rs                 # Criterion benchmarks (WASM vs native)
│   ├── results.md                    # Benchmark results table
│   └── README.md                     # How to run benchmarks
├── tests/
│   ├── test_policy_loader.rs         # Config/sandbox policy tests
│   ├── test_security_enforcement.rs  # Security validation tests
│   ├── test_sandbox_isolation.rs     # E2E: filesystem access denied in WASM
│   ├── test_sandbox_network.rs       # E2E: network access denied in WASM
│   └── test_sandbox_env.rs           # E2E: env var isolation in WASM
├── src/
│   ├── lib.rs
│   ├── sandbox_manager.rs            # SharedEngine, SandboxManager, host-logging impl
│   ├── factory.rs                    # WasmPluginFactory, WasmBridgeHandler, validation
│   ├── conversions.rs                # Native ↔ WIT type conversions
│   ├── policy_loader.rs              # SandboxPolicy parsing, WASI context builder
│   └── payload_registry.rs           # Type-erased custom payload serialization
├── wasm/                             # Compiled .wasm binaries (gitignored)
└── wit/
    ├── world.wit                     # WIT interface definition
    └── deps/                         # WASI interface dependencies
```

---

## Quick Start

### Prerequisites

```bash
rustup target add wasm32-wasip2
```

### Build & Run (end-to-end)

```bash
# 1. Build all plugin binaries
cd crates/cpex-wasm-plugin && make build-all && cd ../..

# 2. Run the capabilities demo (3 plugins in a pipeline)
cargo run -p cpex-wasm-host --example wasm_capabilities_demo
```

### What Happens

1. `WasmPluginFactory` loads 3 `.wasm` binaries from `wasm/` directory
2. Each plugin gets its own sandboxed Store (shared Engine)
3. The pipeline invokes `cmf.tool_pre_invoke` → all 3 plugins run in priority order:
   - **identity-checker** (priority 10): checks PII labels vs subject roles
   - **header-injector** (priority 20): adds "PROCESSED" label + "X-Processed-By" header
   - **audit-logger** (priority 100, audit mode): logs tool name + labels + request ID
4. Then `cmf.tool_post_invoke` runs the applicable plugins again
5. Results flow back through the executor to the caller

---

## Running Tests

```bash
# All host tests (46 tests)
cargo test -p cpex-wasm-host
```

Tests cover:
- **Security enforcement** (15 tests): capability filtering, immutable tier, monotonic labels, write authorization, filtered slot preservation
- **Sandbox isolation** (6 tests, E2E): real `.wasm` plugins attempt filesystem/network/env access — sandbox denies them
- **Conversions** (3 tests): CMF/Identity payload round-trips, extension immutability
- **Policy loader** (8 tests): config parsing, deserialization, deny-all default, context building, invalid permissions
- **Config integration** (8 tests): YAML validity, plugin structure, resource limits
- **Error classification** (6 tests): timeout, fuel, memory, trap, network, unknown

### Sandbox Isolation Tests (E2E with real WASM binaries)

These require pre-built `.wasm` test plugins:

```bash
# Build the sandbox test plugins (one-time)
cd crates/cpex-wasm-plugin
cargo build --target wasm32-wasip2 --release --features fs-test --no-default-features
cp target/wasm32-wasip2/release/cpex_wasm_plugin.wasm ../cpex-wasm-host/wasm/fs-test.wasm

cargo build --target wasm32-wasip2 --release --features net-test --no-default-features
cp target/wasm32-wasip2/release/cpex_wasm_plugin.wasm ../cpex-wasm-host/wasm/net-test.wasm

cargo build --target wasm32-wasip2 --release --features env-test --no-default-features
cp target/wasm32-wasip2/release/cpex_wasm_plugin.wasm ../cpex-wasm-host/wasm/env-test.wasm
cd ../..

# Run just the sandbox tests
cargo test -p cpex-wasm-host --test test_sandbox_isolation
cargo test -p cpex-wasm-host --test test_sandbox_network
cargo test -p cpex-wasm-host --test test_sandbox_env
```

What these prove:
| Test | Asserts |
|------|---------|
| `test_plugin_cannot_read_etc_passwd_without_filesystem_policy` | Plugin reads `/etc/passwd` → WASI returns permission denied |
| `test_plugin_cannot_read_etc_passwd_with_unrelated_filesystem_policy` | `/tmp` allowed but `/etc` still blocked |
| `test_plugin_cannot_access_network_without_policy` | Plugin attempts DNS → denied (no raw socket access in WASI) |
| `test_plugin_cannot_access_network_with_unrelated_allowlist` | `internal.example.com` allowed but `httpbin.org` still blocked |
| `test_plugin_cannot_see_env_vars_without_policy` | `HOME`, `PATH`, `SECRET_API_KEY` all empty |
| `test_plugin_sees_only_allowed_env_var` | Only `CPEX_TEST_ALLOWED` visible; `HOME` and `SECRET_API_KEY` still hidden |

---

## Running Benchmarks

```bash
# Build the noop plugin (one-time)
cd crates/cpex-wasm-plugin
cargo build --target wasm32-wasip2 --release --features noop --no-default-features
cp target/wasm32-wasip2/release/cpex_wasm_plugin.wasm ../cpex-wasm-host/wasm/noop.wasm
cd ../..

# Run benchmarks
cargo bench -p cpex-wasm-host

# View HTML report
open target/criterion/report/index.html
```

### Results (Apple M-series, ARM64)

| Scenario | Latency | vs Native |
|----------|:-------:|:---------:|
| Native handler (noop) | 84 ns | 1x |
| Type conversion only | 843 ns | 10x |
| WASM noop (minimal) | 4.8 µs | 57x |
| WASM with full extensions | 7.9 µs | 94x |

~126,000 WASM plugin calls/sec/core with realistic extensions. For a typical LLM request (200ms), 3 plugin calls add ~24µs overhead (0.01%).

---

## Running Demos

| Demo | Command | What It Shows |
|------|---------|---------------|
| CMF plugin | `cargo run -p cpex-wasm-host --example wasm_plugin_demo` | Single plugin, pre/post invoke |
| Capabilities | `cargo run -p cpex-wasm-host --example wasm_capabilities_demo` | 3 plugins, capability isolation |
| Identity resolve | `cargo run -p cpex-wasm-host --example wasm_identity_resolve_demo` | Custom payload (IdentityPayload) |
| Generic payload | `cargo run -p cpex-wasm-host --example wasm_generic_payload_demo` | Unhandled payload type → allow |

All demos require plugin binaries. Build with `cd crates/cpex-wasm-plugin && make build-all`.

---

## Integration with PluginManager

```rust
use std::path::PathBuf;
use cpex_core::cmf::CmfHook;
use cpex_core::config::parse_config;
use cpex_core::manager::PluginManager;
use cpex_wasm_host::factory::WasmPluginFactory;

let mgr = PluginManager::default();

// Register WASM factory (one per unique kind)
mgr.register_factory(
    "wasm://my-plugin.wasm",
    Box::new(WasmPluginFactory::with_builtin_payloads(PathBuf::from("wasm"))),
);

// Load config → factory creates sandboxed plugin instances
let config = parse_config(&yaml)?;
mgr.load_config(config)?;
mgr.initialize().await?;

// Invoke — WASM plugins participate transparently alongside native plugins
let (result, bg) = mgr
    .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, extensions, None)
    .await;

if !result.continue_processing {
    println!("Denied: {}", result.violation.unwrap().reason);
}
bg.wait_for_background_tasks().await;
```

---

## Configuration

```yaml
plugins:
  - name: my-plugin
    kind: wasm://my-plugin.wasm          # wasm:// triggers WasmPluginFactory
    hooks: [cmf.tool_pre_invoke, cmf.tool_post_invoke]
    mode: sequential                      # sequential|transform|audit|concurrent|fire_and_forget
    priority: 50                          # lower = earlier within same mode
    on_error: fail                        # fail|ignore|disable (circuit breaker)
    capabilities:
      - read_labels
      - append_labels
      - read_headers
      - write_headers
    config:
      sandbox_policy:
        allowed_filesystem:
          - { path: "/data/readonly", permissions: "read" }
        allowed_network:
          - "api.internal.svc"
        allowed_env:
          - "PLUGIN_CONFIG"
        resources:
          max_memory_bytes: 10485760      # 10 MB
          max_fuel: 1000000000            # per invocation (~1B instructions)
          max_execution_time_ms: 5000     # 5 seconds per call
          max_instances: 10
          max_tables: 10
```

**Defaults** (no sandbox_policy): deny-all filesystem, deny-all network, deny-all env, 5s timeout, unlimited fuel/memory.

---

## Security Enforcement

Five layers of defense-in-depth at the WASM trust boundary:

| Layer | What It Does | On Violation |
|-------|-------------|--------------|
| Capability filtering | Strips extension slots the plugin isn't authorized to read | Plugin never receives unauthorized data |
| Immutable tier | Verifies Arc pointer identity on immutable slots after return | Rejects all extension modifications |
| Monotonic labels | Verifies labels can only be added, never removed | Rejects extension modifications |
| Write authorization | Verifies mutations only on slots with write capability | Rejects extension modifications |
| Slot preservation | Hidden slots preserved unchanged during writeback | Pipeline data integrity maintained |

Additionally, the sandbox enforces: fuel limits (per-invocation), execution timeout (epoch-based), memory caps, network allowlist, and filesystem preopens.

---

## Error Handling

WASM runtime errors are classified into proper `PluginError` variants:

| Error | Variant | Executor Behavior |
|-------|---------|-------------------|
| Epoch deadline exceeded | `Timeout` | Applies `on_error` policy |
| Fuel exhausted | `Execution { code: "fuel_exhausted" }` | Applies `on_error` policy |
| Memory limit | `Execution { code: "memory_limit" }` | Applies `on_error` policy |
| Plugin trap/panic | `Execution { code: "wasm_trap" }` | Applies `on_error` policy |
| Network denied | `Execution { code: "network_denied" }` | Applies `on_error` policy |

With `on_error: disable`, the executor permanently disables a failing plugin (circuit breaker).

---

## Module Reference

### `SharedEngine`

One engine + one epoch ticker thread shared across all plugins from the same factory. Reduces overhead from N threads to 1.

```rust
pub struct SharedEngine { /* engine + linker */ }
impl SharedEngine {
    pub fn new() -> Result<Self>;
}
```

### `SandboxManager`

Manages a single plugin in an isolated Store.

```rust
pub struct SandboxManager { /* engine, linker, instance */ }
impl SandboxManager {
    pub fn new() -> Result<Self>;                              // own engine
    pub fn with_shared_engine(shared: &SharedEngine) -> Self;  // shared engine
    pub async fn load_wasmplugin(&mut self, path: &Path, policy: Option<&SandboxPolicy>, name: &str) -> Result<()>;
    pub async fn invoke(&mut self, hook: &str, payload, ext, ctx) -> Result<HookResult>;
    pub fn is_loaded(&self) -> bool;
}
```

### `WasmPluginFactory`

Implements `cpex_core::factory::PluginFactory`. Creates sandboxed plugin instances.

```rust
pub struct WasmPluginFactory { /* wasm_dir, registry, shared_engine */ }
impl WasmPluginFactory {
    pub fn new(wasm_dir: PathBuf, registry: Arc<PayloadSerializerRegistry>) -> Self;
    pub fn with_builtin_payloads(wasm_dir: PathBuf) -> Self;
}
```

### `PayloadSerializerRegistry`

Type-erased serialization for custom payload types crossing the WASM boundary.

```rust
pub struct PayloadSerializerRegistry { /* type_id → (name, ser, deser) */ }
impl PayloadSerializerRegistry {
    pub fn new() -> Self;
    pub fn register<T: WasmSerializablePayload>(&mut self);
    pub fn serialize(&self, payload: &dyn PluginPayload) -> Result<(&str, Vec<u8>)>;
    pub fn deserialize(&self, type_name: &str, bytes: &[u8]) -> Result<Box<dyn PluginPayload>>;
}
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `target 'wasm32-wasip2' not found` | Target not installed | `rustup target add wasm32-wasip2` |
| `failed to load wasm from .../plugin.wasm` | Binary missing | Build: `cd crates/cpex-wasm-plugin && make all` |
| `failed to load wasm from .../<name>.wasm` | Capabilities demo binaries missing | `cd crates/cpex-wasm-plugin && make build-all` |
| `failed to instantiate plugin` | Stale .wasm (WIT mismatch) | Rebuild: `make build-all` |
| `WASM invocation failed: epoch deadline` | Plugin exceeded timeout | Increase `max_execution_time_ms` in config |
| `WASM invocation failed: all fuel consumed` | Plugin exceeded instruction budget | Increase `max_fuel` in config |
| Bench skips WASM tests | `noop.wasm` missing | See "Running Benchmarks" section |
| Sandbox tests skipped | Test `.wasm` binaries missing | See "Sandbox Isolation Tests" section |
| `block_in_place` panic | Single-threaded tokio runtime | Use `rt-multi-thread` feature on tokio |

---

## Full Verification (all steps)

```bash
# Prerequisites
rustup target add wasm32-wasip2

# 1. Build ALL plugin WASM binaries
cd crates/cpex-wasm-plugin
make build-all
cargo build --target wasm32-wasip2 --release --features fs-test --no-default-features
cp target/wasm32-wasip2/release/cpex_wasm_plugin.wasm ../cpex-wasm-host/wasm/fs-test.wasm
cargo build --target wasm32-wasip2 --release --features net-test --no-default-features
cp target/wasm32-wasip2/release/cpex_wasm_plugin.wasm ../cpex-wasm-host/wasm/net-test.wasm
cargo build --target wasm32-wasip2 --release --features env-test --no-default-features
cp target/wasm32-wasip2/release/cpex_wasm_plugin.wasm ../cpex-wasm-host/wasm/env-test.wasm
cargo build --target wasm32-wasip2 --release --features noop --no-default-features
cp target/wasm32-wasip2/release/cpex_wasm_plugin.wasm ../cpex-wasm-host/wasm/noop.wasm
cd ../..

# 2. Host tests (46 tests including sandbox isolation)
cargo test -p cpex-wasm-host

# 3. Plugin unit tests (12 tests)
cargo test --manifest-path crates/cpex-wasm-plugin/Cargo.toml --features identity-checker --no-default-features
cargo test --manifest-path crates/cpex-wasm-plugin/Cargo.toml --features header-injector --no-default-features
cargo test --manifest-path crates/cpex-wasm-plugin/Cargo.toml --features audit-logger --no-default-features
cargo test --manifest-path crates/cpex-wasm-plugin/Cargo.toml --features token-attenuator --no-default-features

# 4. Benchmarks
cargo bench -p cpex-wasm-host

# 5. Demos
cargo run -p cpex-wasm-host --example wasm_capabilities_demo

# 6. Workspace check
cargo check
```

**Expected:** 46 host tests pass, 12 plugin tests pass, benchmarks show ~5-8µs WASM latency, demos run without errors, workspace compiles clean.
