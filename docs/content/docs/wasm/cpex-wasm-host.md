---
title: "cpex-wasm-host (Host Runtime)"
weight: 40
---

# cpex-wasm-host — Host Runtime

Load a `.wasm` plugin, sandbox it with declarative YAML policy, and invoke it in the same pipeline as native plugins — the host handles compilation, resource limits, type conversion, and capability validation automatically.

The `cpex-wasm-host` crate is the **host-side runtime** that integrates with `cpex-core`'s `PluginManager` so WASM plugins participate transparently in the hook pipeline alongside native plugins.

## Purpose

- Load `.wasm` component binaries and compile them with Wasmtime 46.0
- Enforce sandbox policies (filesystem, network, env, CPU, memory) per plugin
- Convert between the framework's native Rust types and WIT component-model types
- Validate plugin results against declared capabilities (defense-in-depth)
- Provide a `PayloadSerializerRegistry` for custom payload types crossing the WASM boundary

## Source directory (`src/`)

### `src/lib.rs`

Module root. Re-exports the five public modules:

```rust
pub mod conversions;
pub mod factory;
pub mod payload_registry;
pub mod policy_loader;
pub mod sandbox_manager;
```

### `src/factory.rs`

The main integration point. Contains:

| Component | Role |
|-----------|------|
| `WasmPluginFactory` | Implements `cpex-core`'s `PluginFactory` trait. Parses `"wasm://plugin.wasm"` URIs, extracts sandbox policy from YAML config, and creates `WasmBridgeHandler` instances per hook. |
| `WasmBridgeHandler` | Implements `AnyHookHandler`. Converts native payloads → WIT, invokes the sandbox, converts WIT → native, then validates extensions against capabilities. |
| `validate_extension_modifications` | Post-invocation check: immutable tier integrity, monotonic label enforcement, write authorization against declared capabilities. |
| `classify_wasm_error` | Maps Wasmtime error strings to typed `PluginError` variants (Timeout, FuelExhausted, MemoryLimit, NetworkDenied, WasmTrap). |

### `src/sandbox_manager.rs`

Manages the Wasmtime runtime for a single plugin:

| Component | Role |
|-----------|------|
| `SharedEngine` | Shared Wasmtime `Engine` + `Linker` + epoch-ticker thread. One per factory; all plugins share compilation caches. |
| `SandboxManager` | Owns a compiled `Component` and a persistent `Store`. Calls `load_wasmplugin()` once, then `invoke()` per hook call (resets fuel + epoch each time). |
| `NetworkPolicy` | Implements `WasiHttpHooks` to intercept outbound HTTP. Filters by host (with wildcard), port, scheme, and method. |
| `WasmPluginState` | Per-plugin store data: WASI context, HTTP context, resource table, store limits. Implements `host-logging::Host`. |

### `src/conversions.rs`

Host-side type conversions between `cpex-core` native types and WIT types:

| Direction | Functions |
|-----------|-----------|
| Native → WIT | `native_payload_to_wit`, `native_identity_payload_to_wit`, `native_delegation_payload_to_wit`, `native_extensions_to_wit`, `native_context_to_wit` |
| WIT → Native | `wit_cmf_payload_to_native`, `wit_identity_payload_to_native`, `wit_delegation_payload_to_native`, `wit_extensions_to_owned`, `wit_hook_result_to_native_filtered`, `wit_context_to_native` |

### `src/policy_loader.rs`

Parses sandbox policy from YAML config and builds a WASI context:

| Type | Purpose |
|------|---------|
| `SandboxPolicy` | Top-level: `allowed_filesystem`, `allowed_network`, `allowed_env`, `resources` |
| `FilesystemRule` | Specifies a `dir` or `file` with a named permission level |
| `NetworkRule` | Host (supports `*.` wildcard), ports, schemes, methods |
| `ResourceLimits` | `max_memory_bytes`, `max_fuel`, `max_execution_time_ms`, `max_instances`, `max_tables` |
| `build_wasi_context()` | Constructs `WasiCtx` + `WasiHttpCtx` from a `SandboxPolicy`. Preopens directories, injects env vars, captures network rules. |

### `src/payload_registry.rs`

Type-erased serialization for custom payloads:

```rust
let mut registry = PayloadSerializerRegistry::new();
registry.register::<MyCustomPayload>();  // must impl WasmSerializablePayload

// At runtime:
let (type_name, bytes) = registry.serialize(&payload)?;
let restored: Box<dyn PluginPayload> = registry.deserialize(type_name, &bytes)?;
```

## Factory constructors

| Constructor | When to use |
|-------------|-------------|
| `WasmPluginFactory::with_builtin_payloads(wasm_dir)` | Most cases — pre-registers CMF, Identity, and Delegation payloads. Panics on engine failure. |
| `WasmPluginFactory::new(wasm_dir, registry)` | When you need custom payload types or want to handle engine errors as `Result`. |

### Using `with_builtin_payloads`

```rust
use std::path::PathBuf;
use cpex_wasm_host::factory::WasmPluginFactory;

let factory = WasmPluginFactory::with_builtin_payloads(PathBuf::from("./wasm"));
```

This pre-registers `MessagePayload`, `IdentityPayload`, and `DelegationPayload`. Credential fields marked `#[serde(skip)]` never cross the boundary.

### Using `new` with custom payloads

```rust
use std::sync::Arc;
use std::path::PathBuf;
use cpex_wasm_host::factory::WasmPluginFactory;
use cpex_wasm_host::payload_registry::PayloadSerializerRegistry;

let mut registry = PayloadSerializerRegistry::new();
registry.register::<MessagePayload>();
registry.register::<IdentityPayload>();
registry.register::<DelegationPayload>();
registry.register::<MyCustomPayload>();  // your domain-specific type

let factory = WasmPluginFactory::new(PathBuf::from("./wasm"), Arc::new(registry))?;
```

Use this when you have custom hook types via `define_hook!` + `impl_wasm_payload!` that need to cross the WASM boundary as `custom-payload` bytes.

## Configuration

YAML config files live in `config/`. Each plugin entry specifies its sandbox policy:

```yaml
plugins:
  - name: my-plugin
    kind: "wasm://my-plugin.wasm"
    hooks:
      - cmf.tool_pre_invoke
    capabilities:
      - read_labels
      - write_headers
    config:
      sandbox:
        # Filesystem access
        filesystem:
          - dir: "./data/cache"
            permission: full-access
          - dir: "./data/audit"
            permission: drop-box

        # Network access
        network:
          - host: "api.example.com"
            ports: [443]
            schemes: ["https"]
            methods: ["GET", "POST"]
          - host: "*.internal.corp"
            ports: []        # any port
            schemes: ["https"]

        # Environment variables
        env_vars:
          - APP_TOKEN
          - LOG_LEVEL

        # Resource limits
        resources:
          max_fuel: 500_000_000
          max_execution_time_ms: 5000
          max_memory_bytes: 10_485_760   # 10 MB
```

### Default policy (deny-all)

A plugin with no `sandbox` config block gets the most restrictive policy:

- **Filesystem**: no preopened directories
- **Network**: all outbound HTTP blocked
- **Env vars**: none visible
- **Resources**: engine defaults (generous but bounded)

### Capabilities

The `capabilities` list controls which extension fields a plugin can read or write. The host strips disallowed fields before the call and discards unauthorized modifications on return.

Available capabilities:

| Capability | Grants access to |
|-----------|-----------------|
| `read_labels` | Security labels |
| `append_labels` | Add labels (monotonic, no removal) |
| `read_subject` | Subject id + type |
| `read_roles` | Subject roles |
| `read_teams` | Subject teams |
| `read_claims` | Subject claims |
| `read_permissions` | Subject permissions |
| `read_client` | OAuth client info |
| `read_workload` | Workload identity |
| `read_headers` | HTTP headers |
| `write_headers` | Modify HTTP headers |
| `read_agent` | Agent context |
| `read_delegation` | Delegation chain |
| `append_delegation` | Append to delegation chain |

## End-to-end example

Here's how the **capabilities demo** runs from config to result:

**1. Config** (`config/config_capabilities.yaml`):

```yaml
plugins:
  - name: identity-checker
    kind: "wasm://identity-checker.wasm"
    hooks: [cmf.tool_pre_invoke]
    capabilities: [read_labels, read_subject, read_roles]
    config:
      sandbox:
        resources:
          max_fuel: 500_000_000
          max_execution_time_ms: 5000

  - name: header-injector
    kind: "wasm://header-injector.wasm"
    hooks: [cmf.tool_pre_invoke, cmf.tool_post_invoke]
    capabilities: [read_headers, write_headers, append_labels]
    config:
      sandbox:
        resources:
          max_fuel: 500_000_000
          max_execution_time_ms: 5000
```

**2. Host code** (from `examples/wasm_capabilities_demo.rs`):

```rust
use std::path::PathBuf;
use cpex_wasm_host::factory::WasmPluginFactory;
use cpex_core::plugin_manager::PluginManager;

let wasm_dir = PathBuf::from("./wasm");

// Create and register a factory per plugin kind
let mut mgr = PluginManager::default();
mgr.register_factory(
    "wasm://identity-checker.wasm",
    Box::new(WasmPluginFactory::with_builtin_payloads(wasm_dir.clone())),
);
mgr.register_factory(
    "wasm://header-injector.wasm",
    Box::new(WasmPluginFactory::with_builtin_payloads(wasm_dir)),
);

// Load config from YAML file and initialize plugins
mgr.load_config_file(Path::new("config/config_capabilities.yaml"))?;
mgr.initialize().await?;

// Build payload + extensions
let payload = MessagePayload { /* CMF message with ToolCall */ };
let extensions = Extensions::builder()
    .security(SecurityExtension { subject: "user:alice".into(), .. })
    .http(HttpExtension { headers: vec![("x-request-id", "abc123")] })
    .build();

// Invoke — plugins only see extensions matching their capabilities
let (result, _bg) = mgr.invoke_named::<CmfHook>(
    "cmf.tool_pre_invoke", payload, extensions, None
).await;
```

**3. What happens inside:**

1. `WasmPluginFactory::create()` parses sandbox policy, compiles `.wasm`, creates `SandboxManager`
2. Executor filters extensions based on plugin capabilities before dispatch
3. `WasmBridgeHandler` converts native types to WIT types
4. `SandboxManager::invoke()` resets fuel/epoch, calls `handle-hook` in the sandbox
5. WIT result is converted back to native types (Arc-preserving `cow_copy`)
6. `validate_extension_modifications()` checks the plugin didn't write to unauthorized fields
7. Result flows back through the executor, which merges validated modifications into the pipeline

**4. Run it:**

```bash
cd crates/cpex-wasm-host
make run-capabilities-demo
```

## Available `make` targets

| Target | Description |
|--------|-------------|
| `make all` | Build all plugins and host examples (default) |
| `make build-all-plugins` | Build demo WASM plugins and stage to `wasm/` |
| `make build-test-plugins` | Build test WASM plugins and stage to `wasm/` |
| `make build-examples` | Compile all host example binaries |
| `make run-all-demos` | Build everything and run ALL demos end-to-end |
| `make run-plugin-demo` | Run the custom-payload plugin demo |
| `make run-capabilities-demo` | Run the capabilities isolation demo |
| `make run-fs-demo` | Run the filesystem sandbox permissions demo |
| `make run-env-demo` | Run the env variable sandbox demo |
| `make run-token-attenuator-demo` | Run the token delegation demo |
| `make run-network-policy-demo` | Run the network policy sandbox demo |
| `make run-resource-limits-demo` | Run the resource limits sandbox demo |
| `make test` | Clean, rebuild all plugins, run all tests |
| `make unit-tests` | Run host unit tests (no WASM plugins needed) |
| `make integration-tests` | Build plugins, then run integration tests |
| `make bench-all` | Build plugins and run benchmarks + generate chart |
| `make clippy` | Run clippy on both host and plugin crates |
| `make sync-wit` | Copy `wit/world.wit` from cpex-wasm-plugin |
| `make check-wit` | Fail if `wit/world.wit` has drifted from cpex-wasm-plugin |
| `make clean` | Remove host build artifacts and `wasm/` binaries |
| `make clean-all` | Remove host + plugin artifacts and ALL `.wasm` files |
| `make help` | Show all available targets |

## Implementation details

This section covers the internals of each component — useful for contributors or anyone debugging the host runtime.

### SharedEngine internals

**Engine configuration:**
- `wasm_component_model(true)` — required for WIT/Component Model support
- `consume_fuel(true)` — enables instruction-level metering
- `epoch_interruption(true)` — enables time-based interruption via epoch counter

**Linker setup** (wires up all host-side imports):
1. `wasmtime_wasi::p2::add_to_linker_async` — WASI Preview 2 (filesystem, clocks, I/O)
2. `wasmtime_wasi_http::p2::add_only_http_to_linker_async` — WASI HTTP outgoing handler
3. `cpex::plugin::host_logging::add_to_linker` — custom `host-logging` interface

**Epoch ticker thread:**
- A dedicated OS thread (`std::thread::spawn`, not a tokio task) that calls `engine.increment_epoch()` in a loop
- Tick interval: **1 millisecond** (hardcoded as `EPOCH_TICK_MS = 1`)
- One thread per `SharedEngine` — all plugins sharing the engine share the ticker
- No shutdown mechanism — the thread lives as long as the process (cheap: 1ms sleep + atomic increment)
- Timeout conversion: `max_execution_time_ms / EPOCH_TICK_MS` = epoch deadline in ticks (e.g., 5000ms = 5000 ticks)
- Uses `std::thread::spawn` intentionally (not tokio) to avoid runtime dependency for the ticker

### SandboxManager internals

**Store persistence:** The `Store<WasmPluginState>` is created once during `load_wasmplugin()` and reused across all subsequent `invoke()` calls. Linear memory, module-level statics, and heap state survive between calls.

**Per-invocation reset:**
```rust
store.set_fuel(instance.fuel_per_invocation)     // fresh instruction budget
store.set_epoch_deadline(instance.epoch_deadline) // fresh wall-clock timeout
```

**NetworkPolicy:** Implements `WasiHttpHooks`, intercepting every outbound HTTP request. Checks:
1. Host pattern match (exact or `*.` wildcard via `host_matches()`)
2. Port allowlist (infers 80/443 from scheme if no port in URI)
3. Scheme allowlist
4. Method allowlist (case-insensitive)

Any failed check returns `ErrorCode::HttpRequestDenied`.

### WasmBridgeHandler invocation flow

| Step | What happens | Location |
|------|--------------|----------|
| 1 | Fast-path downcast for known payload types (CMF, Identity, Delegation); fallback to PayloadSerializerRegistry for custom | `factory.rs:212-245` |
| 2 | Convert extensions via `native_extensions_to_wit` | `factory.rs:249` |
| 3 | Convert context via `native_context_to_wit` | `factory.rs:250` |
| 4 | Acquire `tokio::sync::Mutex`, call `mgr.invoke()` | `factory.rs:253-258` |
| 5 | Classify errors via `classify_wasm_error` on failure | `factory.rs:256` |
| 6 | Convert result via `wit_hook_result_to_native_filtered` | `factory.rs:263-268` |
| 7 | Run `validate_extension_modifications` | `factory.rs:271-279` |
| 8 | Write back modified `ctx.local_state` and `ctx.global_state` | `factory.rs:283-286` |

**Concurrency:** Each plugin has its own `Arc<Mutex<SandboxManager>>`. The Mutex serializes calls to the same plugin. Different plugins have separate Mutex instances and execute concurrently.

### Type conversions (`conversions.rs`) — design decisions

1. **Arc preservation via `cow_copy()`** — When converting WIT extensions back to native, the function seeds from `original.cow_copy()`. This preserves `Arc` pointers on immutable slots (request, meta, agent, mcp, completion, provenance, llm, framework). Post-invocation validation uses `Arc::ptr_eq` to detect tampering — a reconstructed slot would have a different pointer and be rejected.

2. **Filtered-slot awareness** — The conversion checks which slots the guest was authorized to see. Slots hidden by capability filtering are preserved from the original `cow_copy()`, not overwritten by the guest's empty return.

3. **Credential exclusion** — Fields like `IdentityPayload.raw_token`, `DelegationPayload.bearer_token`, and `RawDelegatedToken.token` are never serialized across the boundary (`#[serde(skip)]` in native types and absent from WIT schemas).

4. **JSON string escapes for recursive types** — WIT cannot represent recursive types. Structures like `PromptResult.messages` (which contain content-parts which may contain nested prompt-results) are serialized as JSON strings rather than recursive WIT records.

5. **Full deep copy** — Every conversion clones all fields. Strings are cloned, Vecs are iterated and mapped. No buffer sharing across the WASM boundary. This is the primary per-invocation cost (~843 ns for type conversion alone).

**Mutable slots (overwritten from guest return):** `security`, `http`, `delegation`, `custom`

**Immutable slots (preserved from original, pointer-checked):** `request`, `agent`, `mcp`, `completion`, `provenance`, `llm`, `framework`, `meta`

### Error classification (`classify_wasm_error`)

Maps Wasmtime error strings (lowercased) to typed `PluginError` variants:

| Pattern matched | Error variant | Code |
|-----------------|---------------|------|
| "epoch deadline" | `PluginError::Timeout` | — (has `timeout_ms` field) |
| "all fuel consumed" / "fuel" | `PluginError::Execution` | `"fuel_exhausted"` |
| "memory" + ("grow" or "limit") | `PluginError::Execution` | `"memory_limit"` |
| "unreachable" / "wasm trap" / "panic" | `PluginError::Execution` | `"wasm_trap"` |
| "request denied" / "http_request_denied" | `PluginError::Execution` | `"network_denied"` |
| (anything else) | `PluginError::Execution` | `None` |

This classification is string-based (matching against wasmtime's error messages) and may need updating across wasmtime version upgrades.

### Post-invocation validation (`validate_extension_modifications`)

Runs after WIT → native conversion, before the executor merges results:

| Check | What it verifies | Mechanism |
|-------|------------------|-----------|
| Immutable tier | Arc pointer identity on immutable slots | `original.validate_immutable(owned)` — `Arc::ptr_eq` comparison |
| Monotonic labels | `new_labels.is_superset(&orig_labels)` | Labels can only grow, never shrink |
| Write headers | HTTP headers unchanged unless `write_headers` capability declared | Field-level diff check |
| Write labels | Label count unchanged unless `append_labels` capability declared | Count comparison |
| Write delegation | Chain length/depth unchanged unless `append_delegation` declared | Length/depth/flag comparison |

If any check fails, `modified_extensions` is set to `None` (with a warning log) — the entire extension modification is silently discarded.

The executor then applies a second round of the same checks (defense-in-depth) before merging into the pipeline.

### Performance breakdown per invocation

| Step | Cost |
|------|------|
| Mutex acquire | ~50 ns |
| Fuel + epoch reset | ~40 ns |
| Type conversion (Native → WIT) | ~843 ns |
| Wasmtime component dispatch | ~2.5 μs |
| Guest execution (noop) | ~500 ns |
| Type conversion (WIT → Native) | ~500 ns – 2 μs |
| Post-invocation validation | ~100 ns |
| **Total (noop, minimal payload)** | **~4.8 μs (57x native)** |
| **Total (full extensions)** | **~7.9 μs (94x native)** |

For context: a typical LLM call takes 500ms–5s. The WASM overhead adds 0.001–0.01% to request latency.

## Advantages

- **Drop-in integration** — implements `PluginFactory` / `AnyHookHandler` from `cpex-core`; WASM plugins are transparent to the pipeline
- **Shared compilation** — `SharedEngine` caches compiled modules; multiple plugins share one engine and one epoch ticker thread
- **Fine-grained policy** — six filesystem permission levels, host/port/scheme/method network rules, explicit env var allowlists
- **Defense-in-depth** — capability validation on the return path catches unauthorized modifications at the type level
- **Custom payload extensibility** — `PayloadSerializerRegistry` supports arbitrary domain types without WIT changes
- **Structured error classification** — Wasmtime errors are mapped to typed variants for meaningful error handling

## Limitations

- **Cold start overhead** — first `.wasm` compilation takes several hundred milliseconds; subsequent invocations are ~5 μs
- **~57-94x slower than native** — serialization + sandbox overhead per call; negligible compared to network/LLM latency in typical pipelines
- **Single-threaded per plugin** — each `Store` is single-threaded; the `Mutex` serializes concurrent calls to the same plugin (different plugins run concurrently)
- **WASI P2 only** — requires Wasmtime's component model; legacy WASI P1 modules are not supported
- **Mutable extension slots only** — only `security`, `http`, `delegation`, and `custom` can be modified by the guest; all other extension slots are immutable (changes are detected and discarded)
- **No raw socket access** — WASI P2 does not expose raw TCP/UDP; only HTTP via `wasi:http/outgoing-handler`
- **String-based error classification** — `classify_wasm_error` matches against wasmtime's error message text, which may drift across wasmtime version upgrades
