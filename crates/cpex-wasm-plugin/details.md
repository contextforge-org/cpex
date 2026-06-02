# cpex-wasm-plugin

A WebAssembly Component Model plugin that implements policy enforcement hooks for the CPEX (ContextForge Plugin Execution) framework. Plugins are compiled to `wasm32-wasip2` and executed inside a sandboxed Wasmtime runtime managed by `cpex-wasm-host`.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         cpex-wasm-host                                   │
│                                                                         │
│  ┌──────────────┐     ┌──────────────────┐     ┌────────────────────┐  │
│  │ PolicyLoader │────▶│  SandboxManager  │────▶│  Wasmtime Runtime  │  │
│  │ (config.yaml)│     │                  │     │                    │  │
│  └──────────────┘     │  • fuel metering │     │  ┌──────────────┐  │  │
│                       │  • epoch timeout │     │  │ plugin.wasm  │  │  │
│                       │  • memory limits │     │  │              │  │  │
│                       │  • http gating   │     │  │ handle_hook()│  │  │
│                       └──────────────────┘     │  └──────────────┘  │  │
│                                                └────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

## How It Works

### 1. WIT Interface Contract

The plugin implements the `cpex:plugin/plugin` world defined in `wit/world.wit`. The contract exposes a single exported function:

```wit
export handle-hook: func(
    payload: message-payload,
    extensions: extensions,
    ctx: plugin-context
) -> plugin-result;
```

The host calls `handle-hook` on every message hook event (e.g. `cmf.tool_pre_invoke`, `cmf.tool_post_invoke`). The plugin inspects the payload and extensions, then returns `allow` or `deny(violation)`.

### 2. Data Flow

```
                         ┌─────────────────────┐
                         │    Host Process      │
                         │                      │
                         │  Native types:       │
                         │  • MessagePayload    │
                         │  • Extensions        │
                         │  • PluginContext      │
                         └──────────┬───────────┘
                                    │
                         serialize across ABI
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │   WASM Guest         │
                         │                      │
                         │  WIT-generated types  │
                         │  (MessagePayload,    │
                         │   Extensions, etc.)  │
                         └──────────┬───────────┘
                                    │
                    conversions.rs   │  wit_payload_to_native()
                                    │  wit_extensions_to_native()
                                    ▼
                         ┌─────────────────────┐
                         │   cpex-payload       │
                         │                      │
                         │  Shared domain logic: │
                         │  identity_checker::  │
                         │    identity_check()  │
                         └──────────┬───────────┘
                                    │
                    conversions.rs   │  native_result_to_wit()
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │   plugin-result      │
                         │   (Allow | Deny)     │
                         └─────────────────────┘
```

### 3. Conversion Layer (`src/conversions.rs`)

The Component Model ABI passes WIT-typed records across the host/guest boundary. Inside the guest, `conversions.rs` bridges between WIT-generated types and the native `cpex-payload` types so that plugin logic is written against the canonical domain model:

| Direction | Function | Purpose |
|-----------|----------|---------|
| WIT → Native | `wit_payload_to_native()` | Converts incoming `MessagePayload` |
| WIT → Native | `wit_extensions_to_native()` | Converts `Extensions` (security, HTTP, meta) |
| Native → WIT | `native_result_to_wit()` | Converts `SimplePluginResult` back to WIT variant |

### 4. Plugin Logic

The actual decision-making lives in `cpex-payload::plugins::identity_checker::identity_check`. This function:

1. Determines whether the message is a **tool call** (pre-invoke) or a **tool result** (post-invoke)
2. Inspects security extensions — labels, subject identity, roles
3. Enforces policy: e.g. denies access to PII-labeled data unless the subject holds `hr_admin`
4. Returns `Allow` or `Deny { code, reason }`

## Sandbox Enforcement

The host enforces multi-layered isolation on each plugin instance:

```
┌─────────────── Sandbox Boundary ───────────────────────────────┐
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Resource Limits                                         │   │
│  │  • max_memory_bytes: 10 MB                               │   │
│  │  • max_fuel: 1B instructions                             │   │
│  │  • max_execution_time_ms: 5000 (epoch-based timeout)     │   │
│  │  • max_instances: 10 (wasm instances)                    │   │
│  │  • max_tables: 10                                        │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Filesystem Policy                                       │   │
│  │  • Only preopened dirs/files are visible                  │   │
│  │  • Read-only or read-write per path                       │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Network Policy (wasi:http)                              │   │
│  │  • Outgoing HTTP gated by allowed_hosts allowlist         │   │
│  │  • Non-matching hosts → HttpRequestDenied error           │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Environment Policy                                      │   │
│  │  • Only explicitly listed env vars are visible            │   │
│  │  • All others are invisible to the guest                  │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Build Process

```
┌────────────────┐       cargo build        ┌──────────────────────┐
│  src/lib.rs    │ ─────────────────────────▶│  target/wasm32-      │
│  src/          │   --target wasm32-wasip2  │  wasip2/release/     │
│  conversions.rs│   --release              │  cpex_wasm_plugin.wasm│
│  wit/world.wit │                           └──────────┬───────────┘
└────────────────┘                                      │
                                                   cp to ./
                                                        │
                                                        ▼
                                               ┌────────────────┐
                                               │  plugin.wasm   │
                                               └────────────────┘
```

Build with:
```bash
make build   # or: cargo build --target wasm32-wasip2 --release
```

The compiled component is copied to `plugin.wasm` at the crate root, which is what `cpex-wasm-host` loads at runtime.

## Runtime Invocation Sequence

```
Host main()                SandboxManager              Plugin (WASM)
    │                           │                           │
    │  load_plugin(name,        │                           │
    │    path, sandbox_config)  │                           │
    │──────────────────────────▶│                           │
    │                           │  build WasiCtx            │
    │                           │  set fuel, epoch          │
    │                           │  instantiate component    │
    │                           │──────────────────────────▶│
    │                           │                           │
    │  invoke(name,             │                           │
    │    payload, ext, ctx)     │                           │
    │──────────────────────────▶│                           │
    │                           │  reset fuel + epoch       │
    │                           │  call_handle_hook()       │
    │                           │──────────────────────────▶│
    │                           │                           │ wit_payload_to_native()
    │                           │                           │ wit_extensions_to_native()
    │                           │                           │ identity_check()
    │                           │                           │ native_result_to_wit()
    │                           │◀──────────────────────────│
    │                           │  record fuel consumed     │
    │                           │  record metrics           │
    │◀──────────────────────────│                           │
    │  PluginResult             │                           │
    │  (Allow | Deny)           │                           │
```

## File Structure

```
crates/cpex-wasm-plugin/
├── Cargo.toml          # cdylib crate, depends on wit-bindgen + cpex-payload
├── Makefile            # build target: wasm32-wasip2
├── plugin.wasm         # pre-built component binary
├── src/
│   ├── lib.rs          # Guest impl: IdentityCheckerPlugin + export!()
│   ├── conversions.rs  # WIT ↔ Native type conversions
│   └── errors.rs       # Error types
└── wit/
    ├── world.wit       # Plugin world definition (handle-hook export)
    └── deps/           # WASI interface dependencies
        ├── cli.wit
        ├── clocks.wit
        ├── filesystem.wit
        ├── http.wit
        ├── io.wit
        ├── random.wit
        └── sockets.wit
```

## Key Design Decisions

1. **Shared logic via `cpex-payload`** — Plugin decision logic lives in a pure-Rust crate (`cpex-payload::plugins`) shared between native and WASM targets. The WASM plugin is a thin adapter.

2. **Component Model (not Core WASM)** — Uses WASI Preview 2 and the Component Model for structured type passing across the ABI boundary (no manual serialization).

3. **Fuel + epoch metering** — Each invocation gets a fresh fuel budget and epoch deadline. This prevents infinite loops and bounds CPU time per call.

4. **Network allowlist at the HTTP hook layer** — The host intercepts every outgoing HTTP request via `WasiHttpHooks::send_request` and checks against the policy before the request leaves the process.

5. **Metrics per-plugin** — Every invocation tracks fuel consumed, network denials/allows, traps, and total calls. Exposed via an HTTP dashboard on port 3000.
