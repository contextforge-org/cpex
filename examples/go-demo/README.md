# CPEX Go Demo

Two runnable examples showing the full CPEX plugin pipeline from Go, with plugins written in Rust and loaded via YAML configuration. The plugins are host demo plugins registered by the demo FFI crate, not CPEX builtins. Both configs use hook dispatch (`engine_settings.dispatch: hooks`): each plugin fires at the hooks it declares, ordered by `priority`.

## Prerequisites

- **Go 1.21+**
- **Rust toolchain** (stable, 1.75+)

## Build

```bash
# 1. Build the demo FFI library (includes core + demo plugins)
cd examples/go-demo/ffi
cargo build --release

# 2. Build the Go demos
cd examples/go-demo
go build -o cpex-demo .
go build -o cmf-demo ./cmd/cmf-demo/
```

## Demo 1: Generic Payload (`cpex-demo`)

Uses `PayloadGeneric` (untyped `map[string]any`) with three plugins on the demo's own hooks, `demo.tool_pre_invoke` and `demo.tool_post_invoke`. The `cmf.*` hooks carry a typed `MessagePayload`, so a generic-map host declares its own hooks; the demo FFI crate registers their metadata before the config loads.

| Plugin | Kind | Mode | What it does |
|--------|------|------|-------------|
| identity-checker | `demo/identity` | sequential | Validates `user` field present |
| pii-guard | `demo/pii` | sequential | Blocks PII-tagged tools without clearance |
| audit-logger | `demo/audit` | fire_and_forget | Logs tool invocations |

### Run

```bash
cd examples/go-demo
./cpex-demo
```

### Expected output

```
=== CPEX Go Demo ===

Plugins loaded: 3
Hooks: demo.tool_pre_invoke=true  demo.tool_post_invoke=true

=== Scenario 1: get_compensation (no PII clearance) ===
  Result: DENIED — PII clearance required for this operation [pii_access_denied]

=== Scenario 2: get_compensation (with PII clearance) ===
  Result: ALLOWED

=== Scenario 3: list_departments (non-PII tool) ===
  Result: ALLOWED

=== Scenario 4: list_departments (no user identity) ===
  Result: DENIED — User identity is required [no_identity]
```

### Config

See [`plugins.yaml`](plugins.yaml) for the full configuration.

## Demo 2: CMF Payload (`cmf-demo`)

Uses `PayloadCMFMessage` (typed CMF messages) with rich extensions and two plugins:

| Plugin | Kind | Mode | What it does |
|--------|------|------|-------------|
| tool-policy | `demo/cmf-tool-policy` | sequential | Checks tool permissions against security labels |
| header-injector | `demo/cmf-header-injector` | sequential | Injects response headers via capability-gated write |

### Run

```bash
cd examples/go-demo
./cmf-demo
```

### Expected output

```
=== CPEX CMF Demo ===

Plugins loaded: 2

=== Scenario 1: get_compensation tool call (no PII label) ===
  Result: DENIED: Tool 'get_compensation' is PII-tagged but security context lacks PII label [pii_label_required]

=== Scenario 2: get_compensation tool call (with PII label) ===
  Result: ALLOWED
  Modified response headers:
    X-Tool-Name: get_compensation
    X-Tool-Status: success
    X-CPEX-Processed: true

=== Scenario 3: tool result post-invoke (header injection) ===
  Result: ALLOWED
  Modified response headers:
    X-Tool-Name: get_compensation
    ...
```

### Config

See [`cmf_plugins.yaml`](cmf_plugins.yaml) for capabilities.

## Architecture

```
Go (main.go)
  │
  │  cpex.NewPolicyEngineDefault()
  │  engine.RegisterFactories(callback)  ← one raw C call
  │  engine.LoadConfig(yaml)
  │  engine.Initialize()
  │  engine.InvokeByName(hook, payload, extensions, ...)
  │
  ▼
Go SDK (go/cpex/)
  │  MessagePack serialize payload + extensions
  │
  ▼
cgo FFI (libcpex_demo_ffi.a)
  │  cpex_invoke() → Rust executor
  │
  ▼
Rust Plugins (examples/go-demo/ffi/src/)
  │  Plugin::handle() → PluginResult
  │
  ▼
cgo FFI
  │  MessagePack serialize result + modified extensions
  │
  ▼
Go SDK
  │  PipelineResult { IsDenied(), Violation, ModifiedExtensions }
  │
  ▼
Go (main.go)
```

## Demo Crate Structure

```
examples/go-demo/
  main.go                    — generic payload demo
  plugins.yaml               — config for generic demo
  cmf_plugins.yaml           — config for CMF demo
  go.mod                     — Go module (depends on go/cpex)
  cmd/
    cmf-demo/
      main.go                — CMF payload demo
  ffi/
    Cargo.toml               — Rust crate: cpex-demo-ffi
    src/
      lib.rs                 — C FFI: cpex_demo_register_factories()
      demo_plugins.rs        - demo hooks + 3 generic plugins (identity, PII, audit)
      cmf_plugins.rs         — 2 CMF plugins (tool-policy, header-injector)
```

The `cpex-demo-ffi` crate builds a staticlib that includes both the core `cpex-ffi` symbols and the demo plugin factories. Go links only this one library.

## How Factory Registration Works

The Go SDK's `PolicyEngine` wraps the Rust engine. Plugin factories are Rust code, so registration happens through a callback:

```go
engine.RegisterFactories(func(handle unsafe.Pointer) error {
    // handle is the raw cpex_ffi::CpexEngineInner pointer
    // Call your crate's C registration function
    C.cpex_demo_register_factories(handle)
    return nil
})
```

This keeps the Go SDK generic — it doesn't know about specific factories. Each Rust crate exports its own `register_*_factories()` function.

To use the CPEX builtins (`identity/jwt`, `identity/api-key`, `delegator/oauth`, `elicitation/ciba`, the PDPs and Vault) as well, call `engine.EnableAPL()` before `LoadConfig`. Pass `cpex.WithPrivateDestinations()` when a builtin must reach a localhost or in-cluster address; those are blocked by default.

---

# Adding New Payload Types and Hooks

This section covers how to extend the system with new payload types for Go-to-Rust plugin pipelines.

## Overview

The CPEX payload type registry maps a `uint8` discriminator to a concrete Rust type for efficient deserialization across the FFI boundary. Currently:

| ID | Constant | Rust Type | Go Type |
|----|----------|-----------|---------|
| 0 | `PAYLOAD_GENERIC` | `GenericPayload` | `map[string]any` |
| 1 | `PAYLOAD_CMF_MESSAGE` | `MessagePayload` | `MessagePayload` |
| 2 | `PAYLOAD_IDENTITY` | `IdentityPayload` | `IdentityPayload` |

## Step-by-Step: Adding a New Payload Type

### 1. Define the Rust payload type

In your Rust crate:

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MyPayload {
    pub field_a: String,
    pub field_b: i64,
}
praxis_policy_core::impl_plugin_payload!(MyPayload);
```

### 2. Register the payload type in the FFI crate

In `crates/cpex-ffi/src/lib.rs`:

```rust
// Add the constant
pub const PAYLOAD_MY_TYPE: u8 = 3;

// Add a deserialize arm
fn deserialize_payload(payload_type: u8, bytes: &[u8]) -> Result<...> {
    match payload_type {
        // ... existing arms ...
        PAYLOAD_MY_TYPE => {
            let v: MyPayload = rmp_serde::from_slice(bytes)?;
            Ok(Box::new(v))
        }
        _ => Err(...)
    }
}

// Add a serialize arm
fn serialize_payload(payload: &dyn PluginPayload) -> Option<(u8, Vec<u8>)> {
    // ... existing checks ...
    if let Some(mp) = payload.as_any().downcast_ref::<MyPayload>() {
        return rmp_serde::to_vec_named(mp).ok().map(|b| (PAYLOAD_MY_TYPE, b));
    }
    // ...
}
```

### 3. Define the Go struct

In `go/cpex/types.go` (or a new file):

```go
const PayloadMyType uint8 = 3

type MyPayload struct {
    FieldA string `msgpack:"field_a"`
    FieldB int64  `msgpack:"field_b"`
}
```

### 4. Use it

```go
result, ct, bg, err := engine.InvokeByName(
    "my.hook",
    cpex.PayloadMyType,
    MyPayload{FieldA: "hello", FieldB: 42},
    ext,
    nil,
)

// Deserialize modified payload from result
modified, err := cpex.DeserializePayload[MyPayload](result)
```

### Total: 5 touch points

1. Rust struct + `impl_plugin_payload!`
2. FFI constant
3. FFI `deserialize_payload` match arm
4. FFI `serialize_payload` downcast
5. Go struct with msgpack tags

## Step-by-Step: Adding a New Hook Type

Hooks define what payload goes in and what comes out. For Go callers, hooks are identified by string name (e.g., `"cmf.tool_pre_invoke"`). A host hook needs its metadata registered before any config naming it loads; the config loader refuses a hook name it does not know.

### 1. Define the hook type in Rust

```rust
pub struct MyHook;
impl HookTypeDef for MyHook {
    type Payload = MyPayload;
    type Result = PluginResult<MyPayload>;
    const NAME: &'static str = "my_hook";
}

// Describe the hook to the engine. `family` must match the hook type's
// NAME, so only handlers for MyHook can register on it.
register_hook_metadata(
    "my.hook",
    HookMetadata { family: Some(MyHook::NAME), entity_type: None, phase: HookPhase::Unphased },
);
```

### 2. Write a plugin that handles it

```rust
impl HookHandler<MyHook> for MyPlugin {
    fn handle(
        &self,
        payload: &MyPayload,
        extensions: &Extensions,
        ctx: &mut PluginContext,
    ) -> PluginResult<MyPayload> {
        // ... your logic ...
        PluginResult::allow()
    }
}
```

### 3. Create a factory and register it

```rust
struct MyPluginFactory;
impl PluginFactory for MyPluginFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let plugin = Arc::new(MyPlugin { cfg: config.clone() });
        Ok(PluginInstance {
            plugin: plugin.clone(),
            handlers: vec![
                ("my.hook", Arc::new(TypedHandlerAdapter::<MyHook, _>::new(plugin))),
            ],
        })
    }
}
```

### 4. Register in your FFI crate

```rust
pub fn register_my_factories(engine: &PolicyEngine) {
    engine.register_factory("my-plugin-kind", Box::new(MyPluginFactory));
}
```

### 5. Add to YAML config

```yaml
engine_settings:
  dispatch: hooks

plugins:
  - name: my-plugin
    kind: my-plugin-kind
    hooks: [my.hook]
    mode: sequential
    priority: 10
```

`priority` is accepted only under `dispatch: hooks`. Under the default `dispatch: policy`, call `EnableAPL` and name the plugin from a policy step instead, for example `run(my-plugin)` under a route's `authorization.pre_invocation`.

### 6. Invoke from Go

```go
result, ct, bg, err := engine.InvokeByName("my.hook", cpex.PayloadMyType, payload, ext, nil)
```

The Go side doesn't need to know about the Rust hook type — it just uses the string name and the payload type constant.
