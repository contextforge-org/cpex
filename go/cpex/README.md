# CPEX Go SDK

Go bindings for the CPEX plugin runtime. Wraps the Rust core via cgo — all plugin execution happens in Rust, called from Go through MessagePack-serialized payloads and opaque handles.

## Prerequisites

- **Go 1.21+**
- **Rust toolchain** (stable, 1.75+)
- **Built Rust library**: the Go SDK links against `libcpex_ffi.a`

```bash
# From the repository root
cargo build --release -p cpex-ffi
```

## Package Structure

```
go/cpex/
  ffi.go          — cgo declarations (C function signatures)
  manager.go      — PluginManager, ContextTable, BackgroundTasks
  types.go        — Extensions, PipelineResult, payload constants
  cmf.go          — CMF Message, ContentPart, domain objects
  manager_test.go — tests (require built libcpex_ffi)
```

## Quick Start

```go
import cpex "github.com/contextforge-org/contextforge-plugins-framework/go/cpex"

// 1. Create a manager
mgr, err := cpex.NewPluginManagerDefault()
defer mgr.Shutdown()

// 2. Register plugin factories (Rust-side, via callback)
mgr.RegisterFactories(func(handle unsafe.Pointer) error {
    C.my_register_factories(handle)
    return nil
})

// 3. Load YAML config
mgr.LoadConfig(yamlString)

// 4. Initialize plugins
mgr.Initialize()

// 5. Invoke a hook
result, ct, bg, err := mgr.InvokeByName(
    "tool_pre_invoke",
    cpex.PayloadGeneric,
    map[string]any{"tool_name": "get_compensation", "user": "alice"},
    &cpex.Extensions{
        Meta: &cpex.MetaExtension{
            EntityType: "tool",
            EntityName: "get_compensation",
            Tags:       []string{"pii"},
        },
    },
    nil, // context table (nil for first call)
)
defer ct.Close()
defer bg.Close()

if result.IsDenied() {
    fmt.Printf("Denied: %s\n", result.Violation.Reason)
}
```

## Lifecycle

```
NewPluginManagerDefault()
    → RegisterFactories(fn)     // register Rust plugin factories
    → LoadConfig(yaml)          // parse YAML, instantiate plugins
    → Initialize()              // call plugin.initialize() on all
    → InvokeByName(...)         // invoke hooks, get results
    → Shutdown()                // call plugin.shutdown(), free resources
```

## Payload Types

| Constant             | Value | Description                      |
|----------------------|-------|----------------------------------|
| `PayloadGeneric`     | 0     | Generic map payload (`map[string]any`) |
| `PayloadCMFMessage`  | 1     | Typed CMF `MessagePayload`       |

Use `PayloadGeneric` for simple key-value payloads. Use `PayloadCMFMessage` when sending structured CMF messages with typed content parts (tool calls, resources, media, etc.).

## CMF Content Types

The `ContentPart` tagged union supports all 12 content types:

| Type | Constructor | Content Field |
|------|-------------|---------------|
| `text` | `NewTextPart("hello")` | `Text` |
| `thinking` | `NewThinkingPart("...")` | `Text` |
| `tool_call` | `NewToolCallPart(tc)` | `ToolCallContent` |
| `tool_result` | `NewToolResultPart(tr)` | `ToolResultContent` |
| `resource` | `NewResourcePart(r)` | `ResourceContent` |
| `resource_ref` | `NewResourceRefPart(r)` | `ResourceRefContent` |
| `prompt_request` | `NewPromptRequestPart(pr)` | `PromptRequestContent` |
| `prompt_result` | `NewPromptResultPart(pr)` | `PromptResultContent` |
| `image` | `NewImagePart(img)` | `ImageContent` |
| `video` | `NewVideoPart(vid)` | `VideoContent` |
| `audio` | `NewAudioPart(aud)` | `AudioContent` |
| `document` | `NewDocumentPart(doc)` | `DocumentContent` |

## Extensions

Extensions are passed separately from the payload. Each extension type maps to a Rust extension in `crates/cpex-core/src/extensions/`:

- `MetaExtension` — entity identification for route resolution
- `SecurityExtension` — labels, classification, subject identity
- `HttpExtension` — request/response headers
- `DelegationExtension` — token delegation chain
- `AgentExtension` — agent session and conversation context
- `RequestExtension` — environment, tracing, request ID
- `MCPExtension` — MCP tool/resource/prompt metadata
- `CompletionExtension` — LLM completion stats
- `ProvenanceExtension` — message origin and threading
- `LLMExtension` — model identity and capabilities
- `FrameworkExtension` — agentic framework context

## Context Threading

Pass the `ContextTable` from one invocation to the next to preserve per-plugin state across hooks:

```go
result1, ct1, bg1, _ := mgr.InvokeByName("tool_pre_invoke", ...)
bg1.Close()

// Thread context table into post-invoke
result2, ct2, bg2, _ := mgr.InvokeByName("tool_post_invoke", ..., ct1)
bg2.Close()
ct2.Close()
```

## Writing Plugins (Rust) for Go Callers

Plugins are written in Rust and compiled into a separate FFI crate that the Go program links. This keeps the core `cpex-ffi` library clean while allowing each project to bring its own plugins.

### 1. Create a Rust FFI crate

```
my-project/
  plugins-ffi/
    Cargo.toml
    src/
      lib.rs
      my_plugin.rs
```

**`Cargo.toml`**:

```toml
[package]
name = "my-plugins-ffi"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["staticlib", "cdylib"]

[dependencies]
cpex-core = { path = "path/to/crates/cpex-core" }
cpex-ffi = { path = "path/to/crates/cpex-ffi" }
async-trait = "0.1"
tracing = "0.1"
```

### 2. Define your hook type and plugin

**`src/my_plugin.rs`**:

```rust
use std::sync::Arc;
use async_trait::async_trait;
use cpex_core::context::PluginContext;
use cpex_core::error::{PluginError, PluginViolation};
use cpex_core::factory::{PluginFactory, PluginInstance};
use cpex_core::hooks::adapter::TypedHandlerAdapter;
use cpex_core::hooks::payload::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, HookTypeDef, PluginResult};
use cpex_core::plugin::{Plugin, PluginConfig};
use cpex_ffi::GenericPayload;

// Hook type — the NAME can be any string; Go callers use this name
pub struct MyHook;
impl HookTypeDef for MyHook {
    type Payload = GenericPayload;
    type Result = PluginResult<GenericPayload>;
    const NAME: &'static str = "my_hook";
}

// Plugin implementation
struct RateLimiter {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for RateLimiter {
    fn config(&self) -> &PluginConfig { &self.cfg }
}

impl HookHandler<MyHook> for RateLimiter {
    fn handle(
        &self,
        payload: &GenericPayload,
        extensions: &Extensions,
        ctx: &mut PluginContext,
    ) -> PluginResult<GenericPayload> {
        // Your plugin logic here
        PluginResult::allow()
    }
}

// Factory — creates plugin instances from YAML config
pub struct RateLimiterFactory;
impl PluginFactory for RateLimiterFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, PluginError> {
        let plugin = Arc::new(RateLimiter { cfg: config.clone() });
        Ok(PluginInstance {
            plugin: plugin.clone(),
            handlers: vec![
                ("my_hook", Arc::new(
                    TypedHandlerAdapter::<MyHook, _>::new(plugin),
                )),
            ],
        })
    }
}

pub fn register_factories(manager: &mut cpex_core::manager::PluginManager) {
    manager.register_factory("my/rate-limiter", Box::new(RateLimiterFactory));
}
```

### 3. Export the C registration function

**`src/lib.rs`**:

```rust
mod my_plugin;

// Include cpex-ffi symbols in this staticlib
extern crate cpex_ffi;

use std::os::raw::c_int;

#[no_mangle]
pub unsafe extern "C" fn my_register_factories(
    mgr: *mut cpex_ffi::CpexManagerInner,
) -> c_int {
    let inner = match mgr.as_mut() {
        Some(m) => m,
        None => return -1,
    };
    my_plugin::register_factories(&mut inner.manager);
    0
}
```

### 4. Call from Go

```go
/*
#cgo LDFLAGS: -L/path/to/target/release -lmy_plugins_ffi -lm -ldl -lpthread
int my_register_factories(void* mgr);
*/
import "C"

mgr, _ := cpex.NewPluginManagerDefault()

mgr.RegisterFactories(func(handle unsafe.Pointer) error {
    if C.my_register_factories(handle) != 0 {
        return fmt.Errorf("factory registration failed")
    }
    return nil
})

mgr.LoadConfig(yaml)  // YAML references kind: "my/rate-limiter"
mgr.Initialize()

result, ct, bg, _ := mgr.InvokeByName("my_hook", cpex.PayloadGeneric, payload, ext, nil)
```

### Key points

- `extern crate cpex_ffi;` in your `lib.rs` ensures all core FFI symbols are included in your staticlib — Go links only your library
- The `CpexManagerInner` type from `cpex_ffi` gives you access to the `manager` field for factory registration
- Your C function signature is `int my_register_factories(void* mgr)` — Go passes the SDK's internal handle via the `RegisterFactories` callback
- The YAML `kind` field must match what you pass to `register_factory()`

## Adding a New Payload Type

The payload type registry maps a `uint8` discriminator to a Rust type for FFI deserialization. To add a new one:

### Rust side (3 files)

**1. Define the type** (in `cpex-core` or your own crate):

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MyPayload {
    pub field_a: String,
    pub field_b: i64,
}
cpex_core::impl_plugin_payload!(MyPayload);
```

**2. Register in FFI** (`crates/cpex-ffi/src/lib.rs`):

```rust
pub const PAYLOAD_MY_TYPE: u8 = 2;

// In deserialize_payload():
PAYLOAD_MY_TYPE => {
    let v: MyPayload = rmp_serde::from_slice(bytes)?;
    Ok(Box::new(v))
}

// In serialize_payload():
if let Some(mp) = payload.as_any().downcast_ref::<MyPayload>() {
    return rmp_serde::to_vec_named(mp).ok().map(|b| (PAYLOAD_MY_TYPE, b));
}
```

### Go side (1 file)

**3. Define the Go struct** (`go/cpex/types.go` or a new file):

```go
const PayloadMyType uint8 = 2

type MyPayload struct {
    FieldA string `msgpack:"field_a"`
    FieldB int64  `msgpack:"field_b"`
}
```

### Use it

```go
result, ct, bg, _ := mgr.InvokeByName("my_hook", cpex.PayloadMyType, payload, ext, nil)

// Deserialize modified payload from result
modified, _ := cpex.DeserializePayload[MyPayload](result)
```

**Total: 5 touch points** — Rust struct, FFI constant, deserialize arm, serialize arm, Go struct. No framework registration or config changes needed.

## Tests

```bash
# Build the Rust library first
cargo build --release -p cpex-ffi

# Run Go tests
cd go/cpex && go test -v ./...
```

## See Also

- [Go Demo Examples](../../examples/go-demo/README.md) — runnable demos with YAML configs
- [Rust Core README](../../crates/README.md) — core runtime documentation
- [Rust Examples](../../crates/cpex-core/examples/README.md) — native Rust examples
