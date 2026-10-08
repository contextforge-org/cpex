# CPEX Go SDK

Go bindings for the CPEX policy engine. Wraps the Rust engine via cgo: all plugin execution happens in Rust, called from Go through MessagePack-serialized payloads and opaque handles.

## Prerequisites

- **Go 1.25+**
- **Rust toolchain** (1.96+, pinned in `rust-toolchain.toml`)
- **Built Rust library**: the Go SDK links against `libcpex_ffi.a`

```bash
# From the repository root
cargo build --release -p cpex-ffi
```

## Package Structure

```
go/cpex/
  ffi.go          cgo declarations (C function signatures) and link flags
  abi.go          FFI ABI version check at package init
  engine.go       PolicyEngine, ContextTable, BackgroundTasks
  apl.go          EnableAPL: builtins, HTTP transport, secret providers
  secrets.go      RefreshSecrets, SecretsLastSuccess
  types.go        Extensions, PipelineResult, payload constants
  cmf.go          CMF Message, ContentPart, domain objects
  identity.go     IdentityPayload for identity.resolve
  *_test.go       tests (require built libcpex_ffi)
```

## Quick Start

```go
import cpex "github.com/contextforge-org/cpex/go/cpex"

// 1. Create an engine
engine, err := cpex.NewPolicyEngineDefault()
if err != nil { ... }
defer engine.Shutdown()

// 2. Install the CPEX builtins (identity/jwt, delegator/oauth, PDPs, Vault, ...).
//    Private and loopback destinations are blocked unless you opt in.
engine.EnableAPL(cpex.WithPrivateDestinations())

// 3. Optionally register your own Rust plugin factories (via callback)
engine.RegisterFactories(func(handle unsafe.Pointer) error {
    C.my_register_factories(handle)
    return nil
})

// 4. Load YAML config
engine.LoadConfig(yamlString)

// 5. Initialize plugins
engine.Initialize()

// 6. Invoke a hook
payload := cpex.MessagePayload{Message: cpex.NewMessage("assistant",
    cpex.NewToolCallPart(cpex.ToolCall{ToolCallID: "tc-1", Name: "get_compensation"}),
)}
result, ct, bg, err := engine.InvokeByName(
    "cmf.tool_pre_invoke",
    cpex.PayloadCMFMessage,
    payload,
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

Hook names follow the engine: `cmf.tool_pre_invoke`, `cmf.tool_post_invoke`, `cmf.prompt_pre_invoke`, `cmf.prompt_post_invoke`, `cmf.resource_pre_fetch`, `cmf.resource_post_fetch`, `identity.resolve`, `token.delegate`, and so on. The old unprefixed names (`tool_pre_invoke`, `identity_resolve`, ...) are rejected at config load.

## Lifecycle

```
NewPolicyEngineDefault()
    → EnableAPL(opts...)        // optional: builtins, transport, secret providers
    → RegisterFactories(fn)     // optional: your own Rust plugin factories
    → LoadConfig(yaml)          // parse YAML, instantiate plugins
    → Initialize()              // call plugin.initialize() on all, resolve secrets
    → InvokeByName(...)         // invoke hooks, get results
    → RefreshSecrets()          // optional, on a schedule: re-read secrets
    → Shutdown()                // call plugin.shutdown(), free resources
```

`NewPolicyEngine(yaml)` creates an engine and loads the config in one step. It registers no builtins, so it suits configs that only name plugins registered in Rust.

## Builtins and Egress

`EnableAPL` installs every bundled builtin, one outbound HTTP transport, and the `env`, `file` and `vault` secret providers. Plugins that reach the network (`jwks_url`, OAuth delegation, CIBA, Vault) must declare `capabilities: [perform_http]`.

The transport refuses private, loopback and link-local destinations by default. Pass `cpex.WithPrivateDestinations()` to allow them, for example for a local IdP. This is a host decision; no policy document can turn it on. `EnableAPL` is idempotent: a second call does nothing, whatever its options.

`WithPrivateDestinations` is engine-wide. It lets every outbound builtin (JWKS, token exchange, CIBA, Vault) reach loopback, RFC 1918, link-local addresses including cloud metadata (`169.254.169.254`), and CGNAT. Use it for local development and demos only. A blocked JWKS fetch shows up as `auth.jwks_unavailable`; a blocked token exchange as `delegation.egress_denied`.

`LoadConfig` returns a typed error without the engine's message. The message, naming the rejected key, hook or plugin, goes to the FFI's `tracing` log.

## Secrets

The engine resolves secrets once, at `Initialize`, and never re-reads them on its own:

```go
report, err := engine.RefreshSecrets()   // Updated, Unchanged, Failed
at, ok, err := engine.SecretsLastSuccess("vault")
if !ok {
    // the provider's last refresh failed, or it is not declared
}
```

A value that fails to re-read keeps its last-good bytes and is listed in `report.Failed`. A host that uses Vault, or rotates any secret, must call `RefreshSecrets` on an interval (for example from a `time.Ticker`) and alarm when `SecretsLastSuccess` for a provider falls too far behind. Nothing else re-reads secrets, so the interval bounds how long a revoked credential stays in use.

## ABI Check

On package init the binding compares its expected FFI ABI version (3) with the one `libcpex_ffi` reports and panics on a mismatch, naming both versions. Rebuild `libcpex_ffi` from the same CPEX release as the Go module.

## Payload Types

| Constant             | Value | Description                      |
|----------------------|-------|----------------------------------|
| `PayloadGeneric`     | 0     | Generic map payload (`map[string]any`) |
| `PayloadCMFMessage`  | 1     | Typed CMF `MessagePayload`       |
| `PayloadIdentity`    | 2     | `IdentityPayload` for `identity.resolve` |

Use `PayloadGeneric` for simple key-value payloads. Use `PayloadCMFMessage` when sending structured CMF messages with typed content parts (tool calls, resources, media, etc.). Use `PayloadIdentity` with `identity.resolve` (build it with `NewIdentityPayload`), and pass the route's `Meta` in the extensions: under the default `dispatch: policy`, the engine needs the entity to know which route's `authentication:` to run.

The generic HTTP hooks (`http.request`, `http.response`) are not invocable from Go in this release: the FFI has no payload type for the HTTP hook family. `HttpExtension` does carry the request line (`Method`, `Path`, `Host`, `Scheme`) and the response `Status`, so set `Method` and `Path` on the extensions of an `identity.resolve` call to select an `http:` route's own `authentication:` list.

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

Extensions are passed separately from the payload. Each extension type maps to a Rust extension in `praxis_policy_core::extensions`:

- `MetaExtension`: entity identification for route resolution
- `SecurityExtension`: labels, classification, data policies, and four identity slots: `Subject` (user), `Client` (OAuth client), `CallerWorkload` and `ThisWorkload` (`WorkloadIdentity`)
- `HttpExtension`: request line, request/response headers, response status
- `DelegationExtension`: token delegation chain
- `AgentExtension`: agent session and conversation context
- `RequestExtension`: environment, tracing, request ID
- `MCPExtension`: MCP tool/resource/prompt metadata
- `CompletionExtension`: LLM completion stats
- `ProvenanceExtension`: message origin and threading
- `LLMExtension`: model identity and capabilities
- `FrameworkExtension`: agentic framework context
- `CandidateConstraintExtension`: model, region and site constraints a plugin sets for a router

`SubjectExtension.Claims` and `ClientExtension.Claims` are `map[string]any`: a claim keeps its JSON shape (string, bool, number, array or nested map), so use a type switch or assertion to read one.

Some `[]string` fields tell nil apart from empty, matching a Rust `Option<Vec<_>>`: `DataPolicy.AllowedActions` and `CandidateConstraintExtension.AllowModels`, `AllowRegions` and `AllowSites`. A nil slice means unconstrained; an empty non-nil slice allows nothing.

There is no Go field for the Rust `raw_credentials` slot. Its tokens are never serialized, so use `InvokeResolved` to keep inbound credentials inside the engine.

## Context Threading

Pass the `ContextTable` from one invocation to the next to preserve per-plugin state across hooks:

```go
result1, ct1, bg1, _ := engine.InvokeByName("cmf.tool_pre_invoke", ...)
bg1.Close()

// Thread context table into post-invoke
result2, ct2, bg2, _ := engine.InvokeByName("cmf.tool_post_invoke", ..., ct1)
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
praxis-policy-core = "=0.4.1"
cpex-ffi = { path = "path/to/crates/cpex-ffi" }
async-trait = "0.1"
tracing = "0.1"
```

### 2. Define your hook type and plugin

**`src/my_plugin.rs`**:

```rust
use std::sync::Arc;
use async_trait::async_trait;
use praxis_policy_core::context::PluginContext;
use praxis_policy_core::error::{PluginError, PluginViolation};
use praxis_policy_core::factory::{PluginFactory, PluginInstance};
use praxis_policy_core::hooks::adapter::TypedHandlerAdapter;
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::hooks::trait_def::{HookHandler, HookTypeDef, PluginResult};
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::hooks::{register_hook_metadata, HookMetadata, HookPhase};
use praxis_policy_core::plugin::{Plugin, PluginConfig};
use cpex_ffi::GenericPayload;

// Hook type. NAME identifies the hook family; the hook name Go callers
// invoke is HOOK_MY, registered below.
pub struct MyHook;
impl HookTypeDef for MyHook {
    type Payload = GenericPayload;
    type Result = PluginResult<GenericPayload>;
    const NAME: &'static str = "my_hook";
}

pub const HOOK_MY: &str = "my.hook";

// Plugin implementation
struct RateLimiter {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for RateLimiter {
    fn config(&self) -> &PluginConfig { &self.cfg }
}

impl HookHandler<MyHook> for RateLimiter {
    async fn handle(
        &self,
        payload: &GenericPayload,
        extensions: &Extensions,
        ctx: &mut PluginContext,
    ) -> PluginResult<GenericPayload> {
        // Your plugin logic here
        PluginResult::allow()
    }
}

// Factory: creates plugin instances from YAML config
pub struct RateLimiterFactory;
impl PluginFactory for RateLimiterFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let plugin = Arc::new(RateLimiter { cfg: config.clone() });
        Ok(PluginInstance {
            plugin: plugin.clone(),
            handlers: vec![
                (HOOK_MY, Arc::new(
                    TypedHandlerAdapter::<MyHook, _>::new(plugin),
                )),
            ],
        })
    }
}

pub fn register_factories(engine: &PolicyEngine) {
    // The config loader refuses a hook name it has no metadata for, so
    // describe the host hook before any config naming it loads.
    register_hook_metadata(
        HOOK_MY,
        HookMetadata { family: Some(MyHook::NAME), entity_type: None, phase: HookPhase::Unphased },
    );
    engine.register_factory("my/rate-limiter", Box::new(RateLimiterFactory));
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
    handle: *mut cpex_ffi::CpexEngineInner,
) -> c_int {
    let inner = match handle.as_ref() {
        Some(h) => h,
        None => return -1,
    };
    my_plugin::register_factories(&inner.engine);
    0
}
```

### 4. Call from Go

```go
/*
#cgo LDFLAGS: -L/path/to/target/release -lmy_plugins_ffi -lm -ldl -lpthread
int my_register_factories(void* engine);
*/
import "C"

engine, _ := cpex.NewPolicyEngineDefault()

engine.RegisterFactories(func(handle unsafe.Pointer) error {
    if C.my_register_factories(handle) != 0 {
        return fmt.Errorf("factory registration failed")
    }
    return nil
})

engine.LoadConfig(yaml)  // YAML references kind: "my/rate-limiter"
engine.Initialize()

result, ct, bg, _ := engine.InvokeByName("my.hook", cpex.PayloadGeneric, payload, ext, nil)
```

### Key points

- `extern crate cpex_ffi;` in your `lib.rs` ensures all core FFI symbols are included in your staticlib, so Go links only your library
- The `CpexEngineInner` type from `cpex_ffi` gives you access to the `engine` field (an `Arc<PolicyEngine>`) for factory registration
- Your C function signature is `int my_register_factories(void* engine)`. Go passes the SDK's internal handle via the `RegisterFactories` callback
- The YAML `kind` field must match what you pass to `register_factory()`
- A config that declares `hooks:` and `priority:` on its plugins needs `engine_settings: {dispatch: hooks}`. Under the default `dispatch: policy`, call `EnableAPL` and name the plugin from a policy step such as `run(my-plugin)` instead

## Adding a New Payload Type

The payload type registry maps a `uint8` discriminator to a Rust type for FFI deserialization. To add a new one:

### Rust side (3 files)

**1. Define the type** (in your own crate):

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MyPayload {
    pub field_a: String,
    pub field_b: i64,
}
praxis_policy_core::impl_plugin_payload!(MyPayload);
```

**2. Register in FFI** (`crates/cpex-ffi/src/lib.rs`):

```rust
pub const PAYLOAD_MY_TYPE: u8 = 3;

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
const PayloadMyType uint8 = 3

type MyPayload struct {
    FieldA string `msgpack:"field_a"`
    FieldB int64  `msgpack:"field_b"`
}
```

### Use it

```go
result, ct, bg, _ := engine.InvokeByName("my.hook", cpex.PayloadMyType, payload, ext, nil)

// Deserialize modified payload from result
modified, _ := cpex.DeserializePayload[MyPayload](result)
```

**Total: 5 touch points**: Rust struct, FFI constant, deserialize arm, serialize arm, Go struct. No framework registration or config changes needed.

## Tests

```bash
# Build the Rust library first
cargo build --release -p cpex-ffi

# Run Go tests (add -race for the race detector)
cd go/cpex && go test -v ./...
```

## See Also

- [Go Demo Examples](../../examples/go-demo/README.md): runnable demos with YAML configs
- [Rust crates README](../../crates/README.md): the facade and the crates CPEX adds to the engine
- [Migrating to 0.3](https://contextforge-org.github.io/cpex/docs/migration-0.3/): the Go, C ABI, hook and config changes from 0.2.x
- [Tutorial](../../examples/tutorial/README.md): policy examples, builtins and custom plugins
