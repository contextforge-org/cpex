# CPEX Rust — Public API Specification

**Status**: Draft
**Date**: May 2026
**Source**: `crates/cpex-core` in `github.com/contextforge-org/contextforge-plugins-framework`

CPEX Rust is the core plugin runtime — pure Rust, no FFI/WASM/PyO3 dependencies. It serves two audiences:

- **Embedders** — Rust hosts that want an in-process plugin pipeline (configure → load → invoke).
- **Plugin authors** — code that runs *inside* the runtime as native Rust plugins (define hooks, write `HookHandler` impls).

The Go SDK (`go/cpex`, see [cpex-go-spec.md](./cpex-go-spec.md)) is one consumer of cpex-core via cpex-ffi. Other language bindings layer the same way. This spec documents the Rust API directly, with a focus on plugin authoring (§6, §11).

## 1. Architecture

```
┌──────────────────────────────────────────────────────┐
│  Rust Host                                           │
│                                                      │
│   PluginManager  ───────────────────────────────┐    │
│   │  PluginManager::new(ManagerConfig)          │    │
│   │  PluginManager::from_config(path, factories)│    │
│   │  register_handler::<H, P>(plugin, config)   │    │
│   │  initialize().await                         │    │
│   │  invoke::<H>(payload, ext, ct).await        │    │
│   │  invoke_named::<H>(name, payload, ext, ct)  │    │
│   │  has_hooks_for(name) / plugin_count()       │    │
│   │  shutdown().await                           │    │
│   └─────────────────────────────────────────────┘    │
│                        │                             │
├────────────────────────┼─────────────────────────────┤
│  Executor              ▼                             │
│   ┌─────────────────────────────────────────────┐    │
│   │  5-Phase Pipeline                           │    │
│   │  1. Sequential   — block + modify           │    │
│   │  2. Transform    — modify only              │    │
│   │  3. Audit        — read-only, serial        │    │
│   │  4. Concurrent   — block-only, parallel     │    │
│   │  5. FireAndForget — background tasks        │    │
│   └─────────────────────────────────────────────┘    │
│                        │                             │
├────────────────────────┼─────────────────────────────┤
│  Plugins               ▼                             │
│   impl Plugin + impl HookHandler<H>                  │
│   • Capability-gated extension reads/writes          │
│   • Async lifecycle, sync handle()                   │
└──────────────────────────────────────────────────────┘
```

**Key design decisions:**

- **Typed dispatch is the default.** The recommended API is `invoke::<H>(payload, ...)`, where `H: HookTypeDef` carries the payload type at compile time. The compiler enforces payload/hook compatibility — there's no `Box<dyn PluginPayload>` in user code on the happy path.
- **Hook types are open** — hosts define their own via the `HookTypeDef` trait or the `define_hook!` macro. cpex-core ships built-ins (`tool_pre_invoke`, CMF hooks) but does not require them.
- **Capabilities at config** — extension visibility and write authority are declared in YAML (or programmatically on `PluginConfig`). The executor enforces them by handing out `WriteToken`s only for declared capabilities.
- **Async-by-default handler.** Both plugin lifecycle (`initialize`, `shutdown`) and the per-invocation `handle(...)` are `async`. Handlers that don't need to await anything compile to a trivially-ready future that LLVM inlines, so there is no cost over a plain function call. Handlers that do need to await just `.await` inside the body. See §6.2 for the cost breakdown and the guidance on when to put `.await` in `handle`.

## 2. Crate Layout & Dependencies

```toml
[dependencies]
cpex-core = { git = "https://github.com/contextforge-org/contextforge-plugins-framework", branch = "main" }
async-trait = "0.1"
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

**Module overview** (everything is `pub` unless marked):

| Module | Purpose |
|---|---|
| `cpex_core::plugin` | `Plugin` trait, `PluginConfig`, `PluginMode`, `OnError`, `PluginCondition`, `MatchContext` |
| `cpex_core::hooks` | `HookTypeDef`, `HookHandler<H>`, `PluginPayload`, `PluginResult<P>`, `define_hook!` |
| `cpex_core::factory` | `PluginFactory`, `PluginInstance`, `PluginFactoryRegistry` |
| `cpex_core::manager` | `PluginManager`, `ManagerConfig` |
| `cpex_core::executor` | `PipelineResult`, `BackgroundTasks` |
| `cpex_core::registry` | `HookEntry`, `PluginRef`, `group_by_mode` (rarely used directly) |
| `cpex_core::config` | `CpexConfig`, `load_config`, `parse_config` |
| `cpex_core::extensions` | `Extensions`, `OwnedExtensions`, all extension types, `WriteToken`, `Guarded`, `MonotonicSet` |
| `cpex_core::error` | `PluginError`, `PluginViolation`, `PluginErrorRecord` |
| `cpex_core::cmf` | CMF `MessagePayload`, `Message`, `ContentPart` |
| `cpex_core::context` | `PluginContext`, `PluginContextTable` |

There are no feature flags currently — everything is built unconditionally. cpex-ffi (the C ABI surface) lives in a separate crate and is not part of this spec.

## 3. Lifecycle

```
ManagerConfig::default() → PluginManager::new()
        │
        ▼
register_factory(kind, factory)         ← optional, for kind-driven loading
        │
        ▼
load_config(yaml) | register_handler::<H, P>(...)   ← either YAML or programmatic
        │
        ▼
initialize().await                       ← calls Plugin::initialize() on each
        │
        ▼
invoke::<H>(payload, ext, ct).await      ← repeatable; can be concurrent (preferred typed path)
        │
        ▼
shutdown().await                         ← calls Plugin::shutdown() on each
```

## 4. Quick Reference

| Operation | Method |
|---|---|
| Create manager | `PluginManager::new(ManagerConfig::default())` |
| Register factory | `mgr.register_factory(kind, Box::new(MyFactory))` |
| Load YAML config | `mgr.load_config(cpex_config)` or `mgr.load_config_file(path)` |
| Build from config | `PluginManager::from_config(path, &factories)` |
| Programmatic register | `mgr.register_handler::<H, P>(plugin, config)` |
| Multiple hook names | `mgr.register_handler_for_names::<H, P>(plugin, config, &names)` |
| Initialize | `mgr.initialize().await` |
| Query lifecycle | `mgr.is_initialized()` |
| Check hooks exist | `mgr.has_hooks_for(name)` |
| Count plugins | `mgr.plugin_count()` |
| List plugins | `mgr.plugin_names()` |
| Get plugin | `mgr.get_plugin(name)` → `Option<Arc<PluginRef>>` |
| **Invoke (typed, primary)** | **`mgr.invoke::<H>(payload, ext, ct).await`** |
| Invoke (typed + runtime name) | `mgr.invoke_named::<H>(name, payload, ext, ct).await` |
| Invoke (untyped fallback) | `mgr.invoke_by_name(name, payload, ext, ct).await` |
| Define hook type | `define_hook!{ ToolPreInvoke; "tool_pre_invoke" => Payload(P) -> Result(R); }` |
| Define payload | `impl_plugin_payload!(MyPayload)` |
| Handler | `impl HookHandler<H> for MyPlugin { async fn handle(...) -> H::Result { ... } }` |
| Allow result | `PluginResult::allow()` |
| Deny result | `PluginResult::deny(violation)` |
| Modify payload | `PluginResult::modify_payload(p)` |
| Modify extensions | `PluginResult::modify_extensions(owned)` |
| Wait background | `bg.wait().await` |
| Shutdown | `mgr.shutdown().await` |
| Unregister | `mgr.unregister(name)` |

## 5. Core Types

### 5.1 PluginManager

The top-level object. Owns the plugin registry, factory registry, hook adapter table, and executor.

```rust
pub struct PluginManager { /* private — uses ArcSwap<RuntimeSnapshot> */ }

impl PluginManager {
    // Construction
    pub fn new(config: ManagerConfig) -> Self;
    pub fn default() -> Self;  // ManagerConfig::default()
    pub fn from_config(
        path: &Path,
        factories: &PluginFactoryRegistry,
    ) -> Result<Self, Box<PluginError>>;

    // Factory registration
    pub fn register_factory(
        &self,
        kind: impl Into<String>,
        factory: Box<dyn PluginFactory>,
    );

    // YAML loading
    pub fn load_config_file(&self, path: &Path) -> Result<(), Box<PluginError>>;
    pub fn load_config(&self, cpex: CpexConfig) -> Result<(), Box<PluginError>>;

    // Programmatic plugin registration (preferred for native plugins)
    pub fn register_handler<H, P>(
        &self,
        plugin: Arc<P>,
        config: PluginConfig,
    ) -> Result<(), Box<PluginError>>
    where
        H: HookTypeDef,
        H::Result: Into<PluginResult<H::Payload>>,
        P: Plugin + HookHandler<H> + 'static;

    pub fn register_handler_for_names<H, P>(
        &self,
        plugin: Arc<P>,
        config: PluginConfig,
        names: &[&str],
    ) -> Result<(), Box<PluginError>>
    where
        H: HookTypeDef,
        H::Result: Into<PluginResult<H::Payload>>,
        P: Plugin + HookHandler<H> + 'static;

    pub fn register_raw<H: HookTypeDef>(
        &self,
        plugin: Arc<dyn Plugin>,
        config: PluginConfig,
        handler: Arc<dyn AnyHookHandler>,
    ) -> Result<(), Box<PluginError>>;

    // Lifecycle
    pub async fn initialize(&self) -> Result<(), Box<PluginError>>;
    pub async fn shutdown(&self);
    pub fn is_initialized(&self) -> bool;

    // Query
    pub fn has_hooks_for(&self, name: &str) -> bool;
    pub fn plugin_count(&self) -> usize;
    pub fn plugin_names(&self) -> Vec<String>;
    pub fn get_plugin(&self, name: &str) -> Option<Arc<PluginRef>>;
    pub fn unregister(&self, name: &str) -> Option<Arc<PluginRef>>;

    // Invocation — see §5.2 for the three flavors and when to use each
    pub async fn invoke<H: HookTypeDef>(
        &self,
        payload: H::Payload,
        extensions: Extensions,
        context_table: Option<PluginContextTable>,
    ) -> (PipelineResult, BackgroundTasks);

    pub async fn invoke_named<H: HookTypeDef>(
        &self,
        hook_name: &str,
        payload: H::Payload,
        extensions: Extensions,
        context_table: Option<PluginContextTable>,
    ) -> (PipelineResult, BackgroundTasks);

    pub async fn invoke_by_name(
        &self,
        hook_name: &str,
        payload: Box<dyn PluginPayload>,
        extensions: Extensions,
        context_table: Option<PluginContextTable>,
    ) -> (PipelineResult, BackgroundTasks);
}
```

**Notes:**

- `register_handler` is the **programmatic** registration path — you supply the `Arc<P>` directly. It does not require a `PluginFactory`. Use this for plugins compiled into the same binary as the host.
- `from_config` is the **config-driven** path — it reads YAML, looks up each plugin's `kind` in the factory registry, and calls `factory.create(config)` to instantiate. Use this for plugins selected by config.
- Both paths can coexist: register infrastructure plugins programmatically, then `load_config` to add the YAML-driven ones.
- Invoke methods take `&self` and are `async` — multiple concurrent invokes are supported. The internal registry uses `ArcSwap` for lock-free reads.

### 5.2 Choosing an Invoke Method

Three flavors exist. **Default to `invoke::<H>`.** The other two are for specific scenarios.

```rust
// Primary: typed payload, hook name from H::NAME
let (result, bg) = mgr.invoke::<ToolPreInvoke>(payload, ext, ct).await;

// CMF pattern: typed payload, runtime hook name
let (result, bg) = mgr.invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, ext, ct).await;

// Last resort: type-erased payload (FFI/bridge code that already holds Box<dyn PluginPayload>)
let (result, bg) = mgr.invoke_by_name("tool_pre_invoke", boxed_payload, ext, ct).await;
```

| Method | Payload type | Hook name source | When to use |
|---|---|---|---|
| `invoke::<H>` | `H::Payload` (compile-time checked) | `H::NAME` constant | **Default for Rust callers.** Compiler verifies payload type matches the hook. One hook → one type. |
| `invoke_named::<H>` | `H::Payload` (compile-time checked) | `&str` arg | One hook *type* covers multiple hook *names*. Used by the CMF pattern: `CmfHook` carries `MessagePayload` and is registered under `cmf.tool_pre_invoke`, `cmf.llm_input`, etc. |
| `invoke_by_name` | `Box<dyn PluginPayload>` (type-erased) | `&str` arg | Bridge / FFI code that has already type-erased the payload (e.g., cpex-ffi after MessagePack deserialization). Avoid in user code. |

All three return `(PipelineResult, BackgroundTasks)` directly — no `Result`. The pipeline itself can fail (a plugin denied, a plugin errored with `on_error: fail`), but those are surfaced through `PipelineResult.violation`, `PipelineResult.errors`, and the `continue_processing` flag — see §13.

If the hook name has no registered handlers, all three short-circuit to `PipelineResult::allowed_with(payload, extensions, ct)` and return immediately — zero overhead beyond a registry lookup.

### 5.3 ManagerConfig

```rust
pub struct ManagerConfig {
    pub default_timeout: Duration,
    pub default_on_error: OnError,
    pub max_route_cache_size: usize,
    /* additional fields — see manager.rs */
}

impl Default for ManagerConfig { /* sensible defaults */ }
```

`ManagerConfig::default()` is fine for most hosts. Override `max_route_cache_size` if you have an exceptionally large set of `routes:` in YAML; override `default_timeout` for tighter SLAs.

### 5.4 PluginConfig

The declarative shape that drives plugin loading and runtime behavior. One entry per `plugins:` item in the YAML.

```rust
pub struct PluginConfig {
    pub name: String,                  // unique identifier
    pub kind: String,                  // factory key (e.g., "builtin/identity")
    pub description: Option<String>,
    pub author: Option<String>,
    pub version: Option<String>,
    pub hooks: Vec<String>,            // hook names this plugin handles
    pub mode: PluginMode,              // sequential / transform / audit / concurrent / fire_and_forget / disabled
    pub priority: i32,                 // lower = earlier within phase (default 100)
    pub on_error: OnError,             // fail / ignore / disable
    pub capabilities: HashSet<String>, // extension read/write gates
    pub tags: Vec<String>,
    pub conditions: Vec<PluginCondition>, // legacy scope filtering (ignored when routing_enabled)
    pub config: Option<serde_json::Value>, // plugin-specific settings (opaque to framework)
}
```

`config: Option<serde_json::Value>` is where plugin-specific knobs live. The framework hands the JSON value to the plugin's factory; the factory deserializes it into a typed config struct.

### 5.5 PluginMode

```rust
#[non_exhaustive]
pub enum PluginMode {
    Sequential,    // serial, can block + modify
    Transform,     // serial, can modify (cannot block)
    Audit,         // serial, read-only
    Concurrent,    // parallel, can block (cannot modify)
    FireAndForget, // background, cannot block or modify
    Disabled,      // skipped
}

impl PluginMode {
    pub fn can_block(&self) -> bool;     // Sequential | Concurrent
    pub fn can_modify(&self) -> bool;    // Sequential | Transform
    pub fn is_awaited(&self) -> bool;    // not FireAndForget or Disabled
}
```

Modes determine *both* the phase the plugin runs in *and* the authority it has. The executor enforces this:

| Mode | Phase | Receives | Can Block? | Can Modify? |
|---|---|---|---|---|
| `Sequential` | 1 | owned (clone) | Yes | Yes |
| `Transform` | 2 | owned (clone) | No | Yes |
| `Audit` | 3 | `&Payload` | No | No |
| `Concurrent` | 4 | `&Payload` | Yes | No |
| `FireAndForget` | 5 | `&Payload` | No | No |
| `Disabled` | — | not invoked | — | — |

### 5.6 OnError

```rust
#[non_exhaustive]
pub enum OnError {
    Fail,    // halt pipeline (default)
    Ignore,  // log + record in PipelineResult.errors, continue
    Disable, // log + record + auto-disable for the rest of process lifetime
}
```

`Ignore` and `Disable` failures land in `PipelineResult.errors` (a `Vec<PluginErrorRecord>`); `Fail` failures halt the pipeline and surface via `PipelineResult.continue_processing == false` plus a populated `violation`.

### 5.7 PipelineResult

```rust
pub struct PipelineResult {
    pub continue_processing: bool,
    pub violation: Option<PluginViolation>,
    pub modified_payload: Option<Box<dyn PluginPayload>>,
    pub modified_extensions: Option<OwnedExtensions>,
    pub metadata: HashMap<String, serde_json::Value>,
    pub errors: Vec<PluginErrorRecord>,
    pub context_table: PluginContextTable,
}

impl PipelineResult {
    pub fn is_denied(&self) -> bool;
    pub fn allow() -> Self;
    pub fn with_errors(self, errors: Vec<PluginErrorRecord>) -> Self;
}
```

The aggregate output of running all phases for one invoke:

- `continue_processing` — `false` if any sequential plugin denied. The host should halt downstream work.
- `violation` — populated when a plugin denied; carries the structured reason.
- `modified_payload` — present only if at least one Sequential or Transform plugin produced a modification. Type-erased here for the same reason `invoke_by_name` exists: the executor drops below the type-parameter level. Downcast via `as_any()`, or use the typed-result helper in §5.8.
- `modified_extensions` — present only if at least one capability-holding plugin called `modify_extensions(...)`.
- `errors` — soft errors from `Ignore`/`Disable` plugins. Read these to surface non-fatal failures to logs/dashboards.
- `metadata` — free-form aggregation key-value across plugins. Useful for `_decision_plugin`-style markers.
- `context_table` — per-plugin state to thread into the next invoke.

### 5.8 PluginResult&lt;P&gt;

The **per-handler** result type, distinct from the per-invoke `PipelineResult`. Each `HookHandler<H>::handle(...)` returns one of these.

```rust
pub struct PluginResult<P: PluginPayload> {
    pub continue_processing: bool,
    pub violation: Option<PluginViolation>,
    pub modified_payload: Option<P>,
    pub modified_extensions: Option<OwnedExtensions>,
    pub metadata: HashMap<String, serde_json::Value>,
}

impl<P: PluginPayload> PluginResult<P> {
    pub fn allow() -> Self;
    pub fn deny(violation: PluginViolation) -> Self;
    pub fn modify_payload(payload: P) -> Self;
    pub fn modify_extensions(extensions: OwnedExtensions) -> Self;
    pub fn modify(payload: P, extensions: OwnedExtensions) -> Self;
    pub fn has_modifications(&self) -> bool;
}
```

Plugin authors use the four constructors; manual struct construction is rare. The executor merges per-plugin `PluginResult<P>`s into the final `PipelineResult`.

To read a typed modified payload back from a `PipelineResult`:

```rust
if let Some(boxed) = result.modified_payload.as_ref() {
    if let Some(typed) = boxed.as_any().downcast_ref::<ToolInvokePayload>() {
        // typed: &ToolInvokePayload
    }
}
```

If you stayed on the typed `invoke::<H>` path, the `H::Payload` you sent in is the type to downcast to — no surprises.

### 5.9 PluginError

The framework's error type. All public functions return `Result<T, Box<PluginError>>`.

```rust
#[derive(Debug, Error)]
pub enum PluginError {
    Execution {
        plugin_name: String,
        message: String,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
        code: Option<String>,
        details: HashMap<String, serde_json::Value>,
        proto_error_code: Option<i64>,
    },
    Timeout { plugin_name: String, timeout_ms: u64, proto_error_code: Option<i64> },
    Violation { plugin_name: String, violation: PluginViolation },
    Config { message: String },
    UnknownHook { hook_type: String },
}

impl PluginError {
    pub fn boxed(self) -> Box<Self>;  // sugar for Box::new(self)
}
```

**Why boxed:** the enum is ~184 bytes (large `details` HashMap, `source` trait object). `Result<T, Box<PluginError>>` keeps the success path pointer-sized; the allocation only happens on the error path. This is the standard Rust pattern for rich error types and is enforced by `clippy::result_large_err`.

Construction is ergonomic:

```rust
return Err(PluginError::Config {
    message: "missing policy_file".into(),
}.boxed());

// `?` works automatically — From<T> for Box<T> is in std:
let cfg: MyConfig = serde_json::from_value(raw)?;  // serde error ↗ Box<PluginError>
```

### 5.10 PluginViolation

Structured denial. Returned by plugins that want to halt the pipeline with a reason.

```rust
pub struct PluginViolation {
    pub code: String,                        // machine-readable identifier
    pub reason: String,                      // short human-readable explanation
    pub description: Option<String>,         // longer detail
    pub details: HashMap<String, Value>,     // structured diagnostic data
    pub plugin_name: Option<String>,         // set by framework after return
    pub proto_error_code: Option<i64>,       // wire-protocol error code
}

impl PluginViolation {
    pub fn new(code: impl Into<String>, reason: impl Into<String>) -> Self;
    pub fn with_description(self, description: impl Into<String>) -> Self;
    pub fn with_details(self, details: HashMap<String, Value>) -> Self;
    pub fn with_proto_error_code(self, code: i64) -> Self;
}
```

### 5.11 PluginErrorRecord

`Clone`-able snapshot of a `PluginError`. Lives in `PipelineResult.errors`. `PluginError` itself can't be `Clone` (the `source: Box<dyn Error>` is not cloneable) and errors crossing the FFI boundary need `Serialize`/`Deserialize`.

```rust
#[derive(Clone, Serialize, Deserialize)]
pub struct PluginErrorRecord {
    pub plugin_name: String,
    pub message: String,
    pub code: Option<String>,
    pub details: HashMap<String, Value>,
    pub proto_error_code: Option<i64>,
}

impl From<&PluginError> for PluginErrorRecord { /* ... */ }
impl From<&Box<PluginError>> for PluginErrorRecord { /* forwarder */ }
```

The `From<&Box<PluginError>>` forwarder exists so call sites that hold `e: Box<PluginError>` can write `(&e).into()` without a manual deref.

## 6. Plugin Authoring

This is the heart of the API for plugin authors. The full minimal plugin is:

1. Define a payload type and `impl_plugin_payload!` it.
2. Define a hook type implementing `HookTypeDef`.
3. Implement `Plugin` for the plugin struct.
4. Implement `HookHandler<H>` for each hook the plugin handles.
5. Register the plugin (via `register_handler` or a `PluginFactory`).

§11 walks through this end-to-end. This section explains each piece.

### 6.1 The `Plugin` Trait

Every plugin implements `Plugin`. It carries the plugin's config and the lifecycle hooks.

```rust
#[async_trait]
pub trait Plugin: Send + Sync {
    /// The plugin's configuration. Read-only — the framework holds
    /// the authoritative copy in `PluginRef.trusted_config`.
    fn config(&self) -> &PluginConfig;

    /// One-time initialization. Called before any invokes.
    /// Use to open connections, load resources, validate config.
    async fn initialize(&self) -> Result<(), Box<PluginError>> {
        Ok(())
    }

    /// Graceful shutdown. Called once during teardown.
    async fn shutdown(&self) -> Result<(), Box<PluginError>> {
        Ok(())
    }
}
```

Default implementations for `initialize`/`shutdown` are no-ops; override only if your plugin needs them.

### 6.2 The `HookHandler<H>` Trait

Each hook the plugin handles requires a separate `HookHandler<H>` impl. The type parameter `H` is the hook type (a marker struct implementing `HookTypeDef`).

```rust
pub trait HookHandler<H: HookTypeDef>: Plugin + Send + Sync {
    fn handle(
        &self,
        payload: &H::Payload,
        extensions: &Extensions,
        ctx: &mut PluginContext,
    ) -> impl std::future::Future<Output = H::Result> + Send;
}
```

The `fn ... -> impl Future` shape is **native AFIT** (Associated Fn In Trait, stable since Rust 1.75). Plugin authors write the impl with the more familiar `async fn` form — it desugars to the same thing:

```rust
impl HookHandler<MyHook> for AllowPlugin {
    async fn handle(
        &self,
        _payload: &MyPayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MyPayload> {
        PluginResult::allow()
    }
}

impl HookHandler<MyHook> for AuthzPlugin {
    async fn handle(
        &self,
        payload: &MyPayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MyPayload> {
        match self.client.check(&payload.user).await {
            Ok(true) => PluginResult::allow(),
            _ => PluginResult::deny(/* ... */),
        }
    }
}
```

**Borrow semantics:**

- `payload: &H::Payload` — always a borrow. The executor's mode-aware adapter passes either a clone (Sequential/Transform) or a true reference (Audit/Concurrent/FireAndForget). The plugin sees `&` either way; if it needs to mutate, it `clone()`s and returns `PluginResult::modify_payload(modified)`.
- `extensions: &Extensions` — capability-filtered view. Slots the plugin lacks read capabilities for appear as `None`.
- `ctx: &mut PluginContext` — per-plugin state. Read/write the local state map; stage updates to global state via `ctx.set_global(...)`.

**Async by design.** `handle` is `async fn`. Plugins that don't need to await anything still write `async fn handle(...)` and return synchronously — the compiler emits a trivially-ready future and LLVM inlines it at the adapter site, so there is no observable runtime cost over a plain function call. Plugins that *do* need to await (fresh JWKS fetch, RPC to authz, dynamic policy lookup) just use `.await` inside the body.

**Registration is the same for both.** A single `register_handler::<H, _>` call accepts a plugin whose `handle` body is purely sync as well as one that genuinely awaits — the trait doesn't distinguish.

```rust
manager.register_handler::<MyHook, _>(plugin, config)?;
```

**Cost:**

- Plugins with no `.await` in `handle` compile to a `Ready<H::Result>` future that the executor awaits; LLVM typically inlines this to a direct call. No heap allocation, no scheduler interaction.
- Plugins that actually await pay normal async cost (one boxed future at the type-erased `AnyHookHandler` boundary, plus whatever the awaited work costs). Native AFIT is what avoids per-call boxing at the typed layer — `#[async_trait]` would have boxed every call.

**When to put `.await` in `handle`:** prefer caching at init time and reading from cache on the hot path — that is the most common source of latency regressions in plugins. Only put `.await` in `handle` when caching genuinely won't work (e.g., per-request decisions against authoritative state).

### 6.3 The `PluginPayload` Trait

The base trait for all hook payloads. Object-safe — the framework dispatches via `Box<dyn PluginPayload>` internally, but plugin code rarely sees that directly when using `invoke::<H>`.

```rust
pub trait PluginPayload: Send + Sync + 'static {
    fn clone_boxed(&self) -> Box<dyn PluginPayload>;
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}
```

Implement it via the macro:

```rust
use cpex_core::impl_plugin_payload;

#[derive(Debug, Clone)]
struct ToolInvokePayload {
    tool_name: String,
    user: String,
    arguments: serde_json::Value,
}
impl_plugin_payload!(ToolInvokePayload);
```

The macro expands to the three method impls — saves boilerplate per type. Requirements: the type must be `Clone + Send + Sync + 'static`. No `Serialize` is required by `PluginPayload` itself, but payloads that cross the FFI boundary (and so are deserializable from MessagePack) typically derive `serde::Serialize + Deserialize` too.

### 6.4 Defining a Hook Type

A hook type is a zero-sized marker struct that implements `HookTypeDef`. It associates a name (for registry lookup) with a typed payload and result.

```rust
use cpex_core::hooks::trait_def::{HookTypeDef, PluginResult};

struct ToolPreInvoke;
impl HookTypeDef for ToolPreInvoke {
    type Payload = ToolInvokePayload;
    type Result = PluginResult<ToolInvokePayload>;
    const NAME: &'static str = "tool_pre_invoke";
}
```

**Conventions:**

- `type Result = PluginResult<Self::Payload>` — the standard shape. Custom result types are possible (the trait doesn't require `PluginResult`) but the executor wires `H::Result: Into<PluginResult<H::Payload>>` so anything you return must convert into one.
- `NAME` is the lookup key for `register_handler::<ToolPreInvoke, _>(...)` and the `hooks: [tool_pre_invoke]` line in YAML. It's also what `invoke::<ToolPreInvoke>` uses for dispatch — so calling `invoke::<H>` is exactly equivalent to `invoke_by_name(H::NAME, ...)` with the type advantages.
- One marker can be shared across multiple hook *names* if your plugin handles a family. See the CMF pattern in §6.6.

#### `define_hook!` macro (sugar)

For the common case, a macro generates the marker struct, the trait impl, and a `HookHandler<Self>` shorthand in one declaration:

```rust
use cpex_core::define_hook;

define_hook! {
    /// Hook for tool_pre_invoke.
    ToolPreInvoke;
    "tool_pre_invoke" => Payload(ToolInvokePayload) -> Result(PluginResult<ToolInvokePayload>);
}
```

Either form is fine — manual when you want fine control over docs/derives, the macro for less typing.

### 6.5 PluginResult Constructors

The four canonical outcomes a plugin signals:

| Constructor | What it signals |
|---|---|
| `PluginResult::allow()` | Pass. No changes. |
| `PluginResult::deny(violation)` | Halt the pipeline. Caller sees `result.is_denied() == true`. |
| `PluginResult::modify_payload(p)` | Pass. Replace the payload in flight (Sequential/Transform only). |
| `PluginResult::modify_extensions(owned)` | Pass. Apply extension changes (capability-gated). |
| `PluginResult::modify(p, owned)` | Pass. Both payload and extension changes. |

Audit / Concurrent / FireAndForget plugins should only use `allow()` and `deny()` — `modify_*` calls in those modes are dropped by the executor (the plugin lacks the authority).

### 6.6 Multiple Hooks per Plugin

A single plugin can implement `HookHandler<H>` for several hook types. Each `impl HookHandler<H>` block is independent — they can share `&self` state but don't have to.

```rust
impl HookHandler<ToolPreInvoke> for IdentityResolver {
    async fn handle(&self, p: &ToolInvokePayload, e: &Extensions, c: &mut PluginContext)
        -> PluginResult<ToolInvokePayload>
    { /* ... */ }
}

impl HookHandler<ToolPostInvoke> for IdentityResolver {
    async fn handle(&self, p: &ToolInvokePayload, e: &Extensions, c: &mut PluginContext)
        -> PluginResult<ToolInvokePayload>
    { /* ... */ }
}
```

Register each separately:

```rust
manager.register_handler::<ToolPreInvoke, _>(
    Arc::clone(&plugin), config_for("tool_pre_invoke"))?;
manager.register_handler::<ToolPostInvoke, _>(
    plugin, config_for("tool_post_invoke"))?;
```

For the **CMF pattern** — one handler covers many CMF hook *names* (`cmf.tool_pre_invoke`, `cmf.llm_input`, `cmf.llm_output`, etc.) all carrying the same `MessagePayload` — define a single `CmfHook` marker and register it under multiple names:

```rust
manager.register_handler_for_names::<CmfHook, _>(
    plugin,
    config,
    &[
        "cmf.tool_pre_invoke",
        "cmf.tool_post_invoke",
        "cmf.llm_input",
        "cmf.llm_output",
    ],
)?;
```

This is the case where `invoke_named::<CmfHook>("cmf.tool_pre_invoke", ...)` matters — the type pins the payload to `MessagePayload`, but the runtime hook name selects which set of plugins to fire.

### 6.7 Capability-Gated Extension Writes

Extensions visible to a plugin are filtered by its declared `capabilities`. The framework uses copy-on-write tokens for writes — the plugin clones the extensions, gets a `WriteToken` for slots it has capabilities for, and returns the modified copy.

```rust
use cpex_core::hooks::payload::Extensions;

async fn handle(
    &self,
    payload: &MessagePayload,
    extensions: &Extensions,
    _ctx: &mut PluginContext,
) -> PluginResult<MessagePayload> {
    let mut owned = extensions.cow_copy();

    // http_write_token is Some(...) iff the plugin declared `write_headers`
    if let Some(ref token) = owned.http_write_token {
        if let Some(http) = owned.http.as_mut() {
            let h = http.write(token);
            h.set_response_header("X-Tool-Name", &payload.message.role);
            h.set_response_header("X-CPEX-Processed", "true");
        }
    }

    PluginResult::modify_extensions(owned)
}
```

A plugin without the capability sees `owned.http_write_token == None` and silently can't write — no runtime panic, no security violation. The token *is* the type-system enforcement of the YAML capability.

**Common capabilities** (see `cpex_core::extensions` for the full list):

| Capability | Grants |
|---|---|
| `read_subject` | `SecurityExtension.subject` (read) |
| `read_labels` | `SecurityExtension.labels` (read) |
| `read_headers` | `HttpExtension.request_headers` (read) |
| `write_headers` | `HttpExtension.response_headers` (read + write token) |
| `read_classification` | `SecurityExtension.classification` (read) |
| `write_labels` | `SecurityExtension.labels` (read + monotonic write — append-only) |
| `read_data` / `write_data` | `SecurityExtension.data` |
| `read_objects` | `SecurityExtension.objects` |

`MonotonicSet`-typed fields (like `labels`) only allow append, never removal — the executor enforces this on the post-handle merge.

### 6.8 Choosing on_error

`on_error` is set per-plugin in YAML or `PluginConfig`. Choose based on what failure means for the request:

- **`fail`** — security/policy plugins. Can't enforce → halt the request.
- **`ignore`** — observability plugins (audit, metrics). Failure is annoying but non-fatal.
- **`disable`** — non-essential plugins with potential to fail repeatedly (e.g., a stale external dependency). The framework auto-disables the plugin after one failure to stop log spam.

`Ignore` and `Disable` failures are recorded in `PipelineResult.errors` — they are not silent.

## 7. Factories & Registration

Two registration paths:

| Path | When to use |
|---|---|
| `register_handler::<H, P>` | You construct the plugin in Rust (compiled into the host). Direct, no factory needed. |
| `from_config(path, &factories)` | Plugin set is determined by YAML at runtime. Each `kind` in YAML maps to a registered `PluginFactory`. |

You can mix them: register infrastructure plugins programmatically, then `load_config` to add YAML-configured ones.

### 7.1 The PluginFactory Trait

```rust
pub trait PluginFactory: Send + Sync {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>>;
}
```

A factory takes a `PluginConfig` (one entry from `plugins:` in YAML) and produces a `PluginInstance`. It's responsible for:

1. Constructing the plugin (`Arc::new(MyPlugin { ... })`).
2. Building one `TypedHandlerAdapter<H, P>` per hook the plugin handles.
3. Returning the bundle as a `PluginInstance`.

### 7.2 PluginInstance

```rust
pub struct PluginInstance {
    pub plugin: Arc<dyn Plugin>,
    pub handlers: Vec<(&'static str, Arc<dyn AnyHookHandler>)>,
}
```

`handlers` is one entry per hook name. For a plugin that handles two hooks (`tool_pre_invoke`, `tool_post_invoke`), the factory returns a `PluginInstance` with two entries.

### 7.3 PluginFactoryRegistry

```rust
pub struct PluginFactoryRegistry { /* private */ }

impl PluginFactoryRegistry {
    pub fn new() -> Self;
    pub fn register(&mut self, kind: impl Into<String>, factory: Box<dyn PluginFactory>);
    pub fn get(&self, kind: &str) -> Option<&dyn PluginFactory>;
    pub fn has(&self, kind: &str) -> bool;
    pub fn kinds(&self) -> Vec<&str>;
}
```

Populate before calling `PluginManager::from_config(path, &factories)`. The manager dispatches by `config.kind` — if the kind isn't registered, it returns `PluginError::Config { message: "unknown kind: ..." }`.

## 8. Extensions

Extensions are typed sidecar data carried alongside the payload. They are **always** a separate parameter — never inside the payload — because they need per-plugin capability filtering and independent modification.

```rust
pub struct Extensions {
    pub meta: Option<Arc<MetaExtension>>,
    pub security: Option<Arc<SecurityExtension>>,
    pub http: Option<Arc<HttpExtension>>,
    pub delegation: Option<Arc<DelegationExtension>>,
    pub agent: Option<Arc<AgentExtension>>,
    pub request: Option<Arc<RequestExtension>>,
    pub mcp: Option<Arc<MCPExtension>>,
    pub completion: Option<Arc<CompletionExtension>>,
    pub provenance: Option<Arc<ProvenanceExtension>>,
    pub llm: Option<Arc<LlmExtension>>,
    pub framework: Option<Arc<FrameworkExtension>>,
    pub custom: HashMap<String, serde_json::Value>,
}
```

| Extension | Purpose |
|---|---|
| `Meta` | Entity identification for route resolution (`entity_type`, `entity_name`, `tags`) |
| `Security` | Identity, labels, classification, data policies, authmethod, agent identity |
| `Http` | Request/response headers |
| `Delegation` | Token delegation chain (per-hop subject, audience, scope) |
| `Agent` | Agent execution context (session, conversation, turn) |
| `Request` | Environment, request ID, trace/span IDs, timestamp |
| `MCP` | MCP entity metadata (tool/resource/prompt server IDs) |
| `Completion` | LLM stats (stop reason, tokens, model, latency) |
| `Provenance` | Origin and message threading |
| `LLM` | Model identity (provider, capabilities) |
| `Framework` | Agentic framework context (framework name, node/graph IDs) |
| `Custom` | Free-form key-value |

Each extension is held behind `Arc<T>` so cloning the `Extensions` container is cheap — only the field mutated needs a deep clone. `OwnedExtensions` is the mutable form returned from `cow_copy()`.

For capability-gated writes, see §6.7.

## 9. CMF Payloads & Hooks

**CMF (ContextForge Message Format)** is a typed multi-part message used by the agentic-pipeline hooks (`cmf.tool_pre_invoke`, `cmf.llm_input`, etc.). The full spec is in [cmf-message-spec.md](./cmf-message-spec.md); the highlights:

```rust
use cpex_core::cmf::{Message, MessagePayload, ContentPart, Role};
use serde_json::json;

let msg = MessagePayload {
    message: Message {
        schema_version: "1.0".into(),
        role: Role::User,
        content: vec![
            ContentPart::Text("Look up compensation".into()),
            ContentPart::ToolCall(ToolCall {
                tool_call_id: "tc_001".into(),
                name: "get_compensation".into(),
                arguments: json!({"employee_id": 42}),
                ..Default::default()
            }),
        ],
        channel: None,
    },
};
```

`MessagePayload` already implements `PluginPayload` — no `impl_plugin_payload!` needed.

**Built-in CMF hooks** (registered when you wire CMF into the manager):

| Hook | Purpose |
|---|---|
| `cmf.tool_pre_invoke` | Before tool execution |
| `cmf.tool_post_invoke` | After tool execution |
| `cmf.llm_input` | Before LLM call |
| `cmf.llm_output` | After LLM response |
| `cmf.prompt_pre_fetch` / `cmf.prompt_post_fetch` | Prompt fetch lifecycle |
| `cmf.resource_pre_fetch` / `cmf.resource_post_fetch` | Resource fetch lifecycle |

A single plugin registers a `CmfHook` marker against multiple names with `register_handler_for_names`, then dispatches via `invoke_named::<CmfHook>(name, ...)`. See §6.6.

## 10. YAML Configuration

The full structure of the config file consumed by `load_config_file`:

```yaml
plugin_settings:
  routing_enabled: true       # turn on route resolution (vs legacy conditions)
  plugin_timeout: 30          # default timeout in seconds

global:
  policies:
    all:                      # reserved — fires on every invocation
      plugins: [identity-resolver]
    pii:                      # custom group — fires when route has "pii" tag
      plugins: [pii-guard]

plugins:
  - name: identity-resolver
    kind: builtin/identity     # must match a registered factory key
    hooks: [tool_pre_invoke, tool_post_invoke]
    mode: sequential
    priority: 10
    on_error: fail
    capabilities: [read_subject]
    config:                    # opaque to framework — passed to factory
      strict_mode: true

  - name: pii-guard
    kind: builtin/pii
    hooks: [tool_pre_invoke]
    mode: sequential
    priority: 20
    on_error: fail
    capabilities: [read_labels, read_subject]

  - name: audit-logger
    kind: builtin/audit
    hooks: [tool_pre_invoke, tool_post_invoke]
    mode: fire_and_forget
    priority: 100
    on_error: ignore

routes:
  - tool: get_compensation
    meta:
      tags: [pii, hr]          # adds tags to MetaExtension for matching tools
    plugins:
      - audit-logger           # route-specific override

  - tool: list_departments
    plugins:
      - audit-logger

  - tool: "*"                  # wildcard — catch-all
    plugins:
      - audit-logger
```

**Routes** are evaluated in order; first match wins. The wildcard `"*"` catches anything not matched by an earlier route. `meta.tags` augments the `MetaExtension.tags` for the matched tool, which can then trigger tag-based policy groups.

**Policy groups** are named bundles of plugins. The `"all"` group is reserved and always fires. Other groups (e.g., `pii`) fire when a route's tags include the group name.

Loading:

```rust
let mut factories = PluginFactoryRegistry::new();
factories.register("builtin/identity", Box::new(IdentityFactory));
factories.register("builtin/pii", Box::new(PiiFactory));
factories.register("builtin/audit", Box::new(AuditFactory));

let manager = PluginManager::from_config(Path::new("plugins.yaml"), &factories)?;
manager.initialize().await?;
```

## 11. Sample Plugin: Full Worked Example

This walks through a complete native-Rust plugin from payload definition to invocation. Source for reference: [crates/cpex-core/examples/plugin_demo.rs](../../crates/cpex-core/examples/plugin_demo.rs).

### 11.1 Define the Payload

```rust
use cpex_core::impl_plugin_payload;

#[derive(Debug, Clone)]
struct ToolInvokePayload {
    tool_name: String,
    user: String,
    arguments: String,
}
impl_plugin_payload!(ToolInvokePayload);
```

### 11.2 Define the Hook Types

```rust
use cpex_core::hooks::trait_def::{HookTypeDef, PluginResult};

struct ToolPreInvoke;
impl HookTypeDef for ToolPreInvoke {
    type Payload = ToolInvokePayload;
    type Result = PluginResult<ToolInvokePayload>;
    const NAME: &'static str = "tool_pre_invoke";
}

struct ToolPostInvoke;
impl HookTypeDef for ToolPostInvoke {
    type Payload = ToolInvokePayload;
    type Result = PluginResult<ToolInvokePayload>;
    const NAME: &'static str = "tool_post_invoke";
}
```

### 11.3 Implement the Plugin

```rust
use std::sync::Arc;
use async_trait::async_trait;
use cpex_core::context::PluginContext;
use cpex_core::error::{PluginError, PluginViolation};
use cpex_core::hooks::payload::Extensions;
use cpex_core::hooks::trait_def::HookHandler;
use cpex_core::plugin::{Plugin, PluginConfig};

/// Plugin that requires a non-empty `user` field on every invocation.
struct IdentityResolver {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for IdentityResolver {
    fn config(&self) -> &PluginConfig { &self.cfg }

    async fn initialize(&self) -> Result<(), Box<PluginError>> {
        println!("[identity-resolver] initialized");
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), Box<PluginError>> {
        println!("[identity-resolver] shutdown");
        Ok(())
    }
}
```

### 11.4 Implement the Hook Handlers

```rust
impl HookHandler<ToolPreInvoke> for IdentityResolver {
    async fn handle(
        &self,
        payload: &ToolInvokePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<ToolInvokePayload> {
        if payload.user.is_empty() {
            return PluginResult::deny(PluginViolation::new(
                "no_identity",
                "User identity is required",
            ));
        }
        PluginResult::allow()
    }
}

impl HookHandler<ToolPostInvoke> for IdentityResolver {
    async fn handle(
        &self,
        _payload: &ToolInvokePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<ToolInvokePayload> {
        PluginResult::allow()
    }
}
```

### 11.5 Build a Factory

```rust
use cpex_core::factory::{PluginFactory, PluginInstance};
use cpex_core::hooks::adapter::TypedHandlerAdapter;
use cpex_core::registry::AnyHookHandler;

struct IdentityFactory;

impl PluginFactory for IdentityFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let plugin = Arc::new(IdentityResolver { cfg: config.clone() });

        let mut handlers: Vec<(&'static str, Arc<dyn AnyHookHandler>)> = Vec::new();
        for hook in &config.hooks {
            match hook.as_str() {
                "tool_pre_invoke" => handlers.push((
                    "tool_pre_invoke",
                    Arc::new(TypedHandlerAdapter::<ToolPreInvoke, _>::new(Arc::clone(&plugin))),
                )),
                "tool_post_invoke" => handlers.push((
                    "tool_post_invoke",
                    Arc::new(TypedHandlerAdapter::<ToolPostInvoke, _>::new(Arc::clone(&plugin))),
                )),
                other => return Err(PluginError::Config {
                    message: format!("identity-resolver doesn't handle hook '{}'", other),
                }.boxed()),
            }
        }

        Ok(PluginInstance {
            plugin: plugin as Arc<dyn Plugin>,
            handlers,
        })
    }
}
```

### 11.6 Register and Invoke (Programmatic)

Use `register_handler::<H, _>` for compile-time dispatch and `invoke::<H>` for the typed call path. The compiler enforces that the payload you pass matches `H::Payload`.

```rust
use cpex_core::manager::{PluginManager, ManagerConfig};
use cpex_core::plugin::{PluginConfig, PluginMode, OnError};

#[tokio::main]
async fn main() -> Result<(), Box<PluginError>> {
    let manager = PluginManager::new(ManagerConfig::default());

    // Programmatic registration — skips the factory entirely.
    let cfg = PluginConfig {
        name: "identity-resolver".into(),
        kind: "builtin/identity".into(),
        hooks: vec!["tool_pre_invoke".into()],
        mode: PluginMode::Sequential,
        on_error: OnError::Fail,
        ..Default::default()
    };
    let plugin = Arc::new(IdentityResolver { cfg: cfg.clone() });
    manager.register_handler::<ToolPreInvoke, _>(plugin, cfg)?;

    manager.initialize().await?;

    // Typed invoke — payload type must be ToolPreInvoke::Payload (= ToolInvokePayload).
    let payload = ToolInvokePayload {
        tool_name: "get_compensation".into(),
        user: "alice".into(),
        arguments: r#"{"employee_id": 42}"#.into(),
    };

    let (result, _bg) = manager.invoke::<ToolPreInvoke>(
        payload,
        Extensions::default(),
        None,
    ).await;

    if result.is_denied() {
        let v = result.violation.unwrap();
        eprintln!("DENIED: {} [{}]", v.reason, v.code);
    } else {
        println!("ALLOWED");
    }

    // Soft errors (on_error: ignore/disable plugins) land here.
    for record in &result.errors {
        eprintln!(
            "soft error from {}: {}",
            record.plugin_name, record.message,
        );
    }

    manager.shutdown().await;
    Ok(())
}
```

### 11.7 Threading Context Across Hooks

For pre/post hook pairs, thread the returned `PluginContextTable` from the pre-hook into the post-hook so each plugin sees its own `local_state` from earlier:

```rust
let (pre_result, _bg) = manager.invoke::<ToolPreInvoke>(
    payload.clone(), ext.clone(), None,
).await;

// Tool runs here ...
let tool_output = run_tool(&payload).await?;

// Post-hook: pass pre_result.context_table so plugins see their stashed local_state.
let (post_result, _bg) = manager.invoke::<ToolPostInvoke>(
    payload, ext, Some(pre_result.context_table),
).await;
```

The first invoke takes `None`; subsequent invokes within the same logical request thread `Some(prev.context_table)` through.

### 11.8 Register and Invoke (Config-driven)

For YAML-driven registration, register the factory and call `from_config`:

```rust
use cpex_core::factory::PluginFactoryRegistry;
use std::path::Path;

#[tokio::main]
async fn main() -> Result<(), Box<PluginError>> {
    let mut factories = PluginFactoryRegistry::new();
    factories.register("builtin/identity", Box::new(IdentityFactory));

    let manager = PluginManager::from_config(
        Path::new("plugins.yaml"),
        &factories,
    )?;
    manager.initialize().await?;

    /* same invoke::<ToolPreInvoke> as above */

    manager.shutdown().await;
    Ok(())
}
```

## 12. PluginContext & State

Every `HookHandler::handle` call receives a `&mut PluginContext`. It carries two state stores:

```rust
pub struct PluginContext {
    pub plugin_id: PluginId,
    pub local_state: HashMap<String, Value>,   // per-plugin, persists across hooks
    pub global_state: HashMap<String, Value>,  // shared across plugins, scoped to one invoke chain
    /* helpers */
}
```

| Store | Scope | Use case |
|---|---|---|
| `local_state` | Plugin-private, persists across multiple hooks within one request (`tool_pre_invoke` → `tool_post_invoke`) | Stash per-request data the plugin will need on the corresponding post-hook (e.g., a timer started in pre, stopped in post) |
| `global_state` | Shared across plugins within one invoke chain | Pass data from one plugin to another (e.g., identity-resolver populates `user_id`, downstream plugins read it) |

Threading `local_state` across hooks is the entire reason `PluginContextTable` exists — the embedder threads the returned context table from one invoke into the next, and the framework hydrates each plugin's `local_state` from the table.

`global_state` is committed back to a canonical store after each plugin runs (in Sequential phase) so the next plugin sees the merged view.

## 13. Error Handling

The framework surfaces failures through three channels, each with distinct semantics:

| Channel | Triggers | Where it shows up |
|---|---|---|
| `Result<_, Box<PluginError>>` from `register_*`, `load_config`, `initialize` | Lifecycle errors: parse error, factory error, initialization error | Caller's `Err(...)` |
| `PipelineResult.violation: Option<PluginViolation>` | A plugin called `PluginResult::deny(...)` | Set when `result.is_denied() == true`; `result.continue_processing == false` |
| `PipelineResult.errors: Vec<PluginErrorRecord>` | Plugin returned `Err` with `on_error: ignore` or `on_error: disable`; plugin timeout in non-blocking phase; FFI-layer issues | Soft-error log; pipeline still completed |

Note: invoke methods (`invoke`, `invoke_named`, `invoke_by_name`) do **not** return `Result`. They always return `(PipelineResult, BackgroundTasks)`. All in-pipeline failures land in the channels above. This is deliberate — once you've reached invoke, "the framework couldn't run anything" isn't a possible state; either no plugins matched (and you get an `allow` result) or the pipeline ran and produced a result.

```rust
let (result, _bg) = mgr.invoke::<ToolPreInvoke>(payload, ext, ct).await;

if !result.continue_processing {
    let v = result.violation.unwrap();
    eprintln!("denied [{}]: {}", v.code, v.reason);
    return; // halt downstream work
}

// Soft errors — pipeline ran, but some plugins failed non-fatally.
for record in &result.errors {
    log::warn!(
        "plugin {} failed: {} ({})",
        record.plugin_name, record.message,
        record.code.as_deref().unwrap_or("-"),
    );
}
```

## 14. Threading & Async

- `PluginManager` is `Send + Sync`. Use `Arc<PluginManager>` and call `invoke::<H>(&self, ...)` from many tasks concurrently. The internal registry uses `ArcSwap` for lock-free reads; mutations (registration, config load) clone-and-swap.
- Plugins must be `Send + Sync` (enforced by the `Plugin` trait bound). All plugin state shared via `&self` must be safe for concurrent access.
- `HookHandler::handle` is `async fn`. Plugins that don't need to await compile to a ready future with no observable cost; plugins that need to await per-invocation just use `.await`. Prefer caching state in `Plugin::initialize` and reading from cache on the hot path — `.await` in `handle` adds latency to every request. Never call `block_on` inside `handle`; the manager already runs you on a tokio task and nested blocking will panic.
- The framework runs Concurrent-phase handlers in a `tokio::task::JoinSet` — true parallelism if your plugins are CPU-bound.
- When embedded via cpex-ffi, all managers in the process share **one** tokio runtime. Worker thread count is configurable; see [cpex-go-spec.md](./cpex-go-spec.md) §5.9 for the FFI-side knobs. Within pure Rust, you control the runtime yourself (`#[tokio::main]` or manual `Runtime::new()`).

## 15. Testing Plugins

Native Rust plugins are easy to unit-test — instantiate the plugin, build a `PluginContext`, call `handle` directly without going through the manager.

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use cpex_core::context::PluginContext;
    use cpex_core::hooks::payload::Extensions;
    use cpex_core::plugin::PluginId;

    #[tokio::test]
    async fn rejects_empty_user() {
        let plugin = IdentityResolver {
            cfg: PluginConfig { name: "test".into(), ..Default::default() },
        };
        let payload = ToolInvokePayload {
            tool_name: "test".into(),
            user: "".into(),
            arguments: "{}".into(),
        };
        let mut ctx = PluginContext::new(PluginId::from(1));
        let result = HookHandler::<ToolPreInvoke>::handle(
            &plugin, &payload, &Extensions::default(), &mut ctx).await;
        assert!(result.violation.is_some());
        assert_eq!(result.violation.unwrap().code, "no_identity");
    }
}
```

For integration tests through the full pipeline, build a `PluginManager`, register the plugin, and `invoke::<H>`. The `cpex-core` test suite has examples in `crates/cpex-core/src/manager.rs` (test module).

## 16. Build & Test

The repo Makefile is the canonical interface:

| Target | What it does |
|---|---|
| `make rust-build` / `rust-build-release` | Build workspace (debug / release) |
| `make rust-test` | Full workspace tests |
| `make rust-test-ffi` | Only the cpex-ffi crate tests (faster iteration) |
| `make rust-lint-check` | Read-only `cargo fmt --check` + `cargo clippy -- -D warnings` |
| `make rust-lint` (or `rust-lint-fix`) | Mutating: `cargo fmt` + `clippy --fix` |
| `make examples-build` | Build all examples — catches stale public-API usage |
| `make examples-run` | Build + run each example end-to-end |
| `make ci` | Full CI gate (lint-check + test-all + examples-build) |

Raw commands:

```bash
# Build cpex-core
cargo build -p cpex-core

# Run example
cargo run --example plugin_demo -p cpex-core
cargo run --example cmf_capabilities_demo -p cpex-core

# Tests
cargo test --workspace
```

## 17. Dynamic Plugin Loading (Design Note)

> **Status:** the C ABI path described below is shipped today (cpex-ffi, the Go integration). The Rust `cdylib` path is design-only — see §18 row "Native (`dlopen`) plugin loader."

The framework is built so dynamic plugins (loaded at runtime from a `.so` / `.dylib` / `.dll`) work without changing the typed plugin-author API. The architecture deliberately separates two layers:

```
HookHandler<H>          ← native AFIT, monomorphized inside the plugin's binary
       ↓ wrapped by TypedHandlerAdapter<H, P> at registration time
AnyHookHandler          ← object-safe; #[async_trait] boxes the future
       ↓ vtable
Arc<dyn AnyHookHandler> ← THIS is what crosses module boundaries
```

The typed `HookHandler<H>` is non-object-safe (because of `impl Future` return-position) — you can't have `Box<dyn HookHandler<H>>` and you definitely can't put one across `dlopen`. That's intentional. The plugin compiles its own `TypedHandlerAdapter<H, P>` and erases to `Arc<dyn AnyHookHandler>` *inside its own binary* before handing anything to the host. The host only ever sees `dyn AnyHookHandler`, which has a stable vtable.

### 17.1 Two transport strategies

| Strategy | Status | What crosses the boundary |
|---|---|---|
| **C ABI via cpex-ffi** | Shipped (Go integration) | `extern "C"` functions, opaque manager handles, MessagePack-encoded payloads. Plugins never touch `HookHandler<H>` directly — they implement whatever the FFI shim exposes. See [cpex-go-spec.md](./cpex-go-spec.md). |
| **Rust `cdylib` via `dlopen`** | Not implemented | A `cdylib` exports a registration entry point that returns `Arc<dyn AnyHookHandler>` (or a vec of named handlers). Host loads via `libloading` and registers via `PluginManager::register_raw`. |

### 17.2 Async stays end-to-end

Both transports preserve full async behavior:

```
host:    arc_handler.invoke(payload, ext, ctx).await
            ↓ (vtable call across the module boundary)
plugin:  TypedHandlerAdapter::invoke
            ↓ (downcast to H::Payload + .await)
plugin:  handle(...).await         // plugin can await JWKS, RPC, anything
```

`#[async_trait]` boxes the typed future into `Pin<Box<dyn Future + Send>>` at the `AnyHookHandler` boundary. That boxed future is what crosses the module line. The host awaits it on its own tokio runtime; the plugin's `.await` points are pause points inside that future.

### 17.3 Constraints and gotchas

Independent of which transport you pick:

- **Shared runtime.** The plugin's future doesn't carry its own runtime — it gets driven by whichever tokio runtime the host is awaiting on. In the cpex-ffi path that's the process-shared runtime; in a Rust-cdylib path it'd be whatever the host has running. Plugins must not spawn or own a runtime themselves.
- **No nested `block_on`.** A dynamic plugin must never `block_on` inside `handle` — the future is already running on a tokio task and nested blocking will panic. Same rule as in-tree plugins, but easier to forget when the plugin lives in someone else's repo.
- **Panic isolation.** The host wraps every `AnyHookHandler::invoke` call in `catch_unwind`. cpex-ffi already does this at the C boundary; a Rust `cdylib` host would do the same at the registration shim.

Specific to the Rust `cdylib` path:

- **Rust ABI instability.** Plugin and host must be compiled with the same compiler version *and* same dependency versions. Different versions = UB. Mitigations: pin both, ship the host crate as a `=` version requirement, or use the `abi_stable` crate (gives a C-compatible vtable at the cost of an extra layer).
- **Allocator boundaries.** A `Box`/`Arc` allocated by the plugin must be dropped by the same allocator. The simplest path is for both sides to use the system allocator; otherwise the plugin must expose a free function the host calls on drop.
- **Symbol visibility.** The plugin's registration entry point must be `#[no_mangle] pub extern "C"` so `dlsym` can find it. Everything else can stay regular Rust.

### 17.4 Why this works without changing the typed API

The handler-collapse work in §6.2 (single async `HookHandler<H>` trait) is orthogonal to dynamic loading. AFIT lives at the typed layer (inside the plugin's own binary); the module boundary lives at the type-erased layer. They don't collide. Plugin authors writing native, FFI, or hypothetical-cdylib plugins all write the same `async fn handle(...)` against the same `HookHandler<H>` trait — only the registration shim changes between transports.

## 18. Gaps and Unimplemented Features

| Feature | Python Location | Status in Rust |
|---|---|---|
| `invoke_hook_for_plugin(name, hook, payload)` | `manager.py` | Not implemented — no single-plugin invoke |
| `HookPayloadPolicy` (field-level write control) | `hooks/policies.py` | Not implemented — capabilities are slot-level, not field-level |
| Programmatic capability rebinding per-invoke | `extensions/tiers.py` | Not implemented — capabilities are config-level only |
| `TenantPluginManager` (multi-tenant in one manager) | `manager.py` | Not implemented — one manager per tenant (shared runtime caps total threads when via FFI) |
| Observability provider injection | `manager.py` | Not implemented — observability via `tracing` crate |
| `reset()` (reinitialize without restart) | `manager.py` | Not implemented — shutdown and recreate |
| External plugin transports (gRPC/Unix/MCP) | `framework/external/` | Not yet implemented |
| Isolated (subprocess) plugins | `framework/isolated/` | Not yet implemented |
| PDP (AuthZen/OPA) integration | `framework/pdp/` | Not yet implemented |
| WASM plugin loader | `cpex-hosts::wasm` (planned) | Not yet implemented |
| Native (`dlopen`) plugin loader | `cpex-hosts::native` (planned) | Not yet implemented |
| `retry_delay_ms` in `PipelineResult` | `models.py` | Not implemented |

The `cpex_core::plugin::Plugin` trait doc-comment mentions `cpex-hosts::{wasm,python,native}` host crates that would bridge to non-Rust plugin runtimes. None exist yet — this is a design intent placeholder, not shipped functionality.
