# CPEX Rust Core

Phase 1a of the CPEX Rust plugin runtime. Provides the core types, 5-phase executor, and plugin manager for the ContextForge Plugin Extensibility Framework.

## Status

Phase 1a — core runtime functional, no language bindings yet.

- `cpex-core`: Plugin trait, typed hooks, 5-phase executor, plugin manager
- `cpex-sdk`: Lean re-exports for plugin authors

## Prerequisites

### Install Rust

If you don't have Rust installed:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Follow the prompts, then restart your shell or run:

```bash
source $HOME/.cargo/env
```

Verify the installation:

```bash
rustc --version   # should be 1.75+ (we develop on 1.94)
cargo --version
```

### Update an existing installation

```bash
rustup update stable
```

### Build and test

From the repository root:

```bash
# Check that everything compiles
cargo check -p cpex-core -p cpex-sdk

# Run all tests
cargo test -p cpex-core -p cpex-sdk
```

## What It Does

A typed, 5-phase plugin execution framework where:

- **Hooks have typed payloads** — no JSON parsing for native Rust plugins
- **Extensions are separate from payloads** — capability-filtered per plugin, modified independently
- **The framework never clones payloads** — handlers receive borrows, clone only when modifying
- **Plugin configs are trusted** — `PluginRef` holds config from the loader, not from the plugin
- **Two invoke paths** — `invoke::<H>()` (typed, Rust) and `invoke_by_name()` (dynamic, Python/Go)

## Quick Example

```rust
use std::sync::Arc;
use async_trait::async_trait;
use cpex_core::context::{GlobalContext, PluginContext};
use cpex_core::error::{PluginError, PluginViolation};
use cpex_core::hooks::payload::{Extensions, FilteredExtensions};
use cpex_core::hooks::trait_def::{HookHandler, HookTypeDef, PluginResult};
use cpex_core::manager::PluginManager;
use cpex_core::plugin::{Plugin, PluginConfig, PluginMode, OnError};

// 1. Define a payload
#[derive(Debug, Clone)]
struct ToolCallPayload {
    tool_name: String,
    include_ssn: bool,
}
cpex_core::impl_plugin_payload!(ToolCallPayload);

// 2. Define a hook type
struct ToolPreInvoke;
impl HookTypeDef for ToolPreInvoke {
    type Payload = ToolCallPayload;
    type Result = PluginResult<ToolCallPayload>;
    const NAME: &'static str = "tool_pre_invoke";
}

// 3. Write a plugin
struct SsnGuard { config: PluginConfig }

#[async_trait]
impl Plugin for SsnGuard {
    fn config(&self) -> &PluginConfig { &self.config }
    async fn initialize(&self) -> Result<(), PluginError> { Ok(()) }
    async fn shutdown(&self) -> Result<(), PluginError> { Ok(()) }
}

impl HookHandler<ToolPreInvoke> for SsnGuard {
    fn handle(
        &self,
        payload: &ToolCallPayload,          // borrow — zero cost
        _extensions: &FilteredExtensions,
        _ctx: &PluginContext,
    ) -> PluginResult<ToolCallPayload> {
        if payload.include_ssn {
            PluginResult::deny(PluginViolation::new("ssn_denied", "Requires permission"))
        } else {
            PluginResult::allow()
        }
    }
}

// 4. Register and invoke
async fn run() {
    let mut manager = PluginManager::default();

    let config = PluginConfig {
        name: "ssn-guard".into(),
        kind: "builtin".into(),
        hooks: vec!["tool_pre_invoke".into()],
        mode: PluginMode::Sequential,
        priority: 10,
        on_error: OnError::Fail,
        ..Default::default()
    };

    let plugin = Arc::new(SsnGuard { config: config.clone() });
    manager.register_handler::<ToolPreInvoke, _>(plugin, config).unwrap();
    manager.initialize().await.unwrap();

    let payload = ToolCallPayload {
        tool_name: "get_compensation".into(),
        include_ssn: true,
    };

    let result = manager
        .invoke::<ToolPreInvoke>(payload, Extensions::default(), &GlobalContext::new("req-1"))
        .await;

    assert!(!result.allowed);  // denied — SSN access blocked
}
```

## Crate Structure

```
crates/
├── cpex-core/src/
│   ├── lib.rs          — module declarations
│   ├── plugin.rs       — Plugin trait (lifecycle), PluginConfig, PluginMode, OnError, PluginCondition
│   ├── error.rs        — PluginError, PluginViolation
│   ├── context.rs      — GlobalContext, PluginContext
│   ├── hooks/
│   │   ├── payload.rs  — PluginPayload trait (object-safe), Extensions, FilteredExtensions
│   │   ├── trait_def.rs — HookTypeDef, HookHandler<H>, PluginResult
│   │   ├── adapter.rs  — TypedHandlerAdapter (bridges typed handlers to type-erased dispatch)
│   │   ├── macros.rs   — define_hook! macro
│   │   └── types.rs    — HookType (string wrapper), hook_names, cmf_hook_names
│   ├── registry.rs     — PluginRef (trusted config), PluginRegistry, AnyHookHandler, HookEntry
│   ├── executor.rs     — 5-phase engine, PipelineResult, ErasedResultFields
│   ├── manager.rs      — PluginManager (register_handler, invoke, invoke_by_name, lifecycle)
│   └── config.rs       — (stub — unified YAML parsing, Phase 2)
└── cpex-sdk/src/
    └── lib.rs          — lean re-exports for plugin authors
```

## 5-Phase Execution Model

```
SEQUENTIAL → TRANSFORM → AUDIT → CONCURRENT → FIRE_AND_FORGET
```

| Phase | Can Block? | Can Modify? | Execution |
|-------|------------|-------------|-----------|
| Sequential | Yes | Yes (clone) | Serial, chained |
| Transform | No | Yes (clone) | Serial, chained |
| Audit | No | No | Serial |
| Concurrent | Yes | No | Parallel |
| FireAndForget | No | No | Background |

All handlers receive `&Payload` (borrow). The framework holds ownership. Modified payloads are returned in `PluginResult::modified_payload` and replace the current payload in the pipeline.

## Key Design Decisions

- **PluginRef trust model** — configs come from the config loader, not from `plugin.config()`. Prevents plugins from tampering with their own priority, mode, or capabilities.
- **Borrow-based handlers** — handlers receive `&Payload`, not owned. Framework never clones. Plugins clone only when modifying. Enforced by Rust's borrow checker at compile time.
- **Single `invoke()` path** — one method on `AnyHookHandler`, not separate `invoke_owned`/`invoke_ref`. Simpler API, same behavior.
- **`PluginPayload` trait** — object-safe base for all payloads. `Box<dyn PluginPayload>` instead of `Box<dyn Any>` — type errors caught at compile time.
- **Extensions separate from payload** — capability-filtered per plugin, modified independently. Extension-only changes don't clone the payload.

## Tests

```bash
cargo test -p cpex-core -p cpex-sdk
```

27 unit tests + 6 doc tests covering: registration, priority ordering, trusted config tamper protection, 5-phase execution, allow/deny/modify results, lifecycle management, typed and dynamic invoke paths.

## What's Next

- **Phase 1b**: `cpex-ffi` + Go bindings (first language binding)
- **Phase 1c**: Conformance test corpus (YAML scenarios, Python + Rust)
- **Phase 2**: Unified YAML config parsing
- **Phase 3**: Full CMF extension types (MonotonicSet, Guarded<T>, MetaExtension, etc.)

See [CPEX Rust Core Proposal](../docs/cpex-rust-core-proposal.md) for the full roadmap.
