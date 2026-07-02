# Implementation Progress

Tracks the phase-by-phase implementation of the [Generalized Payload Interface](./generalized-payload-interface.md) spec.

---

## Phase 0: Feature-Gate cpex-core for WASM Compilation

**Status:** Complete

**Goal:** Make `cpex-core` compilable to `wasm32-wasip2` by gating runtime-heavy modules behind a `runtime` feature, so WASM plugin authors can depend on cpex-core directly.

### Changes Made

| File | Change |
|------|--------|
| `crates/cpex-core/Cargo.toml` | Added `[features]` section with `runtime` (default). Made `tokio`, `tokio-util`, `arc-swap`, `cpex-orchestration` optional deps gated behind `runtime`. |
| `crates/cpex-core/src/lib.rs` | Gated `executor`, `manager`, `registry`, `factory`, `visitor` modules behind `#[cfg(feature = "runtime")]`. |
| `crates/cpex-core/src/hooks/mod.rs` | Gated `adapter` module and `TypedHandlerAdapter` re-export behind `#[cfg(feature = "runtime")]`. |
| `crates/cpex-core/src/config.rs` | Gated `load_config()` function and `use std::path::Path` behind `#[cfg(feature = "runtime")]`. `parse_config()` remains always available. |
| `crates/cpex-core/src/delegation/payload.rs` | Gated `use crate::executor::PipelineResult` import and `from_pipeline_result()` method behind `#[cfg(feature = "runtime")]`. |
| `crates/cpex-core/src/identity/payload.rs` | Same gating as delegation — `PipelineResult` import and `from_pipeline_result()` method. |

### Module Availability

| Module | Without `runtime` | With `runtime` (default) |
|--------|-------------------|--------------------------|
| `cmf/` | Available | Available |
| `config` | Available (except `load_config()`) | Available |
| `context` | Available | Available |
| `delegation/` | Available (except `from_pipeline_result()`) | Available |
| `error` | Available | Available |
| `extensions/` | Available | Available |
| `hooks/` | Available (except `adapter` sub-module) | Available |
| `identity/` | Available (except `from_pipeline_result()`) | Available |
| `plugin` | Available | Available |
| `executor` | Excluded | Available |
| `factory` | Excluded | Available |
| `manager` | Excluded | Available |
| `registry` | Excluded | Available |
| `visitor` | Excluded | Available |

### Verification Results

| Check | Result |
|-------|--------|
| `cargo build -p cpex-core` | Pass — default features, all modules compile |
| `cargo build -p cpex-core --no-default-features` | Pass — no tokio pulled in, types-only build |
| `cargo build -p cpex-core --no-default-features --target wasm32-wasip2` | Pass — compiles to WASM component target |
| `cargo test -p cpex-core` | Pass — 12 unit tests + 6 doc-tests, 0 failures |

### Usage

```toml
# Native host (full runtime) — default
[dependencies]
cpex-core = { path = "../cpex-core" }

# WASM guest plugin (types + traits only, no tokio)
[dependencies]
cpex-core = { path = "../cpex-core", default-features = false }
```

---

## Phase 1: WIT Interface Redesign

**Status:** Complete

**Goal:** Add `generic-payload`, `hook-payload` variant, `hook-name` parameter, extensions `extra` overflow field, and `hook-result` with context writeback to the WIT world.

### Changes Made

| File | Change |
|------|--------|
| `crates/cpex-wasm-plugin/wit/world.wit` | Added `generic-payload`, `hook-payload` variant, `extensions.extra`, `hook-result` with `modified-context`; export changed to `handle-hook` with `hook-name: string` parameter |
| `crates/cpex-wasm-host/wit/world.wit` | Mirror of plugin WIT |
| `crates/cpex-wasm-host/src/sandbox_manager.rs` | Updated `invoke()` to `(hook_name: &str, payload: HookPayload, extensions: Extensions, ctx: PluginContext) -> HookResult` |
| `crates/cpex-wasm-host/src/conversions.rs` | Added `extra: None` to `native_extensions_to_wit()`; replaced `wit_result_to_native()` with `wit_hook_result_to_native()` returning `(NativePluginResult, Option<NativePluginContext>)`; added `wit_context_to_native()` and `wit_cmf_payload_to_native()` |
| `crates/cpex-wasm-host/src/factory.rs` | Added `hook_name` field to `WasmBridgeHandler`; per-hook handler instantiation; payload wrapped as `HookPayload::Cmf`; context writeback from `modified_context` |
| `crates/cpex-wasm-plugin/src/conversions.rs` | Added `native_result_to_hook_result()` (wraps payload as `HookPayload::Cmf`, includes `modified_context`); added `native_context_to_wit()`; added `extra: None` to extensions output |

### Verification Results

| Check | Result |
|-------|--------|
| `cargo build -p cpex-wasm-host` | Pass |
| `cargo build --target wasm32-wasip2` (from plugin dir) | Pass |

### Post-Phase-3 WIT Redesign (v1 → v2)

After Phase 3, the `extra: option<string>` overflow field was replaced with explicit typed WIT records for all 8 overflow extension types. See changes below.

| File | Change |
|------|--------|
| Both `wit/world.wit` files (v1) | Added 8 typed extension records; replaced `extra: option<string>` with explicit fields |
| Both `wit/world.wit` files (v2 — full audit) | Added `client-extension`, `workload-identity`, `object-security-profile`, `data-policy`, `retention-policy`, `client-trust-level` enum; `security-extension` now has `client`, `caller-workload`, `this-workload`, `objects`, `data`; `plugin-violation` gains `plugin-name`; `plugin-context` changed from JSON strings to `list<context-entry>`; `authorization-detail` 4 list fields now `option<list<string>>` to preserve None; `prompt-result.messages` kept as `string` (recursive WIT cycle constraint documented) |
| `crates/cpex-wasm-host/src/conversions.rs` | Full rewrite — all new security types, typed context entry conversion, plugin_name wired, client/workload/objects/data round-trip |
| `crates/cpex-wasm-plugin/src/conversions.rs` | Context conversion updated to `ContextEntry` list; `plugin_name` forwarded; new security fields stubbed as None/empty pending Phase 4 |
| `crates/cpex-wasm-host/Cargo.toml` | Added `chrono` dependency |

---

## Phase 2: WasmSerializablePayload Trait

**Status:** Complete

**Goal:** Add opt-in `WasmSerializablePayload` trait + `impl_wasm_payload!` macro to `cpex-core/src/hooks/payload.rs`. Implement for `MessagePayload`.

### Changes Made

| File | Change |
|------|--------|
| `crates/cpex-core/src/hooks/payload.rs` | Added `WasmSerializablePayload` trait with `payload_type_name()`, `to_wasm_bytes()`, `from_wasm_bytes()`; added `impl_wasm_payload!($ty, $name)` macro |
| `crates/cpex-core/src/cmf/message.rs` | Added `impl_wasm_payload!(MessagePayload, "cmf.message")` |
| `crates/cpex-core/src/hooks/mod.rs` | Re-exported `WasmSerializablePayload` at the `hooks` level |

### Verification Results

| Check | Result |
|-------|--------|
| `cargo build -p cpex-core` | Pass |
| `cargo build -p cpex-core --no-default-features --target wasm32-wasip2` | Pass |
| `cargo test -p cpex-core` | Pass — 8 doc-tests (including 2 new for `WasmSerializablePayload` and `impl_wasm_payload!`) |

---

## Phase 3: Host-Side Changes

**Status:** Complete

**Goal:** Update `cpex-wasm-host` — PayloadSerializerRegistry, SandboxManager invoke signature, WasmBridgeHandler dispatch logic, conversions for generic payloads + extensions overflow + context writeback.

### Changes Made

| File | Change |
|------|--------|
| `crates/cpex-wasm-host/src/payload_registry.rs` | **New** — `PayloadSerializerRegistry` with `register<T: WasmSerializablePayload>()`, `serialize(&dyn PluginPayload) -> (&'static str, Vec<u8>)`, `deserialize(type_name, bytes) -> Box<dyn PluginPayload>`, `contains_type_id()` |
| `crates/cpex-wasm-host/src/lib.rs` | Exported `pub mod payload_registry` |
| `crates/cpex-wasm-host/src/conversions.rs` | `native_extensions_to_wit()` now calls `build_extra()` which serializes agent/mcp/completion/provenance/llm/framework/delegation/custom into `extra`; added `apply_extra_to_owned()` for the reverse path; `wit_hook_result_to_native()` now accepts `&PayloadSerializerRegistry`, handles `HookPayload::Generic` writeback, and wires `modified_extensions` via `wit_extensions_to_owned()` |
| `crates/cpex-wasm-host/src/factory.rs` | `WasmPluginFactory` gains `registry: Arc<PayloadSerializerRegistry>` field; `new()` takes it as a parameter; added `with_cmf_only()` convenience constructor; `WasmBridgeHandler` gains `registry` field; `invoke()` uses registry for generic payload path; passes registry to `wit_hook_result_to_native()` |
| `crates/cpex-wasm-host/examples/wasm_plugin_demo.rs` | Updated to `WasmPluginFactory::with_cmf_only()` |

### Verification Results

| Check | Result |
|-------|--------|
| `cargo build -p cpex-wasm-host` | Pass |
| `cargo build -p cpex-wasm-host --examples` | Pass |

---

## Phase 4: Guest-Side Changes

**Status:** Complete

**Goal:** Update `cpex-wasm-plugin` to use cpex-core (no default features) instead of cpex-payload. Add `register_wasm_plugin!` macro with automatic dispatch to `HookHandler<H>` impls.

### Changes Made

| File | Change |
|------|--------|
| `crates/cpex-wasm-plugin/Cargo.toml` | Replaced `cpex-payload` with `cpex-core` (no default features); added `async-trait`, `chrono` |
| `crates/cpex-wasm-plugin/src/conversions.rs` | Full rewrite using cpex-core types — all extension fields wired (agent, mcp, completion, provenance, llm, framework, delegation, security with client/workload/objects/data) |
| `crates/cpex-wasm-plugin/src/lib.rs` | Added `register_wasm_plugin!(PluginType, [HookType, ...])` macro generating the `Guest` impl; added `__block_on` synchronous async executor for WASM; replaced hand-written `Guest` impl with `register_wasm_plugin!(IdentityCheckerPlugin, [CmfHook])`; `IdentityCheckerPlugin` now uses `HookHandler<CmfHook>` (identical to native plugin code) |

### register_wasm_plugin! behaviour

- For `HookPayload::Cmf`: converts WIT → cpex-core `MessagePayload`, calls `HookHandler<CmfHook>::handle()`, converts `PluginResult` → WIT `HookResult` with context writeback
- For `HookPayload::Generic`: returns `allow()` (full generic dispatch pending Phase 5+)
- Async execution: driven to completion via `__block_on` spin-poll (safe in WASM — no I/O awaited, future completes on first poll)

### Verification Results

| Check | Result |
|-------|--------|
| `cargo build --target wasm32-wasip2` (from plugin dir) | Pass — 0 errors, 0 warnings |
| `cargo build -p cpex-wasm-host --examples` | Pass |

---

## Phase 5: Examples

**Status:** Complete

**Goal:** Update existing `wasm_plugin_demo` and add new `wasm_generic_payload_demo` showing custom payloads crossing the WASM boundary.

### Changes Made

| File | Change |
|------|--------|
| `crates/cpex-wasm-host/examples/wasm_plugin_demo.rs` | Rewritten — clean structure, extracted `build_extensions()` helper, uses `cpex_core` imports directly (no `cpex_wasm_host` re-exports), correct `OwnedExtensions` handling in post-invoke step |
| `crates/cpex-wasm-host/examples/wasm_generic_payload_demo.rs` | **New** — defines `ToolInvokePayload` with `impl_plugin_payload!` + `impl_wasm_payload!`; defines `ToolPreInvoke` hook via `define_hook!`; registers both payloads in `PayloadSerializerRegistry`; invokes through WASM pipeline via the generic path (`HookPayload::Generic`) |

### What each demo shows

**`wasm_plugin_demo`** — CMF fast-path: `MessagePayload` → `HookPayload::Cmf` → WASM guest `IdentityCheckerPlugin` (Phase 4 macro-registered) → `PluginResult` → writeback. Full pre-invoke + post-invoke with context table threading.

**`wasm_generic_payload_demo`** — Generic path: custom `ToolInvokePayload` → `PayloadSerializerRegistry.serialize()` → `HookPayload::Generic { payload_type: "cpex.tool_invoke", bytes }` → WASM guest logs receipt and returns allow(). Demonstrates the host-side infrastructure and wire format. Guest-side typed dispatch for generic payloads is the next milestone.

### Verification Results

| Check | Result |
|-------|--------|
| `cargo build -p cpex-wasm-host --examples` | Pass — 0 errors, 0 warnings |
| `cargo test -p cpex-core` | Pass — 8 tests |

---

## Phase 6: End-to-End Verification

**Status:** Complete

**Goal:** Full compile + test + run verification across all crates and both targets.

### Changes Made

| File | Change |
|------|--------|
| `crates/cpex-wasm-host/config/config.yaml` | Added `tool_pre_invoke` to the plugin's hook list so the generic payload demo reaches the WASM boundary |

### Verification Results

| Check | Result |
|-------|--------|
| `cargo build -p cpex-core` | Pass |
| `cargo build -p cpex-core --no-default-features --target wasm32-wasip2` | Pass |
| `cargo build -p cpex-wasm-host` | Pass |
| `cargo build -p cpex-wasm-host --examples` | Pass — 0 errors, 0 warnings |
| `cargo build --target wasm32-wasip2` (from plugin dir) | Pass — 0 errors, 0 warnings |
| `cargo test -p cpex-core` | Pass — 8 passed, 0 failed |
| `cargo run --example wasm_plugin_demo` | Pass — CMF pre/post invoke flow runs end-to-end |
| `cargo run --example wasm_generic_payload_demo` | Pass — Generic payload crosses WASM boundary |

### CMF Demo Output

```
=== WASM Plugin Demo — CMF MessagePayload ===
=== cmf.tool_pre_invoke ===
[WASM] handle_hook: cmf.tool_pre_invoke
[WASM] PRE-INVOKE: checking identity for 'get_compensation'
[WASM] Security labels: ["HR_DATA", "PII"]
[WASM] Subject: Some("alice"), Roles: ["hr_admin"]
[WASM] PRE-INVOKE ALLOWED
Pre-invoke: ALLOWED

  [tool executes: {"salary": 150000, "currency": "USD"}]

=== cmf.tool_post_invoke ===
[WASM] handle_hook: cmf.tool_post_invoke
[WASM] POST-INVOKE: verifying result from 'get_compensation'
[WASM] Result authorized for subject: Some("alice")
[WASM] POST-INVOKE ALLOWED
Post-invoke: ALLOWED

=== Demo complete ===
```

### Generic Payload Demo Output

```
=== WASM Plugin Demo — Generic Payload (ToolInvokePayload) ===
PayloadSerializerRegistry: registered 'cmf.message' and 'cpex.tool_invoke'
Payload: ToolInvokePayload { tool_name: "get_compensation", user: "alice", arguments: "{\"employee_id\": 42}" }
Wire type: 'cpex.tool_invoke' (83 bytes when serialized)

=== tool_pre_invoke via WASM (Generic path) ===
[WASM] handle_hook: tool_pre_invoke
[WASM] generic payload 'cpex.tool_invoke' — returning allow()
Result: ALLOWED
  (guest received Generic payload, logged receipt, returned allow())

=== Demo complete ===
```
