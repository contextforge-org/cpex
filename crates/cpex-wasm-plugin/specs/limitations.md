# Implementation Limitations

Tracks known gaps, stubs, and design constraints in the current WASM plugin implementation.
Entries are grouped by area and linked to the phase that will resolve them where applicable.

---

## Critical

### 1. Non-CMF Payloads Are Hard-Rejected

**File:** `crates/cpex-wasm-host/src/factory.rs:161–169`

`WasmBridgeHandler::invoke` downcasts to `MessagePayload` and returns a hard error for any other type. The `HookPayload::Generic` WIT variant exists but the host never populates it. All non-CMF hooks (`tool_pre_invoke`, `identity_resolve`, etc.) cannot be handled by WASM plugins.

**Resolves in:** Phase 3 (`PayloadSerializerRegistry`) + Phase 2 (`WasmSerializablePayload`)

---

## High

### 2. `PayloadSerializerRegistry` Not Implemented ✓ Resolved in Phase 3

**File:** `crates/cpex-wasm-host/src/payload_registry.rs`

Implemented. `register<T>()`, `serialize()`, `deserialize()`, and `contains_type_id()` are all available.

### 3. `WasmSerializablePayload` Trait Not Implemented ✓ Resolved in Phase 2

**File:** `crates/cpex-core/src/hooks/payload.rs`

Implemented. `WasmSerializablePayload` trait + `impl_wasm_payload!` macro. `MessagePayload` registers as `"cmf.message"`.

### 4. `register_wasm_plugin!` Macro Not Implemented ✓ Resolved in Phase 4

**File:** `crates/cpex-wasm-plugin/src/lib.rs`

Implemented. `register_wasm_plugin!(PluginType, [HookType, ...])` generates the full `Guest` impl. CMF dispatch calls `HookHandler<CmfHook>::handle()`. Generic dispatch returns allow() (full generic dispatch pending Phase 5+).

### 5. Plugin Still Depends on `cpex-payload`, Not `cpex-core` ✓ Resolved in Phase 4

**Files:** `crates/cpex-wasm-plugin/Cargo.toml`, `src/conversions.rs`

Migrated. `cpex-payload` dep removed entirely. `conversions.rs` now uses `cpex_core::` throughout with full extension coverage.

### 6. Six Extension Types Silently Dropped at WASM Boundary ✓ Resolved (WIT redesign + Phase 3)

**Files:** Both `wit/world.wit`, `crates/cpex-wasm-host/src/conversions.rs`

All 8 overflow extension types now have explicit typed WIT records (`agent-extension`, `mcp-extension`, `completion-extension`, `provenance-extension`, `llm-extension`, `framework-extension`, `delegation-extension`). The host converts each field-by-field. The WIT contract is the authoritative schema — no JSON escaping.

**Resolved in Phase 4:** Guest `conversions.rs` now uses cpex-core types throughout and wires all 8 extension fields in `wit_extensions_to_native()`.

### 7. `modified_extensions` Writeback Not Implemented ✓ Resolved in Phase 3

**File:** `crates/cpex-wasm-host/src/conversions.rs`

`wit_hook_result_to_native()` now converts a non-None `modified_extensions` into a native `OwnedExtensions` via `wit_extensions_to_owned()`, including the `extra` overflow field.

### 8. Generic Payload Writeback Is a No-Op ✓ Partially Resolved in Phase 3

**File:** `crates/cpex-wasm-host/src/conversions.rs`

Generic payload writeback now deserialized via `PayloadSerializerRegistry`. The current implementation downcasts the result to `MessagePayload` as a proof-of-concept; full type-erased writeback for arbitrary types requires Phase 4's `register_wasm_plugin!` macro to know the concrete return type at compile time.

### 9. `hook_type_name()` Hardcoded to `"cmf"`

**File:** `crates/cpex-wasm-host/src/factory.rs:201–203`

`WasmBridgeHandler::hook_type_name()` always returns `"cmf"`. This value is used by the hook executor to match handlers to payload types. Handlers for non-CMF hooks will be misrouted or silently skipped.

**Resolves in:** Phase 3/4 (tie `hook_type_name` to the registered hook's type definition)

---

## Medium

### 10. `global_state` Overwritten Without Merge on Context Writeback

**File:** `crates/cpex-wasm-host/src/factory.rs:193–196`

When a guest returns a modified context, the host overwrites both `local_state` and `global_state` from the returned values. `global_state` is shared across all plugins in a pipeline — overwriting it with a stale snapshot from one plugin can discard writes from a preceding plugin in the same hook chain. There is no key-level merge or delta strategy.

### 11. Context Always Written Back (No Dirty Flag)

**File:** `crates/cpex-wasm-plugin/src/conversions.rs:332`

`native_result_to_hook_result()` always emits `modified_context: Some(...)`, even when the plugin made no changes. The host therefore always deserializes and overwrites context on every invocation. A "modified" flag or delta diff would avoid unnecessary serialization and prevent the overwrite race in item 10.

### 12. Fuel Is a Session Budget, Not Per-Invocation

**File:** `crates/cpex-wasm-host/src/sandbox_manager.rs:191–194`

Fuel (Wasmtime's instruction-count limiter) is set once at plugin load time and consumed across all invocations for the lifetime of the sandbox. A plugin that handles many hooks will eventually exhaust the budget and trap. Only the epoch deadline is reset per call. Operators who expect per-call CPU isolation need to be aware of this.

### 13. Epoch Ticker Thread Leaks Per Plugin

**File:** `crates/cpex-wasm-host/src/sandbox_manager.rs:128–133`

`SandboxManager::new()` spawns a `loop` thread with no join handle or shutdown channel. With N loaded plugins there are N permanently-running threads. They are never reclaimed if a plugin is unloaded.

### 14. Single `Mutex<SandboxManager>` Serializes All Concurrent Calls

**File:** `crates/cpex-wasm-host/src/factory.rs:87, 177`

Each plugin has one `SandboxManager` behind a `Mutex`. Concurrent hook invocations for the same plugin queue behind the lock for the full WASM execution duration. There is no instance pool or connection-pool style concurrency.

### 15. `unwrap_or_default()` Silences JSON Deserialization Errors

**Files:** Both `conversions.rs` files, multiple sites

All JSON deserialization in the conversion layer uses `unwrap_or_default()`, silently replacing a malformed or truncated payload with an empty default. A bug in serialization, a truncated buffer, or a type mismatch produces no error — it produces empty data that continues through the pipeline undetected.

Affected fields include: tool-call arguments, resource annotations, prompt arguments, prompt messages, violation details, and plugin context maps.

---

## Low

### 16. `plugin_name` Always `None` in Violations ✓ Resolved (WIT audit)

`plugin-violation` now carries a `plugin-name: option<string>` field. `wit_violation_to_native()` reads it directly. The `WasmBridgeHandler` sets it via the guest's returned `PluginViolation`. Host-side attribution remains the responsibility of `WasmBridgeHandler.plugin_name` (still not injected at the host side — low priority for Phase 4).

### 17. `Box::leak` for Hook Names Accumulates Per `create()` Call

**File:** `crates/cpex-wasm-host/src/factory.rs:98`

Each `WasmPluginFactory::create()` call leaks one `String` per declared hook name to satisfy the `&'static str` bound on handler registration. In test suites or hot-reload scenarios where plugins are created and destroyed repeatedly, these strings accumulate permanently.

### 18. Debug `eprintln!` Calls in Production Paths

**Files:** `crates/cpex-wasm-host/src/sandbox_manager.rs` (10 sites), `crates/cpex-wasm-plugin/src/lib.rs` (4 sites)

Unconditional `eprintln!("[SANDBOX] ...")` and `eprintln!("[WASM] ...")` calls write to stderr on every plugin load and hook invocation. They bypass `tracing` and cannot be silenced at runtime without recompiling.

---

## Remaining WIT Type Representation Notes

These are deliberate design choices documented here to prevent confusion:

| Item | Decision | Reason |
|---|---|---|
| `prompt-result.messages` is `string` not `list<message>` | Kept as JSON string | `message → content-part → prompt-result` is a recursive cycle; WIT has no indirect reference type |
| `tool-call.arguments`, `tool-result.content`, `annotations` fields | `string` (JSON) | `serde_json::Value` has no direct WIT equivalent; the string encoding is explicit and documented in the WIT comments |
| `plugin-context` state entries | `list<context-entry>` with value as `string` | Each value is a `serde_json::Value` — typed per-entry rather than a single opaque blob |
| `delegation-extension.age-seconds` | `string` | Avoids f64 portability issues across WASM boundary |
| `delegation-hop.timestamp` | `string` (ISO 8601) | `DateTime<Utc>` has no WIT primitive; ISO 8601 is the standard wire encoding |
| `delegation-strategy` custom variant | `strategy-custom: option<string>` alongside enum | WIT `enum` cannot carry payload data; split-field is the canonical workaround |
| `client-trust-level` custom variant | `trust-level-custom: option<string>` alongside enum | Same pattern as delegation-strategy |

## Out-of-Scope Stubs (Pending Phases)

| Phase | Deliverable | Status |
|-------|-------------|--------|
| Phase 2 | `WasmSerializablePayload` trait + `impl_wasm_payload!` macro in `cpex-core` | Complete |
| Phase 3 | `PayloadSerializerRegistry`, overflow extensions, generic payload + extensions writeback in host | Complete |
| Phase 4 | `register_wasm_plugin!` macro, migrate plugin from `cpex-payload` → `cpex-core` | Complete |
| Phase 5 | `wasm_plugin_demo` update, new `wasm_generic_payload_demo` example | Complete |
| Phase 6 | Full compile + test + run verification | Not started |
