# Current WASM Plugin Implementation — Known Issues

This document catalogs bugs, gaps, and design issues in the current CMF-based WASM plugin implementation (`cpex-wasm-host`, `cpex-wasm-plugin`).

---

## Critical Issues

### C1. `modified_extensions` always discarded (data loss)

**File:** `cpex-wasm-host/src/conversions.rs` — `wit_result_to_native()`

```rust
modified_extensions: None, // WIT modified_extensions would require OwnedExtensions conversion
```

The WIT `plugin-result` includes `modified-extensions: option<extensions>`, and WASM plugins can return modified extensions. However, the host unconditionally sets `modified_extensions: None`, silently dropping any extension modifications (added security labels, injected HTTP headers, etc.).

**Impact:** WASM plugins that attempt to modify extensions have no effect. The feature is dead code on the guest side.

---

### C2. `metadata` field lost during result erasure

**File:** `cpex-wasm-host/src/factory.rs` → calls `cpex_core::executor::erase_result()`

The native `PluginResult<P>` has a `metadata: Option<serde_json::Value>` field. The host correctly parses it from WIT. However, `erase_result()` creates an `ErasedResultFields` struct that has **no `metadata` field** — the value is permanently discarded before the executor processes it.

**Impact:** WASM plugins cannot communicate metadata back to the pipeline. Any metadata they set is silently lost.

---

### C3. 8 of 12 extension slots missing from WIT interface

**File:** `cpex-wasm-host/wit/world.wit` — `extensions` record

WIT defines only 4 extension slots:
- `request`
- `security`
- `http`
- `meta`

Missing from WIT (present in native `Extensions`):
1. `agent` — Agent execution context (session, conversation, lineage)
2. `delegation` — Delegation chain and strategies
3. `mcp` — MCP entity metadata
4. `completion` — LLM completion information
5. `provenance` — Origin and message threading
6. `llm` — Model identity and capabilities
7. `framework` — Agentic framework context
8. `custom` — Custom extensions (HashMap<String, Value>)

**Impact:** WASM plugins are completely blind to 8 extension categories. They cannot make decisions based on agent context, delegation chains, or LLM metadata.

---

### C4. SecurityExtension fields silently dropped in conversion

**Files:** `cpex-wasm-host/src/conversions.rs`, `cpex-wasm-plugin/src/conversions.rs`

The native `SecurityExtension` has fields beyond what WIT models:
- `agent` / `client` / `caller_workload` / `this_workload` (workload identity)
- `objects` — HashMap of object security profiles
- `data` — HashMap of data policies

The WIT `security-extension` only has: `labels`, `classification`, `subject`, `auth-method`.

On the guest side, `wit_security_to_native` uses `..Default::default()` to zero out extra fields. If extensions ever round-trip through WASM (once C1 is fixed), this data will be permanently lost.

**Impact:** Security-critical context (workload identity, object profiles, data policies) is invisible to WASM plugins and would be destroyed on round-trip.

---

## Moderate Issues

### M1. No context writeback from WASM plugins

**Files:** `cpex-wasm-host/wit/world.wit` (`plugin-result` record), `cpex-wasm-host/src/factory.rs`

The WIT `plugin-result` has no `modified-context` field. Native plugins receive `ctx: &mut PluginContext` and can modify state in-place. WASM plugins receive a read-only snapshot and have no mechanism to return state changes.

**Impact:** WASM plugins cannot maintain stateful behavior across invocations (counters, caches, rate-limit tracking). They are forced to be purely stateless.

---

### M2. MonotonicSet add-only invariant bypassed through WIT

**Files:** `cpex-wasm-host/src/conversions.rs`, `cpex-wasm-plugin/src/conversions.rs`

Native security labels use `MonotonicSet` (append-only — labels can be added but never removed). The WIT interface converts this to `list<string>`. The WASM guest sees a plain list that it can freely modify — including removing labels. On the return path, `MonotonicSet::from_set(...)` accepts whatever the guest returns.

**Impact:** A malicious or buggy WASM plugin can remove security labels, violating a core security invariant of the framework. The host does not enforce monotonicity on the return path.

---

### M3. Epoch ticker thread leak (1 per plugin, never stopped)

**File:** `cpex-wasm-host/src/sandbox_manager.rs`

```rust
std::thread::spawn(move || loop {
    std::thread::sleep(std::time::Duration::from_millis(1));
    engine_clone.increment_epoch();
});
```

Every `SandboxManager::new()` spawns a detached OS thread with an infinite loop (1ms sleep + epoch increment). No `JoinHandle` is stored, no shutdown flag exists, no way to stop it. The `Engine` clone keeps the engine alive even after `SandboxManager` is dropped.

**Impact:** For N WASM plugins, N threads spin perpetually. High CPU wake-up frequency (1000 wakes/sec per plugin). Memory and handle leak on plugin unload.

---

### M4. `Box::leak` for hook name strings (memory leak)

**File:** `cpex-wasm-host/src/factory.rs`

```rust
let leaked: &'static str = Box::leak(hook_name.clone().into_boxed_str());
```

Every hook name string is leaked to obtain `&'static str`. These are never freed.

**Impact:** If plugins are dynamically loaded/unloaded (hot reload), leaked strings accumulate indefinitely. Minor for static configurations, problematic for long-running services with dynamic plugin management.

---

### M5. Fuel budget never resets between invocations

**File:** `cpex-wasm-host/src/sandbox_manager.rs`

Fuel is consumed cumulatively across all invocations of a plugin. Only the epoch deadline (timeout) is reset per call. Once fuel is exhausted, the plugin permanently traps on all subsequent invocations.

**Impact:** Long-running plugins will eventually die with no recovery mechanism. No API to query remaining fuel or reset it. The only workaround is recreating the entire `SandboxManager`.

---

### M6. `plugin_name` always `None` on violations from WASM

**File:** `cpex-wasm-host/src/conversions.rs` — `wit_violation_to_native()`

```rust
plugin_name: None,
```

The WIT `plugin-violation` record does not include `plugin_name`. The host sets it to `None`. Whether the executor fills this in later is unclear.

**Impact:** Violation audit logs from WASM plugins may lack plugin attribution, making it harder to identify which plugin denied a request.

---

### M7. HashSet/MonotonicSet uniqueness not enforced on guest side

**Files:** Both conversion files

Native types use `HashSet` (roles, permissions, teams, tags) and `MonotonicSet` (labels). WIT represents these as `list<string>`. The guest operates on plain vectors with no uniqueness constraint. Duplicates introduced by the guest are silently deduplicated on return, but the guest's logic may behave incorrectly if it assumes unique values.

**Impact:** Subtle logic bugs if guest code does list-length checks or iteration expecting uniqueness.

---

## Minor Issues

### m1. JSON parse errors silently swallowed

**Files:** Both conversion files (10+ occurrences)

```rust
serde_json::from_str(&s).unwrap_or_default()
```

Malformed JSON in fields like `arguments`, `content`, `annotations`, `messages`, or `metadata` is silently replaced with empty defaults.

**Impact:** Plugin bugs that produce invalid JSON are invisible — no error, no log, just empty data. Makes debugging extremely difficult.

---

### m2. `PluginError::Config` used for runtime errors

**File:** `cpex-wasm-host/src/factory.rs`

The `WasmBridgeHandler::invoke` method uses `PluginError::Config` for both configuration issues AND runtime invocation failures (WASM traps, serialization errors).

**Impact:** Operators cannot distinguish between misconfiguration and runtime crashes in error logs/metrics.

---

### m3. `eprintln!` debug output in production code

**File:** `cpex-wasm-host/src/sandbox_manager.rs` (10+ occurrences)

```rust
eprintln!("[SANDBOX] Loading WASM component...");
eprintln!("[SANDBOX] Plugin instantiated successfully");
```

Unconditional stderr writes with no log level or compile-time gating.

**Impact:** Noisy output in production that cannot be suppressed without redirecting stderr. Should use `tracing` crate (already a dependency).

---

### m4. No graceful shutdown for epoch ticker threads

**File:** `cpex-wasm-host/src/sandbox_manager.rs`

No `JoinHandle`, no `AtomicBool` stop flag, no `Drop` impl. Thread outlives its `SandboxManager`.

**Impact:** Resource leak. Blocked clean shutdown of the host process (threads keep running until process exit).

---

### m5. Duplicate conversion code (~1000 lines)

**Files:** `cpex-wasm-host/src/conversions.rs` (484 lines), `cpex-wasm-plugin/src/conversions.rs` (598 lines)

Near-identical functions for role/channel/resource-type mappings, content part conversions, extension mappings. No shared crate or macro.

**Impact:** High maintenance burden. Any CMF schema change requires updating both files in lockstep. Drift bugs are likely over time.

---

### m6. Plugin-side `http` extension coupled to `Guarded` internals

**File:** `cpex-wasm-plugin/src/conversions.rs`

```rust
http: ext.http.as_ref().map(|h| native_http_to_wit(h.read())),
```

Direct call to `.read()` on a `Guarded<HttpExtension>` type. If the guard pattern changes, this silently breaks at compile time (not the worst outcome, but tight coupling).

**Impact:** Minor maintenance concern.

---

## Resolution Mapping

Issues addressed by the [Generalized Payload Interface spec](./generalized-payload-interface.md):

| Issue | Addressed? | How |
|-------|-----------|-----|
| C1 | Yes | `hook-result` includes `modified-extensions` with full conversion |
| C2 | Partially | Metadata preserved in `hook-result`; `erase_result` in cpex-core also needs fixing |
| C3 | Yes | `extra: option<string>` overflow field carries all missing extensions as JSON |
| C4 | Partially | Extra security fields carried in the `extra` JSON overflow |
| M1 | Yes | `modified-context: option<plugin-context>` added to `hook-result` |
| M2 | No | Requires separate fix — host must validate monotonicity on return |
| M3 | No | Requires separate fix — stop flag + Drop impl |
| M4 | No | Requires separate fix — use `String` or `Arc<str>` instead |
| M5 | No | Requires separate fix — fuel reset API or per-invocation budgeting |
| M6 | No | Requires separate fix — host sets plugin_name after WASM returns |
| M7 | Partially | Monotonicity enforcement needed regardless of payload generalization |

Issues NOT addressed by the generalized payload spec should be tracked as separate work items.
