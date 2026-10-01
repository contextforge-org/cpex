# CPEX WASM Plugin — Specification

**Status**: Draft  
**Date**: July 2026  
**Source**: `crates/cpex-wasm-host` + `crates/cpex-wasm-plugin` in `github.com/contextforge-org/contextforge-plugins-framework`

CPEX WASM extends the core plugin runtime with sandboxed execution via WebAssembly Component Model (WASI P2). It serves two audiences:

- **Operators** — deploy untrusted or third-party plugins with enforced resource limits, capability-gated data access, and network sandboxing.
- **Plugin authors** — write the same `HookHandler<H>` implementations as native plugins, compiled to `.wasm` components that run in isolation.

The WASM system integrates transparently with `PluginManager` — WASM and native plugins coexist in the same pipeline, dispatched by the same executor, subject to the same 5-phase execution model.

---

## 1. Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  PluginManager                                                   │
│    register_factory("wasm://...", WasmPluginFactory)              │
│    load_config(yaml)  →  factory.create(PluginConfig)            │
│    invoke_named::<H>(hook, payload, ext, ctx_table)              │
└───────────────────────────────┬──────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│  Executor (cpex-core)                                            │
│    group_by_mode → 5-phase dispatch                              │
│    filter_extensions(ext, capabilities) → filtered view          │
│    set write tokens (write_headers, append_labels, etc.)         │
│    timeout + on_error policy                                     │
└───────────────────────────────┬──────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│  WasmBridgeHandler (cpex-wasm-host)                              │
│    Payload dispatch:                                             │
│      MessagePayload  → HookPayload::Cmf (structured)            │
│      IdentityPayload → HookPayload::Identity (structured)       │
│      DelegationPayload → HookPayload::Delegation (structured)   │
│      Custom types    → HookPayload::Custom (JSON bytes)          │
│    native_extensions_to_wit(filtered) → WIT types                │
│    SandboxManager::invoke() → WASM execution                     │
│    wit_hook_result_to_native_filtered() → ErasedResultFields     │
│    validate_extension_modifications() → accept or reject         │
└───────────────────────────────┬──────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│  Wasmtime Sandbox                                                │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  SharedEngine (1 per factory)                              │  │
│  │    Engine config: component-model + fuel + epoch           │  │
│  │    Linker: WASI P2 + WASI HTTP + host-logging             │  │
│  │    Epoch ticker: 1 thread, 1ms resolution                  │  │
│  ├────────────────────────────────────────────────────────────┤  │
│  │  Store (1 per plugin, isolated)                            │  │
│  │    WasmPluginState: WASI ctx, HTTP ctx, NetworkPolicy,     │  │
│  │                     ResourceTable, StoreLimits, plugin_name│  │
│  │    Fuel: reset per invocation                              │  │
│  │    Epoch deadline: reset per invocation                    │  │
│  └────────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  Guest Component                                           │  │
│  │    export: handle-hook(hook_name, payload, ext, ctx)       │  │
│  │    import: wasi:io, wasi:clocks, wasi:http, host-logging   │  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

---

## 2. Crate Layout

### cpex-wasm-host (host runtime)

| Module | Purpose |
|--------|---------|
| `sandbox_manager` | Wasmtime engine, store, plugin loading, invocation, `SharedEngine` |
| `factory` | `WasmPluginFactory`, `WasmBridgeHandler` — integrates with `PluginManager` |
| `conversions` | Bidirectional native ↔ WIT type mapping (~1300 lines) |
| `policy_loader` | `SandboxPolicy` parsing, WASI context builder |
| `payload_registry` | Type-erased serialization for custom payload types |

### cpex-wasm-plugin (guest SDK)

| Module | Purpose |
|--------|---------|
| `lib.rs` | WIT bindings, `register_wasm_plugin!` macro, `host_log`/`cpex_log!` |
| `conversions.rs` | WIT → native type conversion for the guest side (~730 lines) |
| `plugins/` | Feature-gated demo plugins (identity-checker, header-injector, audit-logger, token-attenuator, noop) |

---

## 3. WIT Interface Contract

**Package:** `cpex:plugin`

### 3.1 Types Interface

Defines all structured types crossing the boundary:

- **CMF**: `role`, `channel`, `resource-type`, `content-part` (12 variants), `message`, `message-payload`
- **Identity**: `identity-payload` with source, headers, output fields
- **Delegation**: `delegation-payload` with target, attenuation, output fields
- **Extensions**: All 11 slots (request, security, http, meta, agent, mcp, completion, provenance, llm, framework, delegation) + custom
- **Result**: `hook-result` with continue_processing, modified_payload, modified_extensions, modified_context, violation, metadata

### 3.2 Host-Logging Interface

```wit
interface host-logging {
  enum log-level { trace, debug, info, warn, error }
  log: func(level: log-level, message: string);
}
```

### 3.3 World Definition

```wit
world plugin {
  import wasi:io/poll@0.2.6;
  import wasi:io/error@0.2.6;
  import wasi:io/streams@0.2.6;
  import wasi:clocks/monotonic-clock@0.2.6;
  import wasi:http/types@0.2.6;
  import wasi:http/outgoing-handler@0.2.6;
  import host-logging;

  export handle-hook: func(
    hook-name: string,
    payload: hook-payload,
    extensions: extensions,
    ctx: plugin-context
  ) -> hook-result;
}
```

---

## 4. Security Model

### 4.1 Capability-Based Extension Filtering

The executor filters extensions before they reach the handler. Slots without declared capabilities are `None`. The plugin never receives unauthorized data.

| Capability | Read Access | Write Access |
|-----------|-------------|--------------|
| `read_labels` | Security labels | — |
| `append_labels` | — | Add labels (monotonic) |
| `read_subject` | Subject id + type | — |
| `read_roles` | Subject roles | — |
| `read_teams` | Subject teams | — |
| `read_claims` | Subject claims | — |
| `read_permissions` | Subject permissions | — |
| `read_client` | OAuth client | — |
| `read_workload` | Workload identity | — |
| `read_headers` | HTTP headers | — |
| `write_headers` | — | Modify HTTP headers |
| `read_agent` | Agent context | — |
| `read_delegation` | Delegation chain | — |
| `append_delegation` | — | Append to chain |
| `read_inbound_credentials` | Raw tokens | — |
| `read_delegated_tokens` | Minted tokens | — |

### 4.2 Post-Invocation Validation (Defense-in-Depth)

After the guest returns, the handler validates:

1. **Immutable tier** — Arc pointer identity on immutable slots (request, agent, mcp, completion, provenance, llm, framework, meta). Tampering → reject all extension modifications.
2. **Monotonic tier** — Security labels must be a superset of the originals. Label removal → reject.
3. **Write authorization** — HTTP/labels/delegation modifications require the corresponding write capability. Unauthorized writes → reject.
4. **Filtered slot preservation** — Slots hidden from the guest are preserved unchanged.

### 4.3 Sandbox Enforcement

| Layer | Scope | Default |
|-------|-------|---------|
| Fuel budget | Per-invocation (reset each call) | Unlimited |
| Execution timeout | Per-invocation (epoch-based) | 5,000 ms |
| Memory limit | Store lifetime | Unlimited |
| Network allowlist | Per outbound HTTP request | Deny all |
| Filesystem | Store lifetime (preopened dirs) | Deny all |
| Environment variables | Store lifetime | None exposed |

### 4.4 Credential Exclusion

Fields marked `#[serde(skip)]` never cross the boundary:
- `RawInboundToken.token`
- `RawDelegatedToken.token`
- `IdentityPayload.raw_token`
- `DelegationPayload.bearer_token`

---

## 5. Data Flow

### 5.1 Outbound (Host → Guest)

```
PluginPayload
  → downcast to MessagePayload? → native_payload_to_wit() → HookPayload::Cmf
  → downcast to IdentityPayload? → native_identity_payload_to_wit() → HookPayload::Identity
  → downcast to DelegationPayload? → native_delegation_payload_to_wit() → HookPayload::Delegation
  → PayloadSerializerRegistry.serialize() → HookPayload::Custom(type_name, bytes)

Extensions (already filtered by executor)
  → native_extensions_to_wit() → WIT Extensions record
  (each slot: Arc<T> → field-by-field clone into WIT structs)
  (JSON-encoded: custom slot, tool arguments, context entries)

PluginContext
  → native_context_to_wit() → WIT PluginContext
  (local_state/global_state → JSON-encoded key-value pairs)
```

### 5.2 Inbound (Guest → Host)

```
HookResult
  → modified_payload:
      Cmf → wit_cmf_payload_to_native()
      Identity → wit_identity_payload_to_native()
      Delegation → wit_delegation_payload_to_native()
      Custom → PayloadSerializerRegistry.deserialize()
  → modified_extensions:
      original.cow_copy() (preserves immutable Arc pointers)
      overlay mutable slots ONLY if guest was authorized to see them
  → modified_context:
      write back local_state + global_state to caller's ctx reference
  → violation:
      wit_violation_to_native()
```

### 5.3 Error Classification

Wasmtime errors are pattern-matched into `PluginError` variants:

| Error pattern | Variant | Code |
|--------------|---------|------|
| "epoch deadline" | `Timeout` | — |
| "all fuel consumed" / "fuel" | `Execution` | `fuel_exhausted` |
| "memory" + "grow"/"limit" | `Execution` | `memory_limit` |
| "unreachable" / "wasm trap" / "panic" | `Execution` | `wasm_trap` |
| "request denied" | `Execution` | `network_denied` |
| Other | `Execution` | None |

---

## 6. Plugin SDK

### 6.1 The `register_wasm_plugin!` Macro

```rust
register_wasm_plugin!(MyPlugin, [CmfHook, IdentityHook]);
```

Generates:
- A `Guest` implementation for the WIT `handle-hook` export
- Payload routing logic (CMF fast-path, Custom variant matching)
- Bidirectional type conversion calls
- A synchronous async executor (`__block_on`) for driving the handler future

### 6.2 Structured Logging

```rust
use crate::cpex_log;

cpex_log!(info, "processing tool '{}' for subject {:?}", tool_name, subject_id);
cpex_log!(warn, "PII access without hr_admin role");
```

Routes to the host's `tracing` subscriber with `plugin=<name>` as a span field.  
In `#[cfg(test)]` mode, falls back to `eprintln!` (no host import available natively).

### 6.3 Available Hook Types

| Hook Type | Payload | WIT Variant |
|-----------|---------|-------------|
| `CmfHook` | `MessagePayload` | `cmf` (structured) |
| `IdentityHook` | `IdentityPayload` | `identity` (structured) |
| `TokenDelegateHook` | `DelegationPayload` | `delegation` (structured) |
| Custom (via `define_hook!`) | Any `WasmSerializablePayload` | `custom` (JSON) |

---

## 7. Configuration

```yaml
plugins:
  - name: my-plugin
    kind: wasm://my-plugin.wasm        # wasm:// prefix triggers WasmPluginFactory
    hooks: [cmf.tool_pre_invoke, cmf.tool_post_invoke]
    mode: sequential                    # sequential|transform|audit|concurrent|fire_and_forget
    priority: 50                        # lower = earlier (within same mode)
    on_error: fail                      # fail|ignore|disable (circuit breaker)
    capabilities:                       # extension visibility + write grants
      - read_labels
      - append_labels
      - read_headers
      - write_headers
    config:
      sandbox_policy:
        allowed_filesystem: []          # deny all by default
        allowed_network:
          - "api.internal.svc"          # hostname allowlist (exact + subdomain match)
        allowed_env: []                 # env vars exposed to plugin
        resources:
          max_memory_bytes: 10485760    # 10 MB linear memory cap
          max_fuel: 1000000000          # instructions per invocation (~1 billion)
          max_execution_time_ms: 5000   # per-invocation timeout (epoch-based)
          max_instances: 10             # WASM module instance limit
          max_tables: 10                # WASM table limit
```

---

## 8. Performance Characteristics

### 8.1 Benchmark Results

| Scenario | Latency | Overhead vs Native |
|----------|:-------:|:------------------:|
| Native handler (noop) | 84 ns | 1x |
| Type conversion only (no WASM) | 843 ns | 10x |
| WASM noop (minimal payload) | 4.8 µs | 57x |
| WASM with full extensions | 7.9 µs | 94x |

### 8.2 Throughput

| Scenario | Calls/sec/core |
|----------|:--------------:|
| Native plugin | ~12,000,000 |
| WASM (minimal) | ~207,000 |
| WASM (full extensions) | ~126,000 |

### 8.3 Cost Breakdown

| Stage | Cost |
|-------|------|
| Mutex acquire | ~50 ns |
| Fuel + epoch reset | ~40 ns |
| Type conversion (native → WIT) | ~843 ns |
| Wasmtime component dispatch | ~2.5 µs |
| Guest execution (noop) | ~500 ns |
| Result conversion (WIT → native) | ~500 ns - 2 µs |
| Post-invocation validation | ~100 ns |

### 8.4 Shared Engine Optimization

All plugins from the same `WasmPluginFactory` share one `Engine` + one epoch ticker thread. N plugins = 1 thread (not N threads). Each plugin gets an isolated `Store` (separate memory, fuel, limits).

---

## 9. Build & Test

### 9.1 Building Plugins

```bash
rustup target add wasm32-wasip2
cd crates/cpex-wasm-plugin
cargo build --target wasm32-wasip2 --release --features <plugin> --no-default-features
```

One binary per feature (WIT single-export constraint).

### 9.2 Running Tests

```bash
# Host-side (35 tests: security, conversions, errors, policy)
cargo test -p cpex-wasm-host

# Plugin-side (12 tests: all 4 plugins × their hook types)
cargo test --manifest-path crates/cpex-wasm-plugin/Cargo.toml \
    --features identity-checker --no-default-features
cargo test --manifest-path crates/cpex-wasm-plugin/Cargo.toml \
    --features header-injector --no-default-features
cargo test --manifest-path crates/cpex-wasm-plugin/Cargo.toml \
    --features audit-logger --no-default-features
cargo test --manifest-path crates/cpex-wasm-plugin/Cargo.toml \
    --features token-attenuator --no-default-features
```

### 9.3 Running Benchmarks

```bash
cd crates/cpex-wasm-plugin
cargo build --target wasm32-wasip2 --release --features noop --no-default-features
cp target/wasm32-wasip2/release/cpex_wasm_plugin.wasm ../cpex-wasm-host/wasm/noop.wasm
cd ../..
cargo bench -p cpex-wasm-host
```

---

## 10. Limitations

### 10.1 Structural (inherent to WASM model)

- One plugin per `.wasm` binary (WIT single-export)
- Single-threaded per plugin (Store is not Sync)
- No raw credential access (security boundary)
- Rust-only guest SDK

### 10.2 Current Implementation

- No pre-compiled module caching (compile from source each load)
- No plugin instance pooling (serial under concurrent load)
- No streaming support (full payload buffering)
- No schema versioning (WIT changes are breaking)
- No plugin manifest / health check protocol
- Epoch ticker thread never stops (leaks on dynamic unload)
- Error classification relies on wasmtime error message strings
- Silent `.ok()` on some serialization failures in conversions

### 10.3 By Design

- `#[serde(skip)]` fields excluded from WIT (credentials)
- Custom extension slot is unrestricted (no capability gating)
- Metadata field dropped at the erasure boundary (consistent with native)
- Guest stdio inherited from host (plugins should use `cpex_log!`)

---

## 11. Design Decisions

This section records the key architectural decisions and their rationale across both `cpex-wasm-host` and `cpex-wasm-plugin`.

### 11.1 Transparent Integration via PluginFactory Trait

**Decision:** WASM plugins register with the same `PluginManager` as native plugins via `WasmPluginFactory` implementing cpex-core's `PluginFactory` trait.

**Rationale:** Operators should not need to change their pipeline configuration or dispatch logic when switching between native and WASM plugins. A WASM plugin and a native plugin can coexist in the same hook pipeline, dispatched by the same executor, subject to the same 5-phase execution model. This makes WASM an implementation detail — the security boundary is invisible to the orchestration layer.

**Consequence:** `WasmBridgeHandler` implements `AnyHookHandler` with the same signature as native handlers. The executor calls `.invoke(payload, extensions, ctx)` identically for both.

### 11.2 SharedEngine — One Epoch Ticker Per Factory

**Decision:** All plugins loaded from a single `WasmPluginFactory` share one `wasmtime::Engine` and one epoch ticker thread (1ms resolution). Each plugin gets its own `Store` with independent memory, fuel, and state.

**Rationale:** Epoch interruption requires a dedicated thread that calls `engine.increment_epoch()` in a loop. Without sharing, N plugins would spawn N threads doing identical work. Sharing the engine also enables future optimizations (module caching, ahead-of-time compilation) since compiled modules are engine-scoped.

**Trade-off:** The epoch ticker thread spawned in `SharedEngine::new()` runs forever — there is no shutdown mechanism. This is an acknowledged leak on dynamic factory unload.

### 11.3 Per-Invocation Resource Reset

**Decision:** Both fuel budget and epoch deadline are reset at the start of every `invoke()` call. Memory limits are store-lifetime (not reset).

**Rationale:** Fuel measures instruction cost and must be fresh each call to prevent a long-lived plugin from silently degrading after accumulating work. The epoch deadline is a wall-clock timeout — it must start from zero each invocation or a plugin that ran fast once could time out later despite being well-behaved. Memory, however, is additive (linear memory never shrinks) so the limit is structural.

### 11.4 Dual Payload Path — Structured WIT vs JSON Bytes

**Decision:** Built-in payloads (CMF, Identity, Delegation) use structured WIT types with field-by-field conversion. Custom payload types use `HookPayload::Custom(type_name, json_bytes)`.

**Rationale:** Structured WIT types give zero-parsing overhead for the common case (most plugins handle CMF messages). For extensibility, the `Custom` variant lets users define arbitrary payload types without modifying the WIT contract. The host's `PayloadSerializerRegistry` maps `TypeId` → `(type_name, serialize_fn, deserialize_fn)` so the dispatch is O(1).

**Trade-off:** Custom payloads pay a JSON serialization cost on both sides. The structured path for CMF/Identity/Delegation avoids this.

### 11.5 Capability-Based Extension Filtering (Pre-Invocation)

**Decision:** The executor strips extension slots the plugin has no declared capability for _before_ converting to WIT. The guest never receives unauthorized data.

**Rationale:** Defense at the narrowest possible point. Even if the WIT conversion code has bugs, an unauthorized slot is `None` at the source. This is the primary access control mechanism; post-invocation validation is defense-in-depth.

### 11.6 Post-Invocation 4-Layer Validation (Defense-in-Depth)

**Decision:** After the guest returns, the host validates extension modifications through 4 independent checks before accepting them.

**Layer 1 — Immutable tier:** Arc pointer identity on immutable slots (request, agent, mcp, completion, provenance, llm, framework, meta). A malicious guest that reconstructs a "similar" object is detected because the Arc address differs.

**Layer 2 — Monotonic labels:** Security labels must be a superset of originals. Removal is never valid.

**Layer 3 — Write authorization:** HTTP/labels/delegation mutations require the corresponding write capability. A plugin with `read_headers` but not `write_headers` cannot modify HTTP headers.

**Layer 4 — Filtered slot preservation:** Slots hidden from the guest (filtered out pre-invocation) are preserved unchanged in the result.

**Rationale:** The WASM boundary is a trust boundary. Unlike native plugins (which run in-process and are trusted to some degree), WASM plugins may be third-party. The 4-layer model ensures that even a fully compromised guest cannot escalate privileges beyond its declared capabilities.

### 11.7 Fail-Closed on Decode Errors

**Decision:** If a custom payload intended for a declared handler fails to deserialize, the plugin returns a deny violation (`wasm_payload_decode_error`), not an allow.

**Rationale:** Silently allowing on a decode failure would skip whatever security check this plugin enforces. If an attacker can craft a payload that causes a parse error, they could bypass the plugin entirely. Failing closed ensures the worst case is a false deny (operational disruption), not a false allow (security bypass).

### 11.8 Credential Exclusion from WIT Types

**Decision:** Fields marked `#[serde(skip)]` on native types (raw tokens, bearer tokens, token bytes) are excluded from the WIT type definitions entirely — they do not exist in the schema.

**Rationale:** Credential material should never cross the sandbox boundary. Even with capability gating, a compromised WASM guest could exfiltrate tokens through side channels (timing, memory patterns). By excluding credentials at the schema level, there is no path — intentional or accidental — for tokens to enter the guest's address space.

### 11.9 Feature-Flag-Per-Plugin Binary

**Decision:** Each plugin compiles to a separate `.wasm` binary via Cargo feature flags. The SDK crate has 13+ features, one per plugin.

**Rationale:** The WIT Component Model exports a single world per component. A component can only export one `handle-hook` function. Multiple plugins in one binary would require a dispatch layer inside the guest — adding complexity and defeating the isolation model. One binary per plugin gives clean isolation: each has its own Store, memory space, and fault domain.

**Consequence:** Build commands require `--features <plugin> --no-default-features` and produce one `.wasm` artifact per invocation.

### 11.10 Macro-Driven SDK (`register_wasm_plugin!`)

**Decision:** Plugin authors never touch WIT types directly. The `register_wasm_plugin!` macro generates the complete `Guest` impl, including payload routing, type conversion, and the synchronous async executor.

**Rationale:** The WIT-generated types are mechanically derived and verbose. Plugin authors should write standard `HookHandler<H>` implementations (identical to native plugins) and get WASM compatibility for free. This lowers the barrier to entry and ensures all WASM plugins follow the same dispatch pattern.

**Generated code includes:**
- `Guest::handle_hook()` with match arms for each payload variant
- Compile-time dispatch via `downcast_ref` (CMF) and `payload_type_name()` matching (Custom)
- `__block_on()` — a trivial poll-loop for driving the handler's `async` future synchronously

### 11.11 Synchronous Async Executor (`__block_on`)

**Decision:** WASM plugins use a no-op waker poll loop to drive `HookHandler::handle()` futures to completion synchronously.

**Rationale:** WASM is single-threaded with no ambient async runtime (no tokio, no epoll). However, `HookHandler` is an `async_trait` for API consistency with native plugins. In practice, WASM handlers resolve on the first `poll()` since they cannot await network or timers directly. The trivial executor avoids pulling in an async runtime dependency that cannot function in WASM.

**Trade-off:** If a handler ever yields `Pending` without external stimulus (impossible today), the loop spin-waits until fuel is exhausted. This is acceptable because WASM handlers are designed to be non-blocking.

### 11.12 Network Allowlist via WASI HTTP Hooks

**Decision:** Outbound HTTP requests are intercepted at the `WasiHttpHooks::send_request()` level and checked against a per-plugin hostname allowlist. Requests to non-allowed hosts return `ErrorCode::HttpRequestDenied`.

**Rationale:** Importing `wasi:http/outgoing-handler` enables HTTP but does not inherently restrict destinations. The `NetworkPolicy` hook provides a clean interception point before any network I/O occurs. Matching is by exact hostname or subdomain (e.g., `api.example.com` matches allowed host `example.com`).

**Consequence:** Network policy errors surface as `PluginError::Execution { code: "network_denied" }` — distinguishable from other failures for accurate error reporting.

### 11.13 Filesystem via WASI Preopens (No World-Level Import)

**Decision:** Filesystem access is controlled by WASI preopened directories in the Store context, not by importing `wasi:filesystem` at the WIT world level.

**Rationale:** Importing filesystem interfaces at the world level makes them available unconditionally. Preopens are strictly additive and can be configured per-plugin: a plugin with no preopens has zero filesystem visibility regardless of what the WIT world declares. This gives operators fine-grained path-level control.

### 11.14 JSON-as-String for Recursive/Complex WIT Fields

**Decision:** Fields that are recursive or structurally complex (e.g., `prompt-result.messages`, `tool-call.arguments`, `context entries`) are serialized as JSON strings in the WIT interface.

**Rationale:** WIT does not support recursive types, self-referential structures, or arbitrary-depth nesting. Rather than flattening these into deeply nested WIT records (which would be brittle and hard to evolve), they are encoded as JSON strings. The guest deserializes them locally. This is an explicit trade-off: slightly higher runtime cost for schema flexibility.

### 11.15 Copy-on-Write Extension Mutation Model

**Decision:** The host creates a CoW copy of extensions before passing to the guest. On return, only mutable slots that the guest was authorized to see are overlaid back. Immutable slots preserve their original Arc pointers.

**Rationale:** The executor's mutation model requires that a plugin's modifications are validated before being applied. By operating on a copy, the original is never corrupted — even if validation rejects all changes. This also enables the immutable-tier check (Arc pointer identity comparison).

### 11.16 Cross-Invocation State via WASM Linear Memory

**Decision:** Module-level `static` variables in the guest persist across invocations because the Store (and thus linear memory) is kept alive between calls. The `OnceLock` pattern provides lazy initialization.

**Rationale:** Some plugins need initialization state (config parsing, connection caches, lookup tables) that should not be rebuilt on every call. Since each plugin has a dedicated Store that lives for the factory's lifetime, linear memory serves as persistent storage naturally. No explicit state-management API is needed.

**Constraint:** The guest struct is `Default::default()`-constructed on each call — instance fields do not persist. Only module-level statics survive across invocations.

### 11.17 WIT Keyword Workarounds

**Decision:** Several Rust type names conflict with WIT keywords. These are renamed at the WIT level:
- `Resource` (Rust enum) → `%resource` (WIT escaped keyword)
- `Return` (enum variant) → `return-complete` (WIT rename)
- `Resource` (struct) → `resource-info` (WIT rename)

**Rationale:** WIT reserves `resource` and `return` as keywords. Rather than renaming the Rust types (which would break the native API), the WIT schema uses escaping or alternative names. The conversion layer maps between them.

### 11.18 Structured Host Logging via WIT Import

**Decision:** Guest plugins log through a WIT-imported `host-logging` interface that routes to the host's `tracing` subscriber with a `plugin=<name>` span field. A `cpex_log!` macro provides ergonomic formatting.

**Rationale:** Guest `eprintln!` goes to the host's inherited stdio — unstructured, unattributed, and lost in production. The host-logging import gives structured logs that participate in the operator's observability stack (filtering by plugin name, log level, etc.). In `#[cfg(test)]` mode, the import doesn't exist, so the macro falls back to `eprintln!`.

### 11.19 Error Classification via String Matching

**Decision:** Wasmtime errors are classified into `PluginError` variants by pattern-matching on the error message string (e.g., `"epoch deadline"` → `Timeout`, `"all fuel consumed"` → `Execution { code: "fuel_exhausted" }`).

**Rationale:** Wasmtime does not expose structured error types for all failure modes. The error message is the only reliable signal for distinguishing timeout vs. fuel exhaustion vs. memory limit vs. trap. This enables the executor to apply correct `on_error` policies (circuit breakers, timeout logging, error aggregation) per failure type.

**Acknowledged limitation:** This is fragile across wasmtime version upgrades if error messages change. A future improvement would be to match on wasmtime's `Trap` enum variants where available.

### 11.20 Deny-All Default Policy

**Decision:** When no `sandbox_policy` is configured (or all allowlists are empty), the plugin runs in a fully locked-down sandbox: no filesystem, no network, no environment variables. Resource limits default to unlimited (wasmtime defaults).

**Rationale:** Secure-by-default. An operator who forgets to configure a policy gets maximum isolation, not maximum access. Plugins that need external access must explicitly declare it — the configuration is the audit trail.

### 11.21 Type-Erased Payload Registry

**Decision:** The `PayloadSerializerRegistry` maps `TypeId` → `(type_name, serialize_fn, deserialize_fn)` using closures that capture the concrete type. It is built once at factory creation and shared immutably.

**Rationale:** The `WasmBridgeHandler` receives `&dyn PluginPayload` (type-erased). It needs to:
1. Determine if the payload type is known
2. Serialize it to a type-discriminated byte format
3. Later, deserialize the guest's returned custom payload back to a concrete type

The registry solves this with O(1) `TypeId` lookup and O(1) `type_name` lookup, without requiring the handler to know about every possible payload type at compile time.

### 11.22 Unhandled Payloads Return Allow

**Decision:** If the guest receives a payload variant it has no handler for (e.g., a CMF hook plugin receiving a Delegation payload), it returns `continue_processing: true` with no modifications — equivalent to a no-op allow.

**Rationale:** Consistent with native plugin behavior. A plugin is only registered for specific hooks. If the dispatcher sends it a payload type it doesn't handle (which can happen during pipeline evolution), silently allowing is correct — the plugin is not responsible for that payload type.

**Contrast with 11.7:** Decode errors on a _declared_ handler fail closed. _Undeclared_ payload types pass through. The distinction is: "I handle this type but the data is corrupt" vs. "this type is not my responsibility."

### 11.23 Extensions Record with 11 Typed Slots + Custom Escape Hatch

**Decision:** The WIT `extensions` record has 11 explicitly typed optional slots (request, security, http, meta, agent, mcp, completion, provenance, llm, framework, delegation) plus a `custom: option<string>` for arbitrary JSON.

**Rationale:** Typed slots give the guest structured access to the most common extension data without JSON parsing. The `custom` slot enables forward-compatibility: new extension types can be added without a WIT schema change (at the cost of losing type safety for that slot).

**Trade-off:** The custom slot is unrestricted by the capability model — any plugin can read/write it. This is by design: custom extensions are application-specific and cannot be pre-categorized into the capability taxonomy.

### 11.24 WASI P2 (Preview 2) as the Target Platform

**Decision:** Target `wasm32-wasip2` and use WASI P2 interfaces (version 0.2.6) for all host capabilities.

**Rationale:** WASI P2 provides the Component Model, typed interfaces, and the `outgoing-handler` HTTP pattern. WASI P1 (preview 1) uses a POSIX-like model that doesn't support typed imports/exports or the Component Model. P2 is required for `wit-bindgen` and the `wasmtime::component` API. The 0.2.6 version is the latest stable specification at time of implementation.

### 11.25 Mutex-Protected SandboxManager

**Decision:** Each `WasmBridgeHandler` holds an `Arc<Mutex<SandboxManager>>`. Invocations acquire the lock before calling into WASM.

**Rationale:** A wasmtime `Store` is `!Sync` — it cannot be shared across threads. The Mutex serializes access. Under concurrent load, this means one plugin processes one request at a time (serial execution per plugin). This is an explicit trade-off: simplicity and safety over throughput.

**Future path:** Instance pooling (multiple Stores per plugin, round-robin dispatch) would remove this bottleneck without changing the security model.
