---
title: "Architecture"
weight: 20
---

# Architecture

How the WASM plugin host, Wasmtime sandbox, and guest plugins interact — from invocation to result validation.

## High-level flow

![CPEX WASM Invocation Pipeline](images/cpex_wasm_invocation_pipeline.png)

The diagram shows both the **request path** (blue, flowing down) and the **response path** (green, flowing up) through four layers:

### Request path (top → bottom)

1. **Your Code** → calls `PluginManager.invoke_named("hook_name", payload, extensions, ctx)`
2. **PluginManager** → routes the hook to matching plugin(s), dispatches to `WasmBridgeHandler`
3. **WasmBridgeHandler** → converts native Rust types to WIT types, acquires the Mutex, calls into SandboxManager
4. **Wasmtime Sandbox** → resets fuel + epoch deadline, then calls the guest's `handle-hook` export
5. **Guest Plugin** → executes handler logic, returns a `HookResult`

### Response path (bottom → top)

1. **Guest Plugin** → returns `HookResult` (allow, deny, or modify)
2. **Wasmtime Sandbox** → returns the result (or traps on fuel/epoch/memory limit)
3. **WasmBridgeHandler** → converts WIT types back to native (Arc-preserving `cow_copy`), validates modifications against capability policy, writes back context state. On error: classifies the trap into a typed `PluginError` (Timeout / Trap / FuelExhausted)
4. **PluginManager** → applies `OnError` policy, merges validated modifications into the pipeline
5. **Your Code** → receives a `(PipelineResult, BackgroundTasks)` tuple containing the final payload, extensions, allow/deny status, and any fire-and-forget tasks

---

## Component ownership

```
WasmPluginFactory
 ├── SharedEngine (Arc, one per factory)
 │    ├── wasmtime::Engine (compiled module cache)
 │    ├── wasmtime::Linker (WASI + host-logging wired up)
 │    └── Epoch ticker thread (1ms interval)
 │
 └── Per plugin:
      └── Arc<Mutex<SandboxManager>>
           ├── WasmPluginInstance
           │    ├── wasmtime::Store<WasmPluginState> (persists across calls)
           │    ├── Component instance (handle-hook export)
           │    ├── fuel_per_invocation (reset each call)
           │    └── epoch_deadline (reset each call)
           └── SandboxPolicy (filesystem, network, env, resources)
```

- All plugins from the same factory share one `SharedEngine` (and one epoch ticker thread)
- Each plugin gets its own `SandboxManager` with its own `Store` — plugins cannot see each other's memory
- The `Mutex` serializes concurrent calls to the **same** plugin; different plugins execute concurrently

---

## Key components

### SharedEngine

A single Wasmtime `Engine` shared across all plugins loaded by one factory. Holds compiled module caches and runs one background epoch-ticker thread that increments the epoch counter every 1ms, enabling wall-clock timeouts without per-plugin OS threads.

### SandboxManager

Owns the Wasmtime `Store` for a plugin. The Store **persists across invocations** — linear memory, module-level statics, and heap state survive between calls. Each invocation only resets fuel (instruction budget) and epoch deadline (wall-clock timeout).

Also builds the WASI context from sandbox policy (filesystem mounts, env vars, network hooks) and provides the `host-logging` import.

### WasmBridgeHandler

Implements `cpex-core`'s `AnyHookHandler` trait — the bridge between the framework's native Rust types and the WIT component-model types. Responsible for:

- Type conversion in both directions (native ↔ WIT)
- Mutex acquisition (one call at a time per plugin)
- Post-invocation validation of the guest's modifications
- Context writeback (local/global state)

### Type Conversions

A bidirectional translation layer (`conversions.rs`) that converts all native cpex-core types to WIT types and back. Key properties:

- **Full deep copy** — all data crosses by value, no zero-copy across the boundary
- **Arc preservation** — immutable extension slots preserve their Arc pointers via `cow_copy()`, enabling tamper detection
- **Credential exclusion** — raw tokens/secrets are never serialized into WASM memory
- **Filtered-slot awareness** — slots hidden by capability filtering are preserved unchanged on the return path

### PayloadSerializerRegistry

A type-erased registry that maps payload type discriminators to serialization logic. Enables custom payload types to cross the WASM boundary via the `custom-payload` variant without modifying the WIT interface.

---

## WIT interface

The guest/host contract is defined in `wit/world.wit` under the `cpex:plugin` package:

```wit
export handle-hook: func(
    hook-name: string,
    payload: hook-payload,
    extensions: extensions,
    ctx: plugin-context,
) -> hook-result;
```

**`hook-payload`** is a variant (tagged union):

| Variant | Payload type | Use case |
|---------|-------------|----------|
| `cmf` | `message-payload` | Tool calls, LLM input/output, resource fetches |
| `identity` | `identity-payload` | Identity resolution from tokens/headers |
| `delegation` | `delegation-payload` | Token delegation and attenuation |
| `custom` | `custom-payload` | User-defined payload types (opaque JSON bytes + type tag) |

**`hook-result`** tells the framework what to do next:

| Field | Type | Effect |
|-------|------|--------|
| `continue-processing` | `bool` | `false` halts the pipeline (deny) |
| `modified-payload` | `option<hook-payload>` | Replace the payload |
| `modified-extensions` | `option<extensions>` | Replace extensions |
| `modified-context` | `option<plugin-context>` | Update plugin context state |
| `violation` | `option<plugin-violation>` | Attach a policy violation (code + message) |
| `metadata` | `option<string>` | Attach diagnostics/telemetry metadata |

---

## Security model

### Six layers of defense

| Layer | What it does | What it prevents |
|-------|--------------|-----------------|
| Memory isolation | Separate linear memory per plugin | One plugin corrupting another or the host |
| WASI capability gating | Sandbox policy (deny-all default) | Unauthorized filesystem, network, or env access |
| Fuel limits | Instruction counter, reset per invocation | CPU exhaustion |
| Epoch timeouts | Background ticker + deadline | Infinite loops and blocking I/O |
| Pre-invocation filtering | Extension slots stripped before call | Plugin seeing unauthorized data |
| Post-invocation validation | Result checked on return | Plugin writing unauthorized modifications |

All layers are **deny-by-default**. A plugin with no sandbox policy config gets: no filesystem, no network, no env vars, default fuel, and default timeout.

### Post-invocation validation

After the guest returns, modifications pass through four checks:

| Check | Rule | On failure |
|-------|------|------------|
| Immutable tier | Certain extension slots (request, agent, mcp, completion, provenance, llm, framework, meta) must not be modified | Entire modification discarded |
| Monotonic tier | Security labels can only be added, never removed | Entire modification discarded |
| Write authorization | Modifications to HTTP headers, labels, or delegation chains require corresponding write capabilities | Entire modification discarded |
| Filtered slot preservation | Slots hidden from the guest must remain unchanged | Automatically preserved |

The executor then applies a second round of the same checks (defense-in-depth) before merging into the pipeline.

---

## Error handling

### Failure modes

| Failure | Result | Pipeline effect |
|---------|--------|-----------------|
| Epoch timeout | `PluginError::Timeout` | Plugin's `OnError` policy applies (Fail/Ignore/Disable) |
| Fuel exhausted | `PluginError::Execution { code: "fuel_exhausted" }` | Same |
| Memory limit exceeded | `PluginError::Execution { code: "memory_limit" }` | Same |
| Guest panic / trap | `PluginError::Execution { code: "wasm_trap" }` | Same |
| Network request denied | `PluginError::Execution { code: "network_denied" }` | Same |
| Custom payload decode error | Deny with `"wasm_payload_decode_error"` | Pipeline halted |
| Invalid extension modifications | Modifications silently discarded | Pipeline continues with original extensions |

### Fail-closed guarantees

- A guest that traps produces an error, never a silent allow
- A custom payload that fails to deserialize produces a deny
- Invalid extension modifications are discarded (original extensions preserved)

---

## Plugin lifecycle

| Phase | What happens |
|-------|--------------|
| Factory creation | `SharedEngine` created (Engine + Linker + epoch ticker thread) |
| Config load | YAML parsed; sandbox policy extracted per plugin |
| Compilation | `.wasm` binary compiled to native code via the engine |
| Store creation | `Store` created with WASI context, network policy, fuel/epoch config |
| Component instantiation | Component linked and instantiated (Store persists from here) |
| **Per-invocation:** | |
| Fuel/epoch reset | Fresh budget for each call (Store and memory persist) |
| Type conversion (out) | Native → WIT |
| Guest execution | `handle-hook` runs within budget |
| Type conversion (in) | WIT → Native (Arc-preserving) |
| Validation | Post-invocation checks |
| Merge | Executor merges validated modifications into pipeline |

The Store persists across invocations — this is how module-level `static` variables retain state between calls.

---

## Further reading

- [cpex-wasm-host (Host Runtime)]({{< relref "cpex-wasm-host" >}}) — implementation details, source file reference, configuration, and code examples
- [cpex-wasm-plugin (Guest SDK)]({{< relref "cpex-wasm-plugin" >}}) — writing plugins, the `register_wasm_plugin!` macro, and build commands
- [Sandboxing Details]({{< relref "sandboxing-details" >}}) — filesystem permission levels, network rules, and resource limits
