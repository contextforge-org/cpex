---
title: "Architecture"
weight: 20
---

# Architecture

How the WASM plugin host, Wasmtime sandbox, and guest plugins interact.

## High-level flow

```
┌─────────────┐
│  Your Code  │
└──────┬──────┘
       │ invoke("hook_name", payload, extensions, ctx)
       ▼
┌─────────────────────────────────────────────────────┐
│              PluginManager                           │
│  routes hook to matching plugin(s)                  │
└──────┬──────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────┐
│           WasmBridgeHandler                         │
│                                                     │
│  1. Convert native types → WIT types                │
│  2. Reset fuel counter + epoch deadline             │
│  3. Call into Wasmtime sandbox                      │
│  4. Convert WIT types → native types                │
│  5. Validate result against capability policy       │
└──────┬──────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────┐
│           Wasmtime Sandbox                          │
│                                                     │
│  • Isolated linear memory (per-plugin Store)        │
│  • Fuel budget (instruction limit)                  │
│  • Epoch timeout (wall-clock interrupt)             │
│  • Capability-filtered extensions                   │
│  • Gated WASI: filesystem / network / env           │
└──────┬──────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────┐
│           Guest Plugin (.wasm)                       │
│                                                     │
│  handle-hook(hook-name, payload, extensions, ctx)   │
│  → HookResult                                       │
└─────────────────────────────────────────────────────┘
```

## Key components

### SharedEngine

A single Wasmtime `Engine` shared across all plugins loaded by one `WasmPluginFactory`. The engine holds compiled module caches and runs one background epoch-ticker thread that periodically increments the epoch counter, enabling wall-clock timeouts without per-plugin OS threads.

### SandboxManager

Owns a Wasmtime `Store` per plugin invocation. Responsibilities:

- Configure fuel (instruction budget) and epoch deadline before each call
- Build the WASI context from the sandbox policy (filesystem mounts, env vars, network access)
- Trap the guest if it exceeds fuel or epoch limits
- Provide the `host-logging` import so guests can emit structured logs

### WasmBridgeHandler

Implements `cpex-core`'s `PluginHandler` trait. Bridges between the framework's native Rust types and the WIT component-model types that cross the WASM boundary. This layer also enforces capability filtering — if a plugin lacks a declared capability, corresponding extension fields are zeroed before the call and any modifications to them are discarded on return.

### PayloadSerializerRegistry

A type-erased registry that maps payload type discriminators (strings) to serialization/deserialization logic. This enables custom payload types to cross the WASM boundary without modifying the WIT interface — the `custom-payload` variant carries opaque bytes tagged with a type identifier that the registry resolves at runtime.

## WIT interface

The guest/host contract is defined in `wit/world.wit` under the `cpex:plugin` package. The single exported function:

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
| `custom` | `custom-payload` | User-defined payload types |

**`hook-result`** tells the framework what to do next:

| Variant | Effect |
|---------|--------|
| `continue-processing` | Pass through unchanged |
| `modified-payload` | Replace the payload |
| `modified-extensions` | Replace extensions |
| `modified-context` | Update plugin context state |
| `violation` | Block the request with a policy violation |
| `metadata` | Attach metadata without modifying the payload |

## Security model (5 layers)

1. **Memory isolation** — each plugin's linear memory is inaccessible to other plugins and the host process
2. **WASI capability gating** — filesystem, network, and environment access require explicit policy grants
3. **Fuel limits** — bounded computation prevents CPU exhaustion
4. **Epoch timeouts** — wall-clock deadlines catch blocking I/O and infinite loops
5. **Capability filtering** — extensions are masked based on declared plugin capabilities

All layers are **deny-by-default**. A plugin with no sandbox policy config gets: no filesystem, no network, no env vars, default fuel, and default timeout.

## Plugin lifecycle

1. **Factory registration** — `WasmPluginFactory` is registered with `PluginManager` for the `wasm://` URI scheme
2. **Config load** — YAML config is parsed; sandbox policy is extracted per plugin
3. **Compilation** — the `.wasm` module is compiled once by the shared engine (cached)
4. **Instantiation** — each invocation creates a fresh `Store` with fuel/epoch/WASI configured
5. **Execution** — `handle-hook` is called; the guest runs within its budget
6. **Result validation** — the bridge validates the result against capability policy
7. **Teardown** — the `Store` is dropped; all guest memory is freed
