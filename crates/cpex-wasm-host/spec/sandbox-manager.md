# Sandbox Manager — Design Specification

## Overview

The Sandbox Manager is the host-side orchestrator for WASM plugin instances in the CPEX framework. It manages the full lifecycle of plugins — from compilation and instantiation through invocation and teardown — while enforcing per-plugin security policies and resource constraints.

Each plugin runs in its own isolated sandbox with a dedicated `Store`, meaning one plugin cannot access another's memory, filesystem, network, or environment variables.

---

## Architecture

```
                    +---------------------+
                    |   SandboxManager    |
                    |                     |
                    |  engine (shared)    |
                    |  linker (shared)    |
                    |  plugins: HashMap   |
                    +--------+------------+
                             |
              +--------------+--------------+
              |                             |
    +---------v----------+       +---------v----------+
    |  PluginInstance A   |       |  PluginInstance B   |
    |                     |       |                     |
    |  Store<PluginState> |       |  Store<PluginState> |
    |  Component (wasm)   |       |  Component (wasm)   |
    |  Plugin handle      |       |  Plugin handle      |
    +---------------------+       +---------------------+
              |                             |
    +---------v----------+       +---------v----------+
    |   PluginState       |       |   PluginState       |
    |                     |       |                     |
    |  WasiCtx            |       |  WasiCtx            |
    |  WasiHttpCtx        |       |  WasiHttpCtx        |
    |  PolicyHttpHooks    |       |  PolicyHttpHooks    |
    |  StoreLimits        |       |  StoreLimits        |
    |  ResourceTable      |       |  ResourceTable      |
    +---------------------+       +---------------------+
```

---

## Capabilities

### Lifecycle Management

| Operation | Description |
|-----------|-------------|
| `new()` | Create manager with shared engine (fuel + epoch enabled) and pre-linked WASI + HTTP interfaces |
| `load_plugin()` | Compile wasm component, build sandboxed context from policy, instantiate, store |
| `invoke()` | Call `handle_hook` on a loaded plugin with per-invocation fuel/epoch reset |
| `unload_plugin()` | Drop a plugin instance, releasing all resources |
| `reload_plugin()` | Destroy and recreate a plugin with a new policy (clean slate) |
| `load_from_config()` | Batch-load all plugins defined in a YAML config file |
| `reload_from_config()` | Reconcile running plugins against a config file (add new, remove stale, reload changed) |
| `list_plugins()` | List currently loaded plugin names |

### Security Policy Enforcement

| Domain | Mechanism | Granularity |
|--------|-----------|-------------|
| **Filesystem** | WASI preopened directories with `DirPerms`/`FilePerms` | Per-directory read/write. No access to anything not preopened. |
| **Environment** | Only explicitly listed vars passed to `WasiCtxBuilder::env()` | Per-variable. Guest sees nothing else. |
| **Network (HTTP)** | `PolicyHttpHooks::send_request()` checks URI authority against allowlist | Per-hostname (including subdomain matching). Denied requests get `ErrorCode::HttpRequestDenied`. |
| **Network (sockets)** | WASI defaults deny all TCP/UDP unless explicitly enabled | Binary on/off at the socket layer |

### Resource Constraints

| Resource | Mechanism | Behavior on Limit |
|----------|-----------|-------------------|
| **Memory** | `StoreLimits::memory_size` via `Store::limiter()` | `memory.grow` traps (with `trap_on_grow_failure`) |
| **CPU (instructions)** | `Config::consume_fuel()` + `Store::set_fuel()` | Execution traps when fuel exhausted |
| **Wall-clock timeout** | `Config::epoch_interruption()` + background ticker (1ms) + `Store::set_epoch_deadline()` | Execution traps when deadline reached |
| **Instance count** | `StoreLimits::instances` | Instantiation fails if limit exceeded |
| **Table count** | `StoreLimits::tables` | Table creation fails if limit exceeded |

### Dynamic Policy Updates

- `reload_plugin(name, new_config)` — destroys existing instance and creates a new one with the updated policy
- `reload_from_config(path, wasm_dir)` — full reconciliation against a config file
- All state is reset on reload (clean slate)

---

## Limitations

### State Persistence Across Reloads

**The current implementation does not preserve plugin state on reload.** When a policy changes and the instance is recreated, all in-memory state (counters, caches, session data, intermediate computations) is lost.

Possible solutions (not yet implemented):

1. **Plugin-side serialize/deserialize** — Add `save-state` / `restore-state` exports to the WIT world. Before reload, host calls `save-state()` to get a byte buffer from the plugin, then passes it back via `restore-state(bytes)` after the new instance is created.

2. **Host-side key-value store** — Provide a host-imported `kv-store` interface (`get`, `set`, `delete`) that plugins use for persistent data. The store lives on the host and survives reloads transparently.

3. **Checkpoint/restore** — Snapshot the linear memory before teardown and restore it in the new instance. Fragile (layout may differ if wasm binary changes) and not supported natively by wasmtime.

### No Shared Memory Between Plugins

Each plugin has its own isolated `Store`. There is no shared-memory mechanism between plugins. Inter-plugin communication must go through the host (e.g., via extensions or a message bus).

### Single-Threaded Per-Plugin

Each `Store` is single-threaded. A plugin cannot be invoked concurrently from multiple tasks. If concurrent invocations are needed, multiple instances of the same plugin must be loaded (instance pooling is not yet implemented).

### Epoch Resolution

The epoch ticker runs at ~1ms granularity. Timeouts are accurate to within a few milliseconds, not microseconds. Very short timeouts (< 5ms) may not fire precisely.

### Fuel is Approximate

Fuel consumption does not map 1:1 to CPU instructions. Different wasm operations consume different amounts of fuel. The fuel budget provides a coarse-grained instruction limit, not a precise instruction count.

### No Hot-Patching of Policies

Filesystem preopens and environment variables are baked into the `WasiCtx` at construction time. There is no way to add/remove a preopen or env var on a running instance — a full reload is required for any policy change.

### Component Compilation is Not Cached

Each `load_plugin` call recompiles the wasm component from disk. For the same wasm binary loaded multiple times (e.g., instance pooling), the compiled `Component` should be cached and shared. This optimization is not yet implemented.

### No Graceful Shutdown

`unload_plugin` and `reload_plugin` drop the instance immediately. If the plugin is mid-execution (e.g., waiting on an HTTP response), the operation is aborted. There is no "drain" or "finish current request" mechanism.

### No Observability

The manager does not currently expose:
- Fuel consumed per invocation
- Memory usage per plugin
- Invocation latency metrics
- Error/trap counts

These would need to be added for production monitoring.

---

## Configuration Schema

```yaml
plugins:
  - name: identity-checker
    sandbox:
      version: wasm-p2
      policy:
        allowed_filesystem:
          - dir: /data
            permission: "read"      # read | write | mutate
          - file: /data/config.json
            permission: "read"
        allowed_network:
          - "httpbin.org"           # hostname allowlist
          - "api.example.com"
        allowed_env:
          - "PLUGIN_API_KEY"       # only these vars visible to guest
      resources:
        max_memory_bytes: 10485760   # 10 MB
        max_fuel: 1000000000         # instruction budget per invocation
        max_execution_time_ms: 5000  # wall-clock timeout
        max_instances: 10
        max_tables: 10
```

---

## Future Work

| Area | Description |
|------|-------------|
| State persistence | Plugin serialize/deserialize or host-side KV store |
| Instance pooling | Pre-warm multiple instances of the same plugin for concurrent invocations |
| Component caching | Cache compiled components to avoid recompilation on reload |
| Observability | Metrics export (fuel used, memory high-water, latency histograms) |
| Graceful shutdown | Drain in-flight requests before teardown |
| Inter-plugin communication | Host-mediated message passing between plugins |
| WASI capability negotiation | Plugin declares required capabilities, host validates against policy before loading |
| Audit logging | Log all policy-denied access attempts (env, fs, network) for security auditing |
