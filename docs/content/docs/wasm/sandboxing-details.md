---
title: "Sandboxing Details"
weight: 50
---

# Sandboxing Details

Every WASM plugin runs inside a Wasmtime sandbox with **deny-by-default** policies. This page documents all sandboxing dimensions, permission levels, and agentic scenarios where each applies.

## Overview of sandbox layers

| Layer | What it controls | Default |
|-------|-----------------|---------|
| Filesystem | Directory/file preopens with permission levels | No access |
| Environment | Which env vars are visible inside the sandbox | None visible |
| Network | Outbound HTTP filtered by host/port/scheme/method | All blocked |
| Resources | CPU fuel, wall-clock timeout, memory ceiling | Engine defaults |

All layers compose — a plugin can have filesystem access but no network, or network access but no filesystem. Each is configured independently in the `sandbox` block of the plugin's YAML config.

---

## Filesystem permissions

Six permission levels control what a plugin can do with preopened directories:

### 1. `read-only`

**Grants:** list directory, read file contents  
**Denies:** write, create, delete

```yaml
filesystem:
  - dir: "./data/rules"
    permission: read-only
```

**Agentic scenario:** A policy-evaluation plugin that reads rule definitions at startup. The plugin can inspect rule files but cannot modify them, preventing a compromised plugin from altering its own governance rules.

### 2. `full-access`

**Grants:** list, read, write, create, delete — all operations  
**Denies:** nothing within the preopened path

```yaml
filesystem:
  - dir: "./data/cache"
    permission: full-access
```

**Agentic scenario:** A caching plugin that stores computed results. The agent orchestrator grants full access to a cache directory so the plugin can create, update, and evict cache entries autonomously.

### 3. `drop-box`

**Grants:** write (create new files, append)  
**Denies:** list directory, read file contents

```yaml
filesystem:
  - dir: "./data/audit"
    permission: drop-box
```

**Agentic scenario:** An audit-logging plugin that writes compliance records. The plugin can emit audit entries but cannot read back previous logs, preventing data exfiltration through the audit channel. Even if compromised, it cannot enumerate what other plugins have logged.

### 4. `fixed-mutable`

**Grants:** read existing files, overwrite existing files  
**Denies:** create new files, create directories, delete

```yaml
filesystem:
  - dir: "./data/counters"
    permission: fixed-mutable
```

**Agentic scenario:** A rate-limiting plugin that maintains counters in pre-created files. The plugin can read and update counter values but cannot create arbitrary new files, bounding its filesystem footprint to a known set.

### 5. `list-only`

**Grants:** enumerate filenames in the directory  
**Denies:** read file contents, write, create, delete

```yaml
filesystem:
  - dir: "./data/plugins"
    permission: list-only
```

**Agentic scenario:** A plugin-discovery agent that scans available plugins by filename convention. It can see what plugins exist without reading their code or config, limiting information exposure to structural metadata only.

### 6. `private-scratch`

**Grants:** write new files, read own files  
**Denies:** list directory (cannot enumerate other files)

```yaml
filesystem:
  - dir: "./data/scratch"
    permission: private-scratch
```

**Agentic scenario:** A multi-tenant plugin where each invocation writes temporary working files. The plugin can create and read back its own files but cannot discover files left by other invocations or plugins sharing the same scratch space.

### Permission summary table

| Permission | list | read | write | create | delete |
|-----------|------|------|-------|--------|--------|
| read-only | yes | yes | no | no | no |
| full-access | yes | yes | yes | yes | yes |
| drop-box | no | no | yes | yes | no |
| fixed-mutable | yes | yes | yes | no | no |
| list-only | yes | no | no | no | no |
| private-scratch | no | yes | yes | yes | no |

---

## Environment variable permissions

By default, **no environment variables** are visible inside the WASM sandbox. The host's `build_wasi_context` only injects variables explicitly listed in `allowed_env` — it never calls `inherit_env()`.

### Configuration

```yaml
sandbox:
  env_vars:
    - APP_TOKEN
    - LOG_LEVEL
    - DEPLOYMENT_ENV
```

### What gets blocked

Any variable NOT in the `allowed_env` list is invisible to the guest. Common variables hidden by default:

| Variable | Why it's hidden |
|----------|----------------|
| `HOME` | Reveals host filesystem structure |
| `PATH` | Exposes installed tooling |
| `SECRET_API_KEY` | Credential leakage |
| `AWS_SECRET_ACCESS_KEY` | Cloud credential leakage |
| `DATABASE_URL` | Infrastructure topology |

### Agentic scenario

An agent orchestrator runs multiple third-party plugins. Each plugin needs only its own API token (`PLUGIN_X_TOKEN`) and a log level. By allowlisting only those two variables, a compromised plugin cannot harvest credentials for other services, even if the host process has them in its environment.

---

## Network permissions

Network access is controlled via WASI HTTP (`wasi:http/outgoing-handler`). Raw TCP/UDP sockets are not available in WASI P2.

### Default: deny-all

With no `network` config, all outbound HTTP requests are blocked by the `NetworkPolicy` implementation of `WasiHttpHooks`.

### Configuration

```yaml
sandbox:
  network:
    - host: "api.example.com"
      ports: [443]
      schemes: ["https"]
      methods: ["GET", "POST"]

    - host: "*.internal.corp"
      ports: []              # empty = any port
      schemes: ["https"]
      methods: []            # empty = any method

    - host: "telemetry.vendor.io"
      ports: [443]
      schemes: ["https"]
      methods: ["POST"]
```

### Rule fields

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `host` | yes | — | Exact match or wildcard (`*.example.com`) |
| `ports` | no | any | Allowed port numbers |
| `schemes` | no | `["https"]` | Allowed URL schemes |
| `methods` | no | any | Allowed HTTP methods |

### Enforcement behavior

The `NetworkPolicy` checks each outbound request against all rules. A request is allowed if **any** rule matches on all four dimensions (host AND port AND scheme AND method). If no rule matches, the request is denied and the plugin receives an error.

### Wildcard matching

`*.example.com` matches `api.example.com` and `staging.api.example.com` but NOT `example.com` itself.

### Agentic scenarios

**Remote authorization:** A plugin calls an external PDP (Policy Decision Point) to authorize tool invocations. Network rules restrict it to exactly one host on HTTPS port 443 with POST only — preventing it from exfiltrating data to other endpoints.

**Telemetry only:** A metrics plugin can POST to a telemetry endpoint but cannot make GET requests (which might fetch attacker-controlled instructions).

**Internal services:** Wildcard `*.internal.corp` allows the plugin to reach any internal microservice while blocking all external traffic.

---

## Resource permissions

Resource limits prevent plugins from consuming unbounded CPU, memory, or wall-clock time.

### Configuration

```yaml
sandbox:
  resources:
    max_fuel: 500_000_000        # Instruction budget
    max_execution_time_ms: 5000  # Wall-clock timeout
    max_memory_bytes: 10_485_760 # 10 MB memory ceiling
    max_instances: 10            # Component instances
    max_tables: 10               # Table elements
```

### Fuel (CPU budget)

Fuel is Wasmtime's instruction counter. Each WASM instruction consumes one unit of fuel. When fuel runs out, execution traps immediately.

| Fuel budget | Approximate workload |
|-------------|---------------------|
| 100,000,000 | Simple validation (string checks, JSON field access) |
| 500,000,000 | Moderate computation (parsing, hashing, policy evaluation) |
| 1,000,000,000 | Heavy computation (cryptographic operations, complex transforms) |

**Agentic scenario:** A validation plugin should finish in microseconds. Setting fuel to 100M ensures a bug (infinite loop, accidental recursion) traps before consuming noticeable CPU, protecting the host's throughput.

### Epoch timeout (wall-clock)

The shared engine's epoch ticker increments every 1ms. Each `Store` has a deadline set before invocation. If the epoch exceeds the deadline, execution traps.

This catches scenarios fuel alone cannot: blocking I/O, sleep-like patterns, and WASI calls that don't consume fuel.

**Agentic scenario:** A plugin making an outbound HTTP call might hang if the remote server is unresponsive. The epoch timeout (e.g., 5000ms) ensures the plugin is killed regardless of whether it's burning fuel or waiting on I/O.

### Memory ceiling

`max_memory_bytes` sets the upper bound on the plugin's linear memory growth. Attempting to grow past this limit traps the plugin.

**Agentic scenario:** A plugin processing user input could be tricked into allocating unbounded memory (zip bomb, recursive JSON). The memory ceiling prevents a single plugin from exhausting host memory.

### What happens on limit violation

| Limit | Error variant | Behavior |
|-------|--------------|----------|
| Fuel exhausted | `PluginError::FuelExhausted` | Immediate trap, store dropped |
| Epoch timeout | `PluginError::Timeout` | Immediate trap, store dropped |
| Memory exceeded | `PluginError::MemoryLimit` | Trap on `memory.grow`, store dropped |

In all cases, the `Store` (and all plugin memory) is dropped after the trap. The next invocation starts fresh.
