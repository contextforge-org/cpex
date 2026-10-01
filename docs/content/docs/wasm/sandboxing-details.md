---
title: "Sandboxing Details"
weight: 50
---

# Sandboxing Details

Every WASM plugin runs inside a [Wasmtime](https://wasmtime.dev/) sandbox with **deny-by-default** policies. This page documents all sandboxing dimensions, permission levels, and agentic scenarios where each applies.

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

Six permission levels control what a plugin can do with preopened directories. These map to Wasmtime's [`DirPerms`](https://docs.rs/wasmtime-wasi/latest/wasmtime_wasi/filesystem/struct.DirPerms.html) and [`FilePerms`](https://docs.rs/wasmtime-wasi/latest/wasmtime_wasi/filesystem/struct.FilePerms.html) flags.

### 1. `read-only`

**DirPerms:** `READ` | **FilePerms:** `READ`

**Grants:** list directory, read file contents  
**Denies:** write, create, delete

```yaml
filesystem:
  - dir: "./data/rules"
    permission: read-only
```

**Agentic scenario:** A policy-evaluation plugin that reads rule definitions at startup. The plugin can inspect rule files but cannot modify them, preventing a compromised plugin from altering its own governance rules.

### 2. `full-access`

**DirPerms:** `READ | MUTATE` | **FilePerms:** `READ | WRITE`

**Grants:** list, read, write, create, delete — all operations  
**Denies:** nothing within the preopened path

```yaml
filesystem:
  - dir: "./data/cache"
    permission: full-access
```

**Agentic scenario:** A caching plugin that stores computed results. The agent orchestrator grants full access to a cache directory so the plugin can create, update, and evict cache entries autonomously.

### 3. `drop-box`

**DirPerms:** `MUTATE` | **FilePerms:** `WRITE`

**Grants:** create directories, delete directories  
**Denies:** list directory, read files, write files (Wasmtime's [`open_at`](https://docs.rs/wasmtime-wasi/latest/wasmtime_wasi/) requires `DirPerms::READ` to open any file, so file-level I/O is denied even though `FilePerms::WRITE` is set)

```yaml
filesystem:
  - dir: "./data/audit"
    permission: drop-box
```

**Agentic scenario:** An audit-logging plugin that needs to create directory structures for organizing audit entries. The plugin can create subdirectories but cannot read back any file contents, preventing data exfiltration. This is primarily useful for directory-level operations rather than file writes.

> **Note:** Despite the name, `drop-box` cannot write to *files* in practice due to wasmtime's permission model where `open_at` requires `DirPerms::READ`. For file-write-only access, use `private-scratch` instead.

### 4. `fixed-mutable`

**DirPerms:** `READ` | **FilePerms:** `READ | WRITE`

**Grants:** list directory, read file contents  
**Denies:** write files, create files, create directories, delete (Wasmtime's [`open_at`](https://docs.rs/wasmtime-wasi/latest/wasmtime_wasi/) checks `DirPerms::MUTATE` before `FilePerms::WRITE`, so file writes require `MUTATE` on the directory regardless)

```yaml
filesystem:
  - dir: "./data/counters"
    permission: fixed-mutable
```

**Agentic scenario:** In practice, this behaves like `read-only` at the file level. The `FilePerms::WRITE` flag has no effect without `DirPerms::MUTATE`. This permission exists for forward-compatibility with runtimes that may decouple directory and file mutation permissions in the future.

> **Note:** In the current Wasmtime implementation, `fixed-mutable` is effectively identical to `read-only` for file operations. Use `full-access` if you need actual write capability.

### 5. `list-only`

**DirPerms:** `READ` | **FilePerms:** empty

**Grants:** enumerate filenames in the directory  
**Denies:** read file contents, write, create, delete

```yaml
filesystem:
  - dir: "./data/plugins"
    permission: list-only
```

**Agentic scenario:** A plugin-discovery agent that scans available plugins by filename convention. It can see what plugins exist without reading their code or config, limiting information exposure to structural metadata only.

### 6. `private-scratch`

**DirPerms:** `MUTATE` | **FilePerms:** `READ | WRITE`

**Grants:** create new files, write to files, read own files  
**Denies:** list directory (cannot enumerate other files, since `DirPerms::READ` is absent)

```yaml
filesystem:
  - dir: "./data/scratch"
    permission: private-scratch
```

**Agentic scenario:** A multi-tenant plugin where each invocation writes temporary working files. The plugin can create and read back its own files (if it knows the path) but cannot discover files left by other invocations or plugins sharing the same scratch space.

### Permission summary table

| Permission | DirPerms | FilePerms | list | read files | write files | create dir | delete |
|-----------|----------|-----------|------|-----------|-------------|------------|--------|
| `read-only` | READ | READ | yes | yes | no | no | no |
| `full-access` | READ+MUTATE | READ+WRITE | yes | yes | yes | yes | yes |
| `drop-box` | MUTATE | WRITE | no | no | no* | yes | yes |
| `fixed-mutable` | READ | READ+WRITE | yes | yes | no* | no | no |
| `list-only` | READ | (empty) | yes | no | no | no | no |
| `private-scratch` | MUTATE | READ+WRITE | no | yes** | yes | yes | no |

\* Wasmtime's `open_at` requires `DirPerms::READ` to open files and `DirPerms::MUTATE` for write operations, so these are effectively denied despite `FilePerms` flags.  
\** Can read files if the path is known (cannot list/discover paths).

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

Network access is controlled via [WASI HTTP](https://github.com/WebAssembly/wasi-http) (`wasi:http/outgoing-handler`). Raw TCP/UDP sockets are not available in WASI P2.

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
| `ports` | no | any | Allowed port numbers. Omitted or empty = any port. When a port list is specified and the request URI has no explicit port, it is inferred from scheme (443 for HTTPS, 80 for HTTP). |
| `schemes` | no | `["https"]` | Allowed URL schemes |
| `methods` | no | any | Allowed HTTP methods (case-insensitive) |

### How empty lists work (two-level model)

The sandbox policy uses a two-level allowlist model:

- **Top-level lists** (`filesystem`, `network`, `env_vars`) are **grants** — each entry opts a resource in. An empty top-level list means nothing is granted (deny-all).
- **Fields within a rule** (`ports`, `methods`) are **filters on an already-granted host** — they narrow the grant. An empty filter means "don't restrict this dimension" (allow any value).

```yaml
# Top-level empty = deny-all (no hosts allowed)
network: []

# Rule present = host granted; empty sub-fields = unrestricted on those dimensions
network:
  - host: "api.example.com"
    ports: []       # any port (not "no ports")
    methods: []     # any method (not "no methods")
```

This means: you opt-in at the rule level (adding the rule is the grant), then optionally restrict port/scheme/method within that grant.

### Enforcement behavior

The `NetworkPolicy` checks each outbound request against all rules. A request is allowed if **any** rule matches on all four dimensions (host AND port AND scheme AND method). If no rule matches, the request is denied with `ErrorCode::HttpRequestDenied`.

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
    max_fuel: 500_000_000        # Instruction budget per invocation
    max_execution_time_ms: 5000  # Wall-clock timeout per invocation
    max_memory_bytes: 10_485_760 # 10 MB memory ceiling
    max_instances: 10            # Component instances
    max_tables: 10               # Table elements
```

### Fuel (CPU budget)

[Fuel](https://docs.wasmtime.dev/api/wasmtime/struct.Store.html#method.set_fuel) is Wasmtime's instruction counter. Each WASM instruction consumes one unit of fuel. When fuel runs out, execution traps immediately. Fuel is **reset per invocation** — each call gets a fresh budget.

| Fuel budget | Approximate workload |
|-------------|---------------------|
| 100,000,000 | Simple validation (string checks, JSON field access) |
| 500,000,000 | Moderate computation (parsing, hashing, policy evaluation) |
| 1,000,000,000 | Heavy computation (cryptographic operations, complex transforms) |

**Agentic scenario:** A validation plugin should finish in microseconds. Setting fuel to 100M ensures a bug (infinite loop, accidental recursion) traps before consuming noticeable CPU, protecting the host's throughput.

### Epoch timeout (wall-clock)

The shared engine's [epoch ticker](https://docs.wasmtime.dev/api/wasmtime/struct.Engine.html#method.increment_epoch) increments every 1ms. Each invocation sets a [deadline](https://docs.wasmtime.dev/api/wasmtime/struct.Store.html#method.set_epoch_deadline) before calling the guest. If the epoch exceeds the deadline, execution traps.

This catches scenarios fuel alone cannot: blocking I/O, sleep-like patterns, and WASI calls that don't consume fuel.

**Agentic scenario:** A plugin making an outbound HTTP call might hang if the remote server is unresponsive. The epoch timeout (e.g., 5000ms) ensures the plugin is interrupted regardless of whether it's burning fuel or waiting on I/O.

### Memory ceiling

`max_memory_bytes` sets the upper bound on the plugin's [linear memory](https://docs.wasmtime.dev/api/wasmtime/struct.Memory.html) growth. Attempting to grow past this limit traps the plugin.

**Agentic scenario:** A plugin processing user input could be tricked into allocating unbounded memory (zip bomb, recursive JSON). The memory ceiling prevents a single plugin from exhausting host memory.

### What happens on limit violation

| Limit | Error produced | Store state |
|-------|---------------|-------------|
| Fuel exhausted | `PluginError::Execution { code: "fuel_exhausted" }` | Store persists — next invocation resets fuel and retries |
| Epoch timeout | `PluginError::Timeout { timeout_ms }` | Store persists — next invocation resets deadline and retries |
| Memory exceeded | `PluginError::Execution { code: "memory_limit" }` | Store persists — but memory may be at ceiling, affecting future calls |

The [Store](https://docs.wasmtime.dev/api/wasmtime/struct.Store.html) is **not dropped** after a trap. The `SandboxManager` returns an error, and the executor applies the plugin's `on_error` policy (`Fail` / `Ignore` / `Disable`). On the next invocation, fuel and epoch are reset fresh — but linear memory and heap state from before the trap remain.

> **Note on memory traps:** After a memory-limit trap, the Store's linear memory remains at its high-water mark. If the plugin consistently needs more memory than the ceiling allows, it will trap on every invocation. Consider increasing `max_memory_bytes` or investigating the plugin's allocation patterns.

---

## Complete YAML example

A full sandbox policy combining all layers:

```yaml
plugins:
  - name: remote-authz
    kind: "wasm://remote-authz.wasm"
    hooks:
      - cmf.tool_pre_invoke
    capabilities:
      - read_subject
      - read_roles
      - read_labels
      - append_labels
    config:
      sandbox:
        # Filesystem: read rules, write audit logs
        filesystem:
          - dir: "./data/authz-rules"
            permission: read-only
          - dir: "./data/audit-logs"
            permission: private-scratch

        # Network: call the PDP, nothing else
        network:
          - host: "pdp.internal.corp"
            ports: [443]
            schemes: ["https"]
            methods: ["POST"]

        # Environment: only the PDP token
        env_vars:
          - PDP_API_TOKEN

        # Resources: moderate budget for network I/O
        resources:
          max_fuel: 500_000_000
          max_execution_time_ms: 10000    # 10s (allows network latency)
          max_memory_bytes: 5_242_880     # 5 MB
```

This plugin can:
- Read authorization rules from `./data/authz-rules`
- Write audit entries to `./data/audit-logs` (cannot list or read back)
- Make HTTPS POST requests to `pdp.internal.corp:443` only
- Read the `PDP_API_TOKEN` environment variable
- Use up to 500M instructions and 5 MB of memory per invocation
- Run for up to 10 seconds (to accommodate network round-trips)

This plugin cannot:
- Access any other filesystem path
- Make requests to any other host, port, scheme, or method
- Read any other environment variable
- Use more than 5 MB of memory or exceed 10s wall-clock time
