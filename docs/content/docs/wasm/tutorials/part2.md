---
title: "Part 2: Sandboxing Demos"
weight: 20
---

# Part 2: Sandboxing Tutorials

> **Prerequisites:** Ensure `wasm32-wasip2` is installed (`rustup target add wasm32-wasip2`) and run all commands from `crates/cpex-wasm-host/`. See [Tutorials index]({{< relref "_index" >}}) for details.

## Tutorial 3: Filesystem Permissions

### Scenario

Your plugin needs access to the host filesystem — reading policy rules, writing audit logs, caching results — but you cannot give it unrestricted access. A compromised or buggy plugin should not be able to read secrets from unrelated directories, overwrite configuration, or enumerate files it has no business knowing about. You need granular, per-directory permission enforcement inside the WASM sandbox.

### Goal

Demonstrate all six WASI filesystem permission levels (`read-only`, `full-access`, `drop-box`, `fixed-mutable`, `list-only`, `private-scratch`) by exercising each permission against a set of directories. For every operation attempted, observe whether the sandbox allows or denies it — confirming that WASI-level enforcement prevents unauthorized filesystem access regardless of what the guest code tries to do.

---

**What you'll learn:** How the six filesystem permission levels enforce access control inside the WASM sandbox.

**Config** (`config/config_fs_sandbox_demo.yaml`):

```yaml
config:
  sandbox_policy:
    allowed_filesystem:
      - dir: examples/data/rules
        permission: read-only
      - dir: examples/data/cache
        permission: full-access
      - dir: examples/data/audit
        permission: drop-box
      - dir: examples/data/counters
        permission: fixed-mutable
      - dir: examples/data/plugins
        permission: list-only
      - dir: examples/data/scratch
        permission: private-scratch
```

**Test matrix:**

| Directory | Permission | Allowed ops | Denied ops |
|-----------|-----------|-------------|------------|
| `examples/data/rules` | read-only | list, read | write, create |
| `examples/data/cache` | full-access | list, read, write, create, delete | — |
| `examples/data/audit` | drop-box | write, create | list, read |
| `examples/data/counters` | fixed-mutable | read, overwrite | create dir |
| `examples/data/plugins` | list-only | list filenames | read contents |
| `examples/data/scratch` | private-scratch | write, read | list dir |

**Run it:**

```bash
make run-fs-demo
```

### Demo

{{< asciinema cast="https://asciinema.org/a/OtgiY1bYETduMHcl.cast" poster="npt:0:03" >}}

**What happens:**

The `fs-sandbox-demo.wasm` plugin is invoked multiple times, each time attempting different filesystem operations against directories configured with different permission levels.

**What to look for in the output:**

```
[ALLOW expected] operation=list_dir      path=examples/data/rules
→ ALLOW
[ALLOW expected] operation=read          path=examples/data/rules/policy.yaml
→ ALLOW
[DENY expected] operation=write         path=examples/data/rules/policy.yaml
→ DENY  [sandbox_violation]
[ALLOW expected] operation=write         path=examples/data/audit/event.log
→ ALLOW
[DENY expected] operation=list_dir      path=examples/data/audit
→ DENY  [sandbox_violation]
```

---

## Tutorial 4: Environment Variable Permissions

### Scenario

Your host process has environment variables containing API tokens, database URLs, and system paths. A WASM plugin may legitimately need an application token (e.g., `CPEX_APP_TOKEN`) to call downstream services, but it must never see `HOME`, `PATH`, or other sensitive variables that could leak host information or credentials. You need an explicit allowlist that controls exactly which variables are visible inside the sandbox.

### Goal

Demonstrate WASI environment variable isolation: only variables listed in `allowed_env` are injected into the sandbox context. The plugin calls `std::env::var()` for five different variables and observes that allowed ones return their values while all others return `Err(NotPresent)` — proving that nothing leaks implicitly from the host environment.

---

**What you'll learn:** How `allowed_env` controls variable visibility, ensuring plugins cannot access credentials they don't need.

**Config** (`config/config_env_sandbox_demo.yaml`):

```yaml
config:
  sandbox_policy:
    allowed_env:
      - CPEX_APP_TOKEN
      - CPEX_LOG_LEVEL
```

**Variables tested:**

| Variable | In `allowed_env`? | Result |
|----------|-------------------|--------|
| `CPEX_APP_TOKEN` | yes | Visible ✓ |
| `CPEX_LOG_LEVEL` | yes | Visible ✓ |
| `HOME` | no | Hidden ✗ |
| `PATH` | no | Hidden ✗ |
| `SECRET_API_KEY` | no | Hidden ✗ |

**Run it:**

```bash
make run-env-demo
```

### Demo

{{< asciinema cast="https://asciinema.org/a/wn5po8w33iBf5cot.cast" poster="npt:0:03" >}}

**What happens:**

The `env-sandbox-demo.wasm` plugin is invoked for each environment variable. It calls `std::env::var()` inside the sandbox and reports whether the variable was visible.

**Key insight:** The host sets actual values for allowed vars before entering the sandbox. The guest's `std::env::var("HOME")` returns `Err(NotPresent)` — the variable simply doesn't exist in the WASI context.

---

## Tutorial 5: Network Permissions

### Scenario

Your plugin needs to make outbound HTTP calls — fetching authorization decisions from a PDP, calling external APIs, or posting telemetry. But an unrestricted network grant would let a compromised plugin exfiltrate data to arbitrary hosts, use unexpected ports, or bypass HTTPS. You need per-plugin network policies that restrict exactly which hosts, ports, schemes, and HTTP methods are permitted.

### Goal

Demonstrate every dimension of network policy enforcement across seven scenarios: deny-by-default (no policy), host allowlisting, wildcard subdomains, port restrictions, scheme enforcement (HTTPS-only), method enforcement (GET-only), and multi-rule configurations with different constraints per host. Each scenario uses the same WASM binary but with a different network policy, proving the host blocks any request that falls outside the allowed rules.

---

**What you'll learn:** How network policies filter outbound HTTP requests by host, port, scheme, and method.

**Config** (`config/config_network_policy_demo.yaml`):

Each scenario is a separate plugin entry sharing the same WASM binary (`net-sandbox-demo.wasm`) but with a different network policy:

```yaml
config:
  sandbox_policy:
    allowed_network:
      - host: "api.example.com"
        ports: [443]
        methods: [GET]
      - host: "data.example.com"
        ports: [443, 8443]
        schemes: [https]
        methods: [GET, POST]
```

**Scenarios tested:**

| Scenario | Policy | Request | Result |
|----------|--------|---------|--------|
| 1. No policy (deny-by-default) | `allowed_network: []` | Any URL | Blocked |
| 2. Host allowlist | `host: "example.com"` | Allowed host / other host | Allowed / Blocked |
| 3. Wildcard host | `host: "*.example.com"` | `sub.example.com` | Allowed |
| 4. Port enforcement | `ports: [443]` | Port 8080 request | Blocked |
| 5. Scheme enforcement | `schemes: ["https"]` | `http://` request | Blocked |
| 6. Method enforcement | `methods: ["GET"]` | POST request | Blocked |
| 7. Multi-rule | Two hosts with different constraints | Mixed requests | Per-rule enforcement |

**Run it:**

```bash
make run-network-policy-demo
```

### Demo

{{< asciinema cast="https://asciinema.org/a/q2c4vcqmQXS5KaQB.cast" poster="npt:0:03" >}}

**What happens:**

Seven scenarios test different network policy dimensions using `net-sandbox-demo.wasm`. All scenarios are loaded from `config/config_network_policy_demo.yaml`.

**What to look for in the output:**

```
--- Scenario 1: no policy (deny-by-default)
  [DENY expected] GET    https://example.com/
  → DENY

--- Scenario 2: host allowlist  allowed=[example.com]
  [ALLOW expected] GET    https://example.com/
  → ALLOW
  [DENY expected] GET    https://other.com/
  → DENY

--- Scenario 6: method enforcement  allowed_methods=[GET]
  [ALLOW expected] GET    https://example.com/
  → ALLOW
  [DENY expected] POST   https://example.com/
  → DENY
```

---

## Tutorial 6: Resource Limits

### Scenario

A WASM plugin contains an unintentional infinite loop, a pathological algorithm that burns CPU, or an allocation pattern that consumes unbounded memory. Without resource limits, a single misbehaving plugin could starve the host process, exhaust system memory, or hang indefinitely — taking down all other plugins and requests. You need hard caps on computation, wall-clock time, and memory that the host enforces unconditionally.

### Goal

Demonstrate three resource-limit enforcement mechanisms: fuel exhaustion (instruction budget), epoch-based timeout (wall-clock deadline), and memory caps (linear memory growth limit). Each scenario deliberately triggers the limit and observes a clean trap — proving that the host terminates runaway plugins predictably, frees all resources, and continues processing subsequent requests unaffected.

---

**What you'll learn:** How fuel, timeout, and memory limits protect the host from runaway plugins.

**Config** (`config/config_resource_limits_demo.yaml`):

Each scenario uses a separate plugin entry with one deliberately tight limit:

```yaml
# Scenario 1: fuel exhaustion
config:
  sandbox_policy:
    resources:
      max_fuel: 100000
      max_execution_time_ms: 10000

# Scenario 2: epoch timeout
config:
  sandbox_policy:
    resources:
      max_fuel: 500000000
      max_execution_time_ms: 200

# Scenario 3: memory limit
config:
  sandbox_policy:
    resources:
      max_memory_bytes: 5242880
      max_fuel: 1000000000
      max_execution_time_ms: 10000
```

**Scenarios:**

| Scenario | Limit | Plugin behavior | Expected result |
|----------|-------|----------------|-----------------|
| 1. Fuel exhaustion | `max_fuel: 100,000` | Tight arithmetic loop burning instructions | Trap — fuel exhausted |
| 2. Epoch timeout | `max_execution_time_ms: 200` | Infinite loop (500M fuel budget) | Trap — epoch deadline interrupted |
| 3. Memory limit | `max_memory_bytes: 5 MB` | Allocates 1 MB chunks in a loop | Trap — memory.grow denied |

**Run it:**

```bash
make run-resource-limits-demo
```

### Demo

{{< asciinema cast="https://asciinema.org/a/cTbuXCwr4skgLHFR.cast" poster="npt:0:03" >}}

**What happens:**

The `resource-sandbox-demo.wasm` plugin is loaded three times under different names, each with a deliberately tiny resource limit. The plugin attempts to exceed the limit and is cleanly terminated by the host.

**What to look for in the output:**

```
Scenario 1: fuel exhaustion  (max_fuel=100,000)
  [TRAPPED] mode=burn_fuel      limit=max_fuel=100,000
  → Plugin trapped in ~μs

Scenario 2: epoch timeout  (max_execution_time_ms=200)
  [TRAPPED] mode=burn_fuel      limit=max_execution_time_ms=200
  → Plugin trapped in ~200ms

Scenario 3: memory limit  (max_memory_bytes=5MB)
  [TRAPPED] mode=alloc_memory   limit=max_memory_bytes=5MB
  → Plugin trapped in ~μs
```

Each trap cleanly drops the `Store`, freeing all plugin memory. The next invocation starts fresh with a new `Store`.

**Related test (for CI):**

```bash
cargo test -p cpex-wasm-host test_sandbox_resource_limits -- --ignored
```

---

## Next Steps

- [Part 1: Plugin Demos]({{< relref "part1" >}}) — custom payloads, policy-based routing, and capability filtering
- [Sandboxing Details]({{< relref "../sandboxing-details" >}}) — in-depth reference on all sandbox policy options and enforcement mechanisms
- [Architecture]({{< relref "../architecture" >}}) — how the plugin pipeline, WASM bridge, and sandbox layers fit together
- [cpex-wasm-host Reference]({{< relref "../cpex-wasm-host" >}}) — API reference for `WasmPluginFactory`, `SandboxPolicy`, and config loading
- [cpex-wasm-plugin Reference]({{< relref "../cpex-wasm-plugin" >}}) — guest-side SDK for writing WASM plugins
