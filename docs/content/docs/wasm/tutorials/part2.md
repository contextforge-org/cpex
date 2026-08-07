---
title: "Part 2: Sandboxing Demos"
weight: 20
---

# Part 2: Sandboxing Tutorials

## Tutorial 3: Filesystem Permissions

**What you'll learn:** How the six filesystem permission levels enforce access control inside the WASM sandbox.

{{< asciinema cast="https://asciinema.org/a/pigLCqNdRIm85GID.cast" poster="npt:0:03" >}}

**Run it:**

```bash
make run-sandbox-demo
```

**What happens:**

The `fs-sandbox-demo.wasm` plugin is invoked multiple times, each time attempting different filesystem operations against directories configured with different permission levels.

**Test matrix:**

| Directory | Permission | Allowed ops | Denied ops |
|-----------|-----------|-------------|------------|
| `data/rules/` | read-only | list, read | write, create |
| `data/cache/` | full-access | list, read, write, create, delete | — |
| `data/audit/` | drop-box | write, create | list, read |
| `data/counters/` | fixed-mutable | read, overwrite | create dir |
| `data/plugins/` | list-only | list filenames | read contents |
| `data/scratch/` | private-scratch | write, read | list dir |

**Config** (`config/config_fs_sandbox_demo.yaml`):

```yaml
sandbox:
  filesystem:
    - dir: "./examples/data/rules"
      permission: read-only
    - dir: "./examples/data/cache"
      permission: full-access
    - dir: "./examples/data/audit"
      permission: drop-box
    - dir: "./examples/data/counters"
      permission: fixed-mutable
    - dir: "./examples/data/plugins"
      permission: list-only
    - dir: "./examples/data/scratch"
      permission: private-scratch
```

**What to look for in the output:**

```
[read-only] list_dir → OK
[read-only] read_file → OK
[read-only] write_file → DENIED (PluginResult::Block)
[drop-box] write_file → OK
[drop-box] list_dir → DENIED
[drop-box] read_file → DENIED
```

---

## Tutorial 4: Environment Variable Permissions

**What you'll learn:** How `allowed_env` controls variable visibility, ensuring plugins cannot access credentials they don't need.

{{< asciinema cast="https://asciinema.org/a/LQtm4ShjcehkFIPe.cast" poster="npt:0:03" >}}


**Run it:**

```bash
make run-env-demo
```

**What happens:**

The `env-sandbox-demo.wasm` plugin is invoked for each environment variable. It calls `std::env::var()` inside the sandbox and reports whether the variable was visible.

**Variables tested:**

| Variable | In `allowed_env`? | Result |
|----------|-------------------|--------|
| `CPEX_APP_TOKEN` | yes | Visible ✓ |
| `CPEX_LOG_LEVEL` | yes | Visible ✓ |
| `HOME` | no | Hidden ✗ |
| `PATH` | no | Hidden ✗ |
| `SECRET_API_KEY` | no | Hidden ✗ |

**Config** (`config/config_env_sandbox_demo.yaml`):

```yaml
sandbox:
  env_vars:
    - CPEX_APP_TOKEN
    - CPEX_LOG_LEVEL
```

**Key insight:** The host sets actual values for allowed vars before entering the sandbox. The guest's `std::env::var("HOME")` returns `Err(NotPresent)` — the variable simply doesn't exist in the WASI context.

---

## Tutorial 5: Network Permissions

**What you'll learn:** How `NetworkPolicy` filters outbound HTTP requests by host, port, scheme, and method.

{{< asciinema cast="https://asciinema.org/a/S41GAnzybvI3Fvyp.cast" poster="npt:0:03" >}}

**Run it:**

```bash
make run-network-policy-demo
```

**What happens:**

Seven scenarios test different network policy dimensions using `net-http-test.wasm`:

| Scenario | Policy | Request | Result |
|----------|--------|---------|--------|
| 1. No policy | `network: []` | Any URL | Blocked |
| 2. Host allowlist | `host: "api.example.com"` | `https://api.example.com/data` | Allowed |
| 3. Wrong host | `host: "api.example.com"` | `https://evil.com/steal` | Blocked |
| 4. Wildcard | `host: "*.example.com"` | `https://staging.example.com/` | Allowed |
| 5. Port enforcement | `ports: [443]` | Port 8080 request | Blocked |
| 6. Scheme enforcement | `schemes: ["https"]` | `http://` request | Blocked |
| 7. Method enforcement | `methods: ["GET"]` | POST request | Blocked |

**Note:** This demo constructs `NetworkRule` configs programmatically (not from YAML) to demonstrate each dimension in isolation. In production, you'd configure these in the plugin's YAML sandbox block.

**Key code pattern:**

```rust
let policy = SandboxPolicy {
    allowed_network: vec![
        NetworkRule {
            host: "api.example.com".into(),
            ports: vec![443],
            schemes: vec!["https".into()],
            methods: vec!["GET".into(), "POST".into()],
        },
    ],
    ..Default::default()
};
```

---

## Tutorial 6: Resource Limits

**What you'll learn:** How fuel, timeout, and memory limits protect the host from runaway plugins.

{{< asciinema cast="https://asciinema.org/a/pua7El09LBPxY86k.cast" poster="npt:0:03" >}}

**Run it:**

```bash
make run-resource-limits-demo
```

**What happens:**

The `resource-test.wasm` plugin is loaded three times, each with a deliberately tiny resource limit. The plugin attempts to exceed the limit and is cleanly terminated by the host.

**Scenarios:**

| Scenario | Limit | Plugin behavior | Expected result |
|----------|-------|----------------|-----------------|
| 1. Fuel exhaustion | `max_fuel: 10,000` | Tight arithmetic loop burning instructions | Trap — fuel exhausted |
| 2. Epoch timeout | `max_execution_time_ms: 200` | Infinite loop (500M fuel budget) | Trap — epoch deadline interrupted |
| 3. Memory limit | `max_memory_bytes: 5 MB` | Allocates 1 MB chunks in a loop | Trap — memory.grow denied |

**Key code pattern:**

```rust
let policy = SandboxPolicy {
    resources: ResourceLimits {
        max_fuel: Some(10_000),
        max_execution_time_ms: Some(200),
        max_memory_bytes: Some(5 * 1024 * 1024),
        ..Default::default()
    },
    ..Default::default()
};
```

**What to look for in the output:**

```
Scenario 1: fuel exhaustion  (max_fuel=10,000)
  [TRAPPED] mode=burn_fuel      limit=max_fuel=10,000
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
