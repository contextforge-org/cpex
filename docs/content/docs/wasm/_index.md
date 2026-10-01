---
title: "WebAssembly Plugins"
weight: 50
bookCollapseSection: false
---

# WebAssembly Plugins

Run plugins in a sandboxed WebAssembly runtime instead of trusting them with full process access.

## Overview

CPEX plugins inspect and modify requests flowing through the hook pipeline — tool calls, LLM messages, identity checks, and token delegation. Normally, plugins run as native Rust code in the same process as the host. The WASM plugin system offers an alternative: compile plugins to WebAssembly and run them in a sandboxed runtime where the host controls exactly what each plugin can access.

This means you can run untrusted or third-party code alongside your own without worrying about it reading secrets, making unauthorized network calls, or crashing the host process.

### The two crates

| Crate | Role |
|-------|------|
| **`cpex-wasm-plugin`** (Guest SDK) | Write your plugin in Rust using the same traits as `cpex-core`. A `register_wasm_plugin!` macro handles all WIT bindings. Run `make` to produce a portable `.wasm` component — no WASM expertise required. |
| **`cpex-wasm-host`** (Host Runtime) | Loads `.wasm` components into a [Wasmtime](https://wasmtime.dev/) sandbox, wires up host-provided functions (logging, HTTP, clocks), enforces resource limits, and invokes the plugin's `handle-hook` export. |

WASM plugins integrate transparently into the same pipeline as native plugins via the `PluginFactory` trait — the rest of the system does not need to know whether a plugin is native or WASM.

### What the sandbox provides

Each plugin instance gets:

- **Isolated linear memory** — no shared address space with the host or other plugins; one plugin's bug cannot corrupt another
- **Zero default access** — no filesystem, network, or env unless explicitly granted via declarative YAML policy
- **CPU budget** — fuel-based instruction limits prevent runaway computation; fuel resets on each invocation
- **Wall-clock timeout** — epoch-based interruption catches infinite loops and blocking calls (default: 5s)
- **Memory cap** — configurable maximum linear memory prevents a single plugin from exhausting host RAM
- **Capability-filtered extensions** — plugins only see the extension fields their declared capabilities allow; unauthorized fields are stripped before crossing the WASM boundary
- **Credential exclusion** — raw tokens and secrets are physically never serialized into WASM memory (`#[serde(skip)]`)
- **Fail-closed error handling** — decode errors or panics result in a deny, never a silent allow

### Execution modes

WASM plugins participate in the same execution model as native plugins:

| Mode | Can block pipeline? | Can modify payload? | Typical use |
|------|:---:|:---:|-------------|
| Sequential | Yes | Yes | Authorization gates, policy enforcement |
| Transform | No | Yes | Header injection, payload enrichment |
| Audit | No | No (discarded) | Immutable logging, compliance trails |
| Concurrent | Yes | No (discarded) | Parallel validation checks |
| FireAndForget | No | No | Webhook notifications, async telemetry |

> **Rule of thumb:** Use WASM when you need isolation, auditability, resource quota enforcement or multi-language support. Use native when you need raw performance, threading, or full OS access.

---

## WASM vs Native: Capability Comparison

### What WASM plugins can do

| Capability | How it works |
|------------|--------------|
| All hook types (CMF, Identity, TokenDelegate, Custom) | Full support via structured WIT variants and JSON custom payloads |
| Modify payloads and extensions | Same `PluginResult` API — allow, deny, modify_payload, modify_extensions |
| Outbound HTTP | Via WASI HTTP, gated by per-host allowlist in sandbox policy |
| Structured logging | `host_log()` emits into the host's tracing infrastructure |
| Cross-invocation state | Module-level `static` variables (e.g., `OnceLock`) persist across calls |
| Cross-plugin state | `PluginContext.global_state` (JSON key-value pairs serialized through WIT) |
| Filesystem access | Scoped preopened directories with configurable permission levels |
| Environment variables | Explicit allowlist of readable env vars |
| Time measurement | Monotonic clock with nanosecond precision |

### What WASM plugins cannot do

| Limitation | Reason | Native alternative |
|------------|--------|-------------------|
| No raw credential access | `raw_token`, `bearer_token` are `#[serde(skip)]` — never cross the WASM boundary | Native plugins with `read_inbound_credentials` see raw token bytes |
| No multi-threading | WASM Store is `!Sync`; one call at a time per plugin | Native plugins can use `rayon`, `crossbeam`, spawn threads |
| No real async runtime | Guest uses a synchronous poll loop, not tokio | Native plugins get full `async`/`await` with `select!`, timers, channels |
| No shared typed references | Isolated linear memory; cannot hold `Arc<dyn Service>` to host resources | Native plugins share connection pools, caches, services via `Arc` |
| No unrestricted OS access | Filesystem, network, env are deny-all by default | Native plugins have full process-level access |
| No plugin instance pooling | Mutex-serialized execution; cannot handle concurrent calls in parallel | Native `&self` handlers are naturally concurrent |
| No streaming payloads | Full payload is buffered and serialized to WIT before invocation | Native plugins could process data incrementally |
| No `initialize()`/`shutdown()` lifecycle | Host stubs these as no-ops; use lazy statics for init | Native plugins get async `initialize()` and `shutdown()` callbacks |
| No `candidate_constraint` writing | Slot excluded from WIT schema (APL-internal only) | Native APL policy engine can write routing constraints |
| Limited error fidelity | Errors reconstructed from wasmtime string messages | Native errors carry typed variants, source chains, backtraces |

### What WASM provides that native cannot

| Advantage | Why it matters |
|-----------|----------------|
| Guaranteed memory isolation | A plugin crash/trap is cleanly contained; cannot corrupt host or other plugins |
| Deterministic resource bounds | Fuel (instruction count), epoch (wall-clock), and memory limits enforced by the runtime |
| Safe hot-reload | Replace the `.wasm` file and re-instantiate with zero risk of dangling state |
| Language flexibility | Any language targeting `wasm32-wasip2` works — not limited to Rust |
| Declarative auditability | Sandbox policy is YAML; exact plugin capabilities are visible in configuration |
| Least-privilege enforcement | Data not sent across the boundary is physically inaccessible — cannot be bypassed |
| Credential exclusion by design | Raw secrets never enter plugin memory, even if the plugin is compromised |
| Fail-closed guarantees | Decode errors, panics, and traps produce a deny — never a silent allow |

## Ideal Use Cases

### Security Policy Enforcement

| Use Case | Description |
|----------|-------------|
| PII detection/redaction | Inspect tool invocations and LLM I/O for sensitive data before it exits the system |
| Authorization gates | Block requests based on identity, roles, or ACLs with cross-invocation state |
| Security label enforcement | Apply/verify classification labels; monotonic writes prevent label downgrading |
| Token attenuation | Reduce privilege scope during delegation hops |

> **Why WASM**: Deny-all default guarantees policy code cannot be tampered with. The capability model ensures plugins get only the minimum data they need.

### Compliance & Audit Logging

| Use Case | Description |
|----------|-------------|
| Immutable audit trails | Log every tool invocation or LLM call; audit-mode plugins physically cannot modify the payload |
| Regulatory compliance | Enforce data handling rules declaratively per-plugin via sandbox policy |
| Data residency enforcement | Network allowlist restricts reachable hosts by scheme, port, and HTTP method |

> **Why WASM**: Audit-mode discards any modifications. The capability model proves exactly what data the plugin could have observed.

### Request/Response Transformation

| Use Case | Description |
|----------|-------------|
| Header injection | Add auth headers, tracing context, or routing metadata |
| Payload enrichment | Annotate CMF messages with metadata before downstream hooks |
| Content filtering | Strip or modify fields in tool invocations before/after execution |

> **Why WASM**: Transform mode allows safe mutation without blocking the pipeline. Fuel/timeout limits prevent a bad transform from stalling the system.

### Identity & Delegation Chain Management

| Use Case | Description |
|----------|-------------|
| Custom identity resolution | Resolve identities from non-standard sources via `IdentityHook` |
| Delegation chain validation | Verify delegation depth, allowed actors, and hop integrity via `TokenDelegateHook` |
| Multi-hop authorization | Enforce policies on who can delegate to whom |

> **Why WASM**: Credential fields (`raw_token`, `bearer_token`) are excluded from the WASM boundary via `#[serde(skip)]` — plugins make decisions without ever seeing raw secrets.

### Agent & MCP Tool Governance

| Use Case | Description |
|----------|-------------|
| Tool pre/post-invoke hooks | Gate which MCP tools an agent can call, or validate their outputs |
| Agent session policies | Enforce rules per conversation/turn using agent context extensions |
| Resource consumption tracking | Monitor token usage and model invocations via completion extensions |

> **Why WASM**: Plugins see rich structured context (agent session, tool metadata, token usage) within strict boundaries. Sequential mode can block dangerous tool calls outright.

### Third-Party / Untrusted Plugin Hosting

| Use Case | Description |
|----------|-------------|
| Customer-supplied plugins | Tenants deploy custom logic without risking host stability |
| Marketplace plugins | Declared capabilities make trust assessment transparent |
| A/B testing policy variants | Deploy competing implementations safely side by side |

> **Why WASM**: Resource limits (memory, fuel, timeout, instance count) prevent exhaustion. Fail-closed on errors. Single-threaded execution prevents concurrency bugs.

### Network-Dependent Plugins

| Use Case | Description |
|----------|-------------|
| External authorization (PDP) | Call an external Policy Decision Point via outbound HTTP, constrained to approved hosts |
| Enrichment from external services | Fetch context from APIs during hook processing |
| Webhook notifications | Fire-and-forget notifications to approved endpoints |

> **Why WASM**: WASI HTTP outgoing handler is gated by a per-host allowlist with scheme/port/method restrictions. Plugins cannot exfiltrate data to arbitrary endpoints.

---

## What's in This Section

| Page | Description |
|------|-------------|
| [Introduction]({{< relref "introduction" >}}) | What WebAssembly is, the Component Model, and trade-offs |
| [Quickstart]({{< relref "quickstart" >}}) | Build and run your first WASM plugin in minutes |
| [Architecture]({{< relref "architecture" >}}) | How the host, sandbox, and guest interact |
| [cpex-wasm-plugin (Guest SDK)]({{< relref "cpex-wasm-plugin" >}}) | Writing plugins, WIT interface, build commands |
| [cpex-wasm-host (Host Runtime)]({{< relref "cpex-wasm-host" >}}) | Loading, sandboxing, and invoking plugins |
| [Sandboxing Details]({{< relref "sandboxing-details" >}}) | Filesystem, env, network, and resource permissions |
| [Benchmarking]({{< relref "benchmarking" >}}) | Performance measurements and optimization guidance |
| [Tutorials]({{< relref "tutorials" >}}) | Hands-on walkthroughs with the built-in demos |
