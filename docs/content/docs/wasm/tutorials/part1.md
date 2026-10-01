---
title: "Part 1: Plugin Demos"
weight: 10
---

# Part 1: Using WASM Plugins with CPEX

> **Prerequisites:** Ensure `wasm32-wasip2` is installed (`rustup target add wasm32-wasip2`) and run all commands from `crates/cpex-wasm-host/`. See [Tutorials index]({{< relref "_index" >}}) for details.

## Tutorial 1: Plugin Demo (custom payload pipeline)

### Scenario

You are building a tool-invocation gateway. Every incoming tool call must pass through an identity check, optionally a PII scan or remote authorization, and finally an audit log — all enforced by WASM plugins running in sandboxed isolation. Different tools require different security stacks (e.g., HR tools need PII scanning, external data tools need remote authz), and the routing is driven by tags in the config rather than hard-coded logic.

### Goal

Demonstrate the end-to-end plugin pipeline: defining a custom payload type, registering multiple WASM plugins with priority ordering, configuring policy-based routing via YAML tags, and observing how different tool invocations trigger different plugin combinations — including allow, deny, and fire-and-forget audit outcomes.

---

**What you'll learn:** How to define a custom payload type, register multiple plugins with policy-based routing, and invoke them through the pipeline.

**Key code pattern:**

```rust
// Define a custom payload
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ToolInvokePayload {
    tool_name: String,
    user: String,
    arguments: String,
}
cpex_core::impl_plugin_payload!(ToolInvokePayload);
cpex_core::impl_wasm_payload!(ToolInvokePayload, "cpex.tool_invoke");

// Register it and create factory
let registry = Arc::new({
    let mut r = PayloadSerializerRegistry::new();
    r.register::<ToolInvokePayload>();
    r
});

let factory = WasmPluginFactory::new(wasm_dir.clone(), registry.clone())?;
```

**Config excerpt** (`config/config_plugin_demo.yaml`):

```yaml
global:
  policies:
    # "all" fires on every invocation
    all:
      plugins: [identity-resolver]
    # activated when a route has the "pii" tag
    pii:
      plugins: [pii-guard]
    # activated when a route has the "external_authz" tag
    external_authz:
      plugins: [remote-authz]

routes:
  - tool: get_compensation
    meta:
      tags: [pii, hr]
    plugins:
      - audit-logger
  - tool: query_external_data
    meta:
      tags: [external_authz]
    plugins:
      - audit-logger
```

**Run it:**

```bash
make run-plugin-demo
```

### Demo

{{< asciinema cast="https://asciinema.org/a/zGOJq0LgFG27xOcl.cast" poster="npt:0:03" >}}

**What happens:**

Four plugins are loaded from `config/config_plugin_demo.yaml` and seven scenarios execute with different route tags, triggering different plugin combinations:

| # | Scenario | Plugins triggered | Expected outcome | Reason |
|---|----------|-------------------|-----------------|--------|
| 1 | `get_compensation` — PII tool, no clearance | identity-resolver → pii-guard | **DENIED** by pii-guard | User lacks PII clearance; pii-guard blocks the request before it reaches the tool |
| 2 | `get_compensation` — PII tool, with clearance | identity-resolver → pii-guard → audit-logger | **ALLOWED** (post-invoke also fires) | User has PII clearance; pii-guard passes, audit-logger records the invocation |
| 3 | `list_departments` — non-PII tool | identity-resolver → audit-logger | **ALLOWED** | Route has no `pii` or `external_authz` tag — only the "all" policy (identity) and audit fire |
| 4 | `some_other_tool` — wildcard route | identity-resolver → audit-logger | **ALLOWED** | Matches the `"*"` wildcard route; no special policy tags, so standard identity + audit only |
| 5 | `query_external_data` — remote authz, ACL hit | identity-resolver → remote-authz → audit-logger | **ALLOWED** | Route has `external_authz` tag; remote-authz checks the ACL and finds the user listed |
| 6 | `query_external_data` — remote authz, ACL miss | identity-resolver → remote-authz | **DENIED** by remote-authz | User is not in the remote ACL; remote-authz denies before audit-logger fires |
| 7 | `list_departments` — no user identity | identity-resolver | **DENIED** by identity-resolver | No user identity in the request; identity-resolver blocks immediately |

---

## Tutorial 2: Capabilities Demo (extension filtering)

### Scenario

You have multiple plugins in a pipeline that all receive the same request context (security labels, HTTP headers, metadata). However, not every plugin should see everything — an audit logger doesn't need access to the caller's subject identity, and an identity checker shouldn't be able to modify HTTP headers. You need fine-grained, host-enforced access control over which extension fields each plugin can read and write.

### Goal

Demonstrate capability-gated extension visibility: three plugins with different capability profiles process the same request, but each only sees and modifies the extension fields it is authorized for. The host pipeline enforces this filtering — a plugin cannot bypass it from guest code, ensuring least-privilege access even across untrusted WASM modules.

---

**What you'll learn:** How capability declarations control which extension fields a plugin can read and write across the WASM boundary.

**Config** (`config/config_capabilities.yaml`):

Each plugin declares its capabilities — the host uses these to gate extension visibility:

```yaml
plugins:
  - name: identity-checker
    capabilities:
      - read_labels
      - read_subject
      - read_roles

  - name: header-injector
    capabilities:
      - read_headers
      - write_headers
      - append_labels

  - name: audit-logger
    capabilities:
      - read_headers
      - read_labels
```

The host pipeline:
- Before the call: the executor zeros extension fields the plugin has no `read_*` capability for
- After the call: the bridge handler discards modifications to fields the plugin has no `write_*` capability for
- This happens at the host level — the guest cannot bypass it

**Run it:**

```bash
make run-capabilities-demo
```

### Demo

{{< asciinema cast="https://asciinema.org/a/QWxRqTzjT3FXtSM9.cast" poster="npt:0:03" >}}

**What happens:**

1. Three plugins are loaded with different capability sets:
   - **identity-checker**: `[read_labels, read_subject, read_roles]`
   - **header-injector**: `[read_headers, write_headers, append_labels]`
   - **audit-logger**: `[read_headers, read_labels]` (audit mode)
2. Extensions are built with `RequestExtension`, `SecurityExtension`, `HttpExtension`, `MetaExtension`
3. Each plugin only sees the extension fields matching its capabilities
4. After invocation, `modified_extensions` reflects only authorized changes

**What to look for in the output:**

```
=== Phase 1: cmf.tool_pre_invoke ===

Pre-invoke result: ALLOWED
  Labels after pre-invoke: ["PII", "HR_DATA"]
  Headers after pre-invoke: {"authorization": "Bearer eyJ...", "x-plugin-trace": "..."}

--- Tool 'get_compensation' executes... ---
  Result: {"salary": 150000, "currency": "USD"}

=== Phase 2: cmf.tool_post_invoke ===

Post-invoke result: ALLOWED
```

**Key observations:**
- `identity-checker` sees subject and roles (has `read_subject`, `read_roles`) but cannot modify headers
- `header-injector` injects an `x-plugin-trace` header (has `write_headers`) but cannot see the subject
- `audit-logger` observes headers and labels in read-only audit mode — it cannot write anything

---

## Next Steps

- [Part 2: Sandboxing Demos]({{< relref "part2" >}}) — filesystem, env, network, and resource limit enforcement
- [Architecture]({{< relref "../architecture" >}}) — how the plugin pipeline, WASM bridge, and sandbox layers fit together
- [cpex-wasm-host Reference]({{< relref "../cpex-wasm-host" >}}) — API reference for `WasmPluginFactory`, `SandboxPolicy`, and config loading
- [cpex-wasm-plugin Reference]({{< relref "../cpex-wasm-plugin" >}}) — guest-side SDK for writing WASM plugins
