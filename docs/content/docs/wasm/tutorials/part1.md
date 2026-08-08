---
title: "Part 1: Plugin Demos"
weight: 10
---

# Part 1: Using WASM Plugins with CPEX

## Tutorial 1: Plugin Demo (custom payload pipeline)

**What you'll learn:** How to define a custom payload type, register multiple plugins with policy-based routing, and invoke them through the pipeline.

{{< asciinema cast="https://asciinema.org/a/neCYIg5MN6V2aoCY.cast" poster="npt:0:03" >}}



**Run it:**

```bash
make run-plugin-demo
```

**What happens:**

1. A custom `ToolInvokePayload` is defined with `tool_name`, `user`, and `arguments` fields
2. Four plugins are loaded from `config/config_plugin_demo.yaml`:
   - **identity-resolver** (priority 10) — resolves caller identity on every request
   - **pii-guard** (priority 20) — blocks requests containing PII (activated by "pii" tag)
   - **remote-authz** (priority 30) — calls external PDP for authorization (activated by "needs_remote_authz" tag)
   - **audit-logger** (priority 100) — logs all invocations in fire-and-forget mode
3. Seven scenarios are executed with different route tags triggering different plugin combinations

**Key code pattern:**

```rust
// Define a custom payload
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ToolInvokePayload {
    tool_name: String,
    user: String,
    arguments: HashMap<String, String>,
}
impl_plugin_payload!(ToolInvokePayload, "tool_invoke");
impl_wasm_payload!(ToolInvokePayload, "tool_invoke");

// Register it
let mut registry = PayloadSerializerRegistry::new();
registry.register::<ToolInvokePayload>();

// Create factory with custom registry
let factory = WasmPluginFactory::new("./wasm", Arc::new(registry))?;
```

**Config excerpt** (`config/config_plugin_demo.yaml`):

```yaml
policies:
  pii:
    condition: { tag: "pii" }
    plugins: [pii-guard]
  external_authz:
    condition: { tag: "needs_remote_authz" }
    plugins: [remote-authz]

routes:
  - name: get_compensation
    tags: [pii, hr]
  - name: query_external_data
    tags: [needs_remote_authz]
```

---

## Tutorial 2: Capabilities Demo (extension filtering)

**What you'll learn:** How capability declarations control which extension fields a plugin can read and write across the WASM boundary.

{{< asciinema cast="https://asciinema.org/a/utOxkW2ZY1FGbwtk.cast" poster="npt:0:03" >}}

**Run it:**

```bash
make run-capabilities-demo
```

**What happens:**

1. Three plugins are loaded with different capability sets:
   - **identity-checker**: `[read_labels, read_subject, read_roles]`
   - **header-injector**: `[read_headers, write_headers, append_labels]`
   - **audit-logger**: `[read_headers, read_labels]` (audit mode)
2. Extensions are built with `SecurityExtension`, `HttpExtension`, `MetaExtension`
3. Each plugin only sees the extension fields matching its capabilities
4. After invocation, `modified_extensions` reflects only authorized changes

**Key concept — capability filtering:**

```yaml
# header-injector can read and write headers, and append labels
capabilities:
  - read_headers
  - write_headers
  - append_labels
```

The `WasmBridgeHandler`:
- Before the call: zeros extension fields the plugin has no `read_*` capability for
- After the call: discards modifications to fields the plugin has no `write_*` capability for
- This happens at the host level — the guest cannot bypass it

**Observe the output:**

```
identity-checker sees subject: "user:alice" ✓
identity-checker tries to write headers → discarded (no write_headers capability)
header-injector sees headers ✓, adds x-plugin-trace header ✓
header-injector does NOT see subject (no read_subject capability)
```
