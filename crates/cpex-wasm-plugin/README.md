# cpex-wasm-plugin

Write CPEX plugins in Rust, compile them to WebAssembly, and run them in sandboxed isolation. You use the exact same `HookHandler` trait as native plugins — the SDK handles all the WASM boundary plumbing for you.

---

## Table of Contents

1. [What Is This?](#what-is-this)
2. [Prerequisites](#prerequisites)
3. [Create Your First Plugin (Step by Step)](#create-your-first-plugin-step-by-step)
4. [Build and Deploy](#build-and-deploy)
5. [Test Your Plugin](#test-your-plugin)
6. [What Your Plugin Can Do](#what-your-plugin-can-do)
7. [Logging](#logging)
8. [Payload Types](#payload-types)
9. [Custom Payload Types (Your Own Structs)](#custom-payload-types-your-own-structs)
10. [Cross-Invocation State](#cross-invocation-state)
11. [Available Capabilities](#available-capabilities)
12. [Built-in Demo Plugins](#built-in-demo-plugins)
13. [Project Structure](#project-structure)
14. [Constraints (What You Can't Do)](#constraints-what-you-cant-do)
15. [Troubleshooting](#troubleshooting)

---

## What Is This?

This crate is the **guest SDK** — it's what plugin authors use. If you want to write a WASM plugin, this is your starting point.

It gives you:
- **`register_wasm_plugin!` macro** — generates all the WIT (WebAssembly Interface Types) glue code. You never deal with WIT directly.
- **`cpex_log!` macro** — structured logging that flows to the host's tracing system.
- **Automatic type conversions** — your handler receives native `cpex-core` types (`Extensions`, `MessagePayload`, etc.), not raw bytes.
- **Native testing** — test your handler logic with `cargo test` (no WASM compilation needed).

You write a normal Rust struct that implements `HookHandler<SomeHook>`. The macro turns it into a WASM component that the host can load and invoke.

---

## Prerequisites

```bash
# Install the WASM compilation target
rustup target add wasm32-wasip2
```

You'll also need the `cpex-wasm-plugin` crate (this crate) as your starting point. If you're adding a plugin to this repository, you're already set. If you're creating a standalone plugin crate, you'll need `cpex-core` and `wit-bindgen` as dependencies.

---

## Create Your First Plugin (Step by Step)

This walks through creating a plugin from scratch. By the end you'll have a working `.wasm` binary that runs in the sandbox.

### Step 1: Create the plugin file

Create a new file at `src/plugins/my_plugin.rs`:

```rust
// src/plugins/my_plugin.rs

use async_trait::async_trait;
use cpex_core::cmf::{CmfHook, MessagePayload};
use cpex_core::context::PluginContext;
use cpex_core::error::{PluginError, PluginViolation};
use cpex_core::extensions::container::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::plugin::{Plugin, PluginConfig};

// Import the logging macro
use crate::cpex_log;

// --- Your plugin struct ---
// This is re-created on every call. Use `static` for persistent state.
pub struct MyPlugin;

impl Default for MyPlugin {
    fn default() -> Self {
        Self
    }
}

// --- Plugin trait (required boilerplate) ---
// This provides metadata about your plugin. The actual logic is in HookHandler below.
static CONFIG: std::sync::OnceLock<PluginConfig> = std::sync::OnceLock::new();

#[async_trait]
impl Plugin for MyPlugin {
    fn config(&self) -> &PluginConfig {
        CONFIG.get_or_init(|| PluginConfig {
            name: "my-plugin".to_string(),
            kind: "wasm://my-plugin.wasm".to_string(),
            hooks: vec!["cmf.tool_pre_invoke".to_string()],
            ..Default::default()
        })
    }
    async fn initialize(&self) -> Result<(), Box<PluginError>> { Ok(()) }
    async fn shutdown(&self) -> Result<(), Box<PluginError>> { Ok(()) }
}

// --- Your actual logic ---
// This runs every time the hook fires. Receives the payload + extensions,
// returns allow/deny/modify.
impl HookHandler<CmfHook> for MyPlugin {
    async fn handle(
        &self,
        payload: &MessagePayload,
        extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        // Example: check if the tool call involves PII data
        if let Some(ref security) = extensions.security {
            if security.has_label("PII") {
                // Check if the user has the right role
                if let Some(ref subject) = security.subject {
                    if !subject.roles.contains("admin") {
                        cpex_log!(warn, "PII access denied — user lacks admin role");
                        return PluginResult::deny(PluginViolation::new(
                            "unauthorized",
                            "Admin role required for PII access",
                        ));
                    }
                }
            }
        }

        cpex_log!(info, "tool call approved");
        PluginResult::allow()
    }
}
```

### Step 2: Register the plugin module

Open `src/plugins/mod.rs` and add your module (feature-gated so only one plugin compiles per binary):

```rust
#[cfg(feature = "my-plugin")]
pub mod my_plugin;
```

### Step 3: Register with the WASM macro

Open `src/lib.rs` and add the registration (this generates all the WIT glue):

```rust
#[cfg(all(feature = "my-plugin", not(test)))]
register_wasm_plugin!(
    plugins::my_plugin::MyPlugin,
    [cpex_core::cmf::CmfHook]   // list all hook types this plugin handles
);
```

### Step 4: Add the feature flag

Open `Cargo.toml` and add:

```toml
[features]
my-plugin = []
```

### Step 5: Done!

Your plugin is now ready to build. Continue to the next section.

---

## Build and Deploy

### Build to WASM

```bash
# From the cpex-wasm-plugin directory:
cargo build --target wasm32-wasip2 --release \
    --features my-plugin --no-default-features
```

This produces a `.wasm` file at:
```
target/wasm32-wasip2/release/cpex_wasm_plugin.wasm
```

### Deploy to the host

Copy it to the host's `wasm/` directory with the name matching your YAML config:

```bash
cp target/wasm32-wasip2/release/cpex_wasm_plugin.wasm \
    ../cpex-wasm-host/wasm/my-plugin.wasm
```

### Configure in YAML

Create or edit the host's YAML config to include your plugin:

```yaml
plugins:
  - name: my-plugin
    kind: wasm://my-plugin.wasm       # must match the filename you copied
    hooks: [cmf.tool_pre_invoke]      # which hooks to run on
    mode: sequential                   # when in the pipeline to run
    priority: 50                       # lower = runs earlier
    on_error: fail                     # what happens if the plugin errors
    capabilities:                      # what data the plugin can see
      - read_labels
      - read_subject
      - read_roles
    config:
      sandbox_policy:                  # resource limits for the sandbox
        allowed_filesystem: []         # no file access
        allowed_network: []            # no network access
        allowed_env: []                # no env vars visible
        resources:
          max_memory_bytes: 10485760   # 10 MB
          max_fuel: 1000000000         # instruction budget per call
          max_execution_time_ms: 5000  # 5 second timeout per call
```

### Build all plugins at once (Makefile)

```bash
# Build all plugin binaries and stage them to the host
make build-all
```

---

## Test Your Plugin

You can test your handler logic **without compiling to WASM**. Tests run as normal native Rust:

```bash
cargo test --features my-plugin --no-default-features
```

### Writing tests

Add tests directly in your plugin file (or in a separate test module):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use cpex_core::hooks::trait_def::HookHandler;
    use cpex_core::cmf::{ContentPart, Message, MessagePayload, Role, ToolCall};
    use cpex_core::cmf::constants::SCHEMA_VERSION;

    fn make_test_payload() -> MessagePayload {
        MessagePayload {
            message: Message {
                schema_version: SCHEMA_VERSION.into(),
                role: Role::Assistant,
                content: vec![ContentPart::ToolCall {
                    content: ToolCall {
                        tool_call_id: "tc_001".into(),
                        name: "get_data".into(),
                        arguments: Default::default(),
                        namespace: None,
                    },
                }],
                channel: None,
            },
        }
    }

    #[tokio::test]
    async fn test_allows_non_pii() {
        let plugin = MyPlugin;
        let payload = make_test_payload();
        let ext = Extensions::default();  // no security labels = no PII
        let mut ctx = PluginContext::default();

        // Note: you must use fully-qualified syntax for the handler call
        let result: PluginResult<MessagePayload> =
            <MyPlugin as HookHandler<CmfHook>>::handle(
                &plugin, &payload, &ext, &mut ctx,
            ).await;

        assert!(result.continue_processing);
    }

    #[tokio::test]
    async fn test_denies_pii_without_admin() {
        let plugin = MyPlugin;
        let payload = make_test_payload();

        // Build extensions with PII label but no admin role
        let mut security = cpex_core::extensions::security::SecurityExtension::default();
        security.add_label("PII");
        let ext = Extensions {
            security: Some(std::sync::Arc::new(security)),
            ..Default::default()
        };
        let mut ctx = PluginContext::default();

        let result: PluginResult<MessagePayload> =
            <MyPlugin as HookHandler<CmfHook>>::handle(
                &plugin, &payload, &ext, &mut ctx,
            ).await;

        assert!(!result.continue_processing);
        assert_eq!(result.violation.as_ref().unwrap().code, "unauthorized");
    }
}
```

**Why the fully-qualified syntax?** Because `HookHandler::handle` is generic and the compiler needs to know which hook type you mean. `<MyPlugin as HookHandler<CmfHook>>::handle(...)` tells it explicitly.

---

## What Your Plugin Can Do

### Allow a request (most common)

```rust
PluginResult::allow()
```

### Deny a request

```rust
PluginResult::deny(PluginViolation::new(
    "error_code",           // machine-readable code
    "Human-readable reason" // shown to the caller
))
```

### Read extensions

Extensions are passed by reference. You only see fields your capabilities grant:

```rust
// Security labels (requires: read_labels)
if let Some(ref security) = extensions.security {
    let has_pii = security.has_label("PII");
    let labels: Vec<&String> = security.labels.iter().collect();
}

// Subject identity (requires: read_subject + read_roles)
if let Some(ref security) = extensions.security {
    if let Some(ref subject) = security.subject {
        let user_id = &subject.id;       // Option<String>
        let roles = &subject.roles;       // HashSet<String>
    }
}

// HTTP headers (requires: read_headers)
if let Some(ref http) = extensions.http {
    let auth = http.get_header("Authorization");
    let req_id = http.get_header("X-Request-ID");
}

// Request metadata (always available, no capability needed)
if let Some(ref request) = extensions.request {
    let env = &request.environment;  // "production", "staging", etc.
}
```

### Modify extensions

Use `cow_copy()` to get a mutable copy, modify it, then return it:

```rust
let mut modified = extensions.cow_copy();

// Add a security label (requires: append_labels)
if let Some(ref mut sec) = modified.security {
    sec.add_label("PROCESSED");
}

PluginResult::modify_extensions(modified)
```

### Modify the payload

```rust
let mut modified_payload = payload.clone();
// ... change fields on modified_payload ...
PluginResult::modify_payload(modified_payload)
```

### Use plugin context (share state between hooks in the same request)

```rust
// In pre-invoke: store something
ctx.set_local("checked_at", serde_json::json!("2024-01-01T12:00:00Z"));

// In post-invoke (same request): read it back
if let Some(val) = ctx.get_local("checked_at") {
    cpex_log!(info, "was checked at: {}", val);
}
```

`local` state is private to your plugin. `global` state is shared across all plugins in the pipeline.

---

## Logging

Use `cpex_log!` for all logging. Never use `println!` or `eprintln!` in production plugins.

```rust
use crate::cpex_log;

cpex_log!(trace, "entering handler");
cpex_log!(debug, "subject={:?}, roles={:?}", subject_id, roles);
cpex_log!(info, "approved tool '{}' for user '{}'", tool_name, user_id);
cpex_log!(warn, "PII access without clearance");
cpex_log!(error, "critical: validation failed: {}", reason);
```

**How it works:** In production (WASM), logs are sent to the host via the `host-logging` WIT import, which routes them through the host's `tracing` subscriber with your plugin name attached. In tests (native), they fall back to `eprintln!`.

---

## Payload Types

Your plugin handles one or more payload types. The most common is CMF (`MessagePayload`), but there are others.

### CMF Payloads — tool calls and results

The standard payload for tool invocation hooks. Contains the LLM message with tool calls or tool results.

```rust
use cpex_core::cmf::{CmfHook, MessagePayload};

impl HookHandler<CmfHook> for MyPlugin {
    async fn handle(&self, payload: &MessagePayload, ...) -> PluginResult<MessagePayload> {
        // Get the tool calls from the message
        for tc in payload.message.get_tool_calls() {
            cpex_log!(info, "tool: {}, args: {:?}", tc.name, tc.arguments);
        }

        // Or get tool results (for post-invoke hooks)
        for tr in payload.message.get_tool_results() {
            cpex_log!(info, "result from: {}, error: {}", tr.tool_name, tr.is_error);
        }

        PluginResult::allow()
    }
}
```

### Identity Payloads — resolving who the caller is

Used by `identity_resolve` hooks to determine caller identity from headers/tokens.

```rust
use cpex_core::identity::{IdentityHook, IdentityPayload};
use cpex_core::extensions::security::{SubjectExtension, SubjectType};

impl HookHandler<IdentityHook> for MyResolver {
    async fn handle(&self, payload: &IdentityPayload, ...) -> PluginResult<IdentityPayload> {
        let user_id = payload.headers().get("x-user-id");

        if let Some(uid) = user_id {
            let mut resolved = payload.clone();
            resolved.subject = Some(SubjectExtension {
                id: Some(uid.clone()),
                subject_type: Some(SubjectType::User),
                ..Default::default()
            });
            return PluginResult::modify_payload(resolved);
        }

        PluginResult::allow()
    }
}

// Register for multiple hooks:
register_wasm_plugin!(MyResolver, [CmfHook, IdentityHook]);
```

### Delegation Payloads — minting tokens for downstream calls

Used by `token_delegate` hooks to create scoped tokens for tool backends.

```rust
use cpex_core::delegation::{DelegationPayload, TokenDelegateHook};

impl HookHandler<TokenDelegateHook> for MyDelegator {
    async fn handle(&self, payload: &DelegationPayload, ...) -> PluginResult<DelegationPayload> {
        // Mint a token for the target service
        let mut resolved = payload.clone();
        // ... set delegated_token, delegation_mode, etc.
        PluginResult::modify_payload(resolved)
    }
}
```

---

## Custom Payload Types (Your Own Structs)

You're not limited to the built-in payload types. You can define any struct as a payload and it will cross the WASM boundary automatically as JSON bytes.

### How to do it

```rust
use serde::{Deserialize, Serialize};
use cpex_core::hooks::trait_def::{HookHandler, HookTypeDef, PluginResult};

// 1. Define your struct (must be Serialize + Deserialize + Clone)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInvokePayload {
    pub tool_name: String,
    pub user: String,
    pub arguments: String,
}

// 2. Implement the traits (these macros handle it)
cpex_core::impl_plugin_payload!(ToolInvokePayload);
cpex_core::impl_wasm_payload!(ToolInvokePayload, "cpex.tool_invoke");
//                                                 ^^^^^^^^^^^^^^^^
//            This string MUST match exactly on host and guest sides.
//            It's the type discriminator used during serialization.

// 3. Define a hook type that uses your payload
pub struct ToolPreInvoke;
impl HookTypeDef for ToolPreInvoke {
    type Payload = ToolInvokePayload;
    type Result = PluginResult<ToolInvokePayload>;
    const NAME: &'static str = "tool_pre_invoke";
}

// 4. Implement HookHandler for your hook type
impl HookHandler<ToolPreInvoke> for MyPlugin {
    async fn handle(
        &self,
        payload: &ToolInvokePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<ToolInvokePayload> {
        if payload.user.is_empty() {
            return PluginResult::deny(PluginViolation::new(
                "no_identity",
                "User identity is required",
            ));
        }
        PluginResult::allow()
    }
}

// 5. Register with your custom hook type
// register_wasm_plugin!(MyPlugin, [ToolPreInvoke]);
```

### Requirements

- The struct **field names and types must match** between host and guest (it's JSON serialized)
- The `impl_wasm_payload!` discriminator string must be **identical** on both sides
- The **host** must register the type with `PayloadSerializerRegistry::register::<ToolInvokePayload>()`

### Working examples

- `src/plugins/tool_invoke_checker.rs` — identity check
- `src/plugins/pii_guard.rs` — PII clearance gate
- `src/plugins/remote_authz.rs` — stateful ACL authorization

---

## Cross-Invocation State

The plugin struct itself is re-created on every call (`Default::default()`). But WASM linear memory persists between calls — so **module-level `static` variables survive across invocations**.

Use `OnceLock` for one-time initialization (like caching an ACL or config):

```rust
use std::collections::HashSet;
use std::sync::OnceLock;

static ACL: OnceLock<HashSet<String>> = OnceLock::new();

fn get_acl() -> &'static HashSet<String> {
    ACL.get_or_init(|| {
        cpex_log!(info, "initializing ACL (first call only)");
        let mut acl = HashSet::new();
        acl.insert("alice".to_string());
        acl.insert("bob".to_string());
        acl
    })
}

impl HookHandler<ToolPreInvoke> for RemoteAuthzPlugin {
    async fn handle(&self, payload: &ToolInvokePayload, ...) -> PluginResult<ToolInvokePayload> {
        let acl = get_acl();  // initialized once, reused forever

        if acl.contains(&payload.user) {
            PluginResult::allow()
        } else {
            PluginResult::deny(...)
        }
    }
}
```

This works because the host's `SandboxManager` keeps the WASM Store alive across invocations (only fuel and epoch are reset per call). See `src/plugins/remote_authz.rs` for the full working example.

---

## Available Capabilities

Declare these in your YAML config's `capabilities` list. Undeclared slots are invisible — your plugin sees `None` for those fields.

| Capability | What you can see |
|-----------|------------------|
| `read_labels` | Security labels (`security.labels`) |
| `append_labels` | Modify: add security labels |
| `read_subject` | Subject identity (`security.subject.id`, `.subject_type`) |
| `read_roles` | Subject roles (`security.subject.roles`) |
| `read_teams` | Subject teams |
| `read_claims` | Subject claims |
| `read_permissions` | Subject permissions |
| `read_client` | OAuth client identity |
| `read_workload` | Workload identity |
| `read_headers` | HTTP request/response headers |
| `write_headers` | Modify: HTTP headers |
| `read_agent` | Agent session context |
| `read_delegation` | Delegation chain |
| `append_delegation` | Modify: append to delegation chain |
| `read_inbound_credentials` | Raw inbound tokens |
| `read_delegated_tokens` | Minted delegation tokens |

---

## Built-in Demo Plugins

### CMF Payload Plugins (used in capabilities demo)

| Plugin | Feature Flag | What It Does |
|--------|-------------|--------------|
| **identity-checker** | `identity-checker` | PII access control + identity resolution from headers |
| **header-injector** | `header-injector` | Adds "PROCESSED" label + injects HTTP header |
| **audit-logger** | `audit-logger` | Read-only logging of tool name, labels, request ID |
| **token-attenuator** | `token-attenuator` | Mints scoped delegation tokens |
| **noop** | `noop` | Returns `allow()` immediately (for benchmarking) |

### Custom Payload Plugins (used in plugin demo)

| Plugin | Feature Flag | What It Does |
|--------|-------------|--------------|
| **tool-invoke-checker** | `tool-invoke-checker` | Identity check — denies empty user |
| **pii-guard** | `pii-guard` | PII clearance gate via context state |
| **audit-logger-custom** | `audit-logger-custom` | Logs invocations (fire-and-forget mode) |
| **remote-authz** | `remote-authz` | ACL authorization with persistent state |
| **compute-bench** | `compute-bench` | Real computation (JSON + hash) for benchmarking |

### How to build and run them

```bash
# Build all plugins at once
make build-all

# Or build a specific one
cargo build --target wasm32-wasip2 --release \
    --features remote-authz --no-default-features

# Run tests for a specific plugin
cargo test --features remote-authz --no-default-features
```

---

## Project Structure

```
cpex-wasm-plugin/
├── Cargo.toml                 # cdylib target, one feature flag per plugin
├── Makefile                   # Build/stage/validate/run targets
├── src/
│   ├── lib.rs                 # SDK core:
│   │                          #   - wit_bindgen::generate! (WIT bindings)
│   │                          #   - register_wasm_plugin! macro
│   │                          #   - cpex_log! macro
│   │                          #   - __block_on (sync executor)
│   │                          #   - Plugin registrations (feature-gated)
│   ├── conversions.rs         # WIT ↔ native type conversions
│   └── plugins/
│       ├── mod.rs             # Feature-gated module declarations
│       ├── identity_checker.rs
│       ├── header_injector.rs
│       ├── audit_logger.rs
│       ├── token_attenuator.rs
│       ├── noop.rs
│       ├── tool_invoke_checker.rs
│       ├── pii_guard.rs
│       ├── audit_logger_custom.rs
│       ├── remote_authz.rs
│       ├── compute_bench.rs
│       ├── fs_test.rs         # (test fixture — attempts filesystem access)
│       ├── net_test.rs        # (test fixture — attempts network access)
│       └── env_test.rs        # (test fixture — attempts env var access)
└── wit/
    ├── world.wit              # WIT interface definition (shared with host)
    └── deps/                  # WASI P2 interface dependencies
```

---

## Constraints (What You Can't Do)

| Constraint | Reason | Workaround |
|-----------|--------|------------|
| **One plugin per `.wasm` binary** | WIT allows only one export per component | Use feature flags — each flag compiles a different plugin |
| **No tokio, no reqwest** | WASM has no async runtime or raw sockets | Use WASI HTTP for network calls (declared in `allowed_network`) |
| **No filesystem I/O** | Sandbox blocks all access by default | Declare paths in `allowed_filesystem` config |
| **No `std::env::var()`** | Sandbox hides all env vars by default | Declare vars in `allowed_env` config |
| **Can't remove security labels** | Monotonic enforcement — labels are add-only | By design: prevents privilege escalation |
| **Can't `.await` yielding futures** | Guest executor polls once then panics | All handlers must complete synchronously (no sleep, no network await in the handler itself) |
| **No raw credential access** | Bearer tokens have `#[serde(skip)]` | By design: plugins needing tokens should run natively |
| **Struct is re-created per call** | `<Plugin>::default()` called each invocation | Use `static OnceLock<T>` for persistent state |

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `cargo build` fails with "target not found" | `rustup target add wasm32-wasip2` |
| Compilation error mentioning `wit_bindgen` | Make sure `wit/` directory exists with `world.wit` |
| Test fails with "type must be known" | Use fully-qualified call: `<MyPlugin as HookHandler<Hook>>::handle(...)` |
| Plugin returns `allow()` but host shows `deny` | Check your YAML capabilities — the host may be rejecting extension modifications you're not authorized for |
| Plugin logs don't appear | Set `RUST_LOG=info` when running the host (logs go through host's tracing) |
| `OnceLock` value resets between calls | It shouldn't — if it does, the host may be reloading the plugin binary. Check config. |
| Plugin panics with "fuel exhausted" | Your logic is too expensive — increase `max_fuel` in YAML config or optimize your code |
| `make build-all` fails | Ensure you're in the `cpex-wasm-plugin` directory and have the WASM target installed |
