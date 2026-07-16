# cpex-wasm-plugin

WASM Plugin SDK for the CPEX framework. Write plugins using the same `HookHandler` trait as native Rust plugins, compile to `.wasm`, and run them in sandboxed isolation with capability-based access control.

---

## What This Crate Provides

- **`register_wasm_plugin!` macro** — generates all WIT glue code. You never touch WIT types directly.
- **`cpex_log!` macro** — structured logging that flows through the host's tracing infrastructure.
- **Bidirectional type conversions** — all 11 extension types, 3 payload types, and plugin context automatically convert between native and WIT.
- **Feature-gated demo plugins** — reference implementations showing common patterns.
- **Native unit testing** — test your handler logic without compiling to WASM.

---

## Create Your Own Plugin in 5 Minutes

### Step 1: Create the handler file

```rust
// src/plugins/my_plugin.rs
use async_trait::async_trait;
use cpex_core::cmf::{CmfHook, MessagePayload};
use cpex_core::context::PluginContext;
use cpex_core::error::{PluginError, PluginViolation};
use cpex_core::extensions::container::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::plugin::{Plugin, PluginConfig};
use crate::cpex_log;

pub struct MyPlugin;

impl Default for MyPlugin {
    fn default() -> Self { Self }
}

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

impl HookHandler<CmfHook> for MyPlugin {
    async fn handle(
        &self,
        payload: &MessagePayload,
        extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        // Read extensions (only slots your capabilities grant)
        if let Some(ref security) = extensions.security {
            if security.has_label("PII") {
                cpex_log!(warn, "PII data detected in tool call");

                // Check authorization
                if let Some(ref subject) = security.subject {
                    if !subject.roles.contains("admin") {
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

### Step 2: Register the plugin

In `src/plugins/mod.rs`:
```rust
#[cfg(feature = "my-plugin")]
pub mod my_plugin;
```

In `src/lib.rs`:
```rust
#[cfg(all(feature = "my-plugin", not(test)))]
register_wasm_plugin!(
    plugins::my_plugin::MyPlugin,
    [cpex_core::cmf::CmfHook]
);
```

In `Cargo.toml`:
```toml
[features]
my-plugin = []
```

### Step 3: Build and deploy

```bash
# Build to WASM
cargo build --target wasm32-wasip2 --release \
    --features my-plugin --no-default-features

# Copy to the host's wasm directory
cp target/wasm32-wasip2/release/cpex_wasm_plugin.wasm \
    ../cpex-wasm-host/wasm/my-plugin.wasm
```

### Step 4: Configure in YAML

```yaml
plugins:
  - name: my-plugin
    kind: wasm://my-plugin.wasm
    hooks: [cmf.tool_pre_invoke]
    mode: sequential
    priority: 50
    on_error: fail
    capabilities:
      - read_labels
      - read_subject
      - read_roles
    config:
      sandbox_policy:
        allowed_filesystem: []
        allowed_network: []
        allowed_env: []
        resources:
          max_memory_bytes: 10485760
          max_fuel: 1000000000
          max_execution_time_ms: 5000
```

That's it. Your plugin runs in a sandboxed WASM environment with the same API as a native plugin.

---

## Testing Your Plugin

Tests run natively — no WASM compilation needed:

```bash
cargo test --features my-plugin --no-default-features
```

Add tests in `src/lib.rs` inside the `#[cfg(test)] mod tests` block:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "my-plugin")]
    mod my_plugin_tests {
        use std::sync::Arc;
        use cpex_core::cmf::CmfHook;
        use cpex_core::context::PluginContext;
        use cpex_core::extensions::container::Extensions;
        use cpex_core::extensions::security::SecurityExtension;
        use cpex_core::hooks::trait_def::HookHandler;
        use crate::plugins::my_plugin::MyPlugin;

        #[tokio::test]
        async fn test_allows_non_pii() {
            let ext = Extensions::default();
            let payload = /* build your payload */;
            let mut ctx = PluginContext::default();

            let result: cpex_core::hooks::trait_def::PluginResult<_> =
                <MyPlugin as HookHandler<CmfHook>>::handle(
                    &MyPlugin, &payload, &ext, &mut ctx,
                ).await;
            assert!(result.continue_processing);
        }
    }
}
```

---

## Capabilities (What Your Plugin Can Do)

### Reading Extensions

Extensions are passed by reference. You only see slots matching your declared capabilities:

```rust
// Security (requires: read_labels, read_subject, read_roles, etc.)
if let Some(ref security) = extensions.security {
    let has_pii = security.has_label("PII");
    let labels: Vec<&String> = security.labels.iter().collect();
    if let Some(ref subject) = security.subject {
        let user_id = &subject.id;
        let roles = &subject.roles;
    }
}

// HTTP headers (requires: read_headers)
if let Some(ref http) = extensions.http {
    let auth = http.get_header("Authorization");
    let req_id = http.get_header("X-Request-ID");
}

// Request metadata (always available)
if let Some(ref request) = extensions.request {
    let env = &request.environment;
    let trace_id = &request.trace_id;
}

// Agent context (requires: read_agent)
if let Some(ref agent) = extensions.agent {
    let session = &agent.session_id;
}
```

### Modifying Extensions

Use `extensions.cow_copy()` to get a mutable workspace, then return it:

```rust
// Requires: append_labels + write_headers capabilities
let mut modified = extensions.cow_copy();

// Add a security label (monotonic — can only add, never remove)
if let Some(ref mut sec) = modified.security {
    sec.add_label("PROCESSED");
}

// Inject an HTTP header
use cpex_core::extensions::guarded::Guarded;
let mut http = extensions.http.as_ref()
    .map(|h| (**h).clone())
    .unwrap_or_default();
http.set_header("X-Processed-By", "my-plugin");
modified.http = Some(Guarded::new(http));

PluginResult::modify_extensions(modified)
```

### Denying Requests

```rust
use cpex_core::error::PluginViolation;

PluginResult::deny(PluginViolation::new(
    "insufficient_permissions",     // code (machine-readable)
    "User lacks admin role for PII" // reason (human-readable)
))
```

### Modifying Payloads

```rust
let mut modified_payload = payload.clone();
// ... modify the message content ...
PluginResult::modify_payload(modified_payload)
```

### Using Plugin Context (state across hooks)

```rust
// Write state in pre-invoke
ctx.set_local("start_time", serde_json::json!(chrono::Utc::now().timestamp_millis()));

// Read it back in post-invoke (same request lifecycle)
if let Some(start) = ctx.get_local("start_time") {
    let elapsed = now - start.as_i64().unwrap();
    cpex_log!(info, "tool execution took {}ms", elapsed);
}
```

---

## Structured Logging

Use `cpex_log!` instead of `println!` or `eprintln!`:

```rust
use crate::cpex_log;

cpex_log!(trace, "entering handler");
cpex_log!(debug, "subject={:?}, roles={:?}", subject_id, roles);
cpex_log!(info, "processing tool '{}' for user '{}'", tool_name, user_id);
cpex_log!(warn, "PII access without admin role");
cpex_log!(error, "validation failed: {}", reason);
```

Logs flow through the host's `tracing` subscriber with your plugin name attached. In tests, they fall back to `eprintln!`.

---

## Handling Different Payload Types

### CMF Payloads (most common)

```rust
impl HookHandler<CmfHook> for MyPlugin {
    async fn handle(&self, payload: &MessagePayload, ...) -> PluginResult<MessagePayload> {
        // Access tool calls
        for tc in payload.message.get_tool_calls() {
            cpex_log!(info, "tool: {} args: {:?}", tc.name, tc.arguments);
        }
        // Access tool results
        for tr in payload.message.get_tool_results() {
            cpex_log!(info, "result: {} error: {}", tr.tool_name, tr.is_error);
        }
        PluginResult::allow()
    }
}
```

### Identity Payloads (custom)

```rust
use cpex_core::identity::{IdentityHook, IdentityPayload};

impl HookHandler<IdentityHook> for MyResolver {
    async fn handle(&self, payload: &IdentityPayload, ...) -> PluginResult<IdentityPayload> {
        // Read headers to resolve identity
        let user_id = payload.headers().get("x-user-id")?;

        let mut resolved = payload.clone();
        resolved.subject = Some(SubjectExtension {
            id: Some(user_id.clone()),
            subject_type: Some(SubjectType::User),
            ..Default::default()
        });
        PluginResult::modify_payload(resolved)
    }
}

// Register for both hooks:
register_wasm_plugin!(MyResolver, [CmfHook, IdentityHook]);
```

### Delegation Payloads (token minting)

```rust
use cpex_core::delegation::{DelegationPayload, TokenDelegateHook, TargetType};

impl HookHandler<TokenDelegateHook> for MyDelegator {
    async fn handle(&self, payload: &DelegationPayload, ...) -> PluginResult<DelegationPayload> {
        let target = payload.target_name();
        let audience = payload.target_audience().unwrap_or(target);

        let mut resolved = payload.clone();
        resolved.delegated_token = Some(RawDelegatedToken { ... });
        resolved.delegation_mode = Some(DelegationMode::OnBehalfOfUser);
        PluginResult::modify_payload(resolved)
    }
}
```

---

## Built-in Demo Plugins

| Plugin | Feature | Hook(s) | What It Does |
|--------|---------|---------|--------------|
| **identity-checker** | `identity-checker` | `CmfHook` + `IdentityHook` | PII access control + identity resolution from headers |
| **header-injector** | `header-injector` | `CmfHook` | Adds "PROCESSED" label + injects HTTP header |
| **audit-logger** | `audit-logger` | `CmfHook` | Read-only logging of tool name, labels, request ID |
| **token-attenuator** | `token-attenuator` | `TokenDelegateHook` | Mints scoped delegation tokens for downstream tools |
| **noop** | `noop` | `CmfHook` | Returns `allow()` immediately (for benchmarking) |

---

## Build Commands

```bash
# Prerequisites
rustup target add wasm32-wasip2

# Build a single plugin
cargo build --target wasm32-wasip2 --release \
    --features identity-checker --no-default-features

# Build all plugins (via Makefile)
make build-all

# Stage to host directory
make stage

# Validate the binary
wasm-tools validate target/wasm32-wasip2/release/cpex_wasm_plugin.wasm

# Inspect component structure
wasm-tools component wit target/wasm32-wasip2/release/cpex_wasm_plugin.wasm
```

---

## Project Structure

```
cpex-wasm-plugin/
├── Cargo.toml              # cdylib target, feature flags per plugin
├── Makefile                 # Build/stage/validate/run targets
├── src/
│   ├── lib.rs              # SDK: wit_bindgen, register_wasm_plugin! macro,
│   │                       #   host_log/cpex_log!, unit tests
│   ├── conversions.rs      # WIT ↔ native type conversions (all 11 extensions)
│   └── plugins/
│       ├── mod.rs           # Feature-gated module declarations
│       ├── identity_checker.rs
│       ├── header_injector.rs
│       ├── audit_logger.rs
│       ├── token_attenuator.rs
│       └── noop.rs
└── wit/
    ├── world.wit           # WIT interface (shared with cpex-wasm-host)
    └── deps/               # WASI P2 interface definitions
```

---

## Constraints

- **One plugin per `.wasm` binary** — WIT's single-export constraint. Use feature flags to build separate binaries.
- **No raw credential access** — `#[serde(skip)]` fields (bearer tokens, delegated token bytes) never cross the boundary.
- **WASM-compatible dependencies only** — no tokio, no reqwest, no file I/O (use WASI HTTP for network calls).
- **Monotonic labels** — security labels can only be added, never removed. Removal is a security violation.
- **Handlers must complete synchronously** — the guest async executor polls once. Don't `.await` anything that yields.

---

## Available Capabilities

Declare in your YAML config to control what extensions your plugin sees:

| Capability | Grants |
|-----------|--------|
| `read_labels` | See security labels |
| `append_labels` | Add security labels |
| `read_subject` | See subject id + type |
| `read_roles` | See subject roles |
| `read_teams` | See subject teams |
| `read_claims` | See subject claims |
| `read_permissions` | See subject permissions |
| `read_client` | See OAuth client identity |
| `read_workload` | See workload identity |
| `read_headers` | See HTTP headers |
| `write_headers` | Modify HTTP headers |
| `read_agent` | See agent context |
| `read_delegation` | See delegation chain |
| `append_delegation` | Append to delegation chain |
| `read_inbound_credentials` | See raw inbound tokens |
| `read_delegated_tokens` | See minted tokens |

Undeclared slots are invisible — your plugin receives `None` for those fields.
