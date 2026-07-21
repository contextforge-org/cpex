// CPEX Plugin Demo
//
// Demonstrates how to:
//   1. Define hook types and payloads
//   2. Build plugins that implement HookHandler
//   3. Create plugin factories for config-driven loading
//   4. Load a YAML config with routing rules
//   5. Invoke hooks with MetaExtension for route resolution
//
// Run with: cargo run --example plugin_demo

use std::sync::Arc;

use async_trait::async_trait;
use cpex_core::context::PluginContext;
use cpex_core::error::{PluginError, PluginViolation};
use cpex_core::executor::PipelineResult;
use cpex_core::factory::{PluginFactory, PluginInstance};
use cpex_core::hooks::adapter::TypedHandlerAdapter;
use cpex_core::hooks::payload::{Extensions, MetaExtension};
use cpex_core::hooks::trait_def::{HookHandler, HookTypeDef, PluginResult};
use cpex_core::manager::PluginManager;
use cpex_core::plugin::{Plugin, PluginConfig};

// ---------------------------------------------------------------------------
// Step 1: Define a payload and hook type
// ---------------------------------------------------------------------------

/// The payload carried through the tool_pre_invoke hook.
#[derive(Debug, Clone)]
struct ToolInvokePayload {
    tool_name: String,
    user: String,
    arguments: String,
}
cpex_core::impl_plugin_payload!(ToolInvokePayload);

/// Hook type for tool_pre_invoke — runs before a tool executes.
struct ToolPreInvoke;
impl HookTypeDef for ToolPreInvoke {
    type Payload = ToolInvokePayload;
    type Result = PluginResult<ToolInvokePayload>;
    const NAME: &'static str = "tool_pre_invoke";
}

/// Hook type for tool_post_invoke — runs after a tool executes.
struct ToolPostInvoke;
impl HookTypeDef for ToolPostInvoke {
    type Payload = ToolInvokePayload;
    type Result = PluginResult<ToolInvokePayload>;
    const NAME: &'static str = "tool_post_invoke";
}

// ---------------------------------------------------------------------------
// Step 2: Build plugins
// ---------------------------------------------------------------------------

/// Identity resolver — checks that a user is present.
struct IdentityResolver {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for IdentityResolver {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
    async fn initialize(&self) -> Result<(), Box<PluginError>> {
        println!("  [identity-resolver] initialized");
        Ok(())
    }
    async fn shutdown(&self) -> Result<(), Box<PluginError>> {
        println!("  [identity-resolver] shutdown");
        Ok(())
    }
}

impl HookHandler<ToolPreInvoke> for IdentityResolver {
    async fn handle(
        &self,
        payload: &ToolInvokePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<ToolInvokePayload> {
        if payload.user.is_empty() {
            println!("  [identity-resolver] DENIED: no user identity");
            return PluginResult::deny(PluginViolation::new(
                "no_identity",
                "User identity is required",
            ));
        }
        println!(
            "  [identity-resolver] OK: user '{}' identified",
            payload.user
        );
        PluginResult::allow()
    }
}

impl HookHandler<ToolPostInvoke> for IdentityResolver {
    async fn handle(
        &self,
        payload: &ToolInvokePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<ToolInvokePayload> {
        println!(
            "  [identity-resolver] post-invoke: user '{}' completed '{}'",
            payload.user, payload.tool_name
        );
        PluginResult::allow()
    }
}

/// PII guard — blocks access to sensitive tools without clearance.
struct PiiGuard {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for PiiGuard {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
    // initialize() and shutdown() use defaults — no setup needed
}

impl HookHandler<ToolPreInvoke> for PiiGuard {
    async fn handle(
        &self,
        payload: &ToolInvokePayload,
        _extensions: &Extensions,
        ctx: &mut PluginContext,
    ) -> PluginResult<ToolInvokePayload> {
        // Check if the user has PII clearance (simulated via context)
        let has_clearance = ctx
            .get_global("pii_clearance")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if !has_clearance {
            println!(
                "  [pii-guard] DENIED: user '{}' lacks PII clearance for '{}'",
                payload.user, payload.tool_name
            );
            return PluginResult::deny(PluginViolation::new(
                "pii_access_denied",
                "PII clearance required",
            ));
        }

        println!(
            "  [pii-guard] OK: user '{}' has PII clearance",
            payload.user
        );
        PluginResult::allow()
    }
}

/// Audit logger — logs all tool invocations (fire-and-forget).
struct AuditLogger {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for AuditLogger {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
    // initialize() and shutdown() use defaults — no setup needed
}

impl HookHandler<ToolPreInvoke> for AuditLogger {
    async fn handle(
        &self,
        payload: &ToolInvokePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<ToolInvokePayload> {
        println!(
            "  [audit-logger] LOG: user='{}' tool='{}' args='{}'",
            payload.user, payload.tool_name, payload.arguments
        );
        PluginResult::allow()
    }
}

impl HookHandler<ToolPostInvoke> for AuditLogger {
    async fn handle(
        &self,
        payload: &ToolInvokePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<ToolInvokePayload> {
        println!(
            "  [audit-logger] LOG: post-invoke user='{}' tool='{}'",
            payload.user, payload.tool_name
        );
        PluginResult::allow()
    }
}

// ---------------------------------------------------------------------------
// Awaiting plugin example — RemoteAuthz
// ---------------------------------------------------------------------------
//
// `HookHandler<H>` is async by design — `handle` is `async fn`.
// Plugins that don't need to `.await` anything still write
// `async fn handle` and return synchronously; this plugin shows the
// other direction, where the body genuinely awaits per-invocation
// work. The realistic version would call a remote authz service
// (gRPC, HTTP, OPA, Cedarling, etc.); here we simulate the network
// round-trip with a small `tokio::time::sleep` so the demo runs
// offline.
//
// Key things this shows:
//   1. Per-request latency state is *cached at init* — the handler
//      consults the in-memory ACL and only "calls out" on a miss.
//      Hot-path I/O is the most common source of latency regressions
//      in plugins, so prefer initialize-time loading wherever you can.
//   2. Registration uses the exact same factory pattern as any other
//      plugin — `TypedHandlerAdapter::<H, _>` and the same
//      `register_factory` call. There is no separate async path.
struct RemoteAuthz {
    cfg: PluginConfig,
    /// ACL "fetched" at init. Populated in Plugin::initialize.
    allowed_users: tokio::sync::RwLock<std::collections::HashSet<String>>,
}

#[async_trait]
impl Plugin for RemoteAuthz {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
    /// Pretend we're loading the ACL from a remote service. In a real
    /// plugin this would be `client.fetch_acl().await`; we simulate
    /// the round-trip with a small sleep so the demo runs offline.
    async fn initialize(&self) -> Result<(), Box<PluginError>> {
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        let mut acl = self.allowed_users.write().await;
        acl.extend(["alice", "bob"].iter().map(|s| s.to_string()));
        println!(
            "  [remote-authz] initialized — ACL cached ({} users)",
            acl.len()
        );
        Ok(())
    }
    async fn shutdown(&self) -> Result<(), Box<PluginError>> {
        println!("  [remote-authz] shutdown");
        Ok(())
    }
}

impl HookHandler<ToolPreInvoke> for RemoteAuthz {
    async fn handle(
        &self,
        payload: &ToolInvokePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<ToolInvokePayload> {
        // Cache hit path — fast.
        let acl = self.allowed_users.read().await;
        if acl.contains(&payload.user) {
            println!(
                "  [remote-authz] OK (cache hit): user '{}' allowed",
                payload.user
            );
            return PluginResult::allow();
        }
        drop(acl); // release read lock before the fake remote call
                   // Cache miss path — simulate a remote authz check. In a real
                   // plugin this is where you'd `.await` a gRPC or HTTP call.
                   // The latency cost is real and shows up on the request path.
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        println!(
            "  [remote-authz] DENIED (cache miss + remote check): user '{}'",
            payload.user
        );
        PluginResult::deny(PluginViolation::new(
            "remote_authz_denied",
            format!("User '{}' not in remote ACL", payload.user),
        ))
    }
}

// ---------------------------------------------------------------------------
// Step 3: Create plugin factories
// ---------------------------------------------------------------------------

struct IdentityFactory;
impl PluginFactory for IdentityFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let plugin = Arc::new(IdentityResolver {
            cfg: config.clone(),
        });
        Ok(PluginInstance {
            plugin: plugin.clone(),
            handlers: vec![
                (
                    "tool_pre_invoke",
                    Arc::new(TypedHandlerAdapter::<ToolPreInvoke, _>::new(plugin.clone())),
                ),
                (
                    "tool_post_invoke",
                    Arc::new(TypedHandlerAdapter::<ToolPostInvoke, _>::new(plugin)),
                ),
            ],
        })
    }
}

struct PiiGuardFactory;
impl PluginFactory for PiiGuardFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let plugin = Arc::new(PiiGuard {
            cfg: config.clone(),
        });
        Ok(PluginInstance {
            plugin: plugin.clone(),
            handlers: vec![(
                "tool_pre_invoke",
                Arc::new(TypedHandlerAdapter::<ToolPreInvoke, _>::new(plugin)),
            )],
        })
    }
}

struct AuditLoggerFactory;
impl PluginFactory for AuditLoggerFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let plugin = Arc::new(AuditLogger {
            cfg: config.clone(),
        });
        Ok(PluginInstance {
            plugin: plugin.clone(),
            handlers: vec![
                (
                    "tool_pre_invoke",
                    Arc::new(TypedHandlerAdapter::<ToolPreInvoke, _>::new(plugin.clone())),
                ),
                (
                    "tool_post_invoke",
                    Arc::new(TypedHandlerAdapter::<ToolPostInvoke, _>::new(plugin)),
                ),
            ],
        })
    }
}

/// Factory for the async plugin. Note the factory body is identical
/// in shape to the sync factories above — `TypedHandlerAdapter` and
/// the `register_factory` path don't care that the underlying handler
/// is async. The framework hides the choice.
struct RemoteAuthzFactory;
impl PluginFactory for RemoteAuthzFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let plugin = Arc::new(RemoteAuthz {
            cfg: config.clone(),
            allowed_users: tokio::sync::RwLock::new(std::collections::HashSet::new()),
        });
        Ok(PluginInstance {
            plugin: plugin.clone(),
            handlers: vec![(
                "tool_pre_invoke",
                Arc::new(TypedHandlerAdapter::<ToolPreInvoke, _>::new(plugin)),
            )],
        })
    }
}

// ---------------------------------------------------------------------------
// Step 4: Build extensions with MetaExtension for routing
// ---------------------------------------------------------------------------

fn make_tool_extensions(tool_name: &str, tags: &[&str]) -> Extensions {
    Extensions {
        meta: Some(Arc::new(MetaExtension {
            entity_type: Some("tool".into()),
            entity_name: Some(tool_name.into()),
            tags: tags.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        })),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Helper to print results
// ---------------------------------------------------------------------------

fn print_result(_label: &str, result: &PipelineResult) {
    if result.continue_processing {
        println!("  Result: ALLOWED");
    } else {
        let violation = result.violation.as_ref().unwrap();
        println!(
            "  Result: DENIED by '{}' — {} [{}]",
            violation.plugin_name.as_deref().unwrap_or("unknown"),
            violation.reason,
            violation.code,
        );
    }
    println!();
}

// ---------------------------------------------------------------------------
// Step 5: Main — load config, invoke hooks, see results
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    println!("=== CPEX Plugin Demo ===\n");

    // --- Load config from YAML file ---
    let config_path = "crates/cpex-core/examples/plugin_demo.yaml";
    println!("--- Loading config from {} ---\n", config_path);
    let yaml = std::fs::read_to_string(config_path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", config_path, e));
    let cpex_config = cpex_core::config::parse_config(&yaml).unwrap();

    let mgr = PluginManager::default();
    mgr.register_factory("builtin/identity", Box::new(IdentityFactory));
    mgr.register_factory("builtin/pii", Box::new(PiiGuardFactory));
    mgr.register_factory("builtin/audit", Box::new(AuditLoggerFactory));
    mgr.register_factory("builtin/remote_authz", Box::new(RemoteAuthzFactory));
    mgr.load_config(cpex_config).unwrap();

    println!("\n--- Initializing plugins ---\n");
    mgr.initialize().await.unwrap();

    println!("\nPlugins loaded: {}", mgr.plugin_count());
    println!(
        "Hooks registered: tool_pre_invoke={}, tool_post_invoke={}\n",
        mgr.has_hooks_for("tool_pre_invoke"),
        mgr.has_hooks_for("tool_post_invoke"),
    );

    // --- Scenario 1: PII tool without clearance ---
    println!("=== Scenario 1: get_compensation (PII tool, no clearance) ===\n");
    let payload = ToolInvokePayload {
        tool_name: "get_compensation".into(),
        user: "alice".into(),
        arguments: "employee_id=42".into(),
    };
    let ext = make_tool_extensions("get_compensation", &[]);
    let (result, bg) = mgr.invoke::<ToolPreInvoke>(payload, ext, None).await;
    print_result("get_compensation (no clearance)", &result);
    // Wait for any fire-and-forget tasks
    bg.wait_for_background_tasks().await;

    // --- Scenario 2: PII tool with clearance ---
    println!("=== Scenario 2: get_compensation (PII tool, with clearance) ===\n");
    let payload = ToolInvokePayload {
        tool_name: "get_compensation".into(),
        user: "alice".into(),
        arguments: "employee_id=42".into(),
    };
    let ext = make_tool_extensions("get_compensation", &[]);
    // Simulate clearance by pre-populating global_state
    // (In production, an earlier hook would set this from a token claim)
    let mut ctx_table = cpex_core::context::PluginContextTable::new();
    ctx_table
        .global_state
        .insert("pii_clearance".into(), serde_json::Value::Bool(true));
    let (result, bg) = mgr
        .invoke::<ToolPreInvoke>(payload, ext, Some(ctx_table))
        .await;
    print_result("get_compensation (with clearance)", &result);
    bg.wait_for_background_tasks().await;

    // Now call post-invoke — threads the context table from pre-invoke
    println!("  --- post-invoke for get_compensation ---\n");
    let payload = ToolInvokePayload {
        tool_name: "get_compensation".into(),
        user: "alice".into(),
        arguments: "employee_id=42".into(),
    };
    let ext = make_tool_extensions("get_compensation", &[]);
    let (post_result, bg) = mgr
        .invoke::<ToolPostInvoke>(payload, ext, Some(result.context_table))
        .await;
    print_result("get_compensation post-invoke", &post_result);
    bg.wait_for_background_tasks().await;

    // --- Scenario 3: Non-PII tool ---
    println!("=== Scenario 3: list_departments (non-PII tool) ===\n");
    let payload = ToolInvokePayload {
        tool_name: "list_departments".into(),
        user: "bob".into(),
        arguments: "".into(),
    };
    let ext = make_tool_extensions("list_departments", &[]);
    let (result, bg) = mgr.invoke::<ToolPreInvoke>(payload, ext, None).await;
    print_result("list_departments", &result);
    bg.wait_for_background_tasks().await;

    // --- Scenario 4: Unknown tool (wildcard route) ---
    println!("=== Scenario 4: some_other_tool (wildcard route) ===\n");
    let payload = ToolInvokePayload {
        tool_name: "some_other_tool".into(),
        user: "charlie".into(),
        arguments: "foo=bar".into(),
    };
    let ext = make_tool_extensions("some_other_tool", &[]);
    let (result, bg) = mgr.invoke::<ToolPreInvoke>(payload, ext, None).await;
    print_result("some_other_tool (wildcard)", &result);
    bg.wait_for_background_tasks().await;

    // --- Scenario 5: Awaiting plugin — cache hit ---
    // RemoteAuthz's `handle` is `async fn` and reads from a tokio
    // RwLock. Its initialize() pre-loaded an ACL containing "alice"
    // and "bob"; this call exercises the cache-hit fast path.
    println!("=== Scenario 5: query_external_data (async plugin, cache hit) ===\n");
    let payload = ToolInvokePayload {
        tool_name: "query_external_data".into(),
        user: "alice".into(),
        arguments: "dataset=sales".into(),
    };
    let ext = make_tool_extensions("query_external_data", &[]);
    let (result, bg) = mgr.invoke::<ToolPreInvoke>(payload, ext, None).await;
    print_result("query_external_data (alice — in ACL)", &result);
    bg.wait_for_background_tasks().await;

    // --- Scenario 6: Awaiting plugin — cache miss path with .await ---
    // "charlie" is not in the cached ACL, so RemoteAuthz takes the
    // cache-miss branch and `.await`s a simulated remote call before
    // denying.
    println!("=== Scenario 6: query_external_data (async plugin, cache miss) ===\n");
    let payload = ToolInvokePayload {
        tool_name: "query_external_data".into(),
        user: "charlie".into(),
        arguments: "dataset=sales".into(),
    };
    let ext = make_tool_extensions("query_external_data", &[]);
    let (result, bg) = mgr.invoke::<ToolPreInvoke>(payload, ext, None).await;
    print_result("query_external_data (charlie — not in ACL)", &result);
    bg.wait_for_background_tasks().await;

    // --- Scenario 7: No user identity ---
    println!("=== Scenario 7: list_departments (no user identity) ===\n");
    let payload = ToolInvokePayload {
        tool_name: "list_departments".into(),
        user: "".into(),
        arguments: "".into(),
    };
    let ext = make_tool_extensions("list_departments", &[]);
    let (result, bg) = mgr.invoke::<ToolPreInvoke>(payload, ext, None).await;
    print_result("list_departments (no user)", &result);
    bg.wait_for_background_tasks().await;

    // --- Shutdown ---
    println!("--- Shutting down ---\n");
    mgr.shutdown().await;

    println!("=== Demo complete ===");
}
