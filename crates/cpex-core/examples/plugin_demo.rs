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
    fn config(&self) -> &PluginConfig { &self.cfg }
    async fn initialize(&self) -> Result<(), PluginError> {
        println!("  [identity-resolver] initialized");
        Ok(())
    }
    async fn shutdown(&self) -> Result<(), PluginError> {
        println!("  [identity-resolver] shutdown");
        Ok(())
    }
}

impl HookHandler<ToolPreInvoke> for IdentityResolver {
    fn handle(
        &self,
        payload: &ToolInvokePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<ToolInvokePayload> {
        if payload.user.is_empty() {
            println!("  [identity-resolver] DENIED: no user identity");
            return PluginResult::deny(
                PluginViolation::new("no_identity", "User identity is required"),
            );
        }
        println!("  [identity-resolver] OK: user '{}' identified", payload.user);
        PluginResult::allow()
    }
}

impl HookHandler<ToolPostInvoke> for IdentityResolver {
    fn handle(
        &self,
        payload: &ToolInvokePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<ToolInvokePayload> {
        println!("  [identity-resolver] post-invoke: user '{}' completed '{}'",
            payload.user, payload.tool_name);
        PluginResult::allow()
    }
}

/// PII guard — blocks access to sensitive tools without clearance.
struct PiiGuard {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for PiiGuard {
    fn config(&self) -> &PluginConfig { &self.cfg }
    // initialize() and shutdown() use defaults — no setup needed
}

impl HookHandler<ToolPreInvoke> for PiiGuard {
    fn handle(
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
            println!("  [pii-guard] DENIED: user '{}' lacks PII clearance for '{}'",
                payload.user, payload.tool_name);
            return PluginResult::deny(
                PluginViolation::new("pii_access_denied", "PII clearance required"),
            );
        }

        println!("  [pii-guard] OK: user '{}' has PII clearance", payload.user);
        PluginResult::allow()
    }
}

/// Audit logger — logs all tool invocations (fire-and-forget).
struct AuditLogger {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for AuditLogger {
    fn config(&self) -> &PluginConfig { &self.cfg }
    // initialize() and shutdown() use defaults — no setup needed
}

impl HookHandler<ToolPreInvoke> for AuditLogger {
    fn handle(
        &self,
        payload: &ToolInvokePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<ToolInvokePayload> {
        println!("  [audit-logger] LOG: user='{}' tool='{}' args='{}'",
            payload.user, payload.tool_name, payload.arguments);
        PluginResult::allow()
    }
}

impl HookHandler<ToolPostInvoke> for AuditLogger {
    fn handle(
        &self,
        payload: &ToolInvokePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<ToolInvokePayload> {
        println!("  [audit-logger] LOG: post-invoke user='{}' tool='{}'",
            payload.user, payload.tool_name);
        PluginResult::allow()
    }
}

// ---------------------------------------------------------------------------
// Step 3: Create plugin factories
// ---------------------------------------------------------------------------

struct IdentityFactory;
impl PluginFactory for IdentityFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, PluginError> {
        let plugin = Arc::new(IdentityResolver { cfg: config.clone() });
        Ok(PluginInstance {
            plugin: plugin.clone(),
            handlers: vec![
                ("tool_pre_invoke", Arc::new(TypedHandlerAdapter::<ToolPreInvoke, _>::new(plugin.clone()))),
                ("tool_post_invoke", Arc::new(TypedHandlerAdapter::<ToolPostInvoke, _>::new(plugin))),
            ],
        })
    }
}

struct PiiGuardFactory;
impl PluginFactory for PiiGuardFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, PluginError> {
        let plugin = Arc::new(PiiGuard { cfg: config.clone() });
        Ok(PluginInstance {
            plugin: plugin.clone(),
            handlers: vec![
                ("tool_pre_invoke", Arc::new(TypedHandlerAdapter::<ToolPreInvoke, _>::new(plugin))),
            ],
        })
    }
}

struct AuditLoggerFactory;
impl PluginFactory for AuditLoggerFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, PluginError> {
        let plugin = Arc::new(AuditLogger { cfg: config.clone() });
        Ok(PluginInstance {
            plugin: plugin.clone(),
            handlers: vec![
                ("tool_pre_invoke", Arc::new(TypedHandlerAdapter::<ToolPreInvoke, _>::new(plugin.clone()))),
                ("tool_post_invoke", Arc::new(TypedHandlerAdapter::<ToolPostInvoke, _>::new(plugin))),
            ],
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
        println!("  Result: DENIED by '{}' — {} [{}]",
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

    let mut mgr = PluginManager::default();
    mgr.register_factory("builtin/identity", Box::new(IdentityFactory));
    mgr.register_factory("builtin/pii", Box::new(PiiGuardFactory));
    mgr.register_factory("builtin/audit", Box::new(AuditLoggerFactory));
    mgr.load_config(cpex_config).unwrap();

    println!("\n--- Initializing plugins ---\n");
    mgr.initialize().await.unwrap();

    println!("\nPlugins loaded: {}", mgr.plugin_count());
    println!("Hooks registered: tool_pre_invoke={}, tool_post_invoke={}\n",
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
    let (result, bg) = mgr.invoke::<ToolPreInvoke>(
        payload, ext, None,
    ).await;
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
    let mut global_state = std::collections::HashMap::new();
    global_state.insert(
        "pii_clearance".into(),
        serde_json::Value::Bool(true),
    );
    // Pass global state via context table
    let mut ctx_table = cpex_core::context::PluginContextTable::new();
    // We need to seed global_state — create a dummy entry
    ctx_table.insert(
        "__seed__".into(),
        cpex_core::context::PluginContext::with_global_state(global_state),
    );
    let (result, bg) = mgr.invoke::<ToolPreInvoke>(
        payload, ext, Some(ctx_table),
    ).await;
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
    let (post_result, bg) = mgr.invoke::<ToolPostInvoke>(
        payload, ext, Some(result.context_table),
    ).await;
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
    let (result, bg) = mgr.invoke::<ToolPreInvoke>(
        payload, ext, None,
    ).await;
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
    let (result, bg) = mgr.invoke::<ToolPreInvoke>(
        payload, ext, None,
    ).await;
    print_result("some_other_tool (wildcard)", &result);
    bg.wait_for_background_tasks().await;

    // --- Scenario 5: No user identity ---
    println!("=== Scenario 5: list_departments (no user identity) ===\n");
    let payload = ToolInvokePayload {
        tool_name: "list_departments".into(),
        user: "".into(),
        arguments: "".into(),
    };
    let ext = make_tool_extensions("list_departments", &[]);
    let (result, bg) = mgr.invoke::<ToolPreInvoke>(
        payload, ext, None,
    ).await;
    print_result("list_departments (no user)", &result);
    bg.wait_for_background_tasks().await;

    // --- Shutdown ---
    println!("--- Shutting down ---\n");
    mgr.shutdown().await;

    println!("=== Demo complete ===");
}
