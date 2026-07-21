// WASM Plugin Demo
//
// End-to-end demo mirroring cpex-core/examples/plugin_demo.rs, but all 4
// plugins run as sandboxed WASM binaries using a custom (user-defined)
// payload type.
//
// Demonstrates:
//   1. Define a custom payload + hook types (same as native plugin_demo)
//   2. Register the payload with PayloadSerializerRegistry
//   3. Load 4 WASM plugins via WasmPluginFactory (one per .wasm binary)
//   4. Multi-plugin pipeline with priority ordering and different modes
//   5. Policy groups with tag-based activation (pii, external_authz)
//   6. Context table threading across pre/post-invoke hooks
//   7. Fire-and-forget audit logging through WASM sandbox
//
// Prerequisites:
//   cd crates/cpex-wasm-host && make build-all-plugins
//
// Run:
//   cargo run -p cpex-wasm-host --example wasm_plugin_demo

use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use cpex_core::config::parse_config;
use cpex_core::executor::PipelineResult;
use cpex_core::extensions::container::Extensions;
use cpex_core::extensions::meta::MetaExtension;
use cpex_core::hooks::trait_def::{HookTypeDef, PluginResult};
use cpex_core::manager::PluginManager;

use cpex_wasm_host::factory::WasmPluginFactory;
use cpex_wasm_host::payload_registry::PayloadSerializerRegistry;

// ---------------------------------------------------------------------------
// Step 1: Define a custom payload and hook types
//
// This is the user-defined payload — it can be anything serializable.
// The same struct exists on each guest plugin for JSON serde roundtrip.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ToolInvokePayload {
    tool_name: String,
    user: String,
    arguments: String,
}

cpex_core::impl_plugin_payload!(ToolInvokePayload);
cpex_core::impl_wasm_payload!(ToolInvokePayload, "cpex.tool_invoke");

struct ToolPreInvoke;
impl HookTypeDef for ToolPreInvoke {
    type Payload = ToolInvokePayload;
    type Result = PluginResult<ToolInvokePayload>;
    const NAME: &'static str = "tool_pre_invoke";
}

struct ToolPostInvoke;
impl HookTypeDef for ToolPostInvoke {
    type Payload = ToolInvokePayload;
    type Result = PluginResult<ToolInvokePayload>;
    const NAME: &'static str = "tool_post_invoke";
}

// ---------------------------------------------------------------------------
// Step 2: Build extensions with MetaExtension for route resolution
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
// Step 3: Main — load config, register WASM factories, invoke hooks
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    // Initialize tracing so plugin cpex_log! calls are visible
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("info".parse().unwrap()),
        )
        .init();

    println!("=== WASM Plugin Demo ===\n");

    // --- Load config from YAML ---
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let config_path = crate_dir.join("config/config_plugin_demo.yaml");
    let wasm_dir = crate_dir.join("wasm");

    println!("--- Loading config from {} ---\n", config_path.display());
    let yaml = std::fs::read_to_string(&config_path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", config_path.display(), e));
    let cpex_config = parse_config(&yaml).unwrap();

    // --- Build payload registry with our custom type ---
    let registry = Arc::new({
        let mut r = PayloadSerializerRegistry::new();
        r.register::<ToolInvokePayload>();
        r
    });

    // --- Create manager and register a WASM factory per plugin kind ---
    let mgr = PluginManager::default();
    mgr.register_factory(
        "wasm://tool-invoke-checker.wasm",
        Box::new(WasmPluginFactory::new(wasm_dir.clone(), registry.clone())),
    );
    mgr.register_factory(
        "wasm://pii-guard.wasm",
        Box::new(WasmPluginFactory::new(wasm_dir.clone(), registry.clone())),
    );
    mgr.register_factory(
        "wasm://remote-authz.wasm",
        Box::new(WasmPluginFactory::new(wasm_dir.clone(), registry.clone())),
    );
    mgr.register_factory(
        "wasm://audit-logger-custom.wasm",
        Box::new(WasmPluginFactory::new(wasm_dir, registry)),
    );

    mgr.load_config(cpex_config).unwrap();

    println!("\n--- Initializing plugins ---\n");
    mgr.initialize().await.unwrap();

    println!("\nPlugins loaded: {}", mgr.plugin_count());
    println!(
        "Hooks registered: tool_pre_invoke={}, tool_post_invoke={}\n",
        mgr.has_hooks_for("tool_pre_invoke"),
        mgr.has_hooks_for("tool_post_invoke"),
    );

    // =========================================================================
    // Scenario 1: PII tool without clearance
    // Expected: identity-resolver allows → pii-guard DENIES
    // =========================================================================
    println!("=== Scenario 1: get_compensation (PII tool, no clearance) ===\n");
    let payload = ToolInvokePayload {
        tool_name: "get_compensation".into(),
        user: "alice".into(),
        arguments: "employee_id=42".into(),
    };
    let ext = make_tool_extensions("get_compensation", &[]);
    let (result, bg) = mgr.invoke::<ToolPreInvoke>(payload, ext, None).await;
    print_result("get_compensation (no clearance)", &result);
    bg.wait_for_background_tasks().await;

    // =========================================================================
    // Scenario 2: PII tool with clearance
    // Expected: identity-resolver allows → pii-guard allows → audit-logger logs
    // =========================================================================
    println!("=== Scenario 2: get_compensation (PII tool, with clearance) ===\n");
    let payload = ToolInvokePayload {
        tool_name: "get_compensation".into(),
        user: "alice".into(),
        arguments: "employee_id=42".into(),
    };
    let ext = make_tool_extensions("get_compensation", &[]);
    let mut ctx_table = cpex_core::context::PluginContextTable::new();
    ctx_table
        .global_state
        .insert("pii_clearance".into(), serde_json::Value::Bool(true));
    let (result, bg) = mgr
        .invoke::<ToolPreInvoke>(payload, ext, Some(ctx_table))
        .await;
    print_result("get_compensation (with clearance)", &result);
    bg.wait_for_background_tasks().await;

    // Thread context table into post-invoke
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

    // =========================================================================
    // Scenario 3: Non-PII tool
    // Expected: identity-resolver allows → audit-logger logs → ALLOWED
    // =========================================================================
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

    // =========================================================================
    // Scenario 4: Unknown tool (wildcard route)
    // Expected: identity-resolver allows → audit-logger logs → ALLOWED
    // =========================================================================
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

    // =========================================================================
    // Scenario 5: Remote authz — cache hit (alice is in ACL)
    // Expected: identity-resolver allows → remote-authz allows → ALLOWED
    // =========================================================================
    println!("=== Scenario 5: query_external_data (remote authz, ACL hit) ===\n");
    let payload = ToolInvokePayload {
        tool_name: "query_external_data".into(),
        user: "alice".into(),
        arguments: "dataset=sales".into(),
    };
    let ext = make_tool_extensions("query_external_data", &[]);
    let (result, bg) = mgr.invoke::<ToolPreInvoke>(payload, ext, None).await;
    print_result("query_external_data (alice — in ACL)", &result);
    bg.wait_for_background_tasks().await;

    // =========================================================================
    // Scenario 6: Remote authz — cache miss (charlie is NOT in ACL)
    // Expected: identity-resolver allows → remote-authz DENIES
    // =========================================================================
    println!("=== Scenario 6: query_external_data (remote authz, ACL miss) ===\n");
    let payload = ToolInvokePayload {
        tool_name: "query_external_data".into(),
        user: "charlie".into(),
        arguments: "dataset=sales".into(),
    };
    let ext = make_tool_extensions("query_external_data", &[]);
    let (result, bg) = mgr.invoke::<ToolPreInvoke>(payload, ext, None).await;
    print_result("query_external_data (charlie — not in ACL)", &result);
    bg.wait_for_background_tasks().await;

    // =========================================================================
    // Scenario 7: No user identity
    // Expected: identity-resolver DENIES (first in pipeline)
    // =========================================================================
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
