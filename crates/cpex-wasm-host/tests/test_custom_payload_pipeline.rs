//! Integration test: verifies the custom-payload WASM plugin pipeline end-to-end.
//!
//! Loads 4 real `.wasm` plugins (tool-invoke-checker, pii-guard, remote-authz,
//! audit-logger-custom) that use a user-defined `ToolInvokePayload` routed
//! through HookPayload::Custom. Tests the full PluginManager → WasmPluginFactory
//! → SandboxManager → guest handler → result path.
//!
//! Requires: all 4 custom-payload `.wasm` binaries built and staged.
//! Run `make build-all-plugins` from crates/cpex-wasm-host first.

use std::path::PathBuf;
use std::sync::{Arc, Once};

use serde::{Deserialize, Serialize};

use cpex_core::config::parse_config;
use cpex_core::context::PluginContextTable;
use cpex_core::extensions::container::Extensions;
use cpex_core::extensions::meta::MetaExtension;
use cpex_core::hooks::trait_def::{HookTypeDef, PluginResult};
use cpex_core::manager::PluginManager;

use cpex_wasm_host::factory::WasmPluginFactory;
use cpex_wasm_host::payload_registry::PayloadSerializerRegistry;

static INIT: Once = Once::new();
fn init_tracing() {
    INIT.call_once(|| {
        tracing_subscriber::fmt()
            .with_test_writer()
            .with_env_filter("info")
            .init();
    });
}

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

fn wasm_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("wasm")
}

fn check_binaries_exist() {
    let dir = wasm_dir();
    for name in &[
        "tool-invoke-checker.wasm",
        "pii-guard.wasm",
        "remote-authz.wasm",
        "audit-logger-custom.wasm",
    ] {
        let path = dir.join(name);
        assert!(
            path.exists(),
            "WASM binary not found: {}. Run `make build-all-plugins` from crates/cpex-wasm-host first.",
            path.display()
        );
    }
}

fn make_extensions(tool_name: &str) -> Extensions {
    Extensions {
        meta: Some(Arc::new(MetaExtension {
            entity_type: Some("tool".into()),
            entity_name: Some(tool_name.into()),
            ..Default::default()
        })),
        ..Default::default()
    }
}

async fn setup_manager() -> PluginManager {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let config_path = crate_dir.join("config/config_plugin_demo.yaml");
    let wasm_dir = crate_dir.join("wasm");

    let yaml = std::fs::read_to_string(&config_path).unwrap();
    let cpex_config = parse_config(&yaml).unwrap();

    let registry = Arc::new({
        let mut r = PayloadSerializerRegistry::new();
        r.register::<ToolInvokePayload>();
        r
    });

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
    mgr.initialize().await.unwrap();
    mgr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_identity_resolver_denies_empty_user() {
    init_tracing();
    check_binaries_exist();
    let mgr = setup_manager().await;

    let payload = ToolInvokePayload {
        tool_name: "list_departments".into(),
        user: "".into(),
        arguments: "".into(),
    };
    let ext = make_extensions("list_departments");
    let (result, bg) = mgr.invoke::<ToolPreInvoke>(payload, ext, None).await;
    bg.wait_for_background_tasks().await;

    assert!(!result.continue_processing);
    let violation = result.violation.as_ref().unwrap();
    assert_eq!(violation.code, "no_identity");
    assert_eq!(violation.plugin_name.as_deref(), Some("identity-resolver"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pii_guard_denies_without_clearance() {
    init_tracing();
    check_binaries_exist();
    let mgr = setup_manager().await;

    let payload = ToolInvokePayload {
        tool_name: "get_compensation".into(),
        user: "alice".into(),
        arguments: "employee_id=42".into(),
    };
    let ext = make_extensions("get_compensation");
    let (result, bg) = mgr.invoke::<ToolPreInvoke>(payload, ext, None).await;
    bg.wait_for_background_tasks().await;

    assert!(!result.continue_processing);
    let violation = result.violation.as_ref().unwrap();
    assert_eq!(violation.code, "pii_access_denied");
    assert_eq!(violation.plugin_name.as_deref(), Some("pii-guard"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pii_guard_allows_with_clearance() {
    init_tracing();
    check_binaries_exist();
    let mgr = setup_manager().await;

    let payload = ToolInvokePayload {
        tool_name: "get_compensation".into(),
        user: "alice".into(),
        arguments: "employee_id=42".into(),
    };
    let ext = make_extensions("get_compensation");
    let mut ctx_table = PluginContextTable::new();
    ctx_table
        .global_state
        .insert("pii_clearance".into(), serde_json::Value::Bool(true));

    let (result, bg) = mgr
        .invoke::<ToolPreInvoke>(payload, ext, Some(ctx_table))
        .await;
    bg.wait_for_background_tasks().await;

    assert!(result.continue_processing);
    assert!(result.violation.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_remote_authz_allows_user_in_acl() {
    init_tracing();
    check_binaries_exist();
    let mgr = setup_manager().await;

    let payload = ToolInvokePayload {
        tool_name: "query_external_data".into(),
        user: "alice".into(),
        arguments: "dataset=sales".into(),
    };
    let ext = make_extensions("query_external_data");
    let (result, bg) = mgr.invoke::<ToolPreInvoke>(payload, ext, None).await;
    bg.wait_for_background_tasks().await;

    assert!(result.continue_processing);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_remote_authz_denies_user_not_in_acl() {
    init_tracing();
    check_binaries_exist();
    let mgr = setup_manager().await;

    let payload = ToolInvokePayload {
        tool_name: "query_external_data".into(),
        user: "charlie".into(),
        arguments: "dataset=sales".into(),
    };
    let ext = make_extensions("query_external_data");
    let (result, bg) = mgr.invoke::<ToolPreInvoke>(payload, ext, None).await;
    bg.wait_for_background_tasks().await;

    assert!(!result.continue_processing);
    let violation = result.violation.as_ref().unwrap();
    assert_eq!(violation.code, "remote_authz_denied");
    assert_eq!(violation.plugin_name.as_deref(), Some("remote-authz"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_non_pii_tool_allowed() {
    init_tracing();
    check_binaries_exist();
    let mgr = setup_manager().await;

    let payload = ToolInvokePayload {
        tool_name: "list_departments".into(),
        user: "bob".into(),
        arguments: "".into(),
    };
    let ext = make_extensions("list_departments");
    let (result, bg) = mgr.invoke::<ToolPreInvoke>(payload, ext, None).await;
    bg.wait_for_background_tasks().await;

    assert!(result.continue_processing);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_context_table_threads_across_hooks() {
    init_tracing();
    check_binaries_exist();
    let mgr = setup_manager().await;

    // Pre-invoke with clearance
    let payload = ToolInvokePayload {
        tool_name: "get_compensation".into(),
        user: "alice".into(),
        arguments: "employee_id=42".into(),
    };
    let ext = make_extensions("get_compensation");
    let mut ctx_table = PluginContextTable::new();
    ctx_table
        .global_state
        .insert("pii_clearance".into(), serde_json::Value::Bool(true));

    let (pre_result, bg) = mgr
        .invoke::<ToolPreInvoke>(payload, ext, Some(ctx_table))
        .await;
    bg.wait_for_background_tasks().await;
    assert!(pre_result.continue_processing);

    // Post-invoke with threaded context table
    let payload = ToolInvokePayload {
        tool_name: "get_compensation".into(),
        user: "alice".into(),
        arguments: "employee_id=42".into(),
    };
    let ext = make_extensions("get_compensation");
    let (post_result, bg) = mgr
        .invoke::<ToolPostInvoke>(payload, ext, Some(pre_result.context_table))
        .await;
    bg.wait_for_background_tasks().await;

    assert!(post_result.continue_processing);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_wildcard_route_allowed() {
    init_tracing();
    check_binaries_exist();
    let mgr = setup_manager().await;

    let payload = ToolInvokePayload {
        tool_name: "unknown_tool_xyz".into(),
        user: "bob".into(),
        arguments: "x=1".into(),
    };
    let ext = make_extensions("unknown_tool_xyz");
    let (result, bg) = mgr.invoke::<ToolPreInvoke>(payload, ext, None).await;
    bg.wait_for_background_tasks().await;

    assert!(result.continue_processing);
}
