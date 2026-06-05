// Integration tests for the identity_checker WASM plugin.
//
// Tests the full pipeline: native types → WIT → WASM sandbox → WIT → native result.
// Mirrors the scenarios from cpex-core/examples/identity_checker_demo.rs but
// exercises the actual WASM binary rather than native Rust code.

use std::path::PathBuf;
use std::sync::Arc;

use cpex_core::cmf::{CmfHook, ContentPart, Message, MessagePayload, Role, ToolCall, ToolResult};
use cpex_core::config::parse_config;
use cpex_core::extensions::security::{SubjectExtension, SubjectType};
use cpex_core::extensions::{Extensions, SecurityExtension};
use cpex_core::manager::PluginManager;
use cpex_wasm_host::factory::WasmPluginFactory;

fn wasm_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("wasm")
}

fn config_yaml() -> &'static str {
    r#"
plugin_settings:
  routing_enabled: true

global:
  policies:
    all:
      plugins: [identity-checker]

plugins:
  - name: identity-checker
    kind: wasm://plugin.wasm
    hooks: [cmf.tool_pre_invoke, cmf.tool_post_invoke]
    mode: sequential
    priority: 10
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
          max_instances: 10
          max_tables: 10

routes:
  - tool: "*"
    plugins: []
"#
}

async fn setup_manager() -> PluginManager {
    let mgr = PluginManager::default();
    mgr.register_factory("wasm://plugin.wasm", Box::new(WasmPluginFactory::new(wasm_dir())));

    let config = parse_config(config_yaml()).unwrap();
    mgr.load_config(config).unwrap();
    mgr.initialize().await.unwrap();
    mgr
}

fn make_tool_call_payload(tool_name: &str) -> MessagePayload {
    MessagePayload {
        message: Message {
            schema_version: "1.0".into(),
            role: Role::Assistant,
            content: vec![
                ContentPart::Text {
                    text: "Invoking tool.".into(),
                },
                ContentPart::ToolCall {
                    content: ToolCall {
                        tool_call_id: "tc_001".into(),
                        name: tool_name.into(),
                        arguments: [("employee_id".to_string(), serde_json::json!(42))].into(),
                        namespace: None,
                    },
                },
            ],
            channel: None,
        },
    }
}

fn make_tool_result_payload(tool_name: &str) -> MessagePayload {
    MessagePayload {
        message: Message {
            schema_version: "1.0".into(),
            role: Role::Tool,
            content: vec![ContentPart::ToolResult {
                content: ToolResult {
                    tool_call_id: "tc_001".into(),
                    tool_name: tool_name.into(),
                    content: serde_json::json!({"salary": 150000, "currency": "USD"}),
                    is_error: false,
                },
            }],
            channel: None,
        },
    }
}

fn make_security_ext(labels: &[&str], subject_id: &str, roles: &[&str]) -> Extensions {
    let mut security = SecurityExtension::default();
    for label in labels {
        security.add_label(*label);
    }
    security.subject = Some(SubjectExtension {
        id: Some(subject_id.into()),
        subject_type: Some(SubjectType::User),
        roles: roles.iter().map(|r| r.to_string()).collect(),
        permissions: Default::default(),
        ..Default::default()
    });

    Extensions {
        security: Some(Arc::new(security)),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Pre-invoke tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn test_pre_invoke_hr_admin_with_pii_allowed() {
    let mgr = setup_manager().await;
    let payload = make_tool_call_payload("get_compensation");
    let ext = make_security_ext(&["PII", "HR_DATA"], "alice", &["hr_admin"]);

    let (result, bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, ext, None)
        .await;
    bg.wait_for_background_tasks().await;

    assert!(
        result.continue_processing,
        "hr_admin should be allowed to access PII data"
    );
    assert!(result.violation.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_pre_invoke_viewer_with_pii_denied() {
    let mgr = setup_manager().await;
    let payload = make_tool_call_payload("get_compensation");
    let ext = make_security_ext(&["PII"], "bob", &["viewer"]);

    let (result, bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, ext, None)
        .await;
    bg.wait_for_background_tasks().await;

    assert!(
        !result.continue_processing,
        "viewer should be denied access to PII data"
    );
    let violation = result.violation.expect("should have violation");
    assert_eq!(violation.code, "insufficient_role");
    assert!(violation.reason.contains("hr_admin"));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_pre_invoke_no_pii_label_allowed() {
    let mgr = setup_manager().await;
    let payload = make_tool_call_payload("get_weather");
    let ext = make_security_ext(&["PUBLIC"], "bob", &["viewer"]);

    let (result, bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, ext, None)
        .await;
    bg.wait_for_background_tasks().await;

    assert!(
        result.continue_processing,
        "non-PII data should be accessible to any role"
    );
    assert!(result.violation.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_pre_invoke_no_subject_allowed() {
    let mgr = setup_manager().await;
    let payload = make_tool_call_payload("get_compensation");

    let mut security = SecurityExtension::default();
    security.add_label("PII");
    // No subject set — the plugin only denies if subject exists AND lacks hr_admin

    let ext = Extensions {
        security: Some(Arc::new(security)),
        ..Default::default()
    };

    let (result, bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, ext, None)
        .await;
    bg.wait_for_background_tasks().await;

    assert!(
        result.continue_processing,
        "no subject means no role check — should allow"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_pre_invoke_no_security_extension_allowed() {
    let mgr = setup_manager().await;
    let payload = make_tool_call_payload("get_compensation");

    let ext = Extensions::default();

    let (result, bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, ext, None)
        .await;
    bg.wait_for_background_tasks().await;

    assert!(
        result.continue_processing,
        "no security extension means no checks — should allow"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_pre_invoke_multiple_roles_including_hr_admin_allowed() {
    let mgr = setup_manager().await;
    let payload = make_tool_call_payload("get_compensation");
    let ext = make_security_ext(&["PII"], "carol", &["viewer", "hr_admin", "manager"]);

    let (result, bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, ext, None)
        .await;
    bg.wait_for_background_tasks().await;

    assert!(
        result.continue_processing,
        "user with hr_admin among multiple roles should be allowed"
    );
}

// ---------------------------------------------------------------------------
// Post-invoke tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn test_post_invoke_always_allows() {
    let mgr = setup_manager().await;
    let payload = make_tool_result_payload("get_compensation");
    let ext = make_security_ext(&["PII"], "alice", &["hr_admin"]);

    let (result, bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_post_invoke", payload, ext, None)
        .await;
    bg.wait_for_background_tasks().await;

    assert!(
        result.continue_processing,
        "post-invoke should always allow"
    );
    assert!(result.violation.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_post_invoke_viewer_still_allows() {
    let mgr = setup_manager().await;
    let payload = make_tool_result_payload("get_compensation");
    let ext = make_security_ext(&["PII"], "bob", &["viewer"]);

    let (result, bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_post_invoke", payload, ext, None)
        .await;
    bg.wait_for_background_tasks().await;

    assert!(
        result.continue_processing,
        "post-invoke does not enforce roles — should allow"
    );
}

// ---------------------------------------------------------------------------
// Pre-invoke + post-invoke chaining
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn test_full_lifecycle_authorized_user() {
    let mgr = setup_manager().await;

    // Pre-invoke
    let pre_payload = make_tool_call_payload("get_compensation");
    let ext = make_security_ext(&["PII", "HR_DATA"], "alice", &["hr_admin"]);

    let (pre_result, pre_bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", pre_payload, ext.clone(), None)
        .await;
    pre_bg.wait_for_background_tasks().await;

    assert!(pre_result.continue_processing, "pre-invoke should allow");

    // Post-invoke (simulating tool executed successfully)
    let post_payload = make_tool_result_payload("get_compensation");

    let (post_result, post_bg) = mgr
        .invoke_named::<CmfHook>(
            "cmf.tool_post_invoke",
            post_payload,
            ext,
            Some(pre_result.context_table),
        )
        .await;
    post_bg.wait_for_background_tasks().await;

    assert!(post_result.continue_processing, "post-invoke should allow");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_full_lifecycle_unauthorized_user_blocked_at_pre_invoke() {
    let mgr = setup_manager().await;

    let pre_payload = make_tool_call_payload("get_compensation");
    let ext = make_security_ext(&["PII"], "mallory", &["intern"]);

    let (pre_result, pre_bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", pre_payload, ext, None)
        .await;
    pre_bg.wait_for_background_tasks().await;

    assert!(
        !pre_result.continue_processing,
        "intern should be denied at pre-invoke"
    );
    let violation = pre_result.violation.expect("should have violation");
    assert_eq!(violation.code, "insufficient_role");
}
