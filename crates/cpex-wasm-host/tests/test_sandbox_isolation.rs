//! Integration test: verifies WASM sandbox filesystem isolation.
//!
//! Loads a real `.wasm` plugin that attempts to read `/etc/passwd`.
//! With no filesystem policy, the read must fail (sandbox denies access).
//! This proves the isolation isn't just config-level — it's enforced at runtime.
//!
//! Requires: `wasm/fs-test.wasm` built from cpex-wasm-plugin with `--features fs-test`

use std::path::PathBuf;
use std::sync::Once;

use cpex_core::cmf::constants::SCHEMA_VERSION;
use cpex_core::cmf::{ContentPart, Message, MessagePayload, Role, ToolCall};
use cpex_core::context::PluginContext;
use cpex_core::extensions::container::Extensions;

use cpex_wasm_host::conversions::{native_context_to_wit, native_extensions_to_wit, native_payload_to_wit};
use cpex_wasm_host::sandbox_manager::{SandboxManager, SharedEngine};

static INIT: Once = Once::new();
fn init_tracing() {
    INIT.call_once(|| {
        tracing_subscriber::fmt()
            .with_test_writer()
            .with_env_filter("info")
            .init();
    });
}

fn wasm_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("wasm/fs-test.wasm")
}

fn make_payload() -> MessagePayload {
    MessagePayload {
        message: Message {
            schema_version: SCHEMA_VERSION.into(),
            role: Role::Assistant,
            content: vec![ContentPart::ToolCall {
                content: ToolCall {
                    tool_call_id: "tc_001".into(),
                    name: "read_file".into(),
                    arguments: Default::default(),
                    namespace: None,
                },
            }],
            channel: None,
        },
    }
}

#[tokio::test]
async fn test_plugin_cannot_read_etc_passwd_without_filesystem_policy() {
    init_tracing();
    let path = wasm_path();
    assert!(path.exists(),
        "WASM binary not found: {}. Run `make build-test-plugins` from crates/cpex-wasm-host first.",
        path.display());


    // Load plugin with NO filesystem policy (deny-all)
    let shared = SharedEngine::new().unwrap();
    let mut mgr = SandboxManager::with_shared_engine(&shared);
    mgr.load_wasmplugin(&path, None, "fs-test")
        .await
        .unwrap();

    let payload = make_payload();
    let wit_payload = cpex_wasm_host::sandbox_manager::types::HookPayload::Cmf(
        native_payload_to_wit(&payload),
    );
    let wit_ext = native_extensions_to_wit(&Extensions::default());
    let wit_ctx = native_context_to_wit(&PluginContext::default());

    let result = mgr
        .invoke("cmf.tool_pre_invoke", wit_payload, wit_ext, wit_ctx)
        .await
        .unwrap();

    // The plugin should have executed (continue_processing = true)
    assert!(result.continue_processing, "plugin should return allow");

    // Check the context — plugin writes fs_read_success into local_state
    let ctx = result.modified_context.expect("plugin should write context");
    let local_entries: std::collections::HashMap<String, String> = ctx
        .local_state
        .into_iter()
        .map(|e| (e.key, e.value))
        .collect();

    let success_value = local_entries
        .get("fs_read_success")
        .expect("plugin should set fs_read_success in context");

    // The read MUST have failed — sandbox denied it
    assert_eq!(
        success_value, "false",
        "SANDBOX ESCAPE: plugin successfully read /etc/passwd! fs_read_success={}, error={}",
        success_value,
        local_entries.get("fs_read_error").unwrap_or(&"<none>".to_string())
    );

    // Verify the error message indicates permission/access denial
    let error_msg = local_entries
        .get("fs_read_error")
        .expect("plugin should set fs_read_error");
    assert!(
        error_msg.contains("denied")
            || error_msg.contains("permission")
            || error_msg.contains("not found")
            || error_msg.contains("No such")
            || error_msg.contains("Capabilities insufficient"),
        "unexpected error message: {}",
        error_msg
    );
}

#[tokio::test]
async fn test_plugin_cannot_read_etc_passwd_with_unrelated_filesystem_policy() {
    init_tracing();
    let path = wasm_path();
    assert!(path.exists(),
        "WASM binary not found: {}. Run `make build-test-plugins` from crates/cpex-wasm-host first.",
        path.display());

    // Load plugin with filesystem policy that only allows /tmp
    let policy = cpex_wasm_host::policy_loader::SandboxPolicy {
        allowed_filesystem: vec![cpex_wasm_host::policy_loader::FilesystemRule {
            dir: Some("/tmp".to_string()),
            file: None,
            permission: "read".to_string(),
        }],
        ..Default::default()
    };

    let shared = SharedEngine::new().unwrap();
    let mut mgr = SandboxManager::with_shared_engine(&shared);
    mgr.load_wasmplugin(&path, Some(&policy), "fs-test-restricted")
        .await
        .unwrap();

    let payload = make_payload();
    let wit_payload = cpex_wasm_host::sandbox_manager::types::HookPayload::Cmf(
        native_payload_to_wit(&payload),
    );
    let wit_ext = native_extensions_to_wit(&Extensions::default());
    let wit_ctx = native_context_to_wit(&PluginContext::default());

    let result = mgr
        .invoke("cmf.tool_pre_invoke", wit_payload, wit_ext, wit_ctx)
        .await
        .unwrap();

    assert!(result.continue_processing);

    let ctx = result.modified_context.expect("plugin should write context");
    let local_entries: std::collections::HashMap<String, String> = ctx
        .local_state
        .into_iter()
        .map(|e| (e.key, e.value))
        .collect();

    let success_value = local_entries
        .get("fs_read_success")
        .expect("plugin should set fs_read_success");

    // Even with /tmp allowed, /etc/passwd must still be denied
    assert_eq!(
        success_value, "false",
        "SANDBOX ESCAPE: plugin read /etc/passwd despite only /tmp being allowed!"
    );
}
