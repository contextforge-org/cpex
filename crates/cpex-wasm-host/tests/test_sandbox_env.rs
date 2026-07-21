//! Integration test: verifies WASM sandbox environment variable isolation.
//!
//! Loads a real `.wasm` plugin that reads env vars (HOME, PATH, SECRET_API_KEY).
//! With no env policy, all must be empty. With a selective policy, only the
//! explicitly allowed variable should be visible.
//!
//! Requires: `wasm/env-test.wasm` built from cpex-wasm-plugin with `--features env-test`

use std::path::PathBuf;
use std::sync::Once;

use cpex_core::cmf::constants::SCHEMA_VERSION;
use cpex_core::cmf::{ContentPart, Message, MessagePayload, Role, ToolCall};
use cpex_core::context::PluginContext;
use cpex_core::extensions::container::Extensions;

use cpex_wasm_host::conversions::{
    native_context_to_wit, native_extensions_to_wit, native_payload_to_wit,
};
use cpex_wasm_host::policy_loader::SandboxPolicy;
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
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("wasm/env-test.wasm")
}

fn make_payload() -> MessagePayload {
    MessagePayload {
        message: Message {
            schema_version: SCHEMA_VERSION.into(),
            role: Role::Assistant,
            content: vec![ContentPart::ToolCall {
                content: ToolCall {
                    tool_call_id: "tc_001".into(),
                    name: "env_check".into(),
                    arguments: Default::default(),
                    namespace: None,
                },
            }],
            channel: None,
        },
    }
}

fn extract_context(
    result: &cpex_wasm_host::sandbox_manager::types::HookResult,
) -> std::collections::HashMap<String, String> {
    result
        .modified_context
        .as_ref()
        .expect("plugin should write context")
        .local_state
        .iter()
        .map(|e| (e.key.clone(), e.value.clone()))
        .collect()
}

#[tokio::test]
async fn test_plugin_cannot_see_env_vars_without_policy() {
    init_tracing();
    let path = wasm_path();
    assert!(path.exists(),
        "WASM binary not found: {}. Run `make build-test-plugins` from crates/cpex-wasm-host first.",
        path.display());

    // Set a host env var that the plugin will try to read
    std::env::set_var("SECRET_API_KEY", "super-secret-value");

    // Load with NO env policy (deny-all)
    let shared = SharedEngine::new().unwrap();
    let mut mgr = SandboxManager::with_shared_engine(&shared);
    mgr.load_wasmplugin(&path, None, "env-test").await.unwrap();

    let payload = make_payload();
    let wit_payload =
        cpex_wasm_host::sandbox_manager::types::HookPayload::Cmf(native_payload_to_wit(&payload));
    let wit_ext = native_extensions_to_wit(&Extensions::default());
    let wit_ctx = native_context_to_wit(&PluginContext::default());

    let result = mgr
        .invoke("cmf.tool_pre_invoke", wit_payload, wit_ext, wit_ctx)
        .await
        .unwrap();

    assert!(result.continue_processing);

    let entries = extract_context(&result);

    // HOME must be empty (not exposed)
    let home = entries.get("env_HOME").unwrap_or(&String::new()).clone();
    assert_eq!(
        home, "\"\"",
        "SANDBOX ESCAPE: plugin can see HOME='{}'",
        home
    );

    // PATH must be empty
    let path_val = entries.get("env_PATH").unwrap_or(&String::new()).clone();
    assert_eq!(
        path_val, "\"\"",
        "SANDBOX ESCAPE: plugin can see PATH='{}'",
        path_val
    );

    // SECRET_API_KEY must be empty
    let secret = entries
        .get("env_SECRET_API_KEY")
        .unwrap_or(&String::new())
        .clone();
    assert_eq!(
        secret, "\"\"",
        "SANDBOX ESCAPE: plugin can see SECRET_API_KEY='{}'",
        secret
    );

    // Clean up
    std::env::remove_var("SECRET_API_KEY");
}

#[tokio::test]
async fn test_plugin_sees_only_allowed_env_var() {
    init_tracing();
    let path = wasm_path();
    assert!(path.exists(),
        "WASM binary not found: {}. Run `make build-test-plugins` from crates/cpex-wasm-host first.",
        path.display());

    // Set the allowed var and a secret var on the host
    std::env::set_var("CPEX_TEST_ALLOWED", "hello-from-host");
    std::env::set_var("SECRET_API_KEY", "super-secret-value");

    // Policy allows ONLY CPEX_TEST_ALLOWED
    let policy = SandboxPolicy {
        allowed_env: vec!["CPEX_TEST_ALLOWED".to_string()],
        ..Default::default()
    };

    let shared = SharedEngine::new().unwrap();
    let mut mgr = SandboxManager::with_shared_engine(&shared);
    mgr.load_wasmplugin(&path, Some(&policy), "env-test-selective")
        .await
        .unwrap();

    let payload = make_payload();
    let wit_payload =
        cpex_wasm_host::sandbox_manager::types::HookPayload::Cmf(native_payload_to_wit(&payload));
    let wit_ext = native_extensions_to_wit(&Extensions::default());
    let wit_ctx = native_context_to_wit(&PluginContext::default());

    let result = mgr
        .invoke("cmf.tool_pre_invoke", wit_payload, wit_ext, wit_ctx)
        .await
        .unwrap();

    assert!(result.continue_processing);

    let entries = extract_context(&result);

    // CPEX_TEST_ALLOWED should be visible
    let allowed = entries
        .get("env_CPEX_TEST_ALLOWED")
        .unwrap_or(&String::new())
        .clone();
    assert_eq!(
        allowed, "\"hello-from-host\"",
        "allowed env var should be visible, got: {}",
        allowed
    );

    // HOME must still be empty (not in allowed list)
    let home = entries.get("env_HOME").unwrap_or(&String::new()).clone();
    assert_eq!(home, "\"\"", "HOME should be hidden, got: {}", home);

    // SECRET_API_KEY must still be empty
    let secret = entries
        .get("env_SECRET_API_KEY")
        .unwrap_or(&String::new())
        .clone();
    assert_eq!(
        secret, "\"\"",
        "SANDBOX ESCAPE: plugin sees SECRET_API_KEY despite not being in allowed_env"
    );

    // Clean up
    std::env::remove_var("CPEX_TEST_ALLOWED");
    std::env::remove_var("SECRET_API_KEY");
}
