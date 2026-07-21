//! Integration test: verifies WASM sandbox network isolation.
//!
//! Loads a real `.wasm` plugin that attempts DNS resolution / network access.
//! With no network policy (deny-all), the access must fail.
//!
//! Requires: `wasm/net-test.wasm` built from cpex-wasm-plugin with `--features net-test`

use std::path::PathBuf;
use std::sync::Once;

use cpex_core::cmf::constants::SCHEMA_VERSION;
use cpex_core::cmf::{ContentPart, Message, MessagePayload, Role, ToolCall};
use cpex_core::context::PluginContext;
use cpex_core::extensions::container::Extensions;

use cpex_wasm_host::conversions::{
    native_context_to_wit, native_extensions_to_wit, native_payload_to_wit,
};
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
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("wasm/net-test.wasm")
}

fn make_payload() -> MessagePayload {
    MessagePayload {
        message: Message {
            schema_version: SCHEMA_VERSION.into(),
            role: Role::Assistant,
            content: vec![ContentPart::ToolCall {
                content: ToolCall {
                    tool_call_id: "tc_001".into(),
                    name: "net_check".into(),
                    arguments: Default::default(),
                    namespace: None,
                },
            }],
            channel: None,
        },
    }
}

#[tokio::test]
async fn test_plugin_cannot_access_network_without_policy() {
    init_tracing();
    let path = wasm_path();
    assert!(path.exists(),
        "WASM binary not found: {}. Run `make build-test-plugins` from crates/cpex-wasm-host first.",
        path.display());

    // Load with NO network policy (deny-all)
    let shared = SharedEngine::new().unwrap();
    let mut mgr = SandboxManager::with_shared_engine(&shared);
    mgr.load_wasmplugin(&path, None, "net-test").await.unwrap();

    let payload = make_payload();
    let wit_payload =
        cpex_wasm_host::sandbox_manager::types::HookPayload::Cmf(native_payload_to_wit(&payload));
    let wit_ext = native_extensions_to_wit(&Extensions::default());
    let wit_ctx = native_context_to_wit(&PluginContext::default());

    let result = mgr
        .invoke("cmf.tool_pre_invoke", wit_payload, wit_ext, wit_ctx)
        .await
        .unwrap();

    assert!(result.continue_processing, "plugin should return allow");

    let ctx = result
        .modified_context
        .expect("plugin should write context");
    let local_entries: std::collections::HashMap<String, String> = ctx
        .local_state
        .into_iter()
        .map(|e| (e.key, e.value))
        .collect();

    let net_access = local_entries
        .get("net_access")
        .expect("plugin should set net_access");

    // Network access must be denied in sandbox
    assert_eq!(
        net_access, "\"denied\"",
        "SANDBOX ESCAPE: plugin accessed network without allowlist! net_access={}",
        net_access
    );
}

#[tokio::test]
async fn test_plugin_cannot_access_network_with_unrelated_allowlist() {
    init_tracing();
    let path = wasm_path();
    assert!(path.exists(),
        "WASM binary not found: {}. Run `make build-test-plugins` from crates/cpex-wasm-host first.",
        path.display());

    // Allow only "internal.example.com" — httpbin.org should still be denied
    let policy = cpex_wasm_host::policy_loader::SandboxPolicy {
        allowed_network: vec!["internal.example.com".to_string()],
        ..Default::default()
    };

    let shared = SharedEngine::new().unwrap();
    let mut mgr = SandboxManager::with_shared_engine(&shared);
    mgr.load_wasmplugin(&path, Some(&policy), "net-test-restricted")
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

    let ctx = result
        .modified_context
        .expect("plugin should write context");
    let local_entries: std::collections::HashMap<String, String> = ctx
        .local_state
        .into_iter()
        .map(|e| (e.key, e.value))
        .collect();

    let net_access = local_entries
        .get("net_access")
        .expect("plugin should set net_access");

    assert_eq!(
        net_access, "\"denied\"",
        "SANDBOX ESCAPE: plugin resolved DNS for httpbin.org despite allowlist being [internal.example.com]!"
    );
}
