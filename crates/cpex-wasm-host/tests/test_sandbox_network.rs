// Location: ./crates/cpex-wasm-host/tests/test_sandbox_network.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
//! Integration tests: verifies WASM sandbox network isolation and policy enforcement.
//!
//! Two sets of tests:
//!
//! 1. DNS isolation (net-test plugin) — proves the raw socket / DNS layer is blocked.
//!    Requires: `wasm/net-test.wasm` built with `--features net-test`
//!
//! 2. WASI HTTP enforcement (net-http-test plugin) — proves that port, scheme, and
//!    HTTP method constraints in NetworkRule are enforced by WasiHttpHooks::send_request.
//!    Requires: `wasm/net-http-test.wasm` built with `--features net-http-test`

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
#[ignore = "requires pre-built WASM plugins — run `make build-test-plugins` first"]
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
#[ignore = "requires pre-built WASM plugins — run `make build-test-plugins` first"]
async fn test_plugin_cannot_access_network_with_unrelated_allowlist() {
    init_tracing();
    let path = wasm_path();
    assert!(path.exists(),
        "WASM binary not found: {}. Run `make build-test-plugins` from crates/cpex-wasm-host first.",
        path.display());

    // Allow only "internal.example.com" — httpbin.org should still be denied
    let policy = cpex_wasm_host::policy_loader::SandboxPolicy {
        allowed_network: vec![cpex_wasm_host::policy_loader::NetworkRule {
            host: "internal.example.com".to_string(),
            ..Default::default()
        }],
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

// ── WASI HTTP enforcement tests (net-http-test plugin) ────────────────────────
//
// These tests prove that port, scheme, and method constraints in NetworkRule
// are enforced by WasiHttpHooks::send_request. They use the net-http-test
// plugin which makes real WASI outgoing HTTP calls.

fn http_wasm_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("wasm/net-http-test.wasm")
}

fn make_http_payload(url: &str, method: &str) -> MessagePayload {
    let mut args = std::collections::HashMap::new();
    args.insert("url".to_string(), serde_json::json!(url));
    args.insert("method".to_string(), serde_json::json!(method));

    MessagePayload {
        message: Message {
            schema_version: SCHEMA_VERSION.into(),
            role: Role::Assistant,
            content: vec![ContentPart::ToolCall {
                content: ToolCall {
                    tool_call_id: "tc_http".into(),
                    name: "http_check".into(),
                    arguments: args,
                    namespace: None,
                },
            }],
            channel: None,
        },
    }
}

async fn invoke_http_plugin(
    mgr: &mut cpex_wasm_host::sandbox_manager::SandboxManager,
    url: &str,
    method: &str,
) -> String {
    use cpex_wasm_host::conversions::{
        native_context_to_wit, native_extensions_to_wit, native_payload_to_wit,
    };
    let payload = make_http_payload(url, method);
    let wit_payload = cpex_wasm_host::sandbox_manager::types::HookPayload::Cmf(
        native_payload_to_wit(&payload),
    );
    let wit_ext = native_extensions_to_wit(&Extensions::default());
    let wit_ctx = native_context_to_wit(&PluginContext::default());

    let result = mgr
        .invoke("cmf.tool_pre_invoke", wit_payload, wit_ext, wit_ctx)
        .await
        .unwrap();

    result
        .modified_context
        .expect("plugin should write context")
        .local_state
        .into_iter()
        .find(|e| e.key == "http_result")
        .map(|e| e.value)
        .unwrap_or_default()
}

#[tokio::test]
#[ignore = "requires pre-built WASM plugins — run `make build-test-plugins` first"]
async fn test_http_request_allowed_when_host_matches() {
    init_tracing();
    let path = http_wasm_path();
    assert!(path.exists(),
        "WASM binary not found: {}. Run `make build-test-plugins` first.", path.display());

    let policy = cpex_wasm_host::policy_loader::SandboxPolicy {
        allowed_network: vec![cpex_wasm_host::policy_loader::NetworkRule {
            host: "example.com".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    };

    let shared = SharedEngine::new().unwrap();
    let mut mgr = SandboxManager::with_shared_engine(&shared);
    mgr.load_wasmplugin(&path, Some(&policy), "net-http-test-allow").await.unwrap();

    let result = invoke_http_plugin(&mut mgr, "https://example.com/", "GET").await;
    assert_eq!(result, "\"allowed\"", "request to allowed host should pass, got: {}", result);
}

#[tokio::test]
#[ignore = "requires pre-built WASM plugins — run `make build-test-plugins` first"]
async fn test_http_request_denied_for_blocked_port() {
    init_tracing();
    let path = http_wasm_path();
    assert!(path.exists(),
        "WASM binary not found: {}. Run `make build-test-plugins` first.", path.display());

    // Allow example.com but only on port 443 — port 8080 must be denied.
    let policy = cpex_wasm_host::policy_loader::SandboxPolicy {
        allowed_network: vec![cpex_wasm_host::policy_loader::NetworkRule {
            host: "example.com".to_string(),
            ports: vec![443],
            ..Default::default()
        }],
        ..Default::default()
    };

    let shared = SharedEngine::new().unwrap();
    let mut mgr = SandboxManager::with_shared_engine(&shared);
    mgr.load_wasmplugin(&path, Some(&policy), "net-http-test-port").await.unwrap();

    let result = invoke_http_plugin(&mut mgr, "https://example.com:8080/", "GET").await;
    assert_eq!(result, "\"denied\"", "request on blocked port 8080 must be denied, got: {}", result);
}

#[tokio::test]
#[ignore = "requires pre-built WASM plugins — run `make build-test-plugins` first"]
async fn test_http_request_denied_for_blocked_scheme() {
    init_tracing();
    let path = http_wasm_path();
    assert!(path.exists(),
        "WASM binary not found: {}. Run `make build-test-plugins` first.", path.display());

    // Default schemes = ["https"] only — plain HTTP must be denied.
    let policy = cpex_wasm_host::policy_loader::SandboxPolicy {
        allowed_network: vec![cpex_wasm_host::policy_loader::NetworkRule {
            host: "example.com".to_string(),
            ..Default::default() // schemes defaults to ["https"]
        }],
        ..Default::default()
    };

    let shared = SharedEngine::new().unwrap();
    let mut mgr = SandboxManager::with_shared_engine(&shared);
    mgr.load_wasmplugin(&path, Some(&policy), "net-http-test-scheme").await.unwrap();

    let result = invoke_http_plugin(&mut mgr, "http://example.com/", "GET").await;
    assert_eq!(result, "\"denied\"", "plain HTTP must be denied when only https is allowed, got: {}", result);
}

#[tokio::test]
#[ignore = "requires pre-built WASM plugins — run `make build-test-plugins` first"]
async fn test_http_request_denied_for_blocked_method() {
    init_tracing();
    let path = http_wasm_path();
    assert!(path.exists(),
        "WASM binary not found: {}. Run `make build-test-plugins` first.", path.display());

    // Only GET allowed — POST must be denied.
    let policy = cpex_wasm_host::policy_loader::SandboxPolicy {
        allowed_network: vec![cpex_wasm_host::policy_loader::NetworkRule {
            host: "example.com".to_string(),
            methods: vec!["GET".to_string()],
            ..Default::default()
        }],
        ..Default::default()
    };

    let shared = SharedEngine::new().unwrap();
    let mut mgr = SandboxManager::with_shared_engine(&shared);
    mgr.load_wasmplugin(&path, Some(&policy), "net-http-test-method").await.unwrap();

    let result = invoke_http_plugin(&mut mgr, "https://example.com/", "POST").await;
    assert_eq!(result, "\"denied\"", "POST must be denied when only GET is allowed, got: {}", result);
}

#[tokio::test]
#[ignore = "requires pre-built WASM plugins — run `make build-test-plugins` first"]
async fn test_http_request_denied_for_unlisted_host() {
    init_tracing();
    let path = http_wasm_path();
    assert!(path.exists(),
        "WASM binary not found: {}. Run `make build-test-plugins` first.", path.display());

    // Allow example.com — request to other.com must be denied.
    let policy = cpex_wasm_host::policy_loader::SandboxPolicy {
        allowed_network: vec![cpex_wasm_host::policy_loader::NetworkRule {
            host: "example.com".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    };

    let shared = SharedEngine::new().unwrap();
    let mut mgr = SandboxManager::with_shared_engine(&shared);
    mgr.load_wasmplugin(&path, Some(&policy), "net-http-test-unlisted").await.unwrap();

    let result = invoke_http_plugin(&mut mgr, "https://other.com/", "GET").await;
    assert_eq!(result, "\"denied\"", "request to unlisted host must be denied, got: {}", result);
}
