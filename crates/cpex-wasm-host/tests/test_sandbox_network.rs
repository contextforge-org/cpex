// Location: ./crates/cpex-wasm-host/tests/test_sandbox_network.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
//! Integration tests: verifies WASM sandbox network isolation and policy enforcement.
//!
//! All tests use the net-sandbox-demo plugin which makes real WASI HTTP calls and
//! writes "allowed" or "denied" into local_state based on the outcome.
//!
//! Tests cover:
//!   - No policy: all outbound HTTP denied (deny-by-default)
//!   - Unrelated allowlist: request to unlisted host denied
//!   - Host allowlist: allowed host passes
//!   - Port enforcement: only listed ports permitted
//!   - Scheme enforcement: https-only by default
//!   - Method enforcement: only listed methods permitted
//!   - Unlisted host with allowlist present: denied
//!
//! Requires: `wasm/net-sandbox-demo.wasm` built with `--features net-sandbox-demo`

use std::collections::HashMap;
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
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("wasm/net-sandbox-demo.wasm")
}

fn make_http_payload(url: &str, method: &str) -> MessagePayload {
    let mut args = HashMap::new();
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

async fn invoke_http_plugin(mgr: &mut SandboxManager, url: &str, method: &str) -> String {
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

// ── Network isolation (deny-by-default) ─────────────────────────────────────

#[tokio::test]
#[ignore = "requires pre-built WASM plugins — run `make build-test-plugins` first"]
async fn test_plugin_cannot_access_network_without_policy() {
    init_tracing();
    let path = wasm_path();
    assert!(path.exists(),
        "WASM binary not found: {}. Run `make build-test-plugins` from crates/cpex-wasm-host first.",
        path.display());

    let shared = SharedEngine::new().unwrap();
    let mut mgr = SandboxManager::with_shared_engine(&shared);
    mgr.load_wasmplugin(&path, None, "net-test-deny-all").await.unwrap();

    let result = invoke_http_plugin(&mut mgr, "https://example.com/", "GET").await;
    assert_eq!(
        result, "\"denied\"",
        "SANDBOX ESCAPE: plugin accessed network without allowlist! result={}",
        result
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

    let result = invoke_http_plugin(&mut mgr, "https://example.com/", "GET").await;
    assert_eq!(
        result, "\"denied\"",
        "SANDBOX ESCAPE: plugin reached example.com despite allowlist being [internal.example.com]!"
    );
}

// ── WASI HTTP enforcement tests ─────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires pre-built WASM plugins — run `make build-test-plugins` first"]
async fn test_http_request_allowed_when_host_matches() {
    init_tracing();
    let path = wasm_path();
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
    mgr.load_wasmplugin(&path, Some(&policy), "net-sandbox-demo-allow").await.unwrap();

    let result = invoke_http_plugin(&mut mgr, "https://example.com/", "GET").await;
    assert_eq!(result, "\"allowed\"", "request to allowed host should pass, got: {}", result);
}

#[tokio::test]
#[ignore = "requires pre-built WASM plugins — run `make build-test-plugins` first"]
async fn test_http_request_denied_for_blocked_port() {
    init_tracing();
    let path = wasm_path();
    assert!(path.exists(),
        "WASM binary not found: {}. Run `make build-test-plugins` first.", path.display());

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
    mgr.load_wasmplugin(&path, Some(&policy), "net-sandbox-demo-port").await.unwrap();

    let result = invoke_http_plugin(&mut mgr, "https://example.com:8080/", "GET").await;
    assert_eq!(result, "\"denied\"", "request on blocked port 8080 must be denied, got: {}", result);
}

#[tokio::test]
#[ignore = "requires pre-built WASM plugins — run `make build-test-plugins` first"]
async fn test_http_request_denied_for_blocked_scheme() {
    init_tracing();
    let path = wasm_path();
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
    mgr.load_wasmplugin(&path, Some(&policy), "net-sandbox-demo-scheme").await.unwrap();

    let result = invoke_http_plugin(&mut mgr, "http://example.com/", "GET").await;
    assert_eq!(result, "\"denied\"", "plain HTTP must be denied when only https is allowed, got: {}", result);
}

#[tokio::test]
#[ignore = "requires pre-built WASM plugins — run `make build-test-plugins` first"]
async fn test_http_request_denied_for_blocked_method() {
    init_tracing();
    let path = wasm_path();
    assert!(path.exists(),
        "WASM binary not found: {}. Run `make build-test-plugins` first.", path.display());

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
    mgr.load_wasmplugin(&path, Some(&policy), "net-sandbox-demo-method").await.unwrap();

    let result = invoke_http_plugin(&mut mgr, "https://example.com/", "POST").await;
    assert_eq!(result, "\"denied\"", "POST must be denied when only GET is allowed, got: {}", result);
}

#[tokio::test]
#[ignore = "requires pre-built WASM plugins — run `make build-test-plugins` first"]
async fn test_http_request_denied_for_unlisted_host() {
    init_tracing();
    let path = wasm_path();
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
    mgr.load_wasmplugin(&path, Some(&policy), "net-sandbox-demo-unlisted").await.unwrap();

    let result = invoke_http_plugin(&mut mgr, "https://other.com/", "GET").await;
    assert_eq!(result, "\"denied\"", "request to unlisted host must be denied, got: {}", result);
}
