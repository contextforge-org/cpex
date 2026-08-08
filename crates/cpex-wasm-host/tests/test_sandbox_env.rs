// Location: ./crates/cpex-wasm-host/tests/test_sandbox_env.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
//! Integration test: verifies WASM sandbox environment variable isolation.
//!
//! Uses the env-sandbox-demo.wasm plugin (same binary as the env demo).
//! The plugin reads an env var name from ToolCall arguments and returns
//! ALLOW if visible or DENY (violation) if hidden.
//!
//! Requires: `wasm/env-sandbox-demo.wasm` built from cpex-wasm-plugin with `--features env-sandbox-demo`

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
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("wasm/env-sandbox-demo.wasm")
}

fn make_payload(env_var: &str) -> MessagePayload {
    let mut arguments = HashMap::new();
    arguments.insert("env_var".to_string(), serde_json::json!(env_var));
    MessagePayload {
        message: Message {
            schema_version: SCHEMA_VERSION.into(),
            role: Role::Assistant,
            content: vec![ContentPart::ToolCall {
                content: ToolCall {
                    tool_call_id: format!("tc_env_{}", env_var),
                    name: "env_check".into(),
                    arguments,
                    namespace: None,
                },
            }],
            channel: None,
        },
    }
}

async fn invoke_env_check(mgr: &mut SandboxManager, env_var: &str) -> bool {
    let payload = make_payload(env_var);
    let wit_payload =
        cpex_wasm_host::sandbox_manager::types::HookPayload::Cmf(native_payload_to_wit(&payload));
    let wit_ext = native_extensions_to_wit(&Extensions::default());
    let wit_ctx = native_context_to_wit(&PluginContext::default());

    let result = mgr
        .invoke("cmf.tool_pre_invoke", wit_payload, wit_ext, wit_ctx)
        .await
        .unwrap();

    // The env-sandbox-demo plugin returns DENY (continue_processing=false)
    // with violation code "env_access_denied" when the var is hidden.
    // Returns ALLOW (continue_processing=true) when the var is visible.
    result.continue_processing
}

#[tokio::test]
#[ignore = "requires pre-built WASM plugins — run `make build-test-plugins` first"]
async fn test_plugin_cannot_see_env_vars_without_policy() {
    init_tracing();
    let path = wasm_path();
    assert!(path.exists(),
        "WASM binary not found: {}. Run `make build-test-plugins` from crates/cpex-wasm-host first.",
        path.display());

    std::env::set_var("SECRET_API_KEY", "super-secret-value");

    let shared = SharedEngine::new().unwrap();
    let mut mgr = SandboxManager::with_shared_engine(&shared);
    mgr.load_wasmplugin(&path, None, "env-sandbox-test").await.unwrap();

    assert!(
        !invoke_env_check(&mut mgr, "HOME").await,
        "SANDBOX ESCAPE: plugin can see HOME without policy"
    );
    assert!(
        !invoke_env_check(&mut mgr, "PATH").await,
        "SANDBOX ESCAPE: plugin can see PATH without policy"
    );
    assert!(
        !invoke_env_check(&mut mgr, "SECRET_API_KEY").await,
        "SANDBOX ESCAPE: plugin can see SECRET_API_KEY without policy"
    );

    std::env::remove_var("SECRET_API_KEY");
}

#[tokio::test]
#[ignore = "requires pre-built WASM plugins — run `make build-test-plugins` first"]
async fn test_plugin_sees_only_allowed_env_var() {
    init_tracing();
    let path = wasm_path();
    assert!(path.exists(),
        "WASM binary not found: {}. Run `make build-test-plugins` from crates/cpex-wasm-host first.",
        path.display());

    std::env::set_var("CPEX_TEST_ALLOWED", "hello-from-host");
    std::env::set_var("SECRET_API_KEY", "super-secret-value");

    let policy = SandboxPolicy {
        allowed_env: vec!["CPEX_TEST_ALLOWED".to_string()],
        ..Default::default()
    };

    let shared = SharedEngine::new().unwrap();
    let mut mgr = SandboxManager::with_shared_engine(&shared);
    mgr.load_wasmplugin(&path, Some(&policy), "env-sandbox-test-selective")
        .await
        .unwrap();

    assert!(
        invoke_env_check(&mut mgr, "CPEX_TEST_ALLOWED").await,
        "allowed env var should be visible inside sandbox"
    );
    assert!(
        !invoke_env_check(&mut mgr, "HOME").await,
        "HOME should be hidden (not in allowed_env)"
    );
    assert!(
        !invoke_env_check(&mut mgr, "SECRET_API_KEY").await,
        "SANDBOX ESCAPE: plugin sees SECRET_API_KEY despite not being in allowed_env"
    );

    std::env::remove_var("CPEX_TEST_ALLOWED");
    std::env::remove_var("SECRET_API_KEY");
}
