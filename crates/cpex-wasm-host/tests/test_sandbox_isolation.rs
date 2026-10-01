// Location: ./crates/cpex-wasm-host/tests/test_sandbox_isolation.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
//! Integration test: verifies WASM sandbox filesystem isolation.
//!
//! Uses the fs-sandbox-demo.wasm plugin (same binary as the FS demo) with
//! operation=read, path=/etc/passwd. With no filesystem policy, the read must
//! be denied. With an unrelated policy (/tmp only), /etc/passwd must still be
//! denied. This proves isolation is enforced at runtime.
//!
//! Requires: `wasm/fs-sandbox-demo.wasm` built from cpex-wasm-plugin with `--features fs-sandbox-demo`

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
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("wasm/fs-sandbox-demo.wasm")
}

fn make_read_payload(path: &str) -> MessagePayload {
    let mut arguments = HashMap::new();
    arguments.insert("operation".to_string(), serde_json::json!("read"));
    arguments.insert("path".to_string(), serde_json::json!(path));
    MessagePayload {
        message: Message {
            schema_version: SCHEMA_VERSION.into(),
            role: Role::Assistant,
            content: vec![ContentPart::ToolCall {
                content: ToolCall {
                    tool_call_id: "tc_001".into(),
                    name: "read_file".into(),
                    arguments,
                    namespace: None,
                },
            }],
            channel: None,
        },
    }
}

#[tokio::test]
#[ignore = "requires pre-built WASM plugins — run `make build-test-plugins` first"]
async fn test_plugin_cannot_read_etc_passwd_without_filesystem_policy() {
    init_tracing();
    let path = wasm_path();
    assert!(path.exists(),
        "WASM binary not found: {}. Run `make build-test-plugins` from crates/cpex-wasm-host first.",
        path.display());

    let shared = SharedEngine::new().unwrap();
    let mut mgr = SandboxManager::with_shared_engine(&shared);
    mgr.load_wasmplugin(&path, None, "fs-sandbox-test")
        .await
        .unwrap();

    let payload = make_read_payload("/etc/passwd");
    let wit_payload =
        cpex_wasm_host::sandbox_manager::types::HookPayload::Cmf(native_payload_to_wit(&payload));
    let wit_ext = native_extensions_to_wit(&Extensions::default());
    let wit_ctx = native_context_to_wit(&PluginContext::default());

    let result = mgr
        .invoke("cmf.tool_pre_invoke", wit_payload, wit_ext, wit_ctx)
        .await
        .unwrap();

    assert!(
        !result.continue_processing,
        "SANDBOX ESCAPE: plugin successfully read /etc/passwd without filesystem policy"
    );

    let violation = result.violation.as_ref().expect("should have a violation");
    assert_eq!(violation.code, "fs_access_denied");
}

#[tokio::test]
#[ignore = "requires pre-built WASM plugins — run `make build-test-plugins` first"]
async fn test_plugin_cannot_read_etc_passwd_with_unrelated_filesystem_policy() {
    init_tracing();
    let path = wasm_path();
    assert!(path.exists(),
        "WASM binary not found: {}. Run `make build-test-plugins` from crates/cpex-wasm-host first.",
        path.display());

    let policy = cpex_wasm_host::policy_loader::SandboxPolicy {
        allowed_filesystem: vec![cpex_wasm_host::policy_loader::FilesystemRule {
            dir: Some("/tmp".to_string()),
            file: None,
            permission: "read-only".to_string(),
        }],
        ..Default::default()
    };

    let shared = SharedEngine::new().unwrap();
    let mut mgr = SandboxManager::with_shared_engine(&shared);
    mgr.load_wasmplugin(&path, Some(&policy), "fs-sandbox-test-restricted")
        .await
        .unwrap();

    let payload = make_read_payload("/etc/passwd");
    let wit_payload =
        cpex_wasm_host::sandbox_manager::types::HookPayload::Cmf(native_payload_to_wit(&payload));
    let wit_ext = native_extensions_to_wit(&Extensions::default());
    let wit_ctx = native_context_to_wit(&PluginContext::default());

    let result = mgr
        .invoke("cmf.tool_pre_invoke", wit_payload, wit_ext, wit_ctx)
        .await
        .unwrap();

    assert!(
        !result.continue_processing,
        "SANDBOX ESCAPE: plugin read /etc/passwd despite only /tmp being allowed!"
    );

    let violation = result.violation.as_ref().expect("should have a violation");
    assert_eq!(violation.code, "fs_access_denied");
}
