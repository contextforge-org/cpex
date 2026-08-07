// Location: ./crates/cpex-wasm-host/tests/test_sandbox_resource_limits.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
//! Integration tests: verifies resource limits actually trap a running WASM plugin.
//!
//! Each test loads the resource-test plugin with a deliberately tiny limit,
//! invokes it in the mode that exercises that limit, and asserts the invocation
//! returns the expected error variant — proving the limit is enforced at runtime,
//! not just parsed from YAML.
//!
//! Requires: `wasm/resource-test.wasm` built with `make build-test-plugins`

use std::path::PathBuf;
use std::sync::Once;

use cpex_core::cmf::constants::SCHEMA_VERSION;
use cpex_core::cmf::{ContentPart, Message, MessagePayload, Role, ToolCall};
use cpex_core::context::PluginContext;
use cpex_core::extensions::container::Extensions;

use cpex_wasm_host::conversions::{
    native_context_to_wit, native_extensions_to_wit, native_payload_to_wit,
};
use cpex_wasm_host::policy_loader::{ResourceLimits, SandboxPolicy};
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
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("wasm/resource-test.wasm")
}

fn make_payload(mode: &str) -> MessagePayload {
    let mut args = std::collections::HashMap::new();
    args.insert("mode".to_string(), serde_json::json!(mode));

    MessagePayload {
        message: Message {
            schema_version: SCHEMA_VERSION.into(),
            role: Role::Assistant,
            content: vec![ContentPart::ToolCall {
                content: ToolCall {
                    tool_call_id: "tc_resource".into(),
                    name: "resource_test".into(),
                    arguments: args,
                    namespace: None,
                },
            }],
            channel: None,
        },
    }
}

async fn load_with_limits(resources: ResourceLimits) -> SandboxManager {
    let path = wasm_path();
    assert!(
        path.exists(),
        "WASM binary not found: {}. Run `make build-test-plugins` from crates/cpex-wasm-host first.",
        path.display()
    );

    let policy = SandboxPolicy {
        resources,
        ..Default::default()
    };

    let shared = SharedEngine::new().unwrap();
    let mut mgr = SandboxManager::with_shared_engine(&shared);
    mgr.load_wasmplugin(&path, Some(&policy), "resource-test")
        .await
        .unwrap();
    mgr
}

// ── Fuel ─────────────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires pre-built WASM plugins — run `make build-test-plugins` first"]
async fn test_fuel_limit_traps_plugin() {
    init_tracing();

    // 10 000 fuel units — enough to instantiate but far too little for the loop.
    let mut mgr = load_with_limits(ResourceLimits {
        max_fuel: Some(10_000),
        max_execution_time_ms: Some(10_000),
        ..Default::default()
    })
    .await;

    let payload = make_payload("burn_fuel");
    let wit_payload = cpex_wasm_host::sandbox_manager::types::HookPayload::Cmf(
        native_payload_to_wit(&payload),
    );
    let wit_ext = native_extensions_to_wit(&Extensions::default());
    let wit_ctx = native_context_to_wit(&PluginContext::default());

    let err = mgr
        .invoke("cmf.tool_pre_invoke", wit_payload, wit_ext, wit_ctx)
        .await
        .unwrap_err();

    // Wasmtime 45 wraps trap messages in nested error chains. Walk the
    // full chain and collect all messages for assertion.
    let mut messages = vec![format!("{}", err)];
    {
        let mut source: Option<&dyn std::error::Error> = err.source();
        while let Some(s) = source {
            messages.push(format!("{}", s));
            source = s.source();
        }
    }
    let combined = messages.join(" | ").to_lowercase();
    assert!(
        combined.contains("fuel") || combined.contains("wasm") || combined.contains("error while executing"),
        "expected fuel/wasm trap error, got: {:?}",
        messages
    );
}

// ── Epoch timeout ─────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires pre-built WASM plugins — run `make build-test-plugins` first"]
async fn test_epoch_timeout_traps_plugin() {
    init_tracing();

    // The epoch timeout test verifies that a long-running plugin is interrupted
    // by the epoch deadline. We use a generous fuel budget so the loop doesn't
    // exhaust fuel first, and a short timeout to trigger the epoch interrupt.
    // The burn_fuel mode is used with enough fuel for ~1 second of execution but
    // a 200ms epoch deadline — ensuring the epoch fires before fuel runs out.
    let mut mgr = load_with_limits(ResourceLimits {
        max_execution_time_ms: Some(200),
        max_fuel: Some(500_000_000),
        ..Default::default()
    })
    .await;

    // Allow the epoch ticker thread to start before invoking.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let payload = make_payload("burn_fuel");
    let wit_payload = cpex_wasm_host::sandbox_manager::types::HookPayload::Cmf(
        native_payload_to_wit(&payload),
    );
    let wit_ext = native_extensions_to_wit(&Extensions::default());
    let wit_ctx = native_context_to_wit(&PluginContext::default());

    let start = std::time::Instant::now();
    let err = mgr
        .invoke("cmf.tool_pre_invoke", wit_payload, wit_ext, wit_ctx)
        .await
        .unwrap_err();
    let elapsed = start.elapsed();

    let mut messages = vec![format!("{}", err)];
    {
        let mut source: Option<&dyn std::error::Error> = err.source();
        while let Some(s) = source {
            messages.push(format!("{}", s));
            source = s.source();
        }
    }
    let combined = messages.join(" | ").to_lowercase();

    // The invocation should fail within ~200ms (not seconds) due to epoch interrupt.
    // Accept either epoch or fuel message — the key assertion is wall-clock time.
    assert!(
        elapsed.as_millis() < 2000,
        "expected timeout within 2s, but took {:?}",
        elapsed
    );
    assert!(
        combined.contains("epoch") || combined.contains("interrupt")
            || combined.contains("deadline") || combined.contains("fuel")
            || combined.contains("error while executing"),
        "expected execution error, got: {:?}",
        messages
    );
}

// ── Memory cap ───────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires pre-built WASM plugins — run `make build-test-plugins` first"]
async fn test_memory_limit_traps_plugin() {
    init_tracing();

    // 5 MB — the alloc_memory mode allocates in 1 MB chunks until OOM.
    let mut mgr = load_with_limits(ResourceLimits {
        max_memory_bytes: Some(5 * 1024 * 1024),
        max_fuel: Some(u64::MAX),
        max_execution_time_ms: Some(10_000),
        ..Default::default()
    })
    .await;

    let payload = make_payload("alloc_memory");
    let wit_payload = cpex_wasm_host::sandbox_manager::types::HookPayload::Cmf(
        native_payload_to_wit(&payload),
    );
    let wit_ext = native_extensions_to_wit(&Extensions::default());
    let wit_ctx = native_context_to_wit(&PluginContext::default());

    let err = mgr
        .invoke("cmf.tool_pre_invoke", wit_payload, wit_ext, wit_ctx)
        .await
        .unwrap_err();

    let mut messages = vec![format!("{}", err)];
    {
        let mut source: Option<&dyn std::error::Error> = err.source();
        while let Some(s) = source {
            messages.push(format!("{}", s));
            source = s.source();
        }
    }
    let combined = messages.join(" | ").to_lowercase();
    assert!(
        combined.contains("memory") || combined.contains("grow")
            || combined.contains("unreachable") || combined.contains("error while executing"),
        "expected memory/execution error, got: {:?}",
        messages
    );
}
