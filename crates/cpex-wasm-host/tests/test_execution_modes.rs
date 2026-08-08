// Location: ./crates/cpex-wasm-host/tests/test_execution_modes.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
//! Integration tests: verifies concurrent and fire_and_forget execution modes
//! work correctly through the WASM plugin pipeline.
//!
//! Requires: noop.wasm built and staged.
//! Run `make build-test-plugins` from crates/cpex-wasm-host first.

use std::path::PathBuf;
use std::sync::{Arc, Once};

use cpex_core::cmf::{CmfHook, MessagePayload};
use cpex_core::config::parse_config;
use cpex_core::extensions::container::Extensions;
use cpex_core::extensions::meta::MetaExtension;
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

fn wasm_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("wasm")
}

fn check_binary_exists() {
    let path = wasm_dir().join("noop.wasm");
    assert!(
        path.exists(),
        "WASM binary not found: {}. Run `make build-test-plugins` first.",
        path.display()
    );
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
    let config_path = crate_dir.join("config/config_execution_modes_test.yaml");
    let wasm_dir = crate_dir.join("wasm");

    let yaml = std::fs::read_to_string(&config_path).unwrap();
    let cpex_config = parse_config(&yaml).unwrap();

    let registry = Arc::new({
        let mut r = PayloadSerializerRegistry::new();
        r.register::<MessagePayload>();
        r
    });

    let mgr = PluginManager::default();
    mgr.register_factory(
        "wasm://noop.wasm",
        Box::new(WasmPluginFactory::new(wasm_dir, registry).expect("engine")),
    );

    mgr.load_config(cpex_config).unwrap();
    mgr.initialize().await.unwrap();
    mgr
}

// ── Concurrent mode ─────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires pre-built WASM plugins — run `make build-test-plugins` first"]
async fn test_concurrent_plugins_all_allow() {
    init_tracing();
    check_binary_exists();
    let mgr = setup_manager().await;
    let ext = make_extensions("some_tool");

    let (result, bg) = mgr
        .invoke::<CmfHook>(
            cpex_core::cmf::MessagePayload {
                message: cpex_core::cmf::Message {
                    schema_version: cpex_core::cmf::constants::SCHEMA_VERSION.into(),
                    role: cpex_core::cmf::Role::Assistant,
                    content: vec![cpex_core::cmf::ContentPart::Text {
                        text: "hello".into(),
                    }],
                    channel: None,
                },
            },
            ext,
            None,
        )
        .await;
    bg.wait_for_background_tasks().await;

    assert!(
        result.continue_processing,
        "concurrent noop plugins should all allow"
    );
    assert!(result.violation.is_none());
}

// ── Fire-and-forget mode ────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires pre-built WASM plugins — run `make build-test-plugins` first"]
async fn test_fire_and_forget_returns_immediately() {
    init_tracing();
    check_binary_exists();
    let mgr = setup_manager().await;

    let payload = cpex_core::cmf::MessagePayload {
        message: cpex_core::cmf::Message {
            schema_version: cpex_core::cmf::constants::SCHEMA_VERSION.into(),
            role: cpex_core::cmf::Role::Assistant,
            content: vec![cpex_core::cmf::ContentPart::Text {
                text: "test".into(),
            }],
            channel: None,
        },
    };
    let ext = make_extensions("some_tool");

    // Fire the post_invoke hook which has a fire_and_forget plugin
    let (result, bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_post_invoke", payload, ext, None)
        .await;

    // Pipeline should return immediately with allow (FAF doesn't block)
    assert!(
        result.continue_processing,
        "fire_and_forget should not block the pipeline"
    );
    assert!(result.violation.is_none());

    // Background tasks should complete without error
    bg.wait_for_background_tasks().await;
}
