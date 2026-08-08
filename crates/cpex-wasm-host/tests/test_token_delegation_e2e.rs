// Location: ./crates/cpex-wasm-host/tests/test_token_delegation_e2e.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
//! Integration test: verifies the token delegation hook (token.delegate) routes
//! through the WASM boundary end-to-end.
//!
//! The host sends a native DelegationPayload (HookPayload::Delegation variant),
//! the plugin macro routes it to the registered TokenDelegateHook handler, and
//! the minted token is returned via the pipeline result.
//!
//! Requires: token-attenuator.wasm built and staged.
//! Run `make build-all-plugins` from crates/cpex-wasm-host first.

use std::path::PathBuf;
use std::sync::{Arc, Once};

use cpex_core::config::parse_config;
use cpex_core::delegation::{
    DelegationPayload, TargetType, TokenDelegateHook, HOOK_TOKEN_DELEGATE,
};
use cpex_core::extensions::container::Extensions;
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
    let path = wasm_dir().join("token-attenuator.wasm");
    assert!(
        path.exists(),
        "WASM binary not found: {}. Run `make build-all-plugins` first.",
        path.display()
    );
}

async fn setup_manager() -> PluginManager {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let config_path = crate_dir.join("config/config_token_attenuator_demo.yaml");
    let wasm_dir = crate_dir.join("wasm");

    let yaml = std::fs::read_to_string(&config_path).unwrap();
    let cpex_config = parse_config(&yaml).unwrap();

    let registry = Arc::new({
        let mut r = PayloadSerializerRegistry::new();
        r.register::<DelegationPayload>();
        r
    });

    let mgr = PluginManager::default();
    mgr.register_factory(
        "wasm://token-attenuator.wasm",
        Box::new(WasmPluginFactory::new(wasm_dir, registry).expect("engine")),
    );

    mgr.load_config(cpex_config).unwrap();
    mgr.initialize().await.unwrap();
    mgr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires pre-built WASM plugins — run `make build-all-plugins` first"]
async fn test_token_delegation_mints_for_tool_target() {
    init_tracing();
    check_binary_exists();
    let mgr = setup_manager().await;

    let payload = DelegationPayload::new("eyJ.caller-token", "get_compensation")
        .with_target_type(TargetType::Tool)
        .with_target_audience("https://hr-service.internal/api")
        .with_required_permissions(vec!["read:compensation".into()]);

    let (result, bg) = mgr
        .invoke_named::<TokenDelegateHook>(
            HOOK_TOKEN_DELEGATE,
            payload,
            Extensions::default(),
            None,
        )
        .await;
    bg.wait_for_background_tasks().await;

    let resolved = DelegationPayload::from_pipeline_result(&result)
        .expect("pipeline should return a modified DelegationPayload");

    let token = resolved
        .delegated_token
        .as_ref()
        .expect("tool target should produce a minted token");

    assert_eq!(token.audience, "https://hr-service.internal/api");
    assert_eq!(token.scopes, vec!["read:compensation"]);
    assert_eq!(token.outbound_header, "Authorization");
    assert_eq!(
        resolved.delegation_mode,
        Some(cpex_core::extensions::raw_credentials::DelegationMode::OnBehalfOfUser)
    );
    assert_eq!(
        resolved.metadata.get("minter").and_then(|v| v.as_str()),
        Some("token-attenuator-wasm")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires pre-built WASM plugins — run `make build-all-plugins` first"]
async fn test_token_delegation_passes_through_agent_target() {
    init_tracing();
    check_binary_exists();
    let mgr = setup_manager().await;

    let payload = DelegationPayload::new("eyJ.caller-token", "summarizer-agent")
        .with_target_type(TargetType::Agent)
        .with_target_audience("https://agents.internal/summarizer");

    let (result, bg) = mgr
        .invoke_named::<TokenDelegateHook>(
            HOOK_TOKEN_DELEGATE,
            payload,
            Extensions::default(),
            None,
        )
        .await;
    bg.wait_for_background_tasks().await;

    assert!(
        result.continue_processing,
        "agent targets should be allowed through"
    );
    // Agent targets should not produce a minted token
    if let Some(p) = DelegationPayload::from_pipeline_result(&result) {
        assert!(
            p.delegated_token.is_none(),
            "agent target should not mint a token"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires pre-built WASM plugins — run `make build-all-plugins` first"]
async fn test_token_delegation_multi_permission_scopes() {
    init_tracing();
    check_binary_exists();
    let mgr = setup_manager().await;

    let payload = DelegationPayload::new("eyJ.caller-token", "query_external_data")
        .with_target_type(TargetType::Tool)
        .with_target_audience("https://data-svc.internal/query")
        .with_required_permissions(vec![
            "read:records".into(),
            "read:metadata".into(),
            "read:audit".into(),
        ]);

    let (result, bg) = mgr
        .invoke_named::<TokenDelegateHook>(
            HOOK_TOKEN_DELEGATE,
            payload,
            Extensions::default(),
            None,
        )
        .await;
    bg.wait_for_background_tasks().await;

    let resolved = DelegationPayload::from_pipeline_result(&result)
        .expect("pipeline should return a modified DelegationPayload");

    let token = resolved
        .delegated_token
        .as_ref()
        .expect("tool target should produce a minted token");

    assert_eq!(token.audience, "https://data-svc.internal/query");
    assert_eq!(
        token.scopes,
        vec!["read:records", "read:metadata", "read:audit"]
    );
}
