// Location: ./crates/cpex-wasm-host/tests/test_identity_resolve_e2e.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
//! Integration test: verifies the identity.resolve hook routes through the
//! WASM boundary end-to-end.
//!
//! The host sends a native IdentityPayload (HookPayload::Identity variant),
//! the plugin macro routes it to the registered IdentityHook handler, and the
//! resolved subject is returned via the pipeline result.
//!
//! Requires: identity-checker.wasm built and staged.
//! Run `make build-all-plugins` from crates/cpex-wasm-host first.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Once};

use cpex_core::config::parse_config;
use cpex_core::extensions::container::Extensions;
use cpex_core::extensions::security::SubjectType;
use cpex_core::identity::{
    IdentityHook, IdentityPayload, TokenSource, HOOK_IDENTITY_RESOLVE,
};
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
    let path = wasm_dir().join("identity-checker.wasm");
    assert!(
        path.exists(),
        "WASM binary not found: {}. Run `make build-all-plugins` first.",
        path.display()
    );
}

async fn setup_manager() -> PluginManager {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let config_path = crate_dir.join("config/config_identity_resolve_test.yaml");
    let wasm_dir = crate_dir.join("wasm");

    let yaml = std::fs::read_to_string(&config_path).unwrap();
    let cpex_config = parse_config(&yaml).unwrap();

    let registry = Arc::new({
        let mut r = PayloadSerializerRegistry::new();
        r.register::<IdentityPayload>();
        r
    });

    let mgr = PluginManager::default();
    mgr.register_factory(
        "wasm://identity-checker.wasm",
        Box::new(WasmPluginFactory::new(wasm_dir, registry).expect("engine")),
    );

    mgr.load_config(cpex_config).unwrap();
    mgr.initialize().await.unwrap();
    mgr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires pre-built WASM plugins — run `make build-all-plugins` first"]
async fn test_identity_resolve_extracts_subject_from_header() {
    init_tracing();
    check_binary_exists();
    let mgr = setup_manager().await;

    let payload = IdentityPayload::new("", TokenSource::Bearer)
        .with_headers(HashMap::from([
            ("x-user-id".into(), "alice-123".into()),
            ("authorization".into(), "Bearer eyJ...".into()),
        ]));

    let (result, bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            payload,
            Extensions::default(),
            None,
        )
        .await;
    bg.wait_for_background_tasks().await;

    assert!(result.continue_processing, "identity resolve should allow");

    let resolved = IdentityPayload::from_pipeline_result(&result)
        .expect("pipeline should return a modified IdentityPayload");

    let subject = resolved
        .subject
        .as_ref()
        .expect("subject should be resolved from x-user-id header");

    assert_eq!(subject.id.as_deref(), Some("alice-123"));
    assert_eq!(subject.subject_type, Some(SubjectType::User));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires pre-built WASM plugins — run `make build-all-plugins` first"]
async fn test_identity_resolve_passes_through_when_no_header() {
    init_tracing();
    check_binary_exists();
    let mgr = setup_manager().await;

    let payload = IdentityPayload::new("", TokenSource::Bearer)
        .with_headers(HashMap::from([
            ("authorization".into(), "Bearer eyJ...".into()),
        ]));

    let (result, bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            payload,
            Extensions::default(),
            None,
        )
        .await;
    bg.wait_for_background_tasks().await;

    assert!(
        result.continue_processing,
        "missing x-user-id should still allow (pass-through)"
    );

    // No subject resolved — either no modified payload or subject is None
    match IdentityPayload::from_pipeline_result(&result) {
        Some(p) => assert!(
            p.subject.is_none(),
            "no x-user-id header means no subject should be resolved"
        ),
        None => {} // no modified payload means pass-through — valid
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires pre-built WASM plugins — run `make build-all-plugins` first"]
async fn test_identity_resolve_skips_when_subject_already_set() {
    init_tracing();
    check_binary_exists();
    let mgr = setup_manager().await;

    let mut payload = IdentityPayload::new("", TokenSource::Bearer)
        .with_headers(HashMap::from([
            ("x-user-id".into(), "should-be-ignored".into()),
        ]));
    payload.subject = Some(cpex_core::extensions::security::SubjectExtension {
        id: Some("pre-existing-user".into()),
        subject_type: Some(SubjectType::Service),
        ..Default::default()
    });

    let (result, bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            payload,
            Extensions::default(),
            None,
        )
        .await;
    bg.wait_for_background_tasks().await;

    assert!(result.continue_processing, "should allow when subject already set");

    // Subject already present — plugin should pass through without overwriting
    match IdentityPayload::from_pipeline_result(&result) {
        Some(p) => {
            let subject = p.subject.as_ref().expect("subject should still be present");
            assert_eq!(subject.id.as_deref(), Some("pre-existing-user"));
            assert_eq!(subject.subject_type, Some(SubjectType::Service));
        }
        None => {} // no modification means original subject preserved — valid
    }
}
