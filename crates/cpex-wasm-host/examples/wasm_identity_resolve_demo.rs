// Location: ./crates/cpex-wasm-host/examples/wasm_identity_resolve_demo.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
// Identity-resolve WASM plugin demo — full typed dispatch on the custom path.
//
// Exercises the complete non-CMF hook flow:
//
//   host: IdentityPayload → PayloadSerializerRegistry.serialize()
//         → HookPayload::Custom { payload_type: "cpex.identity", bytes }
//         → SandboxManager.invoke("identity.resolve", ...)
//   guest: register_wasm_plugin! matches "cpex.identity" against
//          IdentityHook::Payload, deserializes, calls
//          HookHandler<IdentityHook>::handle(), returns the modified
//          payload as a Custom result
//   host:  registry.deserialize() reconstructs IdentityPayload; the
//          executor writes it back as the pipeline payload
//
// The raw bearer token is #[serde(skip)] — it never enters the sandbox.
// The guest resolves the subject from the x-user-id request header.
//
// Prerequisites: build the WASM plugin first:
//   cargo build --target wasm32-wasip2   (in crates/cpex-wasm-plugin)
//   cp ../cpex-wasm-plugin/target/wasm32-wasip2/debug/cpex_wasm_plugin.wasm wasm/plugin.wasm
//
// Run from the workspace root:
//   cargo run -p cpex-wasm-host --example wasm_identity_resolve_demo

use std::collections::HashMap;
use std::path::PathBuf;

use cpex_core::config::parse_config;
use cpex_core::extensions::container::Extensions;
use cpex_core::identity::{IdentityHook, IdentityPayload, TokenSource, HOOK_IDENTITY_RESOLVE};
use cpex_core::manager::PluginManager;

use cpex_wasm_host::factory::WasmPluginFactory;

#[tokio::main]
async fn main() {
    println!("=== WASM Plugin Demo — identity.resolve (Generic typed dispatch) ===\n");

    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let config_path = crate_dir.join("config/config_identity.yaml");

    println!("Loading config: {}", config_path.display());
    let yaml = std::fs::read_to_string(&config_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", config_path.display(), e));
    let cpex_config = parse_config(&yaml).unwrap();

    let mgr = PluginManager::default();
    // with_builtin_payloads registers MessagePayload, IdentityPayload,
    // and DelegationPayload in the serializer registry.
    mgr.register_factory(
        "wasm://plugin.wasm",
        Box::new(WasmPluginFactory::with_builtin_payloads(crate_dir.join("wasm"))),
    );
    mgr.load_config(cpex_config).unwrap();
    mgr.initialize().await.unwrap();

    // Build the identity payload as a host would at request entry.
    // The raw token stays host-side (#[serde(skip)]); the guest sees
    // only the headers and other serializable inputs.
    let mut headers = HashMap::new();
    headers.insert("x-user-id".to_string(), "alice".to_string());
    let payload = IdentityPayload::new("secret-bearer-token", TokenSource::Bearer)
        .with_headers(headers)
        .with_client_host("10.0.0.7");

    println!("Payload in:  subject = {:?}", payload.subject);
    println!("             raw_token present host-side, skipped on the wire\n");

    println!("=== identity.resolve via WASM (Generic path, typed dispatch) ===");
    let (result, bg) = mgr
        .invoke_named::<IdentityHook>(HOOK_IDENTITY_RESOLVE, payload, Extensions::default(), None)
        .await;

    if !result.continue_processing {
        let reason = result
            .violation
            .as_ref()
            .map(|v| v.reason.as_str())
            .unwrap_or("unknown");
        println!("Result: DENIED — {}", reason);
    } else {
        match IdentityPayload::from_pipeline_result(&result) {
            Some(resolved) => {
                let subject_id = resolved.subject.as_ref().and_then(|s| s.id.as_deref());
                println!("Result: ALLOWED");
                println!("Payload out: subject = {:?}", subject_id);
                assert_eq!(
                    subject_id,
                    Some("alice"),
                    "guest-modified IdentityPayload did not survive the round trip"
                );
                println!("\n✓ Guest resolved the subject from x-user-id and the typed");
                println!("  modification survived the WASM boundary in both directions.");
            }
            None => {
                println!("Result: ALLOWED, but payload came back untyped — writeback broken");
                std::process::exit(1);
            }
        }
    }

    bg.wait_for_background_tasks().await;

    println!("\n=== Demo complete ===");
}
