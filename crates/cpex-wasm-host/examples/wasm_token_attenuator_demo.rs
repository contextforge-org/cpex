// Location: ./crates/cpex-wasm-host/examples/wasm_token_attenuator_demo.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
// Token Attenuator WASM Demo
//
// Demonstrates the token.delegate hook using the token-attenuator WASM plugin.
// The host constructs a DelegationPayload (bearer token + target tool), fires
// invoke_named, and the WASM plugin mints a scoped outbound credential for the
// downstream tool. The minted token is extracted via DelegationPayload::from_pipeline_result.
//
// Scenarios:
//   1. Delegate to a Tool target   — plugin mints a scoped token
//   2. Delegate to an Agent target — plugin passes through (non-Tool targets are skipped)
//   3. Multi-permission delegation — plugin scopes token to required_permissions
//
// Prerequisites:
//   cd crates/cpex-wasm-host && make build-all-plugins
//
// Run:
//   cargo run -p cpex-wasm-host --example wasm_token_attenuator_demo

use std::path::PathBuf;
use std::sync::Arc;

use cpex_core::config::parse_config;
use cpex_core::delegation::{DelegationPayload, TargetType, TokenDelegateHook, HOOK_TOKEN_DELEGATE};
use cpex_core::extensions::container::Extensions;
use cpex_core::manager::PluginManager;

use cpex_wasm_host::factory::WasmPluginFactory;
use cpex_wasm_host::payload_registry::PayloadSerializerRegistry;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const CYAN_BOLD: &str = "\x1b[1;36m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const WHITE: &str = "\x1b[97m";
const RESET: &str = "\x1b[0m";

macro_rules! scenario {
    ($($arg:tt)*) => {
        println!("{}{}{}", CYAN_BOLD, format!($($arg)*), RESET)
    };
}

fn print_delegation_result(result: &cpex_core::executor::PipelineResult) {
    match DelegationPayload::from_pipeline_result(result) {
        Some(resolved) => {
            if let Some(token) = &resolved.delegated_token {
                println!(
                    "  {}Token minted:{}  audience='{}' scopes={:?} header='{}'",
                    GREEN, RESET,
                    token.audience,
                    token.scopes,
                    token.outbound_header,
                );
                println!(
                    "  {}Expires at:{}   {}",
                    WHITE, RESET,
                    token.expires_at.format("%Y-%m-%dT%H:%M:%SZ"),
                );
            } else {
                println!("  {}Passed through — no token minted{}", YELLOW, RESET);
            }
            if let Some(mode) = &resolved.delegation_mode {
                println!("  {}Mode:{}          {:?}", WHITE, RESET, mode);
            }
            if let Some(minter) = resolved.metadata.get("minter") {
                println!("  {}Minted by:{}     {}", WHITE, RESET, minter);
            }
        }
        None => {
            println!("  Pipeline denied the delegation request.");
        }
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("info".parse().unwrap()),
        )
        .init();

    println!("=== Token Attenuator WASM Demo ===\n");

    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let config_path = crate_dir.join("config/config_token_attenuator_demo.yaml");
    let wasm_dir = crate_dir.join("wasm");

    println!(
        "--- Loading config from {} ---\n",
        "config/config_token_attenuator_demo.yaml"
    );
    let yaml = std::fs::read_to_string(&config_path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", config_path.display(), e));
    let cpex_config = parse_config(&yaml).unwrap();

    // DelegationPayload is a built-in type — use with_builtin_payloads so it's
    // registered without needing a manual PayloadSerializerRegistry setup.
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

    println!("\n--- Initializing plugins ---\n");
    mgr.initialize().await.unwrap();

    println!(
        "Plugins loaded: {}\n",
        mgr.plugin_count()
    );

    // =========================================================================
    // Scenario 1: Delegate to a Tool target
    // The plugin mints a scoped token because target_type == Tool.
    // =========================================================================
    scenario!("\n=== Scenario 1: delegate to Tool target 'get_compensation' ===\n");
    let payload = DelegationPayload::new("eyJhbGciOiJSUzI1NiJ9.caller-token", "get_compensation")
        .with_target_type(TargetType::Tool)
        .with_target_audience("https://hr-service.internal/api")
        .with_required_permissions(vec!["read:compensation".into()]);

    let (result, bg) = mgr
        .invoke_named::<TokenDelegateHook>(HOOK_TOKEN_DELEGATE, payload, Extensions::default(), None)
        .await;
    print_delegation_result(&result);
    bg.wait_for_background_tasks().await;

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    // =========================================================================
    // Scenario 2: Delegate to an Agent target
    // The plugin returns allow() without minting — non-Tool targets are skipped.
    // =========================================================================
    scenario!("\n=== Scenario 2: delegate to Agent target 'summarizer-agent' ===\n");
    let payload = DelegationPayload::new("eyJhbGciOiJSUzI1NiJ9.caller-token", "summarizer-agent")
        .with_target_type(TargetType::Agent)
        .with_target_audience("https://agents.internal/summarizer");

    let (result, bg) = mgr
        .invoke_named::<TokenDelegateHook>(HOOK_TOKEN_DELEGATE, payload, Extensions::default(), None)
        .await;
    print_delegation_result(&result);
    bg.wait_for_background_tasks().await;

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    // =========================================================================
    // Scenario 3: Multi-permission delegation
    // Required permissions are forwarded as token scopes.
    // =========================================================================
    scenario!("\n=== Scenario 3: multi-permission delegation to 'query_external_data' ===\n");
    let payload = DelegationPayload::new("eyJhbGciOiJSUzI1NiJ9.caller-token", "query_external_data")
        .with_target_type(TargetType::Tool)
        .with_target_audience("https://data-svc.internal/query")
        .with_required_permissions(vec![
            "read:records".into(),
            "read:metadata".into(),
            "read:audit".into(),
        ]);

    let (result, bg) = mgr
        .invoke_named::<TokenDelegateHook>(HOOK_TOKEN_DELEGATE, payload, Extensions::default(), None)
        .await;
    print_delegation_result(&result);
    bg.wait_for_background_tasks().await;

    println!("\n=== Demo complete ===\n");
}
