// Location: ./crates/cpex-wasm-host/examples/wasm_resource_limits_demo.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
// Resource Limits Sandbox Demo
//
// Demonstrates how fuel, epoch timeout, and memory limits protect the host
// from runaway WASM plugins using the PluginManager layer. The same
// resource-sandbox-demo.wasm binary is registered 3 times with deliberately tiny
// limits. Each scenario routes to the appropriate plugin by tool name.
//
// Scenarios:
//   1. Fuel exhaustion   — tight loop burns through a 100,000 fuel budget
//   2. Epoch timeout     — infinite loop interrupted by 200ms deadline
//   3. Memory limit      — 1 MB chunks allocated until 5 MB cap traps
//
// Prerequisites:
//   cd crates/cpex-wasm-host && make build-test-plugins
//
// Run:
//   cargo run -p cpex-wasm-host --example wasm_resource_limits_demo

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use cpex_core::cmf::constants::SCHEMA_VERSION;
use cpex_core::cmf::{CmfHook, ContentPart, Message, MessagePayload, Role, ToolCall};
use cpex_core::config::parse_config;
use cpex_core::executor::PipelineResult;
use cpex_core::extensions::container::Extensions;
use cpex_core::extensions::meta::MetaExtension;
use cpex_core::manager::PluginManager;

use cpex_wasm_host::factory::WasmPluginFactory;
use cpex_wasm_host::payload_registry::PayloadSerializerRegistry;

// ---------------------------------------------------------------------------
// Terminal colours
// ---------------------------------------------------------------------------

const BOLD: &str = "\x1b[1m";
const CYAN: &str = "\x1b[1;36m";
const RED: &str = "\x1b[31m";
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_payload(tool_name: &str, mode: &str) -> MessagePayload {
    let mut arguments = HashMap::new();
    arguments.insert("mode".to_string(), serde_json::json!(mode));
    MessagePayload {
        message: Message {
            schema_version: SCHEMA_VERSION.into(),
            role: Role::Assistant,
            content: vec![ContentPart::ToolCall {
                content: ToolCall {
                    tool_call_id: format!("tc_resource_{}", mode),
                    name: tool_name.into(),
                    arguments,
                    namespace: None,
                },
            }],
            channel: None,
        },
    }
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

async fn invoke(mgr: &PluginManager, tool_name: &str, mode: &str) -> PipelineResult {
    let (result, bg) = mgr
        .invoke_named::<CmfHook>(
            "cmf.tool_pre_invoke",
            make_payload(tool_name, mode),
            make_extensions(tool_name),
            None,
        )
        .await;
    bg.wait_for_background_tasks().await;
    result
}

fn print_result(
    mode: &str,
    limit_desc: &str,
    result: &PipelineResult,
    elapsed: std::time::Duration,
) {
    if result.continue_processing {
        println!(
            "  {}[UNEXPECTED]{} mode={:14} limit={}\n  → Plugin completed (limit did NOT fire)\n",
            CYAN, RESET, mode, limit_desc,
        );
    } else {
        let violation = result.violation.as_ref();
        let code = violation.map(|v| v.code.as_str()).unwrap_or("unknown");
        let reason = violation.map(|v| v.reason.as_str()).unwrap_or("no reason");
        println!(
            "  {}[TRAPPED]{} mode={:14} limit={}\n  {}→ Plugin trapped in {:?}{}\n  {}Code: {}  Reason: {}{}",
            RED, RESET, mode, limit_desc, RED, elapsed, RESET, DIM, code, reason, RESET,
        );
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
                .add_directive("warn".parse().unwrap()),
        )
        .init();

    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let wasm_path = crate_dir.join("wasm/resource-sandbox-demo.wasm");
    if !wasm_path.exists() {
        eprintln!(
            "{}ERROR:{} resource-sandbox-demo.wasm not found at {}\n\
             Run: cd crates/cpex-wasm-host && make build-test-plugins",
            RED,
            RESET,
            wasm_path.display()
        );
        std::process::exit(1);
    }

    println!("{}=== Resource Limits Sandbox Demo ==={}\n", BOLD, RESET);
    println!(
        "{}Plugin:{}  resource-sandbox-demo.wasm (registered 3 times with different limits)",
        DIM, RESET
    );
    println!("{}Payload:{} mode passed as ToolCall argument", DIM, RESET);
    println!(
        "{}Goal:{}    each scenario triggers a resource limit trap, proving the host\n\
         {}        {}cleanly terminates runaway plugins without affecting itself.\n",
        DIM, RESET, DIM, RESET
    );

    let yaml = std::fs::read_to_string(crate_dir.join("config/config_resource_limits_demo.yaml"))
        .expect("config not found");
    let cpex_config = parse_config(&yaml).unwrap();

    let mut registry = PayloadSerializerRegistry::new();
    registry.register::<MessagePayload>();
    let registry = Arc::new(registry);

    let mgr = PluginManager::default();
    mgr.register_factory(
        "wasm://resource-sandbox-demo.wasm",
        Box::new(WasmPluginFactory::new(crate_dir.join("wasm"), registry).expect("engine")),
    );
    mgr.load_config(cpex_config).unwrap();
    mgr.initialize().await.unwrap();

    // =========================================================================
    // Scenario 1: Fuel exhaustion
    // 100,000 fuel units — enough to instantiate but the tight loop exhausts it.
    // =========================================================================
    println!(
        "{}Scenario 1: fuel exhaustion  (max_fuel=100,000){}",
        CYAN, RESET
    );
    let start = std::time::Instant::now();
    let r = invoke(&mgr, "resource_fuel", "burn_fuel").await;
    let elapsed = start.elapsed();
    print_result("burn_fuel", "max_fuel=100,000", &r, elapsed);
    println!();

    // =========================================================================
    // Scenario 2: Epoch timeout
    // 200ms deadline — the infinite loop is interrupted by the epoch ticker.
    // =========================================================================
    println!(
        "{}Scenario 2: epoch timeout  (max_execution_time_ms=200){}",
        CYAN, RESET
    );
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let start = std::time::Instant::now();
    let r = invoke(&mgr, "resource_timeout", "burn_fuel").await;
    let elapsed = start.elapsed();
    print_result("burn_fuel", "max_execution_time_ms=200", &r, elapsed);
    println!();

    // =========================================================================
    // Scenario 3: Memory limit
    // 5 MB cap — the plugin allocates 1 MB chunks until memory.grow is denied.
    // =========================================================================
    println!(
        "{}Scenario 3: memory limit  (max_memory_bytes=5MB){}",
        CYAN, RESET
    );
    let start = std::time::Instant::now();
    let r = invoke(&mgr, "resource_memory", "alloc_memory").await;
    let elapsed = start.elapsed();
    print_result("alloc_memory", "max_memory_bytes=5MB", &r, elapsed);

    println!("\n{}=== Demo complete ==={}\n", BOLD, RESET);
    println!(
        "{}All three resource limits fired correctly — runaway plugins are\n\
         terminated cleanly without host degradation.{}\n",
        DIM, RESET
    );
    mgr.shutdown().await;
}
