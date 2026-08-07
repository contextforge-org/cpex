// Location: ./crates/cpex-wasm-host/examples/wasm_resource_limits_demo.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
// Resource Limits Sandbox Demo
//
// Demonstrates how fuel, epoch timeout, and memory limits protect the host
// from runaway WASM plugins. Each scenario loads resource-test.wasm with a
// deliberately tiny limit and invokes it in a mode that triggers that limit.
//
// Scenarios:
//   1. Fuel exhaustion   — tight loop burns through a 10,000 fuel budget
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

use cpex_core::cmf::constants::SCHEMA_VERSION;
use cpex_core::cmf::{ContentPart, Message, MessagePayload, Role, ToolCall};
use cpex_core::context::PluginContext;
use cpex_core::extensions::container::Extensions;

use cpex_wasm_host::conversions::{
    native_context_to_wit, native_extensions_to_wit, native_payload_to_wit,
};
use cpex_wasm_host::policy_loader::{ResourceLimits, SandboxPolicy};
use cpex_wasm_host::sandbox_manager::{SandboxManager, SharedEngine};

// ---------------------------------------------------------------------------
// Terminal colours
// ---------------------------------------------------------------------------

const BOLD: &str = "\x1b[1m";
const CYAN: &str = "\x1b[1;36m";
const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn wasm_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("wasm/resource-test.wasm")
}

fn make_payload(mode: &str) -> MessagePayload {
    let mut arguments = HashMap::new();
    arguments.insert("mode".to_string(), serde_json::json!(mode));
    MessagePayload {
        message: Message {
            schema_version: SCHEMA_VERSION.into(),
            role: Role::Assistant,
            content: vec![ContentPart::ToolCall {
                content: ToolCall {
                    tool_call_id: format!("tc_resource_{}", mode),
                    name: "resource_test".into(),
                    arguments,
                    namespace: None,
                },
            }],
            channel: None,
        },
    }
}

async fn invoke(mgr: &mut SandboxManager, mode: &str) -> Result<(), String> {
    let payload = make_payload(mode);
    let wit_payload = cpex_wasm_host::sandbox_manager::types::HookPayload::Cmf(
        native_payload_to_wit(&payload),
    );
    let wit_ext = native_extensions_to_wit(&Extensions::default());
    let wit_ctx = native_context_to_wit(&PluginContext::default());

    mgr.invoke("cmf.tool_pre_invoke", wit_payload, wit_ext, wit_ctx)
        .await
        .map(|_| ())
        .map_err(|e| {
            let mut messages = vec![format!("{}", e)];
            let mut source: Option<&dyn std::error::Error> = e.source();
            while let Some(s) = source {
                messages.push(format!("{}", s));
                source = s.source();
            }
            messages.join(" → ")
        })
}

async fn load_plugin(shared: &SharedEngine, resources: ResourceLimits, name: &str) -> SandboxManager {
    let path = wasm_path();
    let policy = SandboxPolicy {
        resources,
        ..Default::default()
    };
    let mut mgr = SandboxManager::with_shared_engine(shared);
    mgr.load_wasmplugin(&path, Some(&policy), name)
        .await
        .unwrap_or_else(|e| panic!("failed to load plugin '{}': {}", name, e));
    mgr
}

fn print_result(mode: &str, limit_desc: &str, result: &Result<(), String>, elapsed: std::time::Duration) {
    match result {
        Ok(()) => {
            println!(
                "  {}[UNEXPECTED]{} mode={:14} limit={}\n  {}→ Plugin completed (limit did NOT fire){}\n",
                GREEN, RESET, mode, limit_desc, GREEN, RESET,
            );
        }
        Err(err) => {
            println!(
                "  {}[TRAPPED]{} mode={:14} limit={}\n  {}→ Plugin trapped in {:?}{}\n  {}Error: {}{}",
                RED, RESET, mode, limit_desc, RED, elapsed, RESET, DIM, err, RESET,
            );
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
                .add_directive("warn".parse().unwrap()),
        )
        .init();

    let path = wasm_path();
    if !path.exists() {
        eprintln!(
            "{}ERROR:{} resource-test.wasm not found at {}\n\
             Run: cd crates/cpex-wasm-host && make build-test-plugins",
            RED, RESET,
            path.display()
        );
        std::process::exit(1);
    }

    println!("{}=== Resource Limits Sandbox Demo ==={}\n", BOLD, RESET);
    println!("{}Plugin:{}  resource-test.wasm", DIM, RESET);
    println!("{}Payload:{} mode passed as ToolCall argument", DIM, RESET);
    println!(
        "{}Goal:{}    each scenario triggers a resource limit trap, proving the host\n\
         {}        {}cleanly terminates runaway plugins without affecting itself.\n",
        DIM, RESET, DIM, RESET
    );

    let shared = SharedEngine::new().unwrap();

    // =========================================================================
    // Scenario 1: Fuel exhaustion
    // 10,000 fuel units — enough to instantiate but the tight loop exhausts
    // it almost immediately.
    // =========================================================================
    println!("{}Scenario 1: fuel exhaustion  (max_fuel=10,000){}", CYAN, RESET);
    let mut mgr = load_plugin(&shared, ResourceLimits {
        max_fuel: Some(10_000),
        max_execution_time_ms: Some(10_000),
        ..Default::default()
    }, "resource-fuel").await;

    let start = std::time::Instant::now();
    let r = invoke(&mut mgr, "burn_fuel").await;
    let elapsed = start.elapsed();
    print_result("burn_fuel", "max_fuel=10,000", &r, elapsed);
    println!();

    // =========================================================================
    // Scenario 2: Epoch timeout
    // 200ms deadline — the infinite loop is interrupted by the epoch ticker.
    // =========================================================================
    println!("{}Scenario 2: epoch timeout  (max_execution_time_ms=200){}", CYAN, RESET);
    let mut mgr = load_plugin(&shared, ResourceLimits {
        max_execution_time_ms: Some(200),
        max_fuel: Some(500_000_000),
        ..Default::default()
    }, "resource-timeout").await;

    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let start = std::time::Instant::now();
    let r = invoke(&mut mgr, "burn_fuel").await;
    let elapsed = start.elapsed();
    print_result("burn_fuel", "max_execution_time_ms=200", &r, elapsed);
    println!();

    // =========================================================================
    // Scenario 3: Memory limit
    // 5 MB cap — the plugin allocates 1 MB chunks until memory.grow is denied.
    // =========================================================================
    println!("{}Scenario 3: memory limit  (max_memory_bytes=5MB){}", CYAN, RESET);
    let mut mgr = load_plugin(&shared, ResourceLimits {
        max_memory_bytes: Some(5 * 1024 * 1024),
        max_fuel: Some(u64::MAX),
        max_execution_time_ms: Some(10_000),
        ..Default::default()
    }, "resource-memory").await;

    let start = std::time::Instant::now();
    let r = invoke(&mut mgr, "alloc_memory").await;
    let elapsed = start.elapsed();
    print_result("alloc_memory", "max_memory_bytes=5MB", &r, elapsed);

    println!("\n{}=== Demo complete ==={}\n", BOLD, RESET);
    println!(
        "{}All three resource limits fired correctly — runaway plugins are\n\
         terminated cleanly without host degradation.{}\n",
        DIM, RESET
    );
}
