// Location: ./crates/cpex-wasm-host/examples/wasm_env_sandbox_demo.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
// Environment Variable Sandbox Permissions Demo
//
// Invokes env-sandbox-demo.wasm with "env_var" as a ToolCall argument.
// The plugin calls std::env::var inside the WASM sandbox and returns:
//   ALLOW — variable was declared in allowed_env and is visible
//   DENY  — variable was not declared; sandbox hides it
//
// How enforcement works:
//   build_wasi_context injects only the variables listed in allowed_env into
//   the WasiCtx via builder.env(key, val). The sandbox never calls
//   inherit_env(), so no host variable leaks implicitly. std::env::var inside
//   the plugin only sees what was explicitly injected.
//
// Run:
//   cd crates/cpex-wasm-host && make run-env-demo

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

const BOLD: &str = "\x1b[1m";
const CYAN: &str = "\x1b[1;36m";
const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";

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
                    name: "env_sandbox_demo".into(),
                    arguments,
                    namespace: None,
                },
            }],
            channel: None,
        },
    }
}

fn make_extensions() -> Extensions {
    Extensions {
        meta: Some(Arc::new(MetaExtension {
            entity_type: Some("tool".into()),
            entity_name: Some("env_sandbox_demo".into()),
            ..Default::default()
        })),
        ..Default::default()
    }
}

async fn invoke(mgr: &PluginManager, env_var: &str) -> PipelineResult {
    let (result, bg) = mgr
        .invoke_named::<CmfHook>(
            "cmf.tool_pre_invoke",
            make_payload(env_var),
            make_extensions(),
            None,
        )
        .await;
    bg.wait_for_background_tasks().await;
    result
}

fn print_case(label: &str, env_var: &str, result: &PipelineResult) {
    if result.continue_processing {
        println!(
            "  {}[{}]{} env_var={}\n  {}→ ALLOW{}",
            DIM, label, RESET, env_var, GREEN, RESET,
        );
    } else {
        let code = result
            .violation
            .as_ref()
            .map(|v| v.code.as_str())
            .unwrap_or("unknown");
        println!(
            "  {}[{}]{} env_var={}\n  {}→ DENY  [{}]{}",
            DIM, label, RESET, env_var, RED, code, RESET,
        );
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("warn".parse().unwrap()),
        )
        .init();

    // Set the env vars the demo will probe. In a real deployment these would
    // already be present in the host process environment.
    std::env::set_var("CPEX_APP_TOKEN", "tok-demo-abc123");
    std::env::set_var("CPEX_LOG_LEVEL", "info");
    std::env::set_var("SECRET_API_KEY", "sk-super-secret-value");
    // HOME and PATH are already set by the shell.

    println!(
        "{}=== Environment Variable Sandbox Permissions Demo ==={}\n",
        BOLD, RESET
    );
    println!("{}Plugin:{} env-sandbox-demo.wasm", DIM, RESET);
    println!(
        "{}Payload:{} env_var passed as ToolCall argument\n",
        DIM, RESET
    );

    println!("{}Host env vars set for this demo:{}", DIM, RESET);
    println!("  CPEX_APP_TOKEN  = tok-demo-abc123   (in allowed_env → visible)");
    println!("  CPEX_LOG_LEVEL  = info              (in allowed_env → visible)");
    println!(
        "  HOME            = {}  (not in allowed_env → hidden)",
        std::env::var("HOME").unwrap_or_else(|_| "<not set>".into())
    );
    println!("  PATH            = <set by shell>    (not in allowed_env → hidden)");
    println!("  SECRET_API_KEY  = sk-super-secret-* (not in allowed_env → hidden)\n");

    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let yaml = std::fs::read_to_string(crate_dir.join("config/config_env_sandbox_demo.yaml"))
        .expect("config not found — run: cd crates/cpex-wasm-host && make run-env-demo");
    let cpex_config = parse_config(&yaml).unwrap();

    let mut registry = PayloadSerializerRegistry::new();
    registry.register::<MessagePayload>();

    let mgr = PluginManager::default();
    mgr.register_factory(
        "wasm://env-sandbox-demo.wasm",
        Box::new(
            WasmPluginFactory::new(crate_dir.join("wasm"), Arc::new(registry)).expect("engine"),
        ),
    );
    mgr.load_config(cpex_config).unwrap();
    mgr.initialize().await.unwrap();

    // =========================================================================
    // Allowed variables — declared in allowed_env; value is visible to plugin
    // =========================================================================
    println!(
        "{}Scenario 1: allowed_env variables (visible inside sandbox){}",
        CYAN, RESET
    );
    let r = invoke(&mgr, "CPEX_APP_TOKEN").await;
    print_case("ALLOW expected", "CPEX_APP_TOKEN", &r);
    let r = invoke(&mgr, "CPEX_LOG_LEVEL").await;
    print_case("ALLOW expected", "CPEX_LOG_LEVEL", &r);

    // =========================================================================
    // Denied variables — not in allowed_env; hidden from sandbox
    // Even though these are set on the host, the plugin cannot see them.
    // =========================================================================
    println!(
        "\n{}Scenario 2: variables NOT in allowed_env (hidden inside sandbox){}",
        CYAN, RESET
    );
    let r = invoke(&mgr, "HOME").await;
    print_case("DENY expected", "HOME", &r);
    let r = invoke(&mgr, "PATH").await;
    print_case("DENY expected", "PATH", &r);
    let r = invoke(&mgr, "SECRET_API_KEY").await;
    print_case("DENY expected", "SECRET_API_KEY", &r);

    println!("\n{}=== Demo complete ==={}\n", BOLD, RESET);
    mgr.shutdown().await;
}
