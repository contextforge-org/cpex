// Location: ./crates/cpex-wasm-host/examples/wasm_fs_sandbox_demo.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
// Filesystem Sandbox Permissions Demo
//
// Invokes fs-sandbox-demo.wasm with "operation" and "path" as ToolCall
// arguments. For each of the six WASI permission levels, two invocations are
// shown — one that the sandbox permits (ALLOW) and one it blocks (DENY).
//
// Permission levels:
//   read-only       DirPerms::READ            FilePerms::READ
//   full-access     DirPerms::READ|MUTATE     FilePerms::READ|WRITE
//   drop-box        DirPerms::MUTATE          FilePerms::WRITE
//   fixed-mutable   DirPerms::READ            FilePerms::READ|WRITE
//   list-only       DirPerms::READ            FilePerms::empty()
//   private-scratch DirPerms::MUTATE          FilePerms::READ|WRITE
//
// Run:
//   cd crates/cpex-wasm-host && make run-sandbox-demo

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
const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_payload(operation: &str, path: &str) -> MessagePayload {
    let mut arguments = HashMap::new();
    arguments.insert("operation".to_string(), serde_json::json!(operation));
    arguments.insert("path".to_string(), serde_json::json!(path));
    MessagePayload {
        message: Message {
            schema_version: SCHEMA_VERSION.into(),
            role: Role::Assistant,
            content: vec![ContentPart::ToolCall {
                content: ToolCall {
                    tool_call_id: format!("tc_{}_{}", operation, path.replace('/', "_")),
                    name: "fs_sandbox_demo".into(),
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
            entity_name: Some("fs_sandbox_demo".into()),
            ..Default::default()
        })),
        ..Default::default()
    }
}

async fn invoke(mgr: &PluginManager, operation: &str, path: &str) -> PipelineResult {
    let (result, bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", make_payload(operation, path), make_extensions(), None)
        .await;
    bg.wait_for_background_tasks().await;
    result
}

fn print_case(label: &str, operation: &str, path: &str, result: &PipelineResult) {
    if result.continue_processing {
        println!(
            "  {}[{}]{} operation={:12} path={}\n  {}→ ALLOW{}",
            DIM, label, RESET, operation, path, GREEN, RESET,
        );
    } else {
        let code = result
            .violation
            .as_ref()
            .map(|v| v.code.as_str())
            .unwrap_or("unknown");
        println!(
            "  {}[{}]{} operation={:12} path={}\n  {}→ DENY  [{}]{}",
            DIM, label, RESET, operation, path, RED, code, RESET,
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

    println!("{}=== Filesystem Sandbox Permissions Demo ==={}\n", BOLD, RESET);
    println!(
        "{}Plugin:{} fs-sandbox-demo.wasm",
        DIM, RESET
    );
    println!(
        "{}Payload:{} operation + path passed as ToolCall arguments\n",
        DIM, RESET
    );

    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let yaml = std::fs::read_to_string(crate_dir.join("config/config_fs_sandbox_demo.yaml"))
        .expect("config not found — run: make setup-sandbox-demo-data");
    let cpex_config = parse_config(&yaml).unwrap();

    let mut registry = PayloadSerializerRegistry::new();
    registry.register::<MessagePayload>();

    let mgr = PluginManager::default();
    mgr.register_factory(
        "wasm://fs-sandbox-demo.wasm",
        Box::new(WasmPluginFactory::new(
            crate_dir.join("wasm"),
            Arc::new(registry),
        ).expect("engine")),
    );
    mgr.load_config(cpex_config).unwrap();
    mgr.initialize().await.unwrap();

    // Paths must match the guest mount point registered by preopened_dir.
    // The config sets dir: "examples/data/<sub>", so the plugin sees exactly
    // that string — absolute host paths are invisible inside the WASM sandbox.
    let p = |sub: &str, file: &str| format!("examples/data/{}/{}", sub, file);
    let d = |sub: &str| format!("examples/data/{}", sub);

    // =========================================================================
    // read-only  —  DirPerms::READ  FilePerms::READ
    // =========================================================================
    println!("{}Scenario 1: read-only (rules/)  DirPerms::READ  FilePerms::READ{}", CYAN, RESET);
    let r = invoke(&mgr, "read",  &p("rules", "policy.yaml")).await;
    print_case("ALLOW expected", "read",  &p("rules", "policy.yaml"), &r);
    let r = invoke(&mgr, "write", &p("rules", "policy.yaml")).await;
    print_case("DENY expected",  "write", &p("rules", "policy.yaml"), &r);

    // =========================================================================
    // full-access  —  DirPerms::READ|MUTATE  FilePerms::READ|WRITE
    // =========================================================================
    println!("\n{}Scenario 2: full-access (cache/)  DirPerms::READ|MUTATE  FilePerms::READ|WRITE{}", CYAN, RESET);
    let r = invoke(&mgr, "write", &p("cache", "output.txt")).await;
    print_case("ALLOW expected", "write", &p("cache", "output.txt"), &r);
    let r = invoke(&mgr, "read",  &p("cache", "output.txt")).await;
    print_case("ALLOW expected", "read",  &p("cache", "output.txt"), &r);

    // =========================================================================
    // drop-box  —  DirPerms::MUTATE  FilePerms::WRITE
    // open_at always requires DirPerms::READ, so file read/write are both
    // denied. Only directory-level mutations (create_dir, delete) are allowed.
    // =========================================================================
    println!("\n{}Scenario 3: drop-box (audit/)  DirPerms::MUTATE  FilePerms::WRITE{}", CYAN, RESET);
    let r = invoke(&mgr, "create_dir", &p("audit", "events")).await;
    print_case("ALLOW expected", "create_dir", &p("audit", "events"), &r);
    let r = invoke(&mgr, "read",       &p("audit", "events")).await;
    print_case("DENY expected",  "read",       &p("audit", "events"), &r);

    // =========================================================================
    // fixed-mutable  —  DirPerms::READ  FilePerms::READ|WRITE
    // wasmtime's open_at checks DirPerms::MUTATE before FilePerms::WRITE, so
    // writing a file requires MUTATE on the dir regardless. In practice this
    // permission behaves like read-only at the file level — reads are allowed,
    // writes and create_dir are denied.
    // =========================================================================
    println!("\n{}Scenario 4: fixed-mutable (counters/)  DirPerms::READ  FilePerms::READ|WRITE{}", CYAN, RESET);
    let r = invoke(&mgr, "read",       &p("counters", "rate.txt")).await;
    print_case("ALLOW expected", "read",       &p("counters", "rate.txt"), &r);
    let r = invoke(&mgr, "create_dir", &p("counters", "new")).await;
    print_case("DENY expected",  "create_dir", &p("counters", "new"), &r);

    // =========================================================================
    // list-only  —  DirPerms::READ  FilePerms::empty()
    // Can enumerate filenames. Opening any file is denied (FilePerms::empty()).
    // =========================================================================
    println!("\n{}Scenario 5: list-only (plugins/)  DirPerms::READ  FilePerms::empty(){}", CYAN, RESET);
    let r = invoke(&mgr, "list_dir", &d("plugins")).await;
    print_case("ALLOW expected", "list_dir", &d("plugins"), &r);
    let r = invoke(&mgr, "read",     &p("plugins", "fs-sandbox-demo.wasm")).await;
    print_case("DENY expected",  "read",     &p("plugins", "fs-sandbox-demo.wasm"), &r);

    // =========================================================================
    // private-scratch  —  DirPerms::MUTATE  FilePerms::READ|WRITE
    // open_at always requires DirPerms::READ, so file I/O is denied despite
    // FilePerms::READ|WRITE. Only directory mutations are allowed.
    // =========================================================================
    println!("\n{}Scenario 6: private-scratch (scratch/)  DirPerms::MUTATE  FilePerms::READ|WRITE{}", CYAN, RESET);
    let r = invoke(&mgr, "create_dir", &p("scratch", "work")).await;
    print_case("ALLOW expected", "create_dir", &p("scratch", "work"), &r);
    let r = invoke(&mgr, "list_dir",   &d("scratch")).await;
    print_case("DENY expected",  "list_dir",   &d("scratch"), &r);

    println!("\n{}=== Demo complete ==={}\n", BOLD, RESET);
    mgr.shutdown().await;
}
