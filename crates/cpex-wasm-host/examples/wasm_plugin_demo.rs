// Location: ./crates/cpex-wasm-host/examples/wasm_plugin_demo.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
// Demonstrates invoking a WASM plugin through the PluginManager pipeline.
// Reads plugin configuration from config/config_wasm_sandbox.yaml.

use std::path::PathBuf;
use std::sync::Arc;

use cpex_core::cmf::{CmfHook, ContentPart, Message, MessagePayload, Role, ToolCall};
use cpex_core::config::parse_config;
use cpex_core::extensions::{Extensions, SecurityExtension};
use cpex_core::extensions::security::SubjectExtension;
use cpex_core::manager::PluginManager;

use cpex_wasm_host::factory::WasmPluginFactory;

#[tokio::main]
async fn main() {
    println!("=== WASM Plugin Demo (via PluginManager) ===\n");

    // 1. Create plugin manager and register wasm factory under the exact kind string.
    //    Each plugin gets its own isolated SandboxManager instance.
    let mgr = PluginManager::default();
    mgr.register_factory(
        "wasm://plugin.wasm",
        Box::new(WasmPluginFactory::new(PathBuf::from("wasm"))),
    );

    // 2. Load config from YAML file — triggers WasmPluginFactory::create()
    println!("[DEBUG] Reading config/config_wasm_sandbox.yaml...");
    let yaml = std::fs::read_to_string("config/config_wasm_sandbox.yaml")
        .expect("failed to read config/config_wasm_sandbox.yaml");
    println!("[DEBUG] Config YAML loaded ({} bytes)", yaml.len());

    let config = parse_config(&yaml).unwrap();
    println!("[DEBUG] Config parsed, loading into PluginManager...");
    mgr.load_config(config).unwrap();
    println!("[DEBUG] load_config OK — WasmPluginFactory::create() succeeded");

    mgr.initialize().await.unwrap();
    println!("[DEBUG] initialize() OK — plugin ready\n");

    // 3. Build a test payload (assistant requesting a tool call)
    let payload = MessagePayload {
        message: Message {
            schema_version: "1.0".into(),
            role: Role::Assistant,
            content: vec![
                ContentPart::Text {
                    text: "Looking up compensation.".into(),
                },
                ContentPart::ToolCall {
                    content: ToolCall {
                        tool_call_id: "tc_001".into(),
                        name: "get_compensation".into(),
                        arguments: [("employee_id".to_string(), serde_json::json!(42))].into(),
                        namespace: None,
                    },
                },
            ],
            channel: None,
        },
    };

    // 4. Build extensions with security context
    let mut security = SecurityExtension::default();
    security.add_label("PII");
    security.subject = Some(SubjectExtension {
        id: Some("alice".into()),
        roles: ["hr_admin".to_string()].into(),
        ..Default::default()
    });

    let ext = Extensions {
        security: Some(Arc::new(security)),
        ..Default::default()
    };

    // 5. Invoke through the plugin manager pipeline
    println!("=== Invoking cmf.tool_pre_invoke ===");
    println!("[DEBUG] Payload: role={:?}, content_parts={}", payload.message.role, payload.message.content.len());
    println!("[DEBUG] Extensions: security={}", ext.security.is_some());

    let (result, bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, ext, None)
        .await;

    println!("[DEBUG] invoke_named returned, waiting for background tasks...");
    bg.wait_for_background_tasks().await;
    println!("[DEBUG] Background tasks done");

    println!("[DEBUG] continue_processing={}, violation={:?}", result.continue_processing, result.violation.is_some());
    if result.continue_processing {
        println!("  Result: ALLOW");
    } else if let Some(ref violation) = result.violation {
        println!("  Result: DENY - [{}] {}", violation.code, violation.reason);
    } else {
        println!("  Result: DENY (no violation details)");
    }
}
