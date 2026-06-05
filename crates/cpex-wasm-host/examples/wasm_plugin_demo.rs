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
use cpex_core::extensions::{HttpExtension, RequestExtension, SecurityExtension};
use cpex_core::hooks::payload::{Extensions, MetaExtension};
use cpex_core::extensions::security::SubjectExtension;
use cpex_core::manager::PluginManager;

use cpex_wasm_host::factory::WasmPluginFactory;

#[tokio::main]
async fn main() {
    println!("=== WASM Plugin Demo (via PluginManager) ===\n");

    // 1. Create plugin manager and register wasm factory under the exact kind string.
    //    Each plugin gets its own isolated SandboxManager instance.
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let config_path = crate_dir.join("config/config_wasm_sandbox.yaml");
    println!("--- Loading config from {} ---\n", config_path.display());
    let yaml = std::fs::read_to_string(&config_path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", config_path.display(), e));
    let cpex_config = parse_config(&yaml).unwrap();

    let mgr = PluginManager::default();
    mgr.register_factory(
        "wasm://plugin.wasm",
        Box::new(WasmPluginFactory::new(crate_dir.join("wasm"))),
    );

    mgr.load_config(cpex_config).unwrap();
    mgr.initialize().await.unwrap();

    // 3. Build a test payload (assistant requesting a tool call)
    let payload = MessagePayload {
        message: Message {
            schema_version: cpex_core::cmf::constants::SCHEMA_VERSION.into(),
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
    security.add_label("HR_DATA");
    security.classification = Some("confidential".into());
    security.subject = Some(SubjectExtension {
        id: Some("alice".into()),
        subject_type: Some(cpex_core::extensions::security::SubjectType::User),
        roles: ["hr_admin".to_string()].into(),
        permissions: ["read_compensation".to_string()].into(),
        ..Default::default()
    });

    let mut http = HttpExtension::default();
    http.set_header("Authorization", "Bearer eyJ...");
    http.set_header("X-Request-ID", "req-abc-123");

    let ext = Extensions {
        request: Some(Arc::new(RequestExtension {
            environment: Some("production".into()),
            request_id: Some("req-abc-123".into()),
            ..Default::default()
        })),
        security: Some(Arc::new(security)),
        http: Some(Arc::new(http)),
        meta: Some(Arc::new(MetaExtension {
            entity_type: Some("tool".into()),
            entity_name: Some("get_compensation".into()),
            tags: ["pii".to_string(), "hr".to_string()].into(),
            ..Default::default()
        })),
        ..Default::default()
    };

    // --- Pre-invoke: type-safe dispatch via invoke_named ---
    println!("=== Phase 1: cmf.tool_pre_invoke ===\n");
    let (pre_result, bg) = mgr
        .invoke_named::<CmfHook>(
            "cmf.tool_pre_invoke",
            payload,
            ext,
            None, // first hook — no context table
        )
        .await;

    println!();

        println!();
    if pre_result.continue_processing {
        println!("Pre-invoke result: ALLOWED");
        if let Some(ref modified_ext) = pre_result.modified_extensions {
            if let Some(ref sec) = modified_ext.security {
                let labels: Vec<&String> = sec.labels.iter().collect();
                println!("  Labels after pre-invoke: {:?}", labels);
            }
            if let Some(ref http) = modified_ext.http {
                println!("  Headers after pre-invoke: {:?}", http.request_headers);
            }
        }
    } else {
        println!(
            "Pre-invoke result: DENIED — {}",
            pre_result.violation.as_ref().unwrap().reason
        );
        bg.wait_for_background_tasks().await;
        println!("\n=== Demo complete ===");
        return;
    }
    bg.wait_for_background_tasks().await;

    println!("\n--- Tool 'get_compensation' executes... ---");
    println!("  Result: {{\"salary\": 150000, \"currency\": \"USD\"}}\n");

    // --- Post-invoke: different CMF message with tool result ---
    println!("=== Phase 2: cmf.tool_post_invoke ===\n");


    let post_payload = MessagePayload {
        message: Message {
            schema_version: cpex_core::cmf::constants::SCHEMA_VERSION.into(),
            role: Role::Tool,
            content: vec![ContentPart::ToolResult {
                content: cpex_core::cmf::ToolResult {
                    tool_call_id: "tc_001".into(),
                    tool_name: "get_compensation".into(),
                    content: serde_json::json!({"salary": 150000, "currency": "USD"}),
                    is_error: false,
                },
            }],
            channel: None,
        },
    };

        // Build post-invoke extensions — carry forward any modifications
    // from pre-invoke via the context table
    let post_ext = pre_result.modified_extensions.unwrap_or_else(|| {
        // Rebuild if no modifications
        let mut security = SecurityExtension::default();
        security.add_label("PII");
        Extensions {
            security: Some(Arc::new(security)),
            meta: Some(Arc::new(MetaExtension {
                entity_type: Some("tool".into()),
                entity_name: Some("get_compensation".into()),
                ..Default::default()
            })),
            ..Default::default()
        }
    });

        let (post_result, post_bg) = mgr
        .invoke_named::<CmfHook>(
            "cmf.tool_post_invoke",
            post_payload,
            post_ext,
            Some(pre_result.context_table),
        )
        .await;

    println!();
    if post_result.continue_processing {
        println!("Post-invoke result: ALLOWED");
    } else {
        println!(
            "Post-invoke result: DENIED — {}",
            post_result.violation.as_ref().unwrap().reason
        );
    }

    post_bg.wait_for_background_tasks().await;
    println!("\n=== Demo complete ===");
}
