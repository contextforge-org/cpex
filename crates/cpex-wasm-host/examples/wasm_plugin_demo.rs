// Location: ./crates/cpex-wasm-host/examples/wasm_plugin_demo.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
// CMF payload WASM plugin demo.
//
// Shows the end-to-end CMF path: a MessagePayload crosses the WASM boundary,
// the guest IdentityCheckerPlugin (written with HookHandler<CmfHook> — identical
// to a native plugin) runs the identity check, and the result flows back.
//
// Prerequisites: build the WASM plugin first:
//   cargo build -p cpex-wasm-plugin --target wasm32-wasip2
//   cargo run --example wasm_plugin_demo
//
// Run from the workspace root:
//   cargo run -p cpex-wasm-host --example wasm_plugin_demo

use std::path::PathBuf;
use std::sync::Arc;

use cpex_core::cmf::{CmfHook, ContentPart, Message, MessagePayload, Role, ToolCall, ToolResult};
use cpex_core::config::parse_config;
use cpex_core::extensions::container::Extensions;
use cpex_core::extensions::http::HttpExtension;
use cpex_core::extensions::meta::MetaExtension;
use cpex_core::extensions::request::RequestExtension;
use cpex_core::extensions::security::{SecurityExtension, SubjectExtension, SubjectType};
use cpex_core::manager::PluginManager;

use cpex_wasm_host::factory::WasmPluginFactory;

#[tokio::main]
async fn main() {
    println!("=== WASM Plugin Demo — CMF MessagePayload ===\n");

    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let config_path = crate_dir.join("config/config.yaml");

    println!("Loading config: {}", config_path.display());
    let yaml = std::fs::read_to_string(&config_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", config_path.display(), e));
    let cpex_config = parse_config(&yaml).unwrap();

    // WasmPluginFactory::with_cmf_only registers MessagePayload in the
    // PayloadSerializerRegistry — the CMF fast-path uses HookPayload::Cmf
    // directly rather than going through the generic serialization path.
    let mgr = PluginManager::default();
    mgr.register_factory(
        "wasm://plugin.wasm",
        Box::new(WasmPluginFactory::with_cmf_only(crate_dir.join("wasm"))),
    );
    mgr.load_config(cpex_config).unwrap();
    mgr.initialize().await.unwrap();

    // Build a pre-invoke payload: assistant requesting a tool call.
    let pre_payload = MessagePayload {
        message: Message {
            schema_version: cpex_core::cmf::constants::SCHEMA_VERSION.into(),
            role: Role::Assistant,
            content: vec![
                ContentPart::Text { text: "Looking up compensation data.".into() },
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

    let pre_ext = build_extensions("PII");

    // --- Phase 1: pre-invoke ---
    println!("=== cmf.tool_pre_invoke ===");
    let (pre_result, pre_bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", pre_payload, pre_ext, None)
        .await;

    if pre_result.continue_processing {
        println!("Pre-invoke: ALLOWED");
    } else {
        let reason = pre_result.violation.as_ref().map(|v| v.reason.as_str()).unwrap_or("unknown");
        println!("Pre-invoke: DENIED — {}", reason);
        pre_bg.wait_for_background_tasks().await;
        println!("\n=== Demo complete ===");
        return;
    }
    pre_bg.wait_for_background_tasks().await;

    println!("\n  [tool executes: {{\"salary\": 150000, \"currency\": \"USD\"}}]\n");

    // --- Phase 2: post-invoke with tool result ---
    println!("=== cmf.tool_post_invoke ===");

    let post_payload = MessagePayload {
        message: Message {
            schema_version: cpex_core::cmf::constants::SCHEMA_VERSION.into(),
            role: Role::Tool,
            content: vec![ContentPart::ToolResult {
                content: ToolResult {
                    tool_call_id: "tc_001".into(),
                    tool_name: "get_compensation".into(),
                    content: serde_json::json!({"salary": 150000, "currency": "USD"}),
                    is_error: false,
                },
            }],
            channel: None,
        },
    };

    // Carry forward any modified extensions from pre-invoke; rebuild if none.
    let post_ext = pre_result.modified_extensions.unwrap_or_else(|| build_extensions("PII"));

    let (post_result, post_bg) = mgr
        .invoke_named::<CmfHook>(
            "cmf.tool_post_invoke",
            post_payload,
            post_ext,
            Some(pre_result.context_table),
        )
        .await;

    if post_result.continue_processing {
        println!("Post-invoke: ALLOWED");
    } else {
        let reason = post_result.violation.as_ref().map(|v| v.reason.as_str()).unwrap_or("unknown");
        println!("Post-invoke: DENIED — {}", reason);
    }

    post_bg.wait_for_background_tasks().await;
    println!("\n=== Demo complete ===");
}

fn build_extensions(security_label: &str) -> Extensions {
    let mut security = SecurityExtension::default();
    security.add_label(security_label);
    security.add_label("HR_DATA");
    security.classification = Some("confidential".into());
    security.subject = Some(SubjectExtension {
        id: Some("alice".into()),
        subject_type: Some(SubjectType::User),
        roles: ["hr_admin".to_string()].into(),
        permissions: ["read_compensation".to_string()].into(),
        ..Default::default()
    });

    let mut http = HttpExtension::default();
    http.set_header("Authorization", "Bearer eyJ...");
    http.set_header("X-Request-ID", "req-abc-123");

    Extensions {
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
    }
}
