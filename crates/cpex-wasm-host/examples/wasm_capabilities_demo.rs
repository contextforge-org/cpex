// WASM Capabilities Demo
//
// Demonstrates:
//   1. Three WASM plugins with different capability profiles
//   2. Capability-gated extension visibility across the WASM sandbox boundary
//   3. Extension modification by a WASM plugin (add label + inject header)
//   4. Multi-plugin pipeline with priority ordering
//
// Prerequisites: build all plugin binaries:
//   cd crates/cpex-wasm-plugin && make build-all
//
// Run:
//   cargo run -p cpex-wasm-host --example wasm_capabilities_demo

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
    // Initialize tracing so plugin cpex_log! calls are visible.
    // Set RUST_LOG=info (or debug/trace) to control verbosity.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("info".parse().unwrap()),
        )
        .init();

    println!("=== WASM Capabilities Demo ===\n");

    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let config_path = crate_dir.join("config/config_capabilities.yaml");
    let wasm_dir = crate_dir.join("wasm");

    println!("Loading config: {}", config_path.display());
    let yaml = std::fs::read_to_string(&config_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", config_path.display(), e));
    let cpex_config = parse_config(&yaml).unwrap();

    let mgr = PluginManager::default();

    // Register the WASM factory for each plugin kind.
    // The factory strips "wasm://" and looks for the .wasm file in the wasm/ dir.
    mgr.register_factory(
        "wasm://identity-checker.wasm",
        Box::new(WasmPluginFactory::with_builtin_payloads(wasm_dir.clone())),
    );
    mgr.register_factory(
        "wasm://header-injector.wasm",
        Box::new(WasmPluginFactory::with_builtin_payloads(wasm_dir.clone())),
    );
    mgr.register_factory(
        "wasm://audit-logger.wasm",
        Box::new(WasmPluginFactory::with_builtin_payloads(wasm_dir)),
    );

    mgr.load_config(cpex_config).unwrap();
    mgr.initialize().await.unwrap();

    // --- Build CMF Message: assistant requesting a tool call ---
    let pre_payload = MessagePayload {
        message: Message {
            schema_version: cpex_core::cmf::constants::SCHEMA_VERSION.into(),
            role: Role::Assistant,
            content: vec![
                ContentPart::Text {
                    text: "Looking up compensation data.".into(),
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

    let ext = build_extensions();

    // --- Phase 1: Pre-invoke ---
    println!("=== Phase 1: cmf.tool_pre_invoke ===\n");

    let (pre_result, pre_bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", pre_payload, ext, None)
        .await;

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
        let reason = pre_result
            .violation
            .as_ref()
            .map(|v| v.reason.as_str())
            .unwrap_or("unknown");
        println!("Pre-invoke result: DENIED — {}", reason);
        pre_bg.wait_for_background_tasks().await;
        println!("\n=== Demo complete ===");
        return;
    }
    pre_bg.wait_for_background_tasks().await;

    // --- Simulate tool execution ---
    println!("\n--- Tool 'get_compensation' executes... ---");
    println!("  Result: {{\"salary\": 150000, \"currency\": \"USD\"}}\n");

    // --- Phase 2: Post-invoke with tool result ---
    println!("=== Phase 2: cmf.tool_post_invoke ===\n");

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

    let post_ext = pre_result
        .modified_extensions
        .unwrap_or_else(build_extensions);

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
        let reason = post_result
            .violation
            .as_ref()
            .map(|v| v.reason.as_str())
            .unwrap_or("unknown");
        println!("Post-invoke result: DENIED — {}", reason);
    }

    post_bg.wait_for_background_tasks().await;
    println!("\n=== Demo complete ===");
}

fn build_extensions() -> Extensions {
    let mut security = SecurityExtension::default();
    security.add_label("PII");
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
