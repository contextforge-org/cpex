// Location: ./crates/cpex-wasm-host/examples/wasm_custom_payload_demo.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
// Custom payload WASM plugin demo.
//
// Demonstrates a custom payload type (ToolInvokePayload) crossing the WASM
// boundary via HookPayload::Custom. This covers the path beyond CMF:
//
//   host: ToolInvokePayload → PayloadSerializerRegistry.serialize()
//         → HookPayload::Custom { payload_type: "cpex.tool_invoke", bytes }
//         → SandboxManager.invoke()
//   WASM guest: receives Custom variant, logs receipt, returns allow()
//   host: PayloadSerializerRegistry.deserialize() on any modified payload
//
// The bundled guest has no HookHandler for ToolInvokePayload, so this
// demo exercises the pass-through path: an unhandled custom payload
// returns allow(), same as a native plugin not registered for the hook.
// See wasm_identity_resolve_demo for full typed dispatch on the custom
// path (IdentityPayload -> HookHandler<IdentityHook> inside the guest).
//
// Prerequisites: build the WASM plugin first:
//   cargo build -p cpex-wasm-plugin --target wasm32-wasip2
//
// Run from the workspace root:
//   cargo run -p cpex-wasm-host --example wasm_custom_payload_demo

use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use cpex_core::config::parse_config;
use cpex_core::extensions::container::Extensions;
use cpex_core::extensions::security::{SecurityExtension, SubjectExtension, SubjectType};
use cpex_core::hooks::payload::WasmSerializablePayload;
use cpex_core::hooks::trait_def::PluginResult;
use cpex_core::manager::PluginManager;
use cpex_core::{impl_plugin_payload, impl_wasm_payload};

use cpex_wasm_host::factory::WasmPluginFactory;
use cpex_wasm_host::payload_registry::PayloadSerializerRegistry;

// ---------------------------------------------------------------------------
// Custom payload type — defined on the host, shared with WASM guests
// ---------------------------------------------------------------------------

/// A structured tool-invocation payload carrying explicit user/tool identity.
/// Distinct from CMF's MessagePayload: models the invocation itself rather
/// than the conversation turn containing the tool call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInvokePayload {
    /// Name of the tool being invoked.
    tool_name: String,
    /// Invoking user's identity.
    user: String,
    /// Serialized tool arguments (JSON).
    arguments: String,
}

// Register with cpex-core's PluginPayload trait system.
impl_plugin_payload!(ToolInvokePayload);

// Register for WASM transport: type discriminator + JSON serialization.
impl_wasm_payload!(ToolInvokePayload, "cpex.tool_invoke");

// ---------------------------------------------------------------------------
// Hook type definition for tool pre-invoke
// ---------------------------------------------------------------------------

cpex_core::define_hook! {
    /// Hook fired before a tool is invoked. Payload carries explicit user/tool identity.
    ToolPreInvoke, "tool_pre_invoke" => {
        payload: ToolInvokePayload,
        result: PluginResult<ToolInvokePayload>,
    }
}

// ---------------------------------------------------------------------------
// Demo
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    println!("=== WASM Plugin Demo — Generic Payload (ToolInvokePayload) ===\n");

    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let config_path = crate_dir.join("config/config.yaml");

    println!("Loading config: {}", config_path.display());
    let yaml = std::fs::read_to_string(&config_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", config_path.display(), e));
    let cpex_config = parse_config(&yaml).unwrap();

    // Build a registry with both MessagePayload (CMF fast-path) and
    // ToolInvokePayload (generic path) registered.
    let mut registry = PayloadSerializerRegistry::new();
    registry.register::<cpex_core::cmf::MessagePayload>();
    registry.register::<ToolInvokePayload>();

    println!(
        "PayloadSerializerRegistry: registered 'cmf.message' and '{}'\n",
        ToolInvokePayload::payload_type_name()
    );

    let mgr = PluginManager::default();
    mgr.register_factory(
        "wasm://plugin.wasm",
        Box::new(WasmPluginFactory::new(crate_dir.join("wasm"), Arc::new(registry))),
    );
    mgr.load_config(cpex_config).unwrap();
    mgr.initialize().await.unwrap();

    // Build the custom payload.
    let payload = ToolInvokePayload {
        tool_name: "get_compensation".into(),
        user: "alice".into(),
        arguments: r#"{"employee_id": 42}"#.into(),
    };

    println!("Payload: {:?}", payload);
    println!(
        "Wire type: '{}' ({} bytes when serialized)\n",
        ToolInvokePayload::payload_type_name(),
        payload.to_wasm_bytes().unwrap().len()
    );

    // Build extensions with identity context.
    let ext = build_extensions();

    // --- Invoke through the WASM pipeline ---
    println!("=== tool_pre_invoke via WASM (Generic path) ===");

    let (result, bg) = mgr
        .invoke_named::<ToolPreInvoke>("tool_pre_invoke", payload, ext, None)
        .await;

    if result.continue_processing {
        println!("Result: ALLOWED");
        println!("  (guest has no ToolInvokePayload handler — passed through as allow())");
    } else {
        let reason = result.violation.as_ref().map(|v| v.reason.as_str()).unwrap_or("unknown");
        println!("Result: DENIED — {}", reason);
    }

    bg.wait_for_background_tasks().await;

    println!("\n=== Demo complete ===");
    println!("\nNote: for typed dispatch of a custom payload inside the guest, see");
    println!("wasm_identity_resolve_demo (IdentityPayload → HookHandler<IdentityHook>).");
}

fn build_extensions() -> Extensions {
    let mut security = SecurityExtension::default();
    security.subject = Some(SubjectExtension {
        id: Some("alice".into()),
        subject_type: Some(SubjectType::User),
        roles: ["tool_user".to_string()].into(),
        permissions: ["invoke_tools".to_string()].into(),
        ..Default::default()
    });

    Extensions {
        security: Some(Arc::new(security)),
        ..Default::default()
    }
}
