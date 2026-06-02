use std::path::Path;

use anyhow::Result;

use cpex_wasm_host::policy_loader::load_plugin_sandbox_config;
use cpex_wasm_host::sandbox_manager::{SandboxManager, types::*};

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== Plugin Smoke Test ===\n");

    // Load config and create sandbox manager
    let mut manager = SandboxManager::new()?;
    println!("[OK] SandboxManager created");

    let sandbox = load_plugin_sandbox_config("config/config.yaml", "identity-checker")?;
    manager
        .load_plugin("identity-checker", Path::new("plugin.wasm"), sandbox)
        .await?;
    println!("[OK] Plugin loaded");

    // Build a minimal payload
    let payload = MessagePayload {
        message: Message {
            schema_version: "1.0".to_string(),
            role: Role::User,
            content: vec![ContentPart::Text("hello from smoke test".to_string())],
            channel: None,
        },
    };

    let extensions = Extensions {
        request: None,
        security: None,
        http: None,
        meta: None,
    };

    let ctx = PluginContext {
        local_state: "{}".to_string(),
        global_state: "{}".to_string(),
    };

    // Invoke the plugin
    let result = manager
        .invoke("identity-checker", payload, extensions, ctx)
        .await?;

    match &result {
        PluginResult::Allow => println!("[OK] Result: ALLOW"),
        PluginResult::Deny(v) => println!("[OK] Result: DENY - [{}] {}", v.code, v.reason),
    }

    println!("\n=== Smoke test passed ===");
    Ok(())
}
