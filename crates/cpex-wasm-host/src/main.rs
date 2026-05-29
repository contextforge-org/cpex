use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::Mutex;

use cpex_wasm_host::dashboard::spawn_dashboard;
use cpex_wasm_host::policy_loader::load_plugin_sandbox_config;
use cpex_wasm_host::sandbox_manager::{SandboxManager, types::PluginResult};

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== CPEX WASM Plugin Host (SandboxManager) ===\n");

    // Set test env vars
    std::env::set_var("PLUGIN_API_KEY", "test-secret-123");
    std::env::set_var("SECRET_DB_PASSWORD", "super-secret-do-not-leak");

    // Create the sandbox manager
    let mut manager = SandboxManager::new()?;
    println!("✓ SandboxManager initialized");

    // Load plugin from config
    let sandbox = load_plugin_sandbox_config("config/config.yaml", "identity-checker")?;
    println!("✓ Loaded sandbox policy:\n{}\n", serde_json::to_string_pretty(&sandbox)?);

    manager
        .load_plugin("identity-checker", Path::new("plugin.wasm"), sandbox)
        .await?;
    println!("✓ Plugin 'identity-checker' loaded");
    println!("  Loaded plugins: {:?}", manager.list_plugins());

    // Wrap manager in Arc<Mutex> and start the dashboard
    let shared = Arc::new(Mutex::new(manager));
    spawn_dashboard(shared.clone(), 3000);

    // Invoke the plugin a few times to generate metrics visible on the dashboard
    println!("\n=== Invoking Plugin (metrics visible at http://localhost:3000) ===");

    let payload = cpex_wasm_host::sandbox_manager::types::MessagePayload {
        data: serde_json::json!({
            "message": {
                "role": "user",
                "content": [{"type": "text", "text": "sandbox manager test"}],
                "tool_calls": [{
                    "id": "call_1",
                    "name": "sandbox_probe",
                    "arguments": "{}"
                }]
            },
            "probe": {
                "env_vars": ["PLUGIN_API_KEY", "SECRET_DB_PASSWORD"],
                "http_requests": ["http://httpbin.org/get", "http://evil.com/steal"]
            }
        }).to_string(),
    };

    let extensions = cpex_wasm_host::sandbox_manager::types::Extensions {
        security: None,
        http: None,
    };

    {
        let mut mgr = shared.lock().await;
        let result = mgr.invoke("identity-checker", payload, extensions).await?;

        match &result {
            PluginResult::Allow => println!("Result: ALLOW"),
            PluginResult::Deny(msg) => {
                if let Some(json_str) = msg.strip_prefix("SANDBOX_PROBE_RESULT:") {
                    let report: serde_json::Value = serde_json::from_str(json_str)?;
                    println!("Sandbox Probe Results:\n{}", serde_json::to_string_pretty(&report)?);
                } else {
                    println!("Result: DENY - {}", msg);
                }
            }
        }

        // Print metrics
        if let Some(m) = mgr.metrics("identity-checker") {
            println!("\nPlugin Metrics:");
            println!("  Invocations: {}", m.total_invocations);
            println!("  Fuel consumed: {}", m.total_fuel_consumed);
            println!("  Network denials: {}", m.network_denials);
            println!("  Network allowed: {}", m.network_allowed);
        }
    }

    // Keep the process alive so the dashboard stays up
    println!("\nDashboard is running. Press Ctrl+C to exit.");
    tokio::signal::ctrl_c().await?;
    println!("\nShutting down.");

    Ok(())
}
