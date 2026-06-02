use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::Mutex;

use cpex_wasm_host::dashboard::spawn_dashboard;
use cpex_wasm_host::policy_loader::load_plugin_sandbox_config;
use cpex_wasm_host::sandbox_manager::{SandboxManager, types::*};

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

    let payload = MessagePayload {
        message: Message {
            schema_version: "1.0".to_string(),
            role: Role::User,
            content: vec![
                ContentPart::Text("sandbox manager test".to_string()),
                ContentPart::ToolCall(ToolCall {
                    tool_call_id: "call_1".to_string(),
                    name: "sandbox_probe".to_string(),
                    arguments: "{}".to_string(),
                    namespace: None,
                }),
            ],
            channel: None,
        },
    };

    let extensions = Extensions {
        request: None,
        security: Some(SecurityExtension {
            labels: vec!["PII".to_string()],
            classification: Some("confidential".to_string()),
            subject: Some(SubjectExtension {
                id: Some("user-42".to_string()),
                subject_type: Some(SubjectType::User),
                roles: vec!["analyst".to_string()],
                permissions: vec!["read".to_string()],
                teams: vec!["data-team".to_string()],
                claims: vec![("org".to_string(), "acme".to_string())],
            }),
            auth_method: Some("oauth2".to_string()),
        }),
        http: None,
        meta: None,
    };

    let ctx = PluginContext {
        local_state: "{}".to_string(),
        global_state: "{}".to_string(),
    };

    {
        let mut mgr = shared.lock().await;
        let result = mgr.invoke("identity-checker", payload, extensions, ctx).await?;

        match &result {
            PluginResult::Allow => println!("Result: ALLOW"),
            PluginResult::Deny(violation) => {
                println!("Result: DENY - [{}] {}", violation.code, violation.reason);
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
