use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::Mutex;

use cpex_wasm_host::dashboard::spawn_dashboard;
use cpex_wasm_host::sandbox_manager::{SandboxManager, types::*};

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== CPEX WASM Plugin Host (SandboxManager) ===\n");

    // Set test env vars
    std::env::set_var("PLUGIN_API_KEY", "test-secret-123");
    std::env::set_var("SECRET_DB_PASSWORD", "super-secret-do-not-leak");

    // Create the sandbox manager and load all plugins from config
    let mut manager = SandboxManager::new()?;
    println!("✓ SandboxManager initialized");

    manager
        .load_from_config(Path::new("config/config.yaml"), Path::new("wasm"))
        .await?;
    println!("✓ Loaded plugins from config: {:?}\n", manager.list_plugins());

    // Wrap manager in Arc<Mutex> and start the dashboard
    let shared = Arc::new(Mutex::new(manager));
    spawn_dashboard(shared.clone(), 3000);

    // Build shared test payload and extensions
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

    // --- Invoke identity-checker (WITH sandbox policy) ---
    println!("=== Invoking 'identity-checker' (WITH sandbox policy) ===");
    println!("  Policy: filesystem=/tmp/cpex-sandbox/data(read), network=httpbin.org, env=PLUGIN_API_KEY");
    println!("  Resources: memory=10MB, fuel=1B, timeout=5s\n");

    {
        let mut mgr = shared.lock().await;
        let result = mgr
            .invoke("identity-checker", payload.clone(), extensions.clone(), ctx.clone())
            .await?;

        if result.continue_processing {
            println!("  Result: ALLOW");
        } else if let Some(violation) = &result.violation {
            println!("  Result: DENY - [{}] {}", violation.code, violation.reason);
        } else {
            println!("  Result: DENY (no violation details)");
        }

        if let Some(m) = mgr.metrics("identity-checker") {
            println!("  Metrics: invocations={}, fuel_consumed={}, network_denials={}, network_allowed={}",
                m.total_invocations, m.total_fuel_consumed, m.network_denials, m.network_allowed);
        }
    }

    // --- Invoke audit-logger (WITHOUT sandbox policy — deny-by-default) ---
    println!("\n=== Invoking 'audit-logger' (WITHOUT sandbox policy — deny-by-default) ===");
    println!("  Policy: filesystem=NONE, network=NONE, env=NONE");
    println!("  Resources: defaults (unlimited)\n");

    {
        let mut mgr = shared.lock().await;
        let result = mgr
            .invoke("audit-logger", payload.clone(), extensions.clone(), ctx.clone())
            .await;

        match result {
            Ok(r) => {
                if r.continue_processing {
                    println!("  Result: ALLOW");
                } else if let Some(violation) = &r.violation {
                    println!("  Result: DENY - [{}] {}", violation.code, violation.reason);
                } else {
                    println!("  Result: DENY (no violation details)");
                }
            }
            Err(e) => {
                println!("  Result: ERROR (sandbox restriction likely) - {}", e);
            }
        }

        if let Some(m) = mgr.metrics("audit-logger") {
            println!("  Metrics: invocations={}, fuel_consumed={}, network_denials={}, network_allowed={}",
                m.total_invocations, m.total_fuel_consumed, m.network_denials, m.network_allowed);
        }
    }

    // Keep the process alive so the dashboard stays up
    println!("\n\nDashboard is running at http://localhost:3000. Press Ctrl+C to exit.");
    tokio::signal::ctrl_c().await?;
    println!("\nShutting down.");

    Ok(())
}
