use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::Mutex;

use cpex_wasm_host::policy_loader::load_plugin_sandbox_config;
use cpex_wasm_host::sandbox_manager::SandboxManager;
use cpex_wasm_dashboard::spawn_dashboard;

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== CPEX WASM Dashboard (Standalone) ===\n");

    std::env::set_var("PLUGIN_API_KEY", "dashboard-test-key");

    let mut manager = SandboxManager::new()?;

    let sandbox = load_plugin_sandbox_config("config/config.yaml", "identity-checker")?;
    manager
        .load_plugin("identity-checker", Path::new("plugin.wasm"), sandbox)
        .await?;
    println!("✓ Plugin 'identity-checker' loaded");

    let shared = Arc::new(Mutex::new(manager));

    // Start the dashboard server on port 3000
    spawn_dashboard(shared.clone(), 3000);

    // Background invoker for demo purposes
    let invoker = shared.clone();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        let mut mgr = invoker.lock().await;
        let payload = cpex_wasm_host::sandbox_manager::types::MessagePayload {
            data: serde_json::json!({
                "message": {
                    "role": "user",
                    "content": [{"type": "text", "text": "periodic check"}],
                    "tool_calls": [{"id": "bg", "name": "sandbox_probe", "arguments": "{}"}]
                },
                "probe": {
                    "env_vars": ["PLUGIN_API_KEY"],
                    "http_requests": ["http://httpbin.org/get", "http://evil.com/x"]
                }
            })
            .to_string(),
        };
        let extensions = cpex_wasm_host::sandbox_manager::types::Extensions {
            security: None,
            http: None,
        };
        let _ = mgr.invoke("identity-checker", payload, extensions).await;
    }
}
