use anyhow::Result;
use wasmtime::{Config, Engine, Store};
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::*;
use wasmtime_wasi::p2::bindings::Command;
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};

// Generate bindings from WIT
wasmtime::component::bindgen!({
    path: "wit/world.wit",
    world: "plugin",
    exports: { default: async },
});

// Host state that implements WasiView
struct HostState {
    wasi: WasiCtx,
    table: wasmtime::component::ResourceTable,
}

impl WasiView for HostState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}
#[tokio::main]
async fn main() -> Result<()> {
    println!("=== CPEX WASM Plugin Host ===\n");

    // 1. Configure Wasmtime engine with component model support
    let mut config = Config::new();
    config.wasm_component_model(true);
    config.async_support(true);
    
    let engine = Engine::new(&config)?;
    println!("✓ Wasmtime engine initialized");
    
    // 2. Create WASI context for the plugin
    let wasi = wasmtime_wasi::WasiCtx::builder()
    .inherit_stdio()
    .inherit_env()
    .build();

    
    let mut store = Store::new(
        &engine, 
        HostState { 
            wasi,
            table: wasmtime::component::ResourceTable::new(),
        }
    );
    println!("✓ WASI context created");
    
    // 3. Set up linker with WASI
    let mut linker = Linker::new(&engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;

    println!("✓ Linker configured with WASI");
    
    // 4. Load the WASM component
    let wasm_path = "plugin.wasm";
    println!("\n--- Loading WASM plugin from: {} ---", wasm_path);
    
    let component = Component::from_file(&engine, wasm_path)?;
    println!("✓ WASM component loaded successfully");
    
    // 5. Instantiate the plugin
    println!("\n--- Instantiating plugin ---");
    let plugin = Plugin::instantiate_async(&mut store, &component, &linker).await?;
    println!("✓ Plugin instantiated");
    
    // 6. Test Scenario 1: Tool call without PII clearance
    println!("\n=== Scenario 1: Tool call without hr_admin role (should DENY) ===");
    let payload1 = cpex::plugin::types::MessagePayload {
        data: serde_json::json!({
            "message": {
                "role": "user",
                "content": [{"type": "text", "text": "Get compensation data"}],
                "tool_calls": [{
                    "id": "call_1",
                    "name": "get_compensation",
                    "arguments": "{\"employee_id\": 42}"
                }]
            }
        }).to_string(),
    };
    
    let extensions1 = cpex::plugin::types::Extensions {
        security: Some(serde_json::json!({
            "subject": {
                "id": "alice",
                "roles": ["user"]
            },
            "labels": ["PII"]
        }).to_string()),
        http: None,
    };
    
    println!("Calling plugin.handle_hook()...");
    let result1 = plugin
        .call_handle_hook(&mut store, &payload1, &extensions1).await?;
    
    print_result("Scenario 1", &result1);
    
    // 7. Test Scenario 2: Tool call with hr_admin role (should ALLOW)
    println!("\n=== Scenario 2: Tool call with hr_admin role (should ALLOW) ===");
    let payload2 = cpex::plugin::types::MessagePayload {
        data: serde_json::json!({
            "message": {
                "role": "user",
                "content": [{"type": "text", "text": "Get compensation data"}],
                "tool_calls": [{
                    "id": "call_2",
                    "name": "get_compensation",
                    "arguments": "{\"employee_id\": 42}"
                }]
            }
        }).to_string(),
    };
    
    let extensions2 = cpex::plugin::types::Extensions {
        security: Some(serde_json::json!({
            "subject": {
                "id": "bob",
                "roles": ["hr_admin"]
            },
            "labels": ["PII"]
        }).to_string()),
        http: None,
    };
    
    println!("Calling plugin.handle_hook()...");
    let result2 = plugin
        .call_handle_hook(&mut store, &payload2, &extensions2).await?;
    
    print_result("Scenario 2", &result2);
    
    // 8. Test Scenario 3: Tool result (POST-INVOKE)
    println!("\n=== Scenario 3: Tool result verification (POST-INVOKE) ===");
    let payload3 = cpex::plugin::types::MessagePayload {
        data: serde_json::json!({
            "message": {
                "role": "tool",
                "content": [{"type": "text", "text": "Salary: $120,000"}],
                "tool_results": [{
                    "tool_call_id": "call_2",
                    "tool_name": "get_compensation",
                    "content": "Salary: $120,000"
                }]
            }
        }).to_string(),
    };
    
    let extensions3 = cpex::plugin::types::Extensions {
        security: Some(serde_json::json!({
            "subject": {
                "id": "bob",
                "roles": ["hr_admin"]
            },
            "labels": []
        }).to_string()),
        http: None,
    };
    
    println!("Calling plugin.handle_hook()...");
    let result3 = plugin
        .call_handle_hook(&mut store, &payload3, &extensions3).await?;
    
    print_result("Scenario 3", &result3);
    
    println!("\n=== WASM Plugin Invocation Complete ===");
    Ok(())
}

fn print_result(scenario: &str, result: &cpex::plugin::types::PluginResult) {
    match result {
        cpex::plugin::types::PluginResult::Allow => {
            println!("✓ {}: ALLOW", scenario);
        }
        cpex::plugin::types::PluginResult::Deny(reason) => {
            println!("✗ {}: DENY - {}", scenario, reason);
        }
    }
}


