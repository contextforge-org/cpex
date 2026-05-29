use anyhow::Result;
use cpex_wasm_host::policy_loader::{self, build_wasi_context, load_plugin_sandbox_config, PolicyHttpHooks};
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

    let sandbox = print_plugin_sandbox_policy("config/config.yaml", "identity-checker")?;

    let plugin_ctx = build_wasi_context(&sandbox)?;
    println!("\n--- WASI Context from Policy ---");
    println!("  Allowed hosts: {:?}", plugin_ctx.allowed_hosts);
    println!("  WasiCtx: created successfully");
    println!("  WasiHttpCtx: created successfully");

    // Demonstrate PolicyHttpHooks enforcement
    let mut hooks = PolicyHttpHooks {
        allowed_hosts: plugin_ctx.allowed_hosts.clone(),
    };
    println!("\n--- Testing PolicyHttpHooks ---");
    test_http_hooks(&mut hooks, "http://httpbin.org/get");
    test_http_hooks(&mut hooks, "http://evil.com/steal");

    // Set test env vars BEFORE building the sandboxed context
    // PLUGIN_API_KEY is in the allowed list, SECRET_DB_PASSWORD is NOT
    std::env::set_var("PLUGIN_API_KEY", "test-secret-123");
    std::env::set_var("SECRET_DB_PASSWORD", "super-secret-do-not-leak");

    // Rebuild context now that env vars are set
    let sandbox = load_plugin_sandbox_config("config/config.yaml", "identity-checker")?;
    let plugin_ctx = build_wasi_context(&sandbox)?;

    // 1. Configure Wasmtime engine with component model support
    let mut config = Config::new();
    config.wasm_component_model(true);
    config.async_support(true);

    let engine = Engine::new(&config)?;
    println!("\n✓ Wasmtime engine initialized");

    // 2. Use the SANDBOXED WasiCtx (only allowed env vars, only allowed dirs)
    let mut store = Store::new(
        &engine,
        HostState {
            wasi: plugin_ctx.wasi_ctx,
            table: wasmtime::component::ResourceTable::new(),
        }
    );
    println!("✓ WASI sandboxed context created (only PLUGIN_API_KEY exposed)");

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

    // 6. Call the plugin — it will try to read env vars internally
    println!("\n=== Env Var Sandbox Test ===");
    println!("Host env has: PLUGIN_API_KEY=test-secret-123, SECRET_DB_PASSWORD=super-secret-do-not-leak");
    println!("Policy allows: [PLUGIN_API_KEY] only\n");

    let payload = cpex::plugin::types::MessagePayload {
        data: serde_json::json!({
            "message": {
                "role": "user",
                "content": [{"type": "text", "text": "test env access"}],
                "tool_calls": [{
                    "id": "call_env_test",
                    "name": "env_test",
                    "arguments": "{}"
                }]
            }
        }).to_string(),
    };

    let extensions = cpex::plugin::types::Extensions {
        security: None,
        http: None,
    };

    println!("Calling plugin.handle_hook()...");
    let result = plugin
        .call_handle_hook(&mut store, &payload, &extensions).await?;

    print_result("Env Sandbox", &result);
    
    println!("\n=== WASM Plugin Invocation Complete ===");
    Ok(())
}

fn test_http_hooks(hooks: &mut PolicyHttpHooks, uri: &str) {
    use wasmtime_wasi_http::p2::WasiHttpHooks;
    use wasmtime_wasi_http::p2::types::OutgoingRequestConfig;

    let request = hyper::Request::builder()
        .uri(uri)
        .body(wasmtime_wasi_http::p2::body::HyperOutgoingBody::default())
        .unwrap();

    let config = OutgoingRequestConfig {
        use_tls: false,
        connect_timeout: std::time::Duration::from_secs(30),
        first_byte_timeout: std::time::Duration::from_secs(30),
        between_bytes_timeout: std::time::Duration::from_secs(30),
    };

    match hooks.send_request(request, config) {
        Ok(_) => println!("  {} -> ALLOWED", uri),
        Err(e) => println!("  {} -> DENIED ({:?})", uri, e),
    }
}

fn print_plugin_sandbox_policy(config_path: &str, plugin_name: &str) -> Result<policy_loader::SandboxConfig> {
    let sandbox = load_plugin_sandbox_config(config_path, plugin_name)?;
    println!(
        "✓ Loaded sandbox policy for {}:\n{}",
        plugin_name,
        serde_json::to_string_pretty(&sandbox)?
    );
    Ok(sandbox)
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


