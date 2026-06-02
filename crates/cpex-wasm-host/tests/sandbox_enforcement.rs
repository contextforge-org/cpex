use anyhow::Result;
use cpex_wasm_host::policy_loader::{
    build_wasi_context, FilesystemRule, PolicyConfig, PolicyHttpHooks, ResourceLimits,
    SandboxConfig,
};
use std::sync::Arc;
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};
use wasmtime_wasi_http::p2::body::HyperOutgoingBody;
use wasmtime_wasi_http::p2::types::OutgoingRequestConfig;
use wasmtime_wasi_http::p2::{WasiHttpCtxView, WasiHttpHooks, WasiHttpView};
use wasmtime_wasi_http::WasiHttpCtx;

wasmtime::component::bindgen!({
    path: "wit",
    world: "plugin",
    exports: { default: async },
});

struct TestHostState {
    wasi: WasiCtx,
    http: WasiHttpCtx,
    hooks: PolicyHttpHooks,
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

impl WasiHttpView for TestHostState {
    fn http(&mut self) -> WasiHttpCtxView<'_> {
        WasiHttpCtxView {
            ctx: &mut self.http,
            table: &mut self.table,
            hooks: &mut self.hooks,
        }
    }
}

fn create_engine() -> Result<Engine> {
    let mut config = Config::new();
    config.wasm_component_model(true);
    Ok(Engine::new(&config)?)
}

fn make_minimal_payload() -> cpex::plugin::types::MessagePayload {
    cpex::plugin::types::MessagePayload {
        message: cpex::plugin::types::Message {
            schema_version: "1.0".to_string(),
            role: cpex::plugin::types::Role::User,
            content: vec![cpex::plugin::types::ContentPart::Text(
                "sandbox test".to_string(),
            )],
            channel: None,
        },
    }
}

fn make_minimal_extensions() -> cpex::plugin::types::Extensions {
    cpex::plugin::types::Extensions {
        request: None,
        security: None,
        http: None,
        meta: None,
    }
}

fn make_pii_non_admin_extensions() -> cpex::plugin::types::Extensions {
    cpex::plugin::types::Extensions {
        request: None,
        security: Some(cpex::plugin::types::SecurityExtension {
            labels: vec!["PII".to_string()],
            classification: None,
            subject: Some(cpex::plugin::types::SubjectExtension {
                id: Some("user-123".to_string()),
                subject_type: Some(cpex::plugin::types::SubjectType::User),
                roles: vec!["viewer".to_string()],
                permissions: vec![],
                teams: vec![],
                claims: vec![],
            }),
            auth_method: None,
        }),
        http: None,
        meta: None,
    }
}

fn make_minimal_ctx() -> cpex::plugin::types::PluginContext {
    cpex::plugin::types::PluginContext {
        local_state: "{}".to_string(),
        global_state: "{}".to_string(),
    }
}

// ============================================================
// POLICY DENY TESTS (plugin-level deny via identity-checker)
// ============================================================

#[tokio::test]
async fn test_policy_denies_pii_access_without_admin_role() -> Result<()> {
    let sandbox = SandboxConfig {
        version: "wasm-p2".to_string(),
        policy: PolicyConfig {
            allowed_env: vec![],
            allowed_filesystem: vec![],
            allowed_network: vec![],
        },
        resources: ResourceLimits::default(),
    };

    let ctx = build_wasi_context(&sandbox)?;
    let engine = create_engine()?;

    let mut store = Store::new(
        &engine,
        TestHostState {
            wasi: ctx.wasi_ctx,
            http: ctx.http_ctx,
            hooks: PolicyHttpHooks {
                allowed_hosts: ctx.allowed_hosts,
            },
            table: wasmtime::component::ResourceTable::new(),
        },
    );

    let mut linker = Linker::new(&engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;
    wasmtime_wasi_http::p2::add_only_http_to_linker_async(&mut linker)?;

    let component = Component::from_file(&engine, "plugin.wasm")?;
    let plugin = Plugin::instantiate_async(&mut store, &component, &linker).await?;

    // Payload with a tool-call so the plugin evaluates pre-invoke path
    let payload = cpex::plugin::types::MessagePayload {
        message: cpex::plugin::types::Message {
            schema_version: "1.0".to_string(),
            role: cpex::plugin::types::Role::User,
            content: vec![cpex::plugin::types::ContentPart::ToolCall(
                cpex::plugin::types::ToolCall {
                    tool_call_id: "tc-1".to_string(),
                    name: "get_employee_records".to_string(),
                    arguments: "{}".to_string(),
                    namespace: None,
                },
            )],
            channel: None,
        },
    };
    let extensions = make_pii_non_admin_extensions();
    let plugin_ctx = make_minimal_ctx();

    let result = plugin
        .call_handle_hook(&mut store, &payload, &extensions, &plugin_ctx)
        .await?;

    assert!(!result.continue_processing, "Expected Deny for PII access without hr_admin role, but got Allow");
    let v = result.violation.expect("Expected violation details");
    assert_eq!(v.code, "insufficient_role");
    assert!(v.reason.contains("hr_admin"));
    Ok(())
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
        resources: ResourceLimits::default(),
    };

    let ctx = build_wasi_context(&sandbox)?;
    let engine = create_engine()?;

    let mut store = Store::new(
        &engine,
        TestHostState {
            wasi: ctx.wasi_ctx,
            http: ctx.http_ctx,
            hooks: PolicyHttpHooks {
                allowed_hosts: ctx.allowed_hosts,
            },
            table: wasmtime::component::ResourceTable::new(),
        },
    );

    let mut linker = Linker::new(&engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;
    wasmtime_wasi_http::p2::add_only_http_to_linker_async(&mut linker)?;

    let component = Component::from_file(&engine, "plugin.wasm")?;
    let plugin = Plugin::instantiate_async(&mut store, &component, &linker).await?;

    let payload = make_minimal_payload();
    let extensions = make_minimal_extensions();
    let plugin_ctx = make_minimal_ctx();

    let result = plugin
        .call_handle_hook(&mut store, &payload, &extensions, &plugin_ctx)
        .await?;

    // The identity-checker plugin allows messages without PII+non-admin conditions
    assert!(
        result.continue_processing,
        "Expected Allow but got Deny: {:?}",
        result.violation
    );
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
        resources: ResourceLimits::default(),
    };

    let ctx = build_wasi_context(&sandbox)?;
    let engine = create_engine()?;

    let mut store = Store::new(
        &engine,
        TestHostState {
            wasi: ctx.wasi_ctx,
            http: ctx.http_ctx,
            hooks: PolicyHttpHooks {
                allowed_hosts: ctx.allowed_hosts,
            },
            table: wasmtime::component::ResourceTable::new(),
        },
    );

    let mut linker = Linker::new(&engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;
    wasmtime_wasi_http::p2::add_only_http_to_linker_async(&mut linker)?;

    let component = Component::from_file(&engine, "plugin.wasm")?;
    let plugin = Plugin::instantiate_async(&mut store, &component, &linker).await?;

    let payload = make_minimal_payload();
    let extensions = make_minimal_extensions();
    let plugin_ctx = make_minimal_ctx();

    // Plugin invocation should succeed (sandbox blocks env at WASI level, not plugin level)
    let result = plugin
        .call_handle_hook(&mut store, &payload, &extensions, &plugin_ctx)
        .await?;

    assert!(
        result.continue_processing,
        "Expected Allow but got Deny: {:?}",
        result.violation
    );
    Ok(())
}

// ============================================================
// FILESYSTEM TESTS
// ============================================================

#[tokio::test]
async fn test_allowed_filesystem_read_succeeds() -> Result<()> {
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
        resources: ResourceLimits::default(),
    };

    let ctx = build_wasi_context(&sandbox)?;
    let engine = create_engine()?;

    let mut store = Store::new(
        &engine,
        TestHostState {
            wasi: ctx.wasi_ctx,
            http: ctx.http_ctx,
            hooks: PolicyHttpHooks {
                allowed_hosts: ctx.allowed_hosts,
            },
            table: wasmtime::component::ResourceTable::new(),
        },
    );

    let mut linker = Linker::new(&engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;
    wasmtime_wasi_http::p2::add_only_http_to_linker_async(&mut linker)?;

    let component = Component::from_file(&engine, "plugin.wasm")?;
    let plugin = Plugin::instantiate_async(&mut store, &component, &linker).await?;

    let payload = make_minimal_payload();
    let extensions = make_minimal_extensions();
    let plugin_ctx = make_minimal_ctx();

    let result = plugin
        .call_handle_hook(&mut store, &payload, &extensions, &plugin_ctx)
        .await?;

    assert!(
        result.continue_processing,
        "Expected Allow but got Deny: {:?}",
        result.violation
    );

    std::fs::remove_dir_all(&tmp)?;
    Ok(())
}

#[tokio::test]
async fn test_disallowed_filesystem_read_is_denied() -> Result<()> {
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
        resources: ResourceLimits::default(),
    };

    let ctx = build_wasi_context(&sandbox)?;
    let engine = create_engine()?;

    let mut store = Store::new(
        &engine,
        TestHostState {
            wasi: ctx.wasi_ctx,
            http: ctx.http_ctx,
            hooks: PolicyHttpHooks {
                allowed_hosts: ctx.allowed_hosts,
            },
            table: wasmtime::component::ResourceTable::new(),
        },
    );

    let mut linker = Linker::new(&engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;
    wasmtime_wasi_http::p2::add_only_http_to_linker_async(&mut linker)?;

    let component = Component::from_file(&engine, "plugin.wasm")?;
    let plugin = Plugin::instantiate_async(&mut store, &component, &linker).await?;

    let payload = make_minimal_payload();
    let extensions = make_minimal_extensions();
    let plugin_ctx = make_minimal_ctx();

    let result = plugin
        .call_handle_hook(&mut store, &payload, &extensions, &plugin_ctx)
        .await?;

    assert!(
        result.continue_processing,
        "Expected Allow but got Deny: {:?}",
        result.violation
    );

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
        resources: ResourceLimits::default(),
    };

    let ctx = build_wasi_context(&sandbox)?;
    let engine = create_engine()?;

    let mut store = Store::new(
        &engine,
        TestHostState {
            wasi: ctx.wasi_ctx,
            http: ctx.http_ctx,
            hooks: PolicyHttpHooks {
                allowed_hosts: ctx.allowed_hosts,
            },
            table: wasmtime::component::ResourceTable::new(),
        },
    );

    let mut linker = Linker::new(&engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;
    wasmtime_wasi_http::p2::add_only_http_to_linker_async(&mut linker)?;

    let component = Component::from_file(&engine, "plugin.wasm")?;
    let plugin = Plugin::instantiate_async(&mut store, &component, &linker).await?;

    let payload = make_minimal_payload();
    let extensions = make_minimal_extensions();
    let plugin_ctx = make_minimal_ctx();

    let result = plugin
        .call_handle_hook(&mut store, &payload, &extensions, &plugin_ctx)
        .await?;

    assert!(
        result.continue_processing,
        "Expected Allow but got Deny: {:?}",
        result.violation
    );

    std::fs::remove_dir_all(&tmp)?;
    Ok(())
}

// ============================================================
// NETWORK TESTS (host-level wasi:http gating via PolicyHttpHooks)
// ============================================================

#[tokio::test]
async fn test_network_denied_when_no_allowed_hosts() -> Result<()> {
    let sandbox = SandboxConfig {
        version: "wasm-p2".to_string(),
        policy: PolicyConfig {
            allowed_env: vec![],
            allowed_filesystem: vec![],
            allowed_network: vec![],
        },
        resources: ResourceLimits::default(),
    };

    let ctx = build_wasi_context(&sandbox)?;
    let engine = create_engine()?;

    let mut store = Store::new(
        &engine,
        TestHostState {
            wasi: ctx.wasi_ctx,
            http: ctx.http_ctx,
            hooks: PolicyHttpHooks {
                allowed_hosts: ctx.allowed_hosts,
            },
            table: wasmtime::component::ResourceTable::new(),
        },
    );

    let mut linker = Linker::new(&engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;
    wasmtime_wasi_http::p2::add_only_http_to_linker_async(&mut linker)?;

    let component = Component::from_file(&engine, "plugin.wasm")?;
    let plugin = Plugin::instantiate_async(&mut store, &component, &linker).await?;

    let payload = make_minimal_payload();
    let extensions = make_minimal_extensions();
    let plugin_ctx = make_minimal_ctx();

    let result = plugin
        .call_handle_hook(&mut store, &payload, &extensions, &plugin_ctx)
        .await?;

    // Plugin itself allows (it's identity-checker with no PII), but network is gated at WASI level
    assert!(
        result.continue_processing,
        "Expected Allow but got Deny: {:?}",
        result.violation
    );
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
        resources: ResourceLimits::default(),
    };

    let ctx = build_wasi_context(&sandbox)?;
    let engine = create_engine()?;

    let mut store = Store::new(
        &engine,
        TestHostState {
            wasi: ctx.wasi_ctx,
            http: ctx.http_ctx,
            hooks: PolicyHttpHooks {
                allowed_hosts: ctx.allowed_hosts,
            },
            table: wasmtime::component::ResourceTable::new(),
        },
    );

    let mut linker = Linker::new(&engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;
    wasmtime_wasi_http::p2::add_only_http_to_linker_async(&mut linker)?;

    let component = Component::from_file(&engine, "plugin.wasm")?;
    let plugin = Plugin::instantiate_async(&mut store, &component, &linker).await?;

    let payload = make_minimal_payload();
    let extensions = make_minimal_extensions();
    let plugin_ctx = make_minimal_ctx();

    let result = plugin
        .call_handle_hook(&mut store, &payload, &extensions, &plugin_ctx)
        .await?;

    assert!(
        result.continue_processing,
        "Expected Allow but got Deny: {:?}",
        result.violation
    );
    Ok(())
}

// ============================================================
// NETWORK TESTS (PolicyHttpHooks — host-level wasi:http gating)
// ============================================================

#[test]
fn test_http_hooks_allowed_host_is_permitted() {
    let mut hooks = PolicyHttpHooks {
        allowed_hosts: Arc::new(vec![
            "httpbin.org".to_string(),
            "api.example.com".to_string(),
        ]),
    };

    let config = OutgoingRequestConfig {
        use_tls: false,
        connect_timeout: std::time::Duration::from_secs(5),
        first_byte_timeout: std::time::Duration::from_secs(5),
        between_bytes_timeout: std::time::Duration::from_secs(5),
    };

    let request = hyper::Request::builder()
        .uri("http://httpbin.org/get")
        .body(HyperOutgoingBody::default())
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
        .body(HyperOutgoingBody::default())
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
        .body(HyperOutgoingBody::default())
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
        .body(HyperOutgoingBody::default())
        .unwrap();

    assert!(hooks.send_request(request, config).is_err());
}
