use std::path::Path;

use anyhow::Result;
use cpex_wasm_host::policy_loader::{
    build_wasi_context, PolicyConfig, PolicyHttpHooks, ResourceLimits, SandboxConfig,
};
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};
use wasmtime_wasi_http::p2::{WasiHttpCtxView, WasiHttpView};
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
    table: ResourceTable,
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

fn default_sandbox() -> SandboxConfig {
    SandboxConfig {
        version: "wasm-p2".to_string(),
        policy: PolicyConfig {
            allowed_env: vec![],
            allowed_filesystem: vec![],
            allowed_network: vec![],
        },
        resources: ResourceLimits::default(),
    }
}

async fn instantiate_plugin(engine: &Engine, wasm_path: &Path, sandbox: &SandboxConfig) -> Result<(Store<TestHostState>, Plugin)> {
    let ctx = build_wasi_context(sandbox)?;

    let store = Store::new(
        engine,
        TestHostState {
            wasi: ctx.wasi_ctx,
            http: ctx.http_ctx,
            hooks: PolicyHttpHooks {
                allowed_hosts: ctx.allowed_hosts,
            },
            table: ResourceTable::new(),
        },
    );

    let mut linker = Linker::new(engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;
    wasmtime_wasi_http::p2::add_only_http_to_linker_async(&mut linker)?;

    let component = Component::from_file(engine, wasm_path)?;
    let mut store = store;
    let plugin = Plugin::instantiate_async(&mut store, &component, &linker).await?;

    Ok((store, plugin))
}

fn make_minimal_ctx() -> cpex::plugin::types::PluginContext {
    cpex::plugin::types::PluginContext {
        local_state: "{}".to_string(),
        global_state: "{}".to_string(),
    }
}

// ============================================================
// IDENTITY CHECKER TESTS
// ============================================================

/// PRE-INVOKE: allows a tool call when caller has hr_admin role (matches demo scenario)
#[tokio::test]
async fn identity_checker_allows_pii_with_hr_admin_role() -> Result<()> {
    let engine = create_engine()?;
    let (mut store, plugin) = instantiate_plugin(
        &engine,
        Path::new("wasm/identity_checker.wasm"),
        &default_sandbox(),
    ).await?;

    let payload = cpex::plugin::types::MessagePayload {
        message: cpex::plugin::types::Message {
            schema_version: "1.0".to_string(),
            role: cpex::plugin::types::Role::Assistant,
            content: vec![cpex::plugin::types::ContentPart::ToolCall(
                cpex::plugin::types::ToolCall {
                    tool_call_id: "tc_001".to_string(),
                    name: "get_compensation".to_string(),
                    arguments: r#"{"employee_id": 42}"#.to_string(),
                    namespace: None,
                },
            )],
            channel: None,
        },
    };

    let extensions = cpex::plugin::types::Extensions {
        request: None,
        security: Some(cpex::plugin::types::SecurityExtension {
            labels: vec!["PII".to_string(), "HR_DATA".to_string()],
            classification: Some("confidential".to_string()),
            subject: Some(cpex::plugin::types::SubjectExtension {
                id: Some("alice".to_string()),
                subject_type: Some(cpex::plugin::types::SubjectType::User),
                roles: vec!["hr_admin".to_string()],
                permissions: vec!["read_compensation".to_string()],
                teams: vec![],
                claims: vec![],
            }),
            auth_method: None,
        }),
        http: None,
        meta: None,
    };

    let result = plugin.call_handle_hook(&mut store, &payload, &extensions, &make_minimal_ctx()).await?;

    assert!(result.continue_processing, "Expected ALLOW for hr_admin accessing PII data");
    assert!(result.violation.is_none());
    Ok(())
}

/// PRE-INVOKE: denies tool call when PII label present but caller lacks hr_admin role
#[tokio::test]
async fn identity_checker_denies_pii_without_hr_admin_role() -> Result<()> {
    let engine = create_engine()?;
    let (mut store, plugin) = instantiate_plugin(
        &engine,
        Path::new("wasm/identity_checker.wasm"),
        &default_sandbox(),
    ).await?;

    let payload = cpex::plugin::types::MessagePayload {
        message: cpex::plugin::types::Message {
            schema_version: "1.0".to_string(),
            role: cpex::plugin::types::Role::Assistant,
            content: vec![cpex::plugin::types::ContentPart::ToolCall(
                cpex::plugin::types::ToolCall {
                    tool_call_id: "tc_001".to_string(),
                    name: "get_compensation".to_string(),
                    arguments: r#"{"employee_id": 42}"#.to_string(),
                    namespace: None,
                },
            )],
            channel: None,
        },
    };

    let extensions = cpex::plugin::types::Extensions {
        request: None,
        security: Some(cpex::plugin::types::SecurityExtension {
            labels: vec!["PII".to_string()],
            classification: None,
            subject: Some(cpex::plugin::types::SubjectExtension {
                id: Some("bob".to_string()),
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
    };

    let result = plugin.call_handle_hook(&mut store, &payload, &extensions, &make_minimal_ctx()).await?;

    assert!(!result.continue_processing, "Expected DENY for non-hr_admin accessing PII data");
    let violation = result.violation.expect("Expected violation details");
    assert_eq!(violation.code, "insufficient_role");
    assert!(violation.reason.contains("hr_admin"));
    assert!(violation.reason.contains("get_compensation"));
    Ok(())
}

/// PRE-INVOKE: allows when no security extension is present (no PII check triggered)
#[tokio::test]
async fn identity_checker_allows_without_security_extension() -> Result<()> {
    let engine = create_engine()?;
    let (mut store, plugin) = instantiate_plugin(
        &engine,
        Path::new("wasm/identity_checker.wasm"),
        &default_sandbox(),
    ).await?;

    let payload = cpex::plugin::types::MessagePayload {
        message: cpex::plugin::types::Message {
            schema_version: "1.0".to_string(),
            role: cpex::plugin::types::Role::Assistant,
            content: vec![cpex::plugin::types::ContentPart::ToolCall(
                cpex::plugin::types::ToolCall {
                    tool_call_id: "tc_001".to_string(),
                    name: "get_compensation".to_string(),
                    arguments: "{}".to_string(),
                    namespace: None,
                },
            )],
            channel: None,
        },
    };

    let extensions = cpex::plugin::types::Extensions {
        request: None,
        security: None,
        http: None,
        meta: None,
    };

    let result = plugin.call_handle_hook(&mut store, &payload, &extensions, &make_minimal_ctx()).await?;

    assert!(result.continue_processing, "Expected ALLOW when no security extension present");
    Ok(())
}

/// POST-INVOKE: allows tool result verification (identity checker always allows post-invoke)
#[tokio::test]
async fn identity_checker_allows_post_invoke_tool_result() -> Result<()> {
    let engine = create_engine()?;
    let (mut store, plugin) = instantiate_plugin(
        &engine,
        Path::new("wasm/identity_checker.wasm"),
        &default_sandbox(),
    ).await?;

    let payload = cpex::plugin::types::MessagePayload {
        message: cpex::plugin::types::Message {
            schema_version: "1.0".to_string(),
            role: cpex::plugin::types::Role::Tool,
            content: vec![cpex::plugin::types::ContentPart::ToolResult(
                cpex::plugin::types::ToolResult {
                    tool_call_id: "tc_001".to_string(),
                    tool_name: "get_compensation".to_string(),
                    content: r#"{"salary": 150000, "currency": "USD"}"#.to_string(),
                    is_error: false,
                },
            )],
            channel: None,
        },
    };

    let extensions = cpex::plugin::types::Extensions {
        request: None,
        security: Some(cpex::plugin::types::SecurityExtension {
            labels: vec!["PII".to_string()],
            classification: None,
            subject: Some(cpex::plugin::types::SubjectExtension {
                id: Some("alice".to_string()),
                subject_type: Some(cpex::plugin::types::SubjectType::User),
                roles: vec!["hr_admin".to_string()],
                permissions: vec![],
                teams: vec![],
                claims: vec![],
            }),
            auth_method: None,
        }),
        http: None,
        meta: None,
    };

    let result = plugin.call_handle_hook(&mut store, &payload, &extensions, &make_minimal_ctx()).await?;

    assert!(result.continue_processing, "Expected ALLOW for post-invoke tool result");
    Ok(())
}

/// PRE-INVOKE: allows when PII label is present but no subject (no role to check against)
#[tokio::test]
async fn identity_checker_allows_pii_without_subject() -> Result<()> {
    let engine = create_engine()?;
    let (mut store, plugin) = instantiate_plugin(
        &engine,
        Path::new("wasm/identity_checker.wasm"),
        &default_sandbox(),
    ).await?;

    let payload = cpex::plugin::types::MessagePayload {
        message: cpex::plugin::types::Message {
            schema_version: "1.0".to_string(),
            role: cpex::plugin::types::Role::Assistant,
            content: vec![cpex::plugin::types::ContentPart::ToolCall(
                cpex::plugin::types::ToolCall {
                    tool_call_id: "tc_001".to_string(),
                    name: "get_employee_records".to_string(),
                    arguments: "{}".to_string(),
                    namespace: None,
                },
            )],
            channel: None,
        },
    };

    let extensions = cpex::plugin::types::Extensions {
        request: None,
        security: Some(cpex::plugin::types::SecurityExtension {
            labels: vec!["PII".to_string()],
            classification: None,
            subject: None,
            auth_method: None,
        }),
        http: None,
        meta: None,
    };

    let result = plugin.call_handle_hook(&mut store, &payload, &extensions, &make_minimal_ctx()).await?;

    assert!(result.continue_processing, "Expected ALLOW when PII present but no subject to evaluate");
    Ok(())
}

/// PRE-INVOKE: denies plain text message when PII label + non-admin subject present
/// (identity checker evaluates PII/role check on any non-tool-result message)
#[tokio::test]
async fn identity_checker_denies_plain_text_with_pii_non_admin() -> Result<()> {
    let engine = create_engine()?;
    let (mut store, plugin) = instantiate_plugin(
        &engine,
        Path::new("wasm/identity_checker.wasm"),
        &default_sandbox(),
    ).await?;

    let payload = cpex::plugin::types::MessagePayload {
        message: cpex::plugin::types::Message {
            schema_version: "1.0".to_string(),
            role: cpex::plugin::types::Role::User,
            content: vec![cpex::plugin::types::ContentPart::Text(
                "Hello, just chatting".to_string(),
            )],
            channel: None,
        },
    };

    let extensions = cpex::plugin::types::Extensions {
        request: None,
        security: Some(cpex::plugin::types::SecurityExtension {
            labels: vec!["PII".to_string()],
            classification: None,
            subject: Some(cpex::plugin::types::SubjectExtension {
                id: Some("bob".to_string()),
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
    };

    let result = plugin.call_handle_hook(&mut store, &payload, &extensions, &make_minimal_ctx()).await?;

    assert!(!result.continue_processing, "Expected DENY: PII label + non-hr_admin triggers role check on all non-result messages");
    let violation = result.violation.expect("Expected violation");
    assert_eq!(violation.code, "insufficient_role");
    Ok(())
}

/// PRE-INVOKE: allows plain text message without PII label
#[tokio::test]
async fn identity_checker_allows_plain_text_without_pii() -> Result<()> {
    let engine = create_engine()?;
    let (mut store, plugin) = instantiate_plugin(
        &engine,
        Path::new("wasm/identity_checker.wasm"),
        &default_sandbox(),
    ).await?;

    let payload = cpex::plugin::types::MessagePayload {
        message: cpex::plugin::types::Message {
            schema_version: "1.0".to_string(),
            role: cpex::plugin::types::Role::User,
            content: vec![cpex::plugin::types::ContentPart::Text(
                "Hello, just chatting".to_string(),
            )],
            channel: None,
        },
    };

    let extensions = cpex::plugin::types::Extensions {
        request: None,
        security: Some(cpex::plugin::types::SecurityExtension {
            labels: vec!["INTERNAL".to_string()],
            classification: None,
            subject: Some(cpex::plugin::types::SubjectExtension {
                id: Some("bob".to_string()),
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
    };

    let result = plugin.call_handle_hook(&mut store, &payload, &extensions, &make_minimal_ctx()).await?;

    assert!(result.continue_processing, "Expected ALLOW: no PII label means no role check");
    Ok(())
}

// ============================================================
// AUDIT LOGGER TESTS
// ============================================================

/// PRE-INVOKE: audit logger always allows, just logs (read-only plugin)
#[tokio::test]
async fn audit_logger_allows_pre_invoke_tool_call() -> Result<()> {
    let engine = create_engine()?;
    let (mut store, plugin) = instantiate_plugin(
        &engine,
        Path::new("wasm/audit_logger.wasm"),
        &default_sandbox(),
    ).await?;

    let payload = cpex::plugin::types::MessagePayload {
        message: cpex::plugin::types::Message {
            schema_version: "1.0".to_string(),
            role: cpex::plugin::types::Role::Assistant,
            content: vec![cpex::plugin::types::ContentPart::ToolCall(
                cpex::plugin::types::ToolCall {
                    tool_call_id: "tc_001".to_string(),
                    name: "get_compensation".to_string(),
                    arguments: r#"{"employee_id": 42}"#.to_string(),
                    namespace: None,
                },
            )],
            channel: None,
        },
    };

    let extensions = cpex::plugin::types::Extensions {
        request: None,
        security: Some(cpex::plugin::types::SecurityExtension {
            labels: vec!["PII".to_string(), "HR_DATA".to_string()],
            classification: Some("confidential".to_string()),
            subject: None,
            auth_method: None,
        }),
        http: Some(cpex::plugin::types::HttpExtension {
            request_headers: vec![
                ("X-Request-ID".to_string(), "req-abc-123".to_string()),
                ("Authorization".to_string(), "Bearer eyJ...".to_string()),
            ],
            response_headers: vec![],
        }),
        meta: Some(cpex::plugin::types::MetaExtension {
            entity_type: Some("tool".to_string()),
            entity_name: Some("get_compensation".to_string()),
            tags: vec!["pii".to_string(), "hr".to_string()],
            scope: None,
            properties: vec![],
        }),
    };

    let result = plugin.call_handle_hook(&mut store, &payload, &extensions, &make_minimal_ctx()).await?;

    assert!(result.continue_processing, "Audit logger should always ALLOW");
    assert!(result.violation.is_none());
    Ok(())
}

/// POST-INVOKE: audit logger allows tool result with error flag
#[tokio::test]
async fn audit_logger_allows_post_invoke_with_error() -> Result<()> {
    let engine = create_engine()?;
    let (mut store, plugin) = instantiate_plugin(
        &engine,
        Path::new("wasm/audit_logger.wasm"),
        &default_sandbox(),
    ).await?;

    let payload = cpex::plugin::types::MessagePayload {
        message: cpex::plugin::types::Message {
            schema_version: "1.0".to_string(),
            role: cpex::plugin::types::Role::Tool,
            content: vec![cpex::plugin::types::ContentPart::ToolResult(
                cpex::plugin::types::ToolResult {
                    tool_call_id: "tc_001".to_string(),
                    tool_name: "get_compensation".to_string(),
                    content: r#"{"error": "permission denied"}"#.to_string(),
                    is_error: true,
                },
            )],
            channel: None,
        },
    };

    let extensions = cpex::plugin::types::Extensions {
        request: None,
        security: Some(cpex::plugin::types::SecurityExtension {
            labels: vec!["PII".to_string()],
            classification: None,
            subject: None,
            auth_method: None,
        }),
        http: Some(cpex::plugin::types::HttpExtension {
            request_headers: vec![
                ("X-Request-ID".to_string(), "req-xyz-789".to_string()),
            ],
            response_headers: vec![],
        }),
        meta: None,
    };

    let result = plugin.call_handle_hook(&mut store, &payload, &extensions, &make_minimal_ctx()).await?;

    assert!(result.continue_processing, "Audit logger should always ALLOW even on tool errors");
    assert!(result.violation.is_none());
    Ok(())
}

/// PRE-INVOKE: audit logger allows with minimal extensions (no security, no http)
#[tokio::test]
async fn audit_logger_allows_with_no_extensions() -> Result<()> {
    let engine = create_engine()?;
    let (mut store, plugin) = instantiate_plugin(
        &engine,
        Path::new("wasm/audit_logger.wasm"),
        &default_sandbox(),
    ).await?;

    let payload = cpex::plugin::types::MessagePayload {
        message: cpex::plugin::types::Message {
            schema_version: "1.0".to_string(),
            role: cpex::plugin::types::Role::Assistant,
            content: vec![cpex::plugin::types::ContentPart::ToolCall(
                cpex::plugin::types::ToolCall {
                    tool_call_id: "tc_002".to_string(),
                    name: "list_users".to_string(),
                    arguments: "{}".to_string(),
                    namespace: None,
                },
            )],
            channel: None,
        },
    };

    let extensions = cpex::plugin::types::Extensions {
        request: None,
        security: None,
        http: None,
        meta: None,
    };

    let result = plugin.call_handle_hook(&mut store, &payload, &extensions, &make_minimal_ctx()).await?;

    assert!(result.continue_processing, "Audit logger should ALLOW with no extensions");
    Ok(())
}

// ============================================================
// HEADER INJECTOR TESTS
// ============================================================

/// PRE-INVOKE: header injector returns modified extensions (COW copy without write tokens
/// means label/header injection is skipped, but extensions are still returned via modify_extensions)
#[tokio::test]
async fn header_injector_returns_modified_extensions() -> Result<()> {
    let engine = create_engine()?;
    let (mut store, plugin) = instantiate_plugin(
        &engine,
        Path::new("wasm/header_injector.wasm"),
        &default_sandbox(),
    ).await?;

    let payload = cpex::plugin::types::MessagePayload {
        message: cpex::plugin::types::Message {
            schema_version: "1.0".to_string(),
            role: cpex::plugin::types::Role::Assistant,
            content: vec![cpex::plugin::types::ContentPart::ToolCall(
                cpex::plugin::types::ToolCall {
                    tool_call_id: "tc_001".to_string(),
                    name: "get_compensation".to_string(),
                    arguments: r#"{"employee_id": 42}"#.to_string(),
                    namespace: None,
                },
            )],
            channel: None,
        },
    };

    let extensions = cpex::plugin::types::Extensions {
        request: None,
        security: Some(cpex::plugin::types::SecurityExtension {
            labels: vec!["PII".to_string()],
            classification: None,
            subject: None,
            auth_method: None,
        }),
        http: Some(cpex::plugin::types::HttpExtension {
            request_headers: vec![
                ("Authorization".to_string(), "Bearer eyJ...".to_string()),
                ("X-Request-ID".to_string(), "req-abc-123".to_string()),
            ],
            response_headers: vec![],
        }),
        meta: None,
    };

    let result = plugin.call_handle_hook(&mut store, &payload, &extensions, &make_minimal_ctx()).await?;

    assert!(result.continue_processing, "Header injector should ALLOW");

    // Header injector always calls PluginResult::modify_extensions with a COW copy.
    // Without write tokens (not provided via WASM boundary), label addition and header
    // injection are gated — the COW copy is returned but without those modifications.
    let modified_ext = result.modified_extensions.expect("Expected modified extensions from header injector");

    // Original security labels should be preserved in the COW copy
    let security = modified_ext.security.expect("Expected security extension in modified output");
    assert!(
        security.labels.contains(&"PII".to_string()),
        "Original 'PII' label should be preserved in COW copy"
    );

    // Original HTTP headers should be preserved
    let http = modified_ext.http.expect("Expected http extension in modified output");
    assert!(
        http.request_headers.iter().any(|(k, _)| k == "Authorization"),
        "Original headers should be preserved"
    );

    Ok(())
}

/// PRE-INVOKE: header injector with no http extension still works
#[tokio::test]
async fn header_injector_handles_missing_http_extension() -> Result<()> {
    let engine = create_engine()?;
    let (mut store, plugin) = instantiate_plugin(
        &engine,
        Path::new("wasm/header_injector.wasm"),
        &default_sandbox(),
    ).await?;

    let payload = cpex::plugin::types::MessagePayload {
        message: cpex::plugin::types::Message {
            schema_version: "1.0".to_string(),
            role: cpex::plugin::types::Role::Assistant,
            content: vec![cpex::plugin::types::ContentPart::ToolCall(
                cpex::plugin::types::ToolCall {
                    tool_call_id: "tc_001".to_string(),
                    name: "some_tool".to_string(),
                    arguments: "{}".to_string(),
                    namespace: None,
                },
            )],
            channel: None,
        },
    };

    let extensions = cpex::plugin::types::Extensions {
        request: None,
        security: None,
        http: None,
        meta: None,
    };

    let result = plugin.call_handle_hook(&mut store, &payload, &extensions, &make_minimal_ctx()).await?;

    assert!(result.continue_processing, "Header injector should ALLOW even without http extension");
    Ok(())
}

// ============================================================
// MULTI-PLUGIN PIPELINE TESTS (mirroring demo flow)
// ============================================================

/// Full pipeline: identity-checker → header-injector → audit-logger (pre-invoke)
/// Mirrors the CMF capabilities demo: authorized caller with PII data
#[tokio::test]
async fn pipeline_pre_invoke_authorized_caller() -> Result<()> {
    let engine = create_engine()?;
    let sandbox = default_sandbox();

    let (mut ic_store, ic_plugin) = instantiate_plugin(
        &engine,
        Path::new("wasm/identity_checker.wasm"),
        &sandbox,
    ).await?;

    let (mut hi_store, hi_plugin) = instantiate_plugin(
        &engine,
        Path::new("wasm/header_injector.wasm"),
        &sandbox,
    ).await?;

    let (mut al_store, al_plugin) = instantiate_plugin(
        &engine,
        Path::new("wasm/audit_logger.wasm"),
        &sandbox,
    ).await?;

    let payload = cpex::plugin::types::MessagePayload {
        message: cpex::plugin::types::Message {
            schema_version: "1.0".to_string(),
            role: cpex::plugin::types::Role::Assistant,
            content: vec![
                cpex::plugin::types::ContentPart::Text("Looking up compensation.".to_string()),
                cpex::plugin::types::ContentPart::ToolCall(
                    cpex::plugin::types::ToolCall {
                        tool_call_id: "tc_001".to_string(),
                        name: "get_compensation".to_string(),
                        arguments: r#"{"employee_id": 42}"#.to_string(),
                        namespace: None,
                    },
                ),
            ],
            channel: None,
        },
    };

    let extensions = cpex::plugin::types::Extensions {
        request: Some(cpex::plugin::types::RequestExtension {
            environment: Some("production".to_string()),
            request_id: Some("req-abc-123".to_string()),
            timestamp: None,
            trace_id: None,
            span_id: None,
        }),
        security: Some(cpex::plugin::types::SecurityExtension {
            labels: vec!["PII".to_string(), "HR_DATA".to_string()],
            classification: Some("confidential".to_string()),
            subject: Some(cpex::plugin::types::SubjectExtension {
                id: Some("alice".to_string()),
                subject_type: Some(cpex::plugin::types::SubjectType::User),
                roles: vec!["hr_admin".to_string()],
                permissions: vec!["read_compensation".to_string()],
                teams: vec![],
                claims: vec![],
            }),
            auth_method: None,
        }),
        http: Some(cpex::plugin::types::HttpExtension {
            request_headers: vec![
                ("Authorization".to_string(), "Bearer eyJ...".to_string()),
                ("X-Request-ID".to_string(), "req-abc-123".to_string()),
            ],
            response_headers: vec![],
        }),
        meta: Some(cpex::plugin::types::MetaExtension {
            entity_type: Some("tool".to_string()),
            entity_name: Some("get_compensation".to_string()),
            tags: vec!["pii".to_string(), "hr".to_string()],
            scope: None,
            properties: vec![],
        }),
    };

    let ctx = make_minimal_ctx();

    // Step 1: Identity checker — should ALLOW (alice has hr_admin)
    let ic_result = ic_plugin.call_handle_hook(&mut ic_store, &payload, &extensions, &ctx).await?;
    assert!(ic_result.continue_processing, "Identity checker should ALLOW authorized caller");

    // Step 2: Header injector — should return modified extensions (COW copy)
    let hi_result = hi_plugin.call_handle_hook(&mut hi_store, &payload, &extensions, &ctx).await?;
    assert!(hi_result.continue_processing, "Header injector should ALLOW");
    let modified_ext = hi_result.modified_extensions.expect("Header injector should produce modified extensions");

    // COW copy preserves original data; write-token-gated modifications are skipped in WASM
    let sec = modified_ext.security.as_ref().expect("Security should be present");
    assert!(sec.labels.contains(&"PII".to_string()), "Original PII label preserved");
    assert!(sec.labels.contains(&"HR_DATA".to_string()), "Original HR_DATA label preserved");

    let http = modified_ext.http.as_ref().expect("HTTP should be present");
    assert!(http.request_headers.iter().any(|(k, _)| k == "Authorization"), "Original headers preserved");

    // Step 3: Audit logger — should ALLOW (read-only)
    let al_result = al_plugin.call_handle_hook(&mut al_store, &payload, &extensions, &ctx).await?;
    assert!(al_result.continue_processing, "Audit logger should ALLOW");

    Ok(())
}

/// Full pipeline: identity-checker denies unauthorized caller, stops pipeline
#[tokio::test]
async fn pipeline_pre_invoke_unauthorized_caller_stops_at_identity_checker() -> Result<()> {
    let engine = create_engine()?;
    let sandbox = default_sandbox();

    let (mut ic_store, ic_plugin) = instantiate_plugin(
        &engine,
        Path::new("wasm/identity_checker.wasm"),
        &sandbox,
    ).await?;

    let payload = cpex::plugin::types::MessagePayload {
        message: cpex::plugin::types::Message {
            schema_version: "1.0".to_string(),
            role: cpex::plugin::types::Role::Assistant,
            content: vec![cpex::plugin::types::ContentPart::ToolCall(
                cpex::plugin::types::ToolCall {
                    tool_call_id: "tc_001".to_string(),
                    name: "get_compensation".to_string(),
                    arguments: r#"{"employee_id": 42}"#.to_string(),
                    namespace: None,
                },
            )],
            channel: None,
        },
    };

    let extensions = cpex::plugin::types::Extensions {
        request: None,
        security: Some(cpex::plugin::types::SecurityExtension {
            labels: vec!["PII".to_string(), "HR_DATA".to_string()],
            classification: Some("confidential".to_string()),
            subject: Some(cpex::plugin::types::SubjectExtension {
                id: Some("mallory".to_string()),
                subject_type: Some(cpex::plugin::types::SubjectType::User),
                roles: vec!["intern".to_string()],
                permissions: vec![],
                teams: vec![],
                claims: vec![],
            }),
            auth_method: None,
        }),
        http: Some(cpex::plugin::types::HttpExtension {
            request_headers: vec![
                ("Authorization".to_string(), "Bearer stolen-token".to_string()),
            ],
            response_headers: vec![],
        }),
        meta: None,
    };

    let ctx = make_minimal_ctx();

    // Identity checker should DENY
    let ic_result = ic_plugin.call_handle_hook(&mut ic_store, &payload, &extensions, &ctx).await?;
    assert!(!ic_result.continue_processing, "Identity checker should DENY unauthorized caller");
    let violation = ic_result.violation.expect("Should have violation");
    assert_eq!(violation.code, "insufficient_role");
    assert!(violation.reason.contains("hr_admin"));

    // In real pipeline, remaining plugins would NOT be invoked after deny
    Ok(())
}

/// POST-INVOKE pipeline: identity-checker verifies result, audit-logger logs
#[tokio::test]
async fn pipeline_post_invoke_tool_result() -> Result<()> {
    let engine = create_engine()?;
    let sandbox = default_sandbox();

    let (mut ic_store, ic_plugin) = instantiate_plugin(
        &engine,
        Path::new("wasm/identity_checker.wasm"),
        &sandbox,
    ).await?;

    let (mut al_store, al_plugin) = instantiate_plugin(
        &engine,
        Path::new("wasm/audit_logger.wasm"),
        &sandbox,
    ).await?;

    let payload = cpex::plugin::types::MessagePayload {
        message: cpex::plugin::types::Message {
            schema_version: "1.0".to_string(),
            role: cpex::plugin::types::Role::Tool,
            content: vec![cpex::plugin::types::ContentPart::ToolResult(
                cpex::plugin::types::ToolResult {
                    tool_call_id: "tc_001".to_string(),
                    tool_name: "get_compensation".to_string(),
                    content: r#"{"salary": 150000, "currency": "USD"}"#.to_string(),
                    is_error: false,
                },
            )],
            channel: None,
        },
    };

    let extensions = cpex::plugin::types::Extensions {
        request: None,
        security: Some(cpex::plugin::types::SecurityExtension {
            labels: vec!["PII".to_string(), "HR_DATA".to_string(), "PROCESSED".to_string()],
            classification: Some("confidential".to_string()),
            subject: Some(cpex::plugin::types::SubjectExtension {
                id: Some("alice".to_string()),
                subject_type: Some(cpex::plugin::types::SubjectType::User),
                roles: vec!["hr_admin".to_string()],
                permissions: vec![],
                teams: vec![],
                claims: vec![],
            }),
            auth_method: None,
        }),
        http: Some(cpex::plugin::types::HttpExtension {
            request_headers: vec![
                ("X-Request-ID".to_string(), "req-abc-123".to_string()),
                ("X-Processed-By".to_string(), "header-injector".to_string()),
            ],
            response_headers: vec![],
        }),
        meta: Some(cpex::plugin::types::MetaExtension {
            entity_type: Some("tool".to_string()),
            entity_name: Some("get_compensation".to_string()),
            tags: vec![],
            scope: None,
            properties: vec![],
        }),
    };

    let ctx = make_minimal_ctx();

    // Step 1: Identity checker post-invoke — always allows
    let ic_result = ic_plugin.call_handle_hook(&mut ic_store, &payload, &extensions, &ctx).await?;
    assert!(ic_result.continue_processing, "Identity checker post-invoke should ALLOW");

    // Step 2: Audit logger post-invoke — always allows (read-only)
    let al_result = al_plugin.call_handle_hook(&mut al_store, &payload, &extensions, &ctx).await?;
    assert!(al_result.continue_processing, "Audit logger post-invoke should ALLOW");

    Ok(())
}

// ============================================================
// SANDBOX MANAGER INTEGRATION TESTS
// ============================================================

/// Test loading multiple plugins via SandboxManager and invoking them
#[tokio::test]
async fn sandbox_manager_loads_and_invokes_multiple_plugins() -> Result<()> {
    use cpex_wasm_host::sandbox_manager::SandboxManager;

    let mut manager = SandboxManager::new()?;

    let sandbox = default_sandbox();
    manager.load_plugin("identity-checker", Path::new("wasm/identity_checker.wasm"), sandbox.clone()).await?;
    manager.load_plugin("audit-logger", Path::new("wasm/audit_logger.wasm"), sandbox.clone()).await?;
    manager.load_plugin("header-injector", Path::new("wasm/header_injector.wasm"), sandbox).await?;

    let loaded = manager.list_plugins();
    assert!(loaded.contains(&"identity-checker"));
    assert!(loaded.contains(&"audit-logger"));
    assert!(loaded.contains(&"header-injector"));

    let payload = cpex_wasm_host::sandbox_manager::types::MessagePayload {
        message: cpex_wasm_host::sandbox_manager::types::Message {
            schema_version: "1.0".to_string(),
            role: cpex_wasm_host::sandbox_manager::types::Role::Assistant,
            content: vec![cpex_wasm_host::sandbox_manager::types::ContentPart::ToolCall(
                cpex_wasm_host::sandbox_manager::types::ToolCall {
                    tool_call_id: "tc_001".to_string(),
                    name: "get_compensation".to_string(),
                    arguments: r#"{"employee_id": 42}"#.to_string(),
                    namespace: None,
                },
            )],
            channel: None,
        },
    };

    let extensions = cpex_wasm_host::sandbox_manager::types::Extensions {
        request: None,
        security: Some(cpex_wasm_host::sandbox_manager::types::SecurityExtension {
            labels: vec!["PII".to_string()],
            classification: None,
            subject: Some(cpex_wasm_host::sandbox_manager::types::SubjectExtension {
                id: Some("alice".to_string()),
                subject_type: Some(cpex_wasm_host::sandbox_manager::types::SubjectType::User),
                roles: vec!["hr_admin".to_string()],
                permissions: vec![],
                teams: vec![],
                claims: vec![],
            }),
            auth_method: None,
        }),
        http: Some(cpex_wasm_host::sandbox_manager::types::HttpExtension {
            request_headers: vec![("X-Request-ID".to_string(), "req-123".to_string())],
            response_headers: vec![],
        }),
        meta: None,
    };

    let ctx = cpex_wasm_host::sandbox_manager::types::PluginContext {
        local_state: "{}".to_string(),
        global_state: "{}".to_string(),
    };

    // Invoke each plugin — all should succeed
    let ic_result = manager.invoke("identity-checker", payload.clone(), extensions.clone(), ctx.clone()).await?;
    assert!(ic_result.continue_processing, "identity-checker should ALLOW hr_admin");

    let hi_result = manager.invoke("header-injector", payload.clone(), extensions.clone(), ctx.clone()).await?;
    assert!(hi_result.continue_processing, "header-injector should ALLOW");

    let al_result = manager.invoke("audit-logger", payload, extensions, ctx).await?;
    assert!(al_result.continue_processing, "audit-logger should ALLOW");

    Ok(())
}

/// Test that SandboxManager metrics track invocations
#[tokio::test]
async fn sandbox_manager_tracks_metrics() -> Result<()> {
    use cpex_wasm_host::sandbox_manager::SandboxManager;

    let mut manager = SandboxManager::new()?;
    manager.load_plugin("identity-checker", Path::new("wasm/identity_checker.wasm"), default_sandbox()).await?;

    let payload = cpex_wasm_host::sandbox_manager::types::MessagePayload {
        message: cpex_wasm_host::sandbox_manager::types::Message {
            schema_version: "1.0".to_string(),
            role: cpex_wasm_host::sandbox_manager::types::Role::User,
            content: vec![cpex_wasm_host::sandbox_manager::types::ContentPart::Text(
                "test".to_string(),
            )],
            channel: None,
        },
    };

    let extensions = cpex_wasm_host::sandbox_manager::types::Extensions {
        request: None,
        security: None,
        http: None,
        meta: None,
    };

    let ctx = cpex_wasm_host::sandbox_manager::types::PluginContext {
        local_state: "{}".to_string(),
        global_state: "{}".to_string(),
    };

    // Invoke twice
    manager.invoke("identity-checker", payload.clone(), extensions.clone(), ctx.clone()).await?;
    manager.invoke("identity-checker", payload, extensions, ctx).await?;

    let metrics = manager.metrics("identity-checker").expect("Metrics should exist");
    assert_eq!(metrics.total_invocations, 2);
    assert_eq!(metrics.total_traps, 0);
    assert!(metrics.total_fuel_consumed > 0, "Should have consumed some fuel");

    Ok(())
}

/// Test unloading a plugin
#[tokio::test]
async fn sandbox_manager_unload_plugin() -> Result<()> {
    use cpex_wasm_host::sandbox_manager::SandboxManager;

    let mut manager = SandboxManager::new()?;
    manager.load_plugin("identity-checker", Path::new("wasm/identity_checker.wasm"), default_sandbox()).await?;

    assert!(manager.list_plugins().contains(&"identity-checker"));

    manager.unload_plugin("identity-checker")?;

    assert!(!manager.list_plugins().contains(&"identity-checker"));

    // Invoking after unload should fail
    let payload = cpex_wasm_host::sandbox_manager::types::MessagePayload {
        message: cpex_wasm_host::sandbox_manager::types::Message {
            schema_version: "1.0".to_string(),
            role: cpex_wasm_host::sandbox_manager::types::Role::User,
            content: vec![cpex_wasm_host::sandbox_manager::types::ContentPart::Text("test".to_string())],
            channel: None,
        },
    };
    let extensions = cpex_wasm_host::sandbox_manager::types::Extensions {
        request: None, security: None, http: None, meta: None,
    };
    let ctx = cpex_wasm_host::sandbox_manager::types::PluginContext {
        local_state: "{}".to_string(),
        global_state: "{}".to_string(),
    };

    let result = manager.invoke("identity-checker", payload, extensions, ctx).await;
    assert!(result.is_err(), "Invoking unloaded plugin should fail");

    Ok(())
}

/// Test loading plugins from config file
#[tokio::test]
async fn sandbox_manager_load_from_config() -> Result<()> {
    use cpex_wasm_host::sandbox_manager::SandboxManager;

    let mut manager = SandboxManager::new()?;
    manager.load_from_config(Path::new("config/config.yaml"), Path::new("wasm")).await?;

    let plugins = manager.list_plugins();
    assert!(plugins.contains(&"identity-checker"), "identity-checker should be loaded from config");
    assert!(plugins.contains(&"audit-logger"), "audit-logger should be loaded from config");

    Ok(())
}
