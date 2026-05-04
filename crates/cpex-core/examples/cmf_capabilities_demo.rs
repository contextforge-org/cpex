// CMF Capabilities Demo
//
// Demonstrates:
//   1. CMF Message with typed content parts (tool call)
//   2. Extensions with security, HTTP, and meta populated
//   3. Config-driven capability gating — plugins only see what they declare
//   4. COW copy for extension modification with write tokens
//   5. MonotonicSet labels (add-only, no remove)
//   6. Guarded HTTP headers (read free, write needs token)
//
// Run with: cargo run --example cmf_capabilities_demo

use std::sync::Arc;

use async_trait::async_trait;
use cpex_core::cmf::{ContentPart, CmfHook, Message, MessagePayload, Role, ToolCall};
use cpex_core::context::PluginContext;
use cpex_core::error::{PluginError, PluginViolation};
use cpex_core::extensions::{
    HttpExtension, RequestExtension, SecurityExtension,
};
use cpex_core::factory::{PluginFactory, PluginInstance};
use cpex_core::hooks::adapter::TypedHandlerAdapter;
use cpex_core::hooks::payload::{Extensions, MetaExtension};
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::manager::PluginManager;
use cpex_core::plugin::{Plugin, PluginConfig};

// ---------------------------------------------------------------------------
// Plugin: IdentityChecker
// Has read_security, read_labels, read_subject, read_roles capabilities.
// Checks if the caller has the required role.
// ---------------------------------------------------------------------------

struct IdentityChecker {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for IdentityChecker {
    fn config(&self) -> &PluginConfig { &self.cfg }
}

impl HookHandler<CmfHook> for IdentityChecker {
    fn handle(
        &self,
        payload: &MessagePayload,
        extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        // Determine if this is pre or post invoke based on message content
        let is_result = payload.message.is_tool_result();

        if is_result {
            // POST-INVOKE: verify the tool result came from an authorized call
            let tool_name = payload.message.get_tool_results()
                .first()
                .map(|tr| tr.tool_name.as_str())
                .unwrap_or("unknown");
            println!("  [identity-checker] POST-INVOKE: verifying result from '{}'", tool_name);

            if let Some(ref security) = extensions.security {
                if let Some(ref subject) = security.subject {
                    println!("  [identity-checker] Result authorized for subject: {:?}", subject.id);
                }
            }
            println!("  [identity-checker] POST-INVOKE ALLOWED");
        } else {
            // PRE-INVOKE: check caller identity and roles
            let tool_name = payload.message.get_tool_calls()
                .first()
                .map(|tc| tc.name.as_str())
                .unwrap_or("unknown");
            println!("  [identity-checker] PRE-INVOKE: checking identity for '{}'", tool_name);

            if let Some(ref security) = extensions.security {
                let labels: Vec<&String> = security.labels.iter().collect();
                println!("  [identity-checker] Security labels: {:?}", labels);

                if let Some(ref subject) = security.subject {
                    println!("  [identity-checker] Subject: {:?}, Roles: {:?}",
                        subject.id, subject.roles.iter().collect::<Vec<_>>());

                    if security.has_label("PII") && !subject.roles.contains("hr_admin") {
                        return PluginResult::deny(PluginViolation::new(
                            "insufficient_role",
                            format!("Tool '{}' requires 'hr_admin' role for PII data", tool_name),
                        ));
                    }
                }
            }

            if extensions.http.is_some() {
                println!("  [identity-checker] WARNING: HTTP visible (unexpected!)");
            } else {
                println!("  [identity-checker] HTTP: not visible (correct — no read_headers)");
            }
            println!("  [identity-checker] PRE-INVOKE ALLOWED");
        }

        PluginResult::allow()
    }
}

// ---------------------------------------------------------------------------
// Plugin: HeaderInjector
// Has read_headers, write_headers, append_labels capabilities.
// Uses COW to add a security label and inject a header.
// ---------------------------------------------------------------------------

struct HeaderInjector {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for HeaderInjector {
    fn config(&self) -> &PluginConfig { &self.cfg }
}

impl HookHandler<CmfHook> for HeaderInjector {
    fn handle(
        &self,
        _payload: &MessagePayload,
        extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        // Can see HTTP (has read_headers)
        if let Some(ref http) = extensions.http {
            println!("  [header-injector] HTTP headers visible: {:?}", http.request_headers);
        }

        // Can NOT see security subject (no read_subject)
        if let Some(ref security) = extensions.security {
            if security.subject.is_some() {
                println!("  [header-injector] WARNING: Subject visible (unexpected!)");
            } else {
                println!("  [header-injector] Security subject: not visible (no read_subject)");
            }
        }

        // COW copy to modify — tokens propagate from the executor
        let mut modified = extensions.cow_copy();

        // Add a label via MonotonicSet (has append_labels)
        if modified.labels_write_token.is_some() {
            modified.security.as_mut().unwrap().add_label("PROCESSED");
            println!("  [header-injector] Added label 'PROCESSED'");
        }

        // Inject a header via Guarded (has write_headers)
        if let Some(ref token) = modified.http_write_token {
            modified.http.as_mut().unwrap().write(token).set_header("X-Processed-By", "header-injector");
            println!("  [header-injector] Injected header 'X-Processed-By'");
        }

        PluginResult::modify_extensions(modified)
    }
}

// ---------------------------------------------------------------------------
// Plugin: AuditLogger
// Has read_headers, read_security, read_labels capabilities.
// Read-only — just logs what it can see.
// ---------------------------------------------------------------------------

struct AuditLogger {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for AuditLogger {
    fn config(&self) -> &PluginConfig { &self.cfg }
}

impl HookHandler<CmfHook> for AuditLogger {
    fn handle(
        &self,
        payload: &MessagePayload,
        extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        let is_result = payload.message.is_tool_result();
        let phase = if is_result { "POST" } else { "PRE" };

        let tool_name = if is_result {
            payload.message.get_tool_results()
                .first()
                .map(|tr| tr.tool_name.as_str())
                .unwrap_or("unknown")
        } else {
            payload.message.get_tool_calls()
                .first()
                .map(|tc| tc.name.as_str())
                .unwrap_or("unknown")
        };

        print!("  [audit-logger] AUDIT[{}]: tool='{}' ", phase, tool_name);

        if let Some(ref security) = extensions.security {
            let labels: Vec<&String> = security.labels.iter().collect();
            print!("labels={:?} ", labels);
        }

        if let Some(ref http) = extensions.http {
            if let Some(req_id) = http.get_header("X-Request-ID") {
                print!("request_id='{}' ", req_id);
            }
        }

        if is_result {
            let is_error = payload.message.get_tool_results()
                .first()
                .map(|tr| tr.is_error)
                .unwrap_or(false);
            print!("error={} ", is_error);
        }

        println!();
        PluginResult::allow()
    }
}

// ---------------------------------------------------------------------------
// Factories
// ---------------------------------------------------------------------------

struct IdentityCheckerFactory;
impl PluginFactory for IdentityCheckerFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, PluginError> {
        let plugin = Arc::new(IdentityChecker { cfg: config.clone() });
        Ok(PluginInstance {
            plugin: plugin.clone(),
            handlers: vec![
                ("cmf.tool_pre_invoke", Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(plugin.clone()))),
                ("cmf.tool_post_invoke", Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(plugin))),
            ],
        })
    }
}

struct HeaderInjectorFactory;
impl PluginFactory for HeaderInjectorFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, PluginError> {
        let plugin = Arc::new(HeaderInjector { cfg: config.clone() });
        Ok(PluginInstance {
            plugin: plugin.clone(),
            handlers: vec![
                ("cmf.tool_pre_invoke", Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(plugin))),
            ],
        })
    }
}

struct AuditLoggerFactory;
impl PluginFactory for AuditLoggerFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, PluginError> {
        let plugin = Arc::new(AuditLogger { cfg: config.clone() });
        Ok(PluginInstance {
            plugin: plugin.clone(),
            handlers: vec![
                ("cmf.tool_pre_invoke", Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(plugin.clone()))),
                ("cmf.tool_post_invoke", Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(plugin))),
            ],
        })
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    println!("=== CMF Capabilities Demo ===\n");

    // Load config from YAML file — capabilities declared per plugin
    let config_path = "crates/cpex-core/examples/cmf_capabilities_demo.yaml";
    println!("--- Loading config from {} ---\n", config_path);
    let yaml = std::fs::read_to_string(config_path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", config_path, e));
    let cpex_config = cpex_core::config::parse_config(&yaml).unwrap();

    let mut mgr = PluginManager::default();
    mgr.register_factory("builtin/identity-checker", Box::new(IdentityCheckerFactory));
    mgr.register_factory("builtin/header-injector", Box::new(HeaderInjectorFactory));
    mgr.register_factory("builtin/audit-logger", Box::new(AuditLoggerFactory));
    mgr.load_config(cpex_config).unwrap();
    mgr.initialize().await.unwrap();

    // --- Build CMF Message ---
    let payload = MessagePayload {
        message: Message {
            schema_version: cpex_core::cmf::constants::SCHEMA_VERSION.into(),
            role: Role::Assistant,
            content: vec![
                ContentPart::Text { text: "Looking up compensation.".into() },
                ContentPart::ToolCall {
                    content: ToolCall {
                        tool_call_id: "tc_001".into(),
                        name: "get_compensation".into(),
                        arguments: [("employee_id".to_string(), serde_json::json!(42))].into(),
                        namespace: None,
                    },
                },
            ],
            channel: None,
        },
    };

    // --- Build Extensions with security, HTTP, meta ---
    let mut security = SecurityExtension::default();
    security.add_label("PII");
    security.add_label("HR_DATA");
    security.classification = Some("confidential".into());
    security.subject = Some(cpex_core::extensions::security::SubjectExtension {
        id: Some("alice".into()),
        subject_type: Some(cpex_core::extensions::security::SubjectType::User),
        roles: ["hr_admin".to_string()].into(),
        permissions: ["read_compensation".to_string()].into(),
        ..Default::default()
    });

    let mut http = HttpExtension::default();
    http.set_header("Authorization", "Bearer eyJ...");
    http.set_header("X-Request-ID", "req-abc-123");

    let ext = Extensions {
        request: Some(Arc::new(RequestExtension {
            environment: Some("production".into()),
            request_id: Some("req-abc-123".into()),
            ..Default::default()
        })),
        security: Some(Arc::new(security)),
        http: Some(Arc::new(http)),
        meta: Some(Arc::new(MetaExtension {
            entity_type: Some("tool".into()),
            entity_name: Some("get_compensation".into()),
            tags: ["pii".to_string(), "hr".to_string()].into(),
            ..Default::default()
        })),
        ..Default::default()
    };

    // --- Pre-invoke: type-safe dispatch via invoke_named ---
    println!("=== Phase 1: cmf.tool_pre_invoke ===\n");

    // invoke_named<CmfHook> gives compile-time payload type checking
    // while routing to the specific "cmf.tool_pre_invoke" hook name
    let (pre_result, bg) = mgr.invoke_named::<CmfHook>(
        "cmf.tool_pre_invoke",
        payload,
        ext,
        None,  // first hook — no context table
    ).await;

    println!();
    if pre_result.continue_processing {
        println!("Pre-invoke result: ALLOWED");
        if let Some(ref modified_ext) = pre_result.modified_extensions {
            if let Some(ref sec) = modified_ext.security {
                let labels: Vec<&String> = sec.labels.iter().collect();
                println!("  Labels after pre-invoke: {:?}", labels);
            }
            if let Some(ref http) = modified_ext.http {
                println!("  Headers after pre-invoke: {:?}", http.request_headers);
            }
        }
    } else {
        println!("Pre-invoke result: DENIED — {}", pre_result.violation.as_ref().unwrap().reason);
        bg.wait_for_background_tasks().await;
        println!("\n=== Demo complete ===");
        return;
    }
    bg.wait_for_background_tasks().await;

    // --- Simulate tool execution ---
    println!("\n--- Tool 'get_compensation' executes... ---");
    println!("  Result: {{\"salary\": 150000, \"currency\": \"USD\"}}\n");

    // --- Post-invoke: different CMF message with tool result ---
    println!("=== Phase 2: cmf.tool_post_invoke ===\n");

    let post_payload = MessagePayload {
        message: Message {
            schema_version: cpex_core::cmf::constants::SCHEMA_VERSION.into(),
            role: Role::Tool,
            content: vec![
                ContentPart::ToolResult {
                    content: cpex_core::cmf::ToolResult {
                        tool_call_id: "tc_001".into(),
                        tool_name: "get_compensation".into(),
                        content: serde_json::json!({"salary": 150000, "currency": "USD"}),
                        is_error: false,
                    },
                },
            ],
            channel: None,
        },
    };

    // Build post-invoke extensions — carry forward any modifications
    // from pre-invoke via the context table
    let post_ext = pre_result.modified_extensions.unwrap_or_else(|| {
        // Rebuild if no modifications
        let mut security = SecurityExtension::default();
        security.add_label("PII");
        Extensions {
            security: Some(Arc::new(security)),
            meta: Some(Arc::new(MetaExtension {
                entity_type: Some("tool".into()),
                entity_name: Some("get_compensation".into()),
                ..Default::default()
            })),
            ..Default::default()
        }
    });

    // Thread the context table from pre-invoke to preserve plugin state
    let (post_result, post_bg) = mgr.invoke_named::<CmfHook>(
        "cmf.tool_post_invoke",
        post_payload,
        post_ext,
        Some(pre_result.context_table),
    ).await;

    println!();
    if post_result.continue_processing {
        println!("Post-invoke result: ALLOWED");
    } else {
        println!("Post-invoke result: DENIED — {}", post_result.violation.as_ref().unwrap().reason);
    }

    post_bg.wait_for_background_tasks().await;
    println!("\n=== Demo complete ===");
}
