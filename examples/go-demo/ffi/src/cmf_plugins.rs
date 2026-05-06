// Location: ./examples/go-demo/ffi/src/cmf_plugins.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// CMF demo plugins — operate on MessagePayload (typed CMF messages).
//
// Two plugins demonstrating typed message inspection and
// capability-gated extension modification:
//
//   - ToolPolicyPlugin: extracts tool calls from the CMF message,
//     checks permissions against meta tags and security labels.
//     PII-tagged tools require a "PII" label in the security
//     extension; admin-tagged tools require an "admin" role.
//
//   - HeaderInjectorPlugin: inspects tool calls/results and injects
//     response headers (X-Tool-Name, X-Tool-Status, X-CPEX-Processed)
//     using the capability-gated Guarded<HttpExtension> write pattern.
//     Requires "write_headers" capability in the plugin config.

use std::sync::Arc;

use async_trait::async_trait;

use cpex_core::cmf::{ContentPart, MessagePayload};
use cpex_core::context::PluginContext;
use cpex_core::error::{PluginError, PluginViolation};
use cpex_core::factory::{PluginFactory, PluginInstance};
use cpex_core::hooks::adapter::TypedHandlerAdapter;
use cpex_core::hooks::payload::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, HookTypeDef, PluginResult};
use cpex_core::plugin::{Plugin, PluginConfig};

// ---------------------------------------------------------------------------
// CMF Hook Type
// ---------------------------------------------------------------------------

/// Hook type for CMF message processing. The hook *name* varies
/// (cmf.tool_pre_invoke, cmf.tool_post_invoke, etc.) but the payload
/// is always MessagePayload.
pub struct CmfHook;

impl HookTypeDef for CmfHook {
    type Payload = MessagePayload;
    type Result = PluginResult<MessagePayload>;
    const NAME: &'static str = "cmf";
}

// ---------------------------------------------------------------------------
// Tool Policy Plugin
// ---------------------------------------------------------------------------

/// Checks tool call permissions against security labels and meta tags.
///
/// Policy rules:
///   - Tools tagged "pii" require security label "PII" in extensions
///   - Tools tagged "admin" require subject role "admin"
///   - All tool calls are logged with their arguments
struct ToolPolicyPlugin {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for ToolPolicyPlugin {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for ToolPolicyPlugin {
    fn handle(
        &self,
        payload: &MessagePayload,
        extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        // Extract tool calls from the CMF message
        let tool_calls: Vec<_> = payload
            .message
            .content
            .iter()
            .filter_map(|cp| match cp {
                ContentPart::ToolCall { content } => Some(content),
                _ => None,
            })
            .collect();

        if tool_calls.is_empty() {
            return PluginResult::allow();
        }

        // Check meta tags for PII requirement
        let has_pii_tag = extensions
            .meta
            .as_ref()
            .map(|m| m.tags.iter().any(|t| t == "pii"))
            .unwrap_or(false);

        // Check security labels
        let has_pii_label = extensions
            .security
            .as_ref()
            .map(|s| s.labels.contains(&"PII".to_string()))
            .unwrap_or(false);

        // If PII tagged but no PII label in security context — deny
        if has_pii_tag && !has_pii_label {
            let tool_name = tool_calls
                .first()
                .map(|tc| tc.name.as_str())
                .unwrap_or("unknown");

            tracing::warn!(
                "[tool-policy] DENIED: tool '{}' requires PII label but caller lacks it",
                tool_name
            );
            return PluginResult::deny(PluginViolation::new(
                "pii_label_required",
                format!(
                    "Tool '{}' is PII-tagged but security context lacks PII label",
                    tool_name
                ),
            ));
        }

        // Check admin requirement
        let has_admin_tag = extensions
            .meta
            .as_ref()
            .map(|m| m.tags.iter().any(|t| t == "admin"))
            .unwrap_or(false);

        if has_admin_tag {
            let has_admin_role = extensions
                .security
                .as_ref()
                .and_then(|s| s.subject.as_ref())
                .map(|subj| subj.roles.iter().any(|r| r == "admin"))
                .unwrap_or(false);

            if !has_admin_role {
                return PluginResult::deny(PluginViolation::new(
                    "admin_required",
                    "This tool requires admin role",
                ));
            }
        }

        for tc in &tool_calls {
            tracing::info!(
                "[tool-policy] OK: tool '{}' (call_id={}) authorized",
                tc.name,
                tc.tool_call_id,
            );
        }

        PluginResult::allow()
    }
}

pub struct ToolPolicyFactory;

impl PluginFactory for ToolPolicyFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let plugin = Arc::new(ToolPolicyPlugin {
            cfg: config.clone(),
        });
        Ok(PluginInstance {
            plugin: plugin.clone(),
            handlers: vec![(
                "cmf.tool_pre_invoke",
                Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(plugin)),
            )],
        })
    }
}

// ---------------------------------------------------------------------------
// Header Injector Plugin
// ---------------------------------------------------------------------------

/// Adds response headers after tool execution.
///
/// Inspects the CMF message (tool results) and adds:
///   - X-Tool-Name: name of the tool that ran
///   - X-Tool-Status: "success" or "error"
///   - X-CPEX-Processed: "true"
struct HeaderInjectorPlugin {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for HeaderInjectorPlugin {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for HeaderInjectorPlugin {
    fn handle(
        &self,
        payload: &MessagePayload,
        extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        // Look for tool results or tool calls
        let tool_name = payload.message.content.iter().find_map(|cp| match cp {
            ContentPart::ToolResult { content } => Some(content.tool_name.as_str()),
            ContentPart::ToolCall { content } => Some(content.name.as_str()),
            _ => None,
        });

        let is_error = payload.message.content.iter().any(|cp| {
            matches!(
                cp,
                ContentPart::ToolResult { content } if content.is_error
            )
        });

        if let Some(name) = tool_name {
            // COW copy — clones mutable slots, propagates write tokens
            let mut owned = extensions.cow_copy();

            // Write to HTTP extension — requires write token from capability
            if let Some(ref token) = owned.http_write_token {
                if let Some(http) = owned.http.as_mut() {
                    let h = http.write(token);
                    h.set_response_header("X-Tool-Name", name);
                    h.set_response_header(
                        "X-Tool-Status",
                        if is_error { "error" } else { "success" },
                    );
                    h.set_response_header("X-CPEX-Processed", "true");
                }
            }

            return PluginResult::modify_extensions(owned);
        }

        PluginResult::allow()
    }
}

pub struct HeaderInjectorFactory;

impl PluginFactory for HeaderInjectorFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let plugin = Arc::new(HeaderInjectorPlugin {
            cfg: config.clone(),
        });
        Ok(PluginInstance {
            plugin: plugin.clone(),
            handlers: vec![
                (
                    "cmf.tool_pre_invoke",
                    Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(plugin.clone())),
                ),
                (
                    "cmf.tool_post_invoke",
                    Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(plugin)),
                ),
            ],
        })
    }
}

/// Register CMF demo plugin factories on a manager.
pub fn register_cmf_factories(manager: &mut cpex_core::manager::PluginManager) {
    manager.register_factory("builtin/cmf-tool-policy", Box::new(ToolPolicyFactory));
    manager.register_factory(
        "builtin/cmf-header-injector",
        Box::new(HeaderInjectorFactory),
    );
}
