// Location: ./crates/cpex-wasm-plugin/src/examples/audit_logger.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya


use async_trait::async_trait;

use cpex_core::cmf::{CmfHook, MessagePayload};
use cpex_core::context::PluginContext;
use cpex_core::error::PluginError;
use cpex_core::extensions::container::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::plugin::{Plugin, PluginConfig};

use crate::cpex_log;

pub struct AuditLoggerPlugin;

impl Default for AuditLoggerPlugin {
    fn default() -> Self {
        Self
    }
}

static PLUGIN_CONFIG: std::sync::OnceLock<PluginConfig> = std::sync::OnceLock::new();

#[async_trait]
impl Plugin for AuditLoggerPlugin {
    fn config(&self) -> &PluginConfig {
        PLUGIN_CONFIG.get_or_init(|| PluginConfig {
            name: "audit-logger".to_string(),
            kind: "wasm://audit-logger.wasm".to_string(),
            hooks: vec![
                "cmf.tool_pre_invoke".to_string(),
                "cmf.tool_post_invoke".to_string(),
            ],
            ..Default::default()
        })
    }

    async fn initialize(&self) -> Result<(), Box<PluginError>> {
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), Box<PluginError>> {
        Ok(())
    }
}

impl HookHandler<CmfHook> for AuditLoggerPlugin {
    async fn handle(
        &self,
        payload: &MessagePayload,
        extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        let is_result = payload.message.is_tool_result();
        let phase = if is_result { "POST" } else { "PRE" };

        let tool_name = if is_result {
            payload
                .message
                .get_tool_results()
                .first()
                .map(|tr| tr.tool_name.as_str())
                .unwrap_or("unknown")
        } else {
            payload
                .message
                .get_tool_calls()
                .first()
                .map(|tc| tc.name.as_str())
                .unwrap_or("unknown")
        };

        let labels_str = extensions
            .security
            .as_ref()
            .map(|s| {
                let labels: Vec<&String> = s.labels.iter().collect();
                format!("{:?}", labels)
            })
            .unwrap_or_else(|| "[]".into());

        let req_id = extensions
            .http
            .as_ref()
            .and_then(|h| h.get_header("X-Request-ID"))
            .unwrap_or_default();

        if is_result {
            let is_error = payload
                .message
                .get_tool_results()
                .first()
                .map(|tr| tr.is_error)
                .unwrap_or(false);
            cpex_log!(info, "AUDIT[{}]: tool='{}' labels={} request_id='{}' error={}",
                phase, tool_name, labels_str, req_id, is_error);
        } else {
            cpex_log!(info, "AUDIT[{}]: tool='{}' labels={} request_id='{}'",
                phase, tool_name, labels_str, req_id);
        }
        PluginResult::allow()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use cpex_core::cmf::constants::SCHEMA_VERSION;
    use cpex_core::cmf::{CmfHook, ContentPart, Message, MessagePayload, Role, ToolCall, ToolResult};
    use cpex_core::context::PluginContext;
    use cpex_core::extensions::container::Extensions;
    use cpex_core::extensions::http::HttpExtension;
    use cpex_core::extensions::security::SecurityExtension;
    use cpex_core::hooks::trait_def::{HookHandler, PluginResult};

    use super::AuditLoggerPlugin;

    fn tool_call_payload(name: &str) -> MessagePayload {
        MessagePayload {
            message: Message {
                schema_version: SCHEMA_VERSION.into(),
                role: Role::Assistant,
                content: vec![ContentPart::ToolCall {
                    content: ToolCall {
                        tool_call_id: format!("tc_{}", name),
                        name: name.into(),
                        arguments: Default::default(),
                        namespace: None,
                    },
                }],
                channel: None,
            },
        }
    }

    fn tool_result_payload(name: &str, content: serde_json::Value, is_error: bool) -> MessagePayload {
        MessagePayload {
            message: Message {
                schema_version: SCHEMA_VERSION.into(),
                role: Role::Tool,
                content: vec![ContentPart::ToolResult {
                    content: ToolResult {
                        tool_call_id: format!("tc_{}", name),
                        tool_name: name.into(),
                        content,
                        is_error,
                    },
                }],
                channel: None,
            },
        }
    }

    #[tokio::test]
    async fn test_always_allows_pre_invoke() {
        let mut sec = SecurityExtension::default();
        sec.add_label("PII");
        let mut http = HttpExtension::default();
        http.set_header("X-Request-ID", "req-123");
        let ext = Extensions {
            security: Some(Arc::new(sec)),
            http: Some(Arc::new(http)),
            ..Default::default()
        };
        let payload = tool_call_payload("get_data");
        let mut ctx = PluginContext::default();
        let result: PluginResult<_> =
            <AuditLoggerPlugin as HookHandler<CmfHook>>::handle(
                &AuditLoggerPlugin, &payload, &ext, &mut ctx,
            ).await;
        assert!(result.continue_processing, "expected ALLOW");
    }

    #[tokio::test]
    async fn test_always_allows_post_invoke() {
        let ext = Extensions::default();
        let payload = tool_result_payload("get_data", serde_json::json!({"result": "ok"}), false);
        let mut ctx = PluginContext::default();
        let result: PluginResult<_> =
            <AuditLoggerPlugin as HookHandler<CmfHook>>::handle(
                &AuditLoggerPlugin, &payload, &ext, &mut ctx,
            ).await;
        assert!(result.continue_processing, "expected ALLOW");
    }
}
