// Location: ./crates/cpex-wasm-plugin/src/plugins/audit_logger_custom.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
// AuditLoggerCustomPlugin — WASM audit logger for the custom payload demo.
//
// Mirrors the native AuditLogger from plugin_demo.rs: logs all tool invocations
// without blocking. Runs as fire_and_forget mode at priority 100.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use cpex_core::context::PluginContext;
use cpex_core::error::PluginError;
use cpex_core::extensions::container::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, HookTypeDef, PluginResult};
use cpex_core::plugin::{Plugin, PluginConfig};

use crate::cpex_log;

// ---------------------------------------------------------------------------
// Payload and hook types (same definition as all demo plugins)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInvokePayload {
    pub tool_name: String,
    pub user: String,
    pub arguments: String,
}

cpex_core::impl_plugin_payload!(ToolInvokePayload);
cpex_core::impl_wasm_payload!(ToolInvokePayload, "cpex.tool_invoke");

pub struct ToolPreInvoke;
impl HookTypeDef for ToolPreInvoke {
    type Payload = ToolInvokePayload;
    type Result = PluginResult<ToolInvokePayload>;
    const NAME: &'static str = "tool_pre_invoke";
}

pub struct ToolPostInvoke;
impl HookTypeDef for ToolPostInvoke {
    type Payload = ToolInvokePayload;
    type Result = PluginResult<ToolInvokePayload>;
    const NAME: &'static str = "tool_post_invoke";
}

// ---------------------------------------------------------------------------
// Plugin implementation
// ---------------------------------------------------------------------------

pub struct AuditLoggerCustomPlugin;

impl Default for AuditLoggerCustomPlugin {
    fn default() -> Self {
        Self
    }
}

static PLUGIN_CONFIG: std::sync::OnceLock<PluginConfig> = std::sync::OnceLock::new();

#[async_trait]
impl Plugin for AuditLoggerCustomPlugin {
    fn config(&self) -> &PluginConfig {
        PLUGIN_CONFIG.get_or_init(|| PluginConfig {
            name: "audit-logger".to_string(),
            kind: "wasm://audit-logger-custom.wasm".to_string(),
            hooks: vec!["tool_pre_invoke".to_string(), "tool_post_invoke".to_string()],
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

impl HookHandler<ToolPreInvoke> for AuditLoggerCustomPlugin {
    async fn handle(
        &self,
        payload: &ToolInvokePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<ToolInvokePayload> {
        cpex_log!(
            info,
            "[audit-logger] LOG: user='{}' tool='{}' args='{}'",
            payload.user,
            payload.tool_name,
            payload.arguments
        );
        PluginResult::allow()
    }
}

impl HookHandler<ToolPostInvoke> for AuditLoggerCustomPlugin {
    async fn handle(
        &self,
        payload: &ToolInvokePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<ToolInvokePayload> {
        cpex_log!(
            info,
            "[audit-logger] LOG: post-invoke user='{}' tool='{}'",
            payload.user,
            payload.tool_name
        );
        PluginResult::allow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cpex_core::hooks::trait_def::HookHandler;

    #[tokio::test]
    async fn test_always_allows() {
        let plugin = AuditLoggerCustomPlugin;
        let payload = ToolInvokePayload {
            tool_name: "get_compensation".into(),
            user: "alice".into(),
            arguments: "employee_id=42".into(),
        };
        let ext = Extensions::default();
        let mut ctx = PluginContext::default();
        let result: PluginResult<ToolInvokePayload> =
            <AuditLoggerCustomPlugin as HookHandler<ToolPreInvoke>>::handle(
                &plugin, &payload, &ext, &mut ctx,
            )
            .await;
        assert!(result.continue_processing);
    }
}
