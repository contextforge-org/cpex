// Location: ./crates/cpex-wasm-plugin/src/plugins/pii_guard.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
// PiiGuardPlugin — WASM plugin that blocks access to PII tools without clearance.
//
// Mirrors the native PiiGuard from plugin_demo.rs: checks that pii_clearance
// is set in PluginContext global state before allowing PII-tagged tools.
// Runs as priority 20 in the sequential pipeline.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use cpex_core::context::PluginContext;
use cpex_core::error::{PluginError, PluginViolation};
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

// ---------------------------------------------------------------------------
// Plugin implementation
// ---------------------------------------------------------------------------

pub struct PiiGuardPlugin;

impl Default for PiiGuardPlugin {
    fn default() -> Self {
        Self
    }
}

static PLUGIN_CONFIG: std::sync::OnceLock<PluginConfig> = std::sync::OnceLock::new();

#[async_trait]
impl Plugin for PiiGuardPlugin {
    fn config(&self) -> &PluginConfig {
        PLUGIN_CONFIG.get_or_init(|| PluginConfig {
            name: "pii-guard".to_string(),
            kind: "wasm://pii-guard.wasm".to_string(),
            hooks: vec!["tool_pre_invoke".to_string()],
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

impl HookHandler<ToolPreInvoke> for PiiGuardPlugin {
    async fn handle(
        &self,
        payload: &ToolInvokePayload,
        _extensions: &Extensions,
        ctx: &mut PluginContext,
    ) -> PluginResult<ToolInvokePayload> {
        let has_clearance = ctx
            .get_global("pii_clearance")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if !has_clearance {
            cpex_log!(
                warn,
                "[pii-guard] DENIED: user '{}' lacks PII clearance for '{}'",
                payload.user,
                payload.tool_name
            );
            return PluginResult::deny(PluginViolation::new(
                "pii_access_denied",
                "PII clearance required",
            ));
        }

        cpex_log!(info, "[pii-guard] OK: user '{}' has PII clearance", payload.user);
        PluginResult::allow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cpex_core::hooks::trait_def::HookHandler;

    #[tokio::test]
    async fn test_no_clearance_denied() {
        let plugin = PiiGuardPlugin;
        let payload = ToolInvokePayload {
            tool_name: "get_compensation".into(),
            user: "alice".into(),
            arguments: "employee_id=42".into(),
        };
        let ext = Extensions::default();
        let mut ctx = PluginContext::default();
        let result: PluginResult<ToolInvokePayload> =
            <PiiGuardPlugin as HookHandler<ToolPreInvoke>>::handle(
                &plugin, &payload, &ext, &mut ctx,
            )
            .await;
        assert!(!result.continue_processing);
        assert_eq!(result.violation.as_ref().unwrap().code, "pii_access_denied");
    }

    #[tokio::test]
    async fn test_with_clearance_allowed() {
        let plugin = PiiGuardPlugin;
        let payload = ToolInvokePayload {
            tool_name: "get_compensation".into(),
            user: "alice".into(),
            arguments: "employee_id=42".into(),
        };
        let ext = Extensions::default();
        let mut ctx = PluginContext::default();
        ctx.set_global("pii_clearance", serde_json::Value::Bool(true));
        let result: PluginResult<ToolInvokePayload> =
            <PiiGuardPlugin as HookHandler<ToolPreInvoke>>::handle(
                &plugin, &payload, &ext, &mut ctx,
            )
            .await;
        assert!(result.continue_processing);
    }
}
