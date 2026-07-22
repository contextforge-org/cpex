// Location: ./crates/cpex-wasm-plugin/src/plugins/tool_invoke_checker.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
// ToolInvokeCheckerPlugin — WASM identity resolver.
//
// Mirrors the native IdentityResolver from plugin_demo.rs: checks that a
// user identity is present in the custom ToolInvokePayload. Runs as the
// first plugin in the sequential pipeline (priority 10).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use cpex_core::context::PluginContext;
use cpex_core::error::{PluginError, PluginViolation};
use cpex_core::extensions::container::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, HookTypeDef, PluginResult};
use cpex_core::plugin::{Plugin, PluginConfig};

use crate::cpex_log;

// ---------------------------------------------------------------------------
// Payload and hook types — shared definition used by all 4 demo plugins.
// Each WASM binary carries its own copy (same struct, same discriminator).
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
// Plugin implementation — identity check only
// ---------------------------------------------------------------------------

pub struct ToolInvokeCheckerPlugin;

impl Default for ToolInvokeCheckerPlugin {
    fn default() -> Self {
        Self
    }
}

static PLUGIN_CONFIG: std::sync::OnceLock<PluginConfig> = std::sync::OnceLock::new();

#[async_trait]
impl Plugin for ToolInvokeCheckerPlugin {
    fn config(&self) -> &PluginConfig {
        PLUGIN_CONFIG.get_or_init(|| PluginConfig {
            name: "identity-resolver".to_string(),
            kind: "wasm://tool-invoke-checker.wasm".to_string(),
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

impl HookHandler<ToolPreInvoke> for ToolInvokeCheckerPlugin {
    async fn handle(
        &self,
        payload: &ToolInvokePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<ToolInvokePayload> {
        if payload.user.is_empty() {
            cpex_log!(warn, "[identity-resolver] DENIED: no user identity");
            return PluginResult::deny(PluginViolation::new(
                "no_identity",
                "User identity is required",
            ));
        }
        cpex_log!(info, "[identity-resolver] OK: user '{}' identified", payload.user);
        PluginResult::allow()
    }
}

impl HookHandler<ToolPostInvoke> for ToolInvokeCheckerPlugin {
    async fn handle(
        &self,
        payload: &ToolInvokePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<ToolInvokePayload> {
        cpex_log!(
            info,
            "[identity-resolver] post-invoke: user '{}' completed '{}'",
            payload.user,
            payload.tool_name
        );
        PluginResult::allow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cpex_core::hooks::payload::WasmSerializablePayload;
    use cpex_core::hooks::trait_def::HookHandler;

    #[test]
    fn test_payload_serde_roundtrip() {
        let payload = ToolInvokePayload {
            tool_name: "get_compensation".into(),
            user: "alice".into(),
            arguments: "employee_id=42".into(),
        };
        let bytes = payload.to_wasm_bytes().unwrap();
        let restored = ToolInvokePayload::from_wasm_bytes(&bytes).unwrap();
        assert_eq!(restored.tool_name, "get_compensation");
        assert_eq!(restored.user, "alice");
        assert_eq!(restored.arguments, "employee_id=42");
    }

    #[tokio::test]
    async fn test_no_user_denied() {
        let plugin = ToolInvokeCheckerPlugin;
        let payload = ToolInvokePayload {
            tool_name: "list_departments".into(),
            user: "".into(),
            arguments: "".into(),
        };
        let ext = Extensions::default();
        let mut ctx = PluginContext::default();
        let result: PluginResult<ToolInvokePayload> =
            <ToolInvokeCheckerPlugin as HookHandler<ToolPreInvoke>>::handle(
                &plugin, &payload, &ext, &mut ctx,
            )
            .await;
        assert!(!result.continue_processing);
        assert_eq!(result.violation.as_ref().unwrap().code, "no_identity");
    }

    #[tokio::test]
    async fn test_user_present_allowed() {
        let plugin = ToolInvokeCheckerPlugin;
        let payload = ToolInvokePayload {
            tool_name: "list_departments".into(),
            user: "alice".into(),
            arguments: "".into(),
        };
        let ext = Extensions::default();
        let mut ctx = PluginContext::default();
        let result: PluginResult<ToolInvokePayload> =
            <ToolInvokeCheckerPlugin as HookHandler<ToolPreInvoke>>::handle(
                &plugin, &payload, &ext, &mut ctx,
            )
            .await;
        assert!(result.continue_processing);
    }
}
