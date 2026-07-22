// Location: ./crates/cpex-wasm-plugin/src/plugins/remote_authz.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
// RemoteAuthzPlugin — WASM plugin that simulates remote authorization with
// cross-invocation state persistence.
//
// Mirrors the native RemoteAuthz from plugin_demo.rs: maintains a cached ACL
// that persists across invocations via WASM linear memory. On the first call,
// the ACL is "fetched" (simulated) and stored in a module-level static. All
// subsequent calls read from the cached set — demonstrating that the WASM
// sandbox's Store (and linear memory) is preserved across invocations.
//
// This is the WASM equivalent of the native plugin's `initialize()` + RwLock
// pattern: the SandboxManager keeps the Store alive, so static variables in
// the WASM module survive between calls.

use std::collections::HashSet;
use std::sync::OnceLock;

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
// Persistent ACL — survives across invocations via WASM linear memory.
//
// The SandboxManager creates the Store once at plugin load time and reuses it
// for every invoke() call (only fuel and epoch are reset). Module-level statics
// in the WASM binary persist across calls, just like an in-memory cache would
// in a long-running native process.
// ---------------------------------------------------------------------------

static ACL: OnceLock<HashSet<String>> = OnceLock::new();

fn get_or_init_acl() -> &'static HashSet<String> {
    ACL.get_or_init(|| {
        cpex_log!(info, "[remote-authz] initializing ACL (first invocation — simulating remote fetch)");
        let mut acl = HashSet::new();
        acl.insert("alice".to_string());
        acl.insert("bob".to_string());
        cpex_log!(info, "[remote-authz] ACL cached ({} users)", acl.len());
        acl
    })
}

// ---------------------------------------------------------------------------
// Plugin implementation
// ---------------------------------------------------------------------------

pub struct RemoteAuthzPlugin;

impl Default for RemoteAuthzPlugin {
    fn default() -> Self {
        Self
    }
}

static PLUGIN_CONFIG: OnceLock<PluginConfig> = OnceLock::new();

#[async_trait]
impl Plugin for RemoteAuthzPlugin {
    fn config(&self) -> &PluginConfig {
        PLUGIN_CONFIG.get_or_init(|| PluginConfig {
            name: "remote-authz".to_string(),
            kind: "wasm://remote-authz.wasm".to_string(),
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

impl HookHandler<ToolPreInvoke> for RemoteAuthzPlugin {
    async fn handle(
        &self,
        payload: &ToolInvokePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<ToolInvokePayload> {
        let acl = get_or_init_acl();

        if acl.contains(&payload.user) {
            cpex_log!(
                info,
                "[remote-authz] OK (ACL hit): user '{}' allowed",
                payload.user
            );
            return PluginResult::allow();
        }

        cpex_log!(
            warn,
            "[remote-authz] DENIED (ACL miss): user '{}' not in remote ACL",
            payload.user
        );
        PluginResult::deny(PluginViolation::new(
            "remote_authz_denied",
            format!("User '{}' not in remote ACL", payload.user),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cpex_core::hooks::trait_def::HookHandler;

    #[tokio::test]
    async fn test_allowed_user_passes() {
        let plugin = RemoteAuthzPlugin;
        let payload = ToolInvokePayload {
            tool_name: "query_external_data".into(),
            user: "alice".into(),
            arguments: "dataset=sales".into(),
        };
        let ext = Extensions::default();
        let mut ctx = PluginContext::default();
        let result: PluginResult<ToolInvokePayload> =
            <RemoteAuthzPlugin as HookHandler<ToolPreInvoke>>::handle(
                &plugin, &payload, &ext, &mut ctx,
            )
            .await;
        assert!(result.continue_processing);
    }

    #[tokio::test]
    async fn test_denied_user_blocked() {
        let plugin = RemoteAuthzPlugin;
        let payload = ToolInvokePayload {
            tool_name: "query_external_data".into(),
            user: "charlie".into(),
            arguments: "dataset=sales".into(),
        };
        let ext = Extensions::default();
        let mut ctx = PluginContext::default();
        let result: PluginResult<ToolInvokePayload> =
            <RemoteAuthzPlugin as HookHandler<ToolPreInvoke>>::handle(
                &plugin, &payload, &ext, &mut ctx,
            )
            .await;
        assert!(!result.continue_processing);
        assert_eq!(result.violation.as_ref().unwrap().code, "remote_authz_denied");
    }

    #[tokio::test]
    async fn test_acl_persists_across_calls() {
        let plugin = RemoteAuthzPlugin;
        let ext = Extensions::default();

        // First call — initializes ACL
        let payload = ToolInvokePayload {
            tool_name: "query_external_data".into(),
            user: "alice".into(),
            arguments: "".into(),
        };
        let mut ctx = PluginContext::default();
        let result: PluginResult<ToolInvokePayload> =
            <RemoteAuthzPlugin as HookHandler<ToolPreInvoke>>::handle(
                &plugin, &payload, &ext, &mut ctx,
            )
            .await;
        assert!(result.continue_processing);

        // Second call — reads from cached ACL (no re-init)
        let payload = ToolInvokePayload {
            tool_name: "query_external_data".into(),
            user: "bob".into(),
            arguments: "".into(),
        };
        let mut ctx = PluginContext::default();
        let result: PluginResult<ToolInvokePayload> =
            <RemoteAuthzPlugin as HookHandler<ToolPreInvoke>>::handle(
                &plugin, &payload, &ext, &mut ctx,
            )
            .await;
        assert!(result.continue_processing);
    }
}
