// Location: ./crates/cpex-wasm-plugin/src/plugins/env_test.rs
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

pub struct EnvTestPlugin;

impl Default for EnvTestPlugin {
    fn default() -> Self {
        Self
    }
}

static PLUGIN_CONFIG: std::sync::OnceLock<PluginConfig> = std::sync::OnceLock::new();

#[async_trait]
impl Plugin for EnvTestPlugin {
    fn config(&self) -> &PluginConfig {
        PLUGIN_CONFIG.get_or_init(|| PluginConfig {
            name: "env-test".to_string(),
            kind: "wasm://env-test.wasm".to_string(),
            hooks: vec!["cmf.tool_pre_invoke".to_string()],
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

impl HookHandler<CmfHook> for EnvTestPlugin {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        _extensions: &Extensions,
        ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        // Try to read HOME (should be hidden unless explicitly allowed)
        let home = std::env::var("HOME").unwrap_or_default();
        ctx.set_local("env_HOME", serde_json::json!(home));

        // Try to read PATH (should be hidden unless explicitly allowed)
        let path = std::env::var("PATH").unwrap_or_default();
        ctx.set_local("env_PATH", serde_json::json!(path));

        // Try to read a test variable that we explicitly allow in the policy
        let allowed = std::env::var("CPEX_TEST_ALLOWED").unwrap_or_default();
        ctx.set_local("env_CPEX_TEST_ALLOWED", serde_json::json!(allowed));

        // Try to read a secret that should never be visible
        let secret = std::env::var("SECRET_API_KEY").unwrap_or_default();
        ctx.set_local("env_SECRET_API_KEY", serde_json::json!(secret));

        cpex_log!(info, "env check: HOME='{}' PATH='{}' ALLOWED='{}' SECRET='{}'",
            home, path, allowed, secret);

        PluginResult::allow()
    }
}
