// Location: ./crates/cpex-wasm-plugin/src/plugins/fs_test.rs
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

pub struct FsTestPlugin;

impl Default for FsTestPlugin {
    fn default() -> Self {
        Self
    }
}

static PLUGIN_CONFIG: std::sync::OnceLock<PluginConfig> = std::sync::OnceLock::new();

#[async_trait]
impl Plugin for FsTestPlugin {
    fn config(&self) -> &PluginConfig {
        PLUGIN_CONFIG.get_or_init(|| PluginConfig {
            name: "fs-test".to_string(),
            kind: "wasm://fs-test.wasm".to_string(),
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

impl HookHandler<CmfHook> for FsTestPlugin {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        _extensions: &Extensions,
        ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        // Try to read /etc/passwd (should fail if not in allowed_filesystem)
        let target_path = "/etc/passwd";
        cpex_log!(info, "attempting to read '{}'", target_path);

        match std::fs::read_to_string(target_path) {
            Ok(content) => {
                // If we could read it, report that in context (test will check this)
                ctx.set_local("fs_read_success", serde_json::json!(true));
                ctx.set_local("fs_read_length", serde_json::json!(content.len()));
                cpex_log!(warn, "successfully read '{}' ({} bytes) — sandbox escape!", target_path, content.len());
                PluginResult::allow()
            }
            Err(e) => {
                // Expected: access denied
                ctx.set_local("fs_read_success", serde_json::json!(false));
                ctx.set_local("fs_read_error", serde_json::json!(e.to_string()));
                cpex_log!(info, "read '{}' denied: {} — sandbox working correctly", target_path, e);
                PluginResult::allow()
            }
        }
    }
}
