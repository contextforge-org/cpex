// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
//
// Your plugin — edit this file and run `make build`.
//
// Steps:
//   1. Rename the struct and update the config below
//   2. Pick your hook type (see table below)
//   3. Write your logic in handle()
//   4. Build: `make build`
//
// Available hook types:
//   CmfHook            → intercept tool calls/results    (event: "cmf.tool_pre_invoke")
//   IdentityHook       → resolve user identity           (event: "identity.resolve")
//   TokenDelegateHook  → mint scoped outbound credentials (event: "token.delegate")
//   Custom             → define your own (see src/examples/tool_invoke_checker.rs)
//
// Return values from handle():
//   PluginResult::allow()              — pass through unchanged
//   PluginResult::deny(violation)      — block with a reason
//   PluginResult::modify_payload(p)    — pass through with modifications

use crate::prelude::*;
use std::sync::OnceLock;

// Lazily-initialized plugin metadata. The host never calls config() on the WASM
// guest (it uses config.yaml instead), but the Plugin trait requires it.
static PLUGIN_CONFIG: OnceLock<PluginConfig> = OnceLock::new();

#[derive(Default)]
pub struct UserPlugin;

#[async_trait]
impl Plugin for UserPlugin {
    fn config(&self) -> &PluginConfig {
        PLUGIN_CONFIG.get_or_init(|| PluginConfig {
            name: "user-plugin".to_string(),
            kind: "wasm://user-plugin.wasm".to_string(),
            // Informational only — the host's config.yaml controls actual routing.
            // Change this to match your hook type:
            //   CmfHook           → "cmf.tool_pre_invoke"
            //   IdentityHook      → "identity.resolve"
            //   TokenDelegateHook → "token.delegate"
            hooks: vec!["cmf.tool_pre_invoke".to_string()],
            ..Default::default()
        })
    }
    async fn initialize(&self) -> Result<(), Box<PluginError>> { Ok(()) }
    async fn shutdown(&self) -> Result<(), Box<PluginError>> { Ok(()) }
}

// Change CmfHook to your hook type if needed.
// Also update the registration in src/lib.rs (bottom of file) to match.
impl HookHandler<CmfHook> for UserPlugin {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        // TODO: Your plugin logic here
        PluginResult::allow()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────
// Run with: cargo test --lib plugin
//       or: make test

#[cfg(test)]
mod tests {
    use cpex_core::cmf::constants::SCHEMA_VERSION;
    use cpex_core::cmf::{CmfHook, ContentPart, Message, MessagePayload, Role, ToolCall};
    use cpex_core::context::PluginContext;
    use cpex_core::extensions::container::Extensions;
    use cpex_core::hooks::trait_def::{HookHandler, PluginResult};

    use super::UserPlugin;

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

    #[tokio::test]
    async fn test_allows_tool_call() {
        let payload = tool_call_payload("any_tool");
        let ext = Extensions::default();
        let mut ctx = PluginContext::default();

        let result: PluginResult<_> =
            <UserPlugin as HookHandler<CmfHook>>::handle(
                &UserPlugin, &payload, &ext, &mut ctx,
            ).await;

        assert!(result.continue_processing, "plugin should allow by default");
        assert!(result.violation.is_none());
    }

    #[tokio::test]
    async fn test_allows_empty_content() {
        let payload = MessagePayload {
            message: Message {
                schema_version: SCHEMA_VERSION.into(),
                role: Role::User,
                content: vec![],
                channel: None,
            },
        };
        let ext = Extensions::default();
        let mut ctx = PluginContext::default();

        let result: PluginResult<_> =
            <UserPlugin as HookHandler<CmfHook>>::handle(
                &UserPlugin, &payload, &ext, &mut ctx,
            ).await;

        assert!(result.continue_processing);
    }
}
