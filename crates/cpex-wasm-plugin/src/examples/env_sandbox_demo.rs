// Location: ./crates/cpex-wasm-plugin/src/examples/env_sandbox_demo.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
// EnvSandboxDemoPlugin — demonstrates WASI environment variable sandbox enforcement.
//
// Reads one argument from the ToolCall payload:
//   "env_var" — name of the environment variable to look up
//
// Calls std::env::var on that name. If WASI injected the variable (it was
// declared in allowed_env), the call succeeds and the plugin returns ALLOW
// with the value stored in ctx. If the variable was not declared (or the host
// does not have it set), std::env::var returns Err and the plugin returns DENY
// with violation code "env_access_denied".


use async_trait::async_trait;

use cpex_core::cmf::{CmfHook, ContentPart, MessagePayload};
use cpex_core::context::PluginContext;
use cpex_core::error::{PluginError, PluginViolation};
use cpex_core::extensions::container::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::plugin::{Plugin, PluginConfig};

use crate::cpex_log;

pub struct EnvSandboxDemoPlugin;

impl Default for EnvSandboxDemoPlugin {
    fn default() -> Self {
        Self
    }
}

static PLUGIN_CONFIG: std::sync::OnceLock<PluginConfig> = std::sync::OnceLock::new();

#[async_trait]
impl Plugin for EnvSandboxDemoPlugin {
    fn config(&self) -> &PluginConfig {
        PLUGIN_CONFIG.get_or_init(|| PluginConfig {
            name: "env-sandbox-demo".to_string(),
            kind: "wasm://env-sandbox-demo.wasm".to_string(),
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

impl HookHandler<CmfHook> for EnvSandboxDemoPlugin {
    async fn handle(
        &self,
        payload: &MessagePayload,
        _extensions: &Extensions,
        ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        let env_var = match extract_var_name(payload) {
            Some(v) => v,
            None => {
                cpex_log!(warn, "[env-sandbox-demo] no tool call with env_var found — allow");
                return PluginResult::allow();
            }
        };

        cpex_log!(info, "[env-sandbox-demo] looking up env_var='{}'", env_var);

        match std::env::var(&env_var) {
            Ok(value) => {
                cpex_log!(info, "[env-sandbox-demo] ALLOW: '{}' is visible", env_var);
                ctx.set_local("env_var", serde_json::json!(env_var));
                ctx.set_local("env_result", serde_json::json!("allowed"));
                ctx.set_local("env_value", serde_json::json!(value));
                PluginResult::allow()
            }
            Err(e) => {
                cpex_log!(warn, "[env-sandbox-demo] DENY: '{}' not visible — {}", env_var, e);
                ctx.set_local("env_var", serde_json::json!(env_var));
                ctx.set_local("env_result", serde_json::json!("denied"));
                ctx.set_local("env_error", serde_json::json!(e.to_string()));
                PluginResult::deny(PluginViolation::new(
                    "env_access_denied",
                    &format!(
                        "environment variable '{}' not visible in sandbox: {}",
                        env_var, e
                    ),
                ))
            }
        }
    }
}

fn extract_var_name(payload: &MessagePayload) -> Option<String> {
    for part in &payload.message.content {
        if let ContentPart::ToolCall { content: tc } = part {
            return tc.arguments.get("env_var")?.as_str().map(|s| s.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use cpex_core::cmf::constants::SCHEMA_VERSION;
    use cpex_core::cmf::{ContentPart, Message, Role, ToolCall};
    use cpex_core::hooks::trait_def::HookHandler;
    use std::collections::HashMap;

    fn make_payload(env_var: &str) -> MessagePayload {
        let mut arguments = HashMap::new();
        arguments.insert("env_var".to_string(), serde_json::json!(env_var));
        MessagePayload {
            message: Message {
                schema_version: SCHEMA_VERSION.into(),
                role: Role::Assistant,
                content: vec![ContentPart::ToolCall {
                    content: ToolCall {
                        tool_call_id: "tc_env_demo".into(),
                        name: "env_sandbox_demo".into(),
                        arguments,
                        namespace: None,
                    },
                }],
                channel: None,
            },
        }
    }

    #[tokio::test]
    async fn test_var_present_on_host_is_allowed() {
        std::env::set_var("CPEX_UNIT_TEST_VAR", "test-value-123");

        let plugin = EnvSandboxDemoPlugin;
        let payload = make_payload("CPEX_UNIT_TEST_VAR");
        let ext = Extensions::default();
        let mut ctx = PluginContext::default();

        let result: PluginResult<MessagePayload> =
            <EnvSandboxDemoPlugin as HookHandler<CmfHook>>::handle(
                &plugin, &payload, &ext, &mut ctx,
            )
            .await;

        assert!(result.continue_processing, "expected ALLOW");
        assert_eq!(ctx.get_local("env_result").unwrap(), "allowed");
        assert_eq!(ctx.get_local("env_value").unwrap(), "test-value-123");

        std::env::remove_var("CPEX_UNIT_TEST_VAR");
    }

    #[tokio::test]
    async fn test_var_absent_from_host_is_denied() {
        std::env::remove_var("CPEX_NONEXISTENT_XYZ_99");

        let plugin = EnvSandboxDemoPlugin;
        let payload = make_payload("CPEX_NONEXISTENT_XYZ_99");
        let ext = Extensions::default();
        let mut ctx = PluginContext::default();

        let result: PluginResult<MessagePayload> =
            <EnvSandboxDemoPlugin as HookHandler<CmfHook>>::handle(
                &plugin, &payload, &ext, &mut ctx,
            )
            .await;

        assert!(!result.continue_processing, "expected DENY");
        assert_eq!(result.violation.as_ref().unwrap().code, "env_access_denied");
        assert_eq!(ctx.get_local("env_result").unwrap(), "denied");
    }

    #[tokio::test]
    async fn test_missing_env_var_arg_passes_through() {
        let payload = MessagePayload {
            message: cpex_core::cmf::Message {
                schema_version: SCHEMA_VERSION.into(),
                role: Role::Assistant,
                content: vec![],
                channel: None,
            },
        };
        let plugin = EnvSandboxDemoPlugin;
        let ext = Extensions::default();
        let mut ctx = PluginContext::default();

        let result: PluginResult<MessagePayload> =
            <EnvSandboxDemoPlugin as HookHandler<CmfHook>>::handle(
                &plugin, &payload, &ext, &mut ctx,
            )
            .await;

        assert!(result.continue_processing, "expected ALLOW — no args to act on");
    }
}
