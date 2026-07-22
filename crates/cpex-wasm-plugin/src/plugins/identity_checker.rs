// Location: ./crates/cpex-wasm-plugin/src/plugin.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
// IdentityCheckerPlugin — the bundled WASM plugin implementation.
//
// Implements HookHandler<CmfHook> using the same trait that a native plugin
// would implement. No WIT types here — conversions are handled by the SDK.

use async_trait::async_trait;

use cpex_core::cmf::{CmfHook, MessagePayload};
use cpex_core::context::PluginContext;
use cpex_core::error::{PluginError, PluginViolation};
use cpex_core::extensions::container::Extensions;
use cpex_core::extensions::security::{SubjectExtension, SubjectType};
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::identity::{IdentityHook, IdentityPayload};
use cpex_core::plugin::{Plugin, PluginConfig};

use crate::cpex_log;

pub struct IdentityCheckerPlugin;

impl Default for IdentityCheckerPlugin {
    fn default() -> Self {
        Self
    }
}

static PLUGIN_CONFIG: std::sync::OnceLock<PluginConfig> = std::sync::OnceLock::new();

#[async_trait]
impl Plugin for IdentityCheckerPlugin {
    fn config(&self) -> &PluginConfig {
        PLUGIN_CONFIG.get_or_init(|| PluginConfig {
            name: "identity-checker".to_string(),
            kind: "wasm://plugin.wasm".to_string(),
            hooks: vec!["cmf".to_string()],
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

impl HookHandler<CmfHook> for IdentityCheckerPlugin {
    async fn handle(
        &self,
        payload: &MessagePayload,
        extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        let is_result = payload.message.is_tool_result();

        if is_result {
            let tool_name = payload
                .message
                .get_tool_results()
                .first()
                .map(|tr| tr.tool_name.as_str())
                .unwrap_or("unknown");

            if let Some(ref security) = extensions.security {
                if let Some(ref subject) = security.subject {
                    cpex_log!(info, "POST-INVOKE: result from '{}' authorized for subject={:?}", tool_name, subject.id);
                }
            }
        } else {
            let tool_name = payload
                .message
                .get_tool_calls()
                .first()
                .map(|tc| tc.name.as_str())
                .unwrap_or("unknown");

            if let Some(ref security) = extensions.security {
                if let Some(ref subject) = security.subject {
                    cpex_log!(debug, "PRE-INVOKE '{}': subject={:?} roles={:?}",
                        tool_name, subject.id, subject.roles.iter().collect::<Vec<_>>());

                    if security.has_label("PII") && !subject.roles.contains("hr_admin") {
                        cpex_log!(warn, "PRE-INVOKE '{}': DENIED — missing hr_admin role for PII", tool_name);
                        return PluginResult::deny(PluginViolation::new(
                            "insufficient_role",
                            &format!(
                                "Tool '{}' requires 'hr_admin' role for PII data",
                                tool_name
                            ),
                        ));
                    }
                }
            }
            cpex_log!(debug, "PRE-INVOKE '{}': ALLOWED", tool_name);
        }

        PluginResult::allow()
    }
}

impl HookHandler<IdentityHook> for IdentityCheckerPlugin {
    /// identity_resolve via the custom payload path. The raw token is
    /// `#[serde(skip)]` and never reaches the sandbox, so this resolves
    /// the subject from the request headers instead.
    async fn handle(
        &self,
        payload: &IdentityPayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<IdentityPayload> {
        if payload.subject.is_some() {
            cpex_log!(debug, "IDENTITY: subject already resolved");
            return PluginResult::allow();
        }

        let Some(user_id) = payload.headers().get("x-user-id") else {
            cpex_log!(debug, "IDENTITY: no x-user-id header — passing through");
            return PluginResult::allow();
        };

        cpex_log!(info, "IDENTITY: resolved subject '{}' from header", user_id);
        let mut resolved = payload.clone();
        resolved.subject = Some(SubjectExtension {
            id: Some(user_id.clone()),
            subject_type: Some(SubjectType::User),
            ..Default::default()
        });
        PluginResult::modify_payload(resolved)
    }
}
