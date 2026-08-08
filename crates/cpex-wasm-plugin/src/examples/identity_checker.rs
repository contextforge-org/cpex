// Location: ./crates/cpex-wasm-plugin/src/examples/identity_checker.rs
// Copyright 2026
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::collections::HashMap;

    use cpex_core::cmf::constants::SCHEMA_VERSION;
    use cpex_core::cmf::{CmfHook, ContentPart, Message, MessagePayload, Role, ToolCall};
    use cpex_core::context::PluginContext;
    use cpex_core::extensions::container::Extensions;
    use cpex_core::extensions::security::{SecurityExtension, SubjectExtension, SubjectType};
    use cpex_core::hooks::payload::PluginPayload;
    use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
    use cpex_core::identity::{IdentityHook, IdentityPayload, TokenSource};

    use super::IdentityCheckerPlugin;

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

    fn ext_with_security(f: impl FnOnce(&mut SecurityExtension)) -> Extensions {
        let mut sec = SecurityExtension::default();
        f(&mut sec);
        Extensions { security: Some(Arc::new(sec)), ..Default::default() }
    }

    fn assert_denied<P: PluginPayload>(result: &PluginResult<P>) {
        assert!(!result.continue_processing, "expected DENY, got ALLOW");
        assert!(result.violation.is_some(), "denied but no violation");
    }

    fn assert_allowed<P: PluginPayload>(result: &PluginResult<P>) {
        assert!(result.continue_processing, "expected ALLOW, got DENY");
    }

    #[tokio::test]
    async fn test_denies_pii_access_without_hr_admin_role() {
        let ext = ext_with_security(|s| {
            s.add_label("PII");
            s.subject = Some(SubjectExtension {
                id: Some("bob".into()),
                subject_type: Some(SubjectType::User),
                roles: ["viewer".to_string()].into(),
                ..Default::default()
            });
        });
        let payload = tool_call_payload("get_compensation");
        let mut ctx = PluginContext::default();
        let result: PluginResult<_> =
            <IdentityCheckerPlugin as HookHandler<CmfHook>>::handle(
                &IdentityCheckerPlugin, &payload, &ext, &mut ctx,
            ).await;
        assert_denied(&result);
    }

    #[tokio::test]
    async fn test_allows_pii_access_with_hr_admin_role() {
        let ext = ext_with_security(|s| {
            s.add_label("PII");
            s.subject = Some(SubjectExtension {
                id: Some("alice".into()),
                subject_type: Some(SubjectType::User),
                roles: ["hr_admin".to_string()].into(),
                ..Default::default()
            });
        });
        let payload = tool_call_payload("get_compensation");
        let mut ctx = PluginContext::default();
        let result: PluginResult<_> =
            <IdentityCheckerPlugin as HookHandler<CmfHook>>::handle(
                &IdentityCheckerPlugin, &payload, &ext, &mut ctx,
            ).await;
        assert_allowed(&result);
    }

    #[tokio::test]
    async fn test_allows_non_pii_without_role() {
        let ext = ext_with_security(|s| s.add_label("PUBLIC"));
        let payload = tool_call_payload("get_weather");
        let mut ctx = PluginContext::default();
        let result: PluginResult<_> =
            <IdentityCheckerPlugin as HookHandler<CmfHook>>::handle(
                &IdentityCheckerPlugin, &payload, &ext, &mut ctx,
            ).await;
        assert_allowed(&result);
    }

    #[tokio::test]
    async fn test_identity_resolves_subject_from_header() {
        let mut headers = HashMap::new();
        headers.insert("x-user-id".to_string(), "alice".to_string());
        let payload = IdentityPayload::new("", TokenSource::Bearer).with_headers(headers);
        let ext = Extensions::default();
        let mut ctx = PluginContext::default();
        let result: PluginResult<_> =
            <IdentityCheckerPlugin as HookHandler<IdentityHook>>::handle(
                &IdentityCheckerPlugin, &payload, &ext, &mut ctx,
            ).await;
        assert_allowed(&result);
        assert!(result.modified_payload.is_some(), "expected modified payload");
        let subject = result.modified_payload.as_ref().unwrap()
            .subject.as_ref().expect("subject should be resolved");
        assert_eq!(subject.id.as_deref(), Some("alice"));
        assert_eq!(subject.subject_type, Some(SubjectType::User));
    }

    #[tokio::test]
    async fn test_identity_passes_through_without_header() {
        let payload = IdentityPayload::new("", TokenSource::Bearer);
        let ext = Extensions::default();
        let mut ctx = PluginContext::default();
        let result: PluginResult<_> =
            <IdentityCheckerPlugin as HookHandler<IdentityHook>>::handle(
                &IdentityCheckerPlugin, &payload, &ext, &mut ctx,
            ).await;
        assert_allowed(&result);
        assert!(result.modified_payload.is_none());
    }

    #[tokio::test]
    async fn test_identity_skips_when_subject_already_resolved() {
        let mut headers = HashMap::new();
        headers.insert("x-user-id".to_string(), "bob".to_string());
        let mut payload = IdentityPayload::new("", TokenSource::Bearer).with_headers(headers);
        payload.subject = Some(SubjectExtension {
            id: Some("existing-user".into()),
            subject_type: Some(SubjectType::User),
            ..Default::default()
        });
        let ext = Extensions::default();
        let mut ctx = PluginContext::default();
        let result: PluginResult<_> =
            <IdentityCheckerPlugin as HookHandler<IdentityHook>>::handle(
                &IdentityCheckerPlugin, &payload, &ext, &mut ctx,
            ).await;
        assert_allowed(&result);
        assert!(result.modified_payload.is_none());
    }
}
