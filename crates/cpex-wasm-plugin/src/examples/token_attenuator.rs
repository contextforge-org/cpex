// Location: ./crates/cpex-wasm-plugin/src/examples/token_attenuator.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya


use async_trait::async_trait;
use chrono::Utc;

use cpex_core::context::PluginContext;
use cpex_core::delegation::{DelegationPayload, TargetType, TokenDelegateHook};
use cpex_core::error::PluginError;
use cpex_core::extensions::container::Extensions;
use cpex_core::extensions::raw_credentials::{DelegationMode, RawDelegatedToken};
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::plugin::{Plugin, PluginConfig};

use crate::cpex_log;

pub struct TokenAttenuatorPlugin;

impl Default for TokenAttenuatorPlugin {
    fn default() -> Self {
        Self
    }
}

static PLUGIN_CONFIG: std::sync::OnceLock<PluginConfig> = std::sync::OnceLock::new();

#[async_trait]
impl Plugin for TokenAttenuatorPlugin {
    fn config(&self) -> &PluginConfig {
        PLUGIN_CONFIG.get_or_init(|| PluginConfig {
            name: "token-attenuator".to_string(),
            kind: "wasm://token-attenuator.wasm".to_string(),
            hooks: vec!["token.delegate".to_string()],
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

impl HookHandler<TokenDelegateHook> for TokenAttenuatorPlugin {
    async fn handle(
        &self,
        payload: &DelegationPayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<DelegationPayload> {
        let target_name = payload.target_name();
        let target_type = payload.target_type();

        cpex_log!(info, "DELEGATE: minting token for target='{}' type={:?}", target_name, target_type);

        // Only handle Tool targets — pass through for other types
        if *target_type != TargetType::Tool {
            cpex_log!(debug, "DELEGATE: not a tool target, passing through");
            return PluginResult::allow();
        }

        // Mint a scoped token for the target tool
        let mut resolved = payload.clone();
        resolved.delegated_token = Some(RawDelegatedToken {
            token: zeroize::Zeroizing::new(String::new()),
            outbound_header: "Authorization".to_string(),
            audience: payload
                .target_audience()
                .unwrap_or(target_name)
                .to_string(),
            scopes: payload
                .required_permissions()
                .iter()
                .map(|s| s.to_string())
                .collect(),
            expires_at: Utc::now() + chrono::Duration::minutes(5),
        });
        resolved.delegation_mode = Some(DelegationMode::OnBehalfOfUser);
        resolved.minted_at = Some(Utc::now());
        resolved.metadata.insert(
            "minter".to_string(),
            serde_json::json!("token-attenuator-wasm"),
        );

        cpex_log!(info, "DELEGATE: token minted for audience='{}'",
            resolved.delegated_token.as_ref().unwrap().audience);

        PluginResult::modify_payload(resolved)
    }
}

#[cfg(test)]
mod tests {
    use cpex_core::context::PluginContext;
    use cpex_core::delegation::{DelegationPayload, TargetType, TokenDelegateHook};
    use cpex_core::extensions::container::Extensions;
    use cpex_core::hooks::trait_def::{HookHandler, PluginResult};

    use super::TokenAttenuatorPlugin;

    #[tokio::test]
    async fn test_mints_token_for_tool_target() {
        let payload = DelegationPayload::new("", "get_compensation")
            .with_target_type(TargetType::Tool)
            .with_target_audience("hr-service.internal")
            .with_required_permissions(vec!["read_compensation".into()]);
        let ext = Extensions::default();
        let mut ctx = PluginContext::default();
        let result: PluginResult<_> =
            <TokenAttenuatorPlugin as HookHandler<TokenDelegateHook>>::handle(
                &TokenAttenuatorPlugin, &payload, &ext, &mut ctx,
            ).await;
        assert!(result.continue_processing, "expected ALLOW");
        assert!(result.modified_payload.is_some(), "expected modified payload");
        let modified = result.modified_payload.as_ref().unwrap();
        let token = modified.delegated_token.as_ref().expect("should mint token");
        assert_eq!(token.audience, "hr-service.internal");
        assert_eq!(token.scopes, vec!["read_compensation"]);
        assert_eq!(token.outbound_header, "Authorization");
        assert!(modified.minted_at.is_some());
        assert_eq!(
            modified.metadata.get("minter").and_then(|v| v.as_str()),
            Some("token-attenuator-wasm")
        );
    }

    #[tokio::test]
    async fn test_passes_through_non_tool_targets() {
        let payload = DelegationPayload::new("", "agent-downstream")
            .with_target_type(TargetType::Agent);
        let ext = Extensions::default();
        let mut ctx = PluginContext::default();
        let result: PluginResult<_> =
            <TokenAttenuatorPlugin as HookHandler<TokenDelegateHook>>::handle(
                &TokenAttenuatorPlugin, &payload, &ext, &mut ctx,
            ).await;
        assert!(result.continue_processing, "expected ALLOW");
        assert!(result.modified_payload.is_none());
    }

    #[tokio::test]
    async fn test_uses_target_name_as_audience_when_no_explicit_audience() {
        let payload = DelegationPayload::new("", "fetch-records")
            .with_target_type(TargetType::Tool);
        let ext = Extensions::default();
        let mut ctx = PluginContext::default();
        let result: PluginResult<_> =
            <TokenAttenuatorPlugin as HookHandler<TokenDelegateHook>>::handle(
                &TokenAttenuatorPlugin, &payload, &ext, &mut ctx,
            ).await;
        assert!(result.modified_payload.is_some(), "expected modified payload");
        let token = result.modified_payload.as_ref().unwrap()
            .delegated_token.as_ref().unwrap();
        assert_eq!(token.audience, "fetch-records");
    }
}
