// Location: ./crates/cpex-wasm-plugin/src/plugins/token_attenuator.rs
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
