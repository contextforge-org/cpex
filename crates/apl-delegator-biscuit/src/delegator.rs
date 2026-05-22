// Location: ./crates/apl-delegator-biscuit/src/delegator.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// `BiscuitDelegator` — `HookHandler<TokenDelegateHook>` that
// performs biscuit-auth capability-token attenuation.
//
// # Flow
//
//   1. Decode `payload.bearer_token()` as base64 → biscuit bytes.
//   2. Parse + verify the inbound biscuit against the configured
//      root public key (`Biscuit::from(bytes, root_public_key)`).
//   3. Build a delegation block carrying the route's narrowing
//      constraints:
//        * `delegated_to("<target_name>")` fact
//        * `audience("<target_audience>")` fact
//        * `check if operation("<perm>")` for each required permission
//        * `check if time($t), $t <= <expires_at>` time-bound
//   4. Append the block via `biscuit.append(block_builder)`. Biscuit
//      generates an ephemeral signing keypair internally — the
//      verifier walks the chain to validate.
//   5. Serialize the new biscuit (now with one more block) to
//      base64 → `RawDelegatedToken`.
//
// # Error handling
//
// Construction errors → `Box<PluginError>` (`PluginError::Config`).
// Runtime errors → `PluginResult::deny(PluginViolation::new(code,
// reason))`:
//   * `delegation.bad_request` — missing bearer token / target audience
//   * `delegation.token_invalid` — base64 decode failed or biscuit
//                                   verification failed (wrong key,
//                                   tampered signature, malformed)
//   * `delegation.attenuation_failed` — block construction failed
//                                        (Datalog syntax error)

use async_trait::async_trait;
use biscuit_auth::builder::BlockBuilder;
use biscuit_auth::{Biscuit, PublicKey};
use chrono::Utc;

use cpex_core::context::PluginContext;
use cpex_core::delegation::{DelegationPayload, TokenDelegateHook};
use cpex_core::error::{PluginError, PluginViolation};
use cpex_core::extensions::raw_credentials::{DelegationMode, RawDelegatedToken};
use cpex_core::hooks::payload::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::plugin::{Plugin, PluginConfig};

use super::config::BiscuitDelegatorConfig;

/// Biscuit-mediated `TokenDelegate` handler.
pub struct BiscuitDelegator {
    cfg: PluginConfig,
    typed: BiscuitDelegatorConfig,
    /// Pre-resolved root public key — verifying every inbound
    /// biscuit's authority block.
    root_public_key: PublicKey,
}

impl std::fmt::Debug for BiscuitDelegator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BiscuitDelegator")
            .field("cfg", &self.cfg.name)
            .field("default_outbound_header", &self.typed.default_outbound_header)
            .field("default_ttl_seconds", &self.typed.default_ttl_seconds)
            .field("root_public_key", &"<elided>")
            .finish()
    }
}

impl BiscuitDelegator {
    /// Build from `PluginConfig`. Parses `cfg.config` into
    /// [`BiscuitDelegatorConfig`] and resolves the root public key.
    pub fn new(cfg: PluginConfig) -> Result<Self, Box<PluginError>> {
        let raw = cfg.config.as_ref().ok_or_else(|| {
            Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (apl-delegator-biscuit) requires a `config:` block",
                    cfg.name
                ),
            })
        })?;
        let typed: BiscuitDelegatorConfig = serde_json::from_value(raw.clone())
            .map_err(|e| {
                Box::new(PluginError::Config {
                    message: format!(
                        "plugin '{}' (apl-delegator-biscuit) config parse failed: {e}",
                        cfg.name
                    ),
                })
            })?;

        let root_public_key = typed.root_public_key.resolve().map_err(|e| {
            Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (apl-delegator-biscuit) root_public_key: {e}",
                    cfg.name
                ),
            })
        })?;

        Ok(Self {
            cfg,
            typed,
            root_public_key,
        })
    }

    /// Resolve the effective TTL — route hint wins if shorter than
    /// the configured default.
    fn effective_ttl_seconds(&self, payload: &DelegationPayload) -> u64 {
        match payload.route_attenuation().and_then(|a| a.ttl_seconds) {
            Some(hint) => hint.min(self.typed.default_ttl_seconds),
            None => self.typed.default_ttl_seconds,
        }
    }
}

#[async_trait]
impl Plugin for BiscuitDelegator {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<TokenDelegateHook> for BiscuitDelegator {
    async fn handle(
        &self,
        payload: &DelegationPayload,
        _ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<DelegationPayload> {
        let bearer = payload.bearer_token();
        if bearer.is_empty() {
            return PluginResult::deny(PluginViolation::new(
                "delegation.bad_request",
                "DelegationPayload carried an empty bearer_token",
            ));
        }
        let audience = payload.target_audience().unwrap_or("").to_string();
        if audience.is_empty() {
            return PluginResult::deny(PluginViolation::new(
                "delegation.bad_request",
                "target_audience missing — biscuit attenuation requires \
                 an audience to scope the delegation block",
            ));
        }

        // 1. Decode + parse + verify inbound biscuit.
        //    `Biscuit::from_base64` handles both URL-safe and
        //    standard base64 variants internally.
        let biscuit = match Biscuit::from_base64(bearer, self.root_public_key) {
            Ok(b) => b,
            Err(e) => {
                return PluginResult::deny(PluginViolation::new(
                    "delegation.token_invalid",
                    format!(
                        "inbound biscuit verification failed against configured \
                         root public key: {e}"
                    ),
                ));
            }
        };

        // 2. Build the delegation block.
        let ttl_secs = self.effective_ttl_seconds(payload);
        let expires_at_unix = (Utc::now()
            + chrono::Duration::seconds(ttl_secs as i64))
        .timestamp();

        // Build the delegation block as a Datalog string. biscuit
        // parses + validates the Datalog at parse time. Building
        // the source as a single string and parsing once is simpler
        // than the typed Fact/Term builder API.
        //
        // Quote-escape any embedded `"` in user-supplied values so a
        // malicious target_name or required_permission can't escape
        // the Datalog string literal and inject extra clauses.
        let mut datalog = String::new();
        datalog.push_str(&format!(
            r#"delegated_to("{}");"#,
            escape_datalog_string(payload.target_name())
        ));
        datalog.push_str(&format!(
            r#"audience("{}");"#,
            escape_datalog_string(&audience)
        ));
        for perm in payload.required_permissions() {
            datalog.push_str(&format!(
                r#"check if operation("{}");"#,
                escape_datalog_string(perm)
            ));
        }
        // Time-bound check — token unusable past expires_at.
        datalog.push_str(&format!(
            "check if time($t), $t <= {expires_at_unix};"
        ));

        // biscuit-auth 6's `BlockBuilder::code` consumes the
        // builder and returns a new one on success (or an error if
        // the Datalog source is malformed).
        let builder = match BlockBuilder::new().code(datalog.as_str()) {
            Ok(b) => b,
            Err(e) => {
                return PluginResult::deny(PluginViolation::new(
                    "delegation.attenuation_failed",
                    format!("delegation block Datalog parse failed: {e}"),
                ));
            }
        };

        // 3. Append the block. Biscuit generates an ephemeral
        //    Ed25519 keypair internally for the new block; the
        //    verifier walks the chain to validate.
        let attenuated = match biscuit.append(builder) {
            Ok(b) => b,
            Err(e) => {
                return PluginResult::deny(PluginViolation::new(
                    "delegation.attenuation_failed",
                    format!("biscuit append failed: {e}"),
                ));
            }
        };

        // 4. Serialize.
        let new_bytes = match attenuated.to_base64() {
            Ok(s) => s,
            Err(e) => {
                return PluginResult::deny(PluginViolation::new(
                    "delegation.attenuation_failed",
                    format!("could not serialize attenuated biscuit: {e}"),
                ));
            }
        };

        // 5. Build RawDelegatedToken.
        let scopes: Vec<String> = {
            let mut s: Vec<String> = payload.required_permissions().to_vec();
            if let Some(att) = payload.route_attenuation() {
                for cap in &att.capabilities {
                    if !s.contains(cap) {
                        s.push(cap.clone());
                    }
                }
            }
            s
        };
        let expires_at = Utc::now() + chrono::Duration::seconds(ttl_secs as i64);
        let token = RawDelegatedToken::new(
            new_bytes,
            self.typed.default_outbound_header.clone(),
            audience,
            scopes,
            expires_at,
        );

        let mut updated = payload.clone();
        updated.delegated_token = Some(token);
        updated.delegation_mode = Some(DelegationMode::OnBehalfOfUser);
        updated.minted_at = Some(Utc::now());
        updated.metadata.insert(
            "delegator".into(),
            serde_json::Value::String("biscuit".into()),
        );

        PluginResult::modify_payload(updated)
    }
}

/// Escape `"` and `\` in a Datalog string literal so user-supplied
/// values (target name, requested scopes) can't break out of the
/// surrounding `"..."` and inject extra Datalog clauses. Belt-and-
/// suspenders — biscuit's parser would likely reject malformed
/// output but the explicit escape avoids relying on parser behavior.
fn escape_datalog_string(s: &str) -> String {
    s.replace('\\', r"\\").replace('"', "\\\"")
}
