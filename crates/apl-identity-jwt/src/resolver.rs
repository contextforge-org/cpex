// Location: ./crates/apl-identity-jwt/src/resolver.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// `JwtIdentityResolver` — `HookHandler<IdentityHook>` that validates
// inbound JWTs and populates the request's `IdentityPayload`.
//
// # Construction
//
// Single entry point: `JwtIdentityResolver::new(cfg: PluginConfig)`.
// Reads `cfg.config` (the typed plugin-specific config field) and
// deserializes it into [`JwtIdentityResolverConfig`], builds the
// runtime `TrustedIssuer` list and the `ClaimMapper`. No alternate
// constructors that bypass the config-driven path — tests
// construct a `PluginConfig` with the right `config` value and go
// through `new` like production code does.
//
// # Runtime flow
//
//   1. Peek at the `iss` claim *without* validating to pick the
//      right trusted issuer config.
//   2. Validate the token (signature + exp + nbf + aud + iss) using
//      that issuer's `DecodingKey`. `iss` is re-checked here as
//      defense-in-depth.
//   3. Map validated claims to a `SubjectExtension` via the
//      configured claim mapper.
//   4. Stash the raw token in `RawCredentialsExtension.inbound_tokens`
//      under `TokenRole::User` for forwarding plugins downstream.
//   5. Return the updated payload via `PluginResult::modify_payload`.
//
// # Error handling
//
// Construction errors → `Box<PluginError>` (`PluginError::Config`).
// Runtime token rejections → `PluginResult::deny(PluginViolation::new(code, reason))`.
// Stable codes for runtime denials:
//
//   * `auth.malformed_header` — JWT structure wrong / empty token
//   * `auth.untrusted_issuer` — `iss` not in trusted list
//   * `auth.signature_invalid` — signature failed
//   * `auth.token_expired` — `exp` in the past
//   * `auth.token_not_yet_valid` — `nbf` in the future
//   * `auth.audience_mismatch` — `aud` didn't include any configured aud
//   * `auth.algorithm_mismatch` — token uses unaccepted algo
//   * `auth.mapping_failed` — claim mapper rejected the claims
//   * `auth.token_invalid` — any other validation failure

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use jsonwebtoken::{decode, Validation};
use serde_json::Value;

use cpex_core::context::PluginContext;
use cpex_core::error::{PluginError, PluginViolation};
use cpex_core::extensions::raw_credentials::{
    RawCredentialsExtension, RawInboundToken, TokenKind, TokenRole,
};
use cpex_core::hooks::payload::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::identity::{IdentityHook, IdentityPayload};
use cpex_core::plugin::{Plugin, PluginConfig};

use super::claim_map::{ClaimMap, ClaimMapper, StandardClaimMap};
use super::config::JwtIdentityResolverConfig;
use super::trusted_issuer::TrustedIssuer;

/// Default clock-skew tolerance, in seconds. Matches what most OIDC
/// clients use as a sane default for `exp` / `nbf`.
const DEFAULT_LEEWAY_SECONDS: u64 = 60;

/// JWT-based identity resolver. See module docs.
#[derive(Debug)]
pub struct JwtIdentityResolver {
    cfg: PluginConfig,
    trusted_issuers: Vec<TrustedIssuer>,
    claim_mapper: Arc<dyn ClaimMapper>,
}

impl JwtIdentityResolver {
    /// Build a resolver from a `PluginConfig`. Reads `cfg.config`
    /// (the plugin-specific config field — `Option<JsonValue>`),
    /// deserializes it into [`JwtIdentityResolverConfig`], builds
    /// the runtime `TrustedIssuer` list, and resolves the claim
    /// mapper by name.
    ///
    /// Returns `PluginError::Config` for any config-time failure:
    /// missing config block, malformed JSON, no trusted issuers,
    /// unparseable decoding key, unknown claim mapper, etc.
    pub fn new(cfg: PluginConfig) -> Result<Self, Box<PluginError>> {
        let raw_config = cfg.config.as_ref().ok_or_else(|| {
            Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (apl-identity-jwt) requires a `config:` block — \
                     missing trusted_issuers etc.",
                    cfg.name
                ),
            })
        })?;

        let typed: JwtIdentityResolverConfig = serde_json::from_value(raw_config.clone())
            .map_err(|e| {
                Box::new(PluginError::Config {
                    message: format!(
                        "plugin '{}' (apl-identity-jwt) config parse failed: {e}",
                        cfg.name
                    ),
                })
            })?;

        if typed.trusted_issuers.is_empty() {
            return Err(Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (apl-identity-jwt) requires at least one \
                     entry in `trusted_issuers`",
                    cfg.name
                ),
            }));
        }

        // Turn each TrustedIssuerConfig into a runtime TrustedIssuer.
        // This is where PEM files get read and DecodingKey instances
        // get built.
        let trusted_issuers = typed
            .trusted_issuers
            .into_iter()
            .map(|raw| {
                raw.build().map_err(|e| {
                    Box::new(PluginError::Config {
                        message: format!(
                            "plugin '{}' (apl-identity-jwt): {e}",
                            cfg.name
                        ),
                    })
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Resolve the claim mapper by name. Unknown names are a
        // config error rather than a silent fallback — fail fast
        // so operators notice typos.
        let claim_mapper: Arc<dyn ClaimMapper> = match typed.claim_mapper.as_deref() {
            None | Some("standard") => Arc::new(StandardClaimMap),
            Some(other) => {
                return Err(Box::new(PluginError::Config {
                    message: format!(
                        "plugin '{}' (apl-identity-jwt): unknown claim_mapper \
                         '{other}'; valid: [standard]",
                        cfg.name
                    ),
                }));
            }
        };

        Ok(Self {
            cfg,
            trusted_issuers,
            claim_mapper,
        })
    }
}

#[async_trait]
impl Plugin for JwtIdentityResolver {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<IdentityHook> for JwtIdentityResolver {
    async fn handle(
        &self,
        payload: &IdentityPayload,
        _ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<IdentityPayload> {
        let raw_token = payload.raw_token();
        if raw_token.is_empty() {
            return PluginResult::deny(PluginViolation::new(
                "auth.malformed_header",
                "IdentityPayload carried an empty raw_token — host didn't \
                 populate the credential before invoking the hook",
            ));
        }

        // 1. Peek at `iss` to find the matching TrustedIssuer config.
        let iss = match peek_issuer(raw_token) {
            Some(iss) => iss,
            None => {
                return PluginResult::deny(PluginViolation::new(
                    "auth.malformed_header",
                    "JWT not well-formed or missing `iss` claim",
                ));
            }
        };
        let issuer = match self.trusted_issuers.iter().find(|i| i.issuer == iss) {
            Some(i) => i,
            None => {
                return PluginResult::deny(PluginViolation::new(
                    "auth.untrusted_issuer",
                    format!("issuer '{iss}' is not in the trusted-issuer list"),
                ));
            }
        };

        // 2. Validate signature + standard claims.
        let token_data = match validate_token(raw_token, issuer) {
            Ok(td) => td,
            Err(e) => {
                let (code, reason) = classify_jwt_error(&e);
                return PluginResult::deny(PluginViolation::new(code, reason));
            }
        };

        // 3. Map claims via the configured claim mapper.
        let subject = match self.claim_mapper.map_subject(&token_data.claims) {
            Some(s) => s,
            None => {
                return PluginResult::deny(PluginViolation::new(
                    "auth.mapping_failed",
                    "claim mapper produced no subject — required claim missing \
                     or has wrong shape",
                ));
            }
        };

        // 4. Stash the raw token for forwarding plugins.
        let source_header = payload
            .source_header()
            .unwrap_or("Authorization")
            .to_string();
        let mut raw_creds = RawCredentialsExtension::default();
        raw_creds.inbound_tokens.insert(
            TokenRole::User,
            RawInboundToken::new(raw_token, source_header, TokenKind::Jwt),
        );

        // 5. Build the updated payload and return.
        let mut updated = payload.clone();
        updated.subject = Some(subject);
        updated.raw_credentials = Some(raw_creds);
        updated.resolved_at = Some(chrono::Utc::now());
        // Pass the full claim map through `raw_claims` so audit /
        // downstream policy that wants uncategorized claims has them.
        updated.raw_claims = token_data.claims;

        PluginResult::modify_payload(updated)
    }
}

// =====================================================================
// Internal helpers
// =====================================================================

/// Pull the `iss` claim out of a JWT *without* verifying the
/// signature. Used purely to look up which trusted issuer config
/// to validate against next.
///
/// **Security note:** the value returned here is untrusted until
/// the subsequent validation pass succeeds. We use it only to
/// select the right `DecodingKey`; validation re-enforces `iss`
/// against the matched config.
fn peek_issuer(token: &str) -> Option<String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .ok()?;
    let value: Value = serde_json::from_slice(&payload_bytes).ok()?;
    value.get("iss")?.as_str().map(String::from)
}

/// Validate the token against the matched issuer's config:
/// signature, exp, nbf, aud, iss.
fn validate_token(
    token: &str,
    issuer: &TrustedIssuer,
) -> Result<jsonwebtoken::TokenData<ClaimMap>, jsonwebtoken::errors::Error> {
    let primary = issuer.algorithms[0];
    let mut validation = Validation::new(primary);
    validation.algorithms = issuer.algorithms.clone();
    validation.set_issuer(&[&issuer.issuer]);
    validation.leeway = if issuer.leeway_seconds == 0 {
        DEFAULT_LEEWAY_SECONDS
    } else {
        issuer.leeway_seconds
    };
    if issuer.audiences.is_empty() {
        validation.validate_aud = false;
    } else {
        let aud_refs: Vec<&str> = issuer.audiences.iter().map(String::as_str).collect();
        validation.set_audience(&aud_refs);
    }
    decode::<ClaimMap>(token, &issuer.decoding_key, &validation)
}

/// Map jsonwebtoken errors to stable violation codes.
fn classify_jwt_error(e: &jsonwebtoken::errors::Error) -> (&'static str, String) {
    use jsonwebtoken::errors::ErrorKind;
    let code = match e.kind() {
        ErrorKind::ExpiredSignature => "auth.token_expired",
        ErrorKind::InvalidSignature => "auth.signature_invalid",
        ErrorKind::ImmatureSignature => "auth.token_not_yet_valid",
        ErrorKind::InvalidAudience => "auth.audience_mismatch",
        ErrorKind::InvalidIssuer => "auth.untrusted_issuer",
        ErrorKind::InvalidAlgorithm | ErrorKind::InvalidAlgorithmName => {
            "auth.algorithm_mismatch"
        }
        ErrorKind::Base64(_) | ErrorKind::Json(_) => "auth.malformed_header",
        _ => "auth.token_invalid",
    };
    (code, e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::json;

    fn jwt_with_payload(payload_json: &str) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        let sig = URL_SAFE_NO_PAD.encode(b"fake-signature");
        format!("{header}.{payload}.{sig}")
    }

    fn cfg_with_config(name: &str, config: Value) -> PluginConfig {
        PluginConfig {
            name: name.into(),
            config: Some(config),
            ..Default::default()
        }
    }

    #[test]
    fn new_rejects_missing_config_block() {
        let cfg = PluginConfig {
            name: "jwt".into(),
            config: None,
            ..Default::default()
        };
        let err = JwtIdentityResolver::new(cfg).expect_err("missing config should fail");
        assert!(format!("{err}").contains("config"));
    }

    #[test]
    fn new_rejects_empty_trusted_issuers() {
        let cfg = cfg_with_config("jwt", json!({ "trusted_issuers": [] }));
        let err = JwtIdentityResolver::new(cfg)
            .expect_err("empty trusted_issuers should fail");
        assert!(format!("{err}").contains("trusted_issuers"));
    }

    #[test]
    fn new_rejects_unknown_claim_mapper() {
        let cfg = cfg_with_config(
            "jwt",
            json!({
                "trusted_issuers": [{
                    "issuer": "https://idp.example.com",
                    "algorithms": ["HS256"],
                    "decoding_key": { "kind": "secret", "secret": "x" },
                }],
                "claim_mapper": "made-up-mapper",
            }),
        );
        let err = JwtIdentityResolver::new(cfg)
            .expect_err("unknown mapper should fail");
        assert!(format!("{err}").contains("claim_mapper"));
    }

    #[test]
    fn new_accepts_well_formed_config() {
        let cfg = cfg_with_config(
            "jwt",
            json!({
                "trusted_issuers": [{
                    "issuer": "https://idp.example.com",
                    "audiences": ["my-api"],
                    "algorithms": ["HS256"],
                    "decoding_key": { "kind": "secret", "secret": "test-secret" },
                    "leeway_seconds": 30,
                }],
                "claim_mapper": "standard",
            }),
        );
        let resolver = JwtIdentityResolver::new(cfg).expect("should construct");
        assert_eq!(resolver.trusted_issuers.len(), 1);
        assert_eq!(resolver.trusted_issuers[0].issuer, "https://idp.example.com");
    }

    #[test]
    fn peek_issuer_extracts_iss() {
        let token = jwt_with_payload(r#"{"sub":"alice","iss":"https://idp.example.com"}"#);
        assert_eq!(
            peek_issuer(&token),
            Some("https://idp.example.com".to_string()),
        );
    }

    #[test]
    fn peek_issuer_returns_none_for_malformed_token() {
        assert!(peek_issuer("not.a-jwt").is_none());
        assert!(peek_issuer("a.b.c.d").is_none());
        assert!(peek_issuer("").is_none());
    }

    #[test]
    fn peek_issuer_returns_none_when_iss_missing() {
        let token = jwt_with_payload(r#"{"sub":"alice"}"#);
        assert!(peek_issuer(&token).is_none());
    }

    #[test]
    fn classify_picks_expected_codes() {
        use jsonwebtoken::errors::{Error, ErrorKind};
        let cases = [
            (ErrorKind::ExpiredSignature, "auth.token_expired"),
            (ErrorKind::InvalidSignature, "auth.signature_invalid"),
            (ErrorKind::ImmatureSignature, "auth.token_not_yet_valid"),
            (ErrorKind::InvalidAudience, "auth.audience_mismatch"),
            (ErrorKind::InvalidIssuer, "auth.untrusted_issuer"),
        ];
        for (kind, expected_code) in cases {
            let err = Error::from(kind);
            let (code, _reason) = classify_jwt_error(&err);
            assert_eq!(code, expected_code);
        }
    }
}
