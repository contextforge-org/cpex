// Location: ./builtins/plugins/delegator-oauth/src/delegator.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// `OAuthDelegator` — `HookHandler<TokenDelegateHook>` that performs
// RFC 8693 OAuth 2.0 Token Exchange against the configured IdP.
//
// # Flow
//
//   1. Read `payload.bearer_token()` (caller's current credential)
//      and `payload.target_audience()` / `required_permissions()` /
//      `route_attenuation` (the narrowing config).
//   2. Build the form-encoded body per RFC 8693:
//        grant_type=urn:ietf:params:oauth:grant-type:token-exchange
//        subject_token=<caller_token>
//        subject_token_type=<configured>
//        audience=<target>
//        scope=<space-separated requested scopes>
//   3. POST to the IdP's token endpoint with HTTP Basic auth
//      (client_id / client_secret).
//   4. Parse the JSON response: `{ access_token, token_type,
//      expires_in, scope, issued_token_type }`.
//   5. Construct a `RawDelegatedToken` with the minted credential +
//      computed expiry + effective scopes.
//   6. Return updated payload via `PluginResult::modify_payload`.
//
// # Error handling
//
// Construction errors → `Box<PluginError>` (`PluginError::Config`).
// Runtime errors → `PluginResult::deny(PluginViolation::new(code,
// reason))`:
//   * `delegation.idp_unreachable` — network failure
//   * `delegation.idp_timeout` — exceeded `timeout_seconds`
//   * `delegation.idp_rejected` — IdP returned 4xx/5xx
//   * `delegation.bad_response` — response not valid JSON or
//                                 missing required fields
//   * `delegation.scope_too_broad` — IdP returned a token whose
//                                    scopes don't include all
//                                    requested permissions

use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;
use zeroize::Zeroizing;

use cpex_core::context::PluginContext;
use cpex_core::delegation::{DelegationPayload, TokenDelegateHook};
use cpex_core::error::{PluginError, PluginViolation};
use cpex_core::extensions::raw_credentials::{DelegationMode, RawDelegatedToken};
use cpex_core::hooks::payload::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::plugin::{Plugin, PluginConfig};

use super::config::OAuthDelegatorConfig;

/// RFC 8693 token-exchange grant type — the value of
/// `grant_type` in the form-encoded request body.
const GRANT_TYPE_TOKEN_EXCHANGE: &str =
    "urn:ietf:params:oauth:grant-type:token-exchange";

/// Default issued-token-type RFC 8693 returns. We don't rely on it
/// for behavior — it's reported back to operators in audit logs
/// only.
const DEFAULT_ISSUED_TOKEN_TYPE: &str =
    "urn:ietf:params:oauth:token-type:access_token";

/// OAuth-mediated `TokenDelegate` handler.
pub struct OAuthDelegator {
    cfg: PluginConfig,
    typed: OAuthDelegatorConfig,
    /// Loaded client secret, zeroized on drop.
    client_secret: Zeroizing<String>,
    /// Shared HTTP client. Pre-built so repeated invocations
    /// reuse connections / TLS sessions.
    http: reqwest::Client,
}

impl std::fmt::Debug for OAuthDelegator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthDelegator")
            .field("cfg", &self.cfg.name)
            .field("token_endpoint", &self.typed.token_endpoint)
            .field("client_id", &self.typed.client_id)
            .field("client_secret", &"<elided>")
            .finish()
    }
}

impl OAuthDelegator {
    /// Build a delegator from a `PluginConfig`. Reads `cfg.config`
    /// into [`OAuthDelegatorConfig`], resolves the client secret,
    /// constructs the shared `reqwest::Client`.
    pub fn new(cfg: PluginConfig) -> Result<Self, Box<PluginError>> {
        let raw = cfg.config.as_ref().ok_or_else(|| {
            Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (cpex-plugin-delegator-oauth) requires a `config:` block",
                    cfg.name
                ),
            })
        })?;
        let typed: OAuthDelegatorConfig = serde_json::from_value(raw.clone())
            .map_err(|e| {
                Box::new(PluginError::Config {
                    message: format!(
                        "plugin '{}' (cpex-plugin-delegator-oauth) config parse failed: {e}",
                        cfg.name
                    ),
                })
            })?;

        if typed.token_endpoint.trim().is_empty() {
            return Err(Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (cpex-plugin-delegator-oauth): token_endpoint must be non-empty",
                    cfg.name
                ),
            }));
        }
        // Reject http:// for token_endpoint by default. The exchange
        // POST sends client_id:client_secret + inbound user JWT;
        // sending these over plaintext defeats the whole flow.
        // `insecure_http: true` is the conscious opt-out for
        // localhost docker-compose demos.
        if let Err(e) = require_https(&typed.token_endpoint, typed.insecure_http) {
            return Err(Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (cpex-plugin-delegator-oauth): token_endpoint {e}",
                    cfg.name,
                ),
            }));
        }
        if typed.client_id.trim().is_empty() {
            return Err(Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (cpex-plugin-delegator-oauth): client_id must be non-empty",
                    cfg.name
                ),
            }));
        }

        let secret = typed.client_secret_source.resolve().map_err(|e| {
            Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (cpex-plugin-delegator-oauth) client secret resolve failed: {e}",
                    cfg.name
                ),
            })
        })?;

        let http = reqwest::Client::builder()
            .timeout(typed.timeout())
            .build()
            .map_err(|e| {
                Box::new(PluginError::Config {
                    message: format!(
                        "plugin '{}' (cpex-plugin-delegator-oauth) HTTP client build failed: {e}",
                        cfg.name
                    ),
                })
            })?;

        Ok(Self {
            cfg,
            typed,
            client_secret: Zeroizing::new(secret),
            http,
        })
    }

    /// Compose the requested scope set: the target's required
    /// permissions plus any extra capabilities from
    /// `route_attenuation`. Returns a space-separated string per
    /// OAuth conventions.
    fn requested_scopes(payload: &DelegationPayload) -> String {
        let mut scopes: Vec<String> = payload.required_permissions().to_vec();
        if let Some(att) = payload.route_attenuation() {
            for cap in &att.capabilities {
                if !scopes.contains(cap) {
                    scopes.push(cap.clone());
                }
            }
        }
        scopes.join(" ")
    }
}

/// Subset of the RFC 8693 response we care about.
#[derive(Debug, Deserialize)]
struct TokenExchangeResponse {
    access_token: String,
    /// Optional per RFC — defaults to `access_token` issued type.
    #[serde(default)]
    issued_token_type: Option<String>,
    /// Optional in RFC; many IdPs send it.
    #[serde(default)]
    expires_in: Option<i64>,
    /// Space-separated effective scopes the IdP actually granted.
    /// May be narrower than what we requested.
    #[serde(default)]
    scope: Option<String>,
}

/// Subset of the standard OAuth error response — `error` is the
/// machine-readable code (`invalid_grant`, `invalid_scope`, …).
#[derive(Debug, Deserialize)]
struct TokenErrorResponse {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

#[async_trait]
impl Plugin for OAuthDelegator {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<TokenDelegateHook> for OAuthDelegator {
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
                "DelegationPayload carried an empty bearer_token — outbound \
                 caller didn't populate the credential before invoking the hook",
            ));
        }
        let audience = payload.target_audience().unwrap_or("");
        if audience.is_empty() {
            return PluginResult::deny(PluginViolation::new(
                "delegation.bad_request",
                "target_audience missing — RFC 8693 token exchange requires \
                 an audience to scope the minted credential",
            ));
        }

        let scope = Self::requested_scopes(payload);

        // Build the form-encoded body. RFC 8693 §2.1.
        let mut form: Vec<(&str, &str)> = vec![
            ("grant_type", GRANT_TYPE_TOKEN_EXCHANGE),
            ("subject_token", bearer),
            ("subject_token_type", &self.typed.subject_token_type),
            ("audience", audience),
        ];
        if !scope.is_empty() {
            form.push(("scope", &scope));
        }

        // POST to the IdP. Basic auth carries our client credentials.
        let response = match self
            .http
            .post(&self.typed.token_endpoint)
            .basic_auth(&self.typed.client_id, Some(self.client_secret.as_str()))
            .form(&form)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) if e.is_timeout() => {
                return PluginResult::deny(PluginViolation::new(
                    "delegation.idp_timeout",
                    format!("token-exchange to {} timed out", self.typed.token_endpoint),
                ));
            }
            Err(e) => {
                return PluginResult::deny(PluginViolation::new(
                    "delegation.idp_unreachable",
                    format!(
                        "token-exchange POST to {} failed: {e}",
                        self.typed.token_endpoint,
                    ),
                ));
            }
        };

        let status = response.status();
        if !status.is_success() {
            // Try to surface the standard `error` / `error_description`
            // fields from the IdP. Fall back to status code.
            let body = response.text().await.unwrap_or_default();
            let (code, reason) = match serde_json::from_str::<TokenErrorResponse>(&body)
            {
                Ok(err) => {
                    let mut reason = err.error.clone();
                    if let Some(desc) = err.error_description {
                        reason.push_str(": ");
                        reason.push_str(&desc);
                    }
                    ("delegation.idp_rejected", reason)
                }
                Err(_) => (
                    "delegation.idp_rejected",
                    format!("IdP returned {status}: {body}"),
                ),
            };
            return PluginResult::deny(PluginViolation::new(code, reason));
        }

        let parsed = match response.json::<TokenExchangeResponse>().await {
            Ok(p) => p,
            Err(e) => {
                return PluginResult::deny(PluginViolation::new(
                    "delegation.bad_response",
                    format!("IdP response wasn't valid token-exchange JSON: {e}"),
                ));
            }
        };

        // Compute effective scopes. IdP's `scope` field wins (it
        // reflects what was actually granted, possibly narrower
        // than what we asked for); fall back to the requested set
        // if the IdP didn't send one.
        let effective_scopes: Vec<String> = if let Some(s) = &parsed.scope {
            s.split_whitespace().map(String::from).collect()
        } else if !scope.is_empty() {
            scope.split_whitespace().map(String::from).collect()
        } else {
            Vec::new()
        };

        // Enforce requested ⊆ effective. Without this check, a route
        // that asked for `read write` and got back `read` would
        // proceed as if the broader grant had succeeded — downstream
        // calls would fail in policy-author-unobservable ways. We
        // compare only when the IdP explicitly sent a `scope` field
        // (otherwise we just used the requested set above, so the
        // subset relationship is trivially true). The required
        // permissions come straight off the DelegationPayload; route
        // attenuation capabilities are advisory extras and not
        // checked here.
        if parsed.scope.is_some() {
            let granted: std::collections::HashSet<&str> =
                effective_scopes.iter().map(String::as_str).collect();
            let missing: Vec<&str> = payload
                .required_permissions()
                .iter()
                .filter(|req| !granted.contains(req.as_str()))
                .map(String::as_str)
                .collect();
            if !missing.is_empty() {
                return PluginResult::deny(PluginViolation::new(
                    "delegation.scope_too_broad",
                    format!(
                        "IdP granted narrower scopes than requested. \
                         requested=[{}] granted=[{}] missing=[{}]",
                        payload.required_permissions().join(" "),
                        effective_scopes.join(" "),
                        missing.join(" "),
                    ),
                ));
            }
        }

        // Compute expiry. Most IdPs send `expires_in` (seconds);
        // if missing, default to 5 minutes — short enough that a
        // misconfigured-but-no-expiry IdP doesn't mint long-lived
        // tokens by accident.
        let ttl_secs = parsed.expires_in.unwrap_or(300);
        // Route attenuation may shorten further.
        let ttl_secs = if let Some(att) = payload.route_attenuation() {
            if let Some(hint) = att.ttl_seconds {
                ttl_secs.min(hint as i64)
            } else {
                ttl_secs
            }
        } else {
            ttl_secs
        };
        let expires_at = Utc::now() + chrono::Duration::seconds(ttl_secs);

        let token = RawDelegatedToken::new(
            parsed.access_token,
            self.typed.default_outbound_header.clone(),
            audience.to_string(),
            effective_scopes,
            expires_at,
        );

        let mut updated = payload.clone();
        updated.delegated_token = Some(token);
        updated.delegation_mode = Some(DelegationMode::OnBehalfOfUser);
        updated.minted_at = Some(Utc::now());
        if let Some(issued) = parsed.issued_token_type {
            updated.metadata.insert(
                "issued_token_type".into(),
                serde_json::Value::String(issued),
            );
        } else {
            updated.metadata.insert(
                "issued_token_type".into(),
                serde_json::Value::String(DEFAULT_ISSUED_TOKEN_TYPE.into()),
            );
        }

        PluginResult::modify_payload(updated)
    }
}

// Silence unused-import warning when only a subset of these is
// reached in any given config path. Kept as a single place so the
// crate's surface is visible at a glance.
#[allow(dead_code)]
fn _force_link(_: Arc<()>) {}

/// Reject `http://` for endpoints that carry credentials. Allows
/// `https://` unconditionally and `http://` only when the operator
/// explicitly set `insecure_http: true`. Empty / un-parseable URLs
/// are returned as-is to whatever validator already exists upstream
/// — this helper only owns the scheme check.
///
/// Returns a short fragment ("must use https://…") that the caller
/// prepends with the field name + plugin name for the full error
/// message.
fn require_https(url: &str, insecure_http: bool) -> Result<(), String> {
    let lowered = url.trim_start().to_ascii_lowercase();
    if lowered.starts_with("https://") {
        return Ok(());
    }
    if lowered.starts_with("http://") {
        if insecure_http {
            return Ok(());
        }
        return Err(format!(
            "must use https:// (got '{url}'). Set `insecure_http: true` \
             to allow plaintext for localhost/dev only — never production."
        ));
    }
    // Anything else (missing scheme, bad scheme): defer to the
    // upstream URL parser. We're not the URL validator, just the
    // scheme gate.
    Ok(())
}

#[cfg(test)]
mod scheme_tests {
    use super::require_https;

    #[test]
    fn https_always_ok() {
        assert!(require_https("https://idp.example/oauth/token", false).is_ok());
        assert!(require_https("HTTPS://IDP.EXAMPLE/", false).is_ok());
    }

    #[test]
    fn http_default_rejected() {
        let err = require_https("http://localhost:8081/oauth/token", false).unwrap_err();
        assert!(err.contains("must use https"), "{}", err);
        assert!(err.contains("insecure_http"), "mentions opt-out: {}", err);
    }

    #[test]
    fn http_with_explicit_opt_in_allowed() {
        assert!(require_https("http://localhost:8081/oauth/token", true).is_ok());
    }

    #[test]
    fn http_with_leading_whitespace_still_rejected() {
        // A trailing newline or leading whitespace from sloppy YAML
        // shouldn't smuggle a plaintext URL past the gate.
        let err = require_https("  http://idp/", false).unwrap_err();
        assert!(err.contains("must use https"));
    }
}
