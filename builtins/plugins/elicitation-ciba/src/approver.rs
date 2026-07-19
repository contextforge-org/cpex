// Location: ./builtins/plugins/elicitation-ciba/src/approver.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// `CibaApprover` — `HookHandler<ElicitationHook>` that reaches a human
// through OIDC CIBA. One `handle` entry point dispatches on
// `ElicitationPayload::operation` to the three short, synchronous
// round-trips:
//
//   * dispatch → backchannel auth POST (`login_hint` / `binding_message`
//                / `scope`) → `auth_req_id` (used as the elicitation id).
//   * check    → token-endpoint poll (`grant_type=...:ciba` +
//                `auth_req_id`) → pending / approved / denied / expired. On
//                approval, extract the approver claim from the OP token and
//                store *that* (never the token — see store.rs).
//   * validate → cross-check the resolved approver (stored at check)
//                against the expected `login_hint`.
//
// # Error handling
//
// Construction errors → `Box<PluginError>` (`PluginError::Config`).
// Runtime *failures* (network, OP rejection, malformed response) →
// `PluginResult::deny(PluginViolation::new(code, reason))`, which the
// apl-cpex bridge maps to an `ElicitationError` and the apl-core
// evaluator then routes through the step's `on_error`. Normal lifecycle
// *states* (pending / approved / denied / expired) are NOT failures —
// they're returned as data on the payload via `modify_payload`.

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use chrono::Utc;
use serde::Deserialize;
use zeroize::Zeroizing;

use cpex_core::context::PluginContext;
use cpex_core::elicitation::{
    ElicitationHook, ElicitationOp, ElicitationOutcomeKind, ElicitationPayload,
    ElicitationStatusKind,
};
use cpex_core::error::{PluginError, PluginViolation};
use cpex_core::hooks::payload::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::plugin::{Plugin, PluginConfig};

use crate::config::{require_https, CibaConfig};
use crate::store::{Correlation, CorrelationStore, InMemoryCorrelationStore};

/// OIDC CIBA grant type for the token-endpoint poll.
const GRANT_TYPE_CIBA: &str = "urn:openid:params:grant-type:ciba";

/// CIBA `ElicitationHook` handler.
pub struct CibaApprover {
    cfg: PluginConfig,
    typed: CibaConfig,
    client_secret: Zeroizing<String>,
    http: reqwest::Client,
    store: Arc<dyn CorrelationStore>,
}

impl std::fmt::Debug for CibaApprover {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CibaApprover")
            .field("plugin", &self.cfg.name)
            .field("backchannel_endpoint", &self.typed.backchannel_endpoint)
            .field("client_id", &self.typed.client_id)
            .field("client_secret", &"<elided>")
            .finish()
    }
}

impl CibaApprover {
    /// Build from a `PluginConfig`: parse `cfg.config` into [`CibaConfig`],
    /// validate endpoints (https unless `insecure_http`), resolve the
    /// client secret, and build the shared HTTP client.
    pub fn new(cfg: PluginConfig) -> Result<Self, Box<PluginError>> {
        let raw = cfg
            .config
            .as_ref()
            .ok_or_else(|| cfg_err(&cfg.name, "requires a `config:` block".to_string()))?;
        let typed: CibaConfig = serde_json::from_value(raw.clone())
            .map_err(|e| cfg_err(&cfg.name, format!("config parse failed: {e}")))?;

        for (field, url) in [
            ("backchannel_endpoint", &typed.backchannel_endpoint),
            ("token_endpoint", &typed.token_endpoint),
        ] {
            if url.trim().is_empty() {
                return Err(cfg_err(&cfg.name, format!("{field} must be non-empty")));
            }
            if let Err(e) = require_https(url, typed.insecure_http) {
                return Err(cfg_err(&cfg.name, format!("{field} {e}")));
            }
        }
        if typed.client_id.trim().is_empty() {
            return Err(cfg_err(
                &cfg.name,
                "client_id must be non-empty".to_string(),
            ));
        }

        let secret = typed
            .client_secret_source
            .resolve()
            .map_err(|e| cfg_err(&cfg.name, format!("client secret resolve failed: {e}")))?;

        let http = reqwest::Client::builder()
            .timeout(typed.http_timeout())
            .build()
            .map_err(|e| cfg_err(&cfg.name, format!("HTTP client build failed: {e}")))?;

        Ok(Self {
            cfg,
            typed,
            client_secret: Zeroizing::new(secret),
            http,
            store: Arc::new(InMemoryCorrelationStore::new()),
        })
    }

    async fn do_dispatch(&self, payload: &ElicitationPayload) -> PluginResult<ElicitationPayload> {
        let login_hint = payload.from();
        if login_hint.is_empty() {
            return deny(
                "elicitation.bad_request",
                "CIBA dispatch requires a resolved approver (login_hint) — `from` \
                 resolved to empty",
            );
        }

        // `requested_expiry` from the step timeout (e.g. "24h"), else the
        // configured default. CIBA wants seconds.
        let requested_expiry = payload
            .timeout()
            .and_then(parse_duration_secs)
            .unwrap_or(self.typed.default_requested_expiry_seconds);
        let requested_expiry = requested_expiry.to_string();

        // Keycloak constrains `binding_message`: ≤50 chars, no spaces,
        // basic plain-text only (verified against Keycloak 26 — a raw
        // purpose with spaces/`$`/punctuation is rejected
        // `invalid_binding_message`). CIBA's binding_message is an
        // anti-phishing correlation code shown on both devices, not the
        // full transaction text — the canonical, human-readable `purpose`
        // is recorded upstream (apl-core audit). So derive a valid code
        // from it. See docs/keycloak-ciba-phase0-runbook.md.
        let binding_message = payload.purpose().map(sanitize_binding_message);

        let mut form: Vec<(&str, &str)> = vec![
            ("scope", &self.typed.scope),
            ("login_hint", login_hint),
            ("requested_expiry", &requested_expiry),
        ];
        if let Some(bm) = &binding_message {
            if !bm.is_empty() {
                form.push(("binding_message", bm));
            }
        }

        let response = match self
            .http
            .post(&self.typed.backchannel_endpoint)
            .basic_auth(&self.typed.client_id, Some(self.client_secret.as_str()))
            .form(&form)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) if e.is_timeout() => {
                return deny(
                    "elicitation.op_timeout",
                    format!("CIBA backchannel POST timed out: {e}"),
                );
            },
            Err(e) => {
                return deny(
                    "elicitation.op_unreachable",
                    format!(
                        "CIBA backchannel POST to {} failed: {e}",
                        self.typed.backchannel_endpoint
                    ),
                );
            },
        };

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return deny(
                "elicitation.op_rejected",
                format!("CIBA backchannel rejected ({status}): {body}"),
            );
        }

        let parsed = match response.json::<BackchannelResponse>().await {
            Ok(p) => p,
            Err(e) => {
                return deny(
                    "elicitation.bad_response",
                    format!("CIBA backchannel response wasn't valid JSON: {e}"),
                );
            },
        };

        // The `auth_req_id` IS the elicitation id the agent echoes on
        // retry — opaque and unique, no separate id to generate.
        let id = parsed.auth_req_id;
        self.store.put(
            &id,
            Correlation {
                expected_approver: login_hint.to_string(),
                resolved_approver: None,
            },
        );

        let expires_at = parsed
            .expires_in
            .map(|secs| (Utc::now() + chrono::Duration::seconds(secs)).to_rfc3339());

        let mut out = payload.clone();
        out.id = Some(id);
        out.status = Some(ElicitationStatusKind::Pending);
        out.approver = Some(login_hint.to_string());
        out.expires_at = expires_at;
        PluginResult::modify_payload(out)
    }

    async fn do_check(&self, payload: &ElicitationPayload) -> PluginResult<ElicitationPayload> {
        let id = match payload.elicitation_id() {
            Some(id) => id,
            None => {
                return deny(
                    "elicitation.bad_request",
                    "CIBA check requires an elicitation id",
                )
            },
        };

        // Cache short-circuit. The OP's `auth_req_id` is single-use: once a
        // poll succeeds we exchange it for tokens (consuming it) and cache
        // just the approver. A later check — e.g. the confirm-then-apply
        // retry after a `peek` already resolved approval — must NOT re-poll
        // (the spent id would come back `invalid_grant`). Replay the cached
        // approved result instead; `validate` re-compares the approver.
        if let Some(corr) = self.store.get(id) {
            if corr.resolved_approver.is_some() {
                let mut out = payload.clone();
                out.status = Some(ElicitationStatusKind::Resolved);
                out.outcome = Some(ElicitationOutcomeKind::Approved);
                return PluginResult::modify_payload(out);
            }
        }

        let form: Vec<(&str, &str)> = vec![("grant_type", GRANT_TYPE_CIBA), ("auth_req_id", id)];

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
                return deny(
                    "elicitation.op_timeout",
                    format!("CIBA token poll timed out: {e}"),
                );
            },
            Err(e) => {
                return deny(
                    "elicitation.op_unreachable",
                    format!(
                        "CIBA token poll to {} failed: {e}",
                        self.typed.token_endpoint
                    ),
                );
            },
        };

        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        if status.is_success() {
            // Approved — the OP handed back tokens (once). Extract the
            // approver claim NOW and store just that string; we never keep
            // the token at rest (see store.rs). `validate` then compares
            // the stored expected vs resolved approver.
            let parsed: TokenResponse = match serde_json::from_str(&body) {
                Ok(p) => p,
                Err(e) => {
                    return deny(
                        "elicitation.bad_response",
                        format!("CIBA token response wasn't valid JSON: {e}"),
                    );
                },
            };
            // Prefer the id_token (carries user claims); fall back to the
            // access_token. Extract the approver claim and drop the token.
            if let Some(token) = parsed.id_token.or(parsed.access_token) {
                if let Some(approver) = decode_jwt_claim(&token, &self.typed.approver_claim) {
                    self.store.set_resolved_approver(id, approver);
                }
                // token dropped here — never persisted.
            }
            let mut out = payload.clone();
            out.status = Some(ElicitationStatusKind::Resolved);
            out.outcome = Some(ElicitationOutcomeKind::Approved);
            return PluginResult::modify_payload(out);
        }

        // Non-2xx: a standard OAuth error body drives the lifecycle.
        let err_code = serde_json::from_str::<OAuthError>(&body)
            .map(|e| e.error)
            .unwrap_or_default();

        let (status_kind, outcome) = match err_code.as_str() {
            // Still waiting — both mean "keep polling".
            "authorization_pending" | "slow_down" => (ElicitationStatusKind::Pending, None),
            "expired_token" => (ElicitationStatusKind::Expired, None),
            "access_denied" => (
                ElicitationStatusKind::Resolved,
                Some(ElicitationOutcomeKind::Denied),
            ),
            // Anything else is a genuine failure, not a lifecycle state.
            _ => {
                return deny(
                    "elicitation.op_rejected",
                    format!("CIBA token poll failed ({status}): {body}"),
                );
            },
        };

        let mut out = payload.clone();
        out.status = Some(status_kind);
        out.outcome = outcome;
        PluginResult::modify_payload(out)
    }

    async fn do_validate(&self, payload: &ElicitationPayload) -> PluginResult<ElicitationPayload> {
        let id = match payload.elicitation_id() {
            Some(id) => id,
            None => {
                return deny(
                    "elicitation.bad_request",
                    "CIBA validate requires an elicitation id",
                )
            },
        };

        let correlation = match self.store.get(id) {
            Some(c) => c,
            None => return invalid(payload, "unknown elicitation id"),
        };
        // Both sides of this comparison are values already stored from the
        // OP's authenticated TLS response, not a token read at rest — this
        // check only asks whether the approver who resolved matches the
        // approver who was asked.
        let resolved = match &correlation.resolved_approver {
            Some(a) => a,
            None => {
                return invalid(
                    payload,
                    &format!(
                        "elicitation has no resolved approver (no `{}` claim was \
                         extracted at check, or it hasn't resolved)",
                        self.typed.approver_claim
                    ),
                )
            },
        };

        let mut out = payload.clone();
        out.approver = Some(resolved.clone());
        if *resolved == correlation.expected_approver {
            out.valid = Some(true);
        } else {
            out.valid = Some(false);
            out.reason = Some(format!(
                "approver mismatch: token names `{resolved}`, expected `{}`",
                correlation.expected_approver
            ));
        }
        PluginResult::modify_payload(out)
    }
}

#[async_trait]
impl Plugin for CibaApprover {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<ElicitationHook> for CibaApprover {
    async fn handle(
        &self,
        payload: &ElicitationPayload,
        _ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<ElicitationPayload> {
        match payload.operation() {
            ElicitationOp::Dispatch => self.do_dispatch(payload).await,
            ElicitationOp::Check => self.do_check(payload).await,
            ElicitationOp::Validate => self.do_validate(payload).await,
        }
    }
}

/// CIBA backchannel auth response (OIDC CIBA core §7.3).
#[derive(Debug, Deserialize)]
struct BackchannelResponse {
    auth_req_id: String,
    #[serde(default)]
    expires_in: Option<i64>,
}

/// Token-endpoint success body (the slice we need).
#[derive(Debug, Deserialize)]
struct TokenResponse {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
}

/// Standard OAuth error body — `error` is the machine code
/// (`authorization_pending`, `access_denied`, …).
#[derive(Debug, Deserialize, Default)]
struct OAuthError {
    #[serde(default)]
    error: String,
}

fn cfg_err(plugin: &str, msg: String) -> Box<PluginError> {
    Box::new(PluginError::Config {
        message: format!("plugin '{plugin}' (cpex-plugin-elicitation-ciba): {msg}"),
    })
}

fn deny(code: &str, reason: impl Into<String>) -> PluginResult<ElicitationPayload> {
    PluginResult::deny(PluginViolation::new(code, reason.into()))
}

/// `validate` failure that is a *verdict*, not a transport error: the
/// payload comes back with `valid = false` and a reason, and the bridge
/// reads that — the runtime then denies. (A `deny` here would instead be
/// an `on_error` failure path.)
fn invalid(payload: &ElicitationPayload, reason: &str) -> PluginResult<ElicitationPayload> {
    let mut out = payload.clone();
    out.valid = Some(false);
    out.reason = Some(reason.to_string());
    PluginResult::modify_payload(out)
}

/// Derive a Keycloak-valid CIBA `binding_message` *cue* from a free-text
/// purpose. Keycloak requires ≤50 chars, no spaces, basic plain-text.
///
/// `binding_message` is NOT the approver-facing description — by CIBA
/// design it is a short anti-phishing **correlation cue** shown on both
/// the requester's and the approver's devices so the human can confirm
/// they're approving the same transaction. The full, canonical
/// human-readable context is the step's `purpose` (kept verbatim in the
/// apl-core audit record) and is delivered to the approver's device by
/// the Authentication Channel + intent registry — see
/// `docs/apl-manager-approval-ciba-design.md` (§ binding_message &
/// approver-facing context).
///
/// To keep the cue readable rather than mangled, **whitespace runs become
/// a single `-`** and every *other* disallowed character (`$`, `,`, `'`,
/// non-ASCII) is **dropped**, not dashed. So "Approve Bob's $25,000 raise
/// for Jane Smith" → "Approve-Bobs-25000-raise-for-Jane-Smith". Capped at
/// 50, trailing `-` trimmed.
fn sanitize_binding_message(purpose: &str) -> String {
    let mut out = String::new();
    let mut prev_dash = false;
    for ch in purpose.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            prev_dash = false;
        } else if ch.is_whitespace() && !out.is_empty() && !prev_dash {
            out.push('-');
            prev_dash = true;
        }
        // Any other disallowed char is dropped (keeps the cue readable).
    }
    let capped: String = out.chars().take(50).collect();
    capped.trim_end_matches('-').to_string()
}

/// Parse a duration string (`"30"`, `"30s"`, `"5m"`, `"24h"`, `"2d"`)
/// into seconds. Bare numbers are seconds. Returns `None` on anything
/// unparseable so the caller can fall back to a default.
fn parse_duration_secs(s: &str) -> Option<u64> {
    let s = s.trim();
    let last = s.chars().last()?;
    let (num, mult) = match last {
        's' => (&s[..s.len() - 1], 1),
        'm' => (&s[..s.len() - 1], 60),
        'h' => (&s[..s.len() - 1], 3600),
        'd' => (&s[..s.len() - 1], 86_400),
        c if c.is_ascii_digit() => (s, 1),
        _ => return None,
    };
    num.trim().parse::<u64>().ok().map(|n| n * mult)
}

/// Decode a single string claim from a JWT's payload segment. Claims
/// extraction only — does NOT verify the signature (see the validate
/// notes). Returns `None` if the token is malformed or the claim is
/// absent / non-string.
fn decode_jwt_claim(token: &str, claim: &str) -> Option<String> {
    let payload_b64 = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    let json: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    json.get(claim)?.as_str().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_units() {
        assert_eq!(parse_duration_secs("30"), Some(30));
        assert_eq!(parse_duration_secs("30s"), Some(30));
        assert_eq!(parse_duration_secs("5m"), Some(300));
        assert_eq!(parse_duration_secs("24h"), Some(86_400));
        assert_eq!(parse_duration_secs("2d"), Some(172_800));
        assert_eq!(parse_duration_secs("nonsense"), None);
        assert_eq!(parse_duration_secs(""), None);
    }

    #[test]
    fn binding_message_is_keycloak_valid() {
        // The real-world purpose that Keycloak rejected raw.
        let bm = sanitize_binding_message("Approve Bob's $25,000 raise for Jane Smith");
        assert!(bm.len() <= 50);
        assert!(!bm.contains(' '));
        assert!(bm.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
        // Whitespace → single `-`; `'`, `$`, `,` dropped (not dashed).
        assert_eq!(bm, "Approve-Bobs-25000-raise-for-Jane-Smith");
        // Caps at 50 and trims a trailing separator.
        let long = sanitize_binding_message(&"x ".repeat(60));
        assert!(long.len() <= 50);
        assert!(!long.ends_with('-'));
        // Empty / all-punctuation collapses to empty (no binding_message sent).
        assert_eq!(sanitize_binding_message("   —   "), "");
    }

    #[test]
    fn decode_claim_from_jwt() {
        // Build a fake JWT: header.payload.sig, payload carries
        // preferred_username. Signature is irrelevant to claim extraction.
        let payload = serde_json::json!({ "preferred_username": "alice", "sub": "u-1" });
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).unwrap());
        let token = format!("aaa.{b64}.bbb");
        assert_eq!(
            decode_jwt_claim(&token, "preferred_username").as_deref(),
            Some("alice")
        );
        assert_eq!(decode_jwt_claim(&token, "sub").as_deref(), Some("u-1"));
        assert!(decode_jwt_claim(&token, "missing").is_none());
        assert!(decode_jwt_claim("not-a-jwt", "sub").is_none());
    }
}
