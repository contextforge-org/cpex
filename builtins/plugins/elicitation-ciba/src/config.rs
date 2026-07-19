// Location: ./builtins/plugins/elicitation-ciba/src/config.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Typed configuration for `CibaApprover`. Deserializes from the
// plugin's `PluginConfig.config` field; the approver's constructor reads
// it and builds the runtime state (the shared `reqwest::Client`, the
// loaded client secret).

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// What operators write under `plugins[<name>].config:` in unified
/// config YAML for a CIBA elicitation handler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CibaConfig {
    /// OIDC CIBA backchannel authentication endpoint — where the
    /// `dispatch` POST lands (e.g.
    /// `https://kc/realms/corp/protocol/openid-connect/ext/ciba/auth`).
    pub backchannel_endpoint: String,

    /// OP token endpoint — where the `check` poll lands with
    /// `grant_type=urn:openid:params:grant-type:ciba` (e.g.
    /// `https://kc/realms/corp/protocol/openid-connect/token`).
    pub token_endpoint: String,

    /// OAuth `client_id` identifying our gateway to the OP. The gateway
    /// is the CIBA *client* that initiates the backchannel request.
    pub client_id: String,

    /// Where to load the client secret from. See [`ClientSecretSource`].
    pub client_secret_source: ClientSecretSource,

    /// OAuth scopes to request on the backchannel auth request. CIBA
    /// requires at least `openid`. This is the *OAuth* scope (what the
    /// minted token may do), distinct from the APL `scope` arg-binding
    /// expression — that one is checked by the apl-core runtime.
    #[serde(default = "default_scope")]
    pub scope: String,

    /// Default `requested_expiry` (seconds) for the elicitation when the
    /// step doesn't carry a `timeout`. How long the approval stays
    /// pollable.
    #[serde(default = "default_requested_expiry_seconds")]
    pub default_requested_expiry_seconds: u64,

    /// Per-call HTTP timeout. Each dispatch/check/validate is a short
    /// round-trip; 5s keeps the request hot path bounded.
    #[serde(default = "default_http_timeout_seconds")]
    pub http_timeout_seconds: u64,

    /// Which token claim names the approver, cross-checked at `validate`
    /// against the `login_hint`. Keycloak's default username claim is
    /// `preferred_username`; deployments keyed on `sub` set that instead.
    #[serde(default = "default_approver_claim")]
    pub approver_claim: String,

    /// Explicitly allow `http://` for the endpoints. By default the
    /// constructor rejects plaintext because the requests carry
    /// `client_id:client_secret`. Set `true` ONLY for `http://localhost`
    /// development against a docker-compose Keycloak.
    #[serde(default)]
    pub insecure_http: bool,
}

/// Where the gateway's OAuth client secret is loaded from. Mirrors
/// `apl-delegator-oauth`'s source enum — env var (production), file
/// (k8s secret volume), or literal (tests/dev only).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClientSecretSource {
    EnvVar { name: String },
    File { path: PathBuf },
    Literal { secret: String },
}

fn default_scope() -> String {
    "openid".to_string()
}

fn default_requested_expiry_seconds() -> u64 {
    300
}

fn default_http_timeout_seconds() -> u64 {
    5
}

fn default_approver_claim() -> String {
    "preferred_username".to_string()
}

impl CibaConfig {
    /// Per-call HTTP timeout as a `Duration`.
    pub fn http_timeout(&self) -> Duration {
        Duration::from_secs(self.http_timeout_seconds)
    }
}

impl ClientSecretSource {
    /// Resolve the secret at construction time. Errors as a string the
    /// caller wraps in `PluginError::Config`.
    pub fn resolve(&self) -> Result<String, String> {
        match self {
            Self::EnvVar { name } => {
                std::env::var(name).map_err(|e| format!("env var '{name}' unavailable: {e}"))
            },
            Self::File { path } => std::fs::read_to_string(path)
                .map(|s| s.trim().to_string())
                .map_err(|e| format!("secret file '{}' unreadable: {e}", path.display())),
            Self::Literal { secret } => Ok(secret.clone()),
        }
    }
}

/// Reject `http://` for endpoints that carry credentials. `https://` is
/// always allowed; `http://` only when `insecure_http` is set. Other
/// schemes defer to the upstream URL parser. Returns a short fragment
/// the caller prefixes with field + plugin name.
pub(crate) fn require_https(url: &str, insecure_http: bool) -> Result<(), String> {
    let lowered = url.trim_start().to_ascii_lowercase();
    if lowered.starts_with("https://") {
        return Ok(());
    }
    if lowered.starts_with("http://") {
        if insecure_http {
            return Ok(());
        }
        return Err(format!(
            "must use https:// (got '{url}'). Set `insecure_http: true` to allow \
             plaintext for localhost/dev only — never production."
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn config_deserializes_with_defaults() {
        let raw = json!({
            "backchannel_endpoint": "https://kc/realms/corp/protocol/openid-connect/ext/ciba/auth",
            "token_endpoint": "https://kc/realms/corp/protocol/openid-connect/token",
            "client_id": "cpex-gateway",
            // aislop-ignore-next-line ai-slop/hardcoded-id -- Literal-secret-source test fixture, not a real credential
            "client_secret_source": { "kind": "literal", "secret": "dev-only" },
        });
        let cfg: CibaConfig = serde_json::from_value(raw).unwrap();
        assert_eq!(cfg.client_id, "cpex-gateway");
        assert_eq!(cfg.scope, "openid");
        assert_eq!(cfg.default_requested_expiry_seconds, 300);
        assert_eq!(cfg.http_timeout_seconds, 5);
        assert_eq!(cfg.approver_claim, "preferred_username");
        assert!(!cfg.insecure_http);
    }

    #[test]
    fn literal_secret_resolves() {
        let src = ClientSecretSource::Literal {
            secret: "hush".into(),
        };
        assert_eq!(src.resolve().unwrap(), "hush");
    }

    #[test]
    fn https_gate() {
        assert!(require_https("https://kc/", false).is_ok());
        assert!(require_https("http://localhost:8080/", false).is_err());
        assert!(require_https("http://localhost:8080/", true).is_ok());
    }
}
