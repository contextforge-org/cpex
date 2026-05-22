// Location: ./crates/apl-delegator-oauth/src/config.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Typed configuration for `OAuthDelegator`. Deserializes from the
// plugin's `PluginConfig.config: Option<JsonValue>` field; the
// delegator's constructor reads this and builds the runtime state
// (the `reqwest::Client`, the loaded client secret).
//
// Serializable intermediate representations stand in for non-
// serializable runtime types (e.g., the secret is loaded from
// env-var / file / literal at construction time, never serialized
// back out).

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Top-level plugin config — what operators write under
/// `plugins[<name>].config:` in unified-config YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthDelegatorConfig {
    /// IdP's token endpoint URL — where the token-exchange POST
    /// lands (e.g., `https://auth.example.com/oauth/token`).
    pub token_endpoint: String,

    /// OAuth `client_id` identifying our gateway to the IdP. The
    /// IdP authenticates us with `(client_id, client_secret)` over
    /// HTTP Basic / form-body before honoring the exchange request.
    pub client_id: String,

    /// Where to load the client secret from. See [`ClientSecretSource`].
    pub client_secret_source: ClientSecretSource,

    /// What `subject_token_type` we tell the IdP the inbound token
    /// is. RFC 8693 defines `access_token`, `refresh_token`,
    /// `id_token`, `jwt`, `saml1`, `saml2`. Most deployments use
    /// access_token — that's the default.
    #[serde(default = "default_subject_token_type")]
    pub subject_token_type: String,

    /// Request timeout. The exchange is on the request hot path —
    /// a 5s default keeps requests bounded if the IdP is slow.
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,

    /// Header name the forwarding plugin should attach the minted
    /// token under when calling the downstream service.
    /// Most targets expect `Authorization`; some bespoke services
    /// want a different header (`X-Service-Token`, etc.).
    #[serde(default = "default_outbound_header")]
    pub default_outbound_header: String,
}

/// Where the gateway's OAuth client secret is loaded from. Three
/// modes covering the common deployment patterns:
///
///   * **`env_var`** — read from a named environment variable at
///     resolver construction. Production-friendly; secret lives in
///     the host's environment, not in committed config.
///   * **`file`** — read from a file path at construction. Useful
///     for Kubernetes secret volumes (`/var/run/secrets/...`) or
///     similar mounted-secret patterns.
///   * **`literal`** — inline secret string. Convenient for tests
///     and dev configs; **never** for production (secret ends up
///     in committed YAML).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClientSecretSource {
    EnvVar { name: String },
    File { path: PathBuf },
    Literal { secret: String },
}

fn default_subject_token_type() -> String {
    "urn:ietf:params:oauth:token-type:access_token".to_string()
}

fn default_timeout_seconds() -> u64 {
    5
}

fn default_outbound_header() -> String {
    "Authorization".to_string()
}

impl OAuthDelegatorConfig {
    /// Helper used by the constructor — exposed for tests.
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_seconds)
    }
}

impl ClientSecretSource {
    /// Resolve the secret at runtime, returning the raw bytes.
    /// Errors as a string so the caller wraps in `PluginError::Config`
    /// with context.
    pub fn resolve(&self) -> Result<String, String> {
        match self {
            Self::EnvVar { name } => std::env::var(name)
                .map_err(|e| format!("env var '{name}' unavailable: {e}")),
            Self::File { path } => std::fs::read_to_string(path)
                .map(|s| s.trim().to_string())
                .map_err(|e| {
                    format!("secret file '{}' unreadable: {e}", path.display())
                }),
            Self::Literal { secret } => Ok(secret.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn config_deserializes_from_json() {
        let raw = json!({
            "token_endpoint": "https://auth.example.com/oauth/token",
            "client_id": "gateway",
            "client_secret_source": { "kind": "literal", "secret": "dev-only" },
        });
        let cfg: OAuthDelegatorConfig = serde_json::from_value(raw).unwrap();
        assert_eq!(cfg.token_endpoint, "https://auth.example.com/oauth/token");
        assert_eq!(cfg.client_id, "gateway");
        assert_eq!(cfg.timeout_seconds, 5);
        assert_eq!(cfg.default_outbound_header, "Authorization");
    }

    #[test]
    fn literal_secret_resolves() {
        let src = ClientSecretSource::Literal {
            secret: "hush".into(),
        };
        assert_eq!(src.resolve().unwrap(), "hush");
    }

    #[test]
    fn missing_env_var_errors() {
        let src = ClientSecretSource::EnvVar {
            name: "_THIS_VAR_DEFINITELY_NOT_SET_FOR_TESTS_".into(),
        };
        assert!(src.resolve().is_err());
    }
}
