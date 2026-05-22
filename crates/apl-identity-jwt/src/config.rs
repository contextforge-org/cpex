// Location: ./crates/apl-identity-jwt/src/config.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Typed configuration for `JwtIdentityResolver`. Deserializes from
// the plugin's `PluginConfig.config: Option<JsonValue>` field; the
// resolver's constructor reads this and builds the runtime state
// (DecodingKey instances, claim mapper selection).
//
// Serializable intermediate representations (`DecodingKeySource`)
// stand in for non-serializable runtime types (`DecodingKey`). The
// build step on each type turns the config representation into the
// runtime form.

use std::path::PathBuf;

use jsonwebtoken::{Algorithm, DecodingKey};
use serde::{Deserialize, Serialize};

use super::trusted_issuer::TrustedIssuer;

/// Top-level plugin config — what operators write under
/// `plugins[<name>].config:` in unified-config YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtIdentityResolverConfig {
    /// One or more trusted issuers. At least one required.
    pub trusted_issuers: Vec<TrustedIssuerConfig>,

    /// Which claim mapper to use. `"standard"` is the OIDC default;
    /// future named mappers (e.g., `"keycloak"`, `"cognito"`) plug
    /// in via the registry pattern in `resolver.rs`. Omitted →
    /// `StandardClaimMap`.
    #[serde(default)]
    pub claim_mapper: Option<String>,
}

/// One issuer's config — issuer URL, audiences, decoding key
/// source, accepted algorithms.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedIssuerConfig {
    /// Expected `iss` claim value.
    pub issuer: String,

    /// Expected audience(s). Empty list disables `aud` validation.
    #[serde(default)]
    pub audiences: Vec<String>,

    /// Algorithms accepted for signature verification (e.g.,
    /// `RS256`, `ES256`). At least one required.
    pub algorithms: Vec<Algorithm>,

    /// Source of the decoding key. See [`DecodingKeySource`].
    pub decoding_key: DecodingKeySource,

    /// Clock-skew tolerance for `exp` / `nbf` validation, in
    /// seconds. `0` (default) means "use resolver default" — the
    /// constructor applies a sensible value (currently 60s).
    #[serde(default)]
    pub leeway_seconds: u64,
}

/// Where the JWT signing key material comes from. Serializable
/// intermediate; the resolver builds a runtime `DecodingKey` from
/// it at construction time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DecodingKeySource {
    /// Inline PEM-encoded public key (RSA / EC). Useful for tests
    /// and dev configs; production deployments usually prefer
    /// `pem_file` so keys don't appear in checked-in configs.
    Pem { pem: String },

    /// Path to a PEM file. Read at construction time. Path is
    /// resolved relative to the host's working directory unless
    /// absolute.
    PemFile { path: PathBuf },

    /// Inline JWK (JSON Web Key) — full JWK structure as JSON.
    Jwk { jwk: serde_json::Value },

    /// Symmetric HMAC secret (HS256 / HS384 / HS512 only). Not
    /// recommended for production; signature verifiers need the
    /// same secret, which makes key distribution painful.
    Secret { secret: String },
}

impl DecodingKeySource {
    /// Turn the serializable source into a runtime `DecodingKey`.
    /// Returns a string error so callers can wrap it into
    /// `PluginError::Config` with context.
    pub fn build(&self) -> Result<DecodingKey, String> {
        match self {
            Self::Pem { pem } => DecodingKey::from_rsa_pem(pem.as_bytes())
                .or_else(|_| DecodingKey::from_ec_pem(pem.as_bytes()))
                .or_else(|_| DecodingKey::from_ed_pem(pem.as_bytes()))
                .map_err(|e| format!("inline PEM key failed to parse: {e}")),
            Self::PemFile { path } => {
                let bytes = std::fs::read(path)
                    .map_err(|e| format!("decoding-key file '{}' unreadable: {e}", path.display()))?;
                DecodingKey::from_rsa_pem(&bytes)
                    .or_else(|_| DecodingKey::from_ec_pem(&bytes))
                    .or_else(|_| DecodingKey::from_ed_pem(&bytes))
                    .map_err(|e| {
                        format!(
                            "decoding-key file '{}' is not valid PEM: {e}",
                            path.display()
                        )
                    })
            }
            Self::Jwk { jwk } => {
                let parsed: jsonwebtoken::jwk::Jwk = serde_json::from_value(jwk.clone())
                    .map_err(|e| format!("JWK is not well-formed: {e}"))?;
                DecodingKey::from_jwk(&parsed)
                    .map_err(|e| format!("JWK could not be converted to DecodingKey: {e}"))
            }
            Self::Secret { secret } => {
                Ok(DecodingKey::from_secret(secret.as_bytes()))
            }
        }
    }
}

impl TrustedIssuerConfig {
    /// Build the runtime `TrustedIssuer` from this serializable
    /// config. Errors at this layer surface as `PluginError::Config`
    /// in the resolver's constructor.
    pub fn build(self) -> Result<TrustedIssuer, String> {
        if self.issuer.trim().is_empty() {
            return Err("trusted_issuer.issuer must be non-empty".into());
        }
        if self.algorithms.is_empty() {
            return Err(format!(
                "trusted_issuer '{}' must list at least one algorithm",
                self.issuer
            ));
        }
        let decoding_key = self.decoding_key.build().map_err(|e| {
            format!(
                "trusted_issuer '{}' decoding_key build failed: {e}",
                self.issuer
            )
        })?;
        Ok(TrustedIssuer {
            issuer: self.issuer,
            audiences: self.audiences,
            decoding_key,
            algorithms: self.algorithms,
            leeway_seconds: self.leeway_seconds,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn decoding_key_source_secret_builds() {
        let src = DecodingKeySource::Secret {
            secret: "test-secret".into(),
        };
        assert!(src.build().is_ok());
    }

    #[test]
    fn decoding_key_source_pem_rejects_garbage() {
        // `DecodingKey` doesn't implement Debug (it carries key
        // material), so `expect_err` won't compile here — match
        // the Err arm directly instead.
        let src = DecodingKeySource::Pem {
            pem: "not actually pem".into(),
        };
        match src.build() {
            Err(msg) => assert!(msg.contains("failed to parse")),
            Ok(_) => panic!("garbage PEM should have failed"),
        }
    }

    #[test]
    fn config_deserializes_from_json() {
        // The shape operators write in unified-config YAML, just
        // serialized as JSON for the test.
        let raw = json!({
            "trusted_issuers": [{
                "issuer": "https://idp.example.com",
                "audiences": ["my-api"],
                "algorithms": ["HS256"],
                "decoding_key": {
                    "kind": "secret",
                    "secret": "test-secret",
                },
                "leeway_seconds": 30,
            }],
            "claim_mapper": "standard",
        });
        let cfg: JwtIdentityResolverConfig = serde_json::from_value(raw).unwrap();
        assert_eq!(cfg.trusted_issuers.len(), 1);
        assert_eq!(cfg.trusted_issuers[0].issuer, "https://idp.example.com");
        assert_eq!(cfg.claim_mapper.as_deref(), Some("standard"));
    }
}
