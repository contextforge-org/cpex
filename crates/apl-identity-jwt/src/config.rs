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

use cpex_core::extensions::raw_credentials::TokenRole;
use jsonwebtoken::{Algorithm, DecodingKey};
use serde::{Deserialize, Serialize};

use super::trusted_issuer::TrustedIssuer;

/// Top-level plugin config — what operators write under
/// `plugins[<name>].config:` in unified-config YAML.
///
/// One instance of this plugin handles ONE inbound credential
/// (one header, one role). Wire multiple instances if a deployment
/// expects multiple inbound tokens — e.g. user JWT in
/// `X-User-Token`, OAuth client token in `Authorization`, and a
/// SPIFFE JWT-SVID in `X-Workload-Token`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtIdentityResolverConfig {
    /// One or more trusted issuers. At least one required.
    pub trusted_issuers: Vec<TrustedIssuerConfig>,

    /// Which identity slot this resolver fills. Determines:
    ///
    ///   * Which `TokenRole` key the raw token gets stashed under in
    ///     `RawCredentialsExtension.inbound_tokens`.
    ///   * Which `SecurityExtension` slot the mapped identity writes
    ///     into — `User` → `security.subject`, `Client` →
    ///     `security.client`, `Workload` → `security.caller_workload`.
    ///
    /// Default `User` keeps single-resolver deployments backwards-
    /// compatible. Custom roles aren't supported yet — the resolver
    /// errors at construction.
    #[serde(default = "default_role")]
    pub role: TokenRole,

    /// HTTP header name this resolver reads its token from
    /// (e.g. `"Authorization"`, `"X-User-Token"`). The `Bearer `
    /// prefix is stripped if present. Recorded on
    /// `RawInboundToken.source_header` so forwarding plugins can
    /// re-attach (or strip) the credential under the same name.
    /// Default `Authorization` matches the most common case.
    #[serde(default = "default_header")]
    pub header: String,

    /// Which claim mapper to use. `"standard"` is the OIDC default;
    /// future named mappers (e.g., `"keycloak"`, `"cognito"`) plug
    /// in via the registry pattern in `resolver.rs`. Omitted →
    /// `StandardClaimMap`.
    #[serde(default)]
    pub claim_mapper: Option<String>,
}

fn default_role() -> TokenRole {
    TokenRole::User
}

fn default_header() -> String {
    "Authorization".to_string()
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

    /// OIDC JWKS endpoint — the standard way to wire to a real IdP
    /// (Keycloak / Auth0 / Cognito / Okta / Authentik …). Fetched
    /// synchronously at plugin construction; the first key with
    /// `use: "sig"` is selected. **No automatic rotation in v0** —
    /// hot-reload the plugin when the IdP rolls a signing key.
    /// `kid`-based key selection per token is also v0+ work.
    JwksUrl { url: String },

    /// Symmetric HMAC secret (HS256 / HS384 / HS512 only). Not
    /// recommended for production; signature verifiers need the
    /// same secret, which makes key distribution painful.
    Secret { secret: String },
}

impl DecodingKeySource {
    /// Whether this source needs network I/O to resolve. Used by
    /// `JwtIdentityResolver` to decide between eager (sync) build at
    /// `new()` and deferred (async) build at `Plugin::initialize()`.
    pub fn needs_async(&self) -> bool {
        matches!(self, Self::JwksUrl { .. })
    }

    /// Synchronously turn the source into a `DecodingKey`. Works for
    /// inline / on-disk sources; **errors for `JwksUrl`** — use
    /// [`build_async`] for those. Returns a string error so callers
    /// can wrap into `PluginError::Config` with context.
    ///
    /// [`build_async`]: Self::build_async
    pub fn build(&self) -> Result<DecodingKey, String> {
        match self {
            Self::Pem { pem } => build_from_pem_bytes(pem.as_bytes(), "inline PEM"),
            Self::PemFile { path } => {
                let bytes = std::fs::read(path)
                    .map_err(|e| format!("decoding-key file '{}' unreadable: {e}", path.display()))?;
                build_from_pem_bytes(&bytes, &format!("file '{}'", path.display()))
            }
            Self::Jwk { jwk } => build_from_jwk_value(jwk),
            Self::JwksUrl { url } => Err(format!(
                "JwksUrl source '{url}' requires async resolution — call build_async()"
            )),
            Self::Secret { secret } => Ok(DecodingKey::from_secret(secret.as_bytes())),
        }
    }

    /// Asynchronously resolve the source — handles every variant
    /// including `JwksUrl` (which does an async HTTP GET against the
    /// IdP's JWKS endpoint and picks the first `use: "sig"` key).
    ///
    /// Called from `JwtIdentityResolver::initialize()` so the host's
    /// PluginManager can drive multiple resolvers' JWKS fetches
    /// concurrently via `futures::join_all`.
    ///
    /// **v0 caveats:**
    ///
    /// * No automatic rotation — the key is bound at initialize time
    ///   and reused for the resolver's lifetime. Hot-reload the
    ///   plugin when the IdP rolls.
    /// * No `kid`-based key selection — first sig-use key wins. A
    ///   future slice should match the JWT header's `kid` against
    ///   `keys[*].kid` to support overlapping rotation windows.
    pub async fn build_async(&self) -> Result<DecodingKey, String> {
        match self {
            Self::JwksUrl { url } => {
                let body = reqwest::get(url)
                    .await
                    .map_err(|e| format!("JWKS GET {url} failed: {e}"))?
                    .error_for_status()
                    .map_err(|e| format!("JWKS GET {url} returned non-2xx: {e}"))?
                    .text()
                    .await
                    .map_err(|e| format!("JWKS GET {url} body read failed: {e}"))?;

                let jwks: jsonwebtoken::jwk::JwkSet = serde_json::from_str(&body)
                    .map_err(|e| format!("JWKS {url} body is not a JWKSet: {e}"))?;

                let key = jwks
                    .keys
                    .iter()
                    .find(|k| {
                        k.common.public_key_use
                            == Some(jsonwebtoken::jwk::PublicKeyUse::Signature)
                    })
                    .or_else(|| jwks.keys.first())
                    .ok_or_else(|| format!("JWKS at {url} contained no usable keys"))?;

                DecodingKey::from_jwk(key)
                    .map_err(|e| format!("JWKS key at {url} not usable as DecodingKey: {e}"))
            }
            // Non-network variants delegate to the sync path; they
            // don't await anything, so the cost is zero vs. a direct
            // sync call.
            other => other.build(),
        }
    }
}

/// PEM helper used by both `Pem` and `PemFile`. Tries RSA, then EC,
/// then EdDSA — covers the algorithms `jsonwebtoken` supports.
fn build_from_pem_bytes(bytes: &[u8], origin: &str) -> Result<DecodingKey, String> {
    DecodingKey::from_rsa_pem(bytes)
        .or_else(|_| DecodingKey::from_ec_pem(bytes))
        .or_else(|_| DecodingKey::from_ed_pem(bytes))
        .map_err(|e| format!("{origin} PEM key failed to parse: {e}"))
}

fn build_from_jwk_value(jwk: &serde_json::Value) -> Result<DecodingKey, String> {
    let parsed: jsonwebtoken::jwk::Jwk = serde_json::from_value(jwk.clone())
        .map_err(|e| format!("JWK is not well-formed: {e}"))?;
    DecodingKey::from_jwk(&parsed).map_err(|e| format!("JWK not usable: {e}"))
}

impl TrustedIssuerConfig {
    /// Validate shape (non-empty issuer, at least one algorithm)
    /// without resolving the key. Used at construction time as a
    /// fast-fail gate so misshapen YAML is rejected before any
    /// network I/O is attempted.
    pub fn validate(&self) -> Result<(), String> {
        if self.issuer.trim().is_empty() {
            return Err("trusted_issuer.issuer must be non-empty".into());
        }
        if self.algorithms.is_empty() {
            return Err(format!(
                "trusted_issuer '{}' must list at least one algorithm",
                self.issuer
            ));
        }
        Ok(())
    }

    /// Synchronously build a runtime `TrustedIssuer`. Works for
    /// inline / on-disk `decoding_key` sources; **errors when
    /// `decoding_key.kind == jwks_url`** — use [`build_async`] for
    /// those.
    ///
    /// [`build_async`]: Self::build_async
    pub fn build(self) -> Result<TrustedIssuer, String> {
        self.validate()?;
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

    /// Asynchronously build a `TrustedIssuer`, handling every
    /// `decoding_key` variant including `JwksUrl`. Called from
    /// `JwtIdentityResolver::initialize()` for sources that deferred
    /// resolution past construction.
    pub async fn build_async(self) -> Result<TrustedIssuer, String> {
        self.validate()?;
        let decoding_key = self.decoding_key.build_async().await.map_err(|e| {
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
