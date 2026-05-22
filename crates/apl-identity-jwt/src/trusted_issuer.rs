// Location: ./crates/apl-identity-jwt/src/trusted_issuer.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// `TrustedIssuer` — config for one OIDC issuer the resolver trusts.
//
// Sub-step A scope: type skeleton. Field detail + constructors land
// in sub-step B alongside the validation logic.

use jsonwebtoken::{Algorithm, DecodingKey};

/// One issuer's trust config — `iss` value to match against,
/// audience to require, decoding key(s), and acceptable algorithms.
///
/// Deployments with multiple IdPs construct one of these per IdP
/// and hand the list to `JwtIdentityResolver::new`. The resolver
/// picks the matching issuer based on the inbound token's `iss`
/// claim.
#[non_exhaustive]
pub struct TrustedIssuer {
    /// Expected `iss` claim value — the resolver rejects tokens
    /// whose `iss` doesn't match.
    pub issuer: String,

    /// Expected audience(s). Tokens must carry at least one matching
    /// `aud` value. Empty vec means "don't check audience"
    /// (only acceptable for trusted-internal flows).
    pub audiences: Vec<String>,

    /// The decoding key — RSA / EC / Ed / HMAC depending on the
    /// algorithm the IdP uses. Sub-step B adds multi-key support
    /// (KID-based selection for key rotation).
    pub decoding_key: DecodingKey,

    /// Algorithms accepted for signature verification. Most
    /// deployments stick to one (RS256 most commonly), but
    /// supporting multiple lets the IdP rotate to a new algo
    /// without us redeploying.
    pub algorithms: Vec<Algorithm>,

    /// Clock-skew tolerance for `exp` / `nbf` claims, in seconds.
    /// Defaults applied in `JwtIdentityResolver::new`.
    pub leeway_seconds: u64,
}

// Manual `Debug` impl — `jsonwebtoken::DecodingKey` doesn't derive
// `Debug` (presumably to avoid leaking key material into logs).
// We elide the key entirely; the issuer URL + algorithms are
// enough for diagnostic output.
impl std::fmt::Debug for TrustedIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedIssuer")
            .field("issuer", &self.issuer)
            .field("audiences", &self.audiences)
            .field("algorithms", &self.algorithms)
            .field("leeway_seconds", &self.leeway_seconds)
            .field("decoding_key", &"<elided>")
            .finish()
    }
}
