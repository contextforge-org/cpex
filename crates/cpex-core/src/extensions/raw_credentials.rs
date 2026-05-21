// Location: ./crates/cpex-core/src/extensions/raw_credentials.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// `RawCredentialsExtension` — Layer 3 of the three-layer credential
// storage model (docs/specs/delegation-hooks-rust-spec.md §4.2).
// Carries the *raw* token material — bearer JWTs, opaque session
// strings, SPIFFE-JWT-SVIDs, UCAN tokens, transaction tokens — that
// IdentityResolve and TokenDelegate handlers need to do their jobs.
//
// # Why this is its own extension
//
// `SubjectExtension` / `ClientExtension` / `WorkloadIdentity` carry
// *validated* identity — claims already extracted, signature already
// checked, scopes already enumerated. Most plugins want that and
// nothing more. A small set of plugins (identity resolvers, token
// exchangers, forwarding proxies) genuinely need the raw material to
// re-attach it to outbound calls or hand it to an introspection
// endpoint. Separating raw from validated lets us gate the raw layer
// behind narrowly-scoped capabilities (`read_inbound_credentials`,
// `read_delegated_tokens`) so a buggy or malicious plugin without
// those caps can't get at credential strings.
//
// # Serialization safety
//
// `RawInboundToken.token` and `RawDelegatedToken.token` are
// `#[serde(skip)]`. Any normal serialization of an `Extensions` —
// debug dumps, audit logs, trace snapshots, hot-reload bundles —
// produces JSON / YAML where the token field is absent. A deserialize
// then yields a struct with `Zeroizing::new(String::new())` as the
// token, which is explicitly safe (empty bearer authenticates
// nowhere) but a deliberate foot-gun: a plugin that deserializes an
// extension snapshot and expects to find a working token will fail
// loudly, not silently leak credentials by accident.
//
// This implicitly means **out-of-process plugins (remote / WASM)
// cannot read or write raw credentials**. That's by design — the
// security audit story is much simpler when "raw credentials never
// leave the host process" is an invariant rather than a per-plugin
// trust decision. Handlers that need raw material must run in-process.
// See the slice plan and the architecture discussion in
// `docs/raw-credentials-slice-plan.md` for the reasoning.
//
// # Memory hygiene
//
// `Zeroizing<String>` wipes the underlying bytes when the struct is
// dropped. The protection is real but not absolute — bytes can still
// leak via String::clone, format!, or temporaries created on the way
// to the wrapper. Treat tokens as best-effort cleared, not
// guaranteed.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Which principal a raw inbound token represents. Lookups in
/// `RawCredentialsExtension.inbound_tokens` are by this key.
///
/// `Custom(String)` is the escape hatch for host-defined roles —
/// HashMap equality is by value, so callers must construct the same
/// `Custom("foo".into())` for both insert and lookup.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenRole {
    /// The user / subject token (e.g. `id_token`, `X-User-Token`).
    User,
    /// The OAuth client / gateway-access token (e.g. `Authorization:
    /// Bearer ...` from a session JWT).
    Client,
    /// A JWT-SVID presented by the inbound workload, when SPIFFE
    /// attestation is JWT-based instead of mTLS-based.
    Workload,
    /// Host-defined role.
    #[serde(untagged)]
    Custom(String),
}

/// The wire-format family of a raw token. Lets handlers pick the
/// right validation path without parsing the token first.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenKind {
    /// Standard JWT — three base64url segments joined by dots.
    Jwt,
    /// Opaque bearer — handler must introspect (RFC 7662) to validate.
    Opaque,
    /// SPIFFE JWT-SVID — JWT-shaped but with SPIFFE-specific claims.
    SpiffeJwt,
    /// UCAN capability token.
    Ucan,
    /// Transaction token — short-lived, single-request scope.
    TxnToken,
}

/// Whether a delegated outbound token represents the user's identity
/// or the gateway's own identity to the downstream service. Affects
/// scope-narrowing rules and audit-log attribution.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationMode {
    /// Outbound token represents the original user (RFC 8693
    /// on-behalf-of / actor-token flows, UCAN delegation).
    OnBehalfOfUser,
    /// Outbound token represents the gateway / agent itself as the
    /// principal; user identity is conveyed via separate context.
    AsGateway,
}

/// One inbound credential, captured at the wire layer and stashed
/// here by an identity-resolver plugin. Validation happens elsewhere
/// — this struct just carries the bytes and a few hints.
///
/// The `token` field is `#[serde(skip)]`. Serializing a struct of
/// this type yields `{ "source_header": "...", "kind": "..." }` —
/// the secret material is left out. Deserializing produces a struct
/// whose `token` is `Zeroizing::new(String::new())`. Document this
/// invariant when handing instances across any process boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawInboundToken {
    /// The raw credential bytes. Cleared on drop via `Zeroizing`.
    /// **Never serialized** — `#[serde(skip)]` strips this field.
    #[serde(skip)]
    pub token: Zeroizing<String>,

    /// The HTTP header (or other wire-level slot) the token arrived
    /// in — `"Authorization"`, `"X-User-Token"`, etc. Forwarding
    /// plugins re-attach under the same name; audit logs cite it.
    pub source_header: String,

    /// Wire-format family of the token. Lets handlers route to the
    /// right validator without re-parsing the token contents.
    pub kind: TokenKind,
}

impl RawInboundToken {
    /// Build a token from raw material + metadata. The most common
    /// constructor; identity-resolver plugins call this once per
    /// recognized credential.
    pub fn new(
        token: impl Into<String>,
        source_header: impl Into<String>,
        kind: TokenKind,
    ) -> Self {
        Self {
            token: Zeroizing::new(token.into()),
            source_header: source_header.into(),
            kind,
        }
    }
}

/// Composite key for cached delegated tokens. Token cache lookups
/// hit on `(subject, audience, scopes, mode)` so different audiences
/// or scope sets for the same subject mint independent tokens.
///
/// `scopes` is a `Vec<String>` (not a `HashSet`) because Cedar / OPA
/// policies frequently care about scope *order* — `["read", "write"]`
/// and `["write", "read"]` may carry different semantics in some IdPs.
/// Callers that want set semantics should sort before constructing.
#[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub struct DelegationKey {
    pub subject_id: String,
    pub audience: String,
    pub scopes: Vec<String>,
    pub mode: DelegationMode,
}

/// One minted outbound credential, produced by a TokenDelegate
/// handler and cached for re-use until expiry. The `token` field is
/// serde-skipped under the same invariant as `RawInboundToken.token`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawDelegatedToken {
    /// The minted outbound credential. Cleared on drop.
    #[serde(skip)]
    pub token: Zeroizing<String>,

    /// Where the consuming plugin should attach the token on the
    /// upstream request. Often `"Authorization"`, sometimes
    /// audience-specific.
    pub outbound_header: String,

    /// The audience the token was minted for. Cache keys include
    /// this; the field here is for audit / debugging.
    pub audience: String,

    /// Effective scopes on the minted token. May be narrower than
    /// the inbound credential's scopes — monotonic narrowing is a
    /// framework-level invariant enforced by TokenDelegate.
    pub scopes: Vec<String>,

    /// Cache eviction trigger. Handlers re-mint when `now >=
    /// expires_at - safety_margin`.
    pub expires_at: DateTime<Utc>,
}

impl RawDelegatedToken {
    pub fn new(
        token: impl Into<String>,
        outbound_header: impl Into<String>,
        audience: impl Into<String>,
        scopes: Vec<String>,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            token: Zeroizing::new(token.into()),
            outbound_header: outbound_header.into(),
            audience: audience.into(),
            scopes,
            expires_at,
        }
    }
}

/// The Layer-3 raw-credentials extension.
///
/// Lives on `Extensions.raw_credentials`. Two maps:
///
/// - `inbound_tokens` — what the wire layer handed us, keyed by
///   `TokenRole`. Populated by identity-resolver plugins.
/// - `delegated_tokens` — what we minted for outbound calls, keyed
///   by `DelegationKey`. Populated by TokenDelegate handlers and
///   read by forwarding / proxy plugins.
///
/// `plugin_credentials` (spec §10.7) is intentionally absent until
/// a plugin-credential consumer exists.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RawCredentialsExtension {
    /// Raw inbound tokens, captured at request entry by identity
    /// resolvers. Read with `read_inbound_credentials`; write with
    /// `write_inbound_credentials` (resolvers only).
    #[serde(default)]
    pub inbound_tokens: HashMap<TokenRole, RawInboundToken>,

    /// Outbound delegated tokens, minted on demand by TokenDelegate
    /// handlers and cached for re-use. Read with
    /// `read_delegated_tokens`; write with `write_delegated_tokens`
    /// (TokenDelegate handlers only).
    #[serde(default)]
    pub delegated_tokens: HashMap<DelegationKey, RawDelegatedToken>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_inbound_token_serializes_without_secret() {
        let tok = RawInboundToken::new(
            "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.sig",
            "Authorization",
            TokenKind::Jwt,
        );
        let json = serde_json::to_string(&tok).unwrap();
        // The secret string must not appear in the serialized form —
        // this is the load-bearing invariant of the whole extension.
        assert!(!json.contains("eyJhbGciOiJSUzI1NiJ9"), "raw token leaked into serialized form: {}", json);
        assert!(json.contains("Authorization"));
        assert!(json.contains("jwt"));
    }

    #[test]
    fn raw_inbound_token_deserializes_with_empty_token() {
        let json = r#"{"source_header":"Authorization","kind":"jwt"}"#;
        let tok: RawInboundToken = serde_json::from_str(json).unwrap();
        assert_eq!(&*tok.token, "");
        assert_eq!(tok.source_header, "Authorization");
        assert!(matches!(tok.kind, TokenKind::Jwt));
    }

    #[test]
    fn raw_delegated_token_serializes_without_secret() {
        let tok = RawDelegatedToken::new(
            "minted-secret-bytes",
            "Authorization",
            "https://downstream.example.com",
            vec!["read".into()],
            Utc::now(),
        );
        let json = serde_json::to_string(&tok).unwrap();
        assert!(!json.contains("minted-secret-bytes"), "delegated token leaked: {}", json);
        assert!(json.contains("downstream.example.com"));
    }

    #[test]
    fn token_role_custom_is_hashmap_compatible() {
        // Documents the lookup pattern — equal Custom values produce
        // equal hashes so they collide in a HashMap as expected.
        let mut map: HashMap<TokenRole, &str> = HashMap::new();
        map.insert(TokenRole::Custom("partner".into()), "p");
        assert_eq!(map.get(&TokenRole::Custom("partner".into())), Some(&"p"));
        assert_eq!(map.get(&TokenRole::Custom("other".into())), None);
    }

    #[test]
    fn delegation_key_hash_eq_consistency() {
        let k1 = DelegationKey {
            subject_id: "alice".into(),
            audience: "https://api.example.com".into(),
            scopes: vec!["read".into(), "write".into()],
            mode: DelegationMode::OnBehalfOfUser,
        };
        let k2 = DelegationKey {
            subject_id: "alice".into(),
            audience: "https://api.example.com".into(),
            scopes: vec!["read".into(), "write".into()],
            mode: DelegationMode::OnBehalfOfUser,
        };
        assert_eq!(k1, k2);

        // Scope order matters (Vec, not HashSet) — different order is
        // intentionally a different key.
        let k3 = DelegationKey {
            scopes: vec!["write".into(), "read".into()],
            ..k1.clone()
        };
        assert_ne!(k1, k3);
    }

    #[test]
    fn extension_round_trip_drops_tokens() {
        let mut ext = RawCredentialsExtension::default();
        ext.inbound_tokens.insert(
            TokenRole::User,
            RawInboundToken::new("user-jwt", "X-User-Token", TokenKind::Jwt),
        );

        let json = serde_json::to_string(&ext).unwrap();
        assert!(!json.contains("user-jwt"));

        let restored: RawCredentialsExtension = serde_json::from_str(&json).unwrap();
        // Round-trip preserves the structure but strips secret material.
        let restored_tok = restored.inbound_tokens.get(&TokenRole::User).unwrap();
        assert_eq!(&*restored_tok.token, "");
        assert_eq!(restored_tok.source_header, "X-User-Token");
    }
}
