// Location: ./crates/cpex-core/src/extensions/raw_credentials.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// `RawCredentialsExtension` — Layer 3 of the three-layer credential
// storage model.
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
// # Where the process boundary actually is
//
// The `#[serde(skip)]` guard is a guard on *these types*, not a
// guarantee about the host process. It means no generic path that
// serializes an `Extensions` — the `extensions` wire channel to an
// out-of-process host, audit dumps, trace snapshots, hot-reload
// bundles — can carry token bytes. That much is absolute: a plugin
// reading `extensions.raw_credentials` out-of-process sees structure
// and metadata with empty token strings.
//
// It is **not** true that raw material never leaves the host process.
// A host may read the in-memory `Zeroizing` field directly and put
// the plaintext on a purpose-built side channel. `cpex-hosts-python`
// does exactly that: `crates/cpex-hosts-python/src/credentials.rs`
// builds a dedicated `credential` DTO carrying the token as a plain
// string, so an identity resolver or token delegator can run in a
// separate worker process. The reversal is deliberate — without it
// those two handler kinds cannot work out-of-process at all — and it
// is narrow by construction, not by policy: the DTO is a distinct
// type with a hand-written redacting `Debug`, and it is the only
// serialize site anywhere that emits token bytes.
//
// ## What gates the crossing
//
// Raw material may cross a process boundary only when all of these
// hold. They are conditions on the host's dispatch path, not
// properties of this module:
//
// - **The plugin declared the matching capability** —
//   `read_inbound_credentials` for inbound tokens,
//   `read_delegated_tokens` for delegated ones. The two are
//   independently scoped; neither unlocks the other.
// - **The hook is one of the two that model a raw token** —
//   `identity_resolve` (`IdentityPayload.raw_token`) and
//   `token_delegate` (`DelegationPayload.bearer_token`). Every other
//   hook gets nothing, even for a plugin holding both capabilities.
// - **Fail closed on both sides of the gate.** No declared capability
//   means no DTO and no token bytes — silently, not as an error.
//   A declared capability that cannot be honored (no extension, no
//   matching token, an empty or whitespace-only token) is an error
//   rather than a no-token dispatch, because a resolver handed an
//   empty bearer may read it as "no authentication required".
//
// ## Residual exposure
//
// The gate decides *which plugin* receives a token. It does not
// constrain what happens after: once the plaintext is resident in a
// worker process, every transitively-installed dependency in that
// worker's environment can read it. That is a materially larger and
// less audited trust boundary than this process, and neither the
// capability gate nor the transport closes it — sending raw
// credentials out-of-process means accepting that dependency tree
// into the credential trust boundary.
//
// The mitigations are real but modest, and should not be read as
// closing that gap. The transport is a private pipe inherited only by
// the child (no listening socket, so no other local process can read
// it), the DTO redacts in `Debug`, and the capability gate narrows the
// blast radius to plugins that asked. None of that helps once a
// malicious or compromised dependency shares the worker's address
// space. Keeping the audit story simple is a reason to prefer
// in-process handlers, not an invariant the framework enforces.
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
    /// A JWT-SVID presented by the *calling* workload, when SPIFFE
    /// attestation is JWT-based instead of mTLS-based. Maps to
    /// `SecurityExtension.caller_workload`.
    ///
    /// Named for the caller specifically: the gateway's own workload
    /// identity (`this_workload`) is a different principal and never
    /// appears here, because this map holds *inbound* credentials and
    /// the gateway's own credential does not arrive on the wire.
    ///
    /// `alias = "workload"` keeps configs written before the rename
    /// working.
    #[serde(rename = "caller_workload", alias = "workload")]
    CallerWorkload,
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

/// Which principal a delegated outbound token speaks for. Affects
/// scope-narrowing rules, audit-log attribution, and how
/// `DelegationKey` partitions the delegated-token cache.
///
/// The four variants track the four identity slots on
/// `SecurityExtension` — `subject`, `client`, `caller_workload`, and
/// `this_workload`. Keeping these principals distinct matters: they
/// present different credentials, and a token minted for one must never
/// be handed to another. Only `OnBehalfOfUser` is a genuine
/// *act-on-behalf-of-another* (delegation); `AsClient`,
/// `AsCallerWorkload`, and `AsThisWorkload` are *act-as-self* — the
/// named principal is the one being scoped.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationMode {
    /// Outbound token represents the original user (RFC 8693
    /// on-behalf-of / actor-token flows, UCAN delegation).
    /// Corresponds to `SecurityExtension.subject`.
    OnBehalfOfUser,

    /// Outbound token represents the *calling client / application*
    /// acting as itself (`SecurityExtension.client`) — an OAuth client
    /// scoping its own credential to a downstream audience, with no user
    /// being delegated. The credential exchanged is the client's own
    /// token, arriving as `inbound_tokens[TokenRole::Client]`.
    ///
    /// Like `AsCallerWorkload`, this mode does *not* identify a single
    /// principal on its own — many different clients call through one
    /// enforcement point, so `DelegationKey.client_id` carries the
    /// specific client. Without it, two clients requesting the same
    /// audience and scopes would collide on one cache entry.
    AsClient,

    /// Outbound token represents the *calling* workload — the attested
    /// agent on the inbound network peer
    /// (`SecurityExtension.caller_workload`), acting autonomously with
    /// no user in the loop. The credential exchanged is the caller's
    /// own JWT-SVID, arriving as `inbound_tokens[TokenRole::CallerWorkload]`.
    ///
    /// Distinct from `AsThisWorkload`: many different agents call through
    /// one enforcement point, so this mode does *not* identify a single
    /// principal on its own — `DelegationKey.workload_id` carries the
    /// specific caller.
    AsCallerWorkload,

    /// Outbound token represents *this* CPEX instance's own attested
    /// identity (`SecurityExtension.this_workload`) — used when the
    /// enforcement point calls infrastructure it owns, or a downstream
    /// that trusts only this instance with user context conveyed
    /// separately.
    ///
    /// This instance's SVID is not an inbound credential: it comes from
    /// the SPIFFE Workload API, not off the wire. Until a source that
    /// populates `this_workload` exists, no handler produces this
    /// mode — do not reach for it as a stand-in for
    /// `AsCallerWorkload`.
    ///
    /// `alias = "as_gateway"`: this variant was renamed from `AsGateway`;
    /// the alias keeps persisted / serialized `as_gateway` values
    /// deserializing.
    #[serde(alias = "as_gateway")]
    AsThisWorkload,
}

/// One inbound credential, captured at the wire layer and stashed
/// here by an identity-resolver plugin. Validation happens elsewhere
/// — this struct just carries the bytes and a few hints.
///
/// The `token` field is `#[serde(skip)]`. Serializing a struct of
/// this type yields `{ "source_header": "...", "kind": "..." }` —
/// the secret material is left out. Deserializing produces a struct
/// whose `token` is `Zeroizing::new(String::new())`.
///
/// A host that needs the plaintext across a process boundary must
/// read the in-memory field and carry it on a purpose-built channel;
/// a serialize-then-reparse silently yields an empty token. See the
/// module docs for the conditions under which that is permitted.
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
/// hit on `(subject, workload, audience, scopes, mode)` so different
/// audiences or scope sets for the same subject mint independent
/// tokens.
///
/// # Every distinguishing principal must appear here
///
/// A cache key has to carry *everything that makes two token requests
/// different*, or a lookup returns a credential minted for somebody
/// else. `subject_id` alone is not enough: a workload-subject exchange
/// has no user, so `subject_id` is empty for every caller, and two
/// different agents requesting the same audience and scopes would
/// otherwise collide on one key — and be served each other's tokens.
/// `workload_id` is what keeps them apart.
///
/// `scopes` is a `Vec<String>` (not a `HashSet`) because Cedar / OPA
/// policies frequently care about scope *order* — `["read", "write"]`
/// and `["write", "read"]` may carry different semantics in some IdPs.
/// Callers that want set semantics should sort before constructing.
/// `#[non_exhaustive]`: construct via [`DelegationKey::new`] + the `with_*`
/// setters so adding a future principal slot doesn't break downstream callers.
#[non_exhaustive]
#[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub struct DelegationKey {
    /// The user the token speaks for. Empty when no user took part
    /// (a workload or client acting as itself).
    pub subject_id: String,

    /// SPIFFE-ID of the calling workload, when one participated in
    /// the exchange — as the subject (`AsCallerWorkload`) or as the
    /// RFC 8693 actor alongside a user. `None` when the exchange
    /// involved no workload credential, which keeps ordinary
    /// user-only delegations sharing one cache entry instead of
    /// being needlessly partitioned per caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_id: Option<String>,

    /// Client-id of the calling OAuth client, when one participated
    /// in the exchange — as the subject (`AsClient`) or as the RFC 8693
    /// actor alongside a user. The exact mirror of `workload_id`: without
    /// it, two different clients requesting the same audience and scopes
    /// (each with an empty `subject_id`) would collide on one key and be
    /// served each other's tokens. `None` when no client credential took
    /// part.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,

    pub audience: String,
    pub scopes: Vec<String>,
    pub mode: DelegationMode,
}

impl DelegationKey {
    /// A key for `mode` + `audience` + `scopes`, with no principal ids set.
    /// Attach whichever principals participated via the `with_*` setters;
    /// this is the construction path `#[non_exhaustive]` requires.
    pub fn new(mode: DelegationMode, audience: impl Into<String>, scopes: Vec<String>) -> Self {
        Self {
            subject_id: String::new(),
            workload_id: None,
            client_id: None,
            audience: audience.into(),
            scopes,
            mode,
        }
    }

    /// Set the user principal (`OnBehalfOfUser`).
    #[must_use]
    pub fn with_subject_id(mut self, subject_id: impl Into<String>) -> Self {
        self.subject_id = subject_id.into();
        self
    }

    /// Set the calling-workload principal (`AsCallerWorkload`, or a workload actor).
    #[must_use]
    pub fn with_workload_id(mut self, workload_id: Option<String>) -> Self {
        self.workload_id = workload_id;
        self
    }

    /// Set the calling-client principal (`AsClient`, or a client actor).
    #[must_use]
    pub fn with_client_id(mut self, client_id: Option<String>) -> Self {
        self.client_id = client_id;
        self
    }
}

/// One minted outbound credential, produced by a TokenDelegate
/// handler and cached for re-use until expiry. The `token` field is
/// serde-skipped under the same rules as `RawInboundToken.token`.
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
/// `plugin_credentials` is intentionally absent until
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
        assert!(
            !json.contains("eyJhbGciOiJSUzI1NiJ9"),
            "raw token leaked into serialized form: {}",
            json
        );
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
        assert!(
            !json.contains("minted-secret-bytes"),
            "delegated token leaked: {}",
            json
        );
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
            workload_id: None,
            client_id: None,
            audience: "https://api.example.com".into(),
            scopes: vec!["read".into(), "write".into()],
            mode: DelegationMode::OnBehalfOfUser,
        };
        let k2 = DelegationKey {
            subject_id: "alice".into(),
            workload_id: None,
            client_id: None,
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

    /// The collision `workload_id` exists to prevent: two different
    /// calling agents doing a workload-subject exchange for the same
    /// audience and scopes. There is no user, so `subject_id` is empty
    /// for both — without the workload in the key they'd collapse to one
    /// entry. (Asserts key distinctness only; cross-request serving isn't
    /// exercised — nothing reads `delegated_tokens` across requests yet.)
    #[test]
    fn workload_subject_keys_are_distinct_per_calling_agent() {
        let payroll = DelegationKey {
            subject_id: String::new(),
            workload_id: Some("spiffe://corp/payroll".into()),
            client_id: None,
            audience: "https://hr.example.com".into(),
            scopes: vec!["read".into()],
            mode: DelegationMode::AsCallerWorkload,
        };
        let recruiting = DelegationKey {
            workload_id: Some("spiffe://corp/recruiting".into()),
            ..payroll.clone()
        };
        assert_ne!(
            payroll, recruiting,
            "two agents with no user must not share a cache entry",
        );

        // Sanity: everything else being equal, the same agent does
        // reuse its own entry — the key isn't accidentally unique.
        let payroll_again = payroll.clone();
        assert_eq!(payroll, payroll_again);

        // And a user-only delegation (no workload involved) stays
        // distinct from a workload one rather than colliding on the
        // empty-subject fallback.
        let user_only = DelegationKey {
            subject_id: "alice".into(),
            workload_id: None,
            client_id: None,
            audience: "https://hr.example.com".into(),
            scopes: vec!["read".into()],
            mode: DelegationMode::OnBehalfOfUser,
        };
        assert_ne!(payroll, user_only);
    }

    #[test]
    fn as_gateway_is_a_back_compat_alias_for_this_workload() {
        // Persisted `as_gateway` (the pre-rename spelling) must still
        // deserialize to AsThisWorkload; the canonical spelling also works.
        assert_eq!(
            serde_json::from_str::<DelegationMode>("\"as_gateway\"").unwrap(),
            DelegationMode::AsThisWorkload,
        );
        assert_eq!(
            serde_json::from_str::<DelegationMode>("\"as_this_workload\"").unwrap(),
            DelegationMode::AsThisWorkload,
        );
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
