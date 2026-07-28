// Location: ./builtins/plugins/identity-jwt/src/trusted_issuer.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// `TrustedIssuer` — config for one OIDC issuer the resolver trusts,
// plus the `KeyStore` that holds its (possibly-multiple) JWKS keys
// indexed by `kid` for token-header-driven key selection.

use std::collections::HashMap;

use jsonwebtoken::{Algorithm, DecodingKey};

/// A bundle of decoding keys for one trust anchor, supporting
/// `kid`-driven selection at verify time.
///
/// JWKS endpoints commonly publish more than one key (rotation grace
/// windows, multi-algo deployments). The standard OIDC pattern is
/// for each token to declare which `kid` it was signed with in its
/// header; verifiers select the matching key from the JWKS rather
/// than picking the first-listed entry and hoping.
///
/// Two slots:
///   - `by_kid`: keys with a JWKS-declared `kid`. The verify path
///     looks here first using the inbound token's header `kid`.
///   - `fallback`: a single key for the kid-less case. Populated
///     for inline sources (`Pem`/`PemFile`/`Jwk`/`Secret`) which
///     have no JWKS context. JWKS-sourced KeyStores leave this
///     `None` — every JWKS key carries a `kid` by spec.
///
/// A KeyStore with no entries at all (`by_kid.is_empty() && fallback.is_none()`)
/// is a valid runtime state — it represents "JWKS fetch failed,
/// retry pending" in the soft-fail design. Today every
/// construction path populates at least one slot before the store
/// is reachable from the resolver.
///
/// # Update discipline (refresh)
///
/// When the periodic refresh task lands, the intended pattern is
/// **whole-store replacement** — the refresh fetches a fresh JWKS,
/// builds a new `KeyStore`, and replaces the old one atomically
/// (`*shared.write().await = new_store`). Do **not** merge new
/// keys into the existing `by_kid` map: that grows unbounded as
/// the IdP rotates kids in and out over the deployment's lifetime
/// (every kid the IdP ever published stays in our map forever).
/// Whole-store replacement bounds the live key count to the
/// IdP's current JWKS size and lets dropped DecodingKeys release.
/// `RwLock` semantics make this race-free: in-flight verifies
/// holding `&DecodingKey` keep the old store alive until they
/// release, at which point the swap completes and the old store
/// drops.
pub struct KeyStore {
    by_kid: HashMap<String, DecodingKey>,
    fallback: Option<DecodingKey>,
}

impl KeyStore {
    /// Empty store. Only useful for the soft-fail placeholder path;
    /// current code always populates before exposing.
    pub fn empty() -> Self {
        Self {
            by_kid: HashMap::new(),
            fallback: None,
        }
    }

    /// Single-key store with no `kid`. Used by inline sources (Pem,
    /// PemFile, Jwk, Secret) — they have no JWKS context to provide
    /// a kid, so the key serves every token regardless of header.
    pub fn single_fallback(key: DecodingKey) -> Self {
        Self {
            by_kid: HashMap::new(),
            fallback: Some(key),
        }
    }

    /// Construct from a JWKS — every key gets indexed by its `kid`.
    /// JWKS entries without a `kid` are silently dropped (the OIDC
    /// spec requires them to carry one; an entry missing `kid` is
    /// an IdP misconfiguration we'd rather surface as
    /// `auth.unknown_kid` at verify time than as a silent
    /// fallback-wins behaviour).
    pub fn from_jwks_entries<I>(entries: I) -> Self
    where
        I: IntoIterator<Item = (String, DecodingKey)>,
    {
        Self {
            by_kid: entries.into_iter().collect(),
            fallback: None,
        }
    }

    /// Look up the key for a token's header `kid`. Returns:
    ///   - the matching kid'd key if `kid` is Some and present
    ///   - the fallback if `kid` is None and a fallback exists
    ///   - None otherwise (caller surfaces `auth.unknown_kid`)
    ///
    /// Deliberately does NOT silently fall back to `fallback` when
    /// a kid'd lookup misses. With both behaviours mixed, an
    /// attacker who controls JWKS body order could downgrade a
    /// kid'd token to a fallback key. The kid'ed lookup is exact;
    /// only kid-absent tokens may use the fallback.
    pub fn select(&self, kid: Option<&str>) -> Option<&DecodingKey> {
        match kid {
            Some(k) => self.by_kid.get(k),
            None => self.fallback.as_ref(),
        }
    }

    /// Diagnostic: how many keys this store knows about. Used in
    /// log lines and the `Debug` impl below; not for control flow.
    pub fn len(&self) -> usize {
        self.by_kid.len() + usize::from(self.fallback.is_some())
    }

    /// Whether the store has any usable key. False only on the
    /// Slice-B soft-fail placeholder path.
    pub fn is_empty(&self) -> bool {
        self.by_kid.is_empty() && self.fallback.is_none()
    }
}

// `DecodingKey` doesn't derive Debug (it carries key bytes; the lib
// avoids accidental log leakage). We elide every key value; only
// the count and kid set surface.
impl std::fmt::Debug for KeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kids: Vec<&str> = self.by_kid.keys().map(String::as_str).collect();
        f.debug_struct("KeyStore")
            .field("kids", &kids)
            .field("has_fallback", &self.fallback.is_some())
            .finish()
    }
}

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

    /// Decoding keys for this issuer, indexed by `kid`. For inline
    /// sources (Pem/Jwk/Secret) this is a single-entry store with
    /// no kid; for JWKS sources every advertised signature key
    /// lands here so the verify path can pick the one matching the
    /// inbound token's header.
    ///
    /// Wrapped in `Arc<RwLock<...>>` so the background JWKS
    /// refresh task can atomically swap in a fresh KeyStore
    /// without blocking concurrent verifies (read guards are held
    /// for the duration of one `decode()`, which is sync — no
    /// `.await` between acquisition and release, so no deadlock
    /// risk and no contention beyond a few µs per request).
    ///
    /// Empty during the soft-fail boot path (initial JWKS fetch
    /// failed, refresh task will retry). Verify checks for this
    /// and returns `auth.jwks_unavailable` rather than the
    /// `auth.unknown_kid` it would otherwise produce.
    pub keys: std::sync::Arc<std::sync::RwLock<KeyStore>>,

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
            .field("keys", &self.keys)
            .finish()
    }
}
