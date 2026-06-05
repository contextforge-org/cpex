// Location: ./crates/apl-identity-jwt/src/resolver.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// `JwtIdentityResolver` — `HookHandler<IdentityHook>` that validates
// inbound JWTs and populates the request's `IdentityPayload`.
//
// # Construction
//
// Single entry point: `JwtIdentityResolver::new(cfg: PluginConfig)`.
// Reads `cfg.config` (the typed plugin-specific config field) and
// deserializes it into [`JwtIdentityResolverConfig`], builds the
// runtime `TrustedIssuer` list and the `ClaimMapper`. No alternate
// constructors that bypass the config-driven path — tests
// construct a `PluginConfig` with the right `config` value and go
// through `new` like production code does.
//
// # Runtime flow
//
//   1. Peek at the `iss` claim *without* validating to pick the
//      right trusted issuer config.
//   2. Validate the token (signature + exp + nbf + aud + iss) using
//      that issuer's `DecodingKey`. `iss` is re-checked here as
//      defense-in-depth.
//   3. Map validated claims to a `SubjectExtension` via the
//      configured claim mapper.
//   4. Stash the raw token in `RawCredentialsExtension.inbound_tokens`
//      under `TokenRole::User` for forwarding plugins downstream.
//   5. Return the updated payload via `PluginResult::modify_payload`.
//
// # Error handling
//
// Construction errors → `Box<PluginError>` (`PluginError::Config`).
// Runtime token rejections → `PluginResult::deny(PluginViolation::new(code, reason))`.
// Stable codes for runtime denials:
//
//   * `auth.malformed_header` — JWT structure wrong / empty token
//   * `auth.untrusted_issuer` — `iss` not in trusted list
//   * `auth.signature_invalid` — signature failed
//   * `auth.token_expired` — `exp` in the past
//   * `auth.token_not_yet_valid` — `nbf` in the future
//   * `auth.audience_mismatch` — `aud` didn't include any configured aud
//   * `auth.algorithm_mismatch` — token uses unaccepted algo
//   * `auth.mapping_failed` — claim mapper rejected the claims
//   * `auth.token_invalid` — any other validation failure

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use jsonwebtoken::{decode, Validation};
use serde_json::Value;

use cpex_core::context::PluginContext;
use cpex_core::error::{PluginError, PluginViolation};
use cpex_core::extensions::raw_credentials::{
    RawCredentialsExtension, RawInboundToken, TokenKind, TokenRole,
};
use cpex_core::hooks::payload::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::identity::{IdentityHook, IdentityPayload};
use cpex_core::plugin::{Plugin, PluginConfig};

use super::claim_map::{ClaimMap, ClaimMapper, StandardClaimMap};
use super::config::{JwtIdentityResolverConfig, TrustedIssuerConfig};
use super::trusted_issuer::{KeyStore, TrustedIssuer};

/// Default clock-skew tolerance, in seconds. Matches what most OIDC
/// clients use as a sane default for `exp` / `nbf`.
const DEFAULT_LEEWAY_SECONDS: u64 = 60;

/// JWT-based identity resolver. See module docs.
///
/// # Async key resolution
///
/// Trusted-issuer keys come in two flavors:
///
/// * **Inline / on-disk** (`Pem`, `PemFile`, `Jwk`, `Secret`) — built
///   eagerly during `new()`. They appear in `trusted_issuers`
///   immediately after construction.
/// * **`JwksUrl`** — deferred to `Plugin::initialize()`. The configs
///   sit in `pending_jwks` until `initialize()` runs; that hook
///   fetches all pending JWKS endpoints **concurrently** via
///   `futures::join_all` and merges the resolved issuers into the
///   `trusted_issuers` vec under the `RwLock`.
///
/// The split keeps construction synchronous (matches the existing
/// `PluginFactory::create` trait surface across the workspace) while
/// putting the network I/O on the natural async hook the host
/// already drives via `PluginManager::initialize().await`.
#[derive(Debug)]
pub struct JwtIdentityResolver {
    cfg: PluginConfig,
    trusted_issuers: std::sync::RwLock<Vec<TrustedIssuer>>,
    /// Issuer configs whose `decoding_key` is a `JwksUrl` —
    /// resolved during `initialize()`. Empty in deployments with
    /// only inline sources.
    pending_jwks: Vec<TrustedIssuerConfig>,
    claim_mapper: Arc<dyn ClaimMapper>,
    /// Which identity slot this resolver fills. Drives
    /// `IdentityPayload` slot selection and the `TokenRole` key under
    /// which the raw token gets stashed in
    /// `RawCredentialsExtension.inbound_tokens`.
    role: TokenRole,
    /// HTTP header this resolver reads its token from
    /// (e.g. `X-User-Token`). Plugins that share a request extract
    /// from different headers; the value lands on
    /// `RawInboundToken.source_header` so forwarding plugins know
    /// where to put it (or strip it) on the upstream call.
    header: String,
    /// Background JWKS-refresh tasks, one per JwksUrl issuer.
    /// Spawned during `initialize()`. Aborted in the resolver's
    /// `Drop` impl — without that, tokio JoinHandles silently
    /// detach the task and the refresh loop runs forever (until
    /// the runtime shuts down or it panics).
    refresh_tasks: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl JwtIdentityResolver {
    /// Build a resolver from a `PluginConfig`. Reads `cfg.config`
    /// (the plugin-specific config field — `Option<JsonValue>`),
    /// deserializes it into [`JwtIdentityResolverConfig`], builds
    /// the runtime `TrustedIssuer` list, and resolves the claim
    /// mapper by name.
    ///
    /// Returns `PluginError::Config` for any config-time failure:
    /// missing config block, malformed JSON, no trusted issuers,
    /// unparseable decoding key, unknown claim mapper, etc.
    pub fn new(cfg: PluginConfig) -> Result<Self, Box<PluginError>> {
        let raw_config = cfg.config.as_ref().ok_or_else(|| {
            Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (apl-identity-jwt) requires a `config:` block — \
                     missing trusted_issuers etc.",
                    cfg.name
                ),
            })
        })?;

        let typed: JwtIdentityResolverConfig = serde_json::from_value(raw_config.clone())
            .map_err(|e| {
                Box::new(PluginError::Config {
                    message: format!(
                        "plugin '{}' (apl-identity-jwt) config parse failed: {e}",
                        cfg.name
                    ),
                })
            })?;

        if typed.trusted_issuers.is_empty() {
            return Err(Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (apl-identity-jwt) requires at least one \
                     entry in `trusted_issuers`",
                    cfg.name
                ),
            }));
        }

        // Partition issuer configs:
        //   * Inline / on-disk decoding keys (Pem, PemFile, Jwk,
        //     Secret) → eagerly built into TrustedIssuers here.
        //   * JwksUrl decoding keys → deferred to initialize() so
        //     the host's PluginManager can drive the HTTP fetches
        //     concurrently across all resolvers.
        let mut trusted_issuers: Vec<TrustedIssuer> = Vec::new();
        let mut pending_jwks: Vec<TrustedIssuerConfig> = Vec::new();
        for raw in typed.trusted_issuers {
            // Validate shape eagerly so bad YAML fails at load_config
            // rather than at the async initialize() boundary.
            raw.validate().map_err(|e| {
                Box::new(PluginError::Config {
                    message: format!("plugin '{}' (apl-identity-jwt): {e}", cfg.name),
                })
            })?;
            if raw.decoding_key.needs_async() {
                pending_jwks.push(raw);
            } else {
                let built = raw.build().map_err(|e| {
                    Box::new(PluginError::Config {
                        message: format!("plugin '{}' (apl-identity-jwt): {e}", cfg.name),
                    })
                })?;
                trusted_issuers.push(built);
            }
        }

        // Resolve the claim mapper by name. Unknown names are a
        // config error rather than a silent fallback — fail fast
        // so operators notice typos.
        let claim_mapper: Arc<dyn ClaimMapper> = match typed.claim_mapper.as_deref() {
            None | Some("standard") => Arc::new(StandardClaimMap),
            Some(other) => {
                return Err(Box::new(PluginError::Config {
                    message: format!(
                        "plugin '{}' (apl-identity-jwt): unknown claim_mapper \
                         '{other}'; valid: [standard]",
                        cfg.name
                    ),
                }));
            }
        };

        // Reject `role: Custom(...)` at construction — the framework
        // has slots for User / Client / Workload (the three named
        // entries on SecurityExtension). Custom roles would write to
        // `inbound_tokens` only, with no SecurityExtension home, so
        // downstream `subject.*` / `client.*` predicates wouldn't see
        // them. If we ever want custom slots, that's its own slice.
        if matches!(typed.role, TokenRole::Custom(_)) {
            return Err(Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (apl-identity-jwt): role: Custom(...) is not \
                     yet supported — pick one of `user`, `client`, `workload`",
                    cfg.name
                ),
            }));
        }
        if typed.header.trim().is_empty() {
            return Err(Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (apl-identity-jwt): `header:` must be a \
                     non-empty HTTP header name",
                    cfg.name
                ),
            }));
        }

        Ok(Self {
            cfg,
            trusted_issuers: std::sync::RwLock::new(trusted_issuers),
            pending_jwks,
            claim_mapper,
            role: typed.role,
            header: typed.header,
            refresh_tasks: std::sync::Mutex::new(Vec::new()),
        })
    }
}

impl Drop for JwtIdentityResolver {
    /// Stop every background refresh task when the resolver drops.
    /// Without this, `tokio::task::JoinHandle` *detaches* on drop
    /// — the refresh loop keeps running until the tokio runtime
    /// shuts down. That's harmless for the program-lifetime
    /// singleton case but creates orphan tasks during plugin
    /// hot-reload or in tests that construct/discard resolvers
    /// repeatedly.
    fn drop(&mut self) {
        let mut tasks = match self.refresh_tasks.lock() {
            Ok(t) => t,
            Err(poisoned) => poisoned.into_inner(),
        };
        for handle in tasks.drain(..) {
            handle.abort();
        }
    }
}

#[async_trait]
impl Plugin for JwtIdentityResolver {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }

    /// Resolve any `JwksUrl` decoding keys deferred at construction,
    /// then spawn a background task per JwksUrl issuer to refresh
    /// the KeyStore on a periodic schedule (default 10 min,
    /// configurable per-issuer via `refresh_secs`).
    ///
    /// **Soft-fail semantics (Slice B):** an unreachable / slow /
    /// malformed JWKS at startup logs a warning and leaves the
    /// issuer's KeyStore *empty*. The plugin still loads, the
    /// gateway still boots, and the background refresh task gets
    /// spawned anyway — so a transient IdP outage during boot
    /// recovers on its own as soon as refresh succeeds. Verify-time
    /// requests against an issuer with an empty KeyStore receive
    /// `auth.jwks_unavailable` rather than crashing the request.
    ///
    /// Initial fetches happen concurrently — N pending issuers
    /// → one `join_all`, not N sequential round-trips — so the
    /// time-to-ready scales with the slowest IdP, not the sum.
    ///
    /// The `PluginManager` drives this once per plugin lifetime
    /// (before any hooks fire). Idempotent: if `pending_jwks` is
    /// empty (no JwksUrl sources) this is a free no-op.
    async fn initialize(&self) -> Result<(), Box<PluginError>> {
        if self.pending_jwks.is_empty() {
            return Ok(());
        }

        // 1. Initial concurrent fetch. Each result is (config,
        //    outcome) — we keep the config alongside the result
        //    so the soft-fail path can construct an empty
        //    KeyStore *and* still spawn refresh for that issuer.
        let fetches = self.pending_jwks.iter().cloned().map(|cfg| async move {
            let outcome = cfg.clone().build_async().await;
            (cfg, outcome)
        });
        let resolved: Vec<(TrustedIssuerConfig, Result<TrustedIssuer, String>)> =
            futures::future::join_all(fetches).await;

        let mut issuers = self
            .trusted_issuers
            .write()
            .unwrap_or_else(|p| p.into_inner());
        let mut new_tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

        for (cfg, outcome) in resolved {
            // Get the shared store: from the successful fetch's
            // TrustedIssuer if we have one, else an empty store
            // bound to a freshly-constructed TrustedIssuer shell.
            // Either way we end up with one TrustedIssuer in
            // `issuers` and a clone of its `Arc<RwLock<KeyStore>>`
            // captured by the refresh task.
            let (shared, plugin_name) = (self.cfg.name.clone(), cfg.issuer.clone());
            let issuer = match outcome {
                Ok(iss) => iss,
                Err(e) => {
                    tracing::warn!(
                        plugin = %shared,
                        issuer = %plugin_name,
                        error = %e,
                        "initial JWKS fetch failed; soft-fail. Verify requests \
                         against this issuer will receive auth.jwks_unavailable \
                         until refresh succeeds."
                    );
                    // Build a TrustedIssuer with an empty KeyStore
                    // so the refresh task can swap a fresh store in
                    // without re-running validation logic.
                    TrustedIssuer {
                        issuer: cfg.issuer.clone(),
                        audiences: cfg.audiences.clone(),
                        keys: Arc::new(std::sync::RwLock::new(KeyStore::empty())),
                        algorithms: cfg.algorithms.clone(),
                        leeway_seconds: cfg.leeway_seconds,
                    }
                }
            };

            // Spawn refresh task. The closure owns:
            //   - a clone of the source (cfg.decoding_key) for
            //     re-fetching
            //   - a clone of the Arc<RwLock<KeyStore>> for atomic
            //     whole-store replacement on success
            //   - plugin / issuer names for diagnostic logging
            if let Some(interval) = cfg.decoding_key.refresh_interval() {
                let source = cfg.decoding_key.clone();
                let shared_store = Arc::clone(&issuer.keys);
                let plugin_label = self.cfg.name.clone();
                let issuer_label = cfg.issuer.clone();
                let handle = tokio::spawn(async move {
                    let mut ticker = tokio::time::interval(interval);
                    // Skip the first immediate tick — the initial
                    // fetch already ran synchronously above. The
                    // first refresh fires at `now + interval`.
                    ticker.tick().await;
                    loop {
                        ticker.tick().await;
                        match source.build_async().await {
                            Ok(new_store) => {
                                // Whole-store replacement. The
                                // old store drops when the write
                                // completes — bounded steady-state
                                // memory regardless of how many
                                // rotations have happened.
                                match shared_store.write() {
                                    Ok(mut g) => *g = new_store,
                                    Err(poisoned) => *poisoned.into_inner() = new_store,
                                }
                                tracing::info!(
                                    plugin = %plugin_label,
                                    issuer = %issuer_label,
                                    "JWKS refresh succeeded"
                                );
                            }
                            Err(e) => {
                                tracing::warn!(
                                    plugin = %plugin_label,
                                    issuer = %issuer_label,
                                    error = %e,
                                    "JWKS refresh failed; keeping previous KeyStore"
                                );
                            }
                        }
                    }
                });
                new_tasks.push(handle);
            }

            issuers.push(issuer);
        }

        // Park the handles so Drop can abort them. Held under a
        // std::sync::Mutex because the resolver's outer methods are
        // a mix of sync and async; we don't await while holding it.
        let mut tasks = self
            .refresh_tasks
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        tasks.extend(new_tasks);

        Ok(())
    }
}

impl HookHandler<IdentityHook> for JwtIdentityResolver {
    async fn handle(
        &self,
        payload: &IdentityPayload,
        _ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<IdentityPayload> {
        // Read OUR configured header from the request's full header
        // map. HTTP headers are case-insensitive (RFC 7230 §3.2);
        // we lowercase the configured name to match the canonical
        // form hosts use when populating the map. Fall back to
        // `payload.raw_token()` only when no header map is populated
        // — covers single-resolver back-compat for hosts that still
        // pre-extract one token.
        let header_lc = self.header.to_ascii_lowercase();
        let header_value = payload.headers().get(header_lc.as_str());
        let raw_token: String = match header_value {
            Some(v) => v.strip_prefix("Bearer ").unwrap_or(v).to_string(),
            None if !payload.raw_token().is_empty() => payload.raw_token().to_string(),
            None => {
                return PluginResult::deny(PluginViolation::new(
                    "auth.malformed_header",
                    format!(
                        "header '{}' missing from request (resolver '{}' / role '{:?}')",
                        self.header, self.cfg.name, self.role
                    ),
                ));
            }
        };
        if raw_token.is_empty() {
            return PluginResult::deny(PluginViolation::new(
                "auth.malformed_header",
                format!("header '{}' is present but empty", self.header),
            ));
        }

        // 1. Peek at `iss` to find the matching TrustedIssuer config.
        let iss = match peek_issuer(&raw_token) {
            Some(iss) => iss,
            None => {
                return PluginResult::deny(PluginViolation::new(
                    "auth.malformed_header",
                    "JWT not well-formed or missing `iss` claim",
                ));
            }
        };
        // Read-lock the issuer list. After `initialize()` it's
        // immutable for the resolver's lifetime; reads are cheap.
        // Recover from a poisoned lock (a panic somewhere else
        // while holding the write lock) — the data is still valid.
        let issuers = self
            .trusted_issuers
            .read()
            .unwrap_or_else(|p| p.into_inner());
        let issuer = match issuers.iter().find(|i| i.issuer == iss) {
            Some(i) => i,
            None => {
                return PluginResult::deny(PluginViolation::new(
                    "auth.untrusted_issuer",
                    format!("issuer '{iss}' is not in the trusted-issuer list"),
                ));
            }
        };

        // 2. Validate signature + standard claims, after kid-driven
        //    key selection. Three distinct deny codes so operators
        //    can tell:
        //      - rotation lag (`auth.unknown_kid`): the IdP rolled
        //        and our refresh hasn't yet pulled the new key.
        //      - JWKS-unavailable (`auth.jwks_unavailable`): the
        //        initial fetch failed and refresh hasn't recovered
        //        — the gateway didn't crash by design, but it
        //        also can't verify tokens for this issuer right now.
        //      - forgery / corruption (`auth.signature_invalid` and
        //        friends): the standard jsonwebtoken outcomes.
        let token_data = match validate_token(&raw_token, issuer) {
            Ok(td) => td,
            Err(ValidateError::KeysUnavailable) => {
                return PluginResult::deny(PluginViolation::new(
                    "auth.jwks_unavailable",
                    format!(
                        "issuer '{iss}' has no signing keys available — \
                         initial JWKS fetch failed and refresh has not \
                         yet succeeded; check upstream IdP reachability"
                    ),
                ));
            }
            Err(ValidateError::UnknownKid(kid)) => {
                let reason = match kid {
                    Some(k) => format!(
                        "token's header `kid` = '{k}' did not match any key in issuer's JWKS"
                    ),
                    None => "token has no `kid` header; issuer's JWKS keys all require kid match"
                        .to_string(),
                };
                return PluginResult::deny(PluginViolation::new("auth.unknown_kid", reason));
            }
            Err(ValidateError::Jwt(e)) => {
                let (code, reason) = classify_jwt_error(&e);
                return PluginResult::deny(PluginViolation::new(code, reason));
            }
        };

        // 3. Build the updated payload by mapping claims into the
        //    typed slot for our configured role.
        let mut updated = payload.clone();
        match &self.role {
            TokenRole::User => match self.claim_mapper.map_subject(&token_data.claims) {
                Some(s) => updated.subject = Some(s),
                None => {
                    return PluginResult::deny(PluginViolation::new(
                        "auth.mapping_failed",
                        "claim mapper produced no subject — required `sub` \
                         claim missing or wrong shape",
                    ));
                }
            },
            TokenRole::Client => match self.claim_mapper.map_client(&token_data.claims) {
                Some(c) => updated.client = Some(c),
                None => {
                    return PluginResult::deny(PluginViolation::new(
                        "auth.mapping_failed",
                        "claim mapper produced no client — required `client_id` \
                         / `azp` claim missing",
                    ));
                }
            },
            TokenRole::Workload => match self.claim_mapper.map_workload(&token_data.claims) {
                Some(w) => updated.caller_workload = Some(w),
                None => {
                    return PluginResult::deny(PluginViolation::new(
                        "auth.mapping_failed",
                        "claim mapper produced no workload — token doesn't look \
                         like a SPIFFE-JWT-SVID (sub doesn't start with `spiffe://`)",
                    ));
                }
            },
            TokenRole::Custom(_) => {
                // Filtered out at construction; defense in depth.
                return PluginResult::deny(PluginViolation::new(
                    "auth.misconfigured",
                    "role: Custom(...) is not supported",
                ));
            }
            // TokenRole is #[non_exhaustive]; future variants must be
            // explicitly handled. Until then, treat unknown roles the
            // same as Custom — surface as misconfigured rather than
            // silently dropping the token.
            _ => {
                return PluginResult::deny(PluginViolation::new(
                    "auth.misconfigured",
                    "unsupported TokenRole variant",
                ));
            }
        }

        // 4. Stash the raw token for forwarding plugins. Key the
        //    stash by the resolver's configured role so multi-token
        //    deployments (user + client + workload) keep each
        //    credential addressable.
        let mut raw_creds = updated
            .raw_credentials
            .clone()
            .unwrap_or_else(RawCredentialsExtension::default);
        raw_creds.inbound_tokens.insert(
            self.role.clone(),
            RawInboundToken::new(raw_token, self.header.clone(), TokenKind::Jwt),
        );
        updated.raw_credentials = Some(raw_creds);
        updated.resolved_at = Some(chrono::Utc::now());
        // Pass the full claim map through `raw_claims` so audit /
        // downstream policy that wants uncategorized claims has them.
        // For multi-resolver chains, the last resolver wins; if
        // operators need per-role raw claims they should read from
        // the typed slots (subject.claims / client.claims) instead.
        updated.raw_claims = token_data.claims;

        PluginResult::modify_payload(updated)
    }
}

// =====================================================================
// Internal helpers
// =====================================================================

/// Pull the `iss` claim out of a JWT *without* verifying the
/// signature. Used purely to look up which trusted issuer config
/// to validate against next.
///
/// **Security note:** the value returned here is untrusted until
/// the subsequent validation pass succeeds. We use it only to
/// select the right `DecodingKey`; validation re-enforces `iss`
/// against the matched config.
fn peek_issuer(token: &str) -> Option<String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .ok()?;
    let value: Value = serde_json::from_slice(&payload_bytes).ok()?;
    value.get("iss")?.as_str().map(String::from)
}

/// Reason `validate_token` couldn't verify the JWT. Wraps the
/// usual `jsonwebtoken::errors::Error` plus the kid-selection
/// and JWKS-availability cases introduced by Slice A / B.
enum ValidateError {
    /// The JWT's header `kid` didn't match any key the issuer's
    /// KeyStore knows about. Distinct from `InvalidSignature` so
    /// the verify path can surface `auth.unknown_kid` with the
    /// specific kid that was missing — operators can match this
    /// against their IdP's currently-published JWKS to confirm
    /// rotation propagated.
    UnknownKid(Option<String>),
    /// The issuer's KeyStore is empty: initial JWKS fetch failed
    /// at `initialize()`, refresh task hasn't yet succeeded. The
    /// gateway didn't crash (soft-fail by design), but it also
    /// can't verify any token from this issuer until refresh
    /// catches up. Surfaces as `auth.jwks_unavailable` so
    /// operators see "JWKS issue at IdP X" rather than the more
    /// alarming `auth.signature_invalid` they'd see if we
    /// silently fell back to e.g. an empty key.
    KeysUnavailable,
    /// jsonwebtoken's own validation outcome (signature, exp,
    /// nbf, iss, aud, algorithm).
    Jwt(jsonwebtoken::errors::Error),
}

/// Validate the token against the matched issuer's config:
/// `kid`-driven key selection, then signature, exp, nbf, aud, iss.
///
/// Two-step lookup:
///   1. Decode just the JWT header (no signature check yet) to
///      read the `kid` claim. We don't trust the result for
///      authorization decisions — we use it only to pick a
///      candidate key from the issuer's `KeyStore`.
///   2. If a key is found, run jsonwebtoken's full validation
///      against it. Failure modes (bad sig, expired, etc.) flow
///      through unchanged.
///   3. If no key matches, return `UnknownKid` — distinct from
///      `InvalidSignature` so operators can tell rotation lag
///      from a forgery attempt at the audit layer.
fn validate_token(
    token: &str,
    issuer: &TrustedIssuer,
) -> Result<jsonwebtoken::TokenData<ClaimMap>, ValidateError> {
    let header = jsonwebtoken::decode_header(token).map_err(ValidateError::Jwt)?;
    let kid = header.kid.as_deref();

    // Acquire a read guard on the issuer's KeyStore. The guard is
    // held for the duration of `decode()` below — sync, no .await
    // between acquire and release, so no risk of deadlock against
    // the refresh task's write lock. Refresh writes block until
    // outstanding readers release; a verify in flight when refresh
    // fires waits a few µs at most.
    let keys = issuer
        .keys
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    if keys.is_empty() {
        return Err(ValidateError::KeysUnavailable);
    }

    let key = match keys.select(kid) {
        Some(k) => k,
        None => return Err(ValidateError::UnknownKid(kid.map(String::from))),
    };

    let primary = issuer.algorithms[0];
    let mut validation = Validation::new(primary);
    validation.algorithms = issuer.algorithms.clone();
    validation.set_issuer(&[&issuer.issuer]);
    validation.leeway = if issuer.leeway_seconds == 0 {
        DEFAULT_LEEWAY_SECONDS
    } else {
        issuer.leeway_seconds
    };
    if issuer.audiences.is_empty() {
        validation.validate_aud = false;
    } else {
        let aud_refs: Vec<&str> = issuer.audiences.iter().map(String::as_str).collect();
        validation.set_audience(&aud_refs);
    }
    decode::<ClaimMap>(token, key, &validation).map_err(ValidateError::Jwt)
}

/// Map jsonwebtoken errors to stable violation codes.
fn classify_jwt_error(e: &jsonwebtoken::errors::Error) -> (&'static str, String) {
    use jsonwebtoken::errors::ErrorKind;
    let code = match e.kind() {
        ErrorKind::ExpiredSignature => "auth.token_expired",
        ErrorKind::InvalidSignature => "auth.signature_invalid",
        ErrorKind::ImmatureSignature => "auth.token_not_yet_valid",
        ErrorKind::InvalidAudience => "auth.audience_mismatch",
        ErrorKind::InvalidIssuer => "auth.untrusted_issuer",
        ErrorKind::InvalidAlgorithm | ErrorKind::InvalidAlgorithmName => {
            "auth.algorithm_mismatch"
        }
        ErrorKind::Base64(_) | ErrorKind::Json(_) => "auth.malformed_header",
        _ => "auth.token_invalid",
    };
    (code, e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::json;

    fn jwt_with_payload(payload_json: &str) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        let sig = URL_SAFE_NO_PAD.encode(b"fake-signature");
        format!("{header}.{payload}.{sig}")
    }

    fn cfg_with_config(name: &str, config: Value) -> PluginConfig {
        PluginConfig {
            name: name.into(),
            config: Some(config),
            ..Default::default()
        }
    }

    #[test]
    fn new_rejects_missing_config_block() {
        let cfg = PluginConfig {
            name: "jwt".into(),
            config: None,
            ..Default::default()
        };
        let err = JwtIdentityResolver::new(cfg).expect_err("missing config should fail");
        assert!(format!("{err}").contains("config"));
    }

    #[test]
    fn new_rejects_empty_trusted_issuers() {
        let cfg = cfg_with_config("jwt", json!({ "trusted_issuers": [] }));
        let err = JwtIdentityResolver::new(cfg)
            .expect_err("empty trusted_issuers should fail");
        assert!(format!("{err}").contains("trusted_issuers"));
    }

    #[test]
    fn new_rejects_unknown_claim_mapper() {
        let cfg = cfg_with_config(
            "jwt",
            json!({
                "trusted_issuers": [{
                    "issuer": "https://idp.example.com",
                    "algorithms": ["HS256"],
                    "decoding_key": { "kind": "secret", "secret": "x" },
                }],
                "claim_mapper": "made-up-mapper",
            }),
        );
        let err = JwtIdentityResolver::new(cfg)
            .expect_err("unknown mapper should fail");
        assert!(format!("{err}").contains("claim_mapper"));
    }

    #[test]
    fn new_accepts_well_formed_config() {
        let cfg = cfg_with_config(
            "jwt",
            json!({
                "trusted_issuers": [{
                    "issuer": "https://idp.example.com",
                    "audiences": ["my-api"],
                    "algorithms": ["HS256"],
                    "decoding_key": { "kind": "secret", "secret": "test-secret" },
                    "leeway_seconds": 30,
                }],
                "claim_mapper": "standard",
            }),
        );
        let resolver = JwtIdentityResolver::new(cfg).expect("should construct");
        let issuers = resolver.trusted_issuers.read().unwrap();
        assert_eq!(issuers.len(), 1);
        assert_eq!(issuers[0].issuer, "https://idp.example.com");
        // Secret source resolves eagerly — no pending JWKS work.
        assert!(resolver.pending_jwks.is_empty());
    }

    #[test]
    fn peek_issuer_extracts_iss() {
        let token = jwt_with_payload(r#"{"sub":"alice","iss":"https://idp.example.com"}"#);
        assert_eq!(
            peek_issuer(&token),
            Some("https://idp.example.com".to_string()),
        );
    }

    #[test]
    fn peek_issuer_returns_none_for_malformed_token() {
        assert!(peek_issuer("not.a-jwt").is_none());
        assert!(peek_issuer("a.b.c.d").is_none());
        assert!(peek_issuer("").is_none());
    }

    #[test]
    fn peek_issuer_returns_none_when_iss_missing() {
        let token = jwt_with_payload(r#"{"sub":"alice"}"#);
        assert!(peek_issuer(&token).is_none());
    }

    #[test]
    fn classify_picks_expected_codes() {
        use jsonwebtoken::errors::{Error, ErrorKind};
        let cases = [
            (ErrorKind::ExpiredSignature, "auth.token_expired"),
            (ErrorKind::InvalidSignature, "auth.signature_invalid"),
            (ErrorKind::ImmatureSignature, "auth.token_not_yet_valid"),
            (ErrorKind::InvalidAudience, "auth.audience_mismatch"),
            (ErrorKind::InvalidIssuer, "auth.untrusted_issuer"),
        ];
        for (kind, expected_code) in cases {
            let err = Error::from(kind);
            let (code, _reason) = classify_jwt_error(&err);
            assert_eq!(code, expected_code);
        }
    }
}
