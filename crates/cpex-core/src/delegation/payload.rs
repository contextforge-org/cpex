// Location: ./crates/cpex-core/src/delegation/payload.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// `DelegationPayload` — the unified state struct threaded through the
// TokenDelegate hook chain. Same input/output split pattern as
// `IdentityPayload`:
//
//   * **Input** (private — host-supplied, never mutated by handlers) —
//     `bearer_token`, `actor_token`, `actor_role`, `subject`, `target_name`,
//     `target_type`, `target_audience`, `required_permissions`,
//     `trust_domain`, `auth_enforced_by`,
//     `route_attenuation`. Set once at the call site that needs to mint
//     a downstream credential. Privacy is enforced at the module
//     boundary: external code reads through accessors and has no
//     setters or mutable field access.
//
//   * **Accumulating output** (`pub` fields) — `delegated_token` and
//     `delegation_update`. Handlers clone the payload, populate these,
//     return the updated payload via `PluginResult::modify_payload`.
//
// # Where this hook fits
//
// IdentityResolve is *inbound* — validates the caller's
// credentials at request entry, populates `security.subject` /
// `security.client` / `security.caller_workload`. TokenDelegate is
// *outbound* — when a plugin (typically a forwarding proxy) needs to
// make a downstream call to a tool or agent, it asks for an
// appropriately-scoped credential for that target. A handler (RFC
// 8693 token exchanger, UCAN minter, passthrough) produces the
// minted token; the framework stashes it in
// `Extensions.raw_credentials.delegated_tokens` for the proxy plugin
// to attach on the upstream request.
//
// # Caching
//
// Not implemented yet. The spec describes a `TokenCacheControl` trait
// that wraps this hook with `get_or_mint(audience, scopes)`
// semantics — outbound callers ask the trait for a token; the trait
// hits the cache first and only dispatches through the hook on cache
// miss. That layer comes later. For now, every
// `mgr.invoke_named::<TokenDelegateHook>(...)` re-runs the chain.
//
// # Rejection
//
// Same as IdentityResolve: handlers reject via
// `PluginResult::deny(PluginViolation::new(code, reason))`. The
// executor halts the chain; no later handler runs and the request
// fails with the violation surfaced to the host. No `rejected` flag
// on the payload.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::executor::PipelineResult;
use crate::extensions::raw_credentials::{DelegationMode, TokenRole};
use crate::extensions::{
    DelegationExtension, Extensions, RawCredentialsExtension, RawDelegatedToken,
};
use crate::impl_plugin_payload;

/// Which principal a delegation exchange is *for* — the party whose
/// identity the minted credential will speak for.
///
/// Deliberately a separate type from [`TokenRole`]. `TokenRole` keys
/// `RawCredentialsExtension.inbound_tokens`, so it can only ever name
/// a credential that arrived on the wire. `Gateway` names *our own*
/// identity, which by definition does not arrive on the wire — it has
/// no inbound slot and no `TokenRole`. Collapsing the two would make
/// "which workload?" ambiguous all over again.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationSubject {
    /// The end user. The ordinary on-behalf-of exchange.
    #[default]
    User,
    /// The OAuth client / application brokering the request.
    Client,
    /// The *calling* workload — an agent acting autonomously, with no
    /// user in the loop. Exchanges the caller's own JWT-SVID.
    CallerWorkload,
    /// This gateway itself. Used when the gateway holds the access to
    /// a downstream — the common "gateway owns the tool credentials"
    /// deployment — and calls it as itself rather than as the caller.
    ///
    /// Has no inbound credential to exchange: the gateway proves who
    /// it is with its own client credentials or its own SVID.
    Gateway,
}

impl DelegationSubject {
    /// Which inbound credential supplies this subject's token, or
    /// `None` for [`Gateway`] — nothing the caller sent is being
    /// exchanged, so there is no inbound slot to read.
    ///
    /// [`Gateway`]: DelegationSubject::Gateway
    pub fn inbound_role(&self) -> Option<TokenRole> {
        match self {
            DelegationSubject::User => Some(TokenRole::User),
            DelegationSubject::Client => Some(TokenRole::Client),
            DelegationSubject::CallerWorkload => Some(TokenRole::CallerWorkload),
            DelegationSubject::Gateway => None,
        }
    }

    /// Parse the value of a `subject:` step key. Returns `None` for
    /// anything unrecognized so callers apply their own policy rather
    /// than silently substituting a principal for a typo'd one.
    ///
    /// `"workload"` is accepted as a legacy spelling of
    /// `caller_workload`.
    pub fn from_config_str(s: &str) -> Option<Self> {
        match s {
            "user" => Some(DelegationSubject::User),
            "client" => Some(DelegationSubject::Client),
            "caller_workload" | "workload" => Some(DelegationSubject::CallerWorkload),
            "gateway" => Some(DelegationSubject::Gateway),
            _ => None,
        }
    }
}

/// Kind of downstream entity the credential is being minted for.
/// `Custom(String)` is the escape hatch for host-defined entity
/// types beyond the well-known shapes.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetType {
    /// A tool invocation (MCP tool, function call).
    Tool,
    /// An agent — another LLM-driven actor.
    Agent,
    /// A static resource (file, URL, document store entry).
    Resource,
    /// A service (microservice, internal API).
    Service,
    /// Operator-defined target kind.
    #[serde(untagged)]
    Custom(String),
}

impl Default for TargetType {
    fn default() -> Self {
        TargetType::Tool
    }
}

/// Who's responsible for enforcing authorization on the downstream
/// call. From the `ObjectSecurityProfile` of the target. Determines
/// whether the gateway brokers credentials (`Caller`), trusts the
/// target to handle auth itself (`Target`), or both layers enforce
/// (`Both`).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthEnforcedBy {
    /// Caller (the gateway / our process) enforces — typical for
    /// internal services that trust the gateway's authorization
    /// decision.
    Caller,
    /// Target enforces — typical for external services with their
    /// own access control. We may still attach credentials but the
    /// downstream makes the final allow/deny decision.
    Target,
    /// Both layers enforce — defense in depth.
    Both,
}

impl Default for AuthEnforcedBy {
    fn default() -> Self {
        AuthEnforcedBy::Caller
    }
}

/// Scope-attenuation config carried from the route DSL. Lets the
/// route author narrow what the minted credential is allowed to do
/// beyond the broad authorization the inbound credential carried.
///
/// `resource_template` is a templated URI (e.g.
/// `"hr://employees/{{ args.employee_id }}"`) that the framework
/// renders against request-time arguments before passing into the
/// minted token's scope claim. v0 doesn't include a template
/// renderer — handlers receive the raw template string and render
/// themselves; a framework-side renderer can come later.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttenuationConfig {
    /// Specific capabilities the route author wants granted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,

    /// URI template for the resource being accessed. Unrendered —
    /// handlers substitute `{{ args.* }}` placeholders themselves
    /// using request context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_template: Option<String>,

    /// Actions allowed on the resource (read / write / delete /
    /// custom verbs).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<String>,

    /// Token lifetime override in seconds. `None` lets the handler
    /// pick its default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
}

/// State threaded through the TokenDelegate hook chain.
///
/// See the module-level docs for the input/output split. Input
/// fields are private (set once via the constructor + builders,
/// never mutated). Output fields are `pub` (handlers populate on
/// clones and return the updated payload).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationPayload {
    /// The caller's current credential — the one a token-exchange
    /// handler will swap for a downstream-scoped credential. Cleared
    /// on drop via `Zeroizing`. `#[serde(skip)]` — never appears in
    /// serialized output.
    #[serde(skip)]
    bearer_token: Zeroizing<String>,

    /// The RFC 8693 `actor_token` — the credential of the party
    /// *acting on behalf of* the subject, typically the caller
    /// workload's SPIFFE JWT-SVID. Sourced by the invoker from
    /// `RawCredentialsExtension[Workload]`, exactly as `bearer_token`
    /// is sourced from `[User]`. Empty when the delegation carries no
    /// actor (the common single-token exchange). Cleared on drop via
    /// `Zeroizing`; `#[serde(skip)]` — never serialized, same
    /// invariant as `bearer_token`.
    #[serde(skip)]
    actor_token: Zeroizing<String>,

    /// Which principal `actor_token` belongs to. `None` when the
    /// exchange carries no actor. Travels with `actor_token` because
    /// the bytes alone don't say whose they are, and the cache key
    /// needs to know whether a workload took part.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    actor_role: Option<TokenRole>,

    /// Which principal this exchange is *for* — whose identity the
    /// minted credential will speak for.
    ///
    /// Handlers can't tell a user token from a workload JWT-SVID by
    /// looking at the bytes, but the distinction decides how the
    /// minted credential must be attributed: a `CallerWorkload`
    /// subject with no user in the picture speaks for the calling
    /// agent (`DelegationMode::AsCallerWorkload`), a `User` subject
    /// speaks for the user (`OnBehalfOfUser`), and `Gateway` speaks
    /// for us (`AsGateway`). Recording it here lets a handler
    /// *derive* the attribution rather than guess it.
    ///
    /// `Gateway` additionally tells a handler there is no inbound
    /// credential to exchange — `bearer_token` is empty by design,
    /// and the handler authenticates as itself instead.
    ///
    /// Defaults to `User`, which keeps every existing single-token
    /// call site meaning exactly what it meant before.
    #[serde(default)]
    subject: DelegationSubject,

    /// Name of the tool / agent / resource being called.
    target_name: String,

    /// Kind of downstream entity.
    #[serde(default)]
    target_type: TargetType,

    /// Audience URI for the target, from route config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target_audience: Option<String>,

    /// Required permissions from the target's `ObjectSecurityProfile`.
    /// Handlers must produce a credential that grants these (or fail).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    required_permissions: Vec<String>,

    /// Target's trust domain (SPIFFE-style) — useful for handlers
    /// that mint workload-identity tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    trust_domain: Option<String>,

    /// Who's responsible for enforcing authorization.
    #[serde(default)]
    auth_enforced_by: AuthEnforcedBy,

    /// Scope-attenuation config from the route DSL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    route_attenuation: Option<AttenuationConfig>,

    /// The minted outbound credential. `None` until a handler
    /// produces one. Carries the raw bytes (cleared on drop), the
    /// header the proxy plugin should attach it under, the
    /// audience it was minted for, the effective scopes, and the
    /// expiry timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_token: Option<RawDelegatedToken>,

    /// Chain update — the new hop to append to the running
    /// `DelegationExtension`. Handlers append themselves to the
    /// chain so audit / policy can trace who delegated to whom.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_update: Option<DelegationExtension>,

    /// What kind of principal the minted token represents.
    /// Handlers populating `delegated_token` should also set this
    /// so `apply_to_extensions` keys the cache correctly:
    ///
    ///   * `OnBehalfOfUser` — token speaks for the original user
    ///     (RFC 8693 on-behalf-of / actor-token, UCAN delegation).
    ///     Standard flow; cache key includes the user's subject id.
    ///   * `AsGateway` — token speaks for the gateway itself.
    ///     User identity is conveyed through separate context.
    ///     Cache key falls back to the gateway's identity.
    ///
    /// `None` defaults to `OnBehalfOfUser` for backward compatibility
    /// with handlers that don't yet populate the field. Long-term,
    /// handlers should always set this explicitly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_mode: Option<DelegationMode>,

    /// Resolution timestamp. Audit-useful.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minted_at: Option<DateTime<Utc>>,

    /// Optional metadata produced by the handler (telemetry,
    /// diagnostics). Not load-bearing for policy.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, serde_json::Value>,
}

impl DelegationPayload {
    /// Construct a payload with the required input fields populated.
    /// The most common entry point — outbound callers (forwarding
    /// proxies, etc.) build this once per delegation point. Optional
    /// input slots are set via the `.with_*` builders below; output
    /// fields start as `None` / empty and accumulate as handlers run.
    pub fn new(bearer_token: impl Into<String>, target_name: impl Into<String>) -> Self {
        Self {
            bearer_token: Zeroizing::new(bearer_token.into()),
            actor_token: Zeroizing::new(String::new()),
            actor_role: None,
            subject: DelegationSubject::default(),
            target_name: target_name.into(),
            target_type: TargetType::Tool,
            target_audience: None,
            required_permissions: Vec::new(),
            trust_domain: None,
            auth_enforced_by: AuthEnforcedBy::Caller,
            route_attenuation: None,
            delegated_token: None,
            delegation_update: None,
            delegation_mode: None,
            minted_at: None,
            metadata: HashMap::new(),
        }
    }

    /// Attach the RFC 8693 actor — the party acting on behalf of the
    /// subject — as a (role, credential) pair. The invoker sets this
    /// from the inbound workload SVID
    /// (`RawCredentialsExtension[CallerWorkload]`) when a delegation step
    /// opts into an actor, mirroring how `bearer_token` is sourced
    /// from the User-role token. A delegator forwards the token as
    /// `actor_token` only when non-empty.
    ///
    /// Role and token are set together deliberately: a token whose
    /// principal is unknown can't be attributed in the audit trail or
    /// partitioned correctly in the delegated-token cache.
    pub fn with_actor(mut self, role: TokenRole, actor_token: impl Into<String>) -> Self {
        self.actor_token = Zeroizing::new(actor_token.into());
        self.actor_role = Some(role);
        self
    }

    /// Record which principal this exchange is for. The invoker sets
    /// this from the step's `subject:` key, so handlers can attribute
    /// the minted token correctly instead of assuming a user is
    /// present — and can tell that a `Gateway` subject means "no
    /// inbound credential, authenticate as yourself."
    pub fn with_subject(mut self, subject: DelegationSubject) -> Self {
        self.subject = subject;
        self
    }

    pub fn with_target_type(mut self, t: TargetType) -> Self {
        self.target_type = t;
        self
    }

    pub fn with_target_audience(mut self, aud: impl Into<String>) -> Self {
        self.target_audience = Some(aud.into());
        self
    }

    pub fn with_required_permissions(mut self, perms: Vec<String>) -> Self {
        self.required_permissions = perms;
        self
    }

    pub fn with_trust_domain(mut self, td: impl Into<String>) -> Self {
        self.trust_domain = Some(td.into());
        self
    }

    pub fn with_auth_enforced_by(mut self, who: AuthEnforcedBy) -> Self {
        self.auth_enforced_by = who;
        self
    }

    pub fn with_route_attenuation(mut self, cfg: AttenuationConfig) -> Self {
        self.route_attenuation = Some(cfg);
        self
    }

    /// The caller's bearer token — borrowed, no way to move or
    /// replace the underlying `Zeroizing<String>` through this.
    pub fn bearer_token(&self) -> &str {
        &self.bearer_token
    }

    /// The actor token — borrowed. Empty string when no actor was
    /// attached (the common single-token exchange). Same borrow-only
    /// discipline as `bearer_token`: no way to move or replace the
    /// underlying `Zeroizing<String>` through this.
    pub fn actor_token(&self) -> &str {
        &self.actor_token
    }

    /// Which principal this exchange is for.
    pub fn subject(&self) -> &DelegationSubject {
        &self.subject
    }

    /// Which principal the actor token speaks for, or `None` when the
    /// exchange carries no actor.
    pub fn actor_role(&self) -> Option<&TokenRole> {
        self.actor_role.as_ref()
    }

    /// Whether the caller's attested workload identity took part in
    /// this exchange — either as the subject (a workload acting
    /// autonomously) or as the RFC 8693 actor alongside a user.
    ///
    /// Drives whether the minted token's cache key is partitioned by
    /// `caller_workload.spiffe_id`. It has to be, in both cases: the
    /// minted credential names the specific workload (as `sub` or as
    /// `act`), so a token minted for one agent is not interchangeable
    /// with one minted for another.
    pub fn involves_workload(&self) -> bool {
        self.subject == DelegationSubject::CallerWorkload
            || self.actor_role == Some(TokenRole::CallerWorkload)
    }

    pub fn target_name(&self) -> &str {
        &self.target_name
    }

    pub fn target_type(&self) -> &TargetType {
        &self.target_type
    }

    pub fn target_audience(&self) -> Option<&str> {
        self.target_audience.as_deref()
    }

    pub fn required_permissions(&self) -> &[String] {
        &self.required_permissions
    }

    pub fn trust_domain(&self) -> Option<&str> {
        self.trust_domain.as_deref()
    }

    pub fn auth_enforced_by(&self) -> AuthEnforcedBy {
        self.auth_enforced_by
    }

    pub fn route_attenuation(&self) -> Option<&AttenuationConfig> {
        self.route_attenuation.as_ref()
    }

    /// Layer another payload's *output* fields onto this one's,
    /// following "Some replaces None, last write wins per slot."
    /// Input fields are not touched — the running payload's input
    /// is canonical for the whole chain.
    ///
    /// Metadata is merged (not replaced) — `other`'s keys overlay
    /// `self`'s, matching the "later handler additively contributes
    /// telemetry" expectation.
    pub fn merge(&mut self, other: DelegationPayload) {
        if other.delegated_token.is_some() {
            self.delegated_token = other.delegated_token;
        }
        if other.delegation_update.is_some() {
            self.delegation_update = other.delegation_update;
        }
        if other.delegation_mode.is_some() {
            self.delegation_mode = other.delegation_mode;
        }
        if other.minted_at.is_some() {
            self.minted_at = other.minted_at;
        }
        for (k, v) in other.metadata {
            self.metadata.insert(k, v);
        }
    }

    /// Pull the resolved `DelegationPayload` out of a `PipelineResult`
    /// returned by `mgr.invoke_named::<TokenDelegateHook>(...)`.
    /// Returns `None` when the pipeline was denied or when the result's
    /// payload wasn't a `DelegationPayload`. Same contract as
    /// `IdentityPayload::from_pipeline_result`.
    pub fn from_pipeline_result(result: &PipelineResult) -> Option<Self> {
        result
            .modified_payload
            .as_ref()
            .and_then(|p| p.as_any().downcast_ref::<DelegationPayload>())
            .cloned()
    }

    /// Apply this payload's resolved output slots back into an
    /// `Extensions` container. Returns a new `Extensions` ready to
    /// hand to the outbound proxy plugin that will attach the minted
    /// credential and forward.
    ///
    /// Application rules:
    ///
    /// - **`raw_credentials.delegated_tokens`** — if the payload
    ///   carries a `delegated_token`, it's inserted into the map under
    ///   a `DelegationKey` derived from the input fields (audience,
    ///   subject not yet plumbed — see "Open work" below). Pre-existing
    ///   delegated tokens are preserved.
    /// - **`delegation`** — `delegation_update` overlays on top of
    ///   the existing chain (Some replaces None / appends).
    ///
    /// # Key composition
    ///
    /// `audience`, `scopes` and `mode` come off the payload. The two
    /// principal fields are read out of the request's `Extensions`
    /// here rather than asking outbound callers to thread them
    /// through:
    ///
    /// - `subject_id` from `security.subject.id`, empty when no user
    ///   took part (a workload acting autonomously).
    /// - `workload_id` from `security.caller_workload.spiffe_id`,
    ///   populated only when [`involves_workload`] — i.e. when a
    ///   workload credential was the subject or the RFC 8693 actor.
    ///
    /// Both are needed. An empty `subject_id` is not a unique
    /// principal: every workload-subject exchange has one, so without
    /// `workload_id` two different calling agents requesting the same
    /// audience and scopes collide on a single key and get served
    /// each other's tokens. Populating `workload_id` only when a
    /// workload actually participated keeps ordinary user-only
    /// delegations sharing one entry rather than being partitioned
    /// per caller for no reason.
    ///
    /// [`involves_workload`]: DelegationPayload::involves_workload
    pub fn apply_to_extensions(&self, mut ext: Extensions) -> Extensions {
        if let Some(ref token) = self.delegated_token {
            use crate::extensions::raw_credentials::DelegationKey;

            let subject_id = ext
                .security
                .as_ref()
                .and_then(|s| s.subject.as_ref())
                .and_then(|s| s.id.clone())
                .unwrap_or_default();

            // Which calling agent this token was minted for. Only set
            // when a workload actually participated — see the
            // "Key composition" note above for why both principals
            // have to be in the key.
            let workload_id = if self.involves_workload() {
                ext.security
                    .as_ref()
                    .and_then(|s| s.caller_workload.as_ref())
                    .and_then(|w| w.spiffe_id.clone())
            } else {
                None
            };

            // Default to OnBehalfOfUser when the handler didn't
            // populate `delegation_mode`. Backward-compatible with
            // earlier handlers; future handlers should
            // populate the field explicitly.
            let mode = self
                .delegation_mode
                .clone()
                .unwrap_or(DelegationMode::OnBehalfOfUser);
            let key = DelegationKey {
                subject_id,
                workload_id,
                audience: token.audience.clone(),
                scopes: token.scopes.clone(),
                mode,
            };

            let mut raw = ext
                .raw_credentials
                .as_ref()
                .map(|arc| (**arc).clone())
                .unwrap_or_else(RawCredentialsExtension::default);
            raw.delegated_tokens.insert(key, token.clone());
            ext.raw_credentials = Some(Arc::new(raw));
        }

        if let Some(ref update) = self.delegation_update {
            // Replace wholesale for v0. A per-hop append semantics
            // would deep-merge the chain, but `DelegationExtension`'s
            // append rules live with the type — handlers that want
            // to add a hop produce a `DelegationExtension` containing
            // the new hop in its chain.
            ext.delegation = Some(Arc::new(update.clone()));
        }

        ext
    }
}

impl_plugin_payload!(DelegationPayload);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::raw_credentials::RawDelegatedToken;

    #[test]
    fn bearer_token_does_not_serialize() {
        let p = DelegationPayload::new("eyJ.caller.tok", "get_compensation");
        let json = serde_json::to_string(&p).unwrap();
        assert!(
            !json.contains("eyJ.caller.tok"),
            "bearer_token leaked into serialized form: {}",
            json,
        );
        assert!(json.contains("get_compensation"));
    }

    #[test]
    fn deserialize_yields_empty_bearer_token() {
        let json = r#"{"target_name":"get_compensation"}"#;
        let p: DelegationPayload = serde_json::from_str(json).unwrap();
        assert_eq!(p.bearer_token(), "");
        assert_eq!(p.target_name(), "get_compensation");
    }

    #[test]
    fn actor_token_defaults_empty_and_builder_sets_it() {
        // No actor by default — the common single-token exchange.
        let p = DelegationPayload::new("caller.tok", "get_compensation");
        assert_eq!(p.actor_token(), "");
        assert_eq!(p.actor_role(), None);

        // Builder attaches the workload SVID (as the invoker does),
        // recording whose credential it is at the same time.
        let p = p.with_actor(TokenRole::CallerWorkload, "svid.jwt.bytes");
        assert_eq!(p.actor_token(), "svid.jwt.bytes");
        assert_eq!(p.actor_role(), Some(&TokenRole::CallerWorkload));
        // Subject is untouched — the two tokens are independent slots.
        assert_eq!(p.bearer_token(), "caller.tok");
    }

    #[test]
    fn involves_workload_covers_both_subject_and_actor_positions() {
        // Neither position: a plain user delegation.
        let user_only = DelegationPayload::new("caller.tok", "t");
        assert!(!user_only.involves_workload());

        // Subject position (Mode A) — workload acting autonomously.
        let mode_a =
            DelegationPayload::new("svid", "t").with_subject(DelegationSubject::CallerWorkload);
        assert!(mode_a.involves_workload());

        // Actor position (Mode B) — user subject, workload actor. The
        // minted token names the workload in `act`, so it still has to
        // partition the cache.
        let mode_b = DelegationPayload::new("user.tok", "t")
            .with_actor(TokenRole::CallerWorkload, "svid.jwt.bytes");
        assert!(mode_b.involves_workload());

        // A non-workload actor doesn't trigger it — nothing to key by.
        let client_actor =
            DelegationPayload::new("user.tok", "t").with_actor(TokenRole::Client, "client.tok");
        assert!(!client_actor.involves_workload());
    }

    #[test]
    fn subject_defaults_to_user_and_builder_overrides_it() {
        // Default keeps every pre-existing single-token call site
        // meaning what it always meant: on-behalf-of a user.
        let p = DelegationPayload::new("caller.tok", "get_compensation");
        assert_eq!(p.subject(), &DelegationSubject::User);

        // The calling agent acting autonomously.
        let p = p.with_subject(DelegationSubject::CallerWorkload);
        assert_eq!(p.subject(), &DelegationSubject::CallerWorkload);
    }

    /// `Gateway` is the one subject with no inbound credential — it
    /// proves who it is by being itself rather than by exchanging
    /// something the caller sent. Handlers key the "an empty bearer
    /// token is expected here" decision off exactly this.
    #[test]
    fn only_gateway_has_no_inbound_role() {
        assert_eq!(
            DelegationSubject::User.inbound_role(),
            Some(TokenRole::User),
        );
        assert_eq!(
            DelegationSubject::Client.inbound_role(),
            Some(TokenRole::Client),
        );
        assert_eq!(
            DelegationSubject::CallerWorkload.inbound_role(),
            Some(TokenRole::CallerWorkload),
        );
        assert_eq!(DelegationSubject::Gateway.inbound_role(), None);
    }

    #[test]
    fn subject_parses_from_config_including_legacy_workload_spelling() {
        assert_eq!(
            DelegationSubject::from_config_str("caller_workload"),
            Some(DelegationSubject::CallerWorkload),
        );
        // Configs written before the rename keep working.
        assert_eq!(
            DelegationSubject::from_config_str("workload"),
            Some(DelegationSubject::CallerWorkload),
        );
        assert_eq!(
            DelegationSubject::from_config_str("gateway"),
            Some(DelegationSubject::Gateway),
        );
        // A typo resolves to None so the caller applies its own
        // default rather than silently picking a principal.
        assert_eq!(DelegationSubject::from_config_str("gatewy"), None);
    }

    #[test]
    fn actor_token_does_not_serialize() {
        let p = DelegationPayload::new("caller.tok", "get_compensation")
            .with_actor(TokenRole::CallerWorkload, "eyJ.workload.svid");
        let json = serde_json::to_string(&p).unwrap();
        assert!(
            !json.contains("eyJ.workload.svid"),
            "actor_token leaked into serialized form: {}",
            json,
        );
    }

    #[test]
    fn input_builders_chain() {
        let p = DelegationPayload::new("tok", "get_compensation")
            .with_target_type(TargetType::Tool)
            .with_target_audience("https://hr.example.com")
            .with_required_permissions(vec!["read:compensation".into()])
            .with_trust_domain("hr.example.com")
            .with_auth_enforced_by(AuthEnforcedBy::Target)
            .with_route_attenuation(AttenuationConfig {
                capabilities: vec!["read:compensation".into()],
                resource_template: Some("hr://employees/{{ args.employee_id }}".into()),
                actions: vec!["read".into()],
                ttl_seconds: Some(60),
            });
        assert_eq!(p.bearer_token(), "tok");
        assert_eq!(p.target_name(), "get_compensation");
        assert_eq!(p.target_audience(), Some("https://hr.example.com"));
        assert_eq!(p.required_permissions(), &["read:compensation".to_string()]);
        assert_eq!(p.trust_domain(), Some("hr.example.com"));
        assert_eq!(p.auth_enforced_by(), AuthEnforcedBy::Target);
        let att = p.route_attenuation().unwrap();
        assert_eq!(att.ttl_seconds, Some(60));
        assert_eq!(att.actions, vec!["read"]);
    }

    #[test]
    fn target_type_custom_round_trips() {
        let t = TargetType::Custom("workflow".into());
        let json = serde_json::to_string(&t).unwrap();
        let back: TargetType = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
    }

    #[test]
    fn handler_can_populate_output_on_clone() {
        // Typical handler pattern: clone running payload, set
        // delegated_token + delegation_update, return.
        let original = DelegationPayload::new("caller-tok", "downstream-tool");
        let mut updated = original.clone();
        updated.delegated_token = Some(RawDelegatedToken::new(
            "minted-bytes",
            "Authorization",
            "https://api.example.com",
            vec!["read".into()],
            Utc::now(),
        ));
        // Input survives the clone.
        assert_eq!(updated.bearer_token(), "caller-tok");
        assert_eq!(updated.target_name(), "downstream-tool");
        // Output populated.
        assert!(updated.delegated_token.is_some());
        // Original untouched.
        assert!(original.delegated_token.is_none());
    }

    #[test]
    fn merge_overlays_outputs() {
        let mut base = DelegationPayload::new("tok", "tool");
        base.metadata.insert("attempt".into(), serde_json::json!(1));
        let mut overlay = DelegationPayload::new("", "");
        overlay.delegated_token = Some(RawDelegatedToken::new(
            "x",
            "Authorization",
            "aud",
            vec![],
            Utc::now(),
        ));
        overlay
            .metadata
            .insert("latency_ms".into(), serde_json::json!(42));
        base.merge(overlay);
        assert!(base.delegated_token.is_some());
        // Metadata merged additively — both keys present.
        assert!(base.metadata.contains_key("attempt"));
        assert!(base.metadata.contains_key("latency_ms"));
    }

    #[test]
    fn apply_to_extensions_writes_delegated_token_keyed_by_audience() {
        use crate::extensions::raw_credentials::DelegationMode;
        use crate::extensions::SubjectExtension;

        let mut p = DelegationPayload::new("tok", "get_compensation");
        p.delegated_token = Some(RawDelegatedToken::new(
            "minted-jwt",
            "Authorization",
            "https://hr.example.com",
            vec!["read:compensation".into()],
            Utc::now() + chrono::Duration::seconds(300),
        ));

        // Pre-existing subject in extensions — DelegationKey.subject_id
        // should pull from there.
        let initial_ext = Extensions {
            security: Some(Arc::new(crate::extensions::SecurityExtension {
                subject: Some(SubjectExtension {
                    id: Some("alice".into()),
                    ..Default::default()
                }),
                ..Default::default()
            })),
            ..Default::default()
        };

        let updated = p.apply_to_extensions(initial_ext);
        let raw = updated.raw_credentials.as_ref().unwrap();
        assert_eq!(raw.delegated_tokens.len(), 1);

        // Look up by the synthesized key.
        let expected_key = crate::extensions::raw_credentials::DelegationKey {
            subject_id: "alice".into(),
            // No workload in this exchange, so the key isn't
            // partitioned by one.
            workload_id: None,
            audience: "https://hr.example.com".into(),
            scopes: vec!["read:compensation".into()],
            mode: DelegationMode::OnBehalfOfUser,
        };
        assert!(raw.delegated_tokens.contains_key(&expected_key));
    }

    /// The end-to-end version of the collision guard: two different
    /// calling agents run the same workload-subject exchange against
    /// the same audience and scopes, sharing one `delegated_tokens`
    /// map. Neither has a user, so both keys carry an empty
    /// `subject_id`; only `workload_id` keeps them apart. If it didn't,
    /// the second agent would overwrite the first's entry and — once a
    /// cross-request cache exists — be served the first agent's token.
    #[test]
    fn two_agents_do_not_share_one_cache_entry() {
        use crate::extensions::security::WorkloadIdentity;

        /// A Mode A payload: workload subject, no user.
        fn workload_exchange(minted: &str) -> DelegationPayload {
            let mut p = DelegationPayload::new("svid-bytes", "get_compensation")
                .with_subject(DelegationSubject::CallerWorkload);
            p.delegated_token = Some(RawDelegatedToken::new(
                minted,
                "Authorization",
                "https://hr.example.com",
                vec!["read:compensation".into()],
                Utc::now() + chrono::Duration::seconds(300),
            ));
            p.delegation_mode = Some(DelegationMode::AsCallerWorkload);
            p
        }

        /// Extensions whose attested caller is `spiffe_id`, carrying
        /// over any already-cached tokens so the two exchanges share
        /// one map.
        fn ext_for(spiffe_id: &str, carry: Option<Arc<RawCredentialsExtension>>) -> Extensions {
            Extensions {
                security: Some(Arc::new(crate::extensions::SecurityExtension {
                    caller_workload: Some(WorkloadIdentity {
                        spiffe_id: Some(spiffe_id.into()),
                        ..Default::default()
                    }),
                    ..Default::default()
                })),
                raw_credentials: carry,
                ..Default::default()
            }
        }

        // Agent 1 mints, then agent 2 mints against the same map.
        let after_payroll = workload_exchange("payroll-token")
            .apply_to_extensions(ext_for("spiffe://corp/payroll", None));
        let carried = after_payroll.raw_credentials.clone();
        let after_both = workload_exchange("recruiting-token")
            .apply_to_extensions(ext_for("spiffe://corp/recruiting", carried));

        let raw = after_both.raw_credentials.as_ref().unwrap();
        assert_eq!(
            raw.delegated_tokens.len(),
            2,
            "each calling agent must get its own cache entry; keys: {:?}",
            raw.delegated_tokens.keys().collect::<Vec<_>>(),
        );

        // And each entry holds that agent's own token — the point of
        // the exercise.
        let lookup = |spiffe: &str| {
            raw.delegated_tokens
                .get(&crate::extensions::raw_credentials::DelegationKey {
                    subject_id: String::new(),
                    workload_id: Some(spiffe.into()),
                    audience: "https://hr.example.com".into(),
                    scopes: vec!["read:compensation".into()],
                    mode: DelegationMode::AsCallerWorkload,
                })
                .map(|t| (*t.token).clone())
        };
        assert_eq!(
            lookup("spiffe://corp/payroll").as_deref(),
            Some("payroll-token"),
        );
        assert_eq!(
            lookup("spiffe://corp/recruiting").as_deref(),
            Some("recruiting-token"),
        );
    }

    #[test]
    fn apply_to_extensions_respects_explicit_delegation_mode() {
        // Handler that mints an AsGateway-mode token (gateway-as-principal
        // flow). The key in `delegated_tokens` should carry AsGateway,
        // not the default OnBehalfOfUser.
        let mut p = DelegationPayload::new("tok", "tool");
        p.delegated_token = Some(RawDelegatedToken::new(
            "gateway-token",
            "Authorization",
            "https://downstream.example.com",
            vec!["service:call".into()],
            Utc::now(),
        ));
        p.delegation_mode = Some(crate::extensions::raw_credentials::DelegationMode::AsGateway);

        let updated = p.apply_to_extensions(Extensions::default());
        let raw = updated.raw_credentials.as_ref().unwrap();
        let key = raw.delegated_tokens.keys().next().unwrap();
        assert!(matches!(
            key.mode,
            crate::extensions::raw_credentials::DelegationMode::AsGateway
        ));
    }

    #[test]
    fn apply_to_extensions_defaults_delegation_mode_when_unset() {
        // Handler that didn't populate delegation_mode — apply should
        // use OnBehalfOfUser as the safe default.
        let mut p = DelegationPayload::new("tok", "tool");
        p.delegated_token = Some(RawDelegatedToken::new(
            "user-token",
            "Authorization",
            "https://aud.example.com",
            vec!["read".into()],
            Utc::now(),
        ));
        // delegation_mode left None.
        let updated = p.apply_to_extensions(Extensions::default());
        let raw = updated.raw_credentials.as_ref().unwrap();
        let key = raw.delegated_tokens.keys().next().unwrap();
        assert!(matches!(
            key.mode,
            crate::extensions::raw_credentials::DelegationMode::OnBehalfOfUser
        ));
    }

    #[test]
    fn merge_threads_delegation_mode_through_chain() {
        // Handler A leaves delegation_mode unset; handler B sets it.
        // After merge, the accumulator should carry handler B's mode.
        let mut base = DelegationPayload::new("tok", "tool");
        // base.delegation_mode = None
        let mut overlay = DelegationPayload::new("", "");
        overlay.delegation_mode =
            Some(crate::extensions::raw_credentials::DelegationMode::AsGateway);
        base.merge(overlay);
        assert!(matches!(
            base.delegation_mode,
            Some(crate::extensions::raw_credentials::DelegationMode::AsGateway)
        ));
    }

    #[test]
    fn apply_to_extensions_falls_back_to_empty_subject_id_when_no_subject() {
        // Gateway-as-principal flow — no Subject extension present.
        // The DelegationKey falls back to empty subject_id rather
        // than panicking; flagged via tracing in production but
        // not fatal here.
        let mut p = DelegationPayload::new("tok", "tool");
        p.delegated_token = Some(RawDelegatedToken::new(
            "minted",
            "Authorization",
            "aud",
            vec![],
            Utc::now(),
        ));
        let updated = p.apply_to_extensions(Extensions::default());
        let raw = updated.raw_credentials.as_ref().unwrap();
        let key = raw.delegated_tokens.keys().next().unwrap();
        assert_eq!(key.subject_id, "");
    }

    #[test]
    fn auth_enforced_by_defaults_to_caller() {
        let p = DelegationPayload::new("tok", "tool");
        assert_eq!(p.auth_enforced_by(), AuthEnforcedBy::Caller);
    }

    #[test]
    fn target_type_defaults_to_tool() {
        let p = DelegationPayload::new("tok", "tool");
        assert_eq!(p.target_type(), &TargetType::Tool);
    }
}
