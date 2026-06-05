// Location: ./crates/cpex-core/src/delegation/payload.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// `DelegationPayload` — the unified state struct threaded through the
// TokenDelegate hook chain. Same input/output split pattern as
// `IdentityPayload` (slice 2):
//
//   * **Input** (private — host-supplied, never mutated by handlers) —
//     `bearer_token`, `target_name`, `target_type`, `target_audience`,
//     `required_permissions`, `trust_domain`, `auth_enforced_by`,
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
// IdentityResolve (slice 2) is *inbound* — validates the caller's
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
// Not in this slice. The spec describes a `TokenCacheControl` trait
// at §9.8 that wraps this hook with `get_or_mint(audience, scopes)`
// semantics — outbound callers ask the trait for a token; the trait
// hits the cache first and only dispatches through the hook on cache
// miss. That layer lives one slice later. For now, every
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
use crate::extensions::raw_credentials::DelegationMode;
use crate::extensions::{
    DelegationExtension, Extensions, RawCredentialsExtension, RawDelegatedToken,
};
use crate::impl_plugin_payload;

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
    // ----- Input (private — caller-supplied, never mutated by handlers) -----
    /// The caller's current credential — the one a token-exchange
    /// handler will swap for a downstream-scoped credential. Cleared
    /// on drop via `Zeroizing`. `#[serde(skip)]` — never appears in
    /// serialized output.
    #[serde(skip)]
    bearer_token: Zeroizing<String>,

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

    // ----- Output (pub — handlers populate via direct assignment on clones) -----
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
    pub fn new(
        bearer_token: impl Into<String>,
        target_name: impl Into<String>,
    ) -> Self {
        Self {
            bearer_token: Zeroizing::new(bearer_token.into()),
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

    // -------- Input builders --------

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

    // -------- Input read accessors --------

    /// The caller's bearer token — borrowed, no way to move or
    /// replace the underlying `Zeroizing<String>` through this.
    pub fn bearer_token(&self) -> &str {
        &self.bearer_token
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

    // -------- Output helpers --------

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

    // -------- Host-side application helpers --------

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
    /// # Open work
    ///
    /// The `DelegationKey` we synthesize here uses only fields the
    /// payload knows about — `audience`, `scopes` (derived from the
    /// effective scopes on the minted token), `mode`. The `subject_id`
    /// field of `DelegationKey` requires reading the request's
    /// `Extensions.security.subject.id`; we plumb that lookup here
    /// rather than asking outbound callers to thread the subject
    /// through. If `security.subject.id` is absent the key falls back
    /// to the empty string — flagged via tracing but not fatal,
    /// because some delegation flows are gateway-as-principal
    /// (AsGateway mode) and don't need a subject.
    pub fn apply_to_extensions(&self, mut ext: Extensions) -> Extensions {
        if let Some(ref token) = self.delegated_token {
            use crate::extensions::raw_credentials::DelegationKey;

            let subject_id = ext
                .security
                .as_ref()
                .and_then(|s| s.subject.as_ref())
                .and_then(|s| s.id.clone())
                .unwrap_or_default();

            // Default to OnBehalfOfUser when the handler didn't
            // populate `delegation_mode`. Backward-compatible with
            // handlers from sub-step B; future handlers should
            // populate the field explicitly.
            let mode = self
                .delegation_mode
                .clone()
                .unwrap_or(DelegationMode::OnBehalfOfUser);
            let key = DelegationKey {
                subject_id,
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
        base.metadata
            .insert("attempt".into(), serde_json::json!(1));
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
            audience: "https://hr.example.com".into(),
            scopes: vec!["read:compensation".into()],
            mode: DelegationMode::OnBehalfOfUser,
        };
        assert!(raw.delegated_tokens.contains_key(&expected_key));
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
        p.delegation_mode = Some(
            crate::extensions::raw_credentials::DelegationMode::AsGateway,
        );

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
        overlay.delegation_mode = Some(
            crate::extensions::raw_credentials::DelegationMode::AsGateway,
        );
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
