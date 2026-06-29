// Location: ./crates/apl-core/src/step.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Policy-phase Step IR and async dispatch traits.
//
// The DSL allows policy:/post_policy: lists to contain three kinds of
// entries beyond predicate-and-action rules:
//
//   - PDP calls: `cedar:(...)`, `opa(...)`, `authzen(...)`, `nemo(...)`,
//     `cel:(...)` with optional `on_deny:` / `on_allow:` reaction blocks
//   - Plugin invocations: `plugin(name)`
//   - Taint effects: `taint(label[, scope])`
//
// `Step` is the union over these forms plus the existing `Rule`. The async
// `evaluate_steps` function walks a Step list, dispatching PDP calls via
// `PdpResolver` and plugin calls via `PluginInvoker`. Taint dispatch is
// recognized but no-op in apl-core — actual SessionStore writes happen in
// `apl-cpex`, which has access to that machinery.
//
// Grounded in apl-dsl-spec.md §3 (effects) / §7 (PDP integration) and
// apl-design.md §8.1 (PdpResolver seam).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::evaluator::Decision;
use crate::pipeline::{TaintEvent, TaintScope};
use crate::rules::Rule;

/// Parser-internal intermediate IR. After the parser builds a Step
/// tree, `parser::step_to_top_level_effect` converts it into the
/// unified [`crate::rules::Effect`] used by the evaluator + every
/// public entry point.
///
/// `Step` exists only because `parse_step` builds its nodes
/// incrementally and the conversion to `Effect::When` /
/// `Effect::Pdp` happens at the top of `compile_apl_blocks` once
/// the source position is known. Not part of the public API as of
/// E4 — external code dispatches on `Effect` everywhere.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Step {
    /// Predicate-and-action rule (the existing 5a/5b/5c case).
    Rule(Rule),

    /// External PDP call. `on_deny` / `on_allow` are reaction Step lists
    /// that fire based on the PDP's decision (DSL §7.5).
    Pdp {
        call: PdpCall,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        on_deny: Vec<Step>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        on_allow: Vec<Step>,
    },

    /// `plugin(name)` — invoke a CPEX-registered plugin. The plugin's
    /// `PluginResult` decision becomes the step's outcome.
    Plugin { name: String },

    /// `delegate: { plugin: ..., ... }` — mint a downstream delegation
    /// token via a TokenDelegateHook plugin. Populates
    /// `delegation.granted_*` attributes in the bag so subsequent
    /// rules in the same step list can read them. See
    /// `docs/apl-identity-delegation-design.md`.
    Delegate(DelegateStep),

    /// `taint(label[, scope])` — apply a taint label. Always succeeds;
    /// never produces a Deny. SessionStore dispatch happens in apl-cpex.
    Taint {
        label: String,
        scopes: Vec<TaintScope>,
    },
}

/// One delegation invocation inside `policy:` or `post_policy:`.
///
/// At runtime the apl-cpex `DelegationInvoker` constructs a
/// `cpex_core::delegation::DelegationPayload` from
///   * the inbound bearer token (pulled from
///     `Extensions.raw_credentials.inbound_tokens`),
///   * this step's `args` (target / audience / permissions / mode /
///     attenuation, layered over the plugin's configured defaults),
///   * extensions-derived context (subject, prior delegation chain),
///
/// then calls `manager.invoke_entries::<TokenDelegateHook>(...)`. On
/// success the resulting `delegated_token` is written into
/// `Extensions.raw_credentials.delegated_tokens.*` and the granted
/// scopes / audience surface as `delegation.granted.*` attributes
/// in the policy bag for downstream rules to inspect.
///
/// `args` is a free-form map because each delegation backend has its
/// own typed config shape; apl-core treats it as opaque and hands it
/// to the plugin via the existing per-call config-override pathway.
///
/// # Multiple `delegate(...)` in one phase (most-recent-wins)
///
/// Multiple `delegate(...)` steps in the same phase are supported —
/// each fires independently, each contributes to `Extensions`
/// (`raw_credentials.delegated_tokens` is a HashMap keyed on
/// audience+scope+mode so tokens accumulate; `delegation.chain`
/// grows with each hop). But the `delegation.granted.*` bag keys
/// are **overwritten** on each call — only the most recent
/// delegate's grants are queryable from downstream `require(...)`
/// rules.
///
/// For fan-out flows that need multiple independently-queryable
/// grants, split into `policy:` + `post_policy:` or reach for a
/// future per-step `as:` alias (not in v0; see the design doc's
/// "Open design questions" section).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DelegateStep {
    /// Plugin name — must reference an entry in the top-level
    /// `plugins:` block that registers under the `token.delegate`
    /// hook.
    pub plugin_name: String,

    /// Per-call config overrides applied for this delegation only.
    /// Layered on top of the plugin's default config; the framework's
    /// `build_override_entries` plumbing handles the merge.
    /// Common keys: `target`, `audience`, `permissions`, `mode`,
    /// `attenuation`. Schema is plugin-defined.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_override: Option<serde_yaml::Value>,

    /// `deny | continue` — what to do when the plugin returns a
    /// deny (e.g. IdP refusal, network error). `None` defaults to
    /// `"deny"` (fail-closed; matches PDP step semantics).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_error: Option<String>,

    /// Human-readable source path (e.g.
    /// `"route.get_compensation.policy[2]"`) — used in audit and
    /// `Decision::Deny.rule_source` when the step denies.
    pub source: String,
}

/// A PDP invocation, opaque-args style. Resolvers parse `args` based on
/// the dialect they handle — apl-core doesn't impose a Cedar/OPA/AuthZen
/// schema on `args`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PdpCall {
    pub dialect: PdpDialect,
    /// Dialect-specific call arguments — typically a map for Cedar
    /// (`action`, `resource`, …) or a string for OPA/AuthZen/NeMo
    /// (a path or query). Resolvers parse this; apl-core treats it
    /// as opaque.
    pub args: serde_yaml::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PdpDialect {
    /// Bare Cedar policy evaluation (`cpex-pdp-cedar-direct`).
    Cedar,
    Opa,
    AuthZen,
    NeMo,
    /// CEL (Common Expression Language) evaluation — `cpex-pdp-cel`.
    /// The `cel:` step carries an `expr:` string that must evaluate to a
    /// boolean against the policy `AttributeBag` (exposed to CEL as nested
    /// namespaces: `subject.id`, `delegation.depth`, `session.labels`, …).
    /// A small, safe, non-Turing-complete predicate language — distinct
    /// from the full PDPs (Cedar/OPA) so all can coexist on one
    /// `PdpRouter`. The canonical route-YAML form is the block map
    /// `cel: { expr: "..." }`; the `cel:(...)` call form is also accepted.
    Cel,
    #[serde(untagged)]
    Custom(String),
}

impl PdpDialect {
    /// Parse a YAML key prefix like `cedar`, `opa`, `authzen`, `nemo`
    /// into the matching `PdpDialect`. Unknown dialects become `Custom`.
    pub fn from_key(key: &str) -> Self {
        match key {
            "cedar" => Self::Cedar,
            "opa" => Self::Opa,
            "authzen" => Self::AuthZen,
            "nemo" => Self::NeMo,
            "cel" => Self::Cel,
            other => Self::Custom(other.to_string()),
        }
    }
}

// =====================================================================
// Resolver traits
// =====================================================================

/// External policy-decision dispatch. Implemented by Cedar, OPA HTTP
/// clients, AuthZen clients, NeMo Guardrails — anything that can answer
/// "given this call, allow or deny?" against a request context.
///
/// `apl-cpex` provides the bridge from CPEX plugins (e.g. `cedar-direct`)
/// to this trait so the host doesn't have to know about the plugin types.
#[async_trait]
pub trait PdpResolver: Send + Sync {
    /// What dialect this resolver handles. The evaluator routes PDP steps
    /// to the resolver whose `dialect()` matches `Step::Pdp.call.dialect`.
    fn dialect(&self) -> PdpDialect;

    async fn evaluate(
        &self,
        call: &PdpCall,
        bag: &crate::attributes::AttributeBag,
    ) -> Result<PdpDecision, PdpError>;
}

/// Build a [`PdpResolver`] from a unified-config block. Implemented per
/// PDP backend (cedar-direct, opa, …) and registered with
/// the apl-cpex visitor so unified-config YAML can declare PDPs
/// without the host pre-constructing them in code.
///
/// Hosts register a factory by handing it to apl-cpex's
/// `AplOptions.pdp_factories`. When the visitor walks the unified
/// config and finds a `global.apl.pdp[].kind` matching the factory's
/// reported `kind()`, it calls `build` with the rest of that block.
///
/// The error type is `Box<dyn Error + Send + Sync>` to keep this trait
/// in apl-core (which has no cpex deps). apl-cpex's visitor wraps
/// the boxed error into `VisitorError` → `PluginError::Config` at the
/// manager boundary.
pub trait PdpFactory: Send + Sync {
    /// Identifies which `kind:` in a config block this factory handles.
    /// Convention: kebab-case matching the published PDP product name
    /// (`"cedar-direct"`, `"opa"`, …).
    fn kind(&self) -> &str;

    /// Build a resolver from the rest of the PDP config block (everything
    /// under the same map level as `kind`). Implementations parse their
    /// own config shape; missing or malformed fields surface here.
    fn build(
        &self,
        config: &serde_yaml::Value,
    ) -> Result<std::sync::Arc<dyn PdpResolver>, Box<dyn std::error::Error + Send + Sync>>;
}

/// Where in the request lifecycle a plugin dispatch is happening.
/// Threads through `PluginInvocation` so the invoker can select the
/// right hook entry from a plugin that registered for both pre and
/// post phases (e.g. `cmf.tool_pre_invoke` AND `cmf.tool_post_invoke`).
///
/// APL's four phases map to two dispatch phases:
///   * `args:` field stages    → `Pre`
///   * `policy:` steps         → `Pre`
///   * `result:` field stages  → `Post`
///   * `post_policy:` steps    → `Post`
///
/// Plugins that need to discriminate `args` vs `policy` (same `Pre`
/// from the dispatcher's perspective) inspect `PluginContext::hook_name()`
/// inside their handler — the hook-routing layer doesn't slice phase
/// finer than Pre/Post.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchPhase {
    Pre,
    Post,
}

/// Context for one plugin invocation: tells the invoker the *intent* of
/// the call so it can dispatch to the right CPEX hook contract.
///
/// `Step` is the policy / post_policy case — the invoker (apl-cpex side)
/// already holds a typed payload reference; APL doesn't need to pass one.
///
/// `Field` is the pipe-chain case — APL is focused on a specific field
/// value mid-transform and the plugin may rewrite that value via
/// `PluginOutcome.modified_value`.
///
/// Both variants carry a `DispatchPhase` so the invoker can resolve the
/// right hook entry against the cpex-core hook routing table when the
/// plugin registered for multiple hooks.
#[derive(Debug, Clone, Copy)]
pub enum PluginInvocation<'a> {
    /// Called from a `policy:` or `post_policy:` step. The plugin operates
    /// on whatever typed payload the invoker was bound to.
    Step { phase: DispatchPhase },
    /// Called inside an `args:` / `result:` pipe chain on one field.
    Field {
        name: &'a str,
        value: &'a serde_json::Value,
        phase: DispatchPhase,
    },
}

impl<'a> PluginInvocation<'a> {
    /// Convenience: the dispatch phase carried by this invocation.
    pub fn phase(&self) -> DispatchPhase {
        match self {
            PluginInvocation::Step { phase } => *phase,
            PluginInvocation::Field { phase, .. } => *phase,
        }
    }
}

/// Plugin invocation dispatch. apl-cpex wraps the CPEX `PluginManager`
/// behind this trait so the apl-core evaluator stays free of cpex-core
/// dependencies.
#[async_trait]
pub trait PluginInvoker: Send + Sync {
    /// Invoke the named plugin against the current request context. The
    /// `invocation` discriminates step vs pipe-chain call.
    async fn invoke(
        &self,
        name: &str,
        bag: &crate::attributes::AttributeBag,
        invocation: PluginInvocation<'_>,
    ) -> Result<PluginOutcome, PluginError>;
}

/// Delegation dispatch — invokes a `TokenDelegateHook` plugin to mint
/// a downstream credential. apl-cpex implements this against
/// `cpex_core::PluginManager::invoke_entries::<TokenDelegateHook>`.
///
/// The invoker holds the request-scoped `Extensions` internally
/// (same pattern as `CmfPluginInvoker`), so the trait method doesn't
/// need to pass them — the invoker uses its own snapshot to construct
/// the `DelegationPayload` (inbound bearer token, subject, prior
/// delegation chain).
#[async_trait]
pub trait DelegationInvoker: Send + Sync {
    /// Run one delegation step. Returns a `DelegationOutcome` carrying
    /// the granted permissions / audience / expiry the IdP issued; the
    /// evaluator writes those into the bag as `delegation.granted_*`
    /// attributes so subsequent rules in the same step list can
    /// inspect them via `require(delegation.granted_permissions
    /// contains "X")` etc.
    ///
    /// `step.config_override` is layered on top of the plugin's
    /// default config and threaded through the standard per-call
    /// override pathway.
    async fn delegate(&self, step: &DelegateStep) -> Result<DelegationOutcome, DelegationError>;
}

/// What a delegation invocation returned.
///
/// On success, `decision` is `Allow` and the granted_* fields reflect
/// what the IdP actually issued (which may be narrower than what the
/// route asked for — `granted_permissions` is the source of truth for
/// what the downstream tool will accept). The evaluator surfaces these
/// into the bag under the `delegation.granted.*` sub-namespace plus a
/// `delegation.granted = true` flag.
///
/// On `Deny`, granted_* fields are empty / `None` and the
/// `delegation.granted` flag is not set (absent → falsy).
#[derive(Debug, Clone)]
pub struct DelegationOutcome {
    pub decision: Decision,
    /// Permissions the IdP actually granted on the minted token. Empty
    /// when the call failed or the plugin returned no token.
    pub granted_permissions: Vec<String>,
    /// Audience the minted token is valid for. `None` when no token
    /// was produced.
    pub granted_audience: Option<String>,
    /// Token expiry (RFC 3339 string for bag-friendly representation).
    /// `None` when no token was produced.
    pub granted_expires_at: Option<String>,
}

impl DelegationOutcome {
    /// Convenience for the "deny, nothing granted" case.
    pub fn deny(decision: Decision) -> Self {
        Self {
            decision,
            granted_permissions: Vec::new(),
            granted_audience: None,
            granted_expires_at: None,
        }
    }
}

#[derive(Debug, Error)]
pub enum DelegationError {
    #[error("no delegation invoker available for plugin `{0}`")]
    NotFound(String),

    #[error("delegation dispatch failed: {0}")]
    Dispatch(String),
}

/// `DelegationInvoker` impl that returns `NotFound` for every call.
/// Useful as the default for evaluator callers that don't run any
/// `delegate(...)` steps — they need to pass *something* implementing
/// the trait, but the noop never actually gets invoked. Tests and
/// hosts that haven't wired a real delegation backend pass this.
pub struct NoopDelegationInvoker;

#[async_trait]
impl DelegationInvoker for NoopDelegationInvoker {
    async fn delegate(&self, step: &DelegateStep) -> Result<DelegationOutcome, DelegationError> {
        Err(DelegationError::NotFound(step.plugin_name.clone()))
    }
}

// =====================================================================
// Resolver results
// =====================================================================

/// What a PDP returned.
#[derive(Debug, Clone, PartialEq)]
pub struct PdpDecision {
    pub decision: Decision,
    /// Optional diagnostic info: matched policy IDs, error codes, etc.
    /// Surfaces in audit logs; not used for control flow.
    pub diagnostics: Vec<String>,
}

/// What a plugin returned.
#[derive(Debug, Clone)]
pub struct PluginOutcome {
    pub decision: Decision,
    /// Plugins may apply taint labels as a side effect. Same shape as
    /// config-emitted taints (`Step::Taint` / `Stage::Taint`) so the
    /// downstream evaluator can append both into a single
    /// `Vec<TaintEvent>` without converting. Each event may carry
    /// multiple scopes — `CmfPluginInvoker` uses single-scope
    /// (`Session`) for v0 but future invokers and plugins that emit
    /// directly are free to span scopes.
    pub taints: Vec<TaintEvent>,
    /// Pipe-context return: when a plugin runs as a stage inside an
    /// args/result chain, it may rewrite the field value (e.g., a PII
    /// scrubber producing a redacted string). `None` means "leave value
    /// unchanged"; always `None` for policy / post_policy invocations.
    pub modified_value: Option<serde_json::Value>,
}

impl PluginOutcome {
    /// Convenience for the common "allow, no taints, no value change" case.
    pub fn allow() -> Self {
        Self {
            decision: Decision::Allow,
            taints: vec![],
            modified_value: None,
        }
    }
}

// =====================================================================
// Errors
// =====================================================================

#[derive(Debug, Error)]
pub enum PdpError {
    #[error("no PDP resolver registered for dialect {0:?}")]
    NoResolver(PdpDialect),

    #[error("PDP dispatch failed: {0}")]
    Dispatch(String),
}

#[derive(Debug, Error)]
pub enum PluginError {
    #[error("no plugin invoker available for `{0}`")]
    NotFound(String),

    #[error("plugin dispatch failed: {0}")]
    Dispatch(String),
}

// =====================================================================
// Convenience
// =====================================================================

impl Step {
    /// Wrap a `Rule` as a `Step`. Saves typing in tests and parser code.
    pub fn rule(r: Rule) -> Self {
        Step::Rule(r)
    }

    /// Returns true if this step is a plain rule (no async dispatch needed).
    pub fn is_rule(&self) -> bool {
        matches!(self, Step::Rule(_))
    }
}

/// Bag keys the delegation step writes after a successful dispatch.
/// Centralized here so the evaluator (writer) and policy authors
/// (readers, via `require(delegation.granted.*)`) agree on the
/// canonical names — typos in either place silently break the
/// IdP-as-PDP pattern.
///
/// # Namespace
///
/// The `delegation.*` namespace at the top level carries INBOUND
/// chain attributes (`delegation.depth`, `delegation.origin`,
/// `delegation.chain`, ...) populated by identity resolver plugins
/// via `IdentityPayload.delegation` + apply-to-extensions, then
/// surfaced through apl-cmf's BagBuilder. See
/// `docs/specs/delegation-hooks-rust-spec.md` §6.3 for that mapping.
///
/// The `delegation.granted.*` sub-namespace defined here is for
/// OUTBOUND results — what came back from a `delegate(...)` step
/// the framework just ran. Two writers (identity plugin for inbound,
/// `delegate(...)` for outbound), distinct sub-trees, no collision.
pub mod delegation_bag_keys {
    /// `StringSet` — permissions actually granted by the IdP on the
    /// minted token. May be narrower than `required_permissions`.
    pub const GRANTED_PERMISSIONS: &str = "delegation.granted.permissions";
    /// `String` — audience the minted token is valid for.
    pub const GRANTED_AUDIENCE: &str = "delegation.granted.audience";
    /// `String` — token expiry as RFC 3339.
    pub const GRANTED_EXPIRES_AT: &str = "delegation.granted.expires_at";
    /// `Bool` — set to `true` after a successful `delegate(...)`
    /// step. Lets policy branch on success without inspecting the
    /// granted_permissions set: `require(delegation.granted)`. Absent
    /// (i.e. evaluates to false) when no delegate step has run OR
    /// when the most recent one denied.
    pub const GRANTED: &str = "delegation.granted";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_key_maps_known_dialects() {
        assert_eq!(PdpDialect::from_key("cedar"), PdpDialect::Cedar);
        assert_eq!(PdpDialect::from_key("opa"), PdpDialect::Opa);
        assert_eq!(PdpDialect::from_key("authzen"), PdpDialect::AuthZen);
        assert_eq!(PdpDialect::from_key("nemo"), PdpDialect::NeMo);
        assert_eq!(PdpDialect::from_key("cel"), PdpDialect::Cel);
    }

    #[test]
    fn from_key_unknown_is_custom() {
        assert_eq!(
            PdpDialect::from_key("rego-remote"),
            PdpDialect::Custom("rego-remote".to_string())
        );
    }

    #[test]
    fn cel_dialect_serde_roundtrips_as_snake_case() {
        // `Cel` is a tagged variant (snake_case) — must round-trip so
        // compiled-route serialization (audit/cache) preserves it.
        let json = serde_json::to_string(&PdpDialect::Cel).unwrap();
        assert_eq!(json, "\"cel\"");
        let back: PdpDialect = serde_json::from_str(&json).unwrap();
        assert_eq!(back, PdpDialect::Cel);
    }
}
