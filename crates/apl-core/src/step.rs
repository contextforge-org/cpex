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
    Taint { label: String, scopes: Vec<TaintScope> },

    /// `require_approval(...)` / `confirm(...)` / … — dispatch an
    /// elicitation to a human and resume once resolved. The elicitation
    /// analogue of `Delegate`; resolution is dispatched to an
    /// `ElicitationHandler` plugin via apl-cpex. See
    /// `docs/apl-manager-approval-ciba-design.md`.
    Elicit(ElicitStep),
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

/// The kind of elicitation — selects which validation contract the
/// runtime applies to the human's response. A single AST node
/// ([`Step::Elicit`]) covers every kind; the DSL exposes each via a
/// sugar verb (`require_approval` → `Approval`, `confirm` → `Confirm`,
/// …) that all parse to the same node. See
/// `docs/apl-elicitation-hook-design.md` for the per-kind contracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ElicitKind {
    /// Yes/no decision from a designated approver (manager approval).
    /// The approver MAY differ from the request subject; the response is
    /// bound to the request's args via `scope`.
    Approval,
    /// Cheap yes/no from the originating user ("yes, really do this").
    Confirm,
    /// Re-auth / second factor by the originating user (fresh token,
    /// elevated `acr`).
    StepUp,
    /// Signed statement from a designated party ("I confirm I reviewed X").
    Attestation,
    /// Free-form clarification from the originating user.
    Info,
    /// Peer review of an action by a colleague.
    Review,
}

impl ElicitKind {
    /// The snake_case wire name (matches the serde representation). Used
    /// by the apl-cpex bridge to pass `kind` to channel plugins as a
    /// string, since cpex-core can't depend on this enum.
    pub fn as_str(&self) -> &'static str {
        match self {
            ElicitKind::Approval => "approval",
            ElicitKind::Confirm => "confirm",
            ElicitKind::StepUp => "step_up",
            ElicitKind::Attestation => "attestation",
            ElicitKind::Info => "info",
            ElicitKind::Review => "review",
        }
    }
}

/// One elicitation invocation inside `policy:` or `post_policy:` — the
/// runtime dispatches a question to a human (approval, confirmation,
/// step-up, …) through a channel plugin, holds a pending state across
/// the agent's retries, validates the response, and resumes.
///
/// Structurally the elicitation analogue of [`DelegateStep`]: the DSL
/// carries the verb; apl-cpex dispatches resolution to the named
/// `ElicitationHandler` plugin (`plugin_name`, resolved exactly like
/// `delegate(...)`). The key
/// difference from delegation — which completes within one request — is
/// that an elicitation spans the gap between *dispatch* (the first
/// request that hits this step) and *resolution* (a later retry). That
/// gap is owned by the channel (e.g. Keycloak CIBA), never by a plugin
/// call: each of dispatch/check/validate is short and synchronous to the
/// request it runs in. See `docs/apl-manager-approval-ciba-design.md`.
///
/// # First arrival vs. retry
///
/// On the first request that reaches this step, the runtime *dispatches*
/// the elicitation and the phase yields a pending entry (the host emits
/// JSON-RPC `-32120`). On a later retry carrying the elicitation id, the
/// runtime *checks* status and, once resolved, *validates* the response
/// against `scope` before the phase may proceed.
///
/// `config_override` is a free-form map for channel-specific params
/// (e.g. CIBA `details_link`, Slack block-kit options); apl-core treats
/// it as opaque and hands it to the plugin via the same per-call
/// config-override pathway delegation uses.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ElicitStep {
    /// Which elicitation contract applies (selects runtime validation).
    pub kind: ElicitKind,

    /// Name of the `ElicitationHandler` plugin to invoke — the routing
    /// key, resolved `name → entry` exactly like `delegate(...)` resolves
    /// its plugin. The first positional argument of the sugar verb (e.g.
    /// `require_approval(manager-approver, ...)`). Which backend it speaks
    /// (CIBA / Slack / in-band) is the plugin's own opaque config, not
    /// something apl-core interprets.
    pub plugin_name: String,

    /// Optional channel label for audit/observability only (e.g.
    /// `"ciba"`, `"slack"`). NOT a routing key — the framework never
    /// dispatches on it. Surfaced into the bag as `elicitation.channel`
    /// so the audit record can show how the human was reached. `None`
    /// when the author doesn't declare one (a Phase 2 plugin may report
    /// its own channel instead).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,

    /// Who is being asked — an attribute reference resolved against the
    /// policy bag at dispatch (e.g. `"user.manager"`, `"user.sub"`). For
    /// CIBA this becomes `login_hint`; the resolved identity is
    /// cross-checked against the responder at `validate()`.
    pub from: String,

    /// Canonical, human-readable description of what's being asked, with
    /// request-arg substitution. Audited verbatim and shown to the
    /// responder (CIBA `binding_message`) — the source of truth for
    /// "what was approved," never an LLM summary. `None` for kinds that
    /// carry their prompt elsewhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,

    /// APL boolean expression the runtime evaluates against the actual
    /// request args at `validate()` to confirm the response covers what
    /// was requested (e.g. `"args.amount <= 25000"`). This is the
    /// args-binding layer — kept in APL because Keycloak does not support
    /// RFC 9396 RAR. `None` for kinds without arg binding (e.g. a bare
    /// `confirm`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// How long the elicitation stays valid before expiring (e.g.
    /// `"24h"`). Surfaces as CIBA `requested_expiry`. `None` defers to
    /// the channel plugin's configured default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,

    /// Per-call config overrides for channel-specific params, layered on
    /// the plugin's default config. Opaque to apl-core.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_override: Option<serde_yaml::Value>,

    /// `deny | continue` — what to do when dispatch or validation fails
    /// (channel error, invalid response). `None` defaults to `"deny"`
    /// (fail-closed; matches delegation/PDP step semantics).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_error: Option<String>,

    /// Human-readable source path (e.g.
    /// `"route.payroll_adjust.policy[0]"`) — used in audit and
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
// Elicitation dispatch
// =====================================================================

/// Elicitation dispatch — drives a human-in-the-loop step (approval,
/// confirmation, step-up, …) through a channel plugin. apl-cpex
/// implements this against the named `ElicitationHandler` plugin
/// (`step.plugin_name`, resolved `name → entry` like delegation); tests
/// and un-wired hosts pass [`NoopElicitationInvoker`].
///
/// Three short, synchronous touchpoints span the human's (possibly
/// hours-long) decision. The wait itself lives in the channel (e.g.
/// Keycloak CIBA), never inside a trait call:
///
/// * [`dispatch`](ElicitationInvoker::dispatch) — once, on the first
///   request that reaches the step: register the intent, open the
///   backchannel, and return the id the agent echoes on retry.
/// * [`check`](ElicitationInvoker::check) — on every retry: read the
///   current status (pending / resolved / expired) without blocking.
/// * [`validate`](ElicitationInvoker::validate) — once status is
///   resolved: confirm the response is *genuine* (signature, intent
///   binding, responder identity). The *sufficiency* check —
///   [`ElicitStep::scope`] against the live request args — is the
///   runtime's job, not the plugin's, because `scope` is an APL
///   expression the plugin cannot evaluate.
///
/// Like [`DelegationInvoker`], the invoker holds the request-scoped
/// `Extensions` internally, so the trait methods take only the step / id
/// and never the request context.
#[async_trait]
pub trait ElicitationInvoker: Send + Sync {
    /// First arrival. Register the intent and open the channel
    /// backchannel for `step`, returning the correlation id plus the
    /// pending metadata the evaluator writes into the bag
    /// (`elicitation.id` / `.approver` / `.intent_id`). Short and
    /// synchronous — the human's decision happens *after* this returns,
    /// inside the channel.
    ///
    /// `resolved_from` is `step.from` already resolved against the request
    /// bag by the runtime (e.g. `claim.manager` → the manager's actual
    /// identity), or the literal `step.from` when it isn't a bag key. The
    /// attribute vocabulary lives in the runtime, so the invoker receives
    /// the resolved identity rather than re-resolving it — for CIBA this
    /// becomes the `login_hint`.
    async fn dispatch(
        &self,
        step: &ElicitStep,
        resolved_from: &str,
    ) -> Result<ElicitationDispatch, ElicitationError>;

    /// Retry. Read the current status of a dispatched elicitation by
    /// `id` without blocking — `Pending` until the human acts, then
    /// `Resolved` (carrying approved/denied) or `Expired`. `step` is
    /// passed (the same step that dispatched) so the invoker can resolve
    /// which handler plugin owns this elicitation — on a retry only the
    /// id is in the bag, but the step is still in scope.
    async fn check(
        &self,
        step: &ElicitStep,
        id: &str,
    ) -> Result<ElicitationStatus, ElicitationError>;

    /// Resolution. Verify that the resolved response is *genuine* — the
    /// signed token validates, its intent binding matches this `id`, and
    /// the responder is the resolved approver. Returns the verdict plus
    /// the facts the evaluator records for audit. The runtime applies the
    /// `scope`-over-args check separately before honoring an approval.
    /// `step` resolves the owning handler plugin (see [`check`]).
    ///
    /// [`check`]: ElicitationInvoker::check
    async fn validate(
        &self,
        step: &ElicitStep,
        id: &str,
    ) -> Result<ElicitationValidation, ElicitationError>;
}

/// What [`ElicitationInvoker::dispatch`] returns — the correlation id
/// plus the pending metadata the evaluator surfaces into the bag
/// (`elicitation.*`) and the host echoes in the JSON-RPC `-32120`
/// pending entry.
#[derive(Debug, Clone)]
pub struct ElicitationDispatch {
    /// Server-side id the agent echoes on retry. Keys the
    /// `{requester, args, scope, original_request_id}` record.
    pub id: String,
    /// Resolved approver identity (the `from` attr resolved at dispatch,
    /// e.g. the manager's `sub`). `None` when the channel resolves the
    /// responder only at validation time. Surfaced as
    /// `elicitation.approver`.
    pub approver: Option<String>,
    /// Registered intent id (lodging-intent binding) when the channel
    /// supports it. Surfaced as `elicitation.intent_id`.
    pub intent_id: Option<String>,
    /// When the elicitation expires (RFC 3339). `None` defers to the
    /// channel plugin's configured default.
    pub expires_at: Option<String>,
}

/// Current state of a dispatched elicitation, read by
/// [`ElicitationInvoker::check`] on each retry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElicitationStatus {
    /// The human has not responded yet — the phase stays pending and the
    /// host re-emits `-32120`.
    Pending,
    /// The human responded. `outcome` carries approved/denied; the
    /// runtime still calls `validate` before honoring an `Approved`.
    Resolved { outcome: ElicitationOutcome },
    /// The elicitation timed out before a response — the runtime fails
    /// closed (subject to the step's `on_error`).
    Expired,
}

/// The human's decision once an elicitation resolves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElicitationOutcome {
    Approved,
    Denied,
}

/// What [`ElicitationInvoker::validate`] returns — the *genuineness*
/// verdict plus the resolved facts the runtime records for audit. The
/// runtime layers the `scope`-over-args check on top before allowing the
/// phase to proceed.
#[derive(Debug, Clone)]
pub struct ElicitationValidation {
    /// `true` when the response is genuine: the signed token validates,
    /// its intent binding matches this elicitation, and the responder is
    /// the resolved approver.
    pub valid: bool,
    /// Who actually consented — cross-checked against the dispatch-time
    /// approver. Recorded as `elicitation.approver`.
    pub approver: Option<String>,
    /// Intent id carried in the signed response, for audit
    /// reconciliation against the registered intent.
    pub intent_id: Option<String>,
    /// Why validation failed, when `valid` is `false`. `None` on success.
    pub reason: Option<String>,
}

/// The "ask again later" bundle — produced when an elicitation has been
/// dispatched but the human hasn't responded yet. It carries everything
/// the host needs to emit a JSON-RPC `-32120` ("request not complete,
/// retry echoing this id") to the agent instead of forwarding the call.
///
/// This is the tri-state channel that lets `Decision` stay binary: a
/// suspended phase reports `Decision::Allow` (nothing was *denied*) with a
/// `Some(PendingElicitation)` alongside it. The host rule is one clause —
/// **forward iff `Allow` AND `pending.is_none()`**; otherwise emit
/// `-32120`. The agent re-sends with `elicitation.id`, the runtime takes
/// the "id present → check, don't re-dispatch" path, and once the human
/// resolves, the phase proceeds past the elicitation.
///
/// Pending **short-circuits** the phase (sequential elicitation): at most
/// one pending per pass. Multiple concurrent pendings are deferred (would
/// turn this into a `Vec` on `StepsEvaluation`).
#[derive(Debug, Clone, PartialEq)]
pub struct PendingElicitation {
    /// Server-side id the agent echoes on retry (`elicitation.id`).
    pub id: String,
    /// Which `ElicitationHandler` plugin owns this elicitation.
    pub plugin_name: String,
    /// Resolved approver identity, when known at dispatch.
    pub approver: Option<String>,
    /// Registered intent id (lodging-intent binding), when the channel
    /// supports it.
    pub intent_id: Option<String>,
    /// Optional channel label for the agent-facing `-32120` / audit.
    pub channel: Option<String>,
    /// When the elicitation expires (RFC 3339), when known.
    pub expires_at: Option<String>,
    /// Rule source path of the originating `Elicit` step, for audit.
    pub source: String,
}

#[derive(Debug, Error)]
pub enum ElicitationError {
    #[error("no elicitation invoker available for plugin `{0}`")]
    NotFound(String),

    #[error("elicitation dispatch failed: {0}")]
    Dispatch(String),
}

/// [`ElicitationInvoker`] impl that returns `NotFound` for every call.
/// The default for evaluator callers that run no elicitation steps —
/// they must pass *something* implementing the trait, but the noop never
/// actually gets invoked. Mirrors [`NoopDelegationInvoker`]; tests and
/// hosts that haven't wired a real channel backend pass this.
pub struct NoopElicitationInvoker;

#[async_trait]
impl ElicitationInvoker for NoopElicitationInvoker {
    async fn dispatch(
        &self,
        step: &ElicitStep,
        _resolved_from: &str,
    ) -> Result<ElicitationDispatch, ElicitationError> {
        Err(ElicitationError::NotFound(step.plugin_name.clone()))
    }

    async fn check(
        &self,
        _step: &ElicitStep,
        id: &str,
    ) -> Result<ElicitationStatus, ElicitationError> {
        Err(ElicitationError::NotFound(id.to_string()))
    }

    async fn validate(
        &self,
        _step: &ElicitStep,
        id: &str,
    ) -> Result<ElicitationValidation, ElicitationError> {
        Err(ElicitationError::NotFound(id.to_string()))
    }
}

/// `ElicitationInvoker` that immediately approves every elicitation:
/// `dispatch` returns a synthetic id (echoing the requested `from` as the
/// resolved approver), `check` reports `Resolved { Approved }` on the
/// first pass, and `validate` returns a genuine verdict. This lets a
/// single request flow dispatch → check → validate → allow without a real
/// channel — for evaluator tests and offline demos.
///
/// NOT for production: it makes no actual approval decision. Hosts wire a
/// real channel invoker (e.g. the apl-cpex `ElicitationHandler` bridge).
#[derive(Default)]
pub struct AutoApprovingElicitor;

#[async_trait]
impl ElicitationInvoker for AutoApprovingElicitor {
    async fn dispatch(
        &self,
        step: &ElicitStep,
        resolved_from: &str,
    ) -> Result<ElicitationDispatch, ElicitationError> {
        Ok(ElicitationDispatch {
            id: format!("auto-{}", step.plugin_name),
            // Echo the *resolved* approver, as a real channel would.
            approver: Some(resolved_from.to_string()),
            intent_id: Some("auto-intent".to_string()),
            expires_at: None,
        })
    }

    async fn check(
        &self,
        _step: &ElicitStep,
        _id: &str,
    ) -> Result<ElicitationStatus, ElicitationError> {
        Ok(ElicitationStatus::Resolved {
            outcome: ElicitationOutcome::Approved,
        })
    }

    async fn validate(
        &self,
        _step: &ElicitStep,
        _id: &str,
    ) -> Result<ElicitationValidation, ElicitationError> {
        Ok(ElicitationValidation {
            valid: true,
            // Leave approver/intent unset — the dispatch-time values
            // already recorded in the bag stand.
            approver: None,
            intent_id: Some("auto-intent".to_string()),
            reason: None,
        })
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

/// Bag keys an elicitation step writes so downstream rules in the same
/// phase — and the audit plugin — can read its state. Centralized here
/// (like [`delegation_bag_keys`]) so the evaluator/invoker (writers) and
/// policy authors (readers, via `require(elicitation.*)`) agree on the
/// canonical names.
///
/// On *dispatch* the runtime writes `id` + `status = "pending"` (plus
/// `approver` / `intent_id` when known). On *resolution* it updates
/// `status` and sets `outcome`. A phase with a pending elicitation does
/// not forward (see `docs/apl-manager-approval-ciba-design.md`).
pub mod elicitation_bag_keys {
    /// `String` — the elicitation id the agent echoes on retry. Server-side
    /// key into `{requester, args, scope, original_request_id}`.
    pub const ID: &str = "elicitation.id";
    /// `String` — `pending | resolved | expired`.
    pub const STATUS: &str = "elicitation.status";
    /// `String` — resolved approver identity, cross-checked against `from`.
    pub const APPROVER: &str = "elicitation.approver";
    /// `String` — `approved | denied` once resolved.
    pub const OUTCOME: &str = "elicitation.outcome";
    /// `String` — registered intent id (lodging-intent binding), echoed in
    /// the OP-signed token for `validate()` and audit reconciliation.
    pub const INTENT_ID: &str = "elicitation.intent_id";
    /// `String` — optional channel label (`ciba` / `slack` / …) for
    /// audit/observability. Not a routing key.
    pub const CHANNEL: &str = "elicitation.channel";
    /// `String` — when the elicitation expires (RFC 3339), when the
    /// channel reported one at dispatch.
    pub const EXPIRES_AT: &str = "elicitation.expires_at";
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

    #[tokio::test]
    async fn noop_elicitation_invoker_is_not_found_for_every_method() {
        // The noop must never silently succeed — every method reports
        // NotFound so an un-wired host fails closed rather than treating
        // an elicitation step as approved.
        let inv = NoopElicitationInvoker;
        let step = ElicitStep {
            kind: ElicitKind::Approval,
            plugin_name: "manager-approver".to_string(),
            channel: Some("ciba".to_string()),
            from: "user.manager".to_string(),
            purpose: None,
            scope: None,
            timeout: None,
            config_override: None,
            on_error: None,
            source: "route.test.policy[0]".to_string(),
        };

        let d = inv.dispatch(&step, "alice@example.com").await;
        assert!(matches!(d, Err(ElicitationError::NotFound(c)) if c == "manager-approver"));

        let c = inv.check(&step, "elic-123").await;
        assert!(matches!(c, Err(ElicitationError::NotFound(id)) if id == "elic-123"));

        let v = inv.validate(&step, "elic-123").await;
        assert!(matches!(v, Err(ElicitationError::NotFound(id)) if id == "elic-123"));
    }

    #[test]
    fn elicitation_status_resolved_carries_outcome() {
        // Resolved is distinct from its outcome — a denied resolution is
        // still "resolved" (the runtime stops retrying) but must not be
        // confused with Pending/Expired.
        let approved = ElicitationStatus::Resolved {
            outcome: ElicitationOutcome::Approved,
        };
        let denied = ElicitationStatus::Resolved {
            outcome: ElicitationOutcome::Denied,
        };
        assert_ne!(approved, denied);
        assert_ne!(approved, ElicitationStatus::Pending);
        assert_ne!(denied, ElicitationStatus::Expired);
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
