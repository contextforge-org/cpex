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
//   - PDP calls: `cedar:(...)`, `opa(...)`, `authzen(...)`, `nemo(...)`
//     with optional `on_deny:` / `on_allow:` reaction blocks
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

/// One entry in a `policy:` or `post_policy:` list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Step {
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

    /// `taint(label[, scope])` — apply a taint label. Always succeeds;
    /// never produces a Deny. SessionStore dispatch happens in apl-cpex.
    Taint { label: String, scopes: Vec<TaintScope> },
}

/// A PDP invocation, opaque-args style. Resolvers parse `args` based on
/// the dialect they handle — apl-core doesn't impose a Cedar/OPA/AuthZen
/// schema on `args`.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    Cedar,
    Opa,
    AuthZen,
    NeMo,
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
            other => Self::Custom(other.to_string()),
        }
    }
}

// =====================================================================
// Resolver traits
// =====================================================================

/// External policy-decision dispatch. Implemented by Cedar/Cedarling, OPA
/// HTTP clients, AuthZen clients, NeMo Guardrails — anything that can
/// answer "given this call, allow or deny?" against a request context.
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

/// Context for one plugin invocation: tells the invoker the *intent* of
/// the call so it can dispatch to the right CPEX hook contract.
///
/// `Step` is the policy / post_policy case — the invoker (apl-cpex side)
/// already holds a typed payload reference; APL doesn't need to pass one.
///
/// `Field` is the pipe-chain case — APL is focused on a specific field
/// value mid-transform and the plugin may rewrite that value via
/// `PluginOutcome.modified_value`.
#[derive(Debug, Clone, Copy)]
pub enum PluginInvocation<'a> {
    /// Called from a `policy:` or `post_policy:` step. The plugin operates
    /// on whatever typed payload the invoker was bound to.
    Step,
    /// Called inside an `args:` / `result:` pipe chain on one field.
    Field { name: &'a str, value: &'a serde_json::Value },
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
        Self { decision: Decision::Allow, taints: vec![], modified_value: None }
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
    pub fn rule(r: Rule) -> Self { Step::Rule(r) }

    /// Returns true if this step is a plain rule (no async dispatch needed).
    pub fn is_rule(&self) -> bool { matches!(self, Step::Rule(_)) }
}
