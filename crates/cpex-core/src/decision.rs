// Location: ./crates/cpex-core/src/decision.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// The DecisionLog — the executor's private, append-only record of what
// each plugin did to a request and how the pipeline ruled on it.
//
// Why it exists: a plugin observing a request (audit-logger, ocsf-audit)
// cannot see the pipeline's verdict — allow/deny/modify lives in the
// executor's control flow (`PluginResult`, the short-circuit return), not
// in `Extensions`. The DecisionLog captures that control flow so an audit
// sink can serialize it. It is built by the executor and handed only to
// audit handlers; it is deliberately NOT placed on `PluginContext`, which
// every plugin can read — the component that records must not be readable
// (or writable) by the components it records.
//
// Kept cheap: it records what happened (which plugin, which phase, which
// action), not copies of payloads.

use crate::error::PluginViolation;
use crate::plugin::PluginMode;

/// What a single plugin did to the request, from the executor's point of
/// view. Derived from the plugin's `PluginResult`, not self-reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginAction {
    /// Ran and let the request continue unchanged.
    Allowed,
    /// Blocked the request. The full violation rides on the terminal
    /// [`Verdict::Deny`]; this marks *which* plugin, in order.
    Denied,
    /// Replaced the payload (accepted by the executor's modify path).
    ModifiedPayload,
    /// Wrote to an extension slot it was capable of writing.
    ModifiedExtensions,
    /// Failed. The string is the error rendered by the executor; whether
    /// this halts the pipeline is decided by the plugin's `on_error`.
    Error(String),
}

/// One entry in the log: a plugin, the phase it ran in, and what it did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionStep {
    /// The plugin instance name (`PluginConfig.name`).
    pub plugin_name: String,
    /// The phase this plugin ran in — Sequential / Transform / Audit / …
    pub phase: PluginMode,
    /// What it did.
    pub action: PluginAction,
}

/// The pipeline's terminal ruling on a request.
#[derive(Debug, Clone)]
pub enum Verdict {
    /// The request was allowed through (possibly after modifications —
    /// those are in [`DecisionLog::steps`]).
    Allow,
    /// The request was blocked. Carries the fully-formed violation the
    /// executor stamped with the deciding plugin's name.
    Deny(PluginViolation),
}

impl Verdict {
    /// True if this verdict blocked the request.
    pub fn is_deny(&self) -> bool {
        matches!(self, Verdict::Deny(_))
    }
}

/// The executor's record of one pipeline invocation: the ordered steps
/// each plugin took, and the terminal verdict.
///
/// `verdict` is `None` while the pipeline is still running and is set once
/// at a return point (allow or deny). An audit sink always receives a
/// finalized log.
#[derive(Debug, Clone, Default)]
pub struct DecisionLog {
    steps: Vec<DecisionStep>,
    verdict: Option<Verdict>,
}

impl DecisionLog {
    /// A fresh log for one pipeline invocation.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append what a plugin did. Called by the executor as each plugin
    /// returns; order is execution order.
    pub fn record(
        &mut self,
        plugin_name: impl Into<String>,
        phase: PluginMode,
        action: PluginAction,
    ) {
        self.steps.push(DecisionStep {
            plugin_name: plugin_name.into(),
            phase,
            action,
        });
    }

    /// Set the terminal verdict. Called once at the pipeline's return
    /// point, before the log is handed to audit handlers.
    pub fn finalize(&mut self, verdict: Verdict) {
        self.verdict = Some(verdict);
    }

    /// The ordered steps taken this invocation.
    pub fn steps(&self) -> &[DecisionStep] {
        &self.steps
    }

    /// The terminal verdict, or `None` if the pipeline hasn't returned yet.
    pub fn verdict(&self) -> Option<&Verdict> {
        self.verdict.as_ref()
    }

    /// True once finalized with a deny.
    pub fn is_denied(&self) -> bool {
        self.verdict.as_ref().is_some_and(Verdict::is_deny)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn violation() -> PluginViolation {
        PluginViolation::new("missing_permission", "not allowed")
    }

    #[test]
    fn records_steps_in_order() {
        let mut log = DecisionLog::new();
        log.record("pii-scanner", PluginMode::Transform, PluginAction::ModifiedPayload);
        log.record("cedar-pdp", PluginMode::Sequential, PluginAction::Denied);

        let steps = log.steps();
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].plugin_name, "pii-scanner");
        assert_eq!(steps[0].action, PluginAction::ModifiedPayload);
        assert_eq!(steps[1].phase, PluginMode::Sequential);
        assert_eq!(steps[1].action, PluginAction::Denied);
    }

    #[test]
    fn verdict_is_none_until_finalized() {
        let mut log = DecisionLog::new();
        assert!(log.verdict().is_none());
        assert!(!log.is_denied());

        log.finalize(Verdict::Deny(violation()));
        assert!(log.is_denied());
        match log.verdict() {
            Some(Verdict::Deny(v)) => assert_eq!(v.code, "missing_permission"),
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn allow_verdict_is_not_a_deny() {
        let mut log = DecisionLog::new();
        log.finalize(Verdict::Allow);
        assert!(!log.is_denied());
    }
}
