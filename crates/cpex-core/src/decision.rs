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
    /// Signalled a block from a non-blocking phase (Transform), so the deny
    /// was suppressed. Recorded as its own action — never as `Allowed` — so
    /// the record reflects the plugin's actual decision, not the discarded
    /// intent. A downstream mapping (e.g. an OCSF `ai_operation` disposition)
    /// must not read this as an allow.
    DenyIgnored,
    /// Cancelled mid-flight because another concurrent branch short-circuited
    /// the phase. An intentional abort, not a failure — distinct from
    /// [`PluginAction::Error`] so it doesn't read as a crash.
    Aborted,
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

/// The W3C trace context for one pipeline invocation — the node identity in
/// the decision graph. `span_id` is this interception's own span,
/// `parent_span_id` is the upstream call that triggered it (the causal edge),
/// and `trace_id` correlates the whole run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    /// The trace this invocation belongs to (W3C trace-id: 32 hex chars).
    pub trace_id: String,
    /// This interception's own span (W3C span-id: 16 hex chars).
    pub span_id: String,
    /// The span of the upstream call that caused this one — the causal edge.
    /// `None` when the request carried no trace context (a trace root).
    pub parent_span_id: Option<String>,
}

impl Span {
    /// Derive the span for an interception from the request's trace context,
    /// child-span model: a fresh `span_id` for this interception, the request's
    /// `span_id` as the causal parent, and the request's `trace_id` carried
    /// through — or a freshly originated trace root when the request carries
    /// none. Adopts W3C ids; it does not invent a bespoke scheme.
    pub fn for_request(trace_id: Option<&str>, parent_span_id: Option<&str>) -> Self {
        Self {
            trace_id: trace_id.map(str::to_owned).unwrap_or_else(new_trace_id),
            span_id: new_span_id(),
            parent_span_id: parent_span_id.map(str::to_owned),
        }
    }
}

/// A freshly originated W3C trace-id: 16 bytes / 32 lowercase hex chars.
fn new_trace_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// A freshly originated W3C span-id: 8 bytes / 16 lowercase hex chars (the
/// first half of a UUID's hex).
fn new_span_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..16].to_string()
}

/// The executor's record of one pipeline invocation: the ordered steps
/// each plugin took, the terminal verdict, and this invocation's span.
///
/// `verdict` is `None` while the pipeline is still running and is set once
/// at a return point (allow or deny). An audit sink always receives a
/// finalized log.
#[derive(Debug, Clone, Default)]
pub struct DecisionLog {
    steps: Vec<DecisionStep>,
    verdict: Option<Verdict>,
    span: Option<Span>,
    input_labels: Vec<String>,
    input_hash: Option<String>,
    epoch: Option<u64>,
    stream_id: Option<String>,
    stream_seq: Option<u64>,
    emission_seq: Option<u64>,
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

    /// Attach this invocation's span (trace context). Called by the executor
    /// at pipeline entry, derived from the request via [`Span::for_request`].
    pub fn set_span(&mut self, span: Span) {
        self.span = Some(span);
    }

    /// This invocation's span (trace context) — the node identity and causal
    /// parent for the decision graph — if the executor set one.
    pub fn span(&self) -> Option<&Span> {
        self.span.as_ref()
    }

    /// Record the taint labels the request carried at pipeline entry — the
    /// input side of this node's provenance. Diffed against the final labels
    /// (on `Extensions.security`), it yields the taint the pipeline added.
    pub fn set_input_labels(&mut self, labels: Vec<String>) {
        self.input_labels = labels;
    }

    /// The taint labels present at pipeline entry.
    pub fn input_labels(&self) -> &[String] {
        &self.input_labels
    }

    /// Record the content hash of the payload at pipeline entry — the input
    /// side of this node's content provenance. Set by the executor only when
    /// content provenance is enabled; otherwise `None`.
    pub fn set_input_hash(&mut self, hash: Option<String>) {
        self.input_hash = hash;
    }

    /// The content hash of the payload at pipeline entry, if captured.
    pub fn input_hash(&self) -> Option<&str> {
        self.input_hash.as_deref()
    }

    /// Stamp the audit-stream identity + sequence numbers, assigned by the
    /// executor at emission. The two counters are **distinct claims** — don't
    /// use one for the other's job:
    ///
    /// - `epoch` — the executor's boot time (Unix nanoseconds), captured once
    ///   at startup. It scopes the counters so a verifier tells a *counter
    ///   reset* (new, larger epoch) from *records lost* (a gap within an
    ///   epoch); being ordered, `(epoch, emission_seq)` is a total order across
    ///   restarts, computable from the record alone. Cross-epoch tail-loss is
    ///   not provable from the counters alone — that is what a durable sink
    ///   (the ledger) is for.
    /// - `stream_id` — the per-type stream (`"decision"`), the entry-type a
    ///   merged consumer keys on.
    /// - `stream_seq` — a **completeness** claim. Dense (gap-free) within
    ///   `(epoch, stream_id)`; a gap means a record was dropped.
    /// - `emission_seq` — an **ordering** claim *only*. Monotonic across all
    ///   streams within the epoch (decisions and effects share it) for
    ///   reconstructing interleaved order. A single-stream consumer sees it
    ///   *sparse* by design — the gaps are the other stream's records, never a
    ///   loss signal.
    pub fn set_stream(
        &mut self,
        epoch: u64,
        stream_id: String,
        stream_seq: u64,
        emission_seq: u64,
    ) {
        self.epoch = Some(epoch);
        self.stream_id = Some(stream_id);
        self.stream_seq = Some(stream_seq);
        self.emission_seq = Some(emission_seq);
    }

    /// The executor boot epoch (Unix nanoseconds) this record was emitted in.
    /// Orderable, so a new/larger value marks a restart — a reset is
    /// distinguishable from a loss, and it extends `emission_seq` to a total
    /// order across restarts.
    pub fn epoch(&self) -> Option<u64> {
        self.epoch
    }

    /// The per-type stream this record belongs to (scopes `stream_seq`).
    pub fn stream_id(&self) -> Option<&str> {
        self.stream_id.as_deref()
    }

    /// **Completeness** counter — dense within `(epoch, stream_id)`; a gap is a
    /// dropped record.
    pub fn stream_seq(&self) -> Option<u64> {
        self.stream_seq
    }

    /// **Ordering** counter — monotonic across decisions and effects within the
    /// epoch. Sparse for a single-stream consumer by design; not a loss signal.
    pub fn emission_seq(&self) -> Option<u64> {
        self.emission_seq
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
        log.record(
            "pii-scanner",
            PluginMode::Transform,
            PluginAction::ModifiedPayload,
        );
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

    #[test]
    fn span_child_model_carries_causal_edge() {
        let span = Span::for_request(Some("trace-abc"), Some("upstream-span"));
        assert_eq!(span.trace_id, "trace-abc", "trace carried through");
        assert_eq!(
            span.parent_span_id.as_deref(),
            Some("upstream-span"),
            "the request's span becomes the causal parent"
        );
        assert_eq!(span.span_id.len(), 16, "own fresh W3C span-id");
        assert_ne!(span.span_id, "upstream-span", "our span, not the parent's");
    }

    #[test]
    fn span_originates_trace_root_when_request_has_none() {
        let span = Span::for_request(None, None);
        assert_eq!(span.trace_id.len(), 32, "originated W3C trace-id");
        assert_eq!(span.span_id.len(), 16, "originated W3C span-id");
        assert!(span.parent_span_id.is_none(), "no parent = trace root");
    }

    #[test]
    fn each_invocation_gets_a_distinct_span() {
        let a = Span::for_request(Some("t"), Some("p"));
        let b = Span::for_request(Some("t"), Some("p"));
        assert_ne!(a.span_id, b.span_id, "each interception mints its own span");
    }

    #[test]
    fn span_is_none_until_set() {
        let mut log = DecisionLog::new();
        assert!(log.span().is_none());
        log.set_span(Span::for_request(Some("t"), None));
        assert_eq!(log.span().unwrap().trace_id, "t");
    }

    #[test]
    fn input_labels_default_empty_and_settable() {
        let mut log = DecisionLog::new();
        assert!(log.input_labels().is_empty());
        log.set_input_labels(vec!["PII".into(), "secret".into()]);
        assert_eq!(
            log.input_labels(),
            &["PII".to_string(), "secret".to_string()]
        );
    }

    #[test]
    fn input_hash_default_none_and_settable() {
        let mut log = DecisionLog::new();
        assert!(log.input_hash().is_none());
        log.set_input_hash(Some("sha256:abc".into()));
        assert_eq!(log.input_hash(), Some("sha256:abc"));
    }

    #[test]
    fn stream_and_sequences_stamp_and_read_back() {
        let mut log = DecisionLog::new();
        assert!(log.epoch().is_none());
        assert!(log.stream_id().is_none());
        assert!(log.stream_seq().is_none());
        assert!(log.emission_seq().is_none());
        log.set_stream(1_700_000_000, "decision".into(), 7, 42);
        assert_eq!(log.epoch(), Some(1_700_000_000));
        assert_eq!(log.stream_id(), Some("decision"));
        assert_eq!(log.stream_seq(), Some(7));
        assert_eq!(log.emission_seq(), Some(42));
    }
}
