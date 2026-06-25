// Location: ./crates/cpex-core/src/elicitation/payload.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// `ElicitationPayload` — the unified state struct threaded through the
// Elicitation hook chain. Same input/accumulator split as
// `DelegationPayload`:
//
//   * **Input** (private — bridge-supplied, never mutated by handlers) —
//     `operation`, `elicitation_id`, `kind`, `from`, `purpose`, `scope`,
//     `timeout`, `channel`. Set once by the apl-cpex bridge before
//     `invoke_entries::<ElicitationHook>`. Read through accessors; no
//     setters or mutable field access at the module boundary.
//
//   * **Accumulating output** (`pub` fields) — `id`, `status`, `outcome`,
//     `approver`, `intent_id`, `expires_at`, `valid`, `reason`,
//     `metadata`. Handlers clone the payload, populate the slots relevant
//     to the `operation`, and return it via `PluginResult::modify_payload`.
//
// # Three operations, one payload
//
// Unlike delegation (one mint per call), an elicitation has three
// touch-points across its lifetime — dispatch / check / validate. They
// share this one payload shape and differ only in which `operation` the
// bridge sets and which output slots the handler fills:
//
//   * `Dispatch`  → handler registers the intent / opens the channel
//                   backchannel, fills `id` / `approver` / `intent_id` /
//                   `expires_at` / `status = Pending`.
//   * `Check`     → handler reads current state, fills `status` (and
//                   `outcome` when resolved).
//   * `Validate`  → handler verifies the response is genuine, fills
//                   `valid` / `approver` / `intent_id` / `reason`.
//
// The hours-long human gap lives in the channel (e.g. Keycloak CIBA),
// never in a handler call — each operation is short and synchronous.
//
// # Decoupling from apl-core
//
// cpex-core does not depend on apl-core, so this module defines its own
// `ElicitationOp` / `ElicitationStatusKind` / `ElicitationOutcomeKind`
// rather than reusing apl-core's `ElicitKind` / `ElicitationStatus`. The
// apl-cpex bridge maps between the two. `kind` is a free string
// (`"approval"`, `"confirm"`, …) — the per-kind *validation contract* is
// the apl-core runtime's job, so the handler only needs it informationally.
//
// # Rejection
//
// Same as delegation: handlers reject via
// `PluginResult::deny(PluginViolation::new(code, reason))`. The executor
// halts the chain and the bridge maps that to an `ElicitationError`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::executor::PipelineResult;
use crate::impl_plugin_payload;

/// Which of the three elicitation touch-points this invocation is. The
/// handler dispatches on it to decide what to do and which output slots
/// to fill.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ElicitationOp {
    /// First arrival — register the intent / open the backchannel.
    Dispatch,
    /// Retry — read current status without blocking.
    Check,
    /// Resolved — verify the response is genuine.
    Validate,
}

/// Current state of a dispatched elicitation, reported by a `Check`
/// handler. Mirrors apl-core's `ElicitationStatus` shape without the
/// dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ElicitationStatusKind {
    /// The human has not responded yet.
    Pending,
    /// The human responded — see `outcome` for approved/denied.
    Resolved,
    /// The elicitation timed out before a response.
    Expired,
}

/// The human's decision once an elicitation resolves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ElicitationOutcomeKind {
    Approved,
    Denied,
}

/// State threaded through the Elicitation hook chain. See the
/// module-level docs for the input/accumulator split. Input fields are
/// private (set once via the constructor + builders, never mutated).
/// Output fields are `pub` (handlers populate on clones and return the
/// updated payload).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElicitationPayload {
    // ----- Input (private — bridge-supplied, never mutated by handlers) -----
    /// Which touch-point this is.
    operation: ElicitationOp,

    /// Correlation id from a prior `Dispatch`. `None` on dispatch (the
    /// handler mints it); `Some` on check / validate.
    elicitation_id: Option<String>,

    /// Elicitation kind (`"approval"`, `"confirm"`, `"step_up"`, …) —
    /// informational for the handler; the validation contract is enforced
    /// by the apl-core runtime, not here.
    kind: String,

    /// Resolved approver identity (the apl-core `from` attr already
    /// resolved against the request bag by the bridge). For CIBA this is
    /// the `login_hint`.
    from: String,

    /// Human-readable description of what's being asked — CIBA
    /// `binding_message`, audited verbatim. `None` for kinds that carry
    /// their prompt elsewhere.
    purpose: Option<String>,

    /// The APL scope expression string, passed through for the handler to
    /// record alongside the registered intent (the runtime evaluates it,
    /// not the handler). `None` for kinds without arg binding.
    scope: Option<String>,

    /// Validity window (e.g. `"24h"`) — CIBA `requested_expiry`. `None`
    /// defers to the handler's configured default.
    timeout: Option<String>,

    /// Optional channel label (`"ciba"` / `"slack"` / …) for the handler's
    /// own logging/telemetry. Not a routing key (the plugin was already
    /// selected by name).
    channel: Option<String>,

    // ----- Output (pub — handlers populate via direct assignment on clones) -----
    /// Correlation id minted on `Dispatch`. The agent echoes it on retry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Current status — set by `Check` (and `Dispatch`, which leaves it
    /// `Pending`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<ElicitationStatusKind>,

    /// Approved / denied — set by `Check` once `status` is `Resolved`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<ElicitationOutcomeKind>,

    /// Resolved approver identity — set by `Dispatch` (when known) and by
    /// `Validate` (the consenting party, cross-checked against `from`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver: Option<String>,

    /// Registered intent id (lodging-intent binding) — set by `Dispatch`
    /// and echoed by `Validate` for audit reconciliation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent_id: Option<String>,

    /// Expiry timestamp (RFC 3339) — set by `Dispatch` when the channel
    /// reports one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,

    /// Genuineness verdict — set by `Validate`. `true` when the signed
    /// response validates, its intent binding matches, and the responder
    /// is the approver. (The runtime layers the scope-over-args check on
    /// top before honoring an approval.)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid: Option<bool>,

    /// Why a `Check`/`Validate` reported the state it did — failure reason
    /// when `valid` is `false`, or diagnostic context. `None` on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// Optional handler metadata (telemetry, diagnostics). Not load-bearing.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, serde_json::Value>,
}

impl ElicitationPayload {
    /// Construct a payload for the given operation + kind + resolved
    /// approver. Optional input slots are set via the `.with_*` builders;
    /// output fields start empty and accumulate as the handler runs.
    pub fn new(
        operation: ElicitationOp,
        kind: impl Into<String>,
        from: impl Into<String>,
    ) -> Self {
        Self {
            operation,
            elicitation_id: None,
            kind: kind.into(),
            from: from.into(),
            purpose: None,
            scope: None,
            timeout: None,
            channel: None,
            id: None,
            status: None,
            outcome: None,
            approver: None,
            intent_id: None,
            expires_at: None,
            valid: None,
            reason: None,
            metadata: HashMap::new(),
        }
    }

    // -------- Input builders --------

    /// Set the correlation id (check / validate operations).
    pub fn with_elicitation_id(mut self, id: impl Into<String>) -> Self {
        self.elicitation_id = Some(id.into());
        self
    }

    pub fn with_purpose(mut self, purpose: impl Into<String>) -> Self {
        self.purpose = Some(purpose.into());
        self
    }

    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    pub fn with_timeout(mut self, timeout: impl Into<String>) -> Self {
        self.timeout = Some(timeout.into());
        self
    }

    pub fn with_channel(mut self, channel: impl Into<String>) -> Self {
        self.channel = Some(channel.into());
        self
    }

    // -------- Input read accessors --------

    pub fn operation(&self) -> ElicitationOp {
        self.operation
    }

    pub fn elicitation_id(&self) -> Option<&str> {
        self.elicitation_id.as_deref()
    }

    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub fn from(&self) -> &str {
        &self.from
    }

    pub fn purpose(&self) -> Option<&str> {
        self.purpose.as_deref()
    }

    pub fn scope(&self) -> Option<&str> {
        self.scope.as_deref()
    }

    pub fn timeout(&self) -> Option<&str> {
        self.timeout.as_deref()
    }

    pub fn channel(&self) -> Option<&str> {
        self.channel.as_deref()
    }

    // -------- Host-side application helper --------

    /// Pull the resolved `ElicitationPayload` out of a `PipelineResult`
    /// returned by `mgr.invoke_entries::<ElicitationHook>(...)`. Returns
    /// `None` when the pipeline was denied or the result's payload wasn't
    /// an `ElicitationPayload`. Same contract as
    /// `DelegationPayload::from_pipeline_result`.
    pub fn from_pipeline_result(result: &PipelineResult) -> Option<Self> {
        result
            .modified_payload
            .as_ref()
            .and_then(|p| p.as_any().downcast_ref::<ElicitationPayload>())
            .cloned()
    }
}

impl_plugin_payload!(ElicitationPayload);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_sets_input_and_leaves_output_empty() {
        let p = ElicitationPayload::new(ElicitationOp::Dispatch, "approval", "alice@example.com")
            .with_purpose("Approve $25,000 raise")
            .with_scope("args.amount <= 25000")
            .with_timeout("24h")
            .with_channel("ciba");

        assert_eq!(p.operation(), ElicitationOp::Dispatch);
        assert_eq!(p.kind(), "approval");
        assert_eq!(p.from(), "alice@example.com");
        assert_eq!(p.purpose(), Some("Approve $25,000 raise"));
        assert_eq!(p.scope(), Some("args.amount <= 25000"));
        assert_eq!(p.timeout(), Some("24h"));
        assert_eq!(p.channel(), Some("ciba"));
        assert!(p.elicitation_id().is_none());
        // Output slots start empty.
        assert!(p.id.is_none());
        assert!(p.status.is_none());
        assert!(p.valid.is_none());
    }

    #[test]
    fn with_elicitation_id_sets_correlation() {
        let p = ElicitationPayload::new(ElicitationOp::Check, "approval", "alice@example.com")
            .with_elicitation_id("elic-123");
        assert_eq!(p.elicitation_id(), Some("elic-123"));
        assert_eq!(p.operation(), ElicitationOp::Check);
    }

    #[test]
    fn payload_roundtrips_through_serde() {
        // The executor clones payloads across handler boundaries via serde
        // in some paths — confirm a populated output survives a round-trip.
        let mut p =
            ElicitationPayload::new(ElicitationOp::Dispatch, "approval", "alice@example.com");
        p.id = Some("elic-1".into());
        p.status = Some(ElicitationStatusKind::Pending);
        p.intent_id = Some("intent-9".into());

        let json = serde_json::to_string(&p).unwrap();
        let back: ElicitationPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id.as_deref(), Some("elic-1"));
        assert_eq!(back.status, Some(ElicitationStatusKind::Pending));
        assert_eq!(back.intent_id.as_deref(), Some("intent-9"));
    }
}
