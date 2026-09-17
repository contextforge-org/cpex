// Location: ./crates/apl-cpex/src/cmf_invoker.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// `CmfPluginInvoker` — `apl-core::PluginInvoker` impl bound to the CMF
// hook family. Drives dispatch off a pre-resolved [`RouteDispatchPlan`]
// (from [`DispatchCache`]) and forwards entries to
// `PluginManager::invoke_entries::<CmfHook>(...)`, which runs the full
// executor pipeline (sequential / transform / audit / concurrent /
// fire-and-forget; on_error / timeouts / mode / write tokens all
// honored). Compile-time payload type safety is provided by the
// `CmfHook: HookTypeDef` bound on `invoke_entries`.
//
// # Request-scoped vs session-scoped state
//
// The invoker carries **request-scoped** state — payload + extensions
// — under interior mutability (`Arc<tokio::sync::Mutex<_>>`) so mutations
// from one plugin call accumulate for the next call in the same
// request. **Session-scoped** state (labels that survive across requests
// in the same session) goes through the pluggable [`SessionStore`]
// trait: hydrated at `for_request` start, persisted via
// [`persist_session`] after route evaluation. Session ID is pulled from
// `extensions.agent.session_id`; absent → both ops are no-ops.
//
// Alongside the payload, the invoker records *whether* a plugin ever
// handed back a payload ([`payload_was_modified`]). That flag is the
// authoritative answer for the host: a plugin mutation is only
// detectable at the moment it's accepted, not by comparing message
// content afterwards (content comparison can't see mutations to
// non-text parts, and equality isn't defined on the CMF payload types).
//
// # Per-call taint extraction
//
// Each plugin invocation diffs `result.modified_extensions.security.labels`
// against the labels visible to *that call*. New labels become
// `PluginOutcome.taints` as `TaintEvent { scopes: vec![Session] }` —
// CMF's monotonic label channel is session-semantic by design, so
// Session is the natural default. Multi-scope plugin emissions (or
// `Message` scope) require either a future second label channel in
// Extensions or explicit config-side `Step::Taint { scopes: [...] }` /
// `Stage::Taint`.
//
// # Lifetime model
//
// One invoker instance per request. Host pre-builds the
// `MessagePayload`, hydrates session-scoped state via `for_request`
// (which is async because it awaits `SessionStore::load_labels`), then
// drives `evaluate_route`. After evaluation, host calls
// [`current_payload`] for body re-serialization and
// [`persist_session`] to commit accumulated session state.
//
// Background tasks returned by `invoke_entries` are dropped for v0;
// when audit/fire-and-forget plugin support is wired into APL's
// lifecycle, we'll thread a `BackgroundTasks` aggregator through the
// invoker.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;

use cpex_core::cmf::{CmfHook, MessagePayload};
use cpex_core::hooks::payload::Extensions;
use cpex_core::hooks::HookPhase;
use cpex_core::manager::PluginManager;

use apl_core::attributes::AttributeBag;
use apl_core::evaluator::Decision;
use apl_core::pipeline::{TaintEvent, TaintScope};
use apl_core::step::{DispatchPhase, PluginError, PluginInvocation, PluginInvoker, PluginOutcome};

use crate::dispatch_plan::RouteDispatchPlan;
use crate::session_store::{SessionStore, SessionStoreError};

/// Bridges APL plugin dispatch to CMF-family CPEX hooks.
///
/// Carries the request's `MessagePayload` and `Extensions` for its
/// entire lifetime so plugin mutations accumulate (one plugin's
/// `[REDACTED]` output is visible to the next plugin in the same
/// route; one plugin's added label seeds the next plugin's filter view).
pub struct CmfPluginInvoker {
    manager: Arc<PluginManager>,
    /// Per-request extensions under interior mutability. Locked across
    /// awaits — `tokio::sync::Mutex` is required because the executor's
    /// `invoke_entries` is async.
    extensions: Arc<Mutex<Extensions>>,
    /// Per-request payload under interior mutability. Same reasoning as
    /// `extensions` — accumulated text rewrites have to be visible to
    /// the next dispatch in the same request.
    payload: Arc<Mutex<MessagePayload>>,
    /// Set the moment a plugin's `modified_payload` is accepted into
    /// `payload` above. Request-scoped and sticky: once any plugin in
    /// the request mutates, it stays `true`.
    ///
    /// This is the *signal* the host reads to decide whether to forward
    /// a modified payload. It exists because the fact is only knowable
    /// here — a caller comparing message content afterwards sees text
    /// parts only, so a redaction of a `ToolResult` (or any other
    /// non-text part) looks identical to no mutation at all.
    payload_modified: AtomicBool,
    /// Pre-resolved per-route plugin lineup. Built (or fetched from a
    /// shared `DispatchCache`) at request start by the host.
    plan: Arc<RouteDispatchPlan>,
    /// Session ID resolved at request start by the 4-tier
    /// [`session_resolver::resolve_session`] (token claim → header →
    /// identity-derived → none). `None` for fully-anonymous traffic
    /// (no claim, no header, no subject id) — hydration + persistence
    /// become no-ops in that case.
    session_id: Option<String>,
    /// Pluggable session-scoped state backend. `Arc<dyn SessionStore>`
    /// rather than a generic so a single invoker type works for memory /
    /// Redis / future-distributed stores without monomorphization churn.
    session_store: Arc<dyn SessionStore>,
    /// Labels present in `extensions.security.labels` immediately after
    /// `SessionStore` hydration but before any plugins have run. Used
    /// by `persist_session` to diff against final labels and append only
    /// the additions to the session store. Empty when there was no
    /// session_id (so no hydration happened).
    initial_labels: HashSet<String>,
}

impl CmfPluginInvoker {
    /// Construct an invoker bound to one request's payload + extensions
    /// and the pre-resolved dispatch plan for the request's route.
    /// Hydrates accumulated session-scoped labels into
    /// `extensions.security.labels` before returning, so the first
    /// plugin sees the full session-monotonic view.
    pub async fn for_request(
        manager: Arc<PluginManager>,
        mut extensions: Extensions,
        payload: MessagePayload,
        plan: Arc<RouteDispatchPlan>,
        session_store: Arc<dyn SessionStore>,
    ) -> Result<Self, SessionStoreError> {
        // Resolve session id via the 4-tier resolver (token claim →
        // header → identity-derived → none). Snapshotted before
        // hydration so the lookup is independent of the COW write
        // that hydration performs.
        let session_id: Option<String> =
            crate::session_resolver::resolve_session(&extensions).map(|(sid, _src)| sid);

        // Hydration: union the session's accumulated labels into the
        // request's security labels. Skipped when there's no session_id
        // (anonymous/sessionless traffic has no state to load and is
        // unaffected by a store outage). A load error propagates so the
        // caller fails the request closed *before* any decision is made
        // — a distributed store being unreachable must never silently
        // present as "no accumulated labels".
        if let Some(sid) = &session_id {
            let stored = session_store.load_labels(sid).await?;
            if !stored.is_empty() {
                extensions = hydrate_labels(extensions, &stored);
            }
        }

        let initial_labels = snapshot_labels(&extensions);

        Ok(Self {
            manager,
            extensions: Arc::new(Mutex::new(extensions)),
            payload: Arc::new(Mutex::new(payload)),
            payload_modified: AtomicBool::new(false),
            plan,
            session_id,
            session_store,
            initial_labels,
        })
    }

    /// Snapshot the current payload. Call after route evaluation to
    /// extract the final (possibly-mutated) `MessagePayload` for body
    /// re-serialization.
    pub async fn current_payload(&self) -> MessagePayload {
        self.payload.lock().await.clone()
    }

    /// Did any plugin in this request hand back a payload?
    ///
    /// `true` from the moment a `modified_payload` is accepted into the
    /// request's payload, and never resets. The host uses this to decide
    /// whether to forward [`current_payload`] downstream. Reported
    /// independently of *what* changed: a plugin that rewrites a tool
    /// result, a tool call's arguments, or a thinking block is as
    /// visible here as one that rewrites text.
    ///
    /// Deliberately `false` when a plugin returned a payload of the
    /// wrong concrete type — that mutation was dropped (with a warning),
    /// so claiming it landed would forward an unmutated payload while
    /// asserting it changed.
    pub fn payload_was_modified(&self) -> bool {
        // Pairs with the `Release` store in `invoke`: plugin branches
        // can run on other tasks (`dispatch_parallel`), so the write
        // has to be visible to this read.
        self.payload_modified.load(Ordering::Acquire)
    }

    /// Snapshot the current extensions. Useful for hosts that need to
    /// inspect the post-evaluation extension state (audit, telemetry).
    pub async fn current_extensions(&self) -> Extensions {
        self.extensions.lock().await.clone()
    }

    /// Shared `Arc<Mutex<Extensions>>` handle. Used by collaborators
    /// (notably `DelegationPluginInvoker`) that need to mutate the
    /// same request-scoped extensions this invoker sees — e.g. a
    /// `delegate(...)` step minting a token needs to write
    /// `raw_credentials.delegated_tokens.*` into the same Extensions
    /// the next CMF plugin will read.
    pub fn extensions_arc(&self) -> Arc<Mutex<Extensions>> {
        Arc::clone(&self.extensions)
    }

    /// Shared `Arc<RouteDispatchPlan>` handle. Collaborators (e.g.
    /// `DelegationPluginInvoker`) need this to look up their own
    /// entries in the same per-route plan the CMF invoker uses.
    pub fn plan_arc(&self) -> Arc<RouteDispatchPlan> {
        Arc::clone(&self.plan)
    }

    /// Drain APL-emitted session-scoped taints into the request's
    /// `security.labels` so the existing label-monotonic flow
    /// ([`persist_session`] below) picks them up. Filters by
    /// `TaintScope::Session` — Message-scoped taints (and any future
    /// scope) are deliberately ignored here; they have their own
    /// destination (TBD: a labels slot on `MessagePayload`).
    ///
    /// Host (`AplRouteHandler`) calls this once per request after
    /// `evaluate_pre` / `evaluate_post` returns, with the
    /// `RouteDecision.taints` slice. No-op when the slice has no
    /// Session-scoped entries — common for routes that don't taint.
    pub async fn apply_session_taints(&self, taints: &[apl_core::pipeline::TaintEvent]) {
        use apl_core::pipeline::TaintScope;
        use cpex_core::extensions::SecurityExtension;

        let session_labels: Vec<&str> = taints
            .iter()
            .filter(|t| t.scopes.contains(&TaintScope::Session))
            .map(|t| t.label.as_str())
            .collect();
        if session_labels.is_empty() {
            return;
        }
        let mut current = self.extensions.lock().await;
        // `Extensions.security` is `Option<Arc<SecurityExtension>>`.
        // Initialize the slot if absent; `Arc::make_mut` gives us a
        // mutable reference to the underlying value, cloning when
        // other Arc holders exist (e.g., a downstream snapshot reader).
        let arc = current
            .security
            .get_or_insert_with(|| Arc::new(SecurityExtension::default()));
        let sec = Arc::make_mut(arc);
        for label in session_labels {
            sec.add_label(label);
        }
    }

    /// Persist session-scoped state added during this request. Diffs
    /// current `security.labels` against the post-hydration snapshot
    /// and appends new labels to the session store. No-op (returns
    /// `Ok`) when there was no session ID or no new labels. Host calls
    /// this exactly once after route evaluation completes.
    ///
    /// An append error is returned so the caller can fail the request
    /// closed. Because this runs after the policy decision is
    /// computed, the route handler converts an append error into a Deny
    /// outcome rather than dropping the accumulated taint silently.
    pub async fn persist_session(&self) -> Result<(), SessionStoreError> {
        let Some(sid) = &self.session_id else {
            return Ok(());
        };
        let current = self.extensions.lock().await;
        let Some(security) = current.security.as_ref() else {
            return Ok(());
        };
        let new_labels: Vec<String> = security
            .labels
            .iter()
            .filter(|l| !self.initial_labels.contains(l.as_str()))
            .cloned()
            .collect();
        drop(current); // release the lock before the await
        if !new_labels.is_empty() {
            self.session_store.append_labels(sid, &new_labels).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl PluginInvoker for CmfPluginInvoker {
    async fn invoke(
        &self,
        plugin_name: &str,
        _bag: &AttributeBag,
        invocation: PluginInvocation<'_>,
    ) -> Result<PluginOutcome, PluginError> {
        let resolved = self
            .plan
            .get(plugin_name)
            .ok_or_else(|| PluginError::NotFound(plugin_name.to_string()))?;

        // Snapshot extensions to read entity_type — the dispatcher
        // needs it for hook routing. Dropped immediately so we don't
        // hold the lock across the per-entry payload clone.
        let request_entity_type: Option<String> = {
            let ext = self.extensions.lock().await;
            ext.meta.as_ref().and_then(|m| m.entity_type.clone())
        };

        // Pick the entry whose registered hook matches the current
        // dispatch context via cpex-core's hook metadata table.
        // Replaces the prior naming heuristic.
        let dispatch_phase = match invocation.phase() {
            DispatchPhase::Pre => HookPhase::Pre,
            DispatchPhase::Post => HookPhase::Post,
        };
        let entry = resolved
            .pick_entry(request_entity_type.as_deref(), dispatch_phase)
            .ok_or_else(|| {
                PluginError::Dispatch(format!(
                    "plugin '{plugin_name}' has no hook matching dispatch \
                     context (entity_type={:?}, phase={:?}); declared hooks: {:?}",
                    request_entity_type,
                    dispatch_phase,
                    resolved.entries_by_hook.keys().collect::<Vec<_>>(),
                ))
            })?;

        // Snapshot the current payload + extensions — `invoke_entries`
        // consumes by-value, so we clone for the call and keep the
        // canonical copies in shared state for the next dispatch.
        let current_payload = self.payload.lock().await.clone();
        let current_extensions = self.extensions.lock().await.clone();

        // Per-call taint diff baseline. New labels in `result` minus
        // these become `PluginOutcome.taints`.
        let before_labels = snapshot_labels(&current_extensions);

        // Per-call field baseline for pipeline-stage dispatch: the field
        // as *this payload* holds it right now.
        //
        // This is the only sound thing to compare a readback against. The
        // pipeline's own `value` may already carry earlier stages' edits
        // (`mask`, `redact`, `hash`) that were never pushed into the
        // payload, so comparing against it would read the payload's
        // untouched original as "the plugin's new value" and hand the
        // pre-redaction plaintext back to the pipeline, undoing the
        // earlier stage.
        let field_before = match invocation {
            PluginInvocation::Field { name, phase, .. } => {
                field_value_from_message(&current_payload.message, name, phase)
            },
            PluginInvocation::Step { .. } => None,
        };

        let (result, _bg) = self
            .manager
            .invoke_entries::<CmfHook>(
                std::slice::from_ref(entry),
                current_payload,
                current_extensions,
                None,
            )
            .await;

        // Map deny: violation reason → APL deny reason; plugin code →
        // rule_source for audit attribution.
        let decision = if result.is_denied() {
            let (reason, rule_source) = match result.violation {
                Some(v) => (Some(v.reason), v.code),
                None => (None, "policy.forbidden".to_string()),
            };
            Decision::Deny {
                reason,
                rule_source,
            }
        } else {
            Decision::Allow
        };

        // Persist any plugin-side payload mutation back into the shared
        // request payload. `PluginPayload` only exposes `as_any`, so we
        // downcast-ref and clone. `MessagePayload: Clone` makes this
        // cheap relative to the FFI/invoke cost.
        //
        // Gated on `payload_modified`, not on `modified_payload.is_some()`:
        // the executor returns the final payload on every allowed
        // pipeline, so `is_some()` is true even when the plugin never
        // touched it.
        let modified_value = if !result.payload_modified {
            None
        } else if let Some(mp_boxed) = result.modified_payload.as_ref() {
            match mp_boxed.as_any().downcast_ref::<MessagePayload>() {
                Some(modified) => {
                    *self.payload.lock().await = modified.clone();
                    // Record the mutation for the host. `Release` so the
                    // flag is visible to `payload_was_modified` even when
                    // this call ran on a `dispatch_parallel` branch task.
                    self.payload_modified.store(true, Ordering::Release);
                    match invocation {
                        PluginInvocation::Field { name, phase, .. } => {
                            let rewritten =
                                field_value_from_message(&modified.message, name, phase)
                                    .filter(|new_value| field_before.as_ref() != Some(new_value));
                            if rewritten.is_none() {
                                tracing::debug!(
                                    plugin = %plugin_name,
                                    field = %name,
                                    "plugin mutated the payload but not this field; \
                                     leaving the field value alone"
                                );
                            }
                            rewritten
                        },
                        PluginInvocation::Step { .. } => None,
                    }
                },
                None => {
                    // Left out of `payload_modified` on purpose: nothing
                    // was written, so the host must keep forwarding the
                    // payload it already has.
                    tracing::warn!(
                        plugin = %plugin_name,
                        "CmfPluginInvoker: modified_payload was not MessagePayload \
                         (downcast failed) — dropping the mutation"
                    );
                    None
                },
            }
        } else {
            None
        };

        // Promote modified extensions back into shared state + extract
        // newly-added labels as taints. The executor returns
        // `Option<Extensions>` for the modified view — `Some` only when
        // a plugin actually changed extensions. The executor has
        // already validated label monotonicity on the way out.
        let taints = if let Some(modified_ext) = result.modified_extensions {
            let after_labels = snapshot_labels(&modified_ext);
            let new_labels: Vec<String> =
                after_labels.difference(&before_labels).cloned().collect();
            *self.extensions.lock().await = modified_ext;
            new_labels
                .into_iter()
                .map(|label| TaintEvent {
                    label,
                    // v0: CMF's `security.labels` is session-semantic by
                    // design (monotonic accumulation). Plugins that need
                    // Message-scoped taints emit them via config-side
                    // `Step::Taint`/`Stage::Taint` for now.
                    scopes: vec![TaintScope::Session],
                })
                .collect()
        } else {
            Vec::new()
        };

        Ok(PluginOutcome {
            decision,
            taints,
            modified_value,
        })
    }
}

/// Read the value of one pipeline field out of a message.
///
/// A plugin dispatched from an `args:` / `result:` stage is handed the
/// whole message, not the field, so its new value for that field has to
/// be read back out. The projection matches what APL evaluated against:
/// Pre addresses args, Post addresses result. `field` is relative to
/// that root.
///
/// Two shapes:
///   * object projection (a tool call's arguments, a structured tool
///     result) → look up `field` in it, `None` when absent.
///   * scalar projection (a text-only message, whose whole content is
///     the field) → the projection itself.
///
/// The caller compares the result against the value the pipeline is
/// holding: equal, or `None` here, both mean "this plugin didn't change
/// this field". The plugin's payload mutation is recorded separately, so
/// reporting no field change never drops it.
fn field_value_from_message(
    message: &cpex_core::cmf::Message,
    field: &str,
    phase: DispatchPhase,
) -> Option<serde_json::Value> {
    let projection = match phase {
        DispatchPhase::Pre => crate::message_projection::extract_args_from_message(message),
        DispatchPhase::Post => crate::message_projection::extract_result_from_message(message),
    };
    if projection.is_object() {
        apl_core::get_dotted(&projection, field).cloned()
    } else {
        Some(projection)
    }
}

/// Snapshot `extensions.security.labels` as an owned `HashSet<String>`.
/// Empty when security is absent.
fn snapshot_labels(extensions: &Extensions) -> HashSet<String> {
    extensions
        .security
        .as_ref()
        .map(|s| s.labels.iter().cloned().collect())
        .unwrap_or_default()
}

/// Add `labels` to `extensions.security.labels` (monotonic union).
/// Creates a security extension if absent. Used at hydration time —
/// merges the SessionStore's accumulated labels into the request view
/// so the first plugin sees the full picture.
fn hydrate_labels(mut extensions: Extensions, labels: &[String]) -> Extensions {
    // Clone the Arc'd security into an owned struct so we can mutate.
    // Most slots stay refcount-shared; only security is materialized.
    let mut security = extensions
        .security
        .as_ref()
        .map(|s| (**s).clone())
        .unwrap_or_default();
    for l in labels {
        security.add_label(l.clone());
    }
    extensions.security = Some(Arc::new(security));
    extensions
}
