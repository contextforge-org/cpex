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
// # Why pre-resolved entries instead of `invoke_named`?
//
// `invoke_named(hook_name, ...)` resolves a fresh lineup per call via
// hook lookup + cpex-core's condition/entity routing. APL's `routes:`
// is already the authoritative plugin lineup, so re-resolving wastes
// work and lets cpex-core's parallel routing model overrule APL. The
// plan-based path caches the resolution per `(route_key, generation)`
// — first invocation builds, subsequent invocations reuse — and
// surfaces hook context (step vs field) via pre-classified entries.
//
// # Lifetime model
//
// One invoker instance per request. The host pre-builds the
// `MessagePayload` once from raw inputs, hands it in via
// [`for_request`], and the invoker carries it through every plugin
// dispatch on the request. Mutations from plugins (e.g. PII redaction)
// are persisted in the shared payload so the next plugin in the chain
// sees the rewritten version. After route evaluation, the host calls
// [`current_payload`] to extract the final bytes for body
// re-serialization.
//
// Background tasks returned by `invoke_entries` are dropped for v0;
// when audit/fire-and-forget plugin support is wired into APL's
// lifecycle, we'll thread a `BackgroundTasks` aggregator through the
// invoker.

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;

use cpex_core::cmf::{CmfHook, MessagePayload};
use cpex_core::hooks::payload::Extensions;
use cpex_core::manager::PluginManager;

use apl_core::attributes::AttributeBag;
use apl_core::evaluator::Decision;
use apl_core::step::{PluginError, PluginInvocation, PluginInvoker, PluginOutcome};

use crate::dispatch_plan::RouteDispatchPlan;

/// Bridges APL plugin dispatch to CMF-family CPEX hooks.
///
/// Carries the request's `MessagePayload` for its entire lifetime so
/// plugin mutations accumulate (one plugin's `[REDACTED]` output is
/// visible to the next plugin in the same route).
pub struct CmfPluginInvoker {
    manager: Arc<PluginManager>,
    extensions: Extensions,
    /// `tokio::sync::Mutex` (not `std::sync::Mutex`) because the lock is
    /// held across `await` points — the manager's invoke is async, and
    /// we don't want two concurrent invocations racing on the payload.
    payload: Arc<Mutex<MessagePayload>>,
    /// Pre-resolved per-route plugin lineup. Built (or fetched from a
    /// shared `DispatchCache`) at request start by the host; the
    /// invoker just reads from it. Shared via `Arc` because the same
    /// plan can serve many requests targeting the same route.
    plan: Arc<RouteDispatchPlan>,
}

impl CmfPluginInvoker {
    /// Construct an invoker bound to one request's payload + extensions
    /// and the pre-resolved dispatch plan for the request's route.
    pub fn for_request(
        manager: Arc<PluginManager>,
        extensions: Extensions,
        payload: MessagePayload,
        plan: Arc<RouteDispatchPlan>,
    ) -> Self {
        Self {
            manager,
            extensions,
            payload: Arc::new(Mutex::new(payload)),
            plan,
        }
    }

    /// Snapshot the current payload. Call after route evaluation to
    /// extract the final (possibly-mutated) `MessagePayload` for body
    /// re-serialization.
    pub async fn current_payload(&self) -> MessagePayload {
        self.payload.lock().await.clone()
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

        // Pick the entry for this invocation context. None means the
        // plugin doesn't declare any hook of the appropriate kind for
        // this route — surface as Dispatch error so config drift fails
        // fast rather than silently no-op'ing.
        let entry = match invocation {
            PluginInvocation::Step => resolved.step_entry.as_ref().ok_or_else(|| {
                PluginError::Dispatch(format!(
                    "plugin '{plugin_name}' has no step-context hook \
                     (policy / post_policy invocation)"
                ))
            })?,
            PluginInvocation::Field { .. } => resolved.field_entry.as_ref().ok_or_else(|| {
                PluginError::Dispatch(format!(
                    "plugin '{plugin_name}' has no field-context hook \
                     (args / result pipeline invocation)"
                ))
            })?,
        };

        // Snapshot the current payload — `invoke_entries` consumes its
        // argument, so we hand it a clone and keep the canonical copy
        // in shared state for the next dispatch.
        let current = self.payload.lock().await.clone();

        let (result, _bg) = self
            .manager
            .invoke_entries::<CmfHook>(
                std::slice::from_ref(entry),
                current,
                self.extensions.clone(),
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

        // Promote any plugin-side payload mutation back into the shared
        // request payload so the next plugin in the chain sees it.
        // `PluginPayload` only exposes `as_any` (no owning downcast), so
        // we downcast-ref and clone. `MessagePayload: Clone` makes this
        // cheap relative to the FFI/invoke cost.
        let modified_value = if let Some(mp_boxed) = result.modified_payload.as_ref() {
            match mp_boxed.as_any().downcast_ref::<MessagePayload>() {
                Some(modified) => {
                    *self.payload.lock().await = modified.clone();
                    // For pipe-chain (`Field`) calls, surface the new text
                    // content as `modified_value` so APL's evaluator can
                    // feed it into the next field-pipeline stage. For
                    // Step calls, the modification is internal to the
                    // shared payload and `modified_value` stays None.
                    match invocation {
                        PluginInvocation::Field { .. } => {
                            Some(serde_json::Value::String(
                                modified.message.get_text_content(),
                            ))
                        }
                        PluginInvocation::Step => None,
                    }
                }
                None => {
                    tracing::warn!(
                        plugin = %plugin_name,
                        "CmfPluginInvoker: modified_payload was not MessagePayload \
                         (downcast failed) — dropping the mutation"
                    );
                    None
                }
            }
        } else {
            None
        };

        // v0: taint extraction not wired. When plugins start emitting
        // labels via `result.modified_extensions.security.labels`, we'll
        // diff against `self.extensions.security.labels` and feed the
        // additions into `PluginOutcome.taints`.
        Ok(PluginOutcome {
            decision,
            taints: Vec::new(),
            modified_value,
        })
    }
}
