// Location: ./crates/apl-cpex/src/elicitation_invoker.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// `ElicitationPluginInvoker` — `apl-core::ElicitationInvoker` impl
// bound to the `ElicitationHook` family. Drives dispatch off a
// pre-resolved [`RouteDispatchPlan::elicitation_entries`] and forwards
// to `PluginManager::invoke_entries::<ElicitationHook>(...)`.
//
// # When this runs
//
// The apl-core evaluator calls one of the three trait methods per
// `Effect::Elicit` it walks, across the lifetime of one elicitation:
//
//   * `dispatch(step, resolved_from)` — first arrival. Builds an
//     `ElicitationPayload` in `Dispatch` mode and invokes the named
//     handler, which registers the intent / opens the backchannel and
//     returns the correlation id + pending metadata.
//   * `check(step, id)` — every retry. `Check` mode; the handler reports
//     the current status without blocking.
//   * `validate(step, id)` — once resolved. `Validate` mode; the handler
//     verifies the response is genuine.
//
// All three resolve the handler the same way delegation does — `name →
// entry` off the plan (`step.plugin_name`). Elicitation routes by plugin
// name, not `(kind, channel)`; `channel` is only an audit label.
//
// # Shared extensions
//
// Like `DelegationPluginInvoker`, this carries the request's shared
// `Extensions` so the handler can read identity (the approver, the
// subject) through the normal hook extensions argument. Get the handle
// via `CmfPluginInvoker::extensions_arc()`.

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;

use cpex_core::elicitation::{
    ElicitationHook, ElicitationOp, ElicitationOutcomeKind, ElicitationPayload,
    ElicitationStatusKind,
};
use cpex_core::hooks::payload::Extensions;
use cpex_core::manager::PluginManager;

use apl_core::step::{
    ElicitStep, ElicitationDispatch, ElicitationError, ElicitationInvoker, ElicitationOutcome,
    ElicitationStatus, ElicitationValidation,
};

use crate::dispatch_plan::RouteDispatchPlan;

/// Bridges APL elicitation-step dispatch (`require_approval(...)`,
/// `confirm(...)`, …) to CPEX `ElicitationHook` plugins.
pub struct ElicitationPluginInvoker {
    manager: Arc<PluginManager>,
    /// Same `Arc<Mutex<Extensions>>` as the CMF invoker for this request,
    /// so the handler reads the same identity the policy evaluated against.
    extensions: Arc<Mutex<Extensions>>,
    /// Pre-resolved per-route elicitation lineup (`name → entry`).
    plan: Arc<RouteDispatchPlan>,
}

impl ElicitationPluginInvoker {
    /// Construct an invoker bound to the request's shared extensions and
    /// the route's pre-resolved dispatch plan. Take the extensions Arc
    /// from `CmfPluginInvoker::extensions_arc()` so this and the CMF
    /// invoker see the same Extensions.
    pub fn new(
        manager: Arc<PluginManager>,
        extensions: Arc<Mutex<Extensions>>,
        plan: Arc<RouteDispatchPlan>,
    ) -> Self {
        Self {
            manager,
            extensions,
            plan,
        }
    }

    /// Resolve the route's `elicit` entry for `plugin_name`, or
    /// `NotFound` (which the evaluator's `on_error` then handles). Routes
    /// that don't reference this plugin won't have it in the plan.
    fn entry_for(
        &self,
        plugin_name: &str,
    ) -> Result<cpex_core::registry::HookEntry, ElicitationError> {
        self.plan
            .elicitation_entries
            .get(plugin_name)
            .cloned()
            .ok_or_else(|| ElicitationError::NotFound(plugin_name.to_string()))
    }

    /// Common dispatch: invoke the resolved entry with `payload`, returns
    /// the resolved `ElicitationPayload` on allow, or an
    /// `ElicitationError` on a handler deny / missing payload. `op` names
    /// the operation (`"dispatch"` / `"check"` / `"validate"`) so a
    /// failure reads accurately rather than always saying "dispatch".
    async fn invoke(
        &self,
        op: &str,
        plugin_name: &str,
        payload: ElicitationPayload,
    ) -> Result<ElicitationPayload, ElicitationError> {
        let entry = self.entry_for(plugin_name)?;
        let current_extensions = self.extensions.lock().await.clone();

        let (result, _bg) = self
            .manager
            .invoke_entries::<ElicitationHook>(
                std::slice::from_ref(&entry),
                payload,
                current_extensions,
                None,
            )
            .await;

        if !result.continue_processing {
            let detail = result
                .violation
                .map(|v| format!("{}: {}", v.code, v.reason))
                .unwrap_or_else(|| "denied without violation detail".to_string());
            return Err(ElicitationError::Handler(format!(
                "{op}: plugin `{plugin_name}` halted: {detail}"
            )));
        }

        ElicitationPayload::from_pipeline_result(&result).ok_or_else(|| {
            ElicitationError::Handler(format!(
                "{op}: plugin `{plugin_name}` returned allow but no ElicitationPayload"
            ))
        })
    }
}

/// Map a step's optional channel/purpose/scope/timeout onto the payload's
/// input builders. Shared by all three operations.
fn apply_step_inputs(mut payload: ElicitationPayload, step: &ElicitStep) -> ElicitationPayload {
    if let Some(purpose) = &step.purpose {
        payload = payload.with_purpose(purpose.clone());
    }
    if let Some(scope) = &step.scope {
        payload = payload.with_scope(scope.clone());
    }
    if let Some(timeout) = &step.timeout {
        payload = payload.with_timeout(timeout.clone());
    }
    if let Some(channel) = &step.channel {
        payload = payload.with_channel(channel.clone());
    }
    payload
}

#[async_trait]
impl ElicitationInvoker for ElicitationPluginInvoker {
    async fn dispatch(
        &self,
        step: &ElicitStep,
        resolved_from: &str,
    ) -> Result<ElicitationDispatch, ElicitationError> {
        let payload = apply_step_inputs(
            ElicitationPayload::new(ElicitationOp::Dispatch, step.kind.as_str(), resolved_from),
            step,
        );
        let out = self.invoke("dispatch", &step.plugin_name, payload).await?;

        // The handler must mint an id on dispatch.
        let id = out.id.ok_or_else(|| {
            ElicitationError::Handler(format!(
                "dispatch: plugin `{}` dispatched without returning an id",
                step.plugin_name
            ))
        })?;
        Ok(ElicitationDispatch {
            id,
            approver: out.approver,
            intent_id: out.intent_id,
            expires_at: out.expires_at,
        })
    }

    async fn check(
        &self,
        step: &ElicitStep,
        id: &str,
    ) -> Result<ElicitationStatus, ElicitationError> {
        let payload = apply_step_inputs(
            ElicitationPayload::new(ElicitationOp::Check, step.kind.as_str(), "")
                .with_elicitation_id(id),
            step,
        );
        let out = self.invoke("check", &step.plugin_name, payload).await?;

        match out.status {
            Some(ElicitationStatusKind::Pending) | None => Ok(ElicitationStatus::Pending),
            Some(ElicitationStatusKind::Expired) => Ok(ElicitationStatus::Expired),
            Some(ElicitationStatusKind::Resolved) => {
                // Resolved must carry an outcome; default to Denied
                // (fail-safe — never silently treat as approved).
                let outcome = match out.outcome {
                    Some(ElicitationOutcomeKind::Approved) => ElicitationOutcome::Approved,
                    Some(ElicitationOutcomeKind::Denied) | None => ElicitationOutcome::Denied,
                };
                Ok(ElicitationStatus::Resolved { outcome })
            }
        }
    }

    async fn validate(
        &self,
        step: &ElicitStep,
        id: &str,
    ) -> Result<ElicitationValidation, ElicitationError> {
        let payload = apply_step_inputs(
            ElicitationPayload::new(ElicitationOp::Validate, step.kind.as_str(), "")
                .with_elicitation_id(id),
            step,
        );
        let out = self.invoke("validate", &step.plugin_name, payload).await?;

        Ok(ElicitationValidation {
            // Absent `valid` is treated as not-valid (fail-closed).
            valid: out.valid.unwrap_or(false),
            approver: out.approver,
            intent_id: out.intent_id,
            reason: out.reason,
        })
    }
}
