// Location: ./crates/cpex-core/src/elicitation/hook.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// `ElicitationHook` — the `HookTypeDef` marker for the Elicitation hook
// family. Plugins implement `HookHandler<ElicitationHook>`; the apl-cpex
// bridge dispatches into it to drive a human-in-the-loop step (approval,
// confirmation, step-up, …).
//
// Single hook name: `"elicit"`. The three touch-points (dispatch /
// check / validate) are NOT separate hook names — they share one
// payload shape and are distinguished by `ElicitationPayload::operation`.
// This keeps registration and the plan trivial: one plugin, one entry,
// resolved `name → entry` exactly like delegation's `token.delegate`.

use crate::hooks::trait_def::PluginResult;

use super::payload::ElicitationPayload;

/// Hook name for Elicitation handlers.
pub const HOOK_ELICIT: &str = "elicit";

crate::define_hook! {
    /// Elicitation hook — drives a human-in-the-loop step through a
    /// channel plugin (Keycloak CIBA, Slack, in-band, …).
    ///
    /// **Payload** ([`ElicitationPayload`]) — unified input + accumulator.
    /// The apl-cpex bridge sets the input fields (`operation`,
    /// `elicitation_id`, `kind`, `from`, `purpose`, `scope`, `timeout`,
    /// `channel`) and invokes the hook; the handler populates the output
    /// fields (`id`, `status`, `outcome`, `approver`, `intent_id`,
    /// `expires_at`, `valid`, `reason`) on a clone of the running payload
    /// and returns it via [`PluginResult::modify_payload`]. Input fields
    /// are private and read through accessors.
    ///
    /// **Result** ([`PluginResult<ElicitationPayload>`][PluginResult]) —
    /// the executor's standard envelope. `modified_payload` carries the
    /// updated payload. `continue_processing = false` halts (the handler
    /// could not service the operation — e.g. unknown channel error); the
    /// bridge maps that to an `ElicitationError`.
    ///
    /// **Three operations, one hook.** [`ElicitationPayload::operation`]
    /// tells the handler whether this is a `Dispatch`, `Check`, or
    /// `Validate` call. A handler typically `match`es on it. The three
    /// short, synchronous calls span the (possibly hours-long) human gap,
    /// which is owned by the channel — never by a handler call.
    ///
    /// **Handler signature:**
    ///
    /// ```rust,ignore
    /// impl HookHandler<ElicitationHook> for CibaApprover {
    ///     async fn handle(
    ///         &self,
    ///         payload: &ElicitationPayload,
    ///         _ext: &Extensions,
    ///         _ctx: &mut PluginContext,
    ///     ) -> PluginResult<ElicitationPayload> {
    ///         let mut out = payload.clone();
    ///         match payload.operation() {
    ///             ElicitationOp::Dispatch => { /* register intent + CIBA backchannel */ }
    ///             ElicitationOp::Check    => { /* poll Keycloak token endpoint */ }
    ///             ElicitationOp::Validate => { /* verify token + intent binding */ }
    ///         }
    ///         PluginResult::modify_payload(out)
    ///     }
    /// }
    /// ```
    ///
    /// **Registration:**
    /// `manager.register_handler_for_names::<ElicitationHook, _>(plugin, config, &["elicit"])`.
    ///
    /// [PluginResult]: crate::hooks::trait_def::PluginResult
    ElicitationHook, "elicit" => {
        payload: ElicitationPayload,
        result: PluginResult<ElicitationPayload>,
    }
}
