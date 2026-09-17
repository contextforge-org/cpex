// Location: ./crates/cpex-core/src/identity/hook.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// `IdentityHook` — the `HookTypeDef` marker for the IdentityResolve
// hook family. Plugins implement `HookHandler<IdentityHook>`; the
// framework dispatches into them at request entry to populate
// `Extensions.security.subject` / `.client` / `.caller_workload` /
// `Extensions.raw_credentials` before any tool / resource / prompt
// hook runs.
//
// # Single hook name (for now)
//
// v0 registers under the single name `identity.resolve`. If a future
// slice introduces an `identity.validate` phase that uses the same
// payload + result shape (e.g. a post-resolve consistency check),
// it can share `IdentityHook` and register under `identity.validate`
// via the multi-name registration path — same pattern as CMF's
// `cmf.tool_pre_invoke` / `cmf.llm_input` / etc. sharing `CmfHook`.
// Phases with a different payload shape (e.g. TokenDelegate) get
// their own hook type rather than reusing this one.
//
// # Lifecycle
//
// This file defines the *types*. Lifecycle wiring — when the
// framework calls `invoke_named::<IdentityHook>(...)`, how results
// merge back into `Extensions` — lands elsewhere.

use crate::hooks::trait_def::PluginResult;

use super::payload::IdentityPayload;

/// Primary hook name for IdentityResolve handlers. Used as the
/// registry key when a host registers the handler via the standard
/// `register_handler` path.
pub const HOOK_IDENTITY_RESOLVE: &str = "identity.resolve";

crate::define_hook! {
    /// Identity-resolve hook.
    ///
    /// **Payload** ([`IdentityPayload`]) — unified input + accumulator.
    /// The host populates the input fields (`raw_token`, `source`,
    /// `headers`, ...) once at request entry and never touches them
    /// again; handlers populate the output fields (`subject`,
    /// `client`, `caller_workload`, `delegation`, `raw_credentials`,
    /// `rejected`, ...) on clones of the running payload. Input
    /// fields are private and read through accessors — handlers
    /// cannot mutate them even on a clone, so the wire-layer input
    /// is canonical across the whole chain.
    ///
    /// **Result** ([`PluginResult<IdentityPayload>`][PluginResult]) —
    /// the executor's standard envelope. `modified_payload` carries
    /// the updated payload. `continue_processing = false` halts the
    /// pipeline (set when the handler decides to reject).
    ///
    /// **Threading.** Sequential-phase semantics already thread
    /// handler N's `modified_payload` into handler N+1's input, so
    /// the chain's natural behavior is "each handler sees the prior
    /// handler's contributions in the running payload." No bespoke
    /// `resolve_identity` method on `PluginManager` — the standard
    /// `invoke_named::<IdentityHook>(...)` does the right thing.
    ///
    /// **Handler signature:**
    ///
    /// ```rust,ignore
    /// impl HookHandler<IdentityHook> for MyResolver {
    ///     async fn handle(
    ///         &self,
    ///         payload: &IdentityPayload,
    ///         _extensions: &Extensions,
    ///         _ctx: &mut PluginContext,
    ///     ) -> PluginResult<IdentityPayload> {
    ///         // Validate the raw token, build the SubjectExtension.
    ///         let claims = self.validate(payload.raw_token()).await?;
    ///         let mut updated = payload.clone();
    ///         updated.subject = Some(claims.into_subject());
    ///         PluginResult::modify_payload(updated)
    ///     }
    /// }
    /// ```
    ///
    /// Handlers that want to layer onto prior state without manually
    /// preserving every untouched field reach for
    /// [`IdentityPayload::merge`][merge].
    ///
    /// **Registration:** `manager.register_handler::<IdentityHook, _>(plugin, config)`
    /// against the hook name `"identity.resolve"`. Multiple handlers
    /// may register; the framework runs them in priority order and
    /// the Sequential-phase chain accumulates their contributions
    /// into the running payload.
    ///
    /// [merge]: super::payload::IdentityPayload::merge
    /// [PluginResult]: crate::hooks::trait_def::PluginResult
    IdentityHook, "identity.resolve" => {
        payload: IdentityPayload,
        result: PluginResult<IdentityPayload>,
    }
}
