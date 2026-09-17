// Location: ./crates/cpex-core/src/delegation/hook.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// `TokenDelegateHook` — the `HookTypeDef` marker for the
// TokenDelegate hook family. Plugins implement
// `HookHandler<TokenDelegateHook>`; outbound code dispatches into it
// to mint a downstream-scoped credential for the call it's about to
// make.
//
// Single hook name (for now): `"token.delegate"`. Future variants
// with the same payload shape — e.g. `"token.refresh"` for a
// refresh-token specific flow — could share `TokenDelegateHook` via
// multi-name registration. Variants with different payloads get
// their own hook type rather than reusing this one.

use crate::hooks::trait_def::PluginResult;

use super::payload::DelegationPayload;

/// Primary hook name for TokenDelegate handlers.
pub const HOOK_TOKEN_DELEGATE: &str = "token.delegate";

crate::define_hook! {
    /// Token-delegation hook.
    ///
    /// **Payload** ([`DelegationPayload`]) — unified input + accumulator.
    /// The outbound caller (typically a forwarding-proxy plugin)
    /// populates the input fields (`bearer_token`, `target_name`,
    /// `target_audience`, `required_permissions`, …) and invokes the
    /// hook; handlers populate the output fields
    /// (`delegated_token`, `delegation_update`, `metadata`) on clones
    /// of the running payload. Input fields are private and read
    /// through accessors — handlers cannot mutate them even on a
    /// clone, so the delegation context is canonical across the chain.
    ///
    /// **Result** ([`PluginResult<DelegationPayload>`][PluginResult])
    /// — the executor's standard envelope. `modified_payload`
    /// carries the updated payload. `continue_processing = false`
    /// halts the pipeline (handler decided no credential can be
    /// minted — e.g. the inbound token's scopes don't cover the
    /// target's required permissions).
    ///
    /// **Threading.** Sequential-phase semantics already thread
    /// handler N's `modified_payload` into handler N+1's input, so
    /// the chain's natural behavior is "each handler sees the prior
    /// handler's contributions in the running payload." Most
    /// deployments will register exactly one TokenDelegate handler
    /// (RFC 8693 exchanger, UCAN minter, …), but chaining works for
    /// hybrid setups — e.g. a passthrough fallback that fires only
    /// when the primary exchanger declined.
    ///
    /// **Handler signature:**
    ///
    /// ```rust,ignore
    /// impl HookHandler<TokenDelegateHook> for RfcExchanger {
    ///     async fn handle(
    ///         &self,
    ///         payload: &DelegationPayload,
    ///         _ext: &Extensions,
    ///         _ctx: &mut PluginContext,
    ///     ) -> PluginResult<DelegationPayload> {
    ///         let minted = self
    ///             .exchange(payload.bearer_token(), payload.target_audience())
    ///             .await?;
    ///         let mut updated = payload.clone();
    ///         updated.delegated_token = Some(minted);
    ///         PluginResult::modify_payload(updated)
    ///     }
    /// }
    /// ```
    ///
    /// **Registration:**
    /// `manager.register_handler_for_names::<TokenDelegateHook, _>(plugin, config, &["token.delegate"])`.
    /// `register_handler::<TokenDelegateHook, _>` alone registers
    /// under the marker's `NAME` ("token") which is the hook family,
    /// not the specific hook name — `register_handler_for_names`
    /// (or the unified-name path) is the right call.
    ///
    /// [PluginResult]: crate::hooks::trait_def::PluginResult
    TokenDelegateHook, "token.delegate" => {
        payload: DelegationPayload,
        result: PluginResult<DelegationPayload>,
    }
}
