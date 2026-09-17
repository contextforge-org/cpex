// Location: ./crates/cpex-hosts-python/src/conversion.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// Payload serialization, hook-name resolution, and the response-to-result
// conversion.
//
// Two directions, both keyed on the hook name:
//
//   outbound: `&dyn PluginPayload` ──> JSON the worker's `json_to_payload`
//             reconstructs into the matching Pydantic model
//   inbound:  the worker's response JSON ──> `ErasedResultFields` the
//             executor consumes
//
// # Why a registry
//
// The host forwards arbitrary payloads, so nothing here can be generic over a
// single `P: PluginPayload`. Outbound, serialization is a downcast chain
// (mirroring `cpex-ffi`'s ordering) because the concrete type arrives erased.
// Inbound, the hook *name* selects which typed payload a `modified_payload`
// deserializes into — a `PayloadKind` per hook name, with `cmf.` routing to
// `MessagePayload` and unrecognized names to the generic payload.

use cpex_core::cmf::MessagePayload;
use cpex_core::error::PluginViolation;
use cpex_core::executor::ErasedResultFields;
use cpex_core::hooks::payload::PluginPayload;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::HostError;
use crate::legacy::payloads::{
    IdentityResolvePayload, PromptPostFetchPayload, PromptPreFetchPayload,
    ResourcePostFetchPayload, ResourcePreFetchPayload, TokenDelegatePayload, ToolPostInvokePayload,
    ToolPreInvokePayload,
};

/// Prefix that marks a CMF hook name.
pub const CMF_PREFIX: &str = "cmf.";

/// Wraps any JSON value for hooks with no typed payload.
///
/// The third copy of this type in the workspace — `cpex-ffi` and the Python
/// bindings each define their own, because cpex-core exports the
/// `impl_plugin_payload!` macro but not a shared struct. Consolidating all
/// three into cpex-core is deferred follow-up work; it would touch the FFI and
/// the bindings, and is not needed to ship this host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenericPayload {
    pub value: Value,
}

cpex_core::impl_plugin_payload!(GenericPayload);

/// Which payload type a hook name maps to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadKind {
    /// Any `cmf.*` hook — the CMF message payload.
    CmfMessage,
    ToolPreInvoke,
    ToolPostInvoke,
    PromptPreFetch,
    PromptPostFetch,
    ResourcePreFetch,
    ResourcePostFetch,
    IdentityResolve,
    TokenDelegate,
    /// No typed payload for this name — carry the JSON as-is.
    Generic,
}

/// Resolve a hook name to its payload kind.
///
/// The `cmf.` prefix is checked first: `cmf.tool_pre_invoke` must route to the
/// CMF message payload, not to the legacy tool payload whose name it contains.
pub fn payload_kind_for_hook(hook_name: &str) -> PayloadKind {
    use cpex_core::hooks::types::hook_names;

    if hook_name.starts_with(CMF_PREFIX) {
        return PayloadKind::CmfMessage;
    }

    match hook_name {
        hook_names::TOOL_PRE_INVOKE => PayloadKind::ToolPreInvoke,
        hook_names::TOOL_POST_INVOKE => PayloadKind::ToolPostInvoke,
        hook_names::PROMPT_PRE_FETCH => PayloadKind::PromptPreFetch,
        hook_names::PROMPT_POST_FETCH => PayloadKind::PromptPostFetch,
        hook_names::RESOURCE_PRE_FETCH => PayloadKind::ResourcePreFetch,
        hook_names::RESOURCE_POST_FETCH => PayloadKind::ResourcePostFetch,
        hook_names::IDENTITY_RESOLVE => PayloadKind::IdentityResolve,
        hook_names::TOKEN_DELEGATE => PayloadKind::TokenDelegate,
        _ => PayloadKind::Generic,
    }
}

/// Whether a hook carries raw credentials.
///
/// Only `identity_resolve` and `token_delegate` do: they are the only two
/// hooks whose Python payload models a raw token at all
/// (`IdentityPayload.raw_token`, `DelegationPayload.bearer_token`). The Python
/// `Extensions` model has no raw-credential slot, so no other hook has
/// anywhere to receive one.
pub fn is_credential_hook(hook_name: &str) -> bool {
    matches!(
        payload_kind_for_hook(hook_name),
        PayloadKind::IdentityResolve | PayloadKind::TokenDelegate
    )
}

/// Serialize an erased payload to the JSON shape the worker reconstructs.
///
/// The downcast chain covers every type this host can hand out, in rough
/// frequency order. `MessagePayload` comes first, mirroring `cpex-ffi`'s
/// `serialize_payload`.
///
/// An unrecognized concrete type is an error rather than a silent `null`: it
/// means some other host handed this adapter a payload it cannot forward, and
/// sending `null` would surface inside the worker as a confusing Pydantic
/// validation failure instead.
pub fn serialize_payload(payload: &dyn PluginPayload) -> Result<Value, HostError> {
    let any = payload.as_any();

    // Macro rather than a chain of near-identical `if let` blocks — ten arms
    // written out drift, and the pattern is mechanical.
    macro_rules! try_downcast {
        ($($ty:ty),+ $(,)?) => {
            $(
                if let Some(concrete) = any.downcast_ref::<$ty>() {
                    return serde_json::to_value(concrete).map_err(|e| HostError::Protocol {
                        message: format!(
                            "could not serialize a {} payload: {e}",
                            stringify!($ty)
                        ),
                    });
                }
            )+
        };
    }

    try_downcast!(
        MessagePayload,
        ToolPreInvokePayload,
        ToolPostInvokePayload,
        PromptPreFetchPayload,
        PromptPostFetchPayload,
        ResourcePreFetchPayload,
        ResourcePostFetchPayload,
        IdentityResolvePayload,
        TokenDelegatePayload,
    );

    // The generic payload unwraps to its inner value rather than serializing
    // the wrapper, so the worker sees the payload itself.
    if let Some(generic) = any.downcast_ref::<GenericPayload>() {
        return Ok(generic.value.clone());
    }

    Err(HostError::Protocol {
        message: "payload type is not one this host can forward to a Python worker \
                  (expected a CMF message payload, a legacy typed payload, or the generic payload)"
            .into(),
    })
}

/// Rebuild a typed payload from JSON, per the hook's payload kind.
///
/// Used for a `modified_payload` coming back from the worker: it must be
/// re-erased as the *same* concrete type the executor expects for the hook, or
/// a downstream downcast fails and the modification is dropped.
pub fn deserialize_payload(
    hook_name: &str,
    value: Value,
) -> Result<Box<dyn PluginPayload>, HostError> {
    fn parse<T>(value: Value, hook_name: &str) -> Result<Box<dyn PluginPayload>, HostError>
    where
        T: PluginPayload + serde::de::DeserializeOwned,
    {
        serde_json::from_value::<T>(value)
            .map(|p| Box::new(p) as Box<dyn PluginPayload>)
            .map_err(|e| HostError::Protocol {
                message: format!("worker returned a modified payload that does not match hook '{hook_name}': {e}"),
            })
    }

    match payload_kind_for_hook(hook_name) {
        PayloadKind::CmfMessage => parse::<MessagePayload>(value, hook_name),
        PayloadKind::ToolPreInvoke => parse::<ToolPreInvokePayload>(value, hook_name),
        PayloadKind::ToolPostInvoke => parse::<ToolPostInvokePayload>(value, hook_name),
        PayloadKind::PromptPreFetch => parse::<PromptPreFetchPayload>(value, hook_name),
        PayloadKind::PromptPostFetch => parse::<PromptPostFetchPayload>(value, hook_name),
        PayloadKind::ResourcePreFetch => parse::<ResourcePreFetchPayload>(value, hook_name),
        PayloadKind::ResourcePostFetch => parse::<ResourcePostFetchPayload>(value, hook_name),
        PayloadKind::IdentityResolve => parse::<IdentityResolvePayload>(value, hook_name),
        PayloadKind::TokenDelegate => parse::<TokenDelegatePayload>(value, hook_name),
        PayloadKind::Generic => Ok(Box::new(GenericPayload { value })),
    }
}

/// Convert a worker response into the erased result the executor consumes.
///
/// Preserves all four decision-bearing fields: whether processing continues,
/// any violation, a modified payload, and modified extensions. A response
/// missing `continue_processing` defaults to `true`, matching
/// `PluginResult`'s Pydantic default — a plugin that returns nothing means
/// "allow", not "deny".
///
/// `inbound` is the capability-filtered view this plugin was dispatched with.
/// The returned-extensions path needs it to reuse the original `Arc`s for
/// immutable slots and to read the write tokens the executor issued — see the
/// `extensions` module for why both are load-bearing.
pub fn response_to_result(
    hook_name: &str,
    response: Value,
    inbound: &cpex_core::extensions::Extensions,
) -> Result<ErasedResultFields, HostError> {
    let continue_processing = response
        .get("continue_processing")
        .and_then(Value::as_bool)
        .unwrap_or(true);

    let violation = match response.get("violation") {
        Some(Value::Null) | None => None,
        Some(raw) => Some(parse_violation(raw.clone())?),
    };

    let modified_payload = match response.get("modified_payload") {
        Some(Value::Null) | None => None,
        Some(raw) => Some(deserialize_payload(hook_name, raw.clone())?),
    };

    let modified_extensions = match response.get(crate::extensions::MODIFIED_EXTENSIONS_FIELD) {
        Some(Value::Null) | None => None,
        Some(raw) => crate::extensions::owned_from_returned_slot(raw, inbound)?,
    };

    Ok(ErasedResultFields {
        continue_processing,
        modified_payload,
        modified_extensions,
        violation,
    })
}

/// Parse a violation, tolerating the Python model's extra fields.
///
/// The Python `PluginViolation` carries `mcp_error_code` and
/// `http_status_code`, which the Rust type does not model — so a strict
/// `from_value` into the Rust struct is not used. `reason` and `code` are
/// pulled out explicitly and defaulted, because a deny with an empty reason is
/// still a deny and must not be downgraded into an error.
fn parse_violation(raw: Value) -> Result<PluginViolation, HostError> {
    let obj = raw.as_object().ok_or_else(|| HostError::Protocol {
        message: "worker returned a violation that is not a JSON object".into(),
    })?;

    let code = obj.get("code").and_then(Value::as_str).unwrap_or_default();
    let reason = obj
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or_default();

    let mut violation = PluginViolation::new(code, reason);
    violation.description = obj
        .get("description")
        .and_then(Value::as_str)
        .map(str::to_string);

    if let Some(details) = obj.get("details").and_then(Value::as_object) {
        violation.details = details.clone().into_iter().collect();
    }

    // The Python side names this `mcp_error_code`; the Rust side calls the same
    // concept `proto_error_code`.
    violation.proto_error_code = obj
        .get("mcp_error_code")
        .or_else(|| obj.get("proto_error_code"))
        .and_then(Value::as_i64);

    Ok(violation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Inbound view for the response-conversion tests.
    ///
    /// Empty by default: these tests exercise response parsing, not the
    /// capability-filtered delivery path, and an empty view carries no write
    /// tokens — so a gated slot in a response is dropped rather than applied.
    /// `extensions::tests` and `tests/extensions_merge_e2e.rs` cover the
    /// token-bearing cases.
    fn no_inbound() -> cpex_core::extensions::Extensions {
        cpex_core::extensions::Extensions::default()
    }

    // --- hook name resolution -----------------------------------------------

    #[test]
    fn cmf_hooks_route_to_the_message_payload() {
        // The CMF-parity acceptance example. `cmf.tool_pre_invoke` contains the
        // legacy name as a substring, so a match that checked the suffix or
        // used `contains` would mis-route it to the tool payload.
        assert_eq!(
            payload_kind_for_hook("cmf.tool_pre_invoke"),
            PayloadKind::CmfMessage
        );
        assert_eq!(
            payload_kind_for_hook("cmf.llm_input"),
            PayloadKind::CmfMessage
        );
        assert_eq!(
            payload_kind_for_hook("cmf.some_future_hook"),
            PayloadKind::CmfMessage,
            "any cmf.* name is a message payload, even one this host predates"
        );
    }

    #[test]
    fn every_legacy_hook_resolves_to_its_own_typed_payload() {
        let expected = [
            ("tool_pre_invoke", PayloadKind::ToolPreInvoke),
            ("tool_post_invoke", PayloadKind::ToolPostInvoke),
            ("prompt_pre_fetch", PayloadKind::PromptPreFetch),
            ("prompt_post_fetch", PayloadKind::PromptPostFetch),
            ("resource_pre_fetch", PayloadKind::ResourcePreFetch),
            ("resource_post_fetch", PayloadKind::ResourcePostFetch),
            ("identity_resolve", PayloadKind::IdentityResolve),
            ("token_delegate", PayloadKind::TokenDelegate),
        ];

        for (hook, kind) in expected {
            assert_eq!(
                payload_kind_for_hook(hook),
                kind,
                "hook '{hook}' resolved wrongly"
            );
        }

        // All eight are distinct — a copy-paste in the match arms would show up
        // here rather than as a wrong payload at runtime.
        let kinds: std::collections::HashSet<_> =
            expected.iter().map(|(_, k)| format!("{k:?}")).collect();
        assert_eq!(
            kinds.len(),
            8,
            "each legacy hook needs its own payload kind"
        );
    }

    #[test]
    fn an_unknown_hook_name_falls_back_to_the_generic_payload() {
        assert_eq!(
            payload_kind_for_hook("some_custom_hook"),
            PayloadKind::Generic
        );
        assert_eq!(payload_kind_for_hook(""), PayloadKind::Generic);
    }

    #[test]
    fn only_identity_and_delegation_are_credential_hooks() {
        assert!(is_credential_hook("identity_resolve"));
        assert!(is_credential_hook("token_delegate"));

        for hook in [
            "tool_pre_invoke",
            "tool_post_invoke",
            "prompt_pre_fetch",
            "resource_pre_fetch",
            "cmf.tool_pre_invoke",
            "unknown",
        ] {
            assert!(
                !is_credential_hook(hook),
                "'{hook}' must not receive credentials"
            );
        }
    }

    // --- outbound serialization ---------------------------------------------

    #[test]
    fn a_tool_pre_invoke_payload_serializes_to_the_worker_field_shape() {
        let payload = ToolPreInvokePayload {
            name: "search".into(),
            args: Some(HashMap::from([("q".into(), serde_json::json!("rust"))])),
            headers: Some(HashMap::from([("X-Tenant".into(), "acme".into())])),
        };

        let json = serialize_payload(&payload).expect("serializes");
        assert_eq!(json["name"], "search");
        assert_eq!(json["args"]["q"], "rust");
        assert_eq!(json["headers"]["X-Tenant"], "acme");
    }

    #[test]
    fn the_generic_payload_serializes_to_its_inner_value() {
        // Not to `{"value": ...}` — the worker expects the payload itself.
        let payload = GenericPayload {
            value: serde_json::json!({"anything": [1, 2, 3]}),
        };
        let json = serialize_payload(&payload).expect("serializes");
        assert_eq!(json["anything"][2], 3);
        assert!(
            json.get("value").is_none(),
            "the wrapper must not appear on the wire"
        );
    }

    #[test]
    fn a_cmf_message_payload_serializes_as_itself() {
        use cpex_core::cmf::{Message, Role};

        let payload = MessagePayload {
            message: Message::text(Role::User, "what is the weather?"),
        };
        let json = serialize_payload(&payload).expect("serializes");
        assert_eq!(json["message"]["role"], "user");
    }

    #[test]
    fn an_unforwardable_payload_type_errors_rather_than_sending_null() {
        #[derive(Debug, Clone)]
        struct ForeignPayload;
        cpex_core::impl_plugin_payload!(ForeignPayload);

        let err =
            serialize_payload(&ForeignPayload).expect_err("an unknown type cannot be forwarded");
        assert!(matches!(err, HostError::Protocol { .. }), "got {err:?}");
    }

    // --- inbound deserialization -------------------------------------------

    #[test]
    fn a_modified_payload_deserializes_into_the_hooks_typed_payload() {
        let boxed =
            deserialize_payload("tool_pre_invoke", serde_json::json!({ "name": "redacted" }))
                .expect("parses");
        let typed = boxed
            .as_any()
            .downcast_ref::<ToolPreInvokePayload>()
            .expect("must come back as the tool payload, or the executor's downcast fails");
        assert_eq!(typed.name, "redacted");
    }

    #[test]
    fn a_cmf_modified_payload_deserializes_as_a_message_payload() {
        use cpex_core::cmf::{Message, Role};

        // Round-tripped through the real type so the JSON matches the CMF
        // schema rather than a hand-guessed shape.
        let original = MessagePayload {
            message: Message::text(Role::Assistant, "redacted"),
        };
        let json = serde_json::to_value(&original).unwrap();

        let boxed = deserialize_payload("cmf.tool_pre_invoke", json).expect("parses");
        let typed = boxed
            .as_any()
            .downcast_ref::<MessagePayload>()
            .expect("a cmf hook's modified payload must come back as a MessagePayload");
        assert_eq!(typed.message.role, Role::Assistant);
    }

    #[test]
    fn an_unknown_hooks_modified_payload_becomes_a_generic_payload() {
        let boxed =
            deserialize_payload("mystery_hook", serde_json::json!({"x": 1})).expect("parses");
        let generic = boxed
            .as_any()
            .downcast_ref::<GenericPayload>()
            .expect("generic");
        assert_eq!(generic.value["x"], 1);
    }

    #[test]
    fn a_mismatched_modified_payload_errors_and_names_the_hook() {
        // `name` is required on the tool payload; omitting it must not silently
        // yield a default-constructed payload.
        let err = deserialize_payload("tool_pre_invoke", serde_json::json!({ "unexpected": true }))
            .expect_err("a payload missing required fields must be rejected");
        assert!(err.to_string().contains("tool_pre_invoke"), "{err}");
    }

    // --- response to result --------------------------------------------------

    #[test]
    fn an_allow_response_becomes_an_allow_result() {
        let fields = response_to_result(
            "tool_pre_invoke",
            serde_json::json!({ "continue_processing": true }),
            &no_inbound(),
        )
        .expect("converts");

        assert!(fields.continue_processing);
        assert!(fields.violation.is_none());
        assert!(fields.modified_payload.is_none());
        assert!(fields.modified_extensions.is_none());
    }

    #[test]
    fn a_response_without_continue_processing_defaults_to_allow() {
        // Matches PluginResult's Pydantic default. Defaulting to deny would
        // block traffic on any plugin that returns a bare result.
        let fields = response_to_result("tool_pre_invoke", serde_json::json!({}), &no_inbound())
            .expect("converts");
        assert!(fields.continue_processing);
    }

    #[test]
    fn a_deny_response_carries_its_violation() {
        let fields = response_to_result(
            "tool_pre_invoke",
            serde_json::json!({
                "continue_processing": false,
                "violation": {
                    "code": "PII_DETECTED",
                    "reason": "email address in args",
                    "description": "matched the email pattern",
                    "details": {"field": "q"},
                    "mcp_error_code": -32603
                }
            }),
            &no_inbound(),
        )
        .expect("converts");

        assert!(!fields.continue_processing);
        let violation = fields.violation.expect("a deny must carry its violation");
        assert_eq!(violation.code, "PII_DETECTED");
        assert_eq!(violation.reason, "email address in args");
        assert_eq!(
            violation.description.as_deref(),
            Some("matched the email pattern")
        );
        assert_eq!(violation.details["field"], "q");
        assert_eq!(
            violation.proto_error_code,
            Some(-32603),
            "the Python mcp_error_code maps onto the Rust proto_error_code"
        );
    }

    #[test]
    fn a_violation_with_only_a_reason_still_denies() {
        // Tolerance matters here: a partially-populated violation must not be
        // converted into a host error, which would turn a deny into a
        // policy-dependent failure.
        let fields = response_to_result(
            "tool_pre_invoke",
            serde_json::json!({ "continue_processing": false, "violation": { "reason": "nope" } }),
            &no_inbound(),
        )
        .expect("a sparse violation is still a violation");

        assert!(!fields.continue_processing);
        let violation = fields.violation.unwrap();
        assert_eq!(violation.reason, "nope");
        assert_eq!(violation.code, "");
    }

    #[test]
    fn a_modified_payload_survives_the_round_trip() {
        let fields = response_to_result(
            "tool_pre_invoke",
            serde_json::json!({
                "continue_processing": true,
                "modified_payload": { "name": "search", "args": {"q": "[REDACTED]"} }
            }),
            &no_inbound(),
        )
        .expect("converts");

        let payload = fields
            .modified_payload
            .expect("the modification must survive");
        let typed = payload
            .as_any()
            .downcast_ref::<ToolPreInvokePayload>()
            .unwrap();
        assert_eq!(typed.args.as_ref().unwrap()["q"], "[REDACTED]");
    }

    #[test]
    fn modified_extensions_survive_the_round_trip() {
        let fields = response_to_result(
            "tool_pre_invoke",
            serde_json::json!({
                "continue_processing": true,
                "modified_extensions": { "custom": { "seen_by": "py-plugin" } }
            }),
            &no_inbound(),
        )
        .expect("converts");

        let extensions = fields.modified_extensions.expect("extensions must survive");
        assert_eq!(
            extensions.custom.expect("custom slot")["seen_by"],
            "py-plugin"
        );
    }

    #[test]
    fn a_gated_slot_write_without_the_capability_is_dropped() {
        // `http`, `security`, and `delegation` writes are gated by a WriteToken
        // the *executor* mints from the plugin's declared capabilities and
        // carries on the inbound view. An empty inbound view means no token was
        // issued, so the write is dropped rather than applied — the host cannot
        // mint a token and must not honor an unauthorized write.
        //
        // This used to be a hard error, back when the host had no inbound view
        // to consult and so could not tell an authorized write from an
        // unauthorized one. It can now, so the tier is enforced instead of
        // refused. `extensions::tests` covers the drop at slot granularity.
        for slot in ["http", "security", "delegation"] {
            let fields = response_to_result(
                "tool_pre_invoke",
                serde_json::json!({
                    "continue_processing": true,
                    "modified_extensions": { slot: {"labels": ["PII"]} }
                }),
                &no_inbound(),
            )
            .expect("an unauthorized gated write is dropped, not a protocol error");

            assert!(
                fields.modified_extensions.is_none(),
                "the '{slot}' write had no token behind it, so nothing should merge"
            );
        }
    }

    #[test]
    fn an_extensions_object_with_only_gated_nulls_is_no_modification() {
        // Pydantic emits unset Optionals as null, so a plugin that touched
        // nothing still sends every key. That must not read as an attempted
        // gated write.
        let fields = response_to_result(
            "tool_pre_invoke",
            serde_json::json!({
                "continue_processing": true,
                "modified_extensions": { "http": null, "security": null, "custom": null }
            }),
            &no_inbound(),
        )
        .expect("all-null slots are not a write");
        assert!(fields.modified_extensions.is_none());
    }

    #[test]
    fn explicit_nulls_are_treated_as_absent() {
        // Pydantic serializes unset Optionals as null, so null and absent must
        // behave identically or every allow response would try to parse a
        // null payload.
        let fields = response_to_result(
            "tool_pre_invoke",
            serde_json::json!({
                "continue_processing": true,
                "modified_payload": null,
                "modified_extensions": null,
                "violation": null
            }),
            &no_inbound(),
        )
        .expect("nulls are absent, not malformed");

        assert!(fields.modified_payload.is_none());
        assert!(fields.modified_extensions.is_none());
        assert!(fields.violation.is_none());
    }

    #[test]
    fn a_malformed_modified_payload_surfaces_as_a_protocol_error() {
        let Err(err) = response_to_result(
            "tool_pre_invoke",
            serde_json::json!({ "continue_processing": true, "modified_payload": "not an object" }),
            &no_inbound(),
        ) else {
            panic!("a payload that cannot be rebuilt must not be silently dropped");
        };
        assert!(matches!(err, HostError::Protocol { .. }), "got {err:?}");
    }
}
