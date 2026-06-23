// Location: ./crates/cpex-hosts-python/src/isolated/payload.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// Payload serialization registry.
//
// PluginPayload has no Serialize bound (object-safe by design). This
// module provides a HookPayloadRegistry that maps hook type names to
// (serialize_fn, deserialize_fn) shim pairs. Each shim downcasts the
// trait object to the concrete type before calling serde_json.
//
// Unknown hook names fall back to GenericPayload which wraps a raw
// serde_json::Value and passes it through unmodified.

use std::collections::HashMap;

use cpex_core::{
    cmf::{
        MessagePayload,
        constants::{
            HOOK_CMF_LLM_INPUT, HOOK_CMF_LLM_OUTPUT, HOOK_CMF_PROMPT_POST_INVOKE,
            HOOK_CMF_PROMPT_PRE_INVOKE, HOOK_CMF_RESOURCE_POST_FETCH, HOOK_CMF_RESOURCE_PRE_FETCH,
            HOOK_CMF_TOOL_POST_INVOKE, HOOK_CMF_TOOL_PRE_INVOKE,
        },
    },
    delegation::{DelegationPayload, HOOK_TOKEN_DELEGATE},
    error::{PluginError, PluginViolation},
    executor::ErasedResultFields,
    hooks::payload::PluginPayload,
    identity::{IdentityPayload, HOOK_IDENTITY_RESOLVE},
};

// ---------------------------------------------------------------------------
// Type aliases for shim function pointers
// ---------------------------------------------------------------------------

pub type SerializeFn = fn(&dyn PluginPayload) -> Result<serde_json::Value, serde_json::Error>;
pub type DeserializeFn = fn(serde_json::Value) -> Result<Box<dyn PluginPayload>, serde_json::Error>;

// ---------------------------------------------------------------------------
// GenericPayload — fallback for unknown hook names
// ---------------------------------------------------------------------------

/// Opaque payload that carries raw JSON across the Python boundary.
/// Used when no concrete type is registered for a hook name.
#[derive(Debug, Clone)]
pub struct GenericPayload(pub serde_json::Value);

cpex_core::impl_plugin_payload!(GenericPayload);

// ---------------------------------------------------------------------------
// HookPayloadRegistry
// ---------------------------------------------------------------------------

/// Maps hook type names to (serialize, deserialize) shim pairs.
pub struct HookPayloadRegistry {
    serialize: HashMap<&'static str, SerializeFn>,
    deserialize: HashMap<&'static str, DeserializeFn>,
}

impl HookPayloadRegistry {
    /// Empty registry. Use `default()` for a registry pre-populated with
    /// all built-in cpex-core payload types.
    pub fn empty() -> Self {
        Self {
            serialize: HashMap::new(),
            deserialize: HashMap::new(),
        }
    }

    /// Register a (serialize, deserialize) shim pair for a hook type name.
    pub fn register(
        &mut self,
        hook_name: &'static str,
        ser: SerializeFn,
        de: DeserializeFn,
    ) {
        self.serialize.insert(hook_name, ser);
        self.deserialize.insert(hook_name, de);
    }

    /// Serialize a payload trait object to JSON.
    /// Falls back to `serde_json::Value::Null` for unknown hook names
    /// (should not happen if the registry is fully populated).
    pub fn payload_to_json(
        &self,
        hook_name: &str,
        payload: &dyn PluginPayload,
    ) -> Result<serde_json::Value, serde_json::Error> {
        match self.serialize.get(hook_name) {
            Some(f) => f(payload),
            None => {
                // Unknown — try to downcast to GenericPayload and return its inner Value.
                if let Some(g) = payload.as_any().downcast_ref::<GenericPayload>() {
                    Ok(g.0.clone())
                } else {
                    Ok(serde_json::Value::Null)
                }
            }
        }
    }

    /// Deserialize a JSON value to a concrete payload type, or GenericPayload.
    pub fn json_to_payload(
        &self,
        hook_name: &str,
        value: serde_json::Value,
    ) -> Result<Box<dyn PluginPayload>, serde_json::Error> {
        match self.deserialize.get(hook_name) {
            Some(f) => f(value),
            None => Ok(Box::new(GenericPayload(value))),
        }
    }

    /// Convert a worker JSON response into ErasedResultFields.
    ///
    /// Worker response schema:
    ///   {
    ///     "continue_processing": bool,
    ///     "violation": {code, reason, ...} | null,
    ///     "modified_payload": {...} | null,
    ///     "request_id": "...",      ← present but ignored here (stripped by caller)
    ///   }
    pub fn json_to_erased(
        &self,
        hook_name: &str,
        response: serde_json::Value,
    ) -> Result<ErasedResultFields, Box<PluginError>> {
        let continue_processing = response
            .get("continue_processing")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let violation: Option<PluginViolation> = response
            .get("violation")
            .filter(|v| !v.is_null())
            .and_then(|v| serde_json::from_value(v.clone()).ok());

        let modified_payload: Option<Box<dyn PluginPayload>> = response
            .get("modified_payload")
            .filter(|v| !v.is_null())
            .map(|v| {
                self.json_to_payload(hook_name, v.clone())
                    .map_err(|e| Box::new(PluginError::Config { message: e.to_string() }))
            })
            .transpose()?;

        Ok(ErasedResultFields {
            continue_processing,
            modified_payload,
            modified_extensions: None,
            violation,
        })
    }
}

impl Default for HookPayloadRegistry {
    /// Pre-populate with all built-in cpex-core payload types.
    fn default() -> Self {
        let mut r = Self::empty();

        // CMF hooks — all use MessagePayload
        for name in &[
            HOOK_CMF_TOOL_PRE_INVOKE,
            HOOK_CMF_TOOL_POST_INVOKE,
            HOOK_CMF_LLM_INPUT,
            HOOK_CMF_LLM_OUTPUT,
            HOOK_CMF_PROMPT_PRE_INVOKE,
            HOOK_CMF_PROMPT_POST_INVOKE,
            HOOK_CMF_RESOURCE_PRE_FETCH,
            HOOK_CMF_RESOURCE_POST_FETCH,
        ] {
            r.register(name, serialize_message_payload, deserialize_message_payload);
        }

        r.register(
            HOOK_IDENTITY_RESOLVE,
            serialize_identity_payload,
            deserialize_identity_payload,
        );
        r.register(
            HOOK_TOKEN_DELEGATE,
            serialize_delegation_payload,
            deserialize_delegation_payload,
        );

        r
    }
}

// ---------------------------------------------------------------------------
// Shim functions — one pair per concrete payload type
// ---------------------------------------------------------------------------

fn serialize_message_payload(p: &dyn PluginPayload) -> Result<serde_json::Value, serde_json::Error> {
    let concrete = p
        .as_any()
        .downcast_ref::<MessagePayload>()
        .expect("serialize_message_payload: downcast failed — handler registered wrong type");
    serde_json::to_value(concrete)
}

fn deserialize_message_payload(v: serde_json::Value) -> Result<Box<dyn PluginPayload>, serde_json::Error> {
    Ok(Box::new(serde_json::from_value::<MessagePayload>(v)?))
}

fn serialize_identity_payload(p: &dyn PluginPayload) -> Result<serde_json::Value, serde_json::Error> {
    let concrete = p
        .as_any()
        .downcast_ref::<IdentityPayload>()
        .expect("serialize_identity_payload: downcast failed");
    serde_json::to_value(concrete)
}

fn deserialize_identity_payload(v: serde_json::Value) -> Result<Box<dyn PluginPayload>, serde_json::Error> {
    Ok(Box::new(serde_json::from_value::<IdentityPayload>(v)?))
}

fn serialize_delegation_payload(p: &dyn PluginPayload) -> Result<serde_json::Value, serde_json::Error> {
    let concrete = p
        .as_any()
        .downcast_ref::<DelegationPayload>()
        .expect("serialize_delegation_payload: downcast failed");
    serde_json::to_value(concrete)
}

fn deserialize_delegation_payload(v: serde_json::Value) -> Result<Box<dyn PluginPayload>, serde_json::Error> {
    Ok(Box::new(serde_json::from_value::<DelegationPayload>(v)?))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use cpex_core::cmf::{Message, MessagePayload, enums::Role};

    fn make_registry() -> HookPayloadRegistry {
        HookPayloadRegistry::default()
    }

    fn msg_payload() -> MessagePayload {
        MessagePayload {
            message: Message::text(Role::User, "hello"),
        }
    }

    #[test]
    fn payload_to_json_message_payload() {
        let r = make_registry();
        let p: Box<dyn PluginPayload> = Box::new(msg_payload());
        let v = r.payload_to_json(HOOK_CMF_TOOL_PRE_INVOKE, p.as_ref()).unwrap();
        assert!(v.is_object());
        assert!(v.get("message").is_some());
    }

    #[test]
    fn json_to_erased_allow() {
        let r = make_registry();
        let resp = serde_json::json!({
            "continue_processing": true,
            "violation": null,
            "modified_payload": null,
            "request_id": "test-123"
        });
        let erased = r.json_to_erased(HOOK_CMF_TOOL_PRE_INVOKE, resp).unwrap();
        assert!(erased.continue_processing);
        assert!(erased.violation.is_none());
        assert!(erased.modified_payload.is_none());
    }

    #[test]
    fn json_to_erased_deny_with_violation() {
        let r = make_registry();
        let resp = serde_json::json!({
            "continue_processing": false,
            "violation": {"code": "pii.found", "reason": "PII detected", "description": null, "details": {}, "plugin_name": null},
            "modified_payload": null,
            "request_id": "test-456"
        });
        let erased = r.json_to_erased(HOOK_CMF_TOOL_PRE_INVOKE, resp).unwrap();
        assert!(!erased.continue_processing);
        let v = erased.violation.unwrap();
        assert_eq!(v.code, "pii.found");
    }

    #[test]
    fn json_to_erased_with_modified_payload() {
        let r = make_registry();
        // ContentPart uses serde tag = "content_type".
        let msg = serde_json::json!({
            "role": "user",
            "content": [{"content_type": "text", "text": "modified"}]
        });
        let resp = serde_json::json!({
            "continue_processing": true,
            "violation": null,
            "modified_payload": {"message": msg},
            "request_id": "test-789"
        });
        let erased = r.json_to_erased(HOOK_CMF_TOOL_PRE_INVOKE, resp).unwrap();
        assert!(erased.continue_processing);
        assert!(erased.modified_payload.is_some());
        // Concrete type should be MessagePayload.
        let mp = erased.modified_payload.unwrap();
        assert!(mp.as_any().downcast_ref::<MessagePayload>().is_some());
    }

    #[test]
    fn json_to_erased_unknown_hook_falls_back_to_generic() {
        let r = make_registry();
        let resp = serde_json::json!({
            "continue_processing": true,
            "violation": null,
            "modified_payload": {"some": "data"},
            "request_id": "test-000"
        });
        let erased = r.json_to_erased("unknown.hook", resp).unwrap();
        assert!(erased.modified_payload.is_some());
        let mp = erased.modified_payload.unwrap();
        assert!(mp.as_any().downcast_ref::<GenericPayload>().is_some());
    }

    #[test]
    fn round_trip_message_payload() {
        let r = make_registry();
        let original = msg_payload();
        let p: &dyn PluginPayload = &original;
        let json = r.payload_to_json(HOOK_CMF_TOOL_PRE_INVOKE, p).unwrap();
        let boxed = r.json_to_payload(HOOK_CMF_TOOL_PRE_INVOKE, json).unwrap();
        let roundtripped = boxed.as_any().downcast_ref::<MessagePayload>().unwrap();
        // Content should survive the round-trip.
        assert_eq!(
            format!("{:?}", original.message),
            format!("{:?}", roundtripped.message),
        );
    }
}
