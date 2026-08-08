// Location: ./crates/cpex-hosts-python/src/legacy/payloads.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// Typed payloads for the eight legacy (non-CMF) hooks.
//
// Each struct's serialized JSON must match the Pydantic model `worker.py`
// reconstructs via `json_to_payload`, field for field — a name mismatch
// surfaces as a Pydantic validation error inside the worker, at invoke time,
// far from its cause. The Python model each one mirrors is named in its doc
// comment; the field-shape tests in this module are the guard.
//
// # Redaction
//
// `IdentityResolvePayload` and `TokenDelegatePayload` carry token-adjacent
// fields, so both get a hand-written `Debug` that prints a placeholder instead
// of the value. A derive would put credential material into any `{:?}` — a
// tracing call, an `unwrap()` panic message, an assertion failure. The
// equivalent gap on the pre-existing cpex-core types is deferred follow-up
// work; these new types do not reintroduce it.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Placeholder printed in place of any token-adjacent value.
const REDACTED: &str = "<redacted>";

/// `tool_pre_invoke` — mirrors `ToolPreInvokePayload`.
///
/// `headers` mirrors `HttpHeaderPayload`, which serializes as a plain string
/// map.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolPreInvokePayload {
    pub name: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<HashMap<String, serde_json::Value>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,
}
cpex_core::impl_plugin_payload!(ToolPreInvokePayload);

/// `tool_post_invoke` — mirrors `ToolPostInvokePayload`.
///
/// `result` is `Any` on the Python side, so it stays an untyped JSON value.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolPostInvokePayload {
    pub name: String,

    #[serde(default)]
    pub result: serde_json::Value,
}
cpex_core::impl_plugin_payload!(ToolPostInvokePayload);

/// `prompt_pre_fetch` — mirrors `PromptPrehookPayload`.
///
/// Note `args` is `dict[str, str]` here, not `dict[str, Any]` as on the tool
/// payload.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PromptPreFetchPayload {
    pub prompt_id: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<HashMap<String, String>>,
}
cpex_core::impl_plugin_payload!(PromptPreFetchPayload);

/// `prompt_post_fetch` — mirrors `PromptPosthookPayload`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PromptPostFetchPayload {
    pub prompt_id: String,

    #[serde(default)]
    pub result: serde_json::Value,
}
cpex_core::impl_plugin_payload!(PromptPostFetchPayload);

/// `resource_pre_fetch` — mirrors `ResourcePreFetchPayload`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourcePreFetchPayload {
    pub uri: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}
cpex_core::impl_plugin_payload!(ResourcePreFetchPayload);

/// `resource_post_fetch` — mirrors `ResourcePostFetchPayload`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourcePostFetchPayload {
    pub uri: String,

    #[serde(default)]
    pub content: serde_json::Value,
}
cpex_core::impl_plugin_payload!(ResourcePostFetchPayload);

/// `identity_resolve` — mirrors `IdentityPayload`.
///
/// `raw_token` is `SecretStr` on the Python side and redacts on serialization,
/// so the value that travels in *this* field is a placeholder, never the real
/// token. The plaintext rides the separate capability-gated `credential`
/// object on the task (see the `credentials` module) and the worker folds it
/// back onto the payload before calling the plugin.
///
/// `Debug` is hand-written — see the module docs.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct IdentityResolvePayload {
    /// Redacted on the wire. Populated from the `credential` object by the
    /// worker, not from this field.
    #[serde(default)]
    pub raw_token: String,

    /// How the credential was presented — `bearer`, `custom`, and so on.
    #[serde(default)]
    pub source: String,

    /// Headers the credential arrived in. Not a `SecretStr` on the Python
    /// side, so the worker scrubs the plaintext out of these values before a
    /// plugin can echo them back.
    #[serde(default)]
    pub headers: HashMap<String, String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_host: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_port: Option<u16>,
}
cpex_core::impl_plugin_payload!(IdentityResolvePayload);

impl std::fmt::Debug for IdentityResolvePayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `raw_token` and every header value are redacted: a header can carry
        // the credential ("Authorization: Bearer <token>"), so printing keys
        // alone is the safe maximum.
        f.debug_struct("IdentityResolvePayload")
            .field("raw_token", &REDACTED)
            .field("source", &self.source)
            .field("header_names", &self.headers.keys().collect::<Vec<_>>())
            .field("client_host", &self.client_host)
            .field("client_port", &self.client_port)
            .finish()
    }
}

/// Scope-attenuation config — mirrors `AttenuationConfig`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttenuationConfig {
    #[serde(default)]
    pub capabilities: Vec<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_template: Option<String>,

    #[serde(default)]
    pub actions: Vec<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<i64>,
}

/// `token_delegate` — mirrors `DelegationPayload`.
///
/// `bearer_token` is `SecretStr | None` on the Python side and redacts on
/// serialization, so this field carries a placeholder. The plaintext travels
/// via the `credential` object.
///
/// `Debug` is hand-written — see the module docs.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct TokenDelegatePayload {
    pub target_name: String,

    #[serde(default = "default_target_type")]
    pub target_type: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_audience: Option<String>,

    #[serde(default)]
    pub required_permissions: Vec<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_domain: Option<String>,

    #[serde(default = "default_auth_enforced_by")]
    pub auth_enforced_by: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_attenuation: Option<AttenuationConfig>,

    /// Redacted on the wire; the plaintext comes from the `credential` object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer_token: Option<String>,
}
cpex_core::impl_plugin_payload!(TokenDelegatePayload);

fn default_target_type() -> String {
    "tool".to_string()
}

fn default_auth_enforced_by() -> String {
    "caller".to_string()
}

impl std::fmt::Debug for TokenDelegatePayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenDelegatePayload")
            .field("target_name", &self.target_name)
            .field("target_type", &self.target_type)
            .field("target_audience", &self.target_audience)
            .field("required_permissions", &self.required_permissions)
            .field("trust_domain", &self.trust_domain)
            .field("auth_enforced_by", &self.auth_enforced_by)
            .field("route_attenuation", &self.route_attenuation)
            // Presence is useful for diagnosis; the value never is.
            .field(
                "bearer_token",
                &self.bearer_token.as_ref().map(|_| REDACTED),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialize and return the JSON object, so field names can be asserted
    /// against the Pydantic models `worker.py` reconstructs.
    fn json_of<T: Serialize>(value: &T) -> serde_json::Value {
        serde_json::to_value(value).expect("payload serializes")
    }

    #[test]
    fn tool_pre_invoke_matches_the_python_field_shape() {
        let payload = ToolPreInvokePayload {
            name: "search".into(),
            args: Some(HashMap::from([("q".into(), serde_json::json!("rust"))])),
            headers: Some(HashMap::from([("X-Tenant".into(), "acme".into())])),
        };
        let json = json_of(&payload);

        assert_eq!(json["name"], "search");
        assert_eq!(json["args"]["q"], "rust");
        assert_eq!(json["headers"]["X-Tenant"], "acme");
    }

    #[test]
    fn tool_pre_invoke_omits_absent_optionals() {
        // Pydantic defaults `args` to {} and `headers` to None. Emitting
        // explicit nulls would override those defaults on the Python side, so
        // absent fields must stay absent.
        let json = json_of(&ToolPreInvokePayload {
            name: "search".into(),
            ..Default::default()
        });
        assert_eq!(
            json.as_object().unwrap().len(),
            1,
            "only `name` should be present: {json}"
        );
    }

    #[test]
    fn tool_pre_invoke_round_trips() {
        let payload = ToolPreInvokePayload {
            name: "search".into(),
            args: Some(HashMap::from([("q".into(), serde_json::json!(7))])),
            headers: None,
        };
        let restored: ToolPreInvokePayload = serde_json::from_value(json_of(&payload)).unwrap();
        assert_eq!(restored.name, "search");
        assert_eq!(restored.args.unwrap()["q"], 7);
    }

    #[test]
    fn tool_post_invoke_matches_the_python_field_shape() {
        let json = json_of(&ToolPostInvokePayload {
            name: "search".into(),
            result: serde_json::json!({"hits": 3}),
        });
        assert_eq!(json["name"], "search");
        assert_eq!(json["result"]["hits"], 3);
    }

    #[test]
    fn prompt_payloads_use_prompt_id_not_name() {
        // The prompt hooks key on `prompt_id`; using `name` here would fail
        // Pydantic validation inside the worker.
        let pre = json_of(&PromptPreFetchPayload {
            prompt_id: "greeting".into(),
            args: Some(HashMap::from([("lang".into(), "en".into())])),
        });
        assert_eq!(pre["prompt_id"], "greeting");
        assert_eq!(pre["args"]["lang"], "en");
        assert!(pre.get("name").is_none());

        let post = json_of(&PromptPostFetchPayload {
            prompt_id: "greeting".into(),
            result: serde_json::json!({"messages": []}),
        });
        assert_eq!(post["prompt_id"], "greeting");
        assert!(post["result"]["messages"].is_array());
    }

    #[test]
    fn prompt_pre_fetch_args_are_strings() {
        // dict[str, str] on the Python side, so a non-string value must not
        // deserialize into it.
        let parsed: Result<PromptPreFetchPayload, _> =
            serde_json::from_value(serde_json::json!({ "prompt_id": "p", "args": {"n": 5} }));
        assert!(
            parsed.is_err(),
            "prompt args are dict[str, str], not dict[str, Any]"
        );
    }

    #[test]
    fn resource_payloads_key_on_uri() {
        let pre = json_of(&ResourcePreFetchPayload {
            uri: "file:///tmp/x".into(),
            metadata: Some(HashMap::from([("etag".into(), serde_json::json!("abc"))])),
        });
        assert_eq!(pre["uri"], "file:///tmp/x");
        assert_eq!(pre["metadata"]["etag"], "abc");

        let post = json_of(&ResourcePostFetchPayload {
            uri: "file:///tmp/x".into(),
            content: serde_json::json!("hello"),
        });
        assert_eq!(post["content"], "hello");
    }

    #[test]
    fn identity_resolve_matches_the_python_field_shape() {
        let json = json_of(&IdentityResolvePayload {
            raw_token: "**********".into(),
            source: "bearer".into(),
            headers: HashMap::from([("Authorization".into(), "**********".into())]),
            client_host: Some("10.0.0.1".into()),
            client_port: Some(443),
        });

        assert_eq!(json["source"], "bearer");
        assert_eq!(json["client_host"], "10.0.0.1");
        assert_eq!(json["client_port"], 443);
        assert!(
            json.get("raw_token").is_some(),
            "the field exists; its value is a placeholder"
        );
    }

    #[test]
    fn token_delegate_matches_the_python_field_shape_and_defaults() {
        let parsed: TokenDelegatePayload =
            serde_json::from_value(serde_json::json!({ "target_name": "billing-api" })).unwrap();

        // Pydantic defaults these two; the host must agree or a minimal
        // payload would deserialize with empty strings.
        assert_eq!(parsed.target_type, "tool");
        assert_eq!(parsed.auth_enforced_by, "caller");
        assert!(parsed.required_permissions.is_empty());
        assert!(parsed.bearer_token.is_none());
    }

    #[test]
    fn token_delegate_carries_attenuation_config() {
        let json = json_of(&TokenDelegatePayload {
            target_name: "billing-api".into(),
            route_attenuation: Some(AttenuationConfig {
                capabilities: vec!["read".into()],
                resource_template: Some("/v1/*".into()),
                actions: vec!["GET".into()],
                ttl_seconds: Some(300),
            }),
            ..Default::default()
        });

        assert_eq!(json["route_attenuation"]["capabilities"][0], "read");
        assert_eq!(json["route_attenuation"]["ttl_seconds"], 300);
    }

    // --- redaction ----------------------------------------------------------

    #[test]
    fn identity_resolve_debug_hides_token_and_header_values() {
        let payload = IdentityResolvePayload {
            raw_token: "eyJhbGciOiJSUzI1NiJ9.SECRET-TOKEN-BYTES".into(),
            source: "bearer".into(),
            headers: HashMap::from([("Authorization".into(), "Bearer SECRET-TOKEN-BYTES".into())]),
            client_host: None,
            client_port: None,
        };

        let debug = format!("{payload:?}");
        assert!(
            !debug.contains("SECRET-TOKEN-BYTES"),
            "token material leaked into Debug: {debug}"
        );
        // The header *name* is still useful for diagnosis.
        assert!(debug.contains("Authorization"));
        assert!(
            debug.contains("bearer"),
            "non-secret fields stay readable: {debug}"
        );
    }

    #[test]
    fn token_delegate_debug_hides_the_bearer_token() {
        let payload = TokenDelegatePayload {
            target_name: "billing-api".into(),
            bearer_token: Some("MINTED-SECRET-BYTES".into()),
            ..Default::default()
        };

        let debug = format!("{payload:?}");
        assert!(
            !debug.contains("MINTED-SECRET-BYTES"),
            "delegated token leaked into Debug: {debug}"
        );
        // Presence is diagnosable without exposing the value.
        assert!(debug.contains("billing-api"));
        assert!(debug.contains(REDACTED));
    }

    #[test]
    fn token_delegate_debug_distinguishes_absent_from_present() {
        let absent = format!(
            "{:?}",
            TokenDelegatePayload {
                target_name: "x".into(),
                ..Default::default()
            }
        );
        assert!(
            absent.contains("None"),
            "an absent token should read as None: {absent}"
        );
        assert!(!absent.contains(REDACTED));
    }
}
