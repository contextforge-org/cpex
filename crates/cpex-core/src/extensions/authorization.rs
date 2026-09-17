// Location: ./crates/cpex-core/src/extensions/authorization.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// AuthorizationDetail — RFC 9396 Rich Authorization Requests.
//
// Carried on DelegationHop alongside `scopes_granted`. Each hop can narrow
// the details structurally (drop entries, remove actions, add constraints).
// The narrowing-check helper lives elsewhere (framework enforcement at the
// TokenDelegate boundary).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A single RFC 9396 authorization_details entry.
///
/// `type` is required (renamed `detail_type` here to avoid the Rust
/// keyword). The remaining fields are optional per the RFC. API-specific
/// extension fields are captured in `extra` via serde flatten.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationDetail {
    #[serde(rename = "type")]
    pub detail_type: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locations: Option<Vec<String>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<String>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub datatypes: Option<Vec<String>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privileges: Option<Vec<String>>,

    /// API-specific fields not covered by the named RFC 9396 fields above.
    /// Subsetting checks treat these opaquely (exact equality).
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_roundtrip_with_rfc9396_keyword() {
        let detail = AuthorizationDetail {
            detail_type: "tool_invocation".into(),
            actions: Some(vec!["read".into()]),
            identifier: Some("get_compensation".into()),
            ..Default::default()
        };
        let json = serde_json::to_string(&detail).unwrap();
        // The `type` field on the wire, not `detail_type`.
        assert!(json.contains(r#""type":"tool_invocation""#));
        assert!(!json.contains("detail_type"));

        let back: AuthorizationDetail = serde_json::from_str(&json).unwrap();
        assert_eq!(back, detail);
    }

    #[test]
    fn extra_fields_round_trip() {
        let json = r#"{
            "type": "payment",
            "actions": ["initiate"],
            "amount": "100.00",
            "currency": "USD"
        }"#;
        let detail: AuthorizationDetail = serde_json::from_str(json).unwrap();
        assert_eq!(detail.detail_type, "payment");
        assert_eq!(
            detail.extra.get("amount").and_then(|v| v.as_str()),
            Some("100.00")
        );
        assert_eq!(
            detail.extra.get("currency").and_then(|v| v.as_str()),
            Some("USD")
        );
    }
}
