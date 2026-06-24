// Location: ./crates/apl-cmf/src/custom.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// `Extensions.custom` (HashMap<String, Value>) → AttributeBag.
//
// Open-ended user namespace. Each top-level key becomes `custom.<key>`,
// and nested objects flatten through the same JSON walker as args/result.
// Lets a host stuff arbitrary policy-relevant data into the bag without
// needing a new extension type.
//
// Namespace:
//   custom.<dotted path>   : Bool | Int | Float | String | StringSet

use apl_core::AttributeBag;
use serde_json::Value;
use std::collections::HashMap;

pub fn extract_custom(custom: &HashMap<String, Value>, bag: &mut AttributeBag) {
    for (k, v) in custom {
        crate::payload::walk(v, &format!("custom.{}", k), bag);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn custom_keys_flatten_under_custom_namespace() {
        let mut custom = HashMap::new();
        custom.insert("feature_flag".into(), json!(true));
        custom.insert(
            "tenant".into(),
            json!({ "id": "acme", "tier": "enterprise" }),
        );
        let mut bag = AttributeBag::new();
        extract_custom(&custom, &mut bag);
        assert_eq!(bag.get_bool("custom.feature_flag"), Some(true));
        assert_eq!(bag.get_string("custom.tenant.id"), Some("acme"));
        assert_eq!(bag.get_string("custom.tenant.tier"), Some("enterprise"));
    }
}
