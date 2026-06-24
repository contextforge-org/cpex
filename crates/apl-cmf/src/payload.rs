// Location: ./crates/apl-cmf/src/payload.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// JSON args/result payload → AttributeBag.
//
// Leaf scalars at any nesting depth land in the bag under their dotted
// path, prefixed with `args.` or `result.`. Nested objects recurse;
// arrays-of-strings flatten into a StringSet; arrays of mixed/scalar
// types are skipped (no list scalar attribute in the bag).
//
// Examples:
//   args = { "include_ssn": true,
//            "user": { "id": "alice", "roles": ["hr", "manager"] } }
//   →  args.include_ssn      : Bool(true)
//      args.user.id          : String("alice")
//      args.user.roles       : StringSet({"hr", "manager"})
//
// Null values are skipped (consistent with bag's missing-key semantics).

use apl_core::AttributeBag;
use serde_json::Value;
use std::collections::HashSet;

use crate::constants::{BAG_ARGS_PREFIX, BAG_RESULT_PREFIX};

/// Flatten an args object into `args.*` keys.
pub fn extract_args(args: &Value, bag: &mut AttributeBag) {
    // `walk` builds dotted paths itself; strip the trailing `.` from
    // the canonical prefix to match its signature.
    walk(args, BAG_ARGS_PREFIX.trim_end_matches('.'), bag);
}

/// Flatten a result object into `result.*` keys.
pub fn extract_result(result: &Value, bag: &mut AttributeBag) {
    walk(result, BAG_RESULT_PREFIX.trim_end_matches('.'), bag);
}

pub(crate) fn walk(value: &Value, prefix: &str, bag: &mut AttributeBag) {
    match value {
        Value::Object(map) => {
            for (key, sub) in map {
                let dotted = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{}.{}", prefix, key)
                };
                walk(sub, &dotted, bag);
            }
        },
        Value::Array(items) => {
            // Promote string-only arrays to StringSet — supports
            // `args.tags contains "urgent"` predicates.
            let mut all_strings: HashSet<String> = HashSet::new();
            let mut ok = true;
            for item in items {
                if let Some(s) = item.as_str() {
                    all_strings.insert(s.to_string());
                } else {
                    ok = false;
                    break;
                }
            }
            if ok && !all_strings.is_empty() {
                bag.set(prefix, all_strings);
            }
            // Non-string arrays (mixed, numeric, nested): silently skipped
            // — no list scalar in the bag for those.
        },
        Value::String(s) => bag.set(prefix, s.clone()),
        Value::Bool(b) => bag.set(prefix, *b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                bag.set(prefix, i);
            } else if let Some(f) = n.as_f64() {
                bag.set(prefix, f);
            }
        },
        Value::Null => {}, // Skip — equivalent to "key not present."
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn args_scalars_at_top_level() {
        let args = json!({ "include_ssn": true, "amount": 100, "name": "alice" });
        let mut bag = AttributeBag::new();
        extract_args(&args, &mut bag);
        assert_eq!(bag.get_bool("args.include_ssn"), Some(true));
        assert_eq!(bag.get_int("args.amount"), Some(100));
        assert_eq!(bag.get_string("args.name"), Some("alice"));
    }

    #[test]
    fn args_nested_objects_dotted() {
        let args = json!({ "user": { "id": "alice", "profile": { "tier": "gold" } } });
        let mut bag = AttributeBag::new();
        extract_args(&args, &mut bag);
        assert_eq!(bag.get_string("args.user.id"), Some("alice"));
        assert_eq!(bag.get_string("args.user.profile.tier"), Some("gold"));
    }

    #[test]
    fn args_string_array_becomes_string_set() {
        let args = json!({ "tags": ["urgent", "audit"] });
        let mut bag = AttributeBag::new();
        extract_args(&args, &mut bag);
        assert!(bag.set_contains("args.tags", "urgent"));
        assert!(bag.set_contains("args.tags", "audit"));
        assert!(!bag.set_contains("args.tags", "missing"));
    }

    #[test]
    fn args_mixed_array_is_skipped() {
        let args = json!({ "mixed": ["a", 1, true] });
        let mut bag = AttributeBag::new();
        extract_args(&args, &mut bag);
        // No `args.mixed` key — type didn't unify, so we dropped it.
        assert!(!bag.contains("args.mixed"));
    }

    #[test]
    fn args_null_is_treated_as_missing() {
        let args = json!({ "maybe": null, "yes": true });
        let mut bag = AttributeBag::new();
        extract_args(&args, &mut bag);
        assert!(!bag.contains("args.maybe"));
        assert_eq!(bag.get_bool("args.yes"), Some(true));
    }

    #[test]
    fn result_uses_result_prefix() {
        let result = json!({ "ssn": "123-45-6789", "salary": 50000 });
        let mut bag = AttributeBag::new();
        extract_result(&result, &mut bag);
        assert_eq!(bag.get_string("result.ssn"), Some("123-45-6789"));
        assert_eq!(bag.get_int("result.salary"), Some(50000));
        // No args.* keys collected.
        assert!(!bag.contains("args.ssn"));
    }

    #[test]
    fn float_numbers_land_as_float() {
        let args = json!({ "score": 0.92 });
        let mut bag = AttributeBag::new();
        extract_args(&args, &mut bag);
        assert_eq!(bag.get_float("args.score"), Some(0.92));
    }
}
