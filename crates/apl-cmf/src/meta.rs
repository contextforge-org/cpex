// Location: ./crates/apl-cmf/src/meta.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// MetaExtension → AttributeBag.
//
// Namespace:
//   meta.entity_type        : String   ("tool" | "resource" | "prompt" | "llm")
//   meta.entity_name        : String
//   meta.tags               : StringSet     ← used by spec-level tag-driven policy inheritance
//   meta.scope              : String
//   meta.properties.<k>     : String

use apl_core::AttributeBag;
use cpex_core::extensions::MetaExtension;
use std::collections::HashSet;

pub fn extract_meta(meta: &MetaExtension, bag: &mut AttributeBag) {
    if let Some(v) = &meta.entity_type {
        bag.set("meta.entity_type", v.clone());
    }
    if let Some(v) = &meta.entity_name {
        bag.set("meta.entity_name", v.clone());
    }
    if !meta.tags.is_empty() {
        let tags: HashSet<String> = meta.tags.iter().cloned().collect();
        bag.set("meta.tags", tags);
    }
    if let Some(v) = &meta.scope {
        bag.set("meta.scope", v.clone());
    }
    for (k, v) in &meta.properties {
        bag.set(format!("meta.properties.{}", k), v.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn tags_and_properties_flatten() {
        let meta = MetaExtension {
            entity_type: Some("tool".into()),
            entity_name: Some("get_compensation".into()),
            tags: HashSet::from(["pii".to_string(), "sensitive".to_string()]),
            scope: Some("hr".into()),
            properties: HashMap::from([("owner".to_string(), "compliance".to_string())]),
        };
        let mut bag = AttributeBag::new();
        extract_meta(&meta, &mut bag);
        assert_eq!(bag.get_string("meta.entity_type"), Some("tool"));
        assert_eq!(bag.get_string("meta.entity_name"), Some("get_compensation"));
        assert!(bag.set_contains("meta.tags", "pii"));
        assert!(bag.set_contains("meta.tags", "sensitive"));
        assert_eq!(bag.get_string("meta.scope"), Some("hr"));
        assert_eq!(bag.get_string("meta.properties.owner"), Some("compliance"));
    }
}
