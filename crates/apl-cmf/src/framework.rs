// Location: ./crates/apl-cmf/src/framework.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// FrameworkExtension → AttributeBag.
//
// Namespace:
//   framework.framework            : String  ("langchain", "crewai", ...)
//   framework.framework_version    : String
//   framework.node_id              : String
//   framework.graph_id             : String
//   framework.metadata.<dotted>    : various (JSON walker — same as args)

use apl_core::AttributeBag;
use cpex_core::extensions::FrameworkExtension;

pub fn extract_framework(f: &FrameworkExtension, bag: &mut AttributeBag) {
    if let Some(v) = &f.framework { bag.set("framework.framework", v.clone()); }
    if let Some(v) = &f.framework_version { bag.set("framework.framework_version", v.clone()); }
    if let Some(v) = &f.node_id { bag.set("framework.node_id", v.clone()); }
    if let Some(v) = &f.graph_id { bag.set("framework.graph_id", v.clone()); }
    // metadata is a HashMap<String, Value> — flatten the same way args/result do.
    for (k, v) in &f.metadata {
        crate::payload::walk(v, &format!("framework.metadata.{}", k), bag);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;

    #[test]
    fn nested_metadata_flattens() {
        let f = FrameworkExtension {
            framework: Some("langchain".into()),
            framework_version: Some("0.1.42".into()),
            node_id: Some("retriever".into()),
            metadata: HashMap::from([
                ("chain_id".to_string(), json!("abc")),
                ("step".to_string(), json!(7)),
                ("flags".to_string(), json!({ "verbose": true })),
            ]),
            ..Default::default()
        };
        let mut bag = AttributeBag::new();
        extract_framework(&f, &mut bag);
        assert_eq!(bag.get_string("framework.framework"), Some("langchain"));
        assert_eq!(bag.get_string("framework.metadata.chain_id"), Some("abc"));
        assert_eq!(bag.get_int("framework.metadata.step"), Some(7));
        assert_eq!(bag.get_bool("framework.metadata.flags.verbose"), Some(true));
    }
}
