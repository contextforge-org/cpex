// Location: ./crates/apl-cmf/src/llm.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// LLMExtension → AttributeBag.
//
// Namespace:
//   llm.model_id        : String
//   llm.provider        : String
//   llm.capabilities    : StringSet

use apl_core::AttributeBag;
use cpex_core::extensions::LLMExtension;
use std::collections::HashSet;

pub fn extract_llm(llm: &LLMExtension, bag: &mut AttributeBag) {
    if let Some(v) = &llm.model_id { bag.set("llm.model_id", v.clone()); }
    if let Some(v) = &llm.provider { bag.set("llm.provider", v.clone()); }
    if !llm.capabilities.is_empty() {
        let caps: HashSet<String> = llm.capabilities.iter().cloned().collect();
        bag.set("llm.capabilities", caps);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_model_and_capabilities() {
        let llm = LLMExtension {
            model_id: Some("gpt-4".into()),
            provider: Some("openai".into()),
            capabilities: vec!["tool_use".into(), "vision".into()],
        };
        let mut bag = AttributeBag::new();
        extract_llm(&llm, &mut bag);
        assert_eq!(bag.get_string("llm.model_id"), Some("gpt-4"));
        assert_eq!(bag.get_string("llm.provider"), Some("openai"));
        assert!(bag.set_contains("llm.capabilities", "tool_use"));
        assert!(bag.set_contains("llm.capabilities", "vision"));
    }
}
