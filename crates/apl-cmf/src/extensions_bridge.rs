// Location: ./crates/apl-cmf/src/extensions_bridge.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Unified entry point: take an `Extensions` container, dispatch each
// present slot to its per-extension extractor.
//
// This is the function `apl-cpex` will call at hook time after assembling
// `Extensions` from the request. It guarantees every slot that's present
// gets bridged, so a new extension type that adds an extractor module
// shows up in the bag automatically.

use apl_core::AttributeBag;
use cpex_core::extensions::Extensions;

use crate::{
    agent::extract_agent, completion::extract_completion, custom::extract_custom,
    delegation::extract_delegation, framework::extract_framework, http::extract_http,
    llm::extract_llm, mcp::extract_mcp, meta::extract_meta, provenance::extract_provenance,
    request::extract_request, security::extract_security,
};

/// Flatten every present slot in `Extensions` into `bag`.
pub fn extract_extensions(ext: &Extensions, bag: &mut AttributeBag) {
    if let Some(v) = &ext.security {
        extract_security(v, bag);
    }
    if let Some(v) = &ext.delegation {
        extract_delegation(v, bag);
    }
    if let Some(v) = &ext.agent {
        extract_agent(v, bag);
    }
    if let Some(v) = &ext.meta {
        extract_meta(v, bag);
    }
    if let Some(v) = &ext.request {
        extract_request(v, bag);
    }
    if let Some(v) = &ext.http {
        extract_http(v, bag);
    }
    if let Some(v) = &ext.llm {
        extract_llm(v, bag);
    }
    if let Some(v) = &ext.mcp {
        extract_mcp(v, bag);
    }
    if let Some(v) = &ext.completion {
        extract_completion(v, bag);
    }
    if let Some(v) = &ext.provenance {
        extract_provenance(v, bag);
    }
    if let Some(v) = &ext.framework {
        extract_framework(v, bag);
    }
    if let Some(v) = &ext.custom {
        extract_custom(v, bag);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cpex_core::extensions::{
        AgentExtension, DelegationExtension, LLMExtension, MetaExtension, SecurityExtension,
        SubjectExtension,
    };
    use std::collections::HashSet;
    use std::sync::Arc;

    #[test]
    fn dispatches_every_present_slot() {
        let mut ext = Extensions::default();
        ext.security = Some(Arc::new(SecurityExtension {
            subject: Some(SubjectExtension {
                id: Some("alice".into()),
                roles: HashSet::from(["hr".to_string()]),
                ..Default::default()
            }),
            ..Default::default()
        }));
        ext.delegation = Some(Arc::new(DelegationExtension::default()));
        ext.agent = Some(Arc::new(AgentExtension {
            session_id: Some("sess-1".into()),
            ..Default::default()
        }));
        ext.meta = Some(Arc::new(MetaExtension {
            tags: HashSet::from(["pii".to_string()]),
            ..Default::default()
        }));
        ext.llm = Some(Arc::new(LLMExtension {
            model_id: Some("gpt-4".into()),
            ..Default::default()
        }));

        let mut bag = AttributeBag::new();
        extract_extensions(&ext, &mut bag);

        // One assertion per namespace — proves the dispatch reached each.
        assert_eq!(bag.get_string("subject.id"), Some("alice"));
        assert_eq!(bag.get_bool("role.hr"), Some(true));
        assert_eq!(bag.get_int("delegation.depth"), Some(0));
        assert_eq!(bag.get_string("agent.session_id"), Some("sess-1"));
        assert!(bag.set_contains("meta.tags", "pii"));
        assert_eq!(bag.get_string("llm.model_id"), Some("gpt-4"));
    }

    #[test]
    fn absent_slots_skipped_no_panic() {
        let ext = Extensions::default();
        let mut bag = AttributeBag::new();
        extract_extensions(&ext, &mut bag);
        assert!(bag.is_empty());
    }
}
