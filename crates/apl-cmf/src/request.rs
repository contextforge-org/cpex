// Location: ./crates/apl-cmf/src/request.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// RequestExtension → AttributeBag.
//
// Namespace:
//   request.environment    : String  ("production" | "staging" | ...)
//   request.request_id     : String
//   request.timestamp      : String  (ISO 8601 — bag stays scalar; predicates
//                                     comparing timestamps would need plugins)
//   request.trace_id       : String
//   request.span_id        : String

use apl_core::AttributeBag;
use cpex_core::extensions::RequestExtension;

pub fn extract_request(req: &RequestExtension, bag: &mut AttributeBag) {
    if let Some(v) = &req.environment {
        bag.set("request.environment", v.clone());
    }
    if let Some(v) = &req.request_id {
        bag.set("request.request_id", v.clone());
    }
    if let Some(v) = &req.timestamp {
        bag.set("request.timestamp", v.clone());
    }
    if let Some(v) = &req.trace_id {
        bag.set("request.trace_id", v.clone());
    }
    if let Some(v) = &req.span_id {
        bag.set("request.span_id", v.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_all_present_fields() {
        let req = RequestExtension {
            environment: Some("production".into()),
            request_id: Some("req-abc".into()),
            timestamp: Some("2026-05-14T12:00:00Z".into()),
            trace_id: Some("trace-1".into()),
            span_id: Some("span-2".into()),
        };
        let mut bag = AttributeBag::new();
        extract_request(&req, &mut bag);
        assert_eq!(bag.get_string("request.environment"), Some("production"));
        assert_eq!(bag.get_string("request.request_id"), Some("req-abc"));
        assert_eq!(bag.get_string("request.trace_id"), Some("trace-1"));
    }

    #[test]
    fn missing_fields_skipped() {
        let req = RequestExtension::default();
        let mut bag = AttributeBag::new();
        extract_request(&req, &mut bag);
        assert!(bag.is_empty());
    }
}
