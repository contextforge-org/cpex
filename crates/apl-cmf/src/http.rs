// Location: ./crates/apl-cmf/src/http.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// HttpExtension → AttributeBag.
//
// Header names are lowercased in the bag (HTTP is case-insensitive). A
// policy author writing `http.request_headers.authorization` doesn't need
// to remember the original case.
//
// Namespace:
//   http.method                    : String  (request line)
//   http.path                      : String
//   http.host                      : String
//   http.scheme                    : String
//   http.request_headers.<name>    : String  (lowercased name)
//   http.response_headers.<name>   : String  (lowercased name)

use apl_core::AttributeBag;
use cpex_core::extensions::HttpExtension;

use crate::constants::{BAG_HTTP_HOST, BAG_HTTP_METHOD, BAG_HTTP_PATH, BAG_HTTP_SCHEME};

pub fn extract_http(http: &HttpExtension, bag: &mut AttributeBag) {
    if let Some(method) = &http.method {
        bag.set(BAG_HTTP_METHOD.to_string(), method.clone());
    }
    if let Some(path) = &http.path {
        bag.set(BAG_HTTP_PATH.to_string(), path.clone());
    }
    if let Some(host) = &http.host {
        bag.set(BAG_HTTP_HOST.to_string(), host.clone());
    }
    if let Some(scheme) = &http.scheme {
        bag.set(BAG_HTTP_SCHEME.to_string(), scheme.clone());
    }
    for (k, v) in &http.request_headers {
        bag.set(
            format!("http.request_headers.{}", k.to_lowercase()),
            v.clone(),
        );
    }
    for (k, v) in &http.response_headers {
        bag.set(
            format!("http.response_headers.{}", k.to_lowercase()),
            v.clone(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_line_surfaced_in_bag() {
        let http = HttpExtension {
            method: Some("POST".to_string()),
            path: Some("/api/widgets".to_string()),
            host: Some("api.example.com".to_string()),
            scheme: Some("https".to_string()),
            ..Default::default()
        };
        let mut bag = AttributeBag::new();
        extract_http(&http, &mut bag);
        assert_eq!(bag.get_string("http.method"), Some("POST"));
        assert_eq!(bag.get_string("http.path"), Some("/api/widgets"));
        assert_eq!(bag.get_string("http.host"), Some("api.example.com"));
        assert_eq!(bag.get_string("http.scheme"), Some("https"));
    }

    #[test]
    fn request_line_absent_when_unset() {
        let http = HttpExtension::default();
        let mut bag = AttributeBag::new();
        extract_http(&http, &mut bag);
        assert_eq!(bag.get_string("http.method"), None);
    }

    #[test]
    fn headers_lowercased_in_bag() {
        let mut http = HttpExtension::default();
        http.set_request_header("Authorization", "Bearer xyz");
        http.set_request_header("X-Trace-Id", "abc-123");
        http.set_response_header("Content-Type", "application/json");

        let mut bag = AttributeBag::new();
        extract_http(&http, &mut bag);
        assert_eq!(
            bag.get_string("http.request_headers.authorization"),
            Some("Bearer xyz")
        );
        assert_eq!(
            bag.get_string("http.request_headers.x-trace-id"),
            Some("abc-123")
        );
        assert_eq!(
            bag.get_string("http.response_headers.content-type"),
            Some("application/json")
        );
    }
}
