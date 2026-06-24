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
//   http.request_headers.<name>    : String  (lowercased name)
//   http.response_headers.<name>   : String  (lowercased name)

use apl_core::AttributeBag;
use cpex_core::extensions::HttpExtension;

pub fn extract_http(http: &HttpExtension, bag: &mut AttributeBag) {
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
