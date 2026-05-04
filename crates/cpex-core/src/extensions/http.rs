// Location: ./crates/cpex-core/src/extensions/http.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// HttpExtension — HTTP request and response headers.
// Mirrors cpex/framework/extensions/http.py.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// HTTP-related extensions.
///
/// Carries both request and response headers separately. The host
/// populates what's available at each hook point:
/// - Pre-invoke: `request_headers` filled, `response_headers` empty
/// - Post-invoke: both filled (request from original, response from upstream)
///
/// Capability-gated: requires `read_headers` to see, `write_headers`
/// to modify (both request and response).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HttpExtension {
    /// HTTP request headers (inbound from caller).
    #[serde(default)]
    pub request_headers: HashMap<String, String>,

    /// HTTP response headers (from upstream, populated post-invoke).
    #[serde(default)]
    pub response_headers: HashMap<String, String>,
}

impl HttpExtension {
    // -- Request header helpers --

    /// Set a request header (overwrites if exists).
    pub fn set_request_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.request_headers.insert(name.into(), value.into());
    }

    /// Get a request header value (case-insensitive lookup).
    pub fn get_request_header(&self, name: &str) -> Option<&str> {
        get_header_ci(&self.request_headers, name)
    }

    /// Check if a request header exists (case-insensitive).
    pub fn has_request_header(&self, name: &str) -> bool {
        self.get_request_header(name).is_some()
    }

    /// Add request header only if it doesn't exist. Returns true if added.
    pub fn add_request_header(&mut self, name: impl Into<String>, value: impl Into<String>) -> bool {
        let name = name.into();
        if self.has_request_header(&name) {
            return false;
        }
        self.request_headers.insert(name, value.into());
        true
    }

    /// Remove a request header by name. Returns the removed value.
    pub fn remove_request_header(&mut self, name: &str) -> Option<String> {
        remove_header_ci(&mut self.request_headers, name)
    }

    // -- Response header helpers --

    /// Set a response header (overwrites if exists).
    pub fn set_response_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.response_headers.insert(name.into(), value.into());
    }

    /// Get a response header value (case-insensitive lookup).
    pub fn get_response_header(&self, name: &str) -> Option<&str> {
        get_header_ci(&self.response_headers, name)
    }

    /// Check if a response header exists (case-insensitive).
    pub fn has_response_header(&self, name: &str) -> bool {
        self.get_response_header(name).is_some()
    }

    // -- Convenience aliases (backward-compatible, default to request) --

    /// Set a header on request headers (convenience alias).
    pub fn set_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.set_request_header(name, value);
    }

    /// Get a header from request headers (convenience alias, case-insensitive).
    pub fn get_header(&self, name: &str) -> Option<&str> {
        self.get_request_header(name)
    }

    /// Check if a request header exists (convenience alias).
    pub fn has_header(&self, name: &str) -> bool {
        self.has_request_header(name)
    }
}

// -- Internal helpers --

fn get_header_ci<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    let lower = name.to_lowercase();
    headers
        .iter()
        .find(|(k, _)| k.to_lowercase() == lower)
        .map(|(_, v)| v.as_str())
}

fn remove_header_ci(headers: &mut HashMap<String, String>, name: &str) -> Option<String> {
    let lower = name.to_lowercase();
    let key = headers
        .keys()
        .find(|k| k.to_lowercase() == lower)
        .cloned();
    key.and_then(|k| headers.remove(&k))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_header_set_and_get() {
        let mut http = HttpExtension::default();
        http.set_request_header("Content-Type", "application/json");
        assert_eq!(http.get_request_header("Content-Type"), Some("application/json"));
    }

    #[test]
    fn test_request_header_case_insensitive() {
        let mut http = HttpExtension::default();
        http.set_request_header("Authorization", "Bearer tok");
        assert_eq!(http.get_request_header("authorization"), Some("Bearer tok"));
        assert_eq!(http.get_request_header("AUTHORIZATION"), Some("Bearer tok"));
    }

    #[test]
    fn test_response_header_set_and_get() {
        let mut http = HttpExtension::default();
        http.set_response_header("Content-Type", "text/html");
        assert_eq!(http.get_response_header("Content-Type"), Some("text/html"));
        assert!(http.has_response_header("content-type"));
    }

    #[test]
    fn test_request_and_response_independent() {
        let mut http = HttpExtension::default();
        http.set_request_header("Authorization", "Bearer req-tok");
        http.set_response_header("X-Response-Time", "42ms");

        // Request headers don't leak into response
        assert!(http.get_response_header("Authorization").is_none());
        // Response headers don't leak into request
        assert!(http.get_request_header("X-Response-Time").is_none());
    }

    #[test]
    fn test_convenience_aliases_default_to_request() {
        let mut http = HttpExtension::default();
        http.set_header("X-Custom", "value");
        assert_eq!(http.get_header("X-Custom"), Some("value"));
        assert!(http.has_header("X-Custom"));
        // Verify it went to request_headers
        assert_eq!(http.get_request_header("X-Custom"), Some("value"));
    }

    #[test]
    fn test_add_request_header_only_if_absent() {
        let mut http = HttpExtension::default();
        assert!(http.add_request_header("X-New", "first"));
        assert!(!http.add_request_header("X-New", "second"));
        assert_eq!(http.get_request_header("X-New"), Some("first"));
    }

    #[test]
    fn test_remove_request_header() {
        let mut http = HttpExtension::default();
        http.set_request_header("X-Remove", "value");
        let removed = http.remove_request_header("x-remove");
        assert_eq!(removed, Some("value".to_string()));
        assert!(!http.has_request_header("X-Remove"));
    }

    #[test]
    fn test_serde_roundtrip() {
        let mut http = HttpExtension::default();
        http.set_request_header("Authorization", "Bearer tok");
        http.set_request_header("X-Request-ID", "req-123");
        http.set_response_header("Content-Type", "application/json");
        http.set_response_header("X-Response-Time", "15ms");

        let json = serde_json::to_string(&http).unwrap();
        let deserialized: HttpExtension = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.get_request_header("Authorization"), Some("Bearer tok"));
        assert_eq!(deserialized.get_response_header("Content-Type"), Some("application/json"));
    }
}
