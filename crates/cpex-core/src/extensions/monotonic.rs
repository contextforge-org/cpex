// Location: ./crates/cpex-core/src/extensions/monotonic.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// MonotonicSet — add-only set enforced at the type level.
//
// Security labels can only grow. The type exposes insert() but not
// remove(). Declassification requires a DeclassifierToken that only
// the security subsystem can construct.
//
// Mirrors the spec in rust-implementation-spec.md §2.2.

use std::collections::HashSet;
use std::hash::Hash;

use serde::{Deserialize, Serialize};

/// A set that only allows additions. No remove() in the public API.
///
/// Plugins can call `insert()` but not `remove()`. Declassification
/// (removal) requires a `DeclassifierToken` that only the security
/// subsystem can construct.
///
/// This enforces the monotonic tier at compile time — a plugin that
/// tries to call `.remove()` gets a compile error.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MonotonicSet<T: Eq + Hash> {
    inner: HashSet<T>,
}

impl<T: Eq + Hash> MonotonicSet<T> {
    /// Create an empty monotonic set.
    pub fn new() -> Self {
        Self {
            inner: HashSet::new(),
        }
    }

    /// Create from an existing HashSet.
    pub fn from_set(set: HashSet<T>) -> Self {
        Self { inner: set }
    }

    /// Add a value. Returns true if the value was newly inserted.
    pub fn insert(&mut self, value: T) -> bool {
        self.inner.insert(value)
    }

    /// Check if the set contains a value.
    pub fn contains(&self, value: &T) -> bool {
        self.inner.contains(value)
    }

    /// Iterate over the values.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.inner.iter()
    }

    /// Number of elements.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Whether this set is a superset of another.
    pub fn is_superset(&self, other: &MonotonicSet<T>) -> bool {
        self.inner.is_superset(&other.inner)
    }

    /// Get a reference to the inner HashSet (read-only).
    pub fn as_set(&self) -> &HashSet<T> {
        &self.inner
    }

    /// Removal requires a DeclassifierToken — privileged, audited operation.
    /// Only the security subsystem can construct the token.
    pub fn remove_with_declassifier(&mut self, value: &T, _token: &DeclassifierToken) -> bool {
        self.inner.remove(value)
    }
}

impl<T: Eq + Hash> Default for MonotonicSet<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Opaque token for declassification — only the security subsystem
/// can create one. Constructing this token is a privileged operation.
pub struct DeclassifierToken {
    _private: (),
}

impl DeclassifierToken {
    /// Only callable by the framework/security subsystem.
    #[allow(dead_code)]
    pub(crate) fn new() -> Self {
        Self { _private: () }
    }
}

/// Case-insensitive label lookup on MonotonicSet<String>.
impl MonotonicSet<String> {
    /// Check if a label exists (case-insensitive).
    pub fn has_label(&self, label: &str) -> bool {
        let lower = label.to_lowercase();
        self.inner.iter().any(|l| l.to_lowercase() == lower)
    }

    /// Add a label (case-preserving on insert).
    pub fn add_label(&mut self, label: impl Into<String>) {
        self.inner.insert(label.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monotonic_insert_only() {
        let mut set = MonotonicSet::new();
        set.insert("PII".to_string());
        set.insert("CONFIDENTIAL".to_string());
        assert!(set.contains(&"PII".to_string()));
        assert_eq!(set.len(), 2);
        // No remove() method available — this is the key guarantee
    }

    #[test]
    fn test_monotonic_superset() {
        let mut before = MonotonicSet::new();
        before.insert("PII".to_string());

        let mut after = before.clone();
        after.insert("HIPAA".to_string());

        assert!(after.is_superset(&before));
        assert!(!before.is_superset(&after));
    }

    #[test]
    fn test_monotonic_declassifier() {
        let mut set = MonotonicSet::new();
        set.insert("PII".to_string());

        // Only works with the token
        let token = DeclassifierToken::new();
        assert!(set.remove_with_declassifier(&"PII".to_string(), &token));
        assert!(!set.contains(&"PII".to_string()));
    }

    #[test]
    fn test_monotonic_has_label_case_insensitive() {
        let mut set = MonotonicSet::new();
        set.add_label("PII");
        assert!(set.has_label("pii"));
        assert!(set.has_label("PII"));
        assert!(set.has_label("Pii"));
    }

    #[test]
    fn test_monotonic_serde_roundtrip() {
        let mut set = MonotonicSet::new();
        set.insert("PII".to_string());
        set.insert("HIPAA".to_string());

        let json = serde_json::to_string(&set).unwrap();
        let deserialized: MonotonicSet<String> = serde_json::from_str(&json).unwrap();
        assert!(deserialized.contains(&"PII".to_string()));
        assert!(deserialized.contains(&"HIPAA".to_string()));
    }
}
