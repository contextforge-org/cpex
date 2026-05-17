// Location: ./crates/apl-core/src/attributes.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// AttributeBag — flat namespace for policy evaluation.
//
// The DSL evaluates predicates against a flat bag of named, typed values.
// Each attribute source (cpex-core extensions, route args, session context,
// custom plugin namespaces) drops keys into the bag through the
// `AttributeExtractor` trait.
//
// A flat bag (rather than nested object access) means the evaluator never
// has to know which extension a key came from — it just queries by name.
// New attribute sources are additive: implement `AttributeExtractor` for
// them and the evaluator picks them up unchanged.
//
// Mapping from cpex-core extensions into the bag lives in `apl-cmf`, not
// here. See docs/specs/apl-design.md §4 for the module layering.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// A single attribute value the evaluator can compare against.
///
/// The five variants cover every shape the DSL needs:
/// `Bool` for `authenticated` / `role.*` / `perm.*`,
/// `Int` for counts and depths,
/// `Float` for confidences and ages,
/// `String` for identifiers,
/// `StringSet` for set-membership operators (`contains`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AttributeValue {
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    StringSet(HashSet<String>),
}

impl From<bool> for AttributeValue {
    fn from(v: bool) -> Self { AttributeValue::Bool(v) }
}
impl From<i64> for AttributeValue {
    fn from(v: i64) -> Self { AttributeValue::Int(v) }
}
impl From<f64> for AttributeValue {
    fn from(v: f64) -> Self { AttributeValue::Float(v) }
}
impl From<&str> for AttributeValue {
    fn from(v: &str) -> Self { AttributeValue::String(v.to_string()) }
}
impl From<String> for AttributeValue {
    fn from(v: String) -> Self { AttributeValue::String(v) }
}
impl From<HashSet<String>> for AttributeValue {
    fn from(v: HashSet<String>) -> Self { AttributeValue::StringSet(v) }
}

/// Flat key→value namespace consumed by the evaluator.
///
/// Populate via `set()` and/or `AttributeExtractor::extract()`; query via
/// the typed `get_*` methods. Once handed to the evaluator the bag is
/// read-only by convention (not enforced — `&mut` borrows are how you
/// build it up in the first place).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttributeBag {
    attrs: HashMap<String, AttributeValue>,
}

impl AttributeBag {
    pub fn new() -> Self {
        Self { attrs: HashMap::new() }
    }

    pub fn set(&mut self, key: impl Into<String>, value: impl Into<AttributeValue>) {
        self.attrs.insert(key.into(), value.into());
    }

    pub fn get(&self, key: &str) -> Option<&AttributeValue> {
        self.attrs.get(key)
    }

    pub fn contains(&self, key: &str) -> bool {
        self.attrs.contains_key(key)
    }

    pub fn get_bool(&self, key: &str) -> Option<bool> {
        match self.get(key) {
            Some(AttributeValue::Bool(v)) => Some(*v),
            _ => None,
        }
    }

    pub fn get_int(&self, key: &str) -> Option<i64> {
        match self.get(key) {
            Some(AttributeValue::Int(v)) => Some(*v),
            _ => None,
        }
    }

    pub fn get_float(&self, key: &str) -> Option<f64> {
        match self.get(key) {
            Some(AttributeValue::Float(v)) => Some(*v),
            // Promote int → float so `depth > 2.5`-style predicates work
            // when depth is stored as Int.
            Some(AttributeValue::Int(v)) => Some(*v as f64),
            _ => None,
        }
    }

    pub fn get_string(&self, key: &str) -> Option<&str> {
        match self.get(key) {
            Some(AttributeValue::String(v)) => Some(v.as_str()),
            _ => None,
        }
    }

    pub fn get_string_set(&self, key: &str) -> Option<&HashSet<String>> {
        match self.get(key) {
            Some(AttributeValue::StringSet(v)) => Some(v),
            _ => None,
        }
    }

    /// DSL `<key> contains <value>` — false if the key is missing or not a set.
    pub fn set_contains(&self, key: &str, value: &str) -> bool {
        self.get_string_set(key)
            .map(|set| set.contains(value))
            .unwrap_or(false)
    }

    pub fn len(&self) -> usize {
        self.attrs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.attrs.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &AttributeValue)> {
        self.attrs.iter().map(|(k, v)| (k.as_str(), v))
    }
}

/// Source of attributes. Implementors drop keys into the bag under a
/// consistent namespace prefix:
///
/// - cpex-core `SecurityExtension.subject`  → `subject.*`, `role.*`, `perm.*`
/// - cpex-core `SecurityExtension.client`   → `client.*`
/// - cpex-core `DelegationExtension`        → `delegation.*`, `delegated`
/// - Route args                              → `args.*`
/// - Session context                         → `session.*`
///
/// Implementations for the cpex-core extensions live in `apl-cmf`, not here.
pub trait AttributeExtractor {
    fn extract(&self, bag: &mut AttributeBag);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_bag() {
        let mut bag = AttributeBag::new();
        bag.set("authenticated", true);
        bag.set("delegation.depth", 2i64);
        bag.set("subject.id", "alice@corp.com");
        bag.set("intent.confidence", 0.92f64);

        assert_eq!(bag.get_bool("authenticated"), Some(true));
        assert_eq!(bag.get_int("delegation.depth"), Some(2));
        assert_eq!(bag.get_string("subject.id"), Some("alice@corp.com"));
        assert_eq!(bag.get_float("intent.confidence"), Some(0.92));
    }

    #[test]
    fn int_to_float_promotion() {
        let mut bag = AttributeBag::new();
        bag.set("delegation.depth", 2i64);
        assert_eq!(bag.get_float("delegation.depth"), Some(2.0));
    }

    #[test]
    fn string_set_contains() {
        let mut bag = AttributeBag::new();
        bag.set(
            "session.labels",
            HashSet::from(["PII".to_string(), "financial".to_string()]),
        );

        assert!(bag.set_contains("session.labels", "PII"));
        assert!(bag.set_contains("session.labels", "financial"));
        assert!(!bag.set_contains("session.labels", "PHI"));
    }

    #[test]
    fn missing_keys() {
        let bag = AttributeBag::new();
        assert_eq!(bag.get_bool("nonexistent"), None);
        assert_eq!(bag.get_int("nonexistent"), None);
        assert!(!bag.set_contains("nonexistent", "value"));
    }

    #[test]
    fn type_mismatch_returns_none() {
        let mut bag = AttributeBag::new();
        bag.set("subject.id", "alice");
        // Stored as String; asking for Bool returns None, not a coerced value.
        assert_eq!(bag.get_bool("subject.id"), None);
        assert_eq!(bag.get_int("subject.id"), None);
    }
}
