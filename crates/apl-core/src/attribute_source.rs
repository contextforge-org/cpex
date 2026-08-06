// Location: ./crates/apl-core/src/attribute_source.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Static attribute provisioning — the `data.*` bag namespace.
//
// `restrict` predicates (and policy predicates generally) read attributes
// that aren't carried by any token or fetched from anywhere: backend-free
// policy constants like tenant→region maps, per-agent model allow-lists,
// org defaults. Those come from a plain, operator-organized data tree that
// lands in the evaluation bag under `data.*` (see
// docs/apl-restrict-effect-design.md §4).
//
// This module is the pure contract: the `AttributeSource` trait (where a
// tree comes from) and the `AttributeTree` value (what it is). The default
// file-backed source and the bag flattening live at the outer layers
// (apl-cpex / apl-cmf) — apl-core stays free of I/O and config deps.

use serde_json::Value;
use thiserror::Error;

/// The static attribute tree — the whole `data:` document, a plain nested
/// value the operator organizes however they like. It carries *literal
/// values only*: no conditionals, no computed fields (that guardrail is
/// structural — there is no syntax in a data tree to express logic).
///
/// Flattened into the bag under `data.*` by the bag builder (apl-cmf):
/// `{ org: { default_region: us } }` → `data.org.default_region = "us"`.
#[derive(Debug, Clone, PartialEq)]
pub struct AttributeTree(Value);

impl AttributeTree {
    /// Wrap a loaded `data` document. Expected to be a JSON/YAML object;
    /// a non-object is tolerated but flattens to nothing useful.
    pub fn new(value: Value) -> Self {
        Self(value)
    }

    /// The empty tree — no static attributes. The default when no source
    /// is configured.
    pub fn empty() -> Self {
        Self(Value::Object(serde_json::Map::new()))
    }

    /// Borrow the underlying value (the bag builder walks this).
    pub fn as_value(&self) -> &Value {
        &self.0
    }

    /// True when the tree holds nothing (no keys).
    pub fn is_empty(&self) -> bool {
        match &self.0 {
            Value::Object(m) => m.is_empty(),
            Value::Null => true,
            _ => false,
        }
    }
}

impl Default for AttributeTree {
    fn default() -> Self {
        Self::empty()
    }
}

/// Where the `data.*` tree comes from — a **trait object injected at
/// construction**, not a CPEX hook-plugin. The host implements it over a
/// file, etcd, Postgres, a k8s ConfigMap, etc., and hands the object to
/// the runtime at startup.
///
/// `load` is **synchronous and one-shot**: it runs once at startup, never
/// on the request hot path, so blocking the init thread on file/network
/// I/O is fine — and it lets the (synchronous) runtime setup call it
/// directly, no async plumbing. A source that fronts a genuinely async
/// store can block on its own runtime at this edge.
///
/// v1 is **snapshot only**. Hot-reload (a `watch` that streams fresh
/// trees) is deferred — that is the one genuinely-async concern, and its
/// shape (stream vs channel vs callback) is best decided when it's built,
/// not stubbed now. A lazy per-key `resolve(path)` for huge stores is
/// likewise deferred.
pub trait AttributeSource: Send + Sync {
    /// Load the full attribute tree (a snapshot).
    fn load(&self) -> Result<AttributeTree, AttributeError>;
}

/// Why an attribute source failed to produce a tree. Loading is a
/// startup/config concern, so these surface as configuration errors at
/// the runtime boundary (fail-fast, not per-request).
#[derive(Debug, Error)]
pub enum AttributeError {
    /// The backing store could not be read (missing file, I/O error,
    /// unreachable etcd, …).
    #[error("attribute source load failed: {0}")]
    Load(String),

    /// The loaded bytes were not valid for the source's format.
    #[error("attribute source parse failed: {0}")]
    Parse(String),

    /// Two inputs set the *same* leaf path to different values — a real
    /// conflict the source refuses to silently resolve (fail-fast merge).
    #[error("attribute conflict at `{path}`: `{existing}` vs `{incoming}`")]
    Conflict {
        path: String,
        existing: String,
        incoming: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_tree_is_empty() {
        assert!(AttributeTree::empty().is_empty());
        assert!(AttributeTree::default().is_empty());
    }

    #[test]
    fn populated_tree_is_not_empty() {
        let t = AttributeTree::new(json!({ "org": { "default_region": "us" } }));
        assert!(!t.is_empty());
        assert_eq!(
            t.as_value().pointer("/org/default_region"),
            Some(&json!("us"))
        );
    }
}
