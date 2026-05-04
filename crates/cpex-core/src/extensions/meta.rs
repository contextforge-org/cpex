// Location: ./crates/cpex-core/src/extensions/meta.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// MetaExtension — host-provided operational metadata.
// Mirrors cpex/framework/extensions/meta.py.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

/// Host-provided operational metadata.
///
/// Carries entity identification (type + name) for route resolution,
/// operational tags for policy group inheritance, scope for
/// host-defined grouping, and arbitrary properties.
///
/// Immutable — set by the host before invoking the hook. Plugins
/// can read but not modify.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MetaExtension {
    /// Entity type: "tool", "resource", "prompt", "llm".
    /// Used by the manager for route resolution.
    #[serde(default)]
    pub entity_type: Option<String>,

    /// Entity name: "get_compensation", "hr://employees/*", etc.
    /// Used by the manager for route resolution.
    #[serde(default)]
    pub entity_name: Option<String>,

    /// Operational tags — drive policy group inheritance.
    /// Merged with static tags from the matching route's `meta.tags`.
    #[serde(default)]
    pub tags: HashSet<String>,

    /// Host-defined grouping (virtual server ID, namespace, etc.).
    #[serde(default)]
    pub scope: Option<String>,

    /// Arbitrary key-value metadata.
    #[serde(default)]
    pub properties: HashMap<String, String>,
}
