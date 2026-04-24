// Location: ./crates/cpex-core/src/context.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Execution context types.
//
// Provides PluginContext — the per-plugin, per-invocation execution
// context carrying transient state (counters, caches, intermediate
// results). All data needed for policy evaluation comes from the
// payload's extensions (filtered by capabilities), not from context.
//
// PluginContext has two state maps:
//   - local_state: private to this plugin, this invocation
//   - global_state: shared across plugins in a pipeline
//
// Identity, request metadata, tenant scope, etc. live in extensions
// (MetaExtension, SecurityExtension), not in the context.
//
// Mirrors the spec's PluginContext in plugin-framework-spec-v2.md §8.1.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Plugin Context
// ---------------------------------------------------------------------------

/// Per-plugin, per-invocation execution context.
///
/// Each plugin receives its own `PluginContext` with:
///
/// - `local_state` — private to this plugin, this invocation. Fresh
///   each time. Used for per-plugin counters, caches, scratch data.
/// - `global_state` — shared across all plugins in a pipeline. The
///   executor merges changes back after serial phases so subsequent
///   plugins see contributions from earlier ones.
///
/// All data needed for policy evaluation (identity, tenant, request
/// metadata) comes from the payload's extensions, capability-gated
/// per plugin. Context is purely for transient execution state.
///
/// ```text
/// PluginContext
/// ├── local_state: HashMap    # Per-plugin, per-request. Private.
/// └── global_state: HashMap   # Shared across plugins. Use with care.
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginContext {
    /// Plugin-local state. Private to this plugin, this invocation.
    #[serde(default)]
    pub local_state: HashMap<String, Value>,

    /// Shared state across all plugins in the pipeline.
    /// The executor merges changes back after each serial-phase plugin.
    #[serde(default)]
    pub global_state: HashMap<String, Value>,
}

impl PluginContext {
    /// Create a new empty plugin context.
    pub fn new() -> Self {
        Self {
            local_state: HashMap::new(),
            global_state: HashMap::new(),
        }
    }

    /// Create a plugin context with pre-populated global state.
    pub fn with_global_state(global_state: HashMap<String, Value>) -> Self {
        Self {
            local_state: HashMap::new(),
            global_state,
        }
    }

    /// Get a value from local state.
    pub fn get_local(&self, key: &str) -> Option<&Value> {
        self.local_state.get(key)
    }

    /// Set a value in local state.
    pub fn set_local(&mut self, key: impl Into<String>, value: Value) {
        self.local_state.insert(key.into(), value);
    }

    /// Get a value from global state.
    pub fn get_global(&self, key: &str) -> Option<&Value> {
        self.global_state.get(key)
    }

    /// Set a value in global state.
    pub fn set_global(&mut self, key: impl Into<String>, value: Value) {
        self.global_state.insert(key.into(), value);
    }
}

impl Default for PluginContext {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Plugin Context Table
// ---------------------------------------------------------------------------

/// Lookup table of `PluginContext` instances indexed by plugin ID.
///
/// Threaded across hook invocations so that a plugin's `local_state`
/// persists from one hook to the next within the same request lifecycle
/// (e.g., `pre_invoke` → `post_invoke`).
///
/// The caller receives the table back in `PipelineResult` and passes
/// it into the next hook invocation. On the first hook call, pass
/// `None` — the executor creates fresh contexts for each plugin.
pub type PluginContextTable = HashMap<String, PluginContext>;
