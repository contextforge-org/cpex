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
use uuid::Uuid;

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

/// Threaded execution state carried from one hook invocation to the next
/// within a single request lifecycle (e.g., `pre_invoke` → `post_invoke`).
///
/// The table holds the canonical pipeline state in two parts:
///
/// - `global_state` — a single shared map across all plugins. The executor
///   clones this into each plugin's `PluginContext.global_state` at the
///   start of a run, then commits the plugin's possibly-modified copy back
///   when the run completes (last-writer-wins for serial phases).
/// - `local_states` — per-plugin private state, indexed by plugin ID.
///   Persists across hook invocations so a plugin's `pre_invoke` can stash
///   data its `post_invoke` will read.
///
/// Storing `global_state` once (rather than copying it inside every per-plugin
/// `PluginContext`) makes the canonical state explicit and removes the
/// non-deterministic "pick an arbitrary plugin's snapshot" pattern that was
/// previously needed to recover it.
///
/// Returned by the executor in `PipelineResult` and passed back into the
/// next hook call. On the first hook call pass `None` — the executor
/// creates a fresh table.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PluginContextTable {
    /// Authoritative shared state across all plugins in the pipeline.
    #[serde(default)]
    pub global_state: HashMap<String, Value>,

    /// Per-plugin local state, indexed by plugin ID (`Uuid`).
    #[serde(default)]
    pub local_states: HashMap<Uuid, HashMap<String, Value>>,
}

impl PluginContextTable {
    /// Create an empty context table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a `PluginContext` for the given plugin, *removing* its stored
    /// local_state from the table and seeding it with a fresh clone of the
    /// canonical global_state. Use in serial phases where the plugin will
    /// commit its local_state changes back via [`store_context`].
    ///
    /// If the plugin has no stored local_state yet, its context starts
    /// empty (first invocation in the request lifecycle).
    pub fn take_context(&mut self, plugin_id: Uuid) -> PluginContext {
        PluginContext {
            local_state: self.local_states.remove(&plugin_id).unwrap_or_default(),
            global_state: self.global_state.clone(),
        }
    }

    /// Build a `PluginContext` for the given plugin without mutating the
    /// table — the local_state is *cloned* and the global_state is cloned.
    /// Use in read-only phases (audit, concurrent, fire-and-forget) where
    /// per-plugin mutations should not influence subsequent plugins.
    pub fn snapshot_context(&self, plugin_id: Uuid) -> PluginContext {
        PluginContext {
            local_state: self
                .local_states
                .get(&plugin_id)
                .cloned()
                .unwrap_or_default(),
            global_state: self.global_state.clone(),
        }
    }

    /// Commit a plugin's context back into the table after it ran. Replaces
    /// the canonical global_state with the plugin's possibly-modified copy
    /// (move, no clone) and stores the plugin's local_state for next time.
    pub fn store_context(&mut self, plugin_id: Uuid, ctx: PluginContext) {
        self.global_state = ctx.global_state;
        self.local_states.insert(plugin_id, ctx.local_state);
    }

    /// Number of plugins with stored local_state in the table.
    pub fn len(&self) -> usize {
        self.local_states.len()
    }

    /// Whether the table holds no per-plugin local_state.
    pub fn is_empty(&self) -> bool {
        self.local_states.is_empty()
    }
}
