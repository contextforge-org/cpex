// Location: ./crates/cpex-core/src/visitor.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// `ConfigVisitor` — extension point for external orchestrators (APL,
// future Rego/Cedar-direct/custom) to participate in unified-config
// loading without cpex-core taking a dep on any specific orchestrator.
//
// # How it fits
//
// The host calls `PluginManager::load_config_yaml(yaml)`. cpex-core
// parses the YAML twice (once into a typed `CpexConfig`, once into a
// raw `serde_yaml::Value`), runs its own plugin instantiation, then
// walks each registered visitor in registration order:
//
//   1. `visit_plugins`       — once per visitor, immediately after
//                              cpex-core's own plugin instantiation,
//                              receiving the parsed `&[PluginConfig]`
//                              so the visitor doesn't have to re-parse
//                              the root `plugins:` block from raw YAML.
//   2. `visit_global`        — global config block
//   3. `visit_default`       — once per entity_type with a default
//   4. `visit_policy_bundle` — once per named policy group (tag)
//   5. `visit_route`         — once per route
//
// Each visitor sees the **raw YAML** so it can find its own block
// (e.g. `apl:`) under any section without cpex-core having to know
// about it. Parsed sibling data is passed alongside (`RouteEntry` for
// routes) for convenience — e.g. APL needs to know whether a route
// matches `tool:` or `resource:` to build the annotation key.
//
// # Why visit per-section rather than per-whole-config
//
// Visitors typically accumulate state across the hierarchy (e.g. APL's
// visitor compiles globals/defaults/tag-bundles into `CompiledRoute`s
// kept in visitor state, then merges them into each route at
// `visit_route`). Per-section calls give the orchestrator a natural
// place to do that accumulation without re-parsing.
//
// # Visit order
//
// All sections for one visitor run before the next visitor starts. For
// single-visitor deployments (the common case) this is identical to
// any other ordering; for multi-visitor it gives each visitor a
// consistent view of its own internal state. Visitor methods are
// invoked synchronously — no async runtime needed at load time.

use std::sync::Arc;

use crate::config::RouteEntry;
use crate::manager::PluginManager;
use crate::plugin::PluginConfig;

/// Error type returned by a config visitor. Boxed `dyn Error` so each
/// orchestrator can carry its own error variants (parse errors, missing
/// plugin references, etc.) without cpex-core having to enumerate them.
pub type VisitorError = Box<dyn std::error::Error + Send + Sync>;

/// Extension point for external orchestrators to participate in unified
/// config loading. Register via [`PluginManager::register_visitor`];
/// invoked during [`PluginManager::load_config_yaml`].
///
/// All methods have default no-op implementations — a visitor only
/// overrides the sections it cares about.
pub trait ConfigVisitor: Send + Sync {
    /// Stable identifier for diagnostics — included in error contexts
    /// if a visitor method returns Err. Convention: short kebab-case
    /// matching the orchestrator's YAML key (e.g. `"apl"`, `"rego"`).
    fn name(&self) -> &str;

    /// Visit the typed plugin declarations from the root `plugins:`
    /// block. Called once per visitor, immediately after cpex-core's
    /// own plugin instantiation completes and before any hierarchy
    /// section is walked. Visitors that need a per-name registry of
    /// hook / capability / on_error metadata can populate it here
    /// without re-parsing the YAML — cpex-core has already validated
    /// the block (no duplicate names, etc.) by this point.
    fn visit_plugins(
        &self,
        _mgr: &Arc<PluginManager>,
        _plugins: &[PluginConfig],
    ) -> Result<(), VisitorError> {
        Ok(())
    }

    /// Visit the top-level `global:` block. `yaml` is the raw value at
    /// that path, or `Value::Null` if `global:` is absent.
    fn visit_global(
        &self,
        _mgr: &Arc<PluginManager>,
        _yaml: &serde_yaml::Value,
    ) -> Result<(), VisitorError> {
        Ok(())
    }

    /// Visit one entry in `global.defaults`. Called once per
    /// `(entity_type, default_block)` pair. `yaml` is the raw value at
    /// `global.defaults.<entity_type>`.
    fn visit_default(
        &self,
        _mgr: &Arc<PluginManager>,
        _entity_type: &str,
        _yaml: &serde_yaml::Value,
    ) -> Result<(), VisitorError> {
        Ok(())
    }

    /// Visit one entry in `global.policies` (a named tag bundle).
    /// Called once per `(tag, policy_group)` pair. `yaml` is the raw
    /// value at `global.policies.<tag>`.
    fn visit_policy_bundle(
        &self,
        _mgr: &Arc<PluginManager>,
        _tag: &str,
        _yaml: &serde_yaml::Value,
    ) -> Result<(), VisitorError> {
        Ok(())
    }

    /// Visit one route entry. `yaml` is the raw value at `routes[i]`
    /// (so orchestrator can find its own block like `apl:`); `parsed`
    /// is the typed `RouteEntry` cpex-core deserialized (so the
    /// orchestrator can read `tool`/`resource`/`prompt`/`llm`,
    /// `meta.scope`, `meta.tags`, etc. without re-parsing).
    fn visit_route(
        &self,
        _mgr: &Arc<PluginManager>,
        _yaml: &serde_yaml::Value,
        _parsed: &RouteEntry,
    ) -> Result<(), VisitorError> {
        Ok(())
    }
}
