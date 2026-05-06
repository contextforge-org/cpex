// Location: ./crates/cpex-core/src/config.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Unified YAML configuration parsing.
//
// Parses the config format that combines global settings, plugin
// declarations, and per-entity routes into a single YAML document.
//
// Supports two modes controlled by `plugin_settings.routing_enabled`:
//   - false (default, backward compatible): plugins declare their
//     own conditions for when they fire.
//   - true: per-entity routing rules determine which plugins fire,
//     with plugin selection via policy groups and meta.tags.
//
// The two modes are mutually exclusive. When routing is disabled,
// the routes and global sections are ignored. When routing is
// enabled, conditions on individual plugins are ignored.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::PluginError;
use crate::plugin::PluginConfig;

// ---------------------------------------------------------------------------
// Top-Level Config
// ---------------------------------------------------------------------------

/// Top-level CPEX configuration.
///
/// Parsed from a single YAML file. Plugin scoping mode is controlled
/// by `plugin_settings.routing_enabled` — if absent or false, plugins
/// use their own `conditions:` field (backward compatible). If true,
/// the `routes:` and `global:` sections take over.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CpexConfig {
    /// Global configuration — policies, defaults.
    /// Only used when `plugin_settings.routing_enabled` is true.
    #[serde(default)]
    pub global: GlobalConfig,

    /// Directories to scan for plugin modules.
    #[serde(default)]
    pub plugin_dirs: Vec<String>,

    /// Plugin declarations.
    #[serde(default)]
    pub plugins: Vec<PluginConfig>,

    /// Per-entity routing rules.
    /// Only used when `plugin_settings.routing_enabled` is true.
    #[serde(default)]
    pub routes: Vec<RouteEntry>,

    /// Global plugin settings (timeout, error behavior, routing mode).
    #[serde(default)]
    pub plugin_settings: PluginSettings,
}

impl CpexConfig {
    /// Whether route-based plugin selection is enabled.
    pub fn routing_enabled(&self) -> bool {
        self.plugin_settings.routing_enabled
    }
}

// ---------------------------------------------------------------------------
// Plugin Settings
// ---------------------------------------------------------------------------

/// Global plugin settings.
///
/// Controls executor behavior and routing mode. All fields have
/// sensible defaults — a missing `plugin_settings:` section is valid.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginSettings {
    /// Enable route-based plugin selection.
    /// When false (default), plugins use their own `conditions:` field.
    /// When true, the `routes:` and `global:` sections determine which
    /// plugins fire per entity.
    #[serde(default)]
    pub routing_enabled: bool,

    /// Default timeout per plugin in seconds.
    #[serde(default = "default_timeout")]
    pub plugin_timeout: u64,

    /// Whether to halt on first deny in concurrent mode.
    #[serde(default = "default_true")]
    pub short_circuit_on_deny: bool,

    /// Whether plugins can execute in parallel within a mode band.
    #[serde(default)]
    pub parallel_execution_within_band: bool,

    /// Whether to halt the pipeline on any plugin error.
    #[serde(default)]
    pub fail_on_plugin_error: bool,

    /// Maximum number of entries in the routing cache.
    ///
    /// When the cache reaches this size, new resolutions are computed
    /// normally but not memoized — the cache rejects further inserts
    /// and emits a warning. This bounds memory growth from
    /// attacker-controlled entity names without the reasoning hazards
    /// of eviction (silently dropped entries, stale-vs-current
    /// confusion). Operators see the warning and tune the cap or
    /// investigate the entity-name growth.
    #[serde(default = "default_route_cache_max_entries")]
    pub route_cache_max_entries: usize,
}

impl Default for PluginSettings {
    fn default() -> Self {
        Self {
            routing_enabled: false,
            plugin_timeout: 30,
            short_circuit_on_deny: true,
            parallel_execution_within_band: false,
            fail_on_plugin_error: false,
            route_cache_max_entries: default_route_cache_max_entries(),
        }
    }
}

fn default_route_cache_max_entries() -> usize {
    10_000
}

fn default_timeout() -> u64 {
    30
}

fn default_true() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Global Config
// ---------------------------------------------------------------------------

/// Global configuration — applies across all routes.
///
/// Only used when routing is enabled. Contains named policy groups
/// (including the reserved `all` group) and per-entity-type defaults.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GlobalConfig {
    /// Named policy groups. The reserved name `all` is applied to
    /// every request unconditionally. Other groups are inherited
    /// by routes via `meta.tags`.
    #[serde(default)]
    pub policies: HashMap<String, PolicyGroup>,

    /// Per-entity-type default policy groups.
    /// Keys are `tool`, `resource`, `prompt`, `llm`.
    #[serde(default)]
    pub defaults: HashMap<String, PolicyGroup>,
}

// ---------------------------------------------------------------------------
// Policy Group
// ---------------------------------------------------------------------------

/// A named policy group — plugins to activate and optional metadata.
///
/// The `all` group is reserved and always applied.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyGroup {
    /// Human-readable description.
    #[serde(default)]
    pub description: Option<String>,

    /// Arbitrary metadata for tooling and audit.
    #[serde(default)]
    pub metadata: HashMap<String, String>,

    /// Plugin references to activate when this group matches.
    #[serde(default)]
    pub plugins: Vec<PluginRouteRef>,
}

// ---------------------------------------------------------------------------
// Plugin Ref (route/group plugin reference)
// ---------------------------------------------------------------------------

/// A reference to a plugin in a route or policy group.
///
/// ```yaml
/// plugins:
///   - rate_limiter                     # bare name
///   - pii_scanner:                     # name with config overrides
///       config:
///         sensitivity: high
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PluginRouteRef {
    /// Just the name — activate the plugin with no config overrides.
    Name(String),
    /// Name with config overrides — single-key map.
    WithOverrides(HashMap<String, serde_json::Value>),
}

impl PluginRouteRef {
    /// Extract the plugin name from this reference.
    pub fn name(&self) -> &str {
        match self {
            Self::Name(name) => name,
            Self::WithOverrides(map) => map.keys().next().map(|s| s.as_str()).unwrap_or(""),
        }
    }

    /// Extract config overrides, if any.
    pub fn overrides(&self) -> Option<&serde_json::Value> {
        match self {
            Self::Name(_) => None,
            Self::WithOverrides(map) => map.values().next(),
        }
    }
}

// ---------------------------------------------------------------------------
// Route Entry
// ---------------------------------------------------------------------------

/// A per-entity routing rule.
///
/// Matches one entity type (tool, resource, prompt, or LLM) and
/// determines which plugins fire.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RouteEntry {
    /// Match a tool by exact name, list, or glob.
    #[serde(default)]
    pub tool: Option<StringOrList>,

    /// Match a resource by exact URI, list, or glob.
    #[serde(default)]
    pub resource: Option<StringOrList>,

    /// Match a prompt by exact name, list, or glob.
    #[serde(default)]
    pub prompt: Option<StringOrList>,

    /// Match an LLM by exact model name, list, or glob.
    #[serde(default)]
    pub llm: Option<StringOrList>,

    /// Operational metadata — tags, scope, properties.
    #[serde(default)]
    pub meta: Option<RouteMeta>,

    /// Conditional match expression — carried but not evaluated
    /// during static resolution. Evaluated at runtime when payload
    /// data is available (future: APL evaluator).
    #[serde(default)]
    pub when: Option<String>,

    /// Plugin references to activate for this route.
    #[serde(default)]
    pub plugins: Vec<PluginRouteRef>,
}

// ---------------------------------------------------------------------------
// Route Meta
// ---------------------------------------------------------------------------

/// Operational metadata on a route entry.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RouteMeta {
    /// Entity tags — drive policy group inheritance.
    #[serde(default)]
    pub tags: Vec<String>,

    /// Host-defined grouping (virtual server ID, namespace, etc.).
    /// Used for scope matching: route scope must match request scope.
    #[serde(default)]
    pub scope: Option<String>,

    /// Arbitrary key-value metadata.
    #[serde(default)]
    pub properties: HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// String or List (for tool matching)
// ---------------------------------------------------------------------------

/// An entity-name pattern. Holds the original pattern string (for
/// serialization round-tripping and operator-facing diagnostics) plus a
/// `WildMatch` matcher pre-compiled at deserialize time so route resolution
/// doesn't re-parse the pattern on every request. Custom `Serialize` /
/// `Deserialize` make this transparent to YAML — it serializes as a plain
/// string, just like the previous `String` field did.
///
/// Glob syntax (via `wildmatch`):
/// - `*` matches any sequence of characters (including empty).
/// - `?` matches any single character.
///
/// The previous hand-rolled matcher only handled trailing-`*` correctly:
/// `*suffix` patterns silently matched almost nothing, and multi-star
/// patterns like `**` accidentally matched everything. Both shapes are
/// real security footguns for scope/tool restriction rules — switching to
/// `wildmatch` gives us full single-segment glob semantics.
#[derive(Debug, Clone)]
pub struct Pattern {
    pattern: String,
    matcher: wildmatch::WildMatch,
}

impl Pattern {
    /// Compile a pattern. Done once at config load; subsequent `matches()`
    /// calls reuse the compiled `WildMatch`.
    pub fn new(pattern: impl Into<String>) -> Self {
        let pattern = pattern.into();
        let matcher = wildmatch::WildMatch::new(&pattern);
        Self { pattern, matcher }
    }

    /// Match the given name against the compiled pattern.
    pub fn matches(&self, name: &str) -> bool {
        self.matcher.matches(name)
    }

    /// The original pattern string (e.g., `"hr-*"`).
    pub fn as_str(&self) -> &str {
        &self.pattern
    }
}

impl Default for Pattern {
    fn default() -> Self {
        Self::new("")
    }
}

impl Serialize for Pattern {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.pattern)
    }
}

impl<'de> Deserialize<'de> for Pattern {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(Pattern::new(s))
    }
}

/// A tool matcher — single name, list of names, or glob pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StringOrList {
    /// Single string (exact name or glob pattern). Pre-compiled at
    /// deserialize time so the route-resolution slow path doesn't re-parse
    /// on each request.
    Single(Pattern),
    /// List of exact names.
    List(Vec<String>),
}

impl Default for StringOrList {
    fn default() -> Self {
        Self::Single(Pattern::default())
    }
}

impl StringOrList {
    /// Check if this matcher matches the given name.
    pub fn matches(&self, name: &str) -> bool {
        match self {
            Self::Single(pattern) => pattern.matches(name),
            Self::List(names) => names.iter().any(|n| n == name),
        }
    }
}

// ---------------------------------------------------------------------------
// Config Loading
// ---------------------------------------------------------------------------

/// Load and parse a CPEX config from a YAML file.
pub fn load_config(path: &Path) -> Result<CpexConfig, Box<PluginError>> {
    let content = std::fs::read_to_string(path).map_err(|e| PluginError::Config {
        message: format!("failed to read config file '{}': {}", path.display(), e),
    })?;
    parse_config(&content)
}

/// Parse a CPEX config from a YAML string.
pub fn parse_config(yaml: &str) -> Result<CpexConfig, Box<PluginError>> {
    let config: CpexConfig = serde_yaml::from_str(yaml).map_err(|e| PluginError::Config {
        message: format!("failed to parse config YAML: {}", e),
    })?;
    validate_config(&config)?;
    Ok(config)
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate a parsed config for structural correctness.
fn validate_config(config: &CpexConfig) -> Result<(), Box<PluginError>> {
    let mut seen_names = HashSet::new();
    for plugin in &config.plugins {
        if !seen_names.insert(&plugin.name) {
            return Err(Box::new(PluginError::Config {
                message: format!("duplicate plugin name: '{}'", plugin.name),
            }));
        }
    }

    if config.routing_enabled() {
        let plugin_names: HashSet<&str> = config.plugins.iter().map(|p| p.name.as_str()).collect();

        for (i, route) in config.routes.iter().enumerate() {
            let count = [
                route.tool.is_some(),
                route.resource.is_some(),
                route.prompt.is_some(),
                route.llm.is_some(),
            ]
            .iter()
            .filter(|&&m| m)
            .count();

            if count == 0 {
                return Err(Box::new(PluginError::Config {
                    message: format!(
                        "route {} has no entity matcher (need tool, resource, prompt, or llm)",
                        i
                    ),
                }));
            }
            if count > 1 {
                return Err(Box::new(PluginError::Config {
                    message: format!(
                        "route {} has multiple entity matchers (need exactly one)",
                        i
                    ),
                }));
            }

            for plugin_ref in &route.plugins {
                if !plugin_names.contains(plugin_ref.name()) {
                    return Err(Box::new(PluginError::Config {
                        message: format!(
                            "route {} references unknown plugin '{}'",
                            i,
                            plugin_ref.name()
                        ),
                    }));
                }
            }
        }

        for (group_name, group) in &config.global.policies {
            for plugin_ref in &group.plugins {
                if !plugin_names.contains(plugin_ref.name()) {
                    return Err(Box::new(PluginError::Config {
                        message: format!(
                            "policy group '{}' references unknown plugin '{}'",
                            group_name,
                            plugin_ref.name()
                        ),
                    }));
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Route Resolution
// ---------------------------------------------------------------------------

/// Specificity scores for route matching.
const SPECIFICITY_EXACT_NAME: usize = 1000;
const SPECIFICITY_NAME_LIST: usize = 500;
const SPECIFICITY_GLOB: usize = 300;
const SPECIFICITY_WHEN_ONLY: usize = 10;
const SPECIFICITY_WILDCARD: usize = 0;

/// Score a single entity matcher (tool / resource / prompt / llm) against
/// a request entity name, returning the specificity bucket if it matches
/// or `None` if it doesn't (or the matcher is absent). Replaces four
/// copy-pasted match arms in `resolve_plugins_for_entity`.
fn score_entity_match(matcher: Option<&StringOrList>, entity_name: &str) -> Option<usize> {
    let matcher = matcher?;
    if !matcher.matches(entity_name) {
        return None;
    }
    let score = match matcher {
        StringOrList::Single(p) if p.as_str() == "*" => SPECIFICITY_WILDCARD,
        StringOrList::Single(p) if p.as_str().contains('*') => SPECIFICITY_GLOB,
        StringOrList::List(_) => SPECIFICITY_NAME_LIST,
        StringOrList::Single(_) => SPECIFICITY_EXACT_NAME,
    };
    Some(score)
}

/// Resolve which plugins should fire for a given entity.
///
/// When routing is disabled, returns all plugin names. When enabled,
/// matches the entity against routes and collects plugins from the
/// `all` group, defaults, matching policy groups (via merged tags),
/// and the route itself.
///
/// `request_scope` and `request_tags` come from the host's
/// `MetaExtension` on the request.
pub fn resolve_plugins_for_entity(
    config: &CpexConfig,
    entity_type: &str,
    entity_name: &str,
    request_scope: Option<&str>,
    request_tags: &HashSet<String>,
) -> Vec<ResolvedPlugin> {
    if !config.routing_enabled() {
        return config
            .plugins
            .iter()
            .map(|p| ResolvedPlugin {
                name: p.name.clone(),
                config_overrides: None,
                when: None,
            })
            .collect();
    }

    let mut resolved = Vec::new();

    // 1. Always include plugins from the "all" policy group
    if let Some(all_group) = config.global.policies.get("all") {
        collect_plugin_refs(&all_group.plugins, &mut resolved, None);
    }

    // 2. Include plugins from matching defaults
    if let Some(default_group) = config.global.defaults.get(entity_type) {
        collect_plugin_refs(&default_group.plugins, &mut resolved, None);
    }

    // 3. Find matching route (with scope check)
    if let Some(route) = find_matching_route(config, entity_type, entity_name, request_scope) {
        // Merge tags: route's static tags + host's runtime tags
        let mut merged_tags: HashSet<String> = request_tags.clone();
        if let Some(meta) = &route.meta {
            for tag in &meta.tags {
                merged_tags.insert(tag.clone());
            }
        }

        // Include plugins from all matching policy groups (merged tags)
        for tag in &merged_tags {
            if tag == "all" {
                continue; // already handled above
            }
            if let Some(group) = config.global.policies.get(tag.as_str()) {
                collect_plugin_refs(&group.plugins, &mut resolved, None);
            }
        }

        // Include route-level plugins, carrying the route's when clause
        collect_plugin_refs(&route.plugins, &mut resolved, route.when.as_deref());
    }

    // Deduplicate by name, preserving order. Later overrides win.
    let mut seen = HashSet::new();
    let mut deduped = Vec::new();
    for rp in resolved.into_iter().rev() {
        if seen.insert(rp.name.clone()) {
            deduped.push(rp);
        }
    }
    deduped.reverse();
    deduped
}

/// A resolved plugin with optional config overrides and when clause.
#[derive(Debug, Clone)]
pub struct ResolvedPlugin {
    /// Plugin name.
    pub name: String,

    /// Config overrides from the route.
    pub config_overrides: Option<serde_json::Value>,

    /// When clause from the route — carried but not evaluated here.
    pub when: Option<String>,
}

/// Collect plugin refs into the resolved list.
fn collect_plugin_refs(
    refs: &[PluginRouteRef],
    resolved: &mut Vec<ResolvedPlugin>,
    route_when: Option<&str>,
) {
    for plugin_ref in refs {
        resolved.push(ResolvedPlugin {
            name: plugin_ref.name().to_string(),
            config_overrides: plugin_ref.overrides().cloned(),
            when: route_when.map(String::from),
        });
    }
}

/// Find the best matching route for an entity by specificity.
///
/// Scope matching: if a route declares a scope, the request must
/// have the same scope. No scope on the route matches any request.
fn find_matching_route<'a>(
    config: &'a CpexConfig,
    entity_type: &str,
    entity_name: &str,
    request_scope: Option<&str>,
) -> Option<&'a RouteEntry> {
    let mut best: Option<(usize, &RouteEntry)> = None;

    for route in &config.routes {
        // Check scope compatibility
        let route_scope = route.meta.as_ref().and_then(|m| m.scope.as_deref());
        let scope_bonus = match (route_scope, request_scope) {
            (None, _) => 0,                          // route is global
            (Some(rs), Some(rq)) if rs == rq => 100, // scopes match
            (Some(_), _) => continue,                // scope mismatch — skip
        };

        let entity_matcher = match entity_type {
            "tool" => route.tool.as_ref(),
            "resource" => route.resource.as_ref(),
            "prompt" => route.prompt.as_ref(),
            "llm" => route.llm.as_ref(),
            _ => continue,
        };
        let base_specificity = match score_entity_match(entity_matcher, entity_name) {
            Some(score) => score,
            None => continue,
        };

        let when_bonus = if route.when.is_some() {
            SPECIFICITY_WHEN_ONLY
        } else {
            0
        };
        let total = base_specificity + scope_bonus + when_bonus;

        if best.is_none_or(|(s, _)| total > s) {
            best = Some((total, route));
        }
    }

    best.map(|(_, route)| route)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: empty tags for tests that don't need them
    fn no_tags() -> HashSet<String> {
        HashSet::new()
    }

    #[test]
    fn test_parse_minimal_config() {
        let yaml = r#"
plugins:
  - name: rate_limiter
    kind: builtin
    hooks: [tool_pre_invoke]
    mode: sequential
    priority: 5
    config:
      max_requests: 100
"#;
        let config = parse_config(yaml).unwrap();
        assert!(!config.routing_enabled());
        assert_eq!(config.plugins.len(), 1);
        assert_eq!(config.plugins[0].name, "rate_limiter");
    }

    #[test]
    fn test_no_plugin_settings_defaults_routing_disabled() {
        let yaml = r#"
plugins:
  - name: test
    kind: builtin
    hooks: [tool_pre_invoke]
"#;
        let config = parse_config(yaml).unwrap();
        assert!(!config.routing_enabled());
        assert_eq!(config.plugin_settings.plugin_timeout, 30);
    }

    #[test]
    fn test_routing_enabled() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
global:
  policies:
    all:
      plugins: [identity]
plugins:
  - name: identity
    kind: builtin
    hooks: [identity_resolve]
routes:
  - tool: get_compensation
    meta:
      tags: [pii]
"#;
        let config = parse_config(yaml).unwrap();
        assert!(config.routing_enabled());
    }

    #[test]
    fn test_duplicate_plugin_names_rejected() {
        let yaml = r#"
plugins:
  - name: dup
    kind: builtin
    hooks: [tool_pre_invoke]
  - name: dup
    kind: builtin
    hooks: [tool_post_invoke]
"#;
        assert!(parse_config(yaml)
            .unwrap_err()
            .to_string()
            .contains("duplicate plugin name"));
    }

    #[test]
    fn test_route_requires_one_entity_matcher() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
plugins: []
routes:
  - meta:
      tags: [pii]
"#;
        assert!(parse_config(yaml)
            .unwrap_err()
            .to_string()
            .contains("no entity matcher"));
    }

    #[test]
    fn test_route_rejects_multiple_entity_matchers() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
plugins: []
routes:
  - tool: get_compensation
    resource: "hr://employees/*"
"#;
        assert!(parse_config(yaml)
            .unwrap_err()
            .to_string()
            .contains("multiple entity matchers"));
    }

    #[test]
    fn test_route_unknown_plugin_rejected() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
plugins:
  - name: known
    kind: builtin
    hooks: [tool_pre_invoke]
routes:
  - tool: get_compensation
    plugins:
      - unknown
"#;
        assert!(parse_config(yaml)
            .unwrap_err()
            .to_string()
            .contains("unknown plugin 'unknown'"));
    }

    #[test]
    fn test_policy_group_unknown_plugin_rejected() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
global:
  policies:
    all:
      plugins: [nonexistent]
plugins: []
routes: []
"#;
        assert!(parse_config(yaml)
            .unwrap_err()
            .to_string()
            .contains("unknown plugin 'nonexistent'"));
    }

    #[test]
    fn test_resolve_conditions_mode_returns_all() {
        let yaml = r#"
plugins:
  - name: a
    kind: builtin
    hooks: [tool_pre_invoke]
  - name: b
    kind: builtin
    hooks: [tool_post_invoke]
"#;
        let config = parse_config(yaml).unwrap();
        let resolved = resolve_plugins_for_entity(&config, "tool", "anything", None, &no_tags());
        let names: Vec<&str> = resolved.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["a", "b"]);
    }

    #[test]
    fn test_resolve_routes_inherits_policy_groups() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
global:
  policies:
    all:
      plugins:
        - identity
    pii:
      plugins:
        - apl_policy
plugins:
  - name: identity
    kind: builtin
    hooks: [identity_resolve]
  - name: apl_policy
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_compensation
    meta:
      tags: [pii]
"#;
        let config = parse_config(yaml).unwrap();
        let resolved =
            resolve_plugins_for_entity(&config, "tool", "get_compensation", None, &no_tags());
        let names: Vec<&str> = resolved.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"identity"));
        assert!(names.contains(&"apl_policy"));
    }

    #[test]
    fn test_resolve_no_matching_route_gets_all_only() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
global:
  policies:
    all:
      plugins:
        - identity
plugins:
  - name: identity
    kind: builtin
    hooks: [identity_resolve]
routes:
  - tool: get_compensation
"#;
        let config = parse_config(yaml).unwrap();
        let resolved =
            resolve_plugins_for_entity(&config, "tool", "unknown_tool", None, &no_tags());
        let names: Vec<&str> = resolved.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["identity"]);
    }

    #[test]
    fn test_exact_match_beats_glob() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
plugins:
  - name: specific
    kind: builtin
    hooks: [tool_pre_invoke]
  - name: general
    kind: builtin
    hooks: [tool_pre_invoke]
routes:
  - tool: "hr-*"
    plugins:
      - general
  - tool: hr-compensation
    plugins:
      - specific
"#;
        let config = parse_config(yaml).unwrap();
        let resolved =
            resolve_plugins_for_entity(&config, "tool", "hr-compensation", None, &no_tags());
        let names: Vec<&str> = resolved.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"specific"));
        assert!(!names.contains(&"general"));
    }

    #[test]
    fn test_plugin_ref_bare_name() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
plugins:
  - name: rate_limiter
    kind: builtin
    hooks: [tool_pre_invoke]
routes:
  - tool: get_compensation
    plugins:
      - rate_limiter
"#;
        let config = parse_config(yaml).unwrap();
        let resolved =
            resolve_plugins_for_entity(&config, "tool", "get_compensation", None, &no_tags());
        assert_eq!(resolved[0].name, "rate_limiter");
        assert!(resolved[0].config_overrides.is_none());
    }

    #[test]
    fn test_plugin_ref_with_overrides() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
plugins:
  - name: rate_limiter
    kind: builtin
    hooks: [tool_pre_invoke]
    config:
      max_requests: 100
routes:
  - tool: get_compensation
    plugins:
      - rate_limiter:
          config:
            max_requests: 10
"#;
        let config = parse_config(yaml).unwrap();
        let resolved =
            resolve_plugins_for_entity(&config, "tool", "get_compensation", None, &no_tags());
        assert_eq!(resolved[0].name, "rate_limiter");
        assert!(resolved[0].config_overrides.is_some());
        let overrides = resolved[0].config_overrides.as_ref().unwrap();
        assert_eq!(overrides["config"]["max_requests"], 10);
    }

    #[test]
    fn test_plugin_ref_mixed_bare_and_overrides() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
plugins:
  - name: rate_limiter
    kind: builtin
    hooks: [tool_pre_invoke]
  - name: pii_scanner
    kind: builtin
    hooks: [tool_pre_invoke]
routes:
  - tool: get_compensation
    plugins:
      - rate_limiter
      - pii_scanner:
          config:
            sensitivity: high
"#;
        let config = parse_config(yaml).unwrap();
        let resolved =
            resolve_plugins_for_entity(&config, "tool", "get_compensation", None, &no_tags());
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0].name, "rate_limiter");
        assert!(resolved[0].config_overrides.is_none());
        assert_eq!(resolved[1].name, "pii_scanner");
        assert!(resolved[1].config_overrides.is_some());
    }

    #[test]
    fn test_deduplication_preserves_order() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
global:
  policies:
    all:
      plugins: [a, b]
    pii:
      plugins: [b, c]
plugins:
  - name: a
    kind: builtin
    hooks: [tool_pre_invoke]
  - name: b
    kind: builtin
    hooks: [tool_pre_invoke]
  - name: c
    kind: builtin
    hooks: [tool_pre_invoke]
routes:
  - tool: get_compensation
    meta:
      tags: [pii]
"#;
        let config = parse_config(yaml).unwrap();
        let resolved =
            resolve_plugins_for_entity(&config, "tool", "get_compensation", None, &no_tags());
        let names: Vec<&str> = resolved.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_glob_trailing_wildcard() {
        let matcher = StringOrList::Single(Pattern::new("hr-*"));
        assert!(matcher.matches("hr-compensation"));
        assert!(matcher.matches("hr-benefits"));
        assert!(matcher.matches("hr-")); // empty match for *
        assert!(!matcher.matches("finance-report"));
        assert!(!matcher.matches("hr"));
    }

    #[test]
    fn test_wildcard_matches_everything() {
        let matcher = StringOrList::Single(Pattern::new("*"));
        assert!(matcher.matches("anything"));
        assert!(matcher.matches(""));
    }

    /// Regression for the security footgun: `*suffix` patterns were
    /// silently matching almost nothing because the previous matcher
    /// looked for `"*suffix"` as a literal prefix.
    #[test]
    fn test_glob_leading_wildcard() {
        let matcher = StringOrList::Single(Pattern::new("*-prod"));
        assert!(matcher.matches("foo-prod"));
        assert!(matcher.matches("-prod")); // empty match for *
        assert!(!matcher.matches("foo-staging"));
        assert!(!matcher.matches("prod"));
    }

    /// Regression for `prefix*suffix` patterns also broken before.
    #[test]
    fn test_glob_mid_wildcard() {
        let matcher = StringOrList::Single(Pattern::new("hr-*-v1"));
        assert!(matcher.matches("hr-comp-v1"));
        assert!(matcher.matches("hr--v1")); // empty match for *
        assert!(!matcher.matches("hr-comp-v2"));
        assert!(!matcher.matches("finance-comp-v1"));
    }

    /// Multiple-wildcard patterns must work everywhere `*` appears.
    #[test]
    fn test_glob_multiple_wildcards() {
        let matcher = StringOrList::Single(Pattern::new("*hr*comp*"));
        assert!(matcher.matches("hr-comp"));
        assert!(matcher.matches("xyz-hr-comp-foo"));
        assert!(!matcher.matches("hr-only"));
        assert!(!matcher.matches("comp-only"));
    }

    /// Regression for the OTHER security footgun: multi-star patterns
    /// like `**` were `trim_end_matches('*')`'d to `""` and then matched
    /// every name via `starts_with("")`. With wildmatch this is a
    /// degenerate-but-correct "match anything" pattern, equivalent to `*`.
    #[test]
    fn test_glob_multi_star_is_equivalent_to_single_star() {
        for pattern in &["**", "***", "*****"] {
            let matcher = StringOrList::Single(Pattern::new(*pattern));
            assert!(
                matcher.matches("anything"),
                "pattern {} should match",
                pattern
            );
            assert!(
                matcher.matches(""),
                "pattern {} should match empty",
                pattern
            );
        }
    }

    /// `WildMatch` is built once at deserialize / `Pattern::new` time and
    /// reused; this test just sanity-checks the round-trip through serde.
    #[test]
    fn test_pattern_round_trips_through_yaml() {
        let yaml = "tool: '*-prod'";
        #[derive(Deserialize, Serialize)]
        struct Wrap {
            tool: StringOrList,
        }
        let parsed: Wrap = serde_yaml::from_str(yaml).unwrap();
        assert!(parsed.tool.matches("foo-prod"));
        assert!(!parsed.tool.matches("foo-staging"));
        let back = serde_yaml::to_string(&parsed).unwrap();
        assert!(
            back.contains("*-prod"),
            "serialized YAML should preserve pattern: {}",
            back
        );
    }

    #[test]
    fn test_list_matches_any_member() {
        let matcher = StringOrList::List(vec![
            "get_compensation".to_string(),
            "get_benefits".to_string(),
        ]);
        assert!(matcher.matches("get_compensation"));
        assert!(matcher.matches("get_benefits"));
        assert!(!matcher.matches("send_email"));
    }

    #[test]
    fn test_validation_skipped_when_routing_disabled() {
        let yaml = r#"
plugins:
  - name: test
    kind: builtin
    hooks: [tool_pre_invoke]
routes:
  - meta:
      tags: [pii]
"#;
        let config = parse_config(yaml);
        assert!(config.is_ok());
    }

    // -- Scope matching tests --

    #[test]
    fn test_scope_match_selects_scoped_route() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
plugins:
  - name: scoped_plugin
    kind: builtin
    hooks: [tool_pre_invoke]
  - name: global_plugin
    kind: builtin
    hooks: [tool_pre_invoke]
routes:
  - tool: get_compensation
    meta:
      scope: hr-services
    plugins:
      - scoped_plugin
  - tool: get_compensation
    plugins:
      - global_plugin
"#;
        let config = parse_config(yaml).unwrap();

        // With matching scope — scoped route wins (more specific)
        let resolved = resolve_plugins_for_entity(
            &config,
            "tool",
            "get_compensation",
            Some("hr-services"),
            &no_tags(),
        );
        let names: Vec<&str> = resolved.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"scoped_plugin"));
        assert!(!names.contains(&"global_plugin"));

        // Without scope — global route matches
        let resolved =
            resolve_plugins_for_entity(&config, "tool", "get_compensation", None, &no_tags());
        let names: Vec<&str> = resolved.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"global_plugin"));
        assert!(!names.contains(&"scoped_plugin"));

        // With different scope — global route matches (scoped doesn't)
        let resolved = resolve_plugins_for_entity(
            &config,
            "tool",
            "get_compensation",
            Some("billing"),
            &no_tags(),
        );
        let names: Vec<&str> = resolved.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"global_plugin"));
        assert!(!names.contains(&"scoped_plugin"));
    }

    // -- Tag merging tests --

    #[test]
    fn test_host_tags_merged_with_route_tags() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
global:
  policies:
    pii:
      plugins: [pii_plugin]
    runtime_tag:
      plugins: [runtime_plugin]
plugins:
  - name: pii_plugin
    kind: builtin
    hooks: [tool_pre_invoke]
  - name: runtime_plugin
    kind: builtin
    hooks: [tool_pre_invoke]
routes:
  - tool: get_compensation
    meta:
      tags: [pii]
"#;
        let config = parse_config(yaml).unwrap();

        // Host provides a runtime tag that matches a policy group
        let mut host_tags = HashSet::new();
        host_tags.insert("runtime_tag".to_string());

        let resolved =
            resolve_plugins_for_entity(&config, "tool", "get_compensation", None, &host_tags);
        let names: Vec<&str> = resolved.iter().map(|r| r.name.as_str()).collect();

        // Both route's static tag (pii) and host's runtime tag activate their groups
        assert!(names.contains(&"pii_plugin"));
        assert!(names.contains(&"runtime_plugin"));
    }

    // -- When clause carried tests --

    #[test]
    fn test_when_clause_carried_on_resolved_plugins() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
plugins:
  - name: conditional_plugin
    kind: builtin
    hooks: [tool_pre_invoke]
routes:
  - tool: get_compensation
    when: "args.include_ssn == true"
    plugins:
      - conditional_plugin
"#;
        let config = parse_config(yaml).unwrap();
        let resolved =
            resolve_plugins_for_entity(&config, "tool", "get_compensation", None, &no_tags());
        assert_eq!(resolved[0].name, "conditional_plugin");
        assert_eq!(
            resolved[0].when.as_deref(),
            Some("args.include_ssn == true")
        );
    }

    #[test]
    fn test_when_clause_not_on_policy_group_plugins() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
global:
  policies:
    all:
      plugins: [global_plugin]
plugins:
  - name: global_plugin
    kind: builtin
    hooks: [tool_pre_invoke]
  - name: route_plugin
    kind: builtin
    hooks: [tool_pre_invoke]
routes:
  - tool: get_compensation
    when: "args.sensitive == true"
    plugins:
      - route_plugin
"#;
        let config = parse_config(yaml).unwrap();
        let resolved =
            resolve_plugins_for_entity(&config, "tool", "get_compensation", None, &no_tags());

        // global_plugin has no when clause (from all group)
        let global = resolved.iter().find(|r| r.name == "global_plugin").unwrap();
        assert!(global.when.is_none());

        // route_plugin carries the route's when clause
        let route = resolved.iter().find(|r| r.name == "route_plugin").unwrap();
        assert_eq!(route.when.as_deref(), Some("args.sensitive == true"));
    }
}
