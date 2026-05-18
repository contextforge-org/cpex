// Location: ./crates/apl-cpex/src/visitor.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// `AplConfigVisitor` — the cpex-core `ConfigVisitor` implementation that
// stacks the unified-config hierarchy (global → defaults → tag bundles
// → routes) into a single `CompiledRoute` per route and installs an
// [`AplRouteHandler`] for each phase via `PluginManager::annotate_route`.
//
// # Hierarchy stacking
//
// Each `visit_*` call carries a single block of raw YAML. The visitor
// finds the `apl:` sub-block (if any), compiles it to a `CompiledRoute`,
// and stashes it in interior state:
//
//   visit_global       → state.global_layer
//   visit_default      → state.default_layers[entity_type]
//   visit_policy_bundle → state.tag_layers[tag]
//   visit_route        → build effective route by layering and annotate.
//
// At `visit_route` we layer least-to-most-specific:
//
//   effective = global
//   effective.apply_layer(default_layer_for(entity_type))
//   for tag in route.meta.tags { effective.apply_layer(tag_layer(tag)) }
//   effective.apply_layer(route_apl_block)
//
// then construct one `AplRouteHandler` per phase (Pre, Post) and call
// `annotate_route` for each `(entity_type, entity_name, scope, hook)`.
//
// # Hook names
//
// v0 binds the `cmf.tool_pre_invoke` hook to the Pre handler and
// `cmf.tool_post_invoke` to the Post handler — see [`HOOK_PRE`] / [`HOOK_POST`].
// Routes that match `prompt:` / `resource:` / `llm:` reuse the same hook
// names (cpex-core annotation keying is on entity-name; the hook is the
// phase channel).

use std::collections::HashMap;
use std::sync::{Arc, RwLock, Weak};

use cpex_core::config::RouteEntry;
use cpex_core::manager::PluginManager;
use cpex_core::plugin::PluginConfig;
use cpex_core::visitor::{ConfigVisitor, VisitorError};

use apl_core::parser::compile_policy_block_value;
use apl_core::plugin_decl::{PluginDeclaration, PluginRegistry};
use apl_core::rules::CompiledRoute;

use crate::dispatch_plan::DispatchCache;
use crate::route_handler::{AplRouteHandler, Phase};
use crate::session_store::SessionStore;
use apl_core::step::PdpResolver;

/// CMF hook name driven by the Pre handler. v0 maps the unified-config
/// `args` + `policy` phases here.
pub const HOOK_PRE: &str = "cmf.tool_pre_invoke";
/// CMF hook name driven by the Post handler. v0 maps the unified-config
/// `result` + `post_policy` phases here.
pub const HOOK_POST: &str = "cmf.tool_post_invoke";

/// Interior state accumulated as the manager walks the visitor.
/// `plugin_registry` is populated by `visit_plugins` (called once per
/// load); the layer fields are populated as the visitor walks
/// `global` / `defaults` / `policies` / `routes`.
#[derive(Default)]
struct VisitorState {
    plugin_registry: PluginRegistry,
    global_layer: Option<CompiledRoute>,
    default_layers: HashMap<String, CompiledRoute>,
    tag_layers: HashMap<String, CompiledRoute>,
}

/// APL implementation of [`cpex_core::visitor::ConfigVisitor`]. Construct
/// once per host with the shared infrastructure (dispatch cache, session
/// store, manager handle, optional PDP) and register with
/// `PluginManager::register_visitor` before calling `load_config_yaml`.
///
/// The plugin registry is populated automatically from cpex-core's
/// already-parsed `Vec<PluginConfig>` via the `visit_plugins` hook —
/// hosts don't need to pre-parse the root `plugins:` block.
pub struct AplConfigVisitor {
    state: RwLock<VisitorState>,
    dispatch_cache: Arc<DispatchCache>,
    session_store: Arc<dyn SessionStore>,
    manager: Weak<PluginManager>,
    /// Shared PDP resolver — typically a `PdpRouter` registered with all
    /// the dialects the host supports (Cedar, OPA, NeMo). Each route
    /// handler holds an `Arc` clone.
    pdp: Option<Arc<dyn PdpResolver>>,
    /// Baseline capabilities granted to every synthetic `AplRouteHandler`
    /// the visitor installs. Unioned with the per-route plugin
    /// capability set so APL predicates that touch extensions
    /// (`require(authenticated)` needs `read_subject`, etc.) work even
    /// when no plugins are referenced. Hosts that want strict gating
    /// can set this to an empty set.
    base_capabilities: std::collections::HashSet<String>,
}

impl AplConfigVisitor {
    pub fn new(
        dispatch_cache: Arc<DispatchCache>,
        session_store: Arc<dyn SessionStore>,
        manager: Weak<PluginManager>,
    ) -> Self {
        Self {
            state: RwLock::new(VisitorState::default()),
            dispatch_cache,
            session_store,
            manager,
            pdp: None,
            base_capabilities: default_base_capabilities(),
        }
    }

    /// Install a shared PDP resolver — `PdpRouter` is the typical
    /// choice when the host needs Cedar **and** OPA **and** NeMo at the
    /// same time. Routes that don't declare `pdp(...)` steps never
    /// touch this; routes that do without a resolver installed will
    /// surface `PdpError::NoResolver` at evaluation time.
    pub fn with_pdp(mut self, pdp: Arc<dyn PdpResolver>) -> Self {
        self.pdp = Some(pdp);
        self
    }

    /// Replace the baseline capability set granted to every installed
    /// `AplRouteHandler`. Default covers read-only attributes APL
    /// predicates commonly touch (subject, role, labels, delegation,
    /// agent). Tighten this when the deployment's policy plugins
    /// don't need broad reads — every cap removed is one fewer
    /// extension slot a buggy predicate can leak through.
    pub fn with_base_capabilities(
        mut self,
        caps: std::collections::HashSet<String>,
    ) -> Self {
        self.base_capabilities = caps;
        self
    }
}

/// Read-only baseline for APL predicates: enough to make
/// `authenticated`, `role.*`, `subject.*`, `security.labels`,
/// `delegated`, `delegation.*`, and `agent.*` evaluate correctly.
/// Excludes all *write* capabilities — those are granted on demand by
/// the per-route plugin union when a plugin declares
/// `append_labels` / `append_delegation` / `write_headers`.
fn default_base_capabilities() -> std::collections::HashSet<String> {
    [
        "read_subject",
        "read_labels",
        "read_delegation",
        "read_agent",
        "read_meta",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

impl ConfigVisitor for AplConfigVisitor {
    fn name(&self) -> &str {
        "apl"
    }

    fn visit_plugins(
        &self,
        _mgr: &Arc<PluginManager>,
        plugins: &[PluginConfig],
    ) -> Result<(), VisitorError> {
        // Translate cpex-core's typed PluginConfig into apl-core's
        // PluginDeclaration. Field-for-field except `capabilities` is a
        // `HashSet` on the cpex side and a `Vec` on the apl side, and
        // `config` is wrapped in `serde_yaml::Value::Mapping` to match
        // apl-core's opaque shape. cpex-core has already validated
        // uniqueness by this point so we don't re-check.
        let mut state = self.state.write().unwrap_or_else(|p| p.into_inner());
        state.plugin_registry.clear();
        for cfg in plugins {
            let decl = PluginDeclaration {
                name: cfg.name.clone(),
                kind: cfg.kind.clone(),
                hooks: cfg.hooks.clone(),
                capabilities: cfg.capabilities.iter().cloned().collect(),
                config: plugin_config_to_yaml(&cfg.config),
                on_error: Some(on_error_to_string(&cfg.on_error)),
                extra: HashMap::new(),
            };
            state.plugin_registry.insert(cfg.name.clone(), decl);
        }
        Ok(())
    }

    fn visit_global(
        &self,
        _mgr: &Arc<PluginManager>,
        yaml: &serde_yaml::Value,
    ) -> Result<(), VisitorError> {
        let Some(apl_block) = apl_subblock(yaml) else {
            return Ok(());
        };
        let compiled = compile_policy_block_value("global.apl", apl_block)
            .map_err(|e| Box::new(e) as VisitorError)?;
        self.state
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .global_layer = Some(compiled);
        Ok(())
    }

    fn visit_default(
        &self,
        _mgr: &Arc<PluginManager>,
        entity_type: &str,
        yaml: &serde_yaml::Value,
    ) -> Result<(), VisitorError> {
        let Some(apl_block) = apl_subblock(yaml) else {
            return Ok(());
        };
        let source = format!("global.defaults.{}.apl", entity_type);
        let compiled = compile_policy_block_value(&source, apl_block)
            .map_err(|e| Box::new(e) as VisitorError)?;
        self.state
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .default_layers
            .insert(entity_type.to_string(), compiled);
        Ok(())
    }

    fn visit_policy_bundle(
        &self,
        _mgr: &Arc<PluginManager>,
        tag: &str,
        yaml: &serde_yaml::Value,
    ) -> Result<(), VisitorError> {
        let Some(apl_block) = apl_subblock(yaml) else {
            return Ok(());
        };
        let source = format!("global.policies.{}.apl", tag);
        let compiled = compile_policy_block_value(&source, apl_block)
            .map_err(|e| Box::new(e) as VisitorError)?;
        self.state
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .tag_layers
            .insert(tag.to_string(), compiled);
        Ok(())
    }

    fn visit_route(
        &self,
        mgr: &Arc<PluginManager>,
        yaml: &serde_yaml::Value,
        parsed: &RouteEntry,
    ) -> Result<(), VisitorError> {
        // Extract the route's APL block (if any) and the entity identity
        // we need for annotate_route. A route without an APL block AND
        // without inherited layers contributes nothing — skip.
        let route_apl = apl_subblock(yaml);
        let (entity_type, entity_names) = match entity_identity(parsed) {
            Some(e) => e,
            None => {
                tracing::warn!(
                    "APL visitor: route has no tool/resource/prompt/llm match — skipping",
                );
                return Ok(());
            }
        };
        let scope = parsed.meta.as_ref().and_then(|m| m.scope.clone());
        let tags: Vec<String> = parsed
            .meta
            .as_ref()
            .map(|m| m.tags.clone())
            .unwrap_or_default();

        // Snapshot the plugin registry once outside the per-entity loop.
        // `visit_plugins` populated this before any `visit_route` call;
        // routes share the same registry, so cloning into an `Arc` once
        // and handing clones to each handler is cheaper than re-reading
        // the RwLock per entity.
        let plugin_registry = {
            let state = self.state.read().unwrap_or_else(|p| p.into_inner());
            Arc::new(state.plugin_registry.clone())
        };

        for entity_name in &entity_names {
            // route_key is what `DispatchCache` keys on, so it must
            // disambiguate scoped vs unscoped routes for the same
            // entity — otherwise two same-named annotations share one
            // cached plan and the second's overrides leak into the first.
            let route_key = match &scope {
                Some(s) => format!("{}:{}@{}", entity_type, entity_name, s),
                None => format!("{}:{}", entity_type, entity_name),
            };
            let state = self.state.read().unwrap_or_else(|p| p.into_inner());

            // Stack least-to-most-specific. Each apply_layer call appends
            // policy/post_policy steps and merges args/result/plugin_overrides
            // by field; the resulting CompiledRoute represents the route's
            // effective policy in evaluation order.
            let mut effective = CompiledRoute::new(&route_key);
            if let Some(layer) = state.global_layer.clone() {
                effective.apply_layer(layer);
            }
            if let Some(layer) = state.default_layers.get(entity_type).cloned() {
                effective.apply_layer(layer);
            }
            for tag in &tags {
                if let Some(layer) = state.tag_layers.get(tag).cloned() {
                    effective.apply_layer(layer);
                }
            }
            drop(state);

            if let Some(block) = route_apl {
                let source = format!("routes.{}.apl", route_key);
                let route_layer = compile_policy_block_value(&source, block)
                    .map_err(|e| Box::new(e) as VisitorError)?;
                effective.apply_layer(route_layer);
            }

            // No layers contributed anything? Don't install a handler — the
            // route falls back to cpex-core's plugin-chain execution.
            if effective.declared_phases().is_empty() {
                continue;
            }

            let route_arc = Arc::new(effective);

            // Install Pre + Post handlers. Each handler instance is bound to
            // ONE phase so the executor can pick the right entry-point off
            // the (entity_type, entity_name, scope, hook_name) key.
            install_handler(
                mgr,
                entity_type,
                entity_name,
                scope.clone(),
                HOOK_PRE,
                Phase::Pre,
                Arc::clone(&route_arc),
                &plugin_registry,
                &self.dispatch_cache,
                &self.session_store,
                &self.manager,
                self.pdp.clone(),
                &self.base_capabilities,
            );
            install_handler(
                mgr,
                entity_type,
                entity_name,
                scope.clone(),
                HOOK_POST,
                Phase::Post,
                route_arc,
                &plugin_registry,
                &self.dispatch_cache,
                &self.session_store,
                &self.manager,
                self.pdp.clone(),
                &self.base_capabilities,
            );
        }

        Ok(())
    }
}

// =====================================================================
// Helpers
// =====================================================================

#[allow(clippy::too_many_arguments)]
fn install_handler(
    mgr: &Arc<PluginManager>,
    entity_type: &str,
    entity_name: &str,
    scope: Option<String>,
    hook_name: &str,
    phase: Phase,
    route: Arc<CompiledRoute>,
    plugin_registry: &Arc<PluginRegistry>,
    dispatch_cache: &Arc<DispatchCache>,
    session_store: &Arc<dyn SessionStore>,
    manager: &Weak<PluginManager>,
    pdp: Option<Arc<dyn PdpResolver>>,
    base_capabilities: &std::collections::HashSet<String>,
) {
    // Capability gating at the synthetic-handler boundary. cpex-core's
    // executor calls `filter_extensions(&ext, &caps)` before every
    // handler invoke — including this one. If the synthetic handler
    // has fewer capabilities than its downstream plugins need, the
    // executor strips extensions on the way in (so APL predicates and
    // downstream plugins see empty views) and rejects mutations on the
    // way out (label / delegation appends fail monotonicity checks).
    //
    // Granted caps = union of every plugin's caps (with per-route
    // overrides applied) ∪ host-supplied baseline. The baseline
    // typically covers read-only attributes APL predicates touch
    // (`subject.*`, `role.*`, `delegated`, …) even when no plugins are
    // referenced.
    let mut capabilities = base_capabilities.clone();
    capabilities.extend(crate::dispatch_plan::route_capability_union(&route, plugin_registry));

    let plugin_config = PluginConfig {
        name: format!(
            "apl::{}::{}::{}",
            entity_type,
            entity_name,
            if phase == Phase::Pre { "pre" } else { "post" }
        ),
        kind: "builtin".to_string(),
        // The annotated handler covers exactly one CMF hook name.
        hooks: vec![hook_name.to_string()],
        capabilities,
        ..Default::default()
    };
    let mut handler =
        AplRouteHandler::new(
            plugin_config.clone(),
            route,
            phase,
            Arc::clone(plugin_registry),
            Arc::clone(dispatch_cache),
            Arc::clone(session_store),
            manager.clone(),
        );
    if let Some(pdp) = pdp {
        handler = handler.with_pdp(pdp);
    }
    mgr.annotate_route(
        entity_type.to_string(),
        entity_name.to_string(),
        scope,
        hook_name.to_string(),
        Arc::new(handler),
        plugin_config,
    );
}

/// Pick the route's entity identities from the first non-None match
/// field. v0: tool > resource > prompt > llm precedence. A list-form
/// match (`tool: [a, b]`) yields one annotation per element so each
/// request gets routed by its specific name.
fn entity_identity(route: &RouteEntry) -> Option<(&'static str, Vec<String>)> {
    if let Some(t) = &route.tool {
        return Some(("tool", names_of(t)));
    }
    if let Some(r) = &route.resource {
        return Some(("resource", names_of(r)));
    }
    if let Some(p) = &route.prompt {
        return Some(("prompt", names_of(p)));
    }
    if let Some(l) = &route.llm {
        return Some(("llm", names_of(l)));
    }
    None
}

fn names_of(sol: &cpex_core::config::StringOrList) -> Vec<String> {
    match sol {
        cpex_core::config::StringOrList::Single(p) => vec![p.as_str().to_string()],
        cpex_core::config::StringOrList::List(v) => v.clone(),
    }
}

/// Bridge cpex-core's JSON-based `Option<serde_json::Value>` config slot
/// into apl-core's `Option<serde_yaml::Value>` shape. JSON is a strict
/// subset of YAML's value model so this is round-trip safe; failure
/// here would only happen if `serde_yaml::to_value` rejects a value
/// `serde_json::Value` already accepted (in practice: never).
fn plugin_config_to_yaml(cfg: &Option<serde_json::Value>) -> Option<serde_yaml::Value> {
    cfg.as_ref().and_then(|v| serde_yaml::to_value(v).ok())
}

/// Map cpex-core's `OnError` enum onto the string shape apl-core's
/// `PluginDeclaration` carries (kept stringly-typed there because the
/// APL spec also allows custom orchestrator-defined error modes).
fn on_error_to_string(on_err: &cpex_core::plugin::OnError) -> String {
    on_err.to_string()
}

/// Pull the `apl:` sub-block out of a section's raw YAML. Returns `None`
/// when absent or null — callers treat that as "no contribution from
/// this section" and move on.
fn apl_subblock(yaml: &serde_yaml::Value) -> Option<&serde_yaml::Value> {
    let block = yaml.get("apl")?;
    if block.is_null() {
        None
    } else {
        Some(block)
    }
}
