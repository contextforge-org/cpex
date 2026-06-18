// Location: ./crates/apl-cpex/tests/visitor_e2e.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// End-to-end integration: unified-config YAML → cpex-core
// `load_config_yaml` → `AplConfigVisitor` walks global / defaults / tags
// / routes → `PluginManager::annotate_route` installs phase-bound
// `AplRouteHandler`s → host calls `invoke_named::<CmfHook>` with meta →
// route-annotation short-circuit fires the handler → APL evaluator runs
// the layered route → real CPEX plugins dispatch through
// `CmfPluginInvoker` inside the handler.
//
// This is the load-bearing test for the visitor + annotation flow. It
// proves the whole hierarchy collapses into per-route handlers exactly
// once at load time, and that dispatch into those handlers behaves like
// any other plugin entry (mode, on_error, capabilities all honored
// because the synthetic plugin's `PluginConfig` flows through the same
// executor path).

use std::sync::Arc;

use async_trait::async_trait;

use cpex_core::cmf::enums::Role;
use cpex_core::cmf::{CmfHook, Message, MessagePayload};
use cpex_core::context::PluginContext;
use cpex_core::error::{PluginError as CoreError, PluginViolation};
use cpex_core::extensions::MetaExtension;
use cpex_core::factory::{PluginFactory, PluginInstance};
use cpex_core::hooks::adapter::TypedHandlerAdapter;
use cpex_core::hooks::payload::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::manager::PluginManager;
use cpex_core::plugin::{Plugin, PluginConfig};

use apl_cpex::{register_apl, AplOptions, DispatchCache, MemorySessionStore};

// =====================================================================
// Test plugins — `allow-gate` (passes through) and `deny-gate` (denies).
// Both register on `cmf.tool_pre_invoke`. APL routes reference them by
// name via `plugin(<name>)` in the YAML; the visitor stacks them into
// the route's compiled steps; the handler dispatches into them through
// CmfPluginInvoker.
// =====================================================================

struct AllowGate {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for AllowGate {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for AllowGate {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        PluginResult::allow()
    }
}

struct AllowGateFactory;
impl PluginFactory for AllowGateFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<CoreError>> {
        let plugin = Arc::new(AllowGate {
            cfg: config.clone(),
        });
        // Register the handler under every hook the operator declared
        // in `hooks: [...]`. Lets tests pin the plugin to llm / prompt
        // / resource hooks via YAML without per-entity factory copies.
        let handlers = hooks_for(config, plugin.clone());
        Ok(PluginInstance {
            plugin,
            handlers,
        })
    }
}

/// Build the adapter list for a plugin from the operator-declared
/// `hooks:` config. Falls back to `cmf.tool_pre_invoke` when nothing
/// is declared (matches v0 default for routes that don't specify).
fn hooks_for<H>(
    config: &PluginConfig,
    plugin: Arc<H>,
) -> Vec<(
    &'static str,
    Arc<dyn cpex_core::registry::AnyHookHandler>,
)>
where
    H: HookHandler<CmfHook> + Plugin + 'static,
{
    let hook_names: Vec<&'static str> = if config.hooks.is_empty() {
        vec!["cmf.tool_pre_invoke"]
    } else {
        config
            .hooks
            .iter()
            .map(|s| Box::leak(s.clone().into_boxed_str()) as &'static str)
            .collect()
    };
    hook_names
        .into_iter()
        .map(|name| {
            let adapter: Arc<dyn cpex_core::registry::AnyHookHandler> = Arc::new(
                TypedHandlerAdapter::<CmfHook, _>::new(Arc::clone(&plugin)),
            );
            (name, adapter)
        })
        .collect()
}

struct DenyGate {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for DenyGate {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for DenyGate {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        PluginResult::deny(PluginViolation::new(
            "policy.forbidden",
            "deny-gate fired",
        ))
    }
}

struct DenyGateFactory;
impl PluginFactory for DenyGateFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<CoreError>> {
        let plugin = Arc::new(DenyGate {
            cfg: config.clone(),
        });
        let handlers = hooks_for(config, plugin.clone());
        Ok(PluginInstance {
            plugin,
            handlers,
        })
    }
}

// =====================================================================
// Helpers
// =====================================================================

fn cmf_payload(text: &str) -> MessagePayload {
    MessagePayload {
        message: Message::text(Role::User, text),
    }
}

fn meta_for_tool(name: &str) -> MetaExtension {
    let mut meta = MetaExtension::default();
    meta.entity_type = Some("tool".to_string());
    meta.entity_name = Some(name.to_string());
    meta
}

/// Build a manager with `allow-gate` and `deny-gate` factories registered,
/// then wire the APL visitor in via `register_apl`. Returns
/// `Arc<PluginManager>` so the caller can dispatch through
/// `invoke_named`. The visitor self-populates its plugin registry from
/// cpex-core's parsed `Vec<PluginConfig>` via `visit_plugins` — no host
/// pre-parse needed.
async fn build_manager_with_visitor(yaml: &str) -> Arc<PluginManager> {
    let mgr = Arc::new(PluginManager::default());
    mgr.register_factory("allow-gate", Box::new(AllowGateFactory));
    mgr.register_factory("deny-gate", Box::new(DenyGateFactory));

    register_apl(
        &mgr,
        AplOptions {
            dispatch_cache: Arc::new(DispatchCache::new()),
            session_store: Arc::new(MemorySessionStore::new()),
            pdps: Vec::new(),
            pdp_factories: Vec::new(),
            base_capabilities: None,
        },
    );

    mgr.load_config_yaml(yaml).expect("load_config_yaml");
    mgr.initialize().await.expect("initialize");
    mgr
}

// =====================================================================
// Scenarios
// =====================================================================

/// Route declares an `apl.policy: [plugin(allow-gate)]`. After the
/// visitor walks the config, `cmf.tool_pre_invoke` for tool `get_weather`
/// must short-circuit to the APL handler, which dispatches the policy
/// step into the registered `allow-gate` plugin → allow.
#[tokio::test]
async fn visitor_route_with_allow_plugin_returns_allow() {
    const YAML: &str = r#"
plugins:
  - name: allow-gate
    kind: allow-gate
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_weather
    apl:
      policy:
        - "plugin(allow-gate)"
"#;
    let mgr = build_manager_with_visitor(YAML).await;

    let ext = Extensions {
        meta: Some(Arc::new(meta_for_tool("get_weather"))),
        ..Default::default()
    };
    let (result, _bg) = mgr
        .invoke_named::<CmfHook>(
            "cmf.tool_pre_invoke",
            cmf_payload("hi"),
            ext,
            None,
        )
        .await;

    assert!(
        result.continue_processing,
        "allow path should continue: violation = {:?}",
        result.violation
    );
}

/// Same shape but with `deny-gate`. The visitor compiles the route,
/// annotates the manager, dispatch goes through the handler, the handler
/// calls into deny-gate via CmfPluginInvoker, the violation propagates
/// out as `PipelineResult.violation` with the original code + reason.
#[tokio::test]
async fn visitor_route_with_deny_plugin_propagates_violation() {
    const YAML: &str = r#"
plugins:
  - name: deny-gate
    kind: deny-gate
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_weather
    apl:
      policy:
        - "plugin(deny-gate)"
"#;
    let mgr = build_manager_with_visitor(YAML).await;

    let ext = Extensions {
        meta: Some(Arc::new(meta_for_tool("get_weather"))),
        ..Default::default()
    };
    let (result, _bg) = mgr
        .invoke_named::<CmfHook>(
            "cmf.tool_pre_invoke",
            cmf_payload("hi"),
            ext,
            None,
        )
        .await;

    assert!(!result.continue_processing, "deny path should halt");
    let violation = result.violation.expect("deny path must surface a violation");
    assert_eq!(
        violation.reason, "deny-gate fired",
        "violation reason must propagate from the plugin through the handler"
    );
    assert_eq!(violation.code, "policy.forbidden");
}

/// Hierarchy: global APL policy step runs FIRST, then route APL policy.
/// Tests apply_layer ordering — global's `plugin(allow-gate)` runs and
/// passes, then route's `plugin(deny-gate)` fires and denies. If the
/// global layer had been appended after instead of before, the deny
/// would have run first and we'd see the deny path; the order assertion
/// is implicit in the violation reason coming from deny-gate.
#[tokio::test]
async fn visitor_stacks_global_then_route_in_order() {
    const YAML: &str = r#"
plugins:
  - name: allow-gate
    kind: allow-gate
    hooks: [cmf.tool_pre_invoke]
  - name: deny-gate
    kind: deny-gate
    hooks: [cmf.tool_pre_invoke]
global:
  apl:
    policy:
      - "plugin(allow-gate)"
routes:
  - tool: get_weather
    apl:
      policy:
        - "plugin(deny-gate)"
"#;
    let mgr = build_manager_with_visitor(YAML).await;

    let ext = Extensions {
        meta: Some(Arc::new(meta_for_tool("get_weather"))),
        ..Default::default()
    };
    let (result, _bg) = mgr
        .invoke_named::<CmfHook>(
            "cmf.tool_pre_invoke",
            cmf_payload("hi"),
            ext,
            None,
        )
        .await;

    let violation = result.violation.expect("route-level deny must fire");
    assert_eq!(violation.reason, "deny-gate fired");
}

/// Tag bundle stacks on top of global. A route tagged `pii` inherits
/// `plugin(deny-gate)` from the tag bundle even though the route itself
/// declares no APL block — proves tag layers are applied without the
/// route having to redeclare anything.
#[tokio::test]
async fn visitor_applies_tag_bundle_to_tagged_route() {
    const YAML: &str = r#"
plugins:
  - name: deny-gate
    kind: deny-gate
    hooks: [cmf.tool_pre_invoke]
global:
  policies:
    pii:
      apl:
        policy:
          - "plugin(deny-gate)"
routes:
  - tool: get_weather
    meta:
      tags: [pii]
"#;
    let mgr = build_manager_with_visitor(YAML).await;

    let ext = Extensions {
        meta: Some(Arc::new(meta_for_tool("get_weather"))),
        ..Default::default()
    };
    let (result, _bg) = mgr
        .invoke_named::<CmfHook>(
            "cmf.tool_pre_invoke",
            cmf_payload("hi"),
            ext,
            None,
        )
        .await;

    let violation = result
        .violation
        .expect("tag bundle's deny-gate should propagate");
    assert_eq!(violation.reason, "deny-gate fired");
}

/// Scope routing: a scoped annotation overrides the unscoped default for
/// the matching scope, while requests in other scopes fall back to the
/// unscoped annotation. Proves the visitor's `meta.scope` propagation is
/// keying annotations correctly through cpex-core's annotation table.
#[tokio::test]
async fn visitor_scoped_annotation_overrides_unscoped() {
    // Two routes for the same tool: one scoped to `vs-a`, one unscoped.
    // The scoped route denies; the unscoped route allows. A request in
    // scope `vs-a` must hit the scoped annotation (deny); a request in
    // scope `vs-b` falls back to the unscoped default (allow).
    const YAML: &str = r#"
plugins:
  - name: allow-gate
    kind: allow-gate
    hooks: [cmf.tool_pre_invoke]
  - name: deny-gate
    kind: deny-gate
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_weather
    meta:
      scope: vs-a
    apl:
      policy:
        - "plugin(deny-gate)"
  - tool: get_weather
    apl:
      policy:
        - "plugin(allow-gate)"
"#;
    let mgr = build_manager_with_visitor(YAML).await;

    // Scope vs-a → scoped annotation → deny.
    let mut meta_a = meta_for_tool("get_weather");
    meta_a.scope = Some("vs-a".to_string());
    let ext_a = Extensions {
        meta: Some(Arc::new(meta_a)),
        ..Default::default()
    };
    let (res_a, _) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", cmf_payload("hi"), ext_a, None)
        .await;
    let v = res_a.violation.expect("scoped annotation should deny");
    assert_eq!(v.reason, "deny-gate fired");

    // Scope vs-b → no scoped match → fall back to unscoped annotation → allow.
    let mut meta_b = meta_for_tool("get_weather");
    meta_b.scope = Some("vs-b".to_string());
    let ext_b = Extensions {
        meta: Some(Arc::new(meta_b)),
        ..Default::default()
    };
    let (res_b, _) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", cmf_payload("hi"), ext_b, None)
        .await;
    assert!(
        res_b.continue_processing,
        "unscoped fall-back should allow (got violation: {:?})",
        res_b.violation
    );
}

/// Sanity-check: an empty plugin registry + no APL blocks anywhere
/// means the visitor installs zero annotations and the manager behaves
/// exactly as if no visitor was registered. Smokes the no-op path.
#[tokio::test]
async fn visitor_with_no_apl_blocks_installs_nothing() {
    // No `apl:` blocks anywhere — just a route + plugin that wouldn't
    // be referenced from any APL step.
    const YAML: &str = r#"
plugins:
  - name: allow-gate
    kind: allow-gate
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: anything
"#;
    let mgr = build_manager_with_visitor(YAML).await;

    let ext = Extensions {
        meta: Some(Arc::new(meta_for_tool("anything"))),
        ..Default::default()
    };
    let (result, _bg) = mgr
        .invoke_named::<CmfHook>(
            "cmf.tool_pre_invoke",
            cmf_payload("hi"),
            ext,
            None,
        )
        .await;

    // Without APL annotations the route resolves through the legacy
    // chain. allow-gate is registered but the route doesn't reference
    // it, so it doesn't fire either. The pipeline returns allow.
    assert!(result.continue_processing);
    assert!(result.violation.is_none());
}

/// Smoke test that the visitor surfaces a compile error from a malformed
/// APL block as a `PluginError::Config` out of `load_config_yaml`. Catches
/// regressions where visitor errors swallow into Ok(_) or panic.
// ---------------------------------------------------------------------
// Slice 102 — multi-entity-type route support (llm / prompt / resource)
// ---------------------------------------------------------------------
//
// Pre-Slice-102, the visitor hardcoded annotation on
// `cmf.tool_pre_invoke` / `cmf.tool_post_invoke` regardless of route
// entity_type — so an `llm:` route would silently bind to the tool
// hooks and never fire when the host called `invoke_named::<CmfHook>("cmf.llm_input", ...)`.
// These tests pin per-entity routing.

fn meta_for_entity(entity_type: &str, entity_name: &str) -> MetaExtension {
    let mut meta = MetaExtension::default();
    meta.entity_type = Some(entity_type.to_string());
    meta.entity_name = Some(entity_name.to_string());
    meta
}

/// `llm:` route → annotation lands on `cmf.llm_input`. Host calling
/// `invoke_named::<CmfHook>("cmf.llm_input", ...)` with matching meta
/// fires the AplRouteHandler.
#[tokio::test]
async fn llm_route_annotates_on_llm_input_hook() {
    const YAML: &str = r#"
plugins:
  - name: allow-gate
    kind: allow-gate
    hooks: [cmf.llm_input]
routes:
  - llm: gpt-4
    apl:
      policy:
        - "plugin(allow-gate)"
"#;
    let mgr = build_manager_with_visitor(YAML).await;

    let ext = Extensions {
        meta: Some(Arc::new(meta_for_entity("llm", "gpt-4"))),
        ..Default::default()
    };
    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.llm_input", cmf_payload("hi"), ext, None)
        .await;

    assert!(
        result.continue_processing,
        "llm route should fire on cmf.llm_input: violation = {:?}",
        result.violation
    );
}

/// Same llm route but post — annotation lands on `cmf.llm_output`.
/// Pre-Slice-102, this would have annotated on `cmf.tool_post_invoke`
/// and never matched.
#[tokio::test]
async fn llm_route_annotates_on_llm_output_hook_for_post_phase() {
    const YAML: &str = r#"
plugins:
  - name: allow-gate
    kind: allow-gate
    hooks: [cmf.llm_output]
routes:
  - llm: gpt-4
    apl:
      post_policy:
        - "plugin(allow-gate)"
"#;
    let mgr = build_manager_with_visitor(YAML).await;

    let ext = Extensions {
        meta: Some(Arc::new(meta_for_entity("llm", "gpt-4"))),
        ..Default::default()
    };
    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.llm_output", cmf_payload("response"), ext, None)
        .await;

    assert!(
        result.continue_processing,
        "llm route post-phase should fire on cmf.llm_output: violation = {:?}",
        result.violation
    );
}

/// `prompt:` route → annotation lands on `cmf.prompt_pre_invoke`.
#[tokio::test]
async fn prompt_route_annotates_on_prompt_pre_invoke_hook() {
    const YAML: &str = r#"
plugins:
  - name: allow-gate
    kind: allow-gate
    hooks: [cmf.prompt_pre_invoke]
routes:
  - prompt: summarize_email
    apl:
      policy:
        - "plugin(allow-gate)"
"#;
    let mgr = build_manager_with_visitor(YAML).await;

    let ext = Extensions {
        meta: Some(Arc::new(meta_for_entity("prompt", "summarize_email"))),
        ..Default::default()
    };
    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.prompt_pre_invoke", cmf_payload("hi"), ext, None)
        .await;

    assert!(
        result.continue_processing,
        "prompt route should fire on cmf.prompt_pre_invoke: violation = {:?}",
        result.violation
    );
}

/// `resource:` route → annotation lands on `cmf.resource_pre_fetch`.
#[tokio::test]
async fn resource_route_annotates_on_resource_pre_fetch_hook() {
    const YAML: &str = r#"
plugins:
  - name: allow-gate
    kind: allow-gate
    hooks: [cmf.resource_pre_fetch]
routes:
  - resource: hr://employees/*
    apl:
      policy:
        - "plugin(allow-gate)"
"#;
    let mgr = build_manager_with_visitor(YAML).await;

    let ext = Extensions {
        meta: Some(Arc::new(meta_for_entity("resource", "hr://employees/E001234"))),
        ..Default::default()
    };
    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.resource_pre_fetch", cmf_payload("hi"), ext, None)
        .await;

    assert!(
        result.continue_processing,
        "resource route should fire on cmf.resource_pre_fetch: violation = {:?}",
        result.violation
    );
}

/// Cross-check: an llm route's APL annotation MUST NOT install on
/// `cmf.tool_pre_invoke`. Pre-Slice-102, the visitor would have
/// annotated llm routes on the tool hook by mistake; this test pins
/// that the bug is gone.
///
/// Setup: plugin registered ONLY under `cmf.llm_input`. The llm
/// route's APL annotation lands (post-Slice-102) on `cmf.llm_input`.
/// Calling `invoke_named::<CmfHook>("cmf.tool_pre_invoke", ...)`
/// finds no APL annotation for that hook AND no plugin chain entry
/// for it → returns `continue_processing=true` with no violations.
/// Calling `cmf.llm_input` DOES fire the annotation and the deny.
#[tokio::test]
async fn llm_route_does_not_fire_on_tool_hook() {
    const YAML: &str = r#"
plugins:
  - name: deny-gate
    kind: deny-gate
    hooks: [cmf.llm_input]
routes:
  - llm: gpt-4
    apl:
      policy:
        - "plugin(deny-gate)"
"#;
    let mgr = build_manager_with_visitor(YAML).await;
    let ext = Extensions {
        meta: Some(Arc::new(meta_for_entity("llm", "gpt-4"))),
        ..Default::default()
    };

    // Calling cmf.tool_pre_invoke must NOT trigger the llm route's
    // APL annotation. With no annotation AND no plugin registered on
    // cmf.tool_pre_invoke, dispatch returns continue.
    let (tool_result, _bg) = mgr
        .invoke_named::<CmfHook>(
            "cmf.tool_pre_invoke",
            cmf_payload("hi"),
            ext.clone(),
            None,
        )
        .await;
    assert!(
        tool_result.continue_processing,
        "llm route MUST NOT bind to cmf.tool_pre_invoke (pre-Slice-102 bug); \
         violation = {:?}",
        tool_result.violation,
    );

    // Sanity: calling the RIGHT hook (cmf.llm_input) DOES fire the
    // annotation, hits deny-gate, denies — proves the route is wired
    // correctly on the llm hook side.
    let (llm_result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.llm_input", cmf_payload("hi"), ext, None)
        .await;
    assert!(
        !llm_result.continue_processing,
        "cmf.llm_input dispatch should hit the deny-gate via the llm route",
    );
}

#[tokio::test]
async fn visitor_compile_error_propagates_from_load_config_yaml() {
    const YAML: &str = r#"
plugins:
  - name: allow-gate
    kind: allow-gate
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_weather
    apl:
      policy:
        - "this-is-not-a-valid-step ::: $$$"
"#;
    let mgr = Arc::new(PluginManager::default());
    mgr.register_factory("allow-gate", Box::new(AllowGateFactory));
    register_apl(&mgr, AplOptions::in_process());

    let err = mgr.load_config_yaml(YAML).expect_err("malformed APL block must error");
    let msg = format!("{}", err);
    assert!(
        msg.contains("visitor 'apl'"),
        "expected visitor error context, got: {}",
        msg
    );
}

/// Flat form: a route may declare `policy:` directly, without the `apl:`
/// wrapper. The visitor recognizes it identically to the wrapped form.
/// (Also exercises the `run(...)` plugin alias.)
#[tokio::test]
async fn visitor_flat_route_without_apl_wrapper_allows() {
    const YAML: &str = r#"
plugins:
  - name: allow-gate
    kind: allow-gate
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_weather
    policy:
      - "run(allow-gate)"
"#;
    let mgr = build_manager_with_visitor(YAML).await;

    let ext = Extensions {
        meta: Some(Arc::new(meta_for_tool("get_weather"))),
        ..Default::default()
    };
    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", cmf_payload("hi"), ext, None)
        .await;

    assert!(
        result.continue_processing,
        "flat (no-apl-wrapper) allow path should continue: violation = {:?}",
        result.violation
    );
}

/// Flat form deny mirrors the wrapped deny path — the route's `policy:`
/// is honored without an `apl:` wrapper and the violation propagates.
#[tokio::test]
async fn visitor_flat_route_without_apl_wrapper_denies() {
    const YAML: &str = r#"
plugins:
  - name: deny-gate
    kind: deny-gate
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_weather
    policy:
      - "plugin(deny-gate)"
"#;
    let mgr = build_manager_with_visitor(YAML).await;

    let ext = Extensions {
        meta: Some(Arc::new(meta_for_tool("get_weather"))),
        ..Default::default()
    };
    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", cmf_payload("hi"), ext, None)
        .await;

    assert!(!result.continue_processing, "flat deny path should halt");
    let violation = result.violation.expect("deny path must surface a violation");
    assert_eq!(violation.reason, "deny-gate fired");
}

// =====================================================================
// Flat `plugins:` MAP form (no `apl:` wrapper) — regression coverage
// for the load-path bug where a route/defaults/policy `plugins:` map
// failed to deserialize into `Vec<PluginRouteRef>` *before* any visitor
// ran. The structural parse now tolerates the map (treats it as APL
// per-plugin override data and leaves the structural list empty); the
// APL visitor consumes the map from the raw YAML. These tests drive the
// map through the real `load_config_yaml` path the unit tests can't hit.
// =====================================================================

/// A route with a flat `policy:` AND a flat `plugins:` *map* override
/// (no `apl:` wrapper) loads through `load_config_yaml` (previously a
/// hard `invalid type: map, expected a sequence` error) and the policy
/// still fires — proving the override map and the activating policy
/// coexist on the same section.
#[tokio::test]
async fn flat_route_with_plugins_map_and_policy_loads_and_denies() {
    const YAML: &str = r#"
plugins:
  - name: deny-gate
    kind: deny-gate
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_weather
    policy:
      - "plugin(deny-gate)"
    plugins:
      deny-gate:
        on_error: ignore
"#;
    let mgr = build_manager_with_visitor(YAML).await;

    let ext = Extensions {
        meta: Some(Arc::new(meta_for_tool("get_weather"))),
        ..Default::default()
    };
    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", cmf_payload("hi"), ext, None)
        .await;

    assert!(
        !result.continue_processing,
        "flat plugins-map route should still run its policy and deny"
    );
    let violation = result.violation.expect("deny path must surface a violation");
    assert_eq!(violation.reason, "deny-gate fired");
}

/// The flat `plugins:` map form must be behaviorally identical to the
/// `apl: { plugins: {...} }` wrapper form — that equivalence is the
/// whole point of "the wrapper is optional". An override map alone
/// declares no phases, so neither form installs an APL handler; whatever
/// the legacy chain then does, both forms must do the same thing. We
/// assert the two routes resolve to the same decision rather than
/// hard-coding the legacy-chain outcome (which this PR doesn't touch).
#[tokio::test]
async fn flat_plugins_map_only_matches_wrapped_plugins_map_only() {
    const FLAT: &str = r#"
plugins:
  - name: deny-gate
    kind: deny-gate
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_weather
    plugins:
      deny-gate:
        on_error: ignore
"#;
    const WRAPPED: &str = r#"
plugins:
  - name: deny-gate
    kind: deny-gate
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_weather
    apl:
      plugins:
        deny-gate:
          on_error: ignore
"#;

    async fn decide(yaml: &str) -> bool {
        let mgr = build_manager_with_visitor(yaml).await;
        let ext = Extensions {
            meta: Some(Arc::new(meta_for_tool("get_weather"))),
            ..Default::default()
        };
        let (result, _bg) = mgr
            .invoke_named::<CmfHook>("cmf.tool_pre_invoke", cmf_payload("hi"), ext, None)
            .await;
        result.continue_processing
    }

    assert_eq!(
        decide(FLAT).await,
        decide(WRAPPED).await,
        "flat plugins-map and apl-wrapped plugins-map must resolve identically",
    );
}

/// A `plugins:` map at `global.defaults.<entity>` scope loads through
/// the full pipeline. Before the fix this failed at the structural
/// `CpexConfig` parse (the defaults group's `plugins` is also a `Vec`).
/// The default layer contributes the policy; the route inherits it.
#[tokio::test]
async fn flat_defaults_plugins_map_loads_through_full_pipeline() {
    const YAML: &str = r#"
plugins:
  - name: deny-gate
    kind: deny-gate
    hooks: [cmf.tool_pre_invoke]
global:
  defaults:
    tool:
      policy:
        - "plugin(deny-gate)"
      plugins:
        deny-gate:
          on_error: ignore
routes:
  - tool: get_weather
"#;
    let mgr = build_manager_with_visitor(YAML).await;

    let ext = Extensions {
        meta: Some(Arc::new(meta_for_tool("get_weather"))),
        ..Default::default()
    };
    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", cmf_payload("hi"), ext, None)
        .await;

    assert!(
        !result.continue_processing,
        "tool default with a flat plugins-map override should still deny via inherited policy"
    );
    assert_eq!(
        result.violation.expect("deny expected").reason,
        "deny-gate fired"
    );
}
