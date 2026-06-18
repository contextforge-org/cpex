// Location: ./crates/apl-cpex/tests/config_override.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Route-level `config:` override propagation. The unified-config spec
// allows a route to declare `plugins.<name>.config: { ... }` that
// REPLACES (not merges) the plugin's base config for THIS route only.
//
// Under the hood:
//
//   1. `AplConfigVisitor` parses the override into `CompiledRoute.plugin_overrides`.
//   2. `RouteDispatchPlan::build` calls `manager.build_override_entries(name, config, caps, on_error)`.
//   3. cpex-core's `build_override_entries` invokes the plugin factory
//      with the merged `PluginConfig`, calls `initialize()` on the
//      result, and wraps every returned handler in a fresh `PluginRef`
//      with an independent circuit breaker.
//
// These tests prove the value the route declared actually reaches the
// plugin's `Plugin::config()` (factory was called with the override)
// and that the base instance is unaffected when a *separate* route
// uses the base config.

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
// Fixtures
// =====================================================================

/// Plugin that reads its OWN `config.allowlist` (a list of strings) and
/// denies the request unless `"open"` is in the list. The point is that
/// each instance (base vs override) reads from its own
/// `Plugin::config()` — which is set at factory-construction time.
/// If the route override never reaches the factory, the override
/// instance has the base config and the gate behaves the same as base.
struct AllowlistGate {
    cfg: PluginConfig,
}

impl AllowlistGate {
    fn allowlist(&self) -> Vec<String> {
        self.cfg
            .config
            .as_ref()
            .and_then(|v| v.get("allowlist"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[async_trait]
impl Plugin for AllowlistGate {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for AllowlistGate {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        if self.allowlist().iter().any(|s| s == "open") {
            PluginResult::allow()
        } else {
            PluginResult::deny(PluginViolation::new(
                "policy.config_gate",
                format!(
                    "allowlist does not include 'open' — saw {:?}",
                    self.allowlist()
                ),
            ))
        }
    }
}

/// Counter so we can prove the factory was invoked again for the
/// override route (i.e. a *new* instance, not a shared one). Two
/// `mgr.invoke_named` calls against two different routes should
/// trigger exactly two factory calls: one at `load_config` for the
/// base, one at `build_override_entries` for the override route. The
/// dispatch cache memoizes the override entry, so subsequent invokes
/// against the same route don't re-instantiate.
struct AllowlistGateFactory {
    instance_count: Arc<std::sync::atomic::AtomicUsize>,
}

impl PluginFactory for AllowlistGateFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<CoreError>> {
        self.instance_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let plugin = Arc::new(AllowlistGate {
            cfg: config.clone(),
        });
        Ok(PluginInstance {
            plugin: plugin.clone(),
            handlers: vec![(
                "cmf.tool_pre_invoke",
                Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(plugin)),
            )],
        })
    }
}

// =====================================================================
// Helpers
// =====================================================================

fn cmf_payload() -> MessagePayload {
    MessagePayload {
        message: Message::text(Role::User, "x"),
    }
}

fn meta_for_tool(name: &str) -> MetaExtension {
    let mut meta = MetaExtension::default();
    meta.entity_type = Some("tool".to_string());
    meta.entity_name = Some(name.to_string());
    meta
}

async fn build_manager(yaml: &str) -> (Arc<PluginManager>, Arc<std::sync::atomic::AtomicUsize>) {
    let instance_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mgr = Arc::new(PluginManager::default());
    mgr.register_factory(
        "allowlist-gate",
        Box::new(AllowlistGateFactory {
            instance_count: Arc::clone(&instance_count),
        }),
    );
    register_apl(
        &mgr,
        AplOptions {
            dispatch_cache: Arc::new(DispatchCache::new()),
            session_store: Arc::new(MemorySessionStore::new()),
            pdps: Vec::new(),
            pdp_factories: Vec::new(),
            session_store_factories: Vec::new(),
            base_capabilities: None,
        },
    );
    mgr.load_config_yaml(yaml).expect("load_config_yaml");
    mgr.initialize().await.expect("initialize");
    (mgr, instance_count)
}

// =====================================================================
// Scenarios
// =====================================================================

/// Base config: `allowlist: ["closed"]` → plugin denies. Route
/// `tool_a` doesn't override, so it uses the base — should deny.
/// Route `tool_b` overrides `allowlist: ["open"]` → factory builds a
/// new instance with that config → plugin allows. Proves the override
/// reaches the factory and the new instance reads it.
#[tokio::test]
async fn config_override_replaces_base_config_for_route() {
    const YAML: &str = r#"
plugins:
  - name: gate
    kind: allowlist-gate
    hooks: [cmf.tool_pre_invoke]
    config:
      allowlist: ["closed"]
routes:
  - tool: tool_a
    apl:
      policy:
        - "plugin(gate)"
  - tool: tool_b
    apl:
      plugins:
        gate:
          config:
            allowlist: ["open"]
      policy:
        - "plugin(gate)"
"#;
    let (mgr, instance_count) = build_manager(YAML).await;

    // tool_a uses the base config → denies.
    let ext_a = Extensions {
        meta: Some(Arc::new(meta_for_tool("tool_a"))),
        ..Default::default()
    };
    let (res_a, _) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", cmf_payload(), ext_a, None)
        .await;
    let v = res_a
        .violation
        .expect("base config has no 'open' — should deny");
    assert_eq!(v.code, "policy.config_gate");
    assert!(
        v.reason.contains("\"closed\""),
        "violation should report the base allowlist, got: {}",
        v.reason
    );

    // tool_b uses the override → allows.
    let ext_b = Extensions {
        meta: Some(Arc::new(meta_for_tool("tool_b"))),
        ..Default::default()
    };
    let (res_b, _) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", cmf_payload(), ext_b, None)
        .await;
    assert!(
        res_b.continue_processing,
        "override should allow — violation: {:?}",
        res_b.violation
    );

    // Factory invoked exactly twice: once at load_config for the base,
    // once at build_override_entries for tool_b. tool_a doesn't override,
    // so no extra call. Subsequent invokes hit the dispatch cache.
    assert_eq!(
        instance_count.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "expected one factory call for base + one for override; \
         a different count means caching / override path is wrong"
    );
}

/// Run tool_b twice. The dispatch cache must memoize the override
/// instance built on the first call so the second call doesn't trigger
/// another factory invocation. Two routes with overrides should still
/// produce exactly 1 + N instances (base + one per overriding route),
/// regardless of how many invokes hit each route.
#[tokio::test]
async fn dispatch_cache_memoizes_override_instances() {
    const YAML: &str = r#"
plugins:
  - name: gate
    kind: allowlist-gate
    hooks: [cmf.tool_pre_invoke]
    config:
      allowlist: ["closed"]
routes:
  - tool: tool_b
    apl:
      plugins:
        gate:
          config:
            allowlist: ["open"]
      policy:
        - "plugin(gate)"
"#;
    let (mgr, instance_count) = build_manager(YAML).await;

    let ext = Extensions {
        meta: Some(Arc::new(meta_for_tool("tool_b"))),
        ..Default::default()
    };

    // Three invokes against tool_b. The factory should fire once for
    // the base (at load_config) and once for the override (at the
    // first dispatch); the second + third dispatches hit the cache.
    for _ in 0..3 {
        let (res, _) = mgr
            .invoke_named::<CmfHook>("cmf.tool_pre_invoke", cmf_payload(), ext.clone(), None)
            .await;
        assert!(res.continue_processing, "{:?}", res.violation);
    }

    assert_eq!(
        instance_count.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "factory should be called exactly twice across three invokes — \
         the dispatch cache must reuse the override instance after the \
         first build"
    );
}

/// Override only `on_error` (no `config:`). Per the spec, this should
/// take the fast path inside `build_override_entries`: shared base
/// plugin Arc, fresh `PluginRef` with merged `TrustedConfig`. The
/// factory must NOT be re-invoked.
#[tokio::test]
async fn caps_only_override_does_not_reinstantiate() {
    const YAML: &str = r#"
plugins:
  - name: gate
    kind: allowlist-gate
    hooks: [cmf.tool_pre_invoke]
    config:
      allowlist: ["open"]
routes:
  - tool: tool_c
    apl:
      plugins:
        gate:
          on_error: ignore
      policy:
        - "plugin(gate)"
"#;
    let (mgr, instance_count) = build_manager(YAML).await;

    let ext = Extensions {
        meta: Some(Arc::new(meta_for_tool("tool_c"))),
        ..Default::default()
    };
    let (res, _) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", cmf_payload(), ext, None)
        .await;
    assert!(res.continue_processing);

    // Only the base instantiation happened at load_config. The override
    // only changes on_error, so the shared-base PluginRef path fires
    // and no factory call is made for the route variant.
    assert_eq!(
        instance_count.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "caps/on_error-only override must NOT re-invoke the factory; \
         doing so would burn resources for a trivial config diff"
    );
}

// ---------------------------------------------------------------------
// Extended coverage — two routes with distinct config overrides for
// the same plugin, and on_error-override plumbing verification.
// ---------------------------------------------------------------------

/// Two routes (`tool_a`, `tool_b`) reference the same plugin (`gate`)
/// with DIFFERENT config overrides. The dispatch cache must produce
/// two independent instances, one per route, each carrying its own
/// override config — proves the cache key (`route_key`) keeps the
/// instances separate. Verified by the per-route runtime behavior
/// AND by the factory-call count: base + override_a + override_b = 3.
#[tokio::test]
async fn two_routes_with_distinct_overrides_produce_distinct_instances() {
    const YAML: &str = r#"
plugins:
  - name: gate
    kind: allowlist-gate
    hooks: [cmf.tool_pre_invoke]
    config:
      allowlist: ["closed"]
routes:
  - tool: tool_a
    apl:
      plugins:
        gate:
          config:
            allowlist: ["alpha"]
      policy:
        - "plugin(gate)"
  - tool: tool_b
    apl:
      plugins:
        gate:
          config:
            allowlist: ["open"]
      policy:
        - "plugin(gate)"
"#;
    let (mgr, instance_count) = build_manager(YAML).await;

    // tool_a override: allowlist=["alpha"] — gate denies (no "open").
    let ext_a = Extensions {
        meta: Some(Arc::new(meta_for_tool("tool_a"))),
        ..Default::default()
    };
    let (res_a, _) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", cmf_payload(), ext_a, None)
        .await;
    let v_a = res_a
        .violation
        .expect("tool_a override has no 'open' — should deny");
    assert!(
        v_a.reason.contains("\"alpha\""),
        "tool_a violation should report its own override allowlist (alpha), got: {}",
        v_a.reason,
    );

    // tool_b override: allowlist=["open"] — gate allows.
    let ext_b = Extensions {
        meta: Some(Arc::new(meta_for_tool("tool_b"))),
        ..Default::default()
    };
    let (res_b, _) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", cmf_payload(), ext_b, None)
        .await;
    assert!(
        res_b.continue_processing,
        "tool_b override has 'open' — should allow: {:?}",
        res_b.violation,
    );

    // Factory invocation count: base (at load_config) + tool_a
    // override (at first tool_a dispatch) + tool_b override (at first
    // tool_b dispatch). Three total — proves the cache holds two
    // distinct instances rather than collapsing them.
    assert_eq!(
        instance_count.load(std::sync::atomic::Ordering::SeqCst),
        3,
        "expected 3 factory calls (base + tool_a override + tool_b override); \
         a smaller count means overrides collapsed across routes",
    );
}

/// Override changes `on_error` only — sanity-check that the override
/// VALUE actually lands on the per-route plugin entry's trusted_config,
/// not just that the factory wasn't re-invoked.
///
/// Counterpart to `caps_only_override_does_not_reinstantiate` (which
/// only checks the perf optimization). This test verifies the
/// PLUMBING: build the plan with and without an on_error override,
/// then read the resolved entry's trusted_config to confirm the
/// override actually flowed through (`Ignore`) vs the base default
/// (`Fail`).
#[tokio::test]
async fn on_error_override_plumbs_through_to_trusted_config() {
    use std::collections::HashMap;

    use apl_core::plugin_decl::{PluginDeclaration, PluginOverride, PluginRegistry};
    use apl_core::rules::{CompiledRoute, Effect};
    use apl_cpex::{DispatchCache, RouteDispatchPlan};
    use cpex_core::plugin::OnError;

    // Single-plugin cpex-core config — load it via the manager so the
    // plugin is registered. No APL visitor / routes wiring needed —
    // we'll build the routes manually below to focus on what the
    // dispatch plan does with overrides.
    const YAML: &str = r#"
plugins:
  - name: gate
    kind: allowlist-gate
    hooks: [cmf.tool_pre_invoke]
    config:
      allowlist: ["open"]
"#;
    let (mgr, _) = build_manager(YAML).await;

    // Construct the APL plugin registry by hand to match what
    // `compile_config` would have produced for the YAML's `plugins:`
    // block. `RouteDispatchPlan::build` consults this to know which
    // plugins to resolve through cpex-core.
    let mut registry = PluginRegistry::new();
    registry.insert(
        "gate".to_string(),
        PluginDeclaration {
            name: "gate".to_string(),
            kind: "allowlist-gate".to_string(),
            hooks: vec!["cmf.tool_pre_invoke".to_string()],
            capabilities: Vec::new(),
            config: None,
            on_error: None,
            extra: HashMap::new(),
        },
    );

    let cache = DispatchCache::new();

    // Override route — sets `on_error: ignore` only.
    let mut route_override = CompiledRoute::default();
    route_override.route_key = "override-route".into();
    route_override.policy.push(Effect::Plugin {
        name: "gate".into(),
    });
    let mut override_block = PluginOverride::default();
    override_block.on_error = Some("ignore".into());
    route_override
        .plugin_overrides
        .insert("gate".to_string(), override_block);
    let plan_override: std::sync::Arc<RouteDispatchPlan> =
        cache.get_or_build(&route_override, &registry, &mgr).await;
    let entry_override = plan_override
        .plugins
        .get("gate")
        .expect("gate must resolve on override route")
        .entries_by_hook
        .values()
        .next()
        .expect("override route entry present");
    assert_eq!(
        entry_override.plugin_ref.trusted_config().on_error,
        OnError::Ignore,
        "override route should carry on_error=Ignore on its entry",
    );

    // Base-config route — no overrides; should carry default Fail.
    let mut route_base = CompiledRoute::default();
    route_base.route_key = "base-route".into();
    route_base.policy.push(Effect::Plugin {
        name: "gate".into(),
    });
    let plan_base = cache.get_or_build(&route_base, &registry, &mgr).await;
    let entry_base = plan_base
        .plugins
        .get("gate")
        .expect("gate must resolve on base route")
        .entries_by_hook
        .values()
        .next()
        .expect("base route entry present");
    assert_eq!(
        entry_base.plugin_ref.trusted_config().on_error,
        OnError::Fail,
        "base route should carry the default on_error=Fail",
    );
}
