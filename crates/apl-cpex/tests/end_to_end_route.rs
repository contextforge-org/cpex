// Location: ./crates/apl-cpex/tests/end_to_end_route.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// End-to-end integration: APL YAML config → `compile_config` →
// `evaluate_route` → `CmfPluginInvoker::invoke` → typed CPEX dispatch
// via `invoke_named::<CmfHook>` → real plugin handler → result mapped
// back through apl-core's `Decision`.
//
// This is the load-bearing test for v0 — it proves apl-core +
// apl-cpex + cpex-core compose through their public surfaces.
//
// The earlier `cmf_invoker_dispatch.rs` exercised the invoker
// directly. This file goes one layer up: the host writes a tiny APL
// route YAML, the evaluator drives the route, and the invoker is the
// only thing that translates plugin-named steps into CMF hook calls.

use std::sync::Arc;

use async_trait::async_trait;
use cpex_core::cmf::enums::Role;
use cpex_core::cmf::{CmfHook, Message, MessagePayload};
use cpex_core::context::PluginContext;
use cpex_core::error::{PluginError as CoreError, PluginViolation};
use cpex_core::factory::{PluginFactory, PluginInstance};
use cpex_core::hooks::adapter::TypedHandlerAdapter;
use cpex_core::hooks::payload::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::manager::PluginManager;
use cpex_core::plugin::{Plugin, PluginConfig};

use apl_core::{
    compile_config, evaluate_route, AttributeBag, Decision, PdpCall, PdpDecision, PdpDialect,
    PdpError, PdpResolver, RoutePayload,
};

use apl_cpex::CmfPluginInvoker;

// ---------------------------------------------------------------------
// Stub PDP — apl-core requires `&dyn PdpResolver`, but no scenario in
// this file exercises a PDP step, so an always-allow stub is enough.
// ---------------------------------------------------------------------

struct AllowPdp;

#[async_trait]
impl PdpResolver for AllowPdp {
    fn dialect(&self) -> PdpDialect {
        PdpDialect::Cedar
    }
    async fn evaluate(
        &self,
        _call: &PdpCall,
        _bag: &AttributeBag,
    ) -> Result<PdpDecision, PdpError> {
        Ok(PdpDecision {
            decision: Decision::Allow,
            diagnostics: vec![],
        })
    }
}

// ---------------------------------------------------------------------
// Test CMF plugins — minimal handlers registered on `cmf.tool_pre_invoke`
// (the hook `CmfPluginInvoker` dispatches `PluginInvocation::Step` to
// by default). Duplicated from `cmf_invoker_dispatch.rs` because cargo
// test files don't share modules without a `tests/common/` layout, and
// the fixtures are tiny enough that mild duplication beats the layout
// churn for v0.
// ---------------------------------------------------------------------

struct AllowPlugin {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for AllowPlugin {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for AllowPlugin {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        PluginResult::allow()
    }
}

struct AllowPluginFactory;
impl PluginFactory for AllowPluginFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<CoreError>> {
        let plugin = Arc::new(AllowPlugin {
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

struct DenyPlugin {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for DenyPlugin {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for DenyPlugin {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        PluginResult::deny(PluginViolation::new(
            "policy.forbidden",
            "scope-gate fixture denied this call",
        ))
    }
}

struct DenyPluginFactory;
impl PluginFactory for DenyPluginFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<CoreError>> {
        let plugin = Arc::new(DenyPlugin {
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

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

async fn manager_with(
    kind: &str,
    factory: Box<dyn PluginFactory>,
) -> Arc<PluginManager> {
    let mgr = PluginManager::default();
    mgr.register_factory(kind, factory);
    let yaml = format!("plugins:\n  - name: {0}\n    kind: {0}\n", kind);
    let cfg = cpex_core::config::parse_config(&yaml).expect("parse_config");
    mgr.load_config(cfg).expect("load_config");
    mgr.initialize().await.expect("initialize");
    Arc::new(mgr)
}

fn empty_payload() -> RoutePayload {
    RoutePayload::new(serde_json::json!({}))
}

fn cmf_payload() -> MessagePayload {
    MessagePayload {
        message: Message::text(Role::User, "irrelevant for v0 step-only test"),
    }
}

// ---------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------

/// Route with one policy step `plugin(scope-gate)`. The CPEX plugin
/// registered under that name returns `allow()`. `evaluate_route` must
/// therefore return `Decision::Allow` end-to-end. The hook name is now
/// resolved from the root `plugins:` block in YAML — no hardcoded
/// defaults on the invoker.
#[tokio::test]
async fn route_with_allow_plugin_evaluates_allow() {
    const YAML: &str = r#"
plugins:
  - name: scope-gate
    kind: scope-gate
    hooks: [cmf.tool_pre_invoke]
routes:
  get_weather:
    policy:
      - "plugin(scope-gate)"
"#;

    let mgr = manager_with("scope-gate", Box::new(AllowPluginFactory)).await;
    let cfg = compile_config(YAML).expect("compile_config");
    let route = cfg.routes.get("get_weather").expect("route present");
    let invoker = CmfPluginInvoker::for_request(
        mgr,
        Extensions::default(),
        cmf_payload(),
        Arc::new(cfg.plugins.clone()),
    )
    .with_route_overrides(route.plugin_overrides.clone());

    let bag = AttributeBag::new();
    let mut payload = empty_payload();
    let decision =
        evaluate_route(route, &bag, &mut payload, &AllowPdp, &invoker).await;

    assert_eq!(decision.decision, Decision::Allow);
    assert!(decision.taints.is_empty());
    assert!(!decision.args_modified);
    assert!(!decision.result_modified);
}

/// Same route shape, but the CPEX plugin denies. `evaluate_route` must
/// surface that as `Decision::Deny` with the violation reason + code
/// flowed through `CmfPluginInvoker`.
#[tokio::test]
async fn route_with_deny_plugin_surfaces_violation_through_route_decision() {
    const YAML: &str = r#"
plugins:
  - name: scope-gate
    kind: scope-gate
    hooks: [cmf.tool_pre_invoke]
routes:
  get_weather:
    policy:
      - "plugin(scope-gate)"
"#;

    let mgr = manager_with("scope-gate", Box::new(DenyPluginFactory)).await;
    let cfg = compile_config(YAML).expect("compile_config");
    let route = cfg.routes.get("get_weather").expect("route present");
    let invoker = CmfPluginInvoker::for_request(
        mgr,
        Extensions::default(),
        cmf_payload(),
        Arc::new(cfg.plugins.clone()),
    )
    .with_route_overrides(route.plugin_overrides.clone());

    let bag = AttributeBag::new();
    let mut payload = empty_payload();
    let decision =
        evaluate_route(route, &bag, &mut payload, &AllowPdp, &invoker).await;

    match decision.decision {
        Decision::Deny {
            reason,
            rule_source,
        } => {
            assert_eq!(
                reason.as_deref(),
                Some("scope-gate fixture denied this call"),
                "violation reason should flow back through CmfPluginInvoker → \
                 PluginOutcome → evaluate_steps → RouteDecision"
            );
            assert_eq!(rule_source, "policy.forbidden");
        }
        other => panic!("expected Decision::Deny, got {:?}", other),
    }
}
