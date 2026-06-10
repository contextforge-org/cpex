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

use apl_core::pipeline::TaintScope;
use apl_core::{
    compile_config, evaluate_route, AttributeBag, Decision, NoopDelegationInvoker, PdpCall,
    PdpDecision, PdpDialect, PdpError, PdpResolver, RoutePayload,
};

use apl_cpex::{CmfPluginInvoker, DispatchCache, MemorySessionStore, SessionStore};

// Build Extensions carrying a client/upstream session id (tier-0) AND an
// authenticated subject, and return the session-store key the resolver
// derives for them. Tier-0 session ids are subject-bound (security review
// Finding 2), so these tests must key the store by the resolved value rather
// than the raw string they supply.
fn session_ext_and_key(session_id: &str, subject_id: &str) -> (Extensions, String) {
    let mut agent = cpex_core::extensions::AgentExtension::default();
    agent.session_id = Some(session_id.into());
    let mut subject = cpex_core::extensions::SubjectExtension::default();
    subject.id = Some(subject_id.into());
    let ext = Extensions {
        agent: Some(Arc::new(agent)),
        security: Some(Arc::new(cpex_core::extensions::SecurityExtension {
            subject: Some(subject),
            ..Default::default()
        })),
        ..Default::default()
    };
    let key = apl_cpex::session_resolver::resolve_session(&ext)
        .expect("subject-bound session resolves")
        .0;
    (ext, key)
}

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

async fn manager_with(kind: &str, factory: Box<dyn PluginFactory>) -> Arc<PluginManager> {
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
    let cache = DispatchCache::new();
    let plan = cache.get_or_build(route, &cfg.plugins, &mgr).await;
    let invoker = Arc::new(
        CmfPluginInvoker::for_request(
            mgr,
            Extensions::default(),
            cmf_payload(),
            plan,
            Arc::new(MemorySessionStore::new()),
        )
        .await,
    );

    let mut bag = AttributeBag::new();
    let mut payload = empty_payload();
    let decision = evaluate_route(
        route,
        &mut bag,
        &mut payload,
        &(Arc::new(AllowPdp) as Arc<dyn apl_core::PdpResolver>),
        &(invoker.clone() as Arc<dyn apl_core::PluginInvoker>),
        &(Arc::new(NoopDelegationInvoker) as Arc<dyn apl_core::DelegationInvoker>),
    )
    .await;

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
    let cache = DispatchCache::new();
    let plan = cache.get_or_build(route, &cfg.plugins, &mgr).await;
    let invoker = Arc::new(
        CmfPluginInvoker::for_request(
            mgr,
            Extensions::default(),
            cmf_payload(),
            plan,
            Arc::new(MemorySessionStore::new()),
        )
        .await,
    );

    let mut bag = AttributeBag::new();
    let mut payload = empty_payload();
    let decision = evaluate_route(
        route,
        &mut bag,
        &mut payload,
        &(Arc::new(AllowPdp) as Arc<dyn apl_core::PdpResolver>),
        &(invoker.clone() as Arc<dyn apl_core::PluginInvoker>),
        &(Arc::new(NoopDelegationInvoker) as Arc<dyn apl_core::DelegationInvoker>),
    )
    .await;

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

// ---------------------------------------------------------------------
// Taint extraction — plugin adds a security label via cow_copy +
// modify_extensions; invoker diffs labels, surfaces the new ones as
// TaintEvent in PluginOutcome.taints. evaluate_steps accumulates them
// into RouteDecision.taints. SessionStore receives the new label via
// persist_session.
// ---------------------------------------------------------------------

struct TaintingPlugin {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for TaintingPlugin {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for TaintingPlugin {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        // cow_copy gives an OwnedExtensions handle inheriting any write
        // tokens the executor set up (append_labels grants the
        // labels_write_token automatically because the registration
        // declares the capability).
        let mut owned = extensions.cow_copy();
        let security = owned.security.get_or_insert_with(Default::default);
        security.add_label("PII");
        PluginResult::modify_extensions(owned)
    }
}

struct TaintingPluginFactory;
impl PluginFactory for TaintingPluginFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<CoreError>> {
        let plugin = Arc::new(TaintingPlugin {
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

/// Build a manager whose registered plugin has `append_labels` capability,
/// without which the executor would refuse the modified labels on the way
/// out (label monotonicity is enforced under the write-token system).
async fn tainting_manager() -> Arc<PluginManager> {
    let mgr = PluginManager::default();
    mgr.register_factory("tagger", Box::new(TaintingPluginFactory));
    let yaml = "plugins:\n  - name: tagger\n    kind: tagger\n    capabilities: [append_labels, read_labels]\n";
    let cfg = cpex_core::config::parse_config(yaml).expect("parse_config");
    mgr.load_config(cfg).expect("load_config");
    mgr.initialize().await.expect("initialize");
    Arc::new(mgr)
}

#[tokio::test]
async fn route_plugin_emitting_label_surfaces_taint_and_persists_to_session() {
    const YAML: &str = r#"
plugins:
  - name: tagger
    kind: tagger
    hooks: [cmf.tool_pre_invoke]
    capabilities: [append_labels, read_labels]
routes:
  classify:
    policy:
      - "plugin(tagger)"
"#;

    let mgr = tainting_manager().await;
    let cfg = compile_config(YAML).expect("compile_config");
    let route = cfg.routes.get("classify").expect("route present");
    let cache = DispatchCache::new();
    let plan = cache.get_or_build(route, &cfg.plugins, &mgr).await;

    // Session id pinned via tier-0 (agent.session_id) plus a subject, so the
    // store key is the deterministic subject-bound hash the resolver derives.
    let (extensions, session_key) = session_ext_and_key("sess-taint-test", "alice");

    let session_store = Arc::new(MemorySessionStore::new());
    let invoker = Arc::new(
        CmfPluginInvoker::for_request(mgr, extensions, cmf_payload(), plan, session_store.clone())
            .await,
    );

    let mut bag = AttributeBag::new();
    let mut payload = empty_payload();
    let decision = evaluate_route(
        route,
        &mut bag,
        &mut payload,
        &(Arc::new(AllowPdp) as Arc<dyn apl_core::PdpResolver>),
        &(invoker.clone() as Arc<dyn apl_core::PluginInvoker>),
        &(Arc::new(NoopDelegationInvoker) as Arc<dyn apl_core::DelegationInvoker>),
    )
    .await;

    // Decision flows through allow (plugin's modify_extensions doesn't
    // halt the pipeline).
    assert_eq!(decision.decision, Decision::Allow);

    // The label-emit traveled the full path:
    //   plugin.handle → modify_extensions →
    //   PipelineResult.modified_extensions →
    //   CmfPluginInvoker.invoke (label diff) →
    //   PluginOutcome.taints →
    //   evaluate_steps_inner accumulator →
    //   StepsEvaluation.taints →
    //   evaluate_route → RouteDecision.taints
    assert_eq!(
        decision.taints.len(),
        1,
        "expected one taint event from tagger plugin"
    );
    let event = &decision.taints[0];
    assert_eq!(event.label, "PII");
    assert_eq!(event.scopes, vec![TaintScope::Session]);

    // SessionStore persistence — host calls persist_session after route
    // evaluation; new labels (vs the post-hydration snapshot) land in
    // the store under the request's session_id.
    invoker.persist_session().await;
    let stored = session_store.load_labels(&session_key).await;
    assert_eq!(stored, vec!["PII".to_string()]);
}

#[tokio::test]
async fn session_store_hydrates_labels_at_request_start() {
    // Pre-seed the session store with a label, then verify the invoker
    // hydrates it into extensions.security.labels at for_request time
    // (so the first plugin call sees the accumulated session state).
    // Subject-bound session key (Finding 2): pre-seed under the resolved key.
    let (extensions, session_key) = session_ext_and_key("sess-existing", "alice");
    let session_store = Arc::new(MemorySessionStore::new());
    session_store
        .append_labels(&session_key, &["PRIOR".to_string()])
        .await;

    let mgr = tainting_manager().await;
    let yaml = r#"
plugins:
  - name: tagger
    kind: tagger
    hooks: [cmf.tool_pre_invoke]
    capabilities: [append_labels, read_labels]
routes:
  classify:
    policy:
      - "plugin(tagger)"
"#;
    let cfg = compile_config(yaml).expect("compile_config");
    let route = cfg.routes.get("classify").unwrap();
    let plan = DispatchCache::new()
        .get_or_build(route, &cfg.plugins, &mgr)
        .await;

    let invoker = Arc::new(
        CmfPluginInvoker::for_request(mgr, extensions, cmf_payload(), plan, session_store.clone())
            .await,
    );

    // Hydrated labels should be observable on the invoker's extensions.
    let snapshot = invoker.current_extensions().await;
    let security = snapshot
        .security
        .expect("hydration creates security extension");
    assert!(
        security.has_label("PRIOR"),
        "hydration should pull PRIOR from session store"
    );

    // Now drive a route — tagger adds PII. After persist, the store has
    // both PRIOR (from hydration) and PII (newly emitted).
    let mut bag = AttributeBag::new();
    let mut payload = empty_payload();
    let decision = evaluate_route(
        route,
        &mut bag,
        &mut payload,
        &(Arc::new(AllowPdp) as Arc<dyn apl_core::PdpResolver>),
        &(invoker.clone() as Arc<dyn apl_core::PluginInvoker>),
        &(Arc::new(NoopDelegationInvoker) as Arc<dyn apl_core::DelegationInvoker>),
    )
    .await;
    assert_eq!(decision.decision, Decision::Allow);

    // Only the NEW label (PII) shows up as a taint — PRIOR was already
    // present before the plugin ran, so it's not a fresh emission.
    assert_eq!(decision.taints.len(), 1);
    assert_eq!(decision.taints[0].label, "PII");

    invoker.persist_session().await;
    let mut stored = session_store.load_labels(&session_key).await;
    stored.sort();
    assert_eq!(stored, vec!["PII".to_string(), "PRIOR".to_string()]);
}

/// Slice TS1 proof: an APL `taint(audit, session)` step lands the
/// label in `security.labels` (via `apply_session_taints`) AND the
/// SessionStore (via `persist_session`). No plugin is involved — the
/// taint comes from the YAML, not from any handler's modify_extensions.
/// This is the load-bearing end-to-end test for the
/// "policy with side-effects" pitch: writing `taint(...)` in YAML
/// actually causes the session to be permanently labelled.
#[tokio::test]
async fn apl_taint_step_lands_in_security_labels_and_persists() {
    const YAML: &str = r#"
routes:
  classify:
    policy:
      - "taint(audit, session)"
"#;

    let mgr = manager_with("noop", Box::new(AllowPluginFactory)).await;
    let cfg = compile_config(YAML).expect("compile_config");
    let route = cfg.routes.get("classify").expect("route present");
    let plan = DispatchCache::new()
        .get_or_build(route, &cfg.plugins, &mgr)
        .await;

    let (extensions, session_key) = session_ext_and_key("sess-apl-taint", "alice");

    let session_store = Arc::new(MemorySessionStore::new());
    let invoker = Arc::new(
        CmfPluginInvoker::for_request(mgr, extensions, cmf_payload(), plan, session_store.clone())
            .await,
    );

    let mut bag = AttributeBag::new();
    let mut payload = empty_payload();
    let decision = evaluate_route(
        route,
        &mut bag,
        &mut payload,
        &(Arc::new(AllowPdp) as Arc<dyn apl_core::PdpResolver>),
        &(invoker.clone() as Arc<dyn apl_core::PluginInvoker>),
        &(Arc::new(NoopDelegationInvoker) as Arc<dyn apl_core::DelegationInvoker>),
    )
    .await;
    assert_eq!(decision.decision, Decision::Allow);

    // Evaluator surfaced the YAML taint into the decision.
    assert_eq!(
        decision.taints.len(),
        1,
        "expected one taint from `taint(...)` step"
    );
    assert_eq!(decision.taints[0].label, "audit");
    assert!(decision.taints[0].scopes.contains(&TaintScope::Session));

    // This is the new wiring: drain Session-scoped taints into
    // `security.labels` exactly as `AplRouteHandler::invoke` does.
    invoker.apply_session_taints(&decision.taints).await;

    let snapshot = invoker.current_extensions().await;
    let security = snapshot
        .security
        .as_ref()
        .expect("apply_session_taints should have created the security ext");
    assert!(
        security.has_label("audit"),
        "session-scoped taint should land in security.labels",
    );

    // And `persist_session` should pick up the label via the diff
    // against `initial_labels` (which was empty here).
    invoker.persist_session().await;
    let stored = session_store.load_labels(&session_key).await;
    assert_eq!(stored, vec!["audit".to_string()]);
}
