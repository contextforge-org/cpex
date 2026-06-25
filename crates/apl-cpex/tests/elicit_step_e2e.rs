// Location: ./crates/apl-cpex/tests/elicit_step_e2e.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// End-to-end test for the elicitation bridge (Phase 2).
//
// Verifies the full flow:
//   * apl-cpex's `RouteDispatchPlan::build` resolves an elicitation
//     plugin's `elicit` entry into `plan.elicitation_entries` by name.
//   * `ElicitationPluginInvoker` builds an `ElicitationPayload` for each
//     of dispatch / check / validate (setting `ElicitationOp`),
//     dispatches via `invoke_entries::<ElicitationHook>(...)`, and maps
//     the returned payload back to apl-core's `ElicitationDispatch` /
//     `ElicitationStatus` / `ElicitationValidation`.
//   * A handler deny surfaces as `ElicitationError`.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use cpex_core::context::PluginContext;
use cpex_core::elicitation::{
    ElicitationHook, ElicitationOp, ElicitationOutcomeKind, ElicitationPayload,
    ElicitationStatusKind, HOOK_ELICIT,
};
use cpex_core::error::PluginViolation;
use cpex_core::hooks::payload::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::manager::PluginManager;
use cpex_core::plugin::{OnError, Plugin, PluginConfig, PluginMode};

use apl_core::{
    compile_config, ElicitKind, ElicitStep, ElicitationInvoker, ElicitationOutcome,
    ElicitationStatus,
};
use apl_cpex::{ElicitationPluginInvoker, RouteDispatchPlan};

use tokio::sync::Mutex as AsyncMutex;

// ---------------------------------------------------------------------
// Fake ElicitationHook plugin — records each operation it saw and
// produces a configurable response per operation.
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
struct OpRecord {
    op: ElicitationOp,
    kind: String,
    from: String,
    elicitation_id: Option<String>,
    purpose: Option<String>,
}

struct FakeApprover {
    cfg: PluginConfig,
    ledger: Arc<Mutex<Vec<OpRecord>>>,
    /// What `check` reports.
    check_status: ElicitationStatusKind,
    check_outcome: Option<ElicitationOutcomeKind>,
    /// What `validate` reports.
    validate_valid: bool,
    /// When `Some`, the handler denies (any op) with this violation code.
    deny_code: Option<String>,
}

#[async_trait]
impl Plugin for FakeApprover {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<ElicitationHook> for FakeApprover {
    async fn handle(
        &self,
        payload: &ElicitationPayload,
        _ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<ElicitationPayload> {
        self.ledger.lock().unwrap().push(OpRecord {
            op: payload.operation(),
            kind: payload.kind().to_string(),
            from: payload.from().to_string(),
            elicitation_id: payload.elicitation_id().map(str::to_string),
            purpose: payload.purpose().map(str::to_string),
        });

        if let Some(code) = &self.deny_code {
            return PluginResult::deny(PluginViolation::new(
                code.clone(),
                "fake-approver denied".to_string(),
            ));
        }

        let mut out = payload.clone();
        match payload.operation() {
            ElicitationOp::Dispatch => {
                out.id = Some("elic-abc".to_string());
                out.status = Some(ElicitationStatusKind::Pending);
                out.approver = Some(payload.from().to_string());
                out.intent_id = Some("intent-77".to_string());
                out.expires_at = Some("2026-12-31T00:00:00Z".to_string());
            }
            ElicitationOp::Check => {
                out.status = Some(self.check_status);
                out.outcome = self.check_outcome;
            }
            ElicitationOp::Validate => {
                out.valid = Some(self.validate_valid);
                out.approver = Some("alice@example.com".to_string());
                out.intent_id = Some("intent-77".to_string());
            }
        }
        PluginResult::modify_payload(out)
    }
}

fn approver_cfg(name: &str) -> PluginConfig {
    PluginConfig {
        name: name.to_string(),
        kind: "test".to_string(),
        description: None,
        author: None,
        version: None,
        hooks: vec![HOOK_ELICIT.to_string()],
        mode: PluginMode::Sequential,
        priority: 10,
        on_error: OnError::Fail,
        capabilities: std::collections::HashSet::new(),
        tags: Vec::new(),
        conditions: Vec::new(),
        config: None,
    }
}

/// Build a manager with the plugin registered, compile the route YAML,
/// and build the dispatch plan for the named route.
async fn setup(
    plugin: Arc<FakeApprover>,
    cfg: PluginConfig,
) -> (Arc<PluginManager>, Arc<RouteDispatchPlan>) {
    let mgr = Arc::new(PluginManager::default());
    mgr.register_handler::<ElicitationHook, _>(plugin, cfg)
        .expect("register elicitation plugin");
    mgr.initialize().await.expect("initialize");

    let yaml = r#"
plugins:
  - name: manager-approver
    kind: test
    hooks: [elicit]
routes:
  payroll_adjust:
    pre_invocation:
      - "require_approval(manager-approver, from: claim.manager, channel: \"ciba\", scope: \"args.amount <= 25000\", purpose: \"Approve raise\")"
"#;
    let cfg = compile_config(yaml).expect("compile route YAML");
    let route = cfg.routes.get("payroll_adjust").expect("route present");
    let plan = RouteDispatchPlan::build(route, &cfg.plugins, &mgr).await;
    (mgr, Arc::new(plan))
}

fn elicit_step() -> ElicitStep {
    ElicitStep {
        kind: ElicitKind::Approval,
        plugin_name: "manager-approver".to_string(),
        channel: Some("ciba".to_string()),
        from: "claim.manager".to_string(),
        purpose: Some("Approve raise".to_string()),
        scope: Some("args.amount <= 25000".to_string()),
        timeout: None,
        config_override: None,
        on_error: None,
        source: "payroll_adjust.policy[0]".to_string(),
    }
}

fn invoker(
    mgr: Arc<PluginManager>,
    plan: Arc<RouteDispatchPlan>,
) -> ElicitationPluginInvoker {
    ElicitationPluginInvoker::new(mgr, Arc::new(AsyncMutex::new(Extensions::default())), plan)
}

// ---------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------

#[tokio::test]
async fn dispatch_maps_payload_outputs_and_passes_resolved_from() {
    let ledger = Arc::new(Mutex::new(Vec::new()));
    let plugin = Arc::new(FakeApprover {
        cfg: approver_cfg("manager-approver"),
        ledger: Arc::clone(&ledger),
        check_status: ElicitationStatusKind::Pending,
        check_outcome: None,
        validate_valid: true,
        deny_code: None,
    });
    let (mgr, plan) = setup(Arc::clone(&plugin), approver_cfg("manager-approver")).await;
    let inv = invoker(mgr, plan);

    let d = inv
        .dispatch(&elicit_step(), "alice@example.com")
        .await
        .expect("dispatch ok");

    assert_eq!(d.id, "elic-abc");
    assert_eq!(d.approver.as_deref(), Some("alice@example.com"));
    assert_eq!(d.intent_id.as_deref(), Some("intent-77"));
    assert_eq!(d.expires_at.as_deref(), Some("2026-12-31T00:00:00Z"));

    // The plugin saw a Dispatch op with the resolved approver + inputs.
    let rec = ledger.lock().unwrap()[0].clone();
    assert_eq!(rec.op, ElicitationOp::Dispatch);
    assert_eq!(rec.kind, "approval");
    assert_eq!(rec.from, "alice@example.com");
    assert_eq!(rec.purpose.as_deref(), Some("Approve raise"));
    assert!(rec.elicitation_id.is_none());
}

#[tokio::test]
async fn check_maps_pending_and_resolved() {
    // Pending.
    let plugin = Arc::new(FakeApprover {
        cfg: approver_cfg("manager-approver"),
        ledger: Arc::new(Mutex::new(Vec::new())),
        check_status: ElicitationStatusKind::Pending,
        check_outcome: None,
        validate_valid: true,
        deny_code: None,
    });
    let (mgr, plan) = setup(Arc::clone(&plugin), approver_cfg("manager-approver")).await;
    let inv = invoker(mgr, plan);
    let s = inv.check(&elicit_step(), "elic-abc").await.expect("check ok");
    assert_eq!(s, ElicitationStatus::Pending);

    // Resolved + approved.
    let plugin = Arc::new(FakeApprover {
        cfg: approver_cfg("manager-approver"),
        ledger: Arc::new(Mutex::new(Vec::new())),
        check_status: ElicitationStatusKind::Resolved,
        check_outcome: Some(ElicitationOutcomeKind::Approved),
        validate_valid: true,
        deny_code: None,
    });
    let (mgr, plan) = setup(Arc::clone(&plugin), approver_cfg("manager-approver")).await;
    let inv = invoker(mgr, plan);
    let s = inv.check(&elicit_step(), "elic-abc").await.expect("check ok");
    assert_eq!(
        s,
        ElicitationStatus::Resolved { outcome: ElicitationOutcome::Approved }
    );
}

#[tokio::test]
async fn check_resolved_without_outcome_defaults_denied() {
    // Fail-safe: Resolved with no outcome must not read as approved.
    let plugin = Arc::new(FakeApprover {
        cfg: approver_cfg("manager-approver"),
        ledger: Arc::new(Mutex::new(Vec::new())),
        check_status: ElicitationStatusKind::Resolved,
        check_outcome: None,
        validate_valid: true,
        deny_code: None,
    });
    let (mgr, plan) = setup(Arc::clone(&plugin), approver_cfg("manager-approver")).await;
    let inv = invoker(mgr, plan);
    let s = inv.check(&elicit_step(), "elic-abc").await.expect("check ok");
    assert_eq!(
        s,
        ElicitationStatus::Resolved { outcome: ElicitationOutcome::Denied }
    );
}

#[tokio::test]
async fn validate_maps_verdict_and_facts() {
    let plugin = Arc::new(FakeApprover {
        cfg: approver_cfg("manager-approver"),
        ledger: Arc::new(Mutex::new(Vec::new())),
        check_status: ElicitationStatusKind::Resolved,
        check_outcome: Some(ElicitationOutcomeKind::Approved),
        validate_valid: true,
        deny_code: None,
    });
    let (mgr, plan) = setup(Arc::clone(&plugin), approver_cfg("manager-approver")).await;
    let inv = invoker(mgr, plan);
    let v = inv
        .validate(&elicit_step(), "elic-abc")
        .await
        .expect("validate ok");
    assert!(v.valid);
    assert_eq!(v.approver.as_deref(), Some("alice@example.com"));
    assert_eq!(v.intent_id.as_deref(), Some("intent-77"));
}

#[tokio::test]
async fn handler_deny_surfaces_as_error() {
    let plugin = Arc::new(FakeApprover {
        cfg: approver_cfg("manager-approver"),
        ledger: Arc::new(Mutex::new(Vec::new())),
        check_status: ElicitationStatusKind::Pending,
        check_outcome: None,
        validate_valid: false,
        deny_code: Some("channel.unavailable".to_string()),
    });
    let (mgr, plan) = setup(Arc::clone(&plugin), approver_cfg("manager-approver")).await;
    let inv = invoker(mgr, plan);
    let err = inv
        .dispatch(&elicit_step(), "alice@example.com")
        .await
        .expect_err("handler denied");
    let msg = format!("{err}");
    assert!(msg.contains("channel.unavailable"), "got: {msg}");
}

#[tokio::test]
async fn unregistered_plugin_is_not_found() {
    // Plan has no entry for a plugin the step names → NotFound, which the
    // evaluator's on_error then handles.
    let plugin = Arc::new(FakeApprover {
        cfg: approver_cfg("manager-approver"),
        ledger: Arc::new(Mutex::new(Vec::new())),
        check_status: ElicitationStatusKind::Pending,
        check_outcome: None,
        validate_valid: true,
        deny_code: None,
    });
    let (mgr, plan) = setup(Arc::clone(&plugin), approver_cfg("manager-approver")).await;
    let inv = invoker(mgr, plan);

    let mut step = elicit_step();
    step.plugin_name = "nonexistent".to_string();
    let err = inv
        .dispatch(&step, "alice@example.com")
        .await
        .expect_err("unregistered");
    assert!(matches!(
        err,
        apl_core::ElicitationError::NotFound(p) if p == "nonexistent"
    ));
}
