// Location: ./crates/apl-cpex/tests/elicit_then_delegate_e2e.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Integration test for the composition of two effects in one route:
// an approval gate (`require_approval` → ElicitationPluginInvoker) that
// must pass before a delegation (`delegate` → DelegationPluginInvoker)
// runs. This is the manager-approval-then-apply pattern.
//
// The apl-core evaluator already unit-tests elicit sequencing and
// delegate dispatch in isolation. What this proves is the CPEX
// integration level: both real bridge invokers plugged into one
// `evaluate_route`, dispatching to real (fake-backed) plugins, in a
// single route.
//
//   * Approval DENIED  → route halts at the gate; the delegate plugin
//                        is never called (no token minted).
//   * Approval APPROVED → gate passes; the delegate runs, mints a
//                        token, and `delegation.granted.*` is visible
//                        to the trailing post-check.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{Duration, Utc};

use cpex_core::context::PluginContext;
use cpex_core::delegation::{DelegationPayload, TokenDelegateHook, HOOK_TOKEN_DELEGATE};
use cpex_core::elicitation::{
    ElicitationHook, ElicitationOp, ElicitationOutcomeKind, ElicitationPayload,
    ElicitationStatusKind, HOOK_ELICIT,
};
use cpex_core::extensions::raw_credentials::{
    RawCredentialsExtension, RawDelegatedToken, RawInboundToken, TokenKind, TokenRole,
};
use cpex_core::hooks::payload::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::manager::PluginManager;
use cpex_core::plugin::{OnError, Plugin, PluginConfig, PluginMode};

use apl_core::{
    compile_config, evaluate_route, AttributeBag, Decision, PdpCall, PdpDecision, PdpDialect,
    PdpError, PdpResolver, RoutePayload,
};
use apl_cpex::{
    CmfPluginInvoker, DelegationPluginInvoker, DispatchCache, ElicitationPluginInvoker,
    MemorySessionStore, SessionStore,
};

// ---------------------------------------------------------------------
// Fake elicit plugin — approves or denies on `check`, per config.
// ---------------------------------------------------------------------

struct FakeApprover {
    cfg: PluginConfig,
    check_outcome: ElicitationOutcomeKind,
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
        let mut out = payload.clone();
        match payload.operation() {
            ElicitationOp::Dispatch => {
                out.id = Some("elic-1".to_string());
                out.status = Some(ElicitationStatusKind::Pending);
                out.approver = Some(payload.from().to_string());
                out.intent_id = Some("intent-1".to_string());
                out.expires_at = Some("2099-12-31T00:00:00Z".to_string());
            },
            // Resolve immediately (approved or denied) so a single
            // evaluate pass reaches the delegate step or halts at it.
            ElicitationOp::Check => {
                out.status = Some(ElicitationStatusKind::Resolved);
                out.outcome = Some(self.check_outcome);
            },
            ElicitationOp::Validate => {
                out.valid = Some(true);
                out.approver = Some("manager@corp.com".to_string());
                out.intent_id = Some("intent-1".to_string());
            },
        }
        PluginResult::modify_payload(out)
    }
}

fn approver_cfg() -> PluginConfig {
    PluginConfig {
        name: "manager-approver".to_string(),
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

// ---------------------------------------------------------------------
// Fake delegate plugin — records that it ran and mints a token.
// ---------------------------------------------------------------------

struct RecordingDelegate {
    cfg: PluginConfig,
    /// Every target the plugin was asked to mint for. Empty ⇒ never ran.
    ledger: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl Plugin for RecordingDelegate {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<TokenDelegateHook> for RecordingDelegate {
    async fn handle(
        &self,
        payload: &DelegationPayload,
        _ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<DelegationPayload> {
        self.ledger
            .lock()
            .unwrap()
            .push(payload.target_name().to_string());

        let token = RawDelegatedToken::new(
            "fake.delegated.token",
            "Authorization",
            "workday-api",
            vec!["read_compensation".to_string()],
            Utc::now() + Duration::seconds(300),
        );
        let mut updated = payload.clone();
        updated.delegated_token = Some(token);
        PluginResult::modify_payload(updated)
    }
}

fn delegate_cfg() -> PluginConfig {
    PluginConfig {
        name: "workday-oauth".to_string(),
        kind: "test".to_string(),
        description: None,
        author: None,
        version: None,
        hooks: vec![HOOK_TOKEN_DELEGATE.to_string()],
        mode: PluginMode::Sequential,
        priority: 10,
        on_error: OnError::Fail,
        capabilities: std::collections::HashSet::new(),
        tags: Vec::new(),
        conditions: Vec::new(),
        config: None,
    }
}

// ---------------------------------------------------------------------
// Always-allow PDP stub — no scenario here exercises a PDP step.
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

// One route: approval gate, then delegation, then a granted post-check.
const ROUTE_YAML: &str = r#"
plugins:
  - name: manager-approver
    kind: test
    hooks: [elicit]
  - name: workday-oauth
    kind: test
    hooks: [token.delegate]
routes:
  payroll_adjust:
    pre_invocation:
      - "require_approval(manager-approver, from: claim.manager, channel: \"ciba\", scope: \"args.amount <= 25000\", purpose: \"Approve raise\")"
      - "delegate(workday-oauth, target: workday-api, permissions: [read_compensation])"
      - "!delegation.granted: deny"
"#;

/// Drive the whole route once with the approver resolving to
/// `outcome`. Returns `(route decision, number of delegate calls)`.
async fn run_route(outcome: ElicitationOutcomeKind) -> (Decision, usize) {
    let ledger: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    let mgr = Arc::new(PluginManager::default());
    mgr.register_handler::<ElicitationHook, _>(
        Arc::new(FakeApprover {
            cfg: approver_cfg(),
            check_outcome: outcome,
        }),
        approver_cfg(),
    )
    .expect("register approver");
    mgr.register_handler::<TokenDelegateHook, _>(
        Arc::new(RecordingDelegate {
            cfg: delegate_cfg(),
            ledger: Arc::clone(&ledger),
        }),
        delegate_cfg(),
    )
    .expect("register delegate");
    mgr.initialize().await.expect("initialize");

    let cfg = compile_config(ROUTE_YAML).expect("compile route YAML");
    let route = cfg.routes.get("payroll_adjust").expect("route present");
    let cache = Arc::new(DispatchCache::new());
    let plan = cache.get_or_build(route, &cfg.plugins, &mgr).await;

    // A User inbound token so the (default user-subject) delegation has
    // a bearer to carry.
    let mut raw = RawCredentialsExtension::default();
    raw.inbound_tokens.insert(
        TokenRole::User,
        RawInboundToken::new("eyJ.fake.user", "Authorization", TokenKind::Jwt),
    );
    let extensions = Extensions {
        raw_credentials: Some(Arc::new(raw)),
        ..Default::default()
    };

    let session_store: Arc<dyn SessionStore> = Arc::new(MemorySessionStore::new());
    let invoker = Arc::new(
        CmfPluginInvoker::for_request(
            Arc::clone(&mgr),
            extensions,
            cpex_core::cmf::MessagePayload {
                message: cpex_core::cmf::Message::text(
                    cpex_core::cmf::enums::Role::User,
                    "adjust payroll",
                ),
            },
            Arc::clone(&plan),
            Arc::clone(&session_store),
        )
        .await
        .expect("for_request"),
    );

    // Both bridge invokers share the request's extensions + plan.
    let delegations = Arc::new(DelegationPluginInvoker::new(
        Arc::clone(&mgr),
        invoker.extensions_arc(),
        invoker.plan_arc(),
    ));
    let elicitations = Arc::new(ElicitationPluginInvoker::new(
        Arc::clone(&mgr),
        invoker.extensions_arc(),
        invoker.plan_arc(),
    ));

    let mut bag = apl_cmf::BagBuilder::new()
        .with_extensions(&invoker.current_extensions().await)
        .with_route_key(&route.route_key)
        .build();
    // Seed the two attributes the gate reads: `from` must resolve to an
    // identity, and the approval `scope` predicate is checked against
    // the live args.
    bag.set("claim.manager", "manager@corp.com");
    bag.set("args.amount", 1000_i64);

    let mut payload = RoutePayload::new(serde_json::Value::Null);
    let decision = evaluate_route(
        route,
        &mut bag,
        &mut payload,
        &(Arc::new(AllowPdp) as Arc<dyn apl_core::PdpResolver>),
        &(invoker.clone() as Arc<dyn apl_core::PluginInvoker>),
        &(delegations.clone() as Arc<dyn apl_core::DelegationInvoker>),
        &(elicitations.clone() as Arc<dyn apl_core::ElicitationInvoker>),
    )
    .await;

    let calls = ledger.lock().unwrap().len();
    (decision.decision, calls)
}

/// Approval denied ⇒ the gate halts the route and the delegation never
/// runs. This is the property that makes "approval gates delegation"
/// real: a denied approval must stop the token from ever being minted.
#[tokio::test]
async fn denied_approval_halts_before_delegation() {
    let (decision, delegate_calls) = run_route(ElicitationOutcomeKind::Denied).await;

    assert!(
        matches!(decision, Decision::Deny { .. }),
        "denied approval must halt the route; got {decision:?}",
    );
    assert_eq!(
        delegate_calls, 0,
        "delegation must NOT run when approval was denied",
    );
}

/// Approval granted ⇒ the gate passes, the delegation runs and mints a
/// token, and the trailing `!delegation.granted: deny` post-check is
/// satisfied so the route allows.
#[tokio::test]
async fn approved_gate_lets_delegation_run() {
    let (decision, delegate_calls) = run_route(ElicitationOutcomeKind::Approved).await;

    assert_eq!(
        decision,
        Decision::Allow,
        "approved gate + successful delegation should allow; got {decision:?}",
    );
    assert_eq!(
        delegate_calls, 1,
        "delegation must run exactly once after approval",
    );
}
