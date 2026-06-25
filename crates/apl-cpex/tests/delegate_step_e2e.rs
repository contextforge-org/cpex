// Location: ./crates/apl-cpex/tests/delegate_step_e2e.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// End-to-end test for `Step::Delegate` dispatch (Slice B).
//
// Verifies the full flow:
//   * APL parser produces a `Step::Delegate` from policy YAML.
//   * apl-cpex's `RouteDispatchPlan::build` resolves the plugin's
//     `token.delegate` entry into `plan.delegation_entries`.
//   * apl-cpex's `DelegationPluginInvoker` constructs a
//     `DelegationPayload`, dispatches via
//     `invoke_entries::<TokenDelegateHook>(...)`, applies the
//     resulting payload to extensions, and surfaces granted_*
//     attributes for downstream rules.
//   * Downstream `require(delegation.granted.* ...)` predicates see
//     the populated bag attributes (IdP-as-PDP path).
//   * `on_error: deny` (the default) halts the route on plugin deny;
//     `on_error: continue` lets the pipeline keep going.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{Duration, Utc};

use cpex_core::context::PluginContext;
use cpex_core::delegation::{DelegationPayload, TokenDelegateHook, HOOK_TOKEN_DELEGATE};
use cpex_core::error::PluginViolation;
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
    CmfPluginInvoker, DelegationPluginInvoker, DispatchCache, MemorySessionStore, SessionStore,
};

// ---------------------------------------------------------------------
// Fake TokenDelegateHook plugin — records every call and produces a
// configurable response (grant scopes / deny).
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
struct DelegateCallRecord {
    plugin_name: String,
    target_name: String,
    target_audience: Option<String>,
    required_permissions: Vec<String>,
}

struct RecordingDelegate {
    cfg: PluginConfig,
    /// Shared ledger — tests assert on what the plugin saw.
    ledger: Arc<Mutex<Vec<DelegateCallRecord>>>,
    /// `Some` → mint a token with these scopes; `None` → deny with
    /// the supplied violation code.
    grant_scopes: Option<Vec<String>>,
    grant_audience: String,
    deny_code: Option<String>,
    /// Snapshot of what extensions the plugin observed when invoked.
    /// Used by capability-gating tests to verify the executor's
    /// per-entry filter narrowed the view to declared caps.
    observed_extensions: Arc<Mutex<Option<ExtensionsObservation>>>,
}

/// Compact summary of what a delegate plugin saw in `Extensions` —
/// just the slots cap-gating tests care about.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ExtensionsObservation {
    saw_subject_id: Option<String>,
    saw_labels: Vec<String>,
    saw_inbound_token_for_user: bool,
    saw_delegation_chain_present: bool,
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
        ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<DelegationPayload> {
        self.ledger.lock().unwrap().push(DelegateCallRecord {
            plugin_name: self.cfg.name.clone(),
            target_name: payload.target_name().to_string(),
            target_audience: payload.target_audience().map(str::to_string),
            required_permissions: payload.required_permissions().to_vec(),
        });

        // Snapshot what this plugin sees in Extensions — the executor's
        // per-entry capability filter narrows the view BEFORE handing
        // it to the handler, so any slot we see proves the cap that
        // gates it was declared.
        *self.observed_extensions.lock().unwrap() = Some(ExtensionsObservation {
            saw_subject_id: ext
                .security
                .as_ref()
                .and_then(|s| s.subject.as_ref())
                .and_then(|s| s.id.clone()),
            saw_labels: ext
                .security
                .as_ref()
                .map(|s| s.labels.iter().cloned().collect())
                .unwrap_or_default(),
            saw_inbound_token_for_user: ext
                .raw_credentials
                .as_ref()
                .map(|rc| rc.inbound_tokens.contains_key(&TokenRole::User))
                .unwrap_or(false),
            saw_delegation_chain_present: ext.delegation.is_some(),
        });

        if let Some(code) = &self.deny_code {
            return PluginResult::deny(PluginViolation::new(
                code.clone(),
                format!("recording-delegate `{}` denied", self.cfg.name),
            ));
        }

        // Grant case — mint a fake token.
        let scopes = self.grant_scopes.clone().unwrap_or_default();
        let token = RawDelegatedToken::new(
            format!("fake.token.for.{}", self.cfg.name),
            "Authorization",
            self.grant_audience.clone(),
            scopes,
            Utc::now() + Duration::seconds(300),
        );
        let mut updated = payload.clone();
        updated.delegated_token = Some(token);
        PluginResult::modify_payload(updated)
    }
}

fn delegate_cfg(name: &str) -> PluginConfig {
    delegate_cfg_with_caps(name, &[])
}

/// Same as `delegate_cfg` but with declared capabilities. Capability
/// names map to cpex-core's `filter_extensions` rules — e.g.
/// `read_subject`, `read_labels`, `read_inbound_credentials`,
/// `read_delegation`. Used by cap-gating tests.
fn delegate_cfg_with_caps(name: &str, caps: &[&str]) -> PluginConfig {
    PluginConfig {
        name: name.to_string(),
        kind: "test".to_string(),
        description: None,
        author: None,
        version: None,
        hooks: vec![HOOK_TOKEN_DELEGATE.to_string()],
        mode: PluginMode::Sequential,
        priority: 10,
        on_error: OnError::Fail,
        capabilities: caps.iter().map(|s| s.to_string()).collect(),
        tags: Vec::new(),
        conditions: Vec::new(),
        config: None,
    }
}

// ---------------------------------------------------------------------
// Stub PDP — apl-core's evaluator requires `&dyn PdpResolver`; no
// scenario here exercises a PDP step, so an always-allow stub is
// enough.
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
// Shared helpers
// ---------------------------------------------------------------------

/// Build request-level Extensions with a fake inbound bearer token so
/// `DelegationPluginInvoker` has something to put in the
/// DelegationPayload's bearer slot.
fn ext_with_bearer(token: &str) -> Extensions {
    let mut raw = RawCredentialsExtension::default();
    raw.inbound_tokens.insert(
        TokenRole::User,
        RawInboundToken::new(token, "Authorization", TokenKind::Jwt),
    );
    Extensions {
        raw_credentials: Some(Arc::new(raw)),
        ..Default::default()
    }
}

/// Build Extensions populated with a subject + label so cap-gating
/// tests can verify what a delegate plugin actually sees after the
/// executor's per-entry filter narrows the view to declared caps.
fn ext_with_subject_and_label(token: &str, subject_id: &str, label: &str) -> Extensions {
    use cpex_core::extensions::{SecurityExtension, SubjectExtension};

    let mut raw = RawCredentialsExtension::default();
    raw.inbound_tokens.insert(
        TokenRole::User,
        RawInboundToken::new(token, "Authorization", TokenKind::Jwt),
    );

    let mut sec = SecurityExtension::default();
    sec.subject = Some(SubjectExtension {
        id: Some(subject_id.to_string()),
        ..Default::default()
    });
    sec.add_label(label);

    Extensions {
        raw_credentials: Some(Arc::new(raw)),
        security: Some(Arc::new(sec)),
        ..Default::default()
    }
}

/// Wire up a PluginManager with one or more TokenDelegate plugins,
/// run the route YAML through apl-core's compile, and return the
/// pieces a test needs to invoke a route.
async fn build_setup(
    yaml: &str,
    plugins: Vec<(String, Arc<RecordingDelegate>, PluginConfig)>,
) -> (
    Arc<PluginManager>,
    apl_core::CompiledConfig,
    Arc<DispatchCache>,
) {
    let mgr = Arc::new(PluginManager::default());
    for (_, plugin, cfg) in plugins {
        mgr.register_handler::<TokenDelegateHook, _>(plugin, cfg)
            .expect("register delegate plugin");
    }
    mgr.initialize().await.expect("initialize");
    let cfg = compile_config(yaml).expect("compile route YAML");
    let cache = Arc::new(DispatchCache::new());
    (mgr, cfg, cache)
}

// ---------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------

/// Baseline: a route with one `delegate(...)` step. The plugin is
/// called with the args from the step, mints a token, and the
/// resulting `delegation.granted.*` bag attributes are visible to
/// downstream `require(...)` rules.
#[tokio::test]
async fn delegate_step_grants_visible_to_downstream_require() {
    let ledger: Arc<Mutex<Vec<DelegateCallRecord>>> = Arc::new(Mutex::new(Vec::new()));
    let plugin = Arc::new(RecordingDelegate {
        cfg: delegate_cfg("workday-oauth"),
        ledger: Arc::clone(&ledger),
        grant_scopes: Some(vec!["read_compensation".to_string()]),
        grant_audience: "workday-api".to_string(),
        deny_code: None,
        observed_extensions: Arc::new(Mutex::new(None)),
    });

    // APL semantics: `allow` rules don't short-circuit — only `deny`
    // halts (spec §3). So the assertion shape is "deny if NOT granted",
    // which falls through to the implicit allow at end-of-steps when
    // the delegate succeeded.
    let yaml = r#"
plugins:
  - name: workday-oauth
    kind: test
    hooks: [token.delegate]
routes:
  get_compensation:
    policy:
      - "delegate(workday-oauth, target: workday-api, permissions: [read_compensation])"
      - "!delegation.granted: deny"
      - "!(delegation.granted.permissions contains 'read_compensation'): deny"
"#;
    let (mgr, cfg, cache) = build_setup(
        yaml,
        vec![(
            "workday-oauth".to_string(),
            Arc::clone(&plugin),
            delegate_cfg("workday-oauth"),
        )],
    )
    .await;

    let route = cfg.routes.get("get_compensation").expect("route present");
    let registry = cfg.plugins.clone();
    let plan = cache.get_or_build(route, &registry, &mgr).await;

    let extensions = ext_with_bearer("eyJ.fake.user-jwt");
    let session_store: Arc<dyn SessionStore> = Arc::new(MemorySessionStore::new());
    let invoker = Arc::new(
        CmfPluginInvoker::for_request(
            Arc::clone(&mgr),
            extensions,
            cpex_core::cmf::MessagePayload {
                message: cpex_core::cmf::Message::text(
                    cpex_core::cmf::enums::Role::User,
                    "fetch compensation",
                ),
            },
            Arc::clone(&plan),
            Arc::clone(&session_store),
        )
        .await
        .expect("for_request"),
    );
    let delegations = Arc::new(DelegationPluginInvoker::new(
        Arc::clone(&mgr),
        invoker.extensions_arc(),
        invoker.plan_arc(),
    ));

    let mut bag = apl_cmf::BagBuilder::new()
        .with_extensions(&invoker.current_extensions().await)
        .with_route_key(&route.route_key)
        .build();
    let mut payload = RoutePayload::new(serde_json::Value::Null);
    let decision = evaluate_route(
        route,
        &mut bag,
        &mut payload,
        &(Arc::new(AllowPdp) as Arc<dyn apl_core::PdpResolver>),
        &(invoker.clone() as Arc<dyn apl_core::PluginInvoker>),
        &(delegations.clone() as Arc<dyn apl_core::DelegationInvoker>),
        &(Arc::new(apl_core::NoopElicitationInvoker) as Arc<dyn apl_core::ElicitationInvoker>),
    )
    .await;

    // Inspect the bag directly — this proves the evaluator wrote
    // granted_* keys, giving us specific diagnostics if the route
    // fails for some other reason.
    assert!(
        matches!(
            bag.get("delegation.granted"),
            Some(apl_core::attributes::AttributeValue::Bool(true))
        ),
        "delegation.granted should be true; bag has: {:?}",
        bag.get("delegation.granted"),
    );
    let perms = bag
        .get_string_set("delegation.granted.permissions")
        .expect("granted.permissions present");
    assert!(perms.contains("read_compensation"));

    assert_eq!(
        decision.decision,
        Decision::Allow,
        "route should allow; got: {:?}",
        decision.decision,
    );

    // Plugin was called with the right args.
    let calls = ledger.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].plugin_name, "workday-oauth");
    assert_eq!(calls[0].target_name, "workday-api");
    assert_eq!(calls[0].required_permissions, vec!["read_compensation"]);

    // Extensions now carry the minted token under raw_credentials.
    let final_ext = invoker.current_extensions().await;
    let raw = final_ext
        .raw_credentials
        .as_ref()
        .expect("raw_credentials present");
    assert_eq!(raw.delegated_tokens.len(), 1, "one minted token");
    let token = raw.delegated_tokens.values().next().unwrap();
    assert_eq!(token.audience, "workday-api");
    assert_eq!(token.scopes, vec!["read_compensation"]);
}

/// IdP-as-PDP: when the plugin denies (e.g. simulating IdP refusal),
/// the route halts with the plugin's violation code — `on_error: deny`
/// is the default and translates the delegate's deny into a route
/// deny.
#[tokio::test]
async fn delegate_step_default_on_error_denies_route() {
    let ledger: Arc<Mutex<Vec<DelegateCallRecord>>> = Arc::new(Mutex::new(Vec::new()));
    let plugin = Arc::new(RecordingDelegate {
        cfg: delegate_cfg("workday-oauth"),
        ledger: Arc::clone(&ledger),
        grant_scopes: None,
        grant_audience: String::new(),
        deny_code: Some("delegation.idp_rejected".to_string()),
        observed_extensions: Arc::new(Mutex::new(None)),
    });

    // Plugin denies. Default on_error: deny → route halts at the
    // delegate step itself with the plugin's violation code. No
    // downstream rule needed for the test.
    let yaml = r#"
plugins:
  - name: workday-oauth
    kind: test
    hooks: [token.delegate]
routes:
  get_compensation:
    policy:
      - "delegate(workday-oauth, target: workday-api, permissions: [write_everything])"
"#;
    let (mgr, cfg, cache) = build_setup(
        yaml,
        vec![(
            "workday-oauth".to_string(),
            Arc::clone(&plugin),
            delegate_cfg("workday-oauth"),
        )],
    )
    .await;

    let route = cfg.routes.get("get_compensation").expect("route present");
    let registry = cfg.plugins.clone();
    let plan = cache.get_or_build(route, &registry, &mgr).await;

    let extensions = ext_with_bearer("eyJ.fake.user-jwt");
    let session_store: Arc<dyn SessionStore> = Arc::new(MemorySessionStore::new());
    let invoker = Arc::new(
        CmfPluginInvoker::for_request(
            Arc::clone(&mgr),
            extensions,
            cpex_core::cmf::MessagePayload {
                message: cpex_core::cmf::Message::text(
                    cpex_core::cmf::enums::Role::User,
                    "fetch comp",
                ),
            },
            Arc::clone(&plan),
            Arc::clone(&session_store),
        )
        .await
        .expect("for_request"),
    );
    let delegations = Arc::new(DelegationPluginInvoker::new(
        Arc::clone(&mgr),
        invoker.extensions_arc(),
        invoker.plan_arc(),
    ));

    let mut bag = apl_cmf::BagBuilder::new()
        .with_extensions(&invoker.current_extensions().await)
        .with_route_key(&route.route_key)
        .build();
    let mut payload = RoutePayload::new(serde_json::Value::Null);
    let decision = evaluate_route(
        route,
        &mut bag,
        &mut payload,
        &(Arc::new(AllowPdp) as Arc<dyn apl_core::PdpResolver>),
        &(invoker.clone() as Arc<dyn apl_core::PluginInvoker>),
        &(delegations.clone() as Arc<dyn apl_core::DelegationInvoker>),
        &(Arc::new(apl_core::NoopElicitationInvoker) as Arc<dyn apl_core::ElicitationInvoker>),
    )
    .await;

    match decision.decision {
        Decision::Deny { rule_source, .. } => {
            assert_eq!(
                rule_source, "delegation.idp_rejected",
                "rule_source should carry the plugin's violation code",
            );
        },
        d => panic!("expected Deny on plugin deny, got {d:?}"),
    }
    assert_eq!(
        ledger.lock().unwrap().len(),
        1,
        "delegate plugin was called once",
    );
}

/// `on_error: continue` — even on plugin deny, the route keeps
/// going. Downstream rules can branch on `delegation.granted` being
/// absent. Useful for "try delegation, fall back to a different
/// flow" patterns.
#[tokio::test]
async fn delegate_step_on_error_continue_lets_pipeline_proceed() {
    let ledger: Arc<Mutex<Vec<DelegateCallRecord>>> = Arc::new(Mutex::new(Vec::new()));
    let plugin = Arc::new(RecordingDelegate {
        cfg: delegate_cfg("audit-receipt"),
        ledger: Arc::clone(&ledger),
        grant_scopes: None,
        grant_audience: String::new(),
        deny_code: Some("audit.unavailable".to_string()),
        observed_extensions: Arc::new(Mutex::new(None)),
    });

    let yaml = r#"
plugins:
  - name: audit-receipt
    kind: test
    hooks: [token.delegate]
routes:
  any:
    policy:
      - "delegate(audit-receipt, target: audit, on_error: continue)"
"#;
    let (mgr, cfg, cache) = build_setup(
        yaml,
        vec![(
            "audit-receipt".to_string(),
            Arc::clone(&plugin),
            delegate_cfg("audit-receipt"),
        )],
    )
    .await;

    let route = cfg.routes.get("any").expect("route present");
    let registry = cfg.plugins.clone();
    let plan = cache.get_or_build(route, &registry, &mgr).await;

    let extensions = ext_with_bearer("eyJ.fake.user-jwt");
    let session_store: Arc<dyn SessionStore> = Arc::new(MemorySessionStore::new());
    let invoker = Arc::new(
        CmfPluginInvoker::for_request(
            Arc::clone(&mgr),
            extensions,
            cpex_core::cmf::MessagePayload {
                message: cpex_core::cmf::Message::text(cpex_core::cmf::enums::Role::User, "any"),
            },
            Arc::clone(&plan),
            Arc::clone(&session_store),
        )
        .await
        .expect("for_request"),
    );
    let delegations = Arc::new(DelegationPluginInvoker::new(
        Arc::clone(&mgr),
        invoker.extensions_arc(),
        invoker.plan_arc(),
    ));

    let mut bag = apl_cmf::BagBuilder::new()
        .with_extensions(&invoker.current_extensions().await)
        .with_route_key(&route.route_key)
        .build();
    let mut payload = RoutePayload::new(serde_json::Value::Null);
    let decision = evaluate_route(
        route,
        &mut bag,
        &mut payload,
        &(Arc::new(AllowPdp) as Arc<dyn apl_core::PdpResolver>),
        &(invoker.clone() as Arc<dyn apl_core::PluginInvoker>),
        &(delegations.clone() as Arc<dyn apl_core::DelegationInvoker>),
        &(Arc::new(apl_core::NoopElicitationInvoker) as Arc<dyn apl_core::ElicitationInvoker>),
    )
    .await;

    assert_eq!(
        decision.decision,
        Decision::Allow,
        "on_error: continue → route allows despite plugin deny",
    );
}

/// Most-recent-wins semantics for multiple `delegate(...)` calls in
/// one phase. Two delegates in a row both succeed; the
/// `delegation.granted.*` bag keys reflect the LAST one.
/// Extensions-side carries BOTH minted tokens (`raw_credentials.delegated_tokens`).
#[tokio::test]
async fn multiple_delegates_most_recent_wins_in_bag_extensions_accumulate() {
    let ledger: Arc<Mutex<Vec<DelegateCallRecord>>> = Arc::new(Mutex::new(Vec::new()));
    let workday = Arc::new(RecordingDelegate {
        cfg: delegate_cfg("workday-oauth"),
        ledger: Arc::clone(&ledger),
        grant_scopes: Some(vec!["read_compensation".to_string()]),
        grant_audience: "workday-api".to_string(),
        deny_code: None,
        observed_extensions: Arc::new(Mutex::new(None)),
    });
    let payroll = Arc::new(RecordingDelegate {
        cfg: delegate_cfg("payroll-oauth"),
        ledger: Arc::clone(&ledger),
        grant_scopes: Some(vec!["read_salary".to_string()]),
        grant_audience: "payroll-api".to_string(),
        deny_code: None,
        observed_extensions: Arc::new(Mutex::new(None)),
    });

    // After both delegates run, the bag reflects payroll's grants
    // (most recent). The contains-check on 'read_salary' succeeds
    // (because payroll's grant is what's currently in
    // `delegation.granted.permissions`); a check for
    // 'read_compensation' would FAIL even though workday minted a
    // token with that permission, because the bag key is
    // overwritten. Extensions-side accumulation (both tokens
    // present) is verified separately below.
    let yaml = r#"
plugins:
  - name: workday-oauth
    kind: test
    hooks: [token.delegate]
  - name: payroll-oauth
    kind: test
    hooks: [token.delegate]
routes:
  fanout:
    policy:
      - "delegate(workday-oauth, target: workday-api, permissions: [read_compensation])"
      - "delegate(payroll-oauth, target: payroll-api, permissions: [read_salary])"
      - "!(delegation.granted.permissions contains 'read_salary'): deny"
"#;
    let (mgr, cfg, cache) = build_setup(
        yaml,
        vec![
            (
                "workday-oauth".to_string(),
                Arc::clone(&workday),
                delegate_cfg("workday-oauth"),
            ),
            (
                "payroll-oauth".to_string(),
                Arc::clone(&payroll),
                delegate_cfg("payroll-oauth"),
            ),
        ],
    )
    .await;

    let route = cfg.routes.get("fanout").expect("route present");
    let registry = cfg.plugins.clone();
    let plan = cache.get_or_build(route, &registry, &mgr).await;

    let extensions = ext_with_bearer("eyJ.fake.user-jwt");
    let session_store: Arc<dyn SessionStore> = Arc::new(MemorySessionStore::new());
    let invoker = Arc::new(
        CmfPluginInvoker::for_request(
            Arc::clone(&mgr),
            extensions,
            cpex_core::cmf::MessagePayload {
                message: cpex_core::cmf::Message::text(cpex_core::cmf::enums::Role::User, "fanout"),
            },
            Arc::clone(&plan),
            Arc::clone(&session_store),
        )
        .await
        .expect("for_request"),
    );
    let delegations = Arc::new(DelegationPluginInvoker::new(
        Arc::clone(&mgr),
        invoker.extensions_arc(),
        invoker.plan_arc(),
    ));

    let mut bag = apl_cmf::BagBuilder::new()
        .with_extensions(&invoker.current_extensions().await)
        .with_route_key(&route.route_key)
        .build();
    let mut payload = RoutePayload::new(serde_json::Value::Null);
    let decision = evaluate_route(
        route,
        &mut bag,
        &mut payload,
        &(Arc::new(AllowPdp) as Arc<dyn apl_core::PdpResolver>),
        &(invoker.clone() as Arc<dyn apl_core::PluginInvoker>),
        &(delegations.clone() as Arc<dyn apl_core::DelegationInvoker>),
        &(Arc::new(apl_core::NoopElicitationInvoker) as Arc<dyn apl_core::ElicitationInvoker>),
    )
    .await;

    assert_eq!(decision.decision, Decision::Allow);

    // Both plugins fired, in order.
    let calls = ledger.lock().unwrap().clone();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].plugin_name, "workday-oauth");
    assert_eq!(calls[1].plugin_name, "payroll-oauth");

    // Extensions accumulate — BOTH minted tokens are stashed.
    let final_ext = invoker.current_extensions().await;
    let raw = final_ext.raw_credentials.as_ref().unwrap();
    assert_eq!(raw.delegated_tokens.len(), 2);
    let auds: std::collections::HashSet<&str> = raw
        .delegated_tokens
        .values()
        .map(|t| t.audience.as_str())
        .collect();
    assert!(auds.contains("workday-api"));
    assert!(auds.contains("payroll-api"));
}

// ---------------------------------------------------------------------
// Capability gating on the delegate() step path.
//
// The executor calls `filter_extensions(&ext, &caps)` per entry before
// each handler runs (executor.rs:440 in cpex-core). These tests pin
// that behavior end-to-end for the `Step::Delegate` dispatch path —
// proves that what an operator declares as `capabilities:` on a
// `token.delegate` plugin is enforced exactly the same way it is for
// CMF plugins.
// ---------------------------------------------------------------------

/// Delegate plugin declaring `read_subject` AND `read_inbound_credentials`
/// (the inbound-credentials cap is needed because the bearer token
/// arrives via raw_credentials and the invoker passes Extensions
/// through unmodified beyond the per-entry filter). Plugin sees the
/// subject, sees the inbound bearer token, but NOT the security label
/// (no read_labels cap).
#[tokio::test]
async fn delegate_with_read_subject_sees_subject_but_not_labels() {
    let ledger: Arc<Mutex<Vec<DelegateCallRecord>>> = Arc::new(Mutex::new(Vec::new()));
    let observed: Arc<Mutex<Option<ExtensionsObservation>>> = Arc::new(Mutex::new(None));

    let plugin_cfg = delegate_cfg_with_caps(
        "scoped-delegate",
        &["read_subject", "read_inbound_credentials"],
    );
    let plugin = Arc::new(RecordingDelegate {
        cfg: plugin_cfg.clone(),
        ledger: Arc::clone(&ledger),
        grant_scopes: Some(vec!["read_compensation".to_string()]),
        grant_audience: "workday-api".to_string(),
        deny_code: None,
        observed_extensions: Arc::clone(&observed),
    });

    let yaml = r#"
plugins:
  - name: scoped-delegate
    kind: test
    hooks: [token.delegate]
routes:
  get_compensation:
    policy:
      - "delegate(scoped-delegate, target: workday-api, permissions: [read_compensation])"
"#;
    let (mgr, cfg, cache) = build_setup(
        yaml,
        vec![(
            "scoped-delegate".to_string(),
            Arc::clone(&plugin),
            plugin_cfg,
        )],
    )
    .await;

    let route = cfg.routes.get("get_compensation").expect("route present");
    let registry = cfg.plugins.clone();
    let plan = cache.get_or_build(route, &registry, &mgr).await;

    // Extensions with BOTH subject (id=alice) AND a label (pii) —
    // proves the cap filter is selective.
    let extensions = ext_with_subject_and_label("eyJ.fake.jwt", "alice", "pii");
    let session_store: Arc<dyn SessionStore> = Arc::new(MemorySessionStore::new());
    let invoker = Arc::new(
        CmfPluginInvoker::for_request(
            Arc::clone(&mgr),
            extensions,
            cpex_core::cmf::MessagePayload {
                message: cpex_core::cmf::Message::text(
                    cpex_core::cmf::enums::Role::User,
                    "fetch compensation",
                ),
            },
            Arc::clone(&plan),
            Arc::clone(&session_store),
        )
        .await
        .expect("for_request"),
    );
    let delegations = Arc::new(DelegationPluginInvoker::new(
        Arc::clone(&mgr),
        invoker.extensions_arc(),
        invoker.plan_arc(),
    ));

    let mut bag = apl_cmf::BagBuilder::new()
        .with_extensions(&invoker.current_extensions().await)
        .with_route_key(&route.route_key)
        .build();
    let mut payload = RoutePayload::new(serde_json::Value::Null);
    let _ = evaluate_route(
        route,
        &mut bag,
        &mut payload,
        &(Arc::new(AllowPdp) as Arc<dyn apl_core::PdpResolver>),
        &(invoker.clone() as Arc<dyn apl_core::PluginInvoker>),
        &(delegations.clone() as Arc<dyn apl_core::DelegationInvoker>),
        &(Arc::new(apl_core::NoopElicitationInvoker) as Arc<dyn apl_core::ElicitationInvoker>),
    )
    .await;

    let obs = observed
        .lock()
        .unwrap()
        .clone()
        .expect("plugin should have run and recorded its view");

    assert_eq!(
        obs.saw_subject_id.as_deref(),
        Some("alice"),
        "read_subject cap should expose subject.id",
    );
    assert!(
        obs.saw_inbound_token_for_user,
        "read_inbound_credentials cap should expose the inbound user token",
    );
    assert!(
        obs.saw_labels.is_empty(),
        "without read_labels, the label should NOT leak — saw: {:?}",
        obs.saw_labels,
    );
}

/// Delegate plugin declaring NO capabilities. Should see NOTHING in
/// security or raw_credentials — the executor strips both slots
/// because no relevant cap is held. Verifies the negative case:
/// failure to declare a cap actually does hide the slot.
#[tokio::test]
async fn delegate_without_caps_sees_stripped_extensions() {
    let ledger: Arc<Mutex<Vec<DelegateCallRecord>>> = Arc::new(Mutex::new(Vec::new()));
    let observed: Arc<Mutex<Option<ExtensionsObservation>>> = Arc::new(Mutex::new(None));

    // Empty caps array — plugin opts into nothing.
    let plugin_cfg = delegate_cfg_with_caps("capless-delegate", &[]);
    let plugin = Arc::new(RecordingDelegate {
        cfg: plugin_cfg.clone(),
        ledger: Arc::clone(&ledger),
        grant_scopes: Some(vec!["read_compensation".to_string()]),
        grant_audience: "workday-api".to_string(),
        deny_code: None,
        observed_extensions: Arc::clone(&observed),
    });

    let yaml = r#"
plugins:
  - name: capless-delegate
    kind: test
    hooks: [token.delegate]
routes:
  any:
    policy:
      - "delegate(capless-delegate, target: workday-api)"
"#;
    let (mgr, cfg, cache) = build_setup(
        yaml,
        vec![(
            "capless-delegate".to_string(),
            Arc::clone(&plugin),
            plugin_cfg,
        )],
    )
    .await;

    let route = cfg.routes.get("any").expect("route present");
    let registry = cfg.plugins.clone();
    let plan = cache.get_or_build(route, &registry, &mgr).await;

    let extensions = ext_with_subject_and_label("eyJ.fake.jwt", "alice", "pii");
    let session_store: Arc<dyn SessionStore> = Arc::new(MemorySessionStore::new());
    let invoker = Arc::new(
        CmfPluginInvoker::for_request(
            Arc::clone(&mgr),
            extensions,
            cpex_core::cmf::MessagePayload {
                message: cpex_core::cmf::Message::text(cpex_core::cmf::enums::Role::User, "any"),
            },
            Arc::clone(&plan),
            Arc::clone(&session_store),
        )
        .await
        .expect("for_request"),
    );
    let delegations = Arc::new(DelegationPluginInvoker::new(
        Arc::clone(&mgr),
        invoker.extensions_arc(),
        invoker.plan_arc(),
    ));

    let mut bag = apl_cmf::BagBuilder::new()
        .with_extensions(&invoker.current_extensions().await)
        .with_route_key(&route.route_key)
        .build();
    let mut payload = RoutePayload::new(serde_json::Value::Null);
    let _ = evaluate_route(
        route,
        &mut bag,
        &mut payload,
        &(Arc::new(AllowPdp) as Arc<dyn apl_core::PdpResolver>),
        &(invoker.clone() as Arc<dyn apl_core::PluginInvoker>),
        &(delegations.clone() as Arc<dyn apl_core::DelegationInvoker>),
        &(Arc::new(apl_core::NoopElicitationInvoker) as Arc<dyn apl_core::ElicitationInvoker>),
    )
    .await;

    let obs = observed
        .lock()
        .unwrap()
        .clone()
        .expect("plugin should have run");

    // Load-bearing negative assertions — no cap → no slot.
    assert!(
        obs.saw_subject_id.is_none(),
        "without read_subject, subject must be hidden — saw: {:?}",
        obs.saw_subject_id,
    );
    assert!(
        obs.saw_labels.is_empty(),
        "without read_labels, labels must be hidden",
    );
    assert!(
        !obs.saw_inbound_token_for_user,
        "without read_inbound_credentials, inbound token must be hidden",
    );
}
