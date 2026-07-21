// Location: ./crates/apl-cmf/tests/end_to_end.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Full vertical slice: cpex-core extensions → apl-cmf bridge → apl-core
// evaluator on a YAML-compiled route. If this test breaks, the whole
// stack is misaligned (extension shape, bag vocabulary, or compiler).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use apl_cmf::BagBuilder;
use apl_core::{
    compile_config, evaluate_route, AttributeBag, Decision, DelegationInvoker, ElicitationInvoker,
    NoopDelegationInvoker, NoopElicitationInvoker, PdpCall, PdpDecision, PdpDialect, PdpError,
    PdpResolver, PluginError, PluginInvocation, PluginInvoker, PluginOutcome, RoutePayload,
};
use async_trait::async_trait;
use cpex_core::extensions::{
    DelegationExtension, DelegationHop, SecurityExtension, SubjectExtension, SubjectType,
    WorkloadIdentity,
};
use serde_json::json;

// `evaluate_route` takes `&Arc<dyn PluginInvoker>` / `&Arc<dyn DelegationInvoker>`
// so the call paths inside apl-core can `Arc::clone` an owned, 'static reference
// into each spawned branch (E3.2). All tests pass the same no-op stubs; wrap once.
fn pdp() -> Arc<dyn PdpResolver> {
    Arc::new(AllowPdp)
}
fn plugins() -> Arc<dyn PluginInvoker> {
    Arc::new(NoPlugins)
}
fn delegations() -> Arc<dyn DelegationInvoker> {
    Arc::new(NoopDelegationInvoker)
}
fn elicitations() -> Arc<dyn ElicitationInvoker> {
    Arc::new(NoopElicitationInvoker)
}

// HR route from unified-config-proposal.md §Example 1.
const HR_ROUTE_YAML: &str = r#"
routes:
  get_employee:
    args:
      employee_id: "str"
    pre_invocation:
      - "require(authenticated)"
      - "delegation.depth > 2: deny"
    result:
      ssn: "str | redact(!perm.view_ssn)"
      salary: "int | redact(!role.hr)"
      employee_id: "str | mask(4)"
"#;

// ---------- PDP / Plugin stubs ----------

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

struct NoPlugins;
#[async_trait]
impl PluginInvoker for NoPlugins {
    async fn invoke(
        &self,
        name: &str,
        _bag: &AttributeBag,
        _invocation: PluginInvocation<'_>,
    ) -> Result<PluginOutcome, PluginError> {
        Err(PluginError::NotFound(name.into()))
    }
}

// ---------- Realistic extension fixtures ----------

fn alice_hr() -> SecurityExtension {
    SecurityExtension {
        subject: Some(SubjectExtension {
            id: Some("alice@corp.com".into()),
            subject_type: Some(SubjectType::User),
            roles: HashSet::from(["hr".to_string()]),
            permissions: HashSet::from(["view_ssn".to_string()]),
            teams: HashSet::from(["compliance".to_string()]),
            claims: HashMap::from([("iss".to_string(), "auth.corp".to_string())]),
        }),
        this_workload: Some(WorkloadIdentity {
            client_id: Some("hr-tool".into()),
            ..Default::default()
        }),
        auth_method: Some("jwt".into()),
        ..Default::default()
    }
}

fn mallory_no_perm() -> SecurityExtension {
    SecurityExtension {
        subject: Some(SubjectExtension {
            id: Some("mallory@corp.com".into()),
            subject_type: Some(SubjectType::User),
            ..Default::default()
        }),
        auth_method: Some("jwt".into()),
        ..Default::default()
    }
}

fn shallow_delegation() -> DelegationExtension {
    let mut del = DelegationExtension {
        origin_subject_id: Some("alice@corp.com".into()),
        ..Default::default()
    };
    del.append_hop(DelegationHop {
        subject_id: "alice@corp.com".into(),
        ..Default::default()
    });
    del
}

fn deep_delegation() -> DelegationExtension {
    let mut del = DelegationExtension::default();
    for hop in ["a", "b", "c"] {
        del.append_hop(DelegationHop {
            subject_id: hop.into(),
            ..Default::default()
        });
    }
    del
}

// ---------- Tests ----------

#[tokio::test]
async fn alice_full_route_through_cmf_bridge() {
    let mut bag = BagBuilder::new()
        .with_security(&alice_hr())
        .with_delegation(&shallow_delegation())
        .with_route_key("get_employee")
        .build();

    // Sanity-check the bag came out the way we expect.
    assert_eq!(bag.get_bool("authenticated"), Some(true));
    assert_eq!(bag.get_bool("role.hr"), Some(true));
    assert_eq!(bag.get_bool("perm.view_ssn"), Some(true));
    assert_eq!(bag.get_int("delegation.depth"), Some(1));

    let routes = compile_config(HR_ROUTE_YAML).unwrap().routes;
    let route = routes.get("get_employee").unwrap();

    let mut payload = RoutePayload::with_result(
        json!({ "employee_id": "123-45-6789" }),
        json!({
            "ssn": "555-12-3456",
            "salary": 95000,
            "employee_id": "123-45-6789",
        }),
    );

    let r = evaluate_route(
        route,
        &mut bag,
        &mut payload,
        &pdp(),
        &plugins(),
        &delegations(),
        &elicitations(),
    )
    .await;
    assert_eq!(r.decision, Decision::Allow);
    let result = payload.result.as_ref().unwrap();
    // view_ssn=true and role.hr=true → both fields kept; employee_id masked.
    assert_eq!(result["ssn"], json!("555-12-3456"));
    assert_eq!(result["salary"], json!(95000));
    assert_eq!(result["employee_id"], json!("*******6789"));
}

#[tokio::test]
async fn mallory_gets_both_fields_redacted_through_cmf_bridge() {
    let mut bag = BagBuilder::new()
        .with_security(&mallory_no_perm())
        .with_delegation(&shallow_delegation())
        .build();

    let routes = compile_config(HR_ROUTE_YAML).unwrap().routes;
    let route = routes.get("get_employee").unwrap();

    let mut payload = RoutePayload::with_result(
        json!({ "employee_id": "555-44-3333" }),
        json!({
            "ssn": "111-22-3333",
            "salary": 80000,
            "employee_id": "555-44-3333",
        }),
    );

    let r = evaluate_route(
        route,
        &mut bag,
        &mut payload,
        &pdp(),
        &plugins(),
        &delegations(),
        &elicitations(),
    )
    .await;
    assert_eq!(r.decision, Decision::Allow);
    let result = payload.result.as_ref().unwrap();
    // Neither role.hr nor perm.view_ssn populated → both redact()s fire.
    assert_eq!(result["ssn"], json!("[REDACTED]"));
    assert_eq!(result["salary"], json!("[REDACTED]"));
    assert_eq!(result["employee_id"], json!("*******3333"));
}

#[tokio::test]
async fn deep_delegation_denies_through_cmf_bridge() {
    let mut bag = BagBuilder::new()
        .with_security(&alice_hr())
        .with_delegation(&deep_delegation()) // depth = 3
        .build();

    assert_eq!(bag.get_int("delegation.depth"), Some(3));

    let routes = compile_config(HR_ROUTE_YAML).unwrap().routes;
    let route = routes.get("get_employee").unwrap();

    let mut payload = RoutePayload::with_result(
        json!({ "employee_id": "123-45-6789" }),
        json!({ "ssn": "x", "salary": 1, "employee_id": "123-45-6789" }),
    );
    let r = evaluate_route(
        route,
        &mut bag,
        &mut payload,
        &pdp(),
        &plugins(),
        &delegations(),
        &elicitations(),
    )
    .await;
    assert!(matches!(r.decision, Decision::Deny { .. }));
    // Result fields untouched — the result phase never ran.
    assert_eq!(payload.result.as_ref().unwrap()["ssn"], json!("x"));
}

#[tokio::test]
async fn args_attributes_flow_into_bag_for_policy_use() {
    // Bridge args payload into the bag, then check that a policy
    // predicate using `args.<key>` evaluates against it. Uses an
    // ad-hoc route, since the canonical HR route doesn't reference
    // `args.*` in its policy block.
    let yaml = r#"
routes:
  guarded_route:
    pre_invocation:
      - "args.include_ssn == true: deny"
"#;
    let routes = compile_config(yaml).unwrap().routes;
    let route = routes.get("guarded_route").unwrap();

    let args = json!({ "include_ssn": true, "id": "abc" });
    let mut bag = BagBuilder::new()
        .with_security(&alice_hr())
        .with_args(&args)
        .build();
    assert_eq!(bag.get_bool("args.include_ssn"), Some(true));

    let mut payload = RoutePayload::new(args);
    let r = evaluate_route(
        route,
        &mut bag,
        &mut payload,
        &pdp(),
        &plugins(),
        &delegations(),
        &elicitations(),
    )
    .await;
    match r.decision {
        Decision::Deny { rule_source, .. } => {
            assert!(
                rule_source.contains("pre_invocation"),
                "got source {}",
                rule_source
            );
        },
        d => panic!("expected Deny on include_ssn, got {:?}", d),
    }
}

#[tokio::test]
async fn anonymous_user_denied_at_authenticated_check() {
    // No security extension at all → no `authenticated` key in bag →
    // `require(authenticated)` denies.
    let mut bag = BagBuilder::new()
        .with_delegation(&shallow_delegation())
        .build();
    assert!(!bag.contains("authenticated"));

    let routes = compile_config(HR_ROUTE_YAML).unwrap().routes;
    let route = routes.get("get_employee").unwrap();

    let mut payload = RoutePayload::with_result(
        json!({ "employee_id": "123-45-6789" }),
        json!({ "ssn": "x", "salary": 1, "employee_id": "123-45-6789" }),
    );
    let r = evaluate_route(
        route,
        &mut bag,
        &mut payload,
        &pdp(),
        &plugins(),
        &delegations(),
        &elicitations(),
    )
    .await;
    assert!(matches!(r.decision, Decision::Deny { .. }));
}
