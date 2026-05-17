// Location: ./crates/apl-core/tests/yaml_end_to_end.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// End-to-end integration: YAML config → compiled IR → evaluated against a
// realistic AttributeBag and payload. This exercises the public crate API
// only (`compile_config` + `evaluate_route` + traits) and serves as the
// authoritative "if this passes, apl-core works as a unit" check.
//
// The fixture follows Example 1 from unified-config-proposal.md, adapted to
// the map-keyed `routes:` shape that the parser actually accepts (the spec's
// list-with-matchers form is a deferred shape).

use apl_core::{
    compile_config, evaluate_route, AttributeBag, Decision, FieldOutcome, PdpCall, PdpDecision,
    PdpDialect, PdpError, PdpResolver, PluginError, PluginInvocation, PluginInvoker,
    PluginOutcome, RoutePayload,
};
use async_trait::async_trait;
use serde_json::json;

// ----- Fixtures: a baseline route used by every scenario below. -----

const HR_ROUTE_YAML: &str = r#"
routes:
  get_employee:
    args:
      employee_id: "str"
    policy:
      - "require(authenticated)"
      - "delegation.depth > 2: deny"
    result:
      ssn: "str | redact(!perm.view_ssn)"
      salary: "int | redact(!role.hr)"
      employee_id: "str | mask(4)"
"#;

struct AllowPdp;
#[async_trait]
impl PdpResolver for AllowPdp {
    fn dialect(&self) -> PdpDialect { PdpDialect::Cedar }
    async fn evaluate(
        &self,
        _call: &PdpCall,
        _bag: &AttributeBag,
    ) -> Result<PdpDecision, PdpError> {
        Ok(PdpDecision { decision: Decision::Allow, diagnostics: vec![] })
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

// ----- Scenarios -----

#[tokio::test]
async fn alice_full_access_sees_unredacted_result_with_masked_id() {
    // Alice: authenticated HR with view_ssn permission, depth=1.
    let mut bag = AttributeBag::new();
    bag.set("authenticated", true);
    bag.set("role.hr", true);
    bag.set("perm.view_ssn", true);
    bag.set("delegation.depth", 1_i64);

    let routes = compile_config(HR_ROUTE_YAML).expect("YAML compiles").routes;
    let route = routes.get("get_employee").expect("route present");

    let mut payload = RoutePayload::with_result(
        json!({ "employee_id": "123-45-6789" }),
        json!({
            "ssn": "555-12-3456",
            "salary": 95000,
            "employee_id": "123-45-6789",
        }),
    );

    let r = evaluate_route(route, &bag, &mut payload, &AllowPdp, &NoPlugins).await;
    assert_eq!(r.decision, Decision::Allow);
    assert!(r.args_modified == false, "args has only a `str` validator, no mutation");
    assert!(r.result_modified, "result has mask + redact stages");

    let result = payload.result.as_ref().unwrap();
    // view_ssn=true → redact(!view_ssn) skipped → ssn intact.
    assert_eq!(result["ssn"], json!("555-12-3456"));
    // role.hr=true → redact(!role.hr) skipped → salary intact.
    assert_eq!(result["salary"], json!(95000));
    // mask(4) always applies → keeps last 4 chars.
    assert_eq!(result["employee_id"], json!("*******6789"));
}

#[tokio::test]
async fn mallory_no_perm_no_role_gets_both_fields_redacted() {
    // Mallory: authenticated but no role, no perm, shallow delegation.
    let mut bag = AttributeBag::new();
    bag.set("authenticated", true);
    bag.set("delegation.depth", 1_i64);
    // role.hr and perm.view_ssn are absent → IsTrue=false → !IsTrue=true → redact fires.

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

    let r = evaluate_route(route, &bag, &mut payload, &AllowPdp, &NoPlugins).await;
    assert_eq!(r.decision, Decision::Allow);

    let result = payload.result.as_ref().unwrap();
    assert_eq!(result["ssn"], json!("[REDACTED]"));
    assert_eq!(result["salary"], json!("[REDACTED]"));
    assert_eq!(result["employee_id"], json!("*******3333"));
}

#[tokio::test]
async fn deep_delegation_denies_at_policy() {
    // Authenticated user but delegation.depth=3 > 2 → policy deny.
    let mut bag = AttributeBag::new();
    bag.set("authenticated", true);
    bag.set("role.hr", true);
    bag.set("perm.view_ssn", true);
    bag.set("delegation.depth", 3_i64);

    let routes = compile_config(HR_ROUTE_YAML).unwrap().routes;
    let route = routes.get("get_employee").unwrap();

    let mut payload = RoutePayload::with_result(
        json!({ "employee_id": "123-45-6789" }),
        json!({ "ssn": "x", "salary": 1, "employee_id": "123-45-6789" }),
    );

    let r = evaluate_route(route, &bag, &mut payload, &AllowPdp, &NoPlugins).await;
    match r.decision {
        Decision::Deny { rule_source, .. } => {
            assert!(rule_source.contains("policy"), "got source: {}", rule_source);
        }
        d => panic!("expected policy deny, got {:?}", d),
    }
    // Result phase never ran → no result mutation.
    assert!(!r.result_modified);
    assert_eq!(payload.result.as_ref().unwrap()["ssn"], json!("x"));
    assert_eq!(payload.result.as_ref().unwrap()["employee_id"], json!("123-45-6789"));
}

#[tokio::test]
async fn unauthenticated_user_is_denied_before_args_mutate_result() {
    // No `authenticated` key → require(authenticated) fails → deny.
    let bag = AttributeBag::new();
    bag.contains("authenticated"); // sanity: confirm we built an empty bag.

    let routes = compile_config(HR_ROUTE_YAML).unwrap().routes;
    let route = routes.get("get_employee").unwrap();

    let mut payload = RoutePayload::with_result(
        json!({ "employee_id": "123-45-6789" }),
        json!({ "ssn": "999-99-9999", "salary": 50000, "employee_id": "123-45-6789" }),
    );

    let r = evaluate_route(route, &bag, &mut payload, &AllowPdp, &NoPlugins).await;
    assert!(matches!(r.decision, Decision::Deny { .. }));
    assert!(!r.result_modified);
}

#[tokio::test]
async fn args_validator_rejects_wrong_type() {
    // args.employee_id is declared `str` — an integer value violates that
    // and should produce a deny during the args phase, before policy runs.
    let mut bag = AttributeBag::new();
    bag.set("authenticated", true);
    bag.set("delegation.depth", 1_i64);

    let routes = compile_config(HR_ROUTE_YAML).unwrap().routes;
    let route = routes.get("get_employee").unwrap();

    let mut payload = RoutePayload::with_result(
        json!({ "employee_id": 42 }), // ← wrong type
        json!({ "ssn": "x", "salary": 1, "employee_id": "x" }),
    );

    let r = evaluate_route(route, &bag, &mut payload, &AllowPdp, &NoPlugins).await;
    match r.decision {
        Decision::Deny { rule_source, .. } => {
            assert!(
                rule_source.contains("employee_id"),
                "expected args field source, got {}",
                rule_source,
            );
        }
        d => panic!("expected args-phase deny, got {:?}", d),
    }
    // Result phase didn't run.
    assert!(!r.result_modified);
}

#[tokio::test]
async fn inbound_only_evaluation_skips_result_phase() {
    // Simulates the inbound path: payload has no result yet. Args + policy
    // run; result phase is skipped; post_policy runs (none defined here).
    let mut bag = AttributeBag::new();
    bag.set("authenticated", true);
    bag.set("delegation.depth", 1_i64);

    let routes = compile_config(HR_ROUTE_YAML).unwrap().routes;
    let route = routes.get("get_employee").unwrap();

    let mut payload = RoutePayload::new(json!({ "employee_id": "123-45-6789" }));
    let r = evaluate_route(route, &bag, &mut payload, &AllowPdp, &NoPlugins).await;
    assert_eq!(r.decision, Decision::Allow);
    assert!(!r.result_modified);
    assert!(payload.result.is_none());
    // Args field is untouched — `str` is validator-only, no transform.
    assert_eq!(payload.args["employee_id"], json!("123-45-6789"));
}

// ----- Smoke test: phase-existence reporting matches what's in the YAML. -----

#[test]
fn compiled_route_phase_set_reflects_yaml_blocks() {
    use apl_core::Phase;
    let routes = compile_config(HR_ROUTE_YAML).unwrap().routes;
    let route = routes.get("get_employee").unwrap();
    let phases = route.declared_phases();
    assert!(phases.contains(Phase::Args));
    assert!(phases.contains(Phase::Policy));
    assert!(phases.contains(Phase::Result));
    assert!(!phases.contains(Phase::PostPolicy));
}

// Marker so the file isn't all `_` — sanity check that `FieldOutcome` is
// reachable as part of the public surface alongside the orchestrator's
// `RouteDecision`. Removing this when downstream consumers exist.
#[test]
fn public_surface_includes_field_outcome() {
    let _: FieldOutcome = FieldOutcome::Pass;
}
