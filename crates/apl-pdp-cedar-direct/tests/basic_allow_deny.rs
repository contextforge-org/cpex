// Location: ./crates/apl-pdp-cedar-direct/tests/basic_allow_deny.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Smoke tests for `CedarDirectResolver`. Cover the canonical
// allow/deny paths, the role-driven case (proves bag attributes reach
// the principal entity), and the policy-id attribution that operators
// rely on for audit logs.

use apl_core::attributes::AttributeBag;
use apl_core::evaluator::Decision;
use apl_core::step::{PdpCall, PdpDialect, PdpResolver};

use apl_pdp_cedar_direct::CedarDirectResolver;

/// Build a `PdpCall` against `Action::"read"` on a `Document::"doc-1"`.
/// Used across the test cases so the request side stays constant and
/// only the policy + bag varies.
fn read_doc_call() -> PdpCall {
    PdpCall {
        dialect: PdpDialect::Cedar,
        args: serde_yaml::from_str(
            r#"
action: 'Action::"read"'
resource:
  type: Document
  id: doc-1
"#,
        )
        .unwrap(),
    }
}

fn alice_bag() -> AttributeBag {
    let mut bag = AttributeBag::new();
    bag.set("subject.id", "alice");
    bag.set("subject.type", "User");
    bag
}

// =====================================================================
// Scenarios
// =====================================================================

/// One unconditional `permit` policy → request → Allow. Confirms the
/// happy path end-to-end: parse, build entities, build request,
/// authorize, translate decision back.
#[tokio::test]
async fn unconditional_permit_returns_allow() {
    const POLICY: &str = r#"
        @id("allow-all")
        permit(principal, action, resource);
    "#;

    let resolver = CedarDirectResolver::from_policy_text(POLICY).expect("policy parses");
    let decision = resolver
        .evaluate(&read_doc_call(), &alice_bag())
        .await
        .expect("evaluate");

    assert_eq!(decision.decision, Decision::Allow);
    assert_eq!(decision.diagnostics, vec!["allow-all".to_string()]);
}

/// No policies → default-deny. Confirms the fail-closed default that
/// drops out of Cedar's semantics (no `permit` matches, so the request
/// denies).
#[tokio::test]
async fn empty_policy_set_denies_by_default() {
    let resolver = CedarDirectResolver::from_policy_text("").expect("empty policy set is valid");
    let decision = resolver
        .evaluate(&read_doc_call(), &alice_bag())
        .await
        .expect("evaluate");

    match decision.decision {
        Decision::Deny { rule_source, .. } => {
            assert_eq!(rule_source, "cedar.default_deny");
        }
        other => panic!("expected Deny on empty policy set, got {:?}", other),
    }
    assert!(decision.diagnostics.is_empty(), "no policies fired");
}

/// A policy that requires `principal.roles.contains("hr")`. Bag has
/// `role.hr=true` → reaches principal.roles → Allow. Proves the
/// bag-attribute-to-entity-attribute translation works end-to-end:
/// apl-cmf would normally populate `role.hr` from
/// `SecurityExtension.subject.roles`, but the bag works the same way
/// however it got there.
#[tokio::test]
async fn role_in_bag_reaches_principal_attributes() {
    const POLICY: &str = r#"
        @id("hr-only")
        permit(principal, action == Action::"read", resource)
        when { principal.roles.contains("hr") };
    "#;

    let resolver = CedarDirectResolver::from_policy_text(POLICY).expect("policy parses");

    // Alice has role.hr → policy permits.
    let mut bag = alice_bag();
    bag.set("role.hr", true);
    let decision = resolver.evaluate(&read_doc_call(), &bag).await.expect("evaluate");
    assert_eq!(decision.decision, Decision::Allow);
    assert_eq!(decision.diagnostics, vec!["hr-only".to_string()]);

    // Bob has no roles → policy doesn't match → default-deny.
    let mut bob_bag = AttributeBag::new();
    bob_bag.set("subject.id", "bob");
    bob_bag.set("subject.type", "User");
    let decision = resolver
        .evaluate(&read_doc_call(), &bob_bag)
        .await
        .expect("evaluate");
    match decision.decision {
        Decision::Deny { rule_source, .. } => {
            assert_eq!(
                rule_source, "cedar.default_deny",
                "no permit matched → default-deny, not policy-attributed"
            );
        }
        other => panic!("expected Deny for bob, got {:?}", other),
    }
}

/// A policy with `@id("blocklist")` that forbids access for a specific
/// principal. When the forbid fires, the violation's `rule_source`
/// should carry the policy id so wire errors / audit logs say
/// "denied via blocklist" instead of "denied by Cedar."
#[tokio::test]
async fn forbid_attribution_carries_policy_id() {
    const POLICY: &str = r#"
        @id("permit-all")
        permit(principal, action, resource);

        @id("blocklist")
        forbid(principal == User::"alice", action, resource);
    "#;

    let resolver = CedarDirectResolver::from_policy_text(POLICY).expect("policy parses");
    let decision = resolver
        .evaluate(&read_doc_call(), &alice_bag())
        .await
        .expect("evaluate");

    match decision.decision {
        Decision::Deny { rule_source, reason } => {
            assert_eq!(
                rule_source, "blocklist",
                "violation should be attributed to the forbid policy by id"
            );
            assert!(
                reason.as_deref().unwrap_or("").contains("blocklist"),
                "reason should mention the firing policy: {:?}",
                reason
            );
        }
        other => panic!("expected Deny via blocklist, got {:?}", other),
    }
    assert!(decision.diagnostics.iter().any(|d| d == "blocklist"));
}

/// Missing `subject.id` in the bag is a configuration fault (identity
/// hook didn't populate it). Resolver returns a Dispatch error rather
/// than silently building a malformed Cedar request.
#[tokio::test]
async fn missing_subject_id_errors_clearly() {
    const POLICY: &str = "permit(principal, action, resource);";
    let resolver = CedarDirectResolver::from_policy_text(POLICY).expect("policy parses");

    // Empty bag → no subject.id.
    let bag = AttributeBag::new();
    let err = resolver
        .evaluate(&read_doc_call(), &bag)
        .await
        .expect_err("should fail with no subject.id");

    let msg = format!("{}", err);
    assert!(
        msg.contains("subject.id"),
        "error should mention the missing key: {}",
        msg
    );
}

/// Construction from a config block — the path the visitor uses when
/// it sees a Cedar PDP block in unified-config YAML.
#[tokio::test]
async fn from_config_builds_resolver_from_yaml_block() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
dialect: cedar
policy_text: |
  @id("from-config")
  permit(principal, action, resource);
"#,
    )
    .expect("yaml parses");

    let resolver = CedarDirectResolver::from_config(&yaml).expect("config valid");
    let decision = resolver
        .evaluate(&read_doc_call(), &alice_bag())
        .await
        .expect("evaluate");
    assert_eq!(decision.decision, Decision::Allow);
    assert_eq!(decision.diagnostics, vec!["from-config".to_string()]);
}

/// Operators can register the resolver under a custom dialect to
/// coexist with another Cedar engine on the same PdpRouter.
#[tokio::test]
async fn with_dialect_overrides_default() {
    let resolver = CedarDirectResolver::from_policy_text("permit(principal, action, resource);")
        .expect("policy parses")
        .with_dialect(PdpDialect::Custom("workload".to_string()));

    assert_eq!(resolver.dialect(), PdpDialect::Custom("workload".to_string()));
}
