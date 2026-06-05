// Location: ./crates/apl-cedarling/tests/pdp_basic.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Basic e2e for `CedarlingPdpResolver`: build a Cedarling instance
// against an inline policy store, dispatch a `cedar:` call through
// the resolver, assert the allow/deny path.
//
// This test exercises the full Cedarling stack — bootstrap config
// parsing, policy store loading, schema validation, Cedar evaluation,
// response translation. The `policy-store_no_trusted_issuers.yaml`
// pattern (no trusted JWT issuers configured) is what makes
// `authorize_unsigned` viable for us — Cedarling skips its JWT
// validation path entirely when there are no trusted issuers, so we
// can drive policy decisions purely from the bag-built entities.

use std::sync::Arc;

use apl_core::attributes::AttributeBag;
use apl_core::evaluator::Decision;
use apl_core::step::{PdpCall, PdpDialect, PdpResolver};

use apl_cedarling::pdp::CedarlingPdpResolver;
use cedarling::{BootstrapConfig, Cedarling, PolicyStoreSource};

/// Minimal policy store: one permit policy that fires for
/// `Action::"read"` against any `Document` when the principal
/// carries `roles` containing "reader". The schema declares a
/// `Jans` namespace so policy IDs / entities resolve cleanly.
const POLICY_STORE_YAML: &str = r#"
cedar_version: v4.0.0
policy_stores:
  test-store-001:
    cedar_version: v4.0.0
    name: "test"
    policies:
      1:
        description: reader-only read permit
        creation_date: "2026-05-21T00:00:00.000000"
        policy_content:
          encoding: none
          content_type: cedar
          body: |-
            permit(
                principal,
                action == Jans::Action::"read",
                resource
            )when{
              principal.roles.contains("reader")
            };
    schema:
      encoding: none
      content_type: cedar
      body: |-
        namespace Jans {
        entity Document = { "classification": String };
        entity User = { "roles": Set<String> };
        action "read" appliesTo {
          principal: [User],
          resource: [Document],
          context: {}
        };
        }
"#;

/// Build a Cedarling instance configured with the test policy store
/// and no trusted JWT issuers — so `authorize_unsigned` is the right
/// path (no token validation involved).
async fn build_cedarling() -> Arc<Cedarling> {
    let mut config = BootstrapConfig::default();
    config.application_name = "apl-cedarling-test".to_string();
    config.policy_store_config.source =
        PolicyStoreSource::Yaml(POLICY_STORE_YAML.to_string());
    let cedarling = Cedarling::new(&config)
        .await
        .expect("Cedarling::new should succeed with valid config");
    Arc::new(cedarling)
}

fn alice_with_reader_role() -> AttributeBag {
    let mut bag = AttributeBag::new();
    bag.set("subject.id", "alice");
    bag.set("subject.type", "User");
    bag.set("role.reader", true);
    bag
}

fn bob_no_roles() -> AttributeBag {
    let mut bag = AttributeBag::new();
    bag.set("subject.id", "bob");
    bag.set("subject.type", "User");
    bag
}

fn read_doc_call() -> PdpCall {
    PdpCall {
        // Route YAML `cedarling:(...)` produces this dialect.
        // `apl-pdp-cedar-direct` registers under `PdpDialect::Cedar`
        // so both resolvers can coexist in one PdpRouter.
        dialect: PdpDialect::Cedarling,
        args: serde_yaml::from_str(
            r#"
action: 'Jans::Action::"read"'
resource:
  type: Jans::Document
  id: doc-42
  attributes:
    classification: internal
"#,
        )
        .unwrap(),
    }
}

#[tokio::test]
async fn reader_role_allows() {
    let cedarling = build_cedarling().await;
    let resolver = CedarlingPdpResolver::new(cedarling)
        .with_entity_namespace("Jans");
    let decision = resolver
        .evaluate(&read_doc_call(), &alice_with_reader_role())
        .await
        .expect("evaluate should succeed");
    assert!(
        matches!(decision.decision, Decision::Allow),
        "alice with role.reader should be allowed: got {:?}",
        decision.decision,
    );
}

#[tokio::test]
async fn missing_role_default_denies() {
    let cedarling = build_cedarling().await;
    let resolver = CedarlingPdpResolver::new(cedarling)
        .with_entity_namespace("Jans");
    let decision = resolver
        .evaluate(&read_doc_call(), &bob_no_roles())
        .await
        .expect("evaluate should succeed");
    match decision.decision {
        Decision::Deny { rule_source, .. } => {
            // No permit fired → cedar.default_deny sentinel.
            assert_eq!(rule_source, "cedar.default_deny");
        }
        Decision::Allow => panic!("bob without reader role should be denied"),
    }
}

#[tokio::test]
async fn missing_subject_id_errors_clearly() {
    let cedarling = build_cedarling().await;
    let resolver = CedarlingPdpResolver::new(cedarling);
    // Bag with no subject.id at all — resolver should fail
    // construction of the principal entity with a clear error.
    let bag = AttributeBag::new();
    let err = resolver
        .evaluate(&read_doc_call(), &bag)
        .await
        .expect_err("missing subject.id should error");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("subject.id"),
        "error should call out the missing key, got: {msg}",
    );
}
