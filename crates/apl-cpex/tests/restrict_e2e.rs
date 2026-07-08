// Location: ./crates/apl-cpex/tests/restrict_e2e.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// End-to-end: an APL route with `restrict` effects, driven through the
// real PluginManager + APL visitor, must fold the emitted constraints
// and surface them on the typed `candidate_constraint` extension slot
// that the host router reads off `PipelineResult.modified_extensions`.
// A `custom`-label contradiction must fail closed. Covers R2 of
// docs/apl-restrict-effect-design.md.

use std::sync::Arc;

use cpex_core::cmf::enums::Role;
use cpex_core::cmf::{CmfHook, Message, MessagePayload};
use cpex_core::extensions::{CandidateConstraintExtension, Extensions, MetaExtension, OnEmpty};
use cpex_core::manager::PluginManager;

use apl_cpex::{register_apl, AplOptions, DispatchCache, MemorySessionStore};

fn cmf_payload(text: &str) -> MessagePayload {
    MessagePayload {
        message: Message::text(Role::User, text),
    }
}

fn meta_for_tool(name: &str) -> MetaExtension {
    let mut meta = MetaExtension::default();
    meta.entity_type = Some("tool".to_string());
    meta.entity_name = Some(name.to_string());
    meta
}

/// Build a manager wired with the APL visitor from `yaml`. `restrict`
/// needs no plugins of its own, so no factories are registered.
async fn build_manager(yaml: &str) -> Arc<PluginManager> {
    let mgr = Arc::new(PluginManager::default());
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
    mgr
}

/// Read the folded constraint off the merged extensions' typed slot.
fn constraint(ext: &Extensions) -> Option<CandidateConstraintExtension> {
    ext.candidate_constraint.as_ref().map(|arc| (**arc).clone())
}

/// A single unconditional `restrict` emits its constraint on
/// `cpex.candidate_constraint`, and the request still continues (restrict
/// never denies).
#[tokio::test]
async fn restrict_emits_constraint_on_side_channel() {
    const YAML: &str = r#"
routes:
  - tool: infer
    apl:
      pre_invocation:
        - restrict: { allow_regions: [eu] }
"#;
    let mgr = build_manager(YAML).await;

    let ext = Extensions {
        meta: Some(Arc::new(meta_for_tool("infer"))),
        ..Default::default()
    };
    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", cmf_payload("hi"), ext, None)
        .await;

    assert!(
        result.continue_processing,
        "restrict never denies: violation = {:?}",
        result.violation
    );
    let merged = result
        .modified_extensions
        .expect("restrict must surface a constraint via modified_extensions");
    let c = constraint(&merged).expect("candidate_constraint slot must be set");
    assert_eq!(c.allow_regions.as_deref(), Some(&["eu".to_string()][..]));
    assert_eq!(c.on_empty, OnEmpty::Deny);
}

/// Two restricts in the same phase fold: allow-sets intersect, deny-sets
/// union, and the blob is the single folded result.
#[tokio::test]
async fn two_restricts_fold_into_one_blob() {
    const YAML: &str = r#"
routes:
  - tool: infer
    apl:
      pre_invocation:
        - restrict: { allow_models: ["vllm/*", "anthropic/*"], deny_models: ["openai/*"] }
        - restrict: { allow_models: ["anthropic/*", "cohere/*"] }
"#;
    let mgr = build_manager(YAML).await;

    let ext = Extensions {
        meta: Some(Arc::new(meta_for_tool("infer"))),
        ..Default::default()
    };
    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", cmf_payload("hi"), ext, None)
        .await;

    assert!(result.continue_processing);
    let merged = result.modified_extensions.expect("modified_extensions");
    let c = constraint(&merged).expect("candidate_constraint slot");
    assert_eq!(c.allow_models.as_deref(), Some(&["anthropic/*".to_string()][..])); // intersection
    assert_eq!(c.deny_models, vec!["openai/*".to_string()]); // union
    assert_eq!(c.on_empty, OnEmpty::Deny);
}

/// A `when`-gated restrict that does NOT fire (gate false) emits no blob.
#[tokio::test]
async fn gated_restrict_absent_when_gate_false() {
    const YAML: &str = r#"
routes:
  - tool: infer
    apl:
      pre_invocation:
        - when: "session.labels contains 'eu_resident'"
          do:
            - restrict: { allow_regions: [eu] }
"#;
    let mgr = build_manager(YAML).await;

    // No `eu_resident` label on the session → gate is false.
    let ext = Extensions {
        meta: Some(Arc::new(meta_for_tool("infer"))),
        ..Default::default()
    };
    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", cmf_payload("hi"), ext, None)
        .await;

    assert!(result.continue_processing);
    // Either no modified_extensions at all, or one with an empty slot.
    let has_constraint = result
        .modified_extensions
        .as_ref()
        .and_then(constraint)
        .is_some();
    assert!(
        !has_constraint,
        "gate was false — no constraint should be emitted"
    );
}

/// Two restricts requiring the same `custom` label to differ is an
/// unsatisfiable contradiction — the request fails closed with a
/// `policy.restrict_conflict` violation.
#[tokio::test]
async fn conflicting_custom_labels_fail_closed() {
    const YAML: &str = r#"
routes:
  - tool: infer
    apl:
      pre_invocation:
        - restrict: { custom: { gpu: h100 } }
        - restrict: { custom: { gpu: a100 } }
"#;
    let mgr = build_manager(YAML).await;

    let ext = Extensions {
        meta: Some(Arc::new(meta_for_tool("infer"))),
        ..Default::default()
    };
    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", cmf_payload("hi"), ext, None)
        .await;

    assert!(
        !result.continue_processing,
        "contradictory custom labels must fail closed"
    );
    let violation = result.violation.expect("conflict must surface a violation");
    assert_eq!(violation.code, "policy.restrict_conflict");
}
