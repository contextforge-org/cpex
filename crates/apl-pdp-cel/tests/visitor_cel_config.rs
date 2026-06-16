// Location: ./crates/apl-pdp-cel/tests/visitor_cel_config.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// End-to-end integration: a unified-config YAML that
//
//   1. declares a `cel` PDP under `global.apl.pdp[]`,
//   2. attaches a `cel:(expr: "...")` policy step to a route,
//
// must flow a real decision from the cpex-core dispatcher through
// `AplConfigVisitor` → `PdpFactory` → `CelResolver` → the `cel`
// interpreter → back into the route handler's allow/deny split.
//
// This proves the *wiring* end-to-end. The crate's unit tests cover the
// bag→activation mapping and the resolver in isolation; what's special
// here is that the resolver was never instantiated in Rust by the test —
// the visitor built it from YAML at `load_config_yaml` time because the
// host registered `CelPdpFactory` via `AplOptions.pdp_factories`. If this
// passes, an operator who drops a `cel` block into their config gets the
// same behavior without writing any glue.

use std::collections::HashSet;
use std::sync::Arc;

use cpex_core::cmf::enums::Role;
use cpex_core::cmf::{CmfHook, Message, MessagePayload};
use cpex_core::extensions::{MetaExtension, SecurityExtension, SubjectExtension, SubjectType};
use cpex_core::hooks::payload::Extensions;
use cpex_core::manager::PluginManager;

use apl_cpex::{register_apl, AplOptions, DispatchCache, MemorySessionStore};
use apl_pdp_cel::CelPdpFactory;

// The config the visitor walks. A `cel:` step whose expression reads the
// common attribute vocabulary (`subject.id`, `role.*`) the cmf BagBuilder
// lifts from the SecurityExtension. `has(role.reader)` guards the optional
// role namespace so a principal with no roles evaluates to a clean `false`
// (Deny) rather than an undeclared-variable error.
const YAML: &str = r#"
global:
  apl:
    pdp:
      - kind: cel
routes:
  - tool: get_document
    apl:
      policy:
        - cel:
            expr: |
              subject.id == "alice" && has(role.reader) && role.reader
"#;

fn meta_for_tool(name: &str) -> MetaExtension {
    MetaExtension {
        entity_type: Some("tool".to_string()),
        entity_name: Some(name.to_string()),
        ..Default::default()
    }
}

fn security_with_roles(id: &str, roles: &[&str]) -> SecurityExtension {
    SecurityExtension {
        subject: Some(SubjectExtension {
            id: Some(id.to_string()),
            subject_type: Some(SubjectType::User),
            roles: roles.iter().map(|r| r.to_string()).collect::<HashSet<_>>(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

async fn build_manager() -> Arc<PluginManager> {
    build_manager_with_yaml(YAML)
        .await
        .expect("load_config_yaml")
}

/// Build a manager from arbitrary YAML; returns the load error so
/// negative tests can inspect it. Mirrors `build_manager` but lets
/// tests swap the config text under test.
async fn build_manager_with_yaml(
    yaml: &str,
) -> Result<Arc<PluginManager>, Box<dyn std::error::Error + Send + Sync>> {
    let mgr = Arc::new(PluginManager::default());
    register_apl(
        &mgr,
        AplOptions {
            dispatch_cache: Arc::new(DispatchCache::new()),
            session_store: Arc::new(MemorySessionStore::new()),
            pdps: Vec::new(),
            // The factory is the load-bearing wiring under test: the visitor
            // sees `kind: cel` in YAML and finds this factory by key.
            pdp_factories: vec![Arc::new(CelPdpFactory::new())],
            base_capabilities: None,
        },
    );
    mgr.load_config_yaml(yaml).map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
        format!("{e}").into()
    })?;
    mgr.initialize().await.map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
        format!("{e}").into()
    })?;
    Ok(mgr)
}

fn payload() -> MessagePayload {
    MessagePayload {
        message: Message::text(Role::User, "fetch doc-42"),
    }
}

/// `alice` with `role.reader=true` satisfies the CEL predicate → Allow.
/// End-to-end: visitor built the resolver from YAML, route handler
/// dispatched the `cel:` step into it, CEL returned `true`, pipeline
/// continues.
#[tokio::test]
async fn config_declared_cel_pdp_allows_matching_subject() {
    let mgr = build_manager().await;
    let ext = Extensions {
        meta: Some(Arc::new(meta_for_tool("get_document"))),
        security: Some(Arc::new(security_with_roles("alice", &["reader"]))),
        ..Default::default()
    };

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload(), ext, None)
        .await;

    assert!(
        result.continue_processing,
        "alice+reader should satisfy the CEL predicate; got violation = {:?}",
        result.violation
    );
}

/// `eve` is not `alice` → the CEL predicate is `false` → Deny halts the
/// pipeline. (Short-circuit `&&` means the missing `role` namespace is
/// never touched.)
#[tokio::test]
async fn config_declared_cel_pdp_denies_non_matching_subject() {
    let mgr = build_manager().await;
    let ext = Extensions {
        meta: Some(Arc::new(meta_for_tool("get_document"))),
        security: Some(Arc::new(security_with_roles("eve", &["reader"]))),
        ..Default::default()
    };

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload(), ext, None)
        .await;

    assert!(
        !result.continue_processing,
        "eve should fail the subject.id check and be denied",
    );
    assert!(
        result.violation.is_some(),
        "deny path must surface a violation",
    );
}

/// A malformed CEL PDP config (`on_error: maybe`) must be rejected at
/// `load_config_yaml` rather than discovered on first request. The
/// visitor → `CelPdpFactory::build` → `CelResolver::from_config` chain
/// surfaces `BuildError::ConfigShape` as a `cpex_core::PluginError`,
/// which bubbles out of load.
#[tokio::test]
async fn malformed_on_error_is_rejected_at_load() {
    const BAD_YAML: &str = r#"
global:
  apl:
    pdp:
      - kind: cel
        on_error: maybe
routes:
  - tool: get_document
    apl:
      policy:
        - cel:
            expr: |
              subject.id == "alice"
"#;
    let err = match build_manager_with_yaml(BAD_YAML).await {
        Ok(_) => panic!("malformed on_error must fail load_config_yaml"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("on_error") && msg.contains("maybe"),
        "load error should name the bad field and value; got: {msg}",
    );
}

/// `on_error: allow` at the config level flips an eval error (here, an
/// undeclared-variable reference) to Allow end-to-end. Pins the
/// fail-open knob travels from YAML → factory → resolver → router →
/// route-handler decision the same way as the unit-level resolver test.
#[tokio::test]
async fn on_error_allow_yaml_flips_eval_error_to_allow_end_to_end() {
    const ALLOW_YAML: &str = r#"
global:
  apl:
    pdp:
      - kind: cel
        on_error: allow
routes:
  - tool: get_document
    apl:
      policy:
        - cel:
            expr: |
              nonexistent.field == "value"
"#;
    let mgr = build_manager_with_yaml(ALLOW_YAML)
        .await
        .expect("on_error: allow config must load cleanly");

    let ext = Extensions {
        meta: Some(Arc::new(meta_for_tool("get_document"))),
        security: Some(Arc::new(security_with_roles("alice", &["reader"]))),
        ..Default::default()
    };

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload(), ext, None)
        .await;

    assert!(
        result.continue_processing,
        "eval error under on_error=allow must surface as Allow; got violation = {:?}",
        result.violation,
    );
}

/// A `cel:` step with no `expr` (the author wrote reactions but forgot
/// the predicate) is an author bug that the parser accepts opaquely —
/// the resolver only learns of it at request time. It must surface as a
/// clean Deny ("PDP error") that halts the pipeline, never a panic.
/// Complements the unit-level `missing_expr_is_dispatch_error` by
/// proving the error travels through the real dispatcher.
#[tokio::test]
async fn missing_expr_at_request_time_denies_without_panicking() {
    const NO_EXPR_YAML: &str = r#"
global:
  apl:
    pdp:
      - kind: cel
routes:
  - tool: get_document
    apl:
      policy:
        - cel:
            on_deny:
              - deny
"#;
    let mgr = build_manager_with_yaml(NO_EXPR_YAML)
        .await
        .expect("a cel step without expr is accepted at parse/load time");

    let ext = Extensions {
        meta: Some(Arc::new(meta_for_tool("get_document"))),
        security: Some(Arc::new(security_with_roles("alice", &["reader"]))),
        ..Default::default()
    };

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload(), ext, None)
        .await;

    assert!(
        !result.continue_processing,
        "a missing-expr cel step must halt the pipeline, not allow through",
    );
    assert!(
        result.violation.is_some(),
        "missing-expr dispatch error must surface as a violation",
    );
}

/// A `cel:` predicate that reads the `meta` namespace
/// (`meta.entity_name`) proves the cmf BagBuilder lifts `MetaExtension`
/// into the bag and the activation exposes it to CEL — the other
/// integration cases only exercise `subject.*` / `role.*` from the
/// SecurityExtension. Gates the tool by name end-to-end.
#[tokio::test]
async fn cel_reads_meta_entity_name_from_bag() {
    const META_YAML: &str = r#"
global:
  apl:
    pdp:
      - kind: cel
routes:
  - tool: get_document
    apl:
      policy:
        - cel:
            expr: |
              meta.entity_name == "get_document"
"#;
    let mgr = build_manager_with_yaml(META_YAML)
        .await
        .expect("load_config_yaml");

    // Matching tool name → predicate true → Allow.
    let allow_ext = Extensions {
        meta: Some(Arc::new(meta_for_tool("get_document"))),
        security: Some(Arc::new(security_with_roles("alice", &["reader"]))),
        ..Default::default()
    };
    let (allow, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload(), allow_ext, None)
        .await;
    assert!(
        allow.continue_processing,
        "meta.entity_name == \"get_document\" must reach CEL and allow; got violation = {:?}",
        allow.violation,
    );
}
