// Location: ./builtins/pdps/opa/tests/visitor_opa_config.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// End-to-end integration: a unified-config YAML that
//
//   1. declares an `opa` PDP under `global.apl.pdp[]` with Rego module(s),
//   2. attaches an `opa: { query: "..." }` policy step to a route,
//
// must flow a real decision from the cpex-core dispatcher through
// `AplConfigVisitor` → `PdpFactory` → `OpaResolver` → the regorus engine →
// back into the route handler's allow/deny split.
//
// This proves the wiring end-to-end. The crate's unit tests cover the
// bag→input mapping, config parsing, and the decision contract in isolation;
// what's special here is that the resolver was never instantiated in Rust by
// the test — the visitor built it from YAML at `load_config_yaml` time because
// the host registered `OpaPdpFactory` via `AplOptions.pdp_factories`. If this
// passes, an operator who drops an `opa` block into their config gets the same
// behavior without writing any glue.

use std::collections::HashSet;
use std::sync::Arc;

use cpex_core::cmf::enums::Role;
use cpex_core::cmf::{CmfHook, Message, MessagePayload};
use cpex_core::extensions::{MetaExtension, SecurityExtension, SubjectExtension, SubjectType};
use cpex_core::hooks::payload::Extensions;
use cpex_core::manager::PluginManager;

use apl_cpex::{register_apl, AplOptions, DispatchCache, MemorySessionStore};
use cpex_pdp_opa::OpaPdpFactory;

// A boolean allow-rule policy declared globally; the route queries it. The bag
// the cmf BagBuilder lifts from the SecurityExtension exposes `subject.id`,
// which the policy reads as `input.subject.id`.
const YAML: &str = r#"
global:
  apl:
    pdp:
      - kind: opa
        modules:
          - |
            package authz
            default allow := false
            allow if input.subject.id == "alice"
routes:
  - tool: get_document
    apl:
      pre_invocation:
        - opa:
            query: data.authz.allow
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

/// Build a manager from arbitrary YAML; returns the load error so negative
/// tests can inspect it.
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
            // sees `kind: opa` in YAML and finds this factory by key.
            pdp_factories: vec![Arc::new(OpaPdpFactory::new())],
            session_store_factories: Vec::new(),
            base_capabilities: None,
        },
    );
    mgr.load_config_yaml(yaml)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { format!("{e}").into() })?;
    mgr.initialize()
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { format!("{e}").into() })?;
    Ok(mgr)
}

fn payload() -> MessagePayload {
    MessagePayload {
        message: Message::text(Role::User, "fetch doc-42"),
    }
}

/// `alice` satisfies the Rego `allow` rule → the query is `true` → Allow.
/// End-to-end: the visitor built the resolver from YAML, the route handler
/// dispatched the `opa:` step into it, regorus returned `true`, the pipeline
/// continues.
#[tokio::test]
async fn config_declared_opa_pdp_allows_matching_subject() {
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
        "alice should satisfy the Rego allow rule; got violation = {:?}",
        result.violation
    );
}

/// `eve` does not match; the `allow` rule has a `default` of false → the query
/// is `false` → Deny halts the pipeline with a violation.
#[tokio::test]
async fn config_declared_opa_pdp_denies_non_matching_subject() {
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

/// A malformed OPA PDP config (`on_error: maybe`) must be rejected at
/// `load_config_yaml` rather than discovered on first request. The
/// visitor → `OpaPdpFactory::build` → `OpaResolver::from_config` chain surfaces
/// `BuildError::ConfigShape` as a `PluginError`, which bubbles out of load.
#[tokio::test]
async fn malformed_on_error_is_rejected_at_load() {
    const BAD_YAML: &str = r#"
global:
  apl:
    pdp:
      - kind: opa
        on_error: maybe
        modules:
          - "package authz\ndefault allow := false\n"
routes:
  - tool: get_document
    apl:
      pre_invocation:
        - opa:
            query: data.authz.allow
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

/// An `opa:` step with no `query` is an author bug the parser accepts opaquely;
/// the resolver only learns of it at request time. It must surface as a clean
/// Deny that halts the pipeline, never a panic.
#[tokio::test]
async fn missing_query_at_request_time_denies_without_panicking() {
    const NO_QUERY_YAML: &str = r#"
global:
  apl:
    pdp:
      - kind: opa
        modules:
          - "package authz\ndefault allow := false\n"
routes:
  - tool: get_document
    apl:
      pre_invocation:
        - opa:
            on_deny:
              - deny
"#;
    let mgr = build_manager_with_yaml(NO_QUERY_YAML)
        .await
        .expect("an opa step without query is accepted at parse/load time");

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
        "a missing-query opa step must halt the pipeline, not allow through",
    );
    assert!(
        result.violation.is_some(),
        "missing-query dispatch error must surface as a violation",
    );
}

/// The deny-set idiom works end-to-end: a `deny[msg]` set-valued query allows
/// when empty and denies when non-empty. This is the dominant OPA authoring
/// style, so proving it through the real dispatcher matters.
#[tokio::test]
async fn deny_set_idiom_end_to_end() {
    const DENY_SET_YAML: &str = r#"
global:
  apl:
    pdp:
      - kind: opa
        modules:
          - |
            package authz
            deny contains msg if {
                input.subject.id != "alice"
                msg := "subject not on the allowlist"
            }
routes:
  - tool: get_document
    apl:
      pre_invocation:
        - opa:
            query: data.authz.deny
"#;
    let mgr = build_manager_with_yaml(DENY_SET_YAML)
        .await
        .expect("load_config_yaml");

    // alice → empty deny set → allow.
    let (allow, _bg) = mgr
        .invoke_named::<CmfHook>(
            "cmf.tool_pre_invoke",
            payload(),
            Extensions {
                meta: Some(Arc::new(meta_for_tool("get_document"))),
                security: Some(Arc::new(security_with_roles("alice", &[]))),
                ..Default::default()
            },
            None,
        )
        .await;
    assert!(
        allow.continue_processing,
        "empty deny set must allow; got violation = {:?}",
        allow.violation
    );

    // eve → non-empty deny set → deny.
    let (deny, _bg) = mgr
        .invoke_named::<CmfHook>(
            "cmf.tool_pre_invoke",
            payload(),
            Extensions {
                meta: Some(Arc::new(meta_for_tool("get_document"))),
                security: Some(Arc::new(security_with_roles("eve", &[]))),
                ..Default::default()
            },
            None,
        )
        .await;
    assert!(
        !deny.continue_processing && deny.violation.is_some(),
        "non-empty deny set must halt with a violation",
    );
}

/// External `data` declared in the config is loaded into the engine's `data`
/// root and readable by policy — an operator can port a policy that splits
/// logic (modules) from lookup tables (data) with no rewrite.
#[tokio::test]
async fn external_data_is_readable_end_to_end() {
    const DATA_YAML: &str = r#"
global:
  apl:
    pdp:
      - kind: opa
        modules:
          - |
            package authz
            default allow := false
            allow if "reader" in data.roles[input.subject.id]
        data:
          roles:
            alice: [reader]
routes:
  - tool: get_document
    apl:
      pre_invocation:
        - opa:
            query: data.authz.allow
"#;
    let mgr = build_manager_with_yaml(DATA_YAML)
        .await
        .expect("load_config_yaml");

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>(
            "cmf.tool_pre_invoke",
            payload(),
            Extensions {
                meta: Some(Arc::new(meta_for_tool("get_document"))),
                security: Some(Arc::new(security_with_roles("alice", &[]))),
                ..Default::default()
            },
            None,
        )
        .await;
    assert!(
        result.continue_processing,
        "alice has the reader role in the data document and should be allowed; \
         got violation = {:?}",
        result.violation
    );
}
