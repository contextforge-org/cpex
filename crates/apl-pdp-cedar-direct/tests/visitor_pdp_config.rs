// Location: ./crates/apl-pdp-cedar-direct/tests/visitor_pdp_config.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// End-to-end integration: a unified-config YAML that
//
//   1. declares a `cedar-direct` PDP under `global.apl.pdp[]`,
//   2. embeds Cedar policy text inline in that declaration,
//   3. attaches a `cedar:(...)` policy step to a route,
//
// must flow a real authorization decision from the cpex-core dispatcher
// through `AplConfigVisitor` → `PdpFactory` → `CedarDirectResolver` →
// Cedar's `Authorizer` → back into the route handler's deny/allow split.
//
// This proves the *wiring* end-to-end. The cedar-direct unit tests in
// `basic_allow_deny.rs` already cover the resolver in isolation; what's
// special here is that the resolver was never instantiated in Rust by
// the test — the visitor built it from YAML at `load_config_yaml` time
// because the host registered `CedarDirectPdpFactory` via
// `AplOptions.pdp_factories`. If this test passes, an operator who
// drops a `cedar-direct` block into their config gets the same behavior
// without writing any glue.

use std::collections::HashSet;
use std::sync::Arc;

use cpex_core::cmf::enums::Role;
use cpex_core::cmf::{CmfHook, Message, MessagePayload};
use cpex_core::extensions::{
    MetaExtension, SecurityExtension, SubjectExtension, SubjectType,
};
use cpex_core::hooks::payload::Extensions;
use cpex_core::manager::PluginManager;

use apl_cpex::{register_apl, AplOptions, DispatchCache, MemorySessionStore};
use apl_pdp_cedar_direct::CedarDirectPdpFactory;

// The configuration the visitor walks. Single Cedar permit policy that
// only fires for principals carrying the `reader` role; everything else
// hits Cedar's default-deny path.
const YAML: &str = r#"
global:
  apl:
    pdp:
      - kind: cedar-direct
        policy_text: |
          @id("reader-permit")
          permit(principal, action == Action::"read", resource)
          when { principal.roles.contains("reader") };
routes:
  - tool: get_document
    apl:
      policy:
        - cedar:
            action: 'Action::"read"'
            resource:
              type: Document
              id: doc-42
"#;

fn meta_for_tool(name: &str) -> MetaExtension {
    let mut m = MetaExtension::default();
    m.entity_type = Some("tool".to_string());
    m.entity_name = Some(name.to_string());
    m
}

/// Build a `SecurityExtension` with the given subject id and roles. The
/// bag-builder lifts these into `subject.id` / `role.<name>` keys, which
/// `entities.rs` reads when constructing the Cedar principal. Anything
/// the policy needs about the principal must come through this surface.
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
    let mgr = Arc::new(PluginManager::default());
    register_apl(
        &mgr,
        AplOptions {
            dispatch_cache: Arc::new(DispatchCache::new()),
            session_store: Arc::new(MemorySessionStore::new()),
            pdps: Vec::new(),
            // The factory is the load-bearing wiring under test: the
            // visitor sees `kind: cedar-direct` in YAML and finds this
            // factory by key.
            pdp_factories: vec![Arc::new(CedarDirectPdpFactory::new())],
            base_capabilities: None,
        },
    );
    mgr.load_config_yaml(YAML).expect("load_config_yaml");
    mgr.initialize().await.expect("initialize");
    mgr
}

fn payload() -> MessagePayload {
    MessagePayload {
        message: Message::text(Role::User, "fetch doc-42"),
    }
}

// =====================================================================
// Scenarios
// =====================================================================

/// Principal `alice` carries `role.reader=true`, which the permit policy
/// requires. End-to-end: visitor built the resolver from YAML, route
/// handler dispatched the `cedar:` step into that resolver, Cedar
/// returned Allow, the pipeline continues.
#[tokio::test]
async fn config_declared_cedar_pdp_allows_reader() {
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
        "reader-permit should allow alice; got violation = {:?}",
        result.violation
    );
}

/// Principal `bob` carries no roles, so the permit's guard
/// (`principal.roles.contains("reader")`) is false and no other policy
/// fires. Cedar default-denies; the route handler maps that to a
/// pipeline-halting violation with `code = cedar.default_deny`.
#[tokio::test]
async fn config_declared_cedar_pdp_denies_non_reader() {
    let mgr = build_manager().await;
    let ext = Extensions {
        meta: Some(Arc::new(meta_for_tool("get_document"))),
        security: Some(Arc::new(security_with_roles("bob", &[]))),
        ..Default::default()
    };

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload(), ext, None)
        .await;

    assert!(
        !result.continue_processing,
        "missing reader role should default-deny",
    );
    let v = result.violation.expect("deny path must surface a violation");
    assert_eq!(
        v.code, "cedar.default_deny",
        "default-deny path should use the cedar-direct sentinel code; got {}",
        v.code
    );
}
