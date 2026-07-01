// Location: ./crates/apl-cpex/tests/global_http_authz.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// End-to-end: a `global` APL policy is evaluated for a generic
// (non-MCP/A2A) HTTP request that carries no entity. The visitor installs
// a catch-all handler under (ENTITY_HTTP, ENTITY_NAME_GLOBAL,
// HOOK_CMF_HTTP_REQUEST); the host fires that hook with `meta` set to the
// reserved coordinates and an `http` extension carrying the request line.
// This is the entity-less authorization path the Praxis AuthPolicy
// transpiler targets (spike Phase B / U3). It also exercises U1
// (http.method in the bag) and U2 (custom denyWith via the route
// `response:` block surfaced on the violation details).

use std::sync::Arc;

use cpex_core::cmf::constants::{ENTITY_HTTP, ENTITY_NAME_GLOBAL, HOOK_CMF_HTTP_REQUEST};
use cpex_core::cmf::enums::Role;
use cpex_core::cmf::{CmfHook, Message, MessagePayload};
use cpex_core::extensions::{Extensions, HttpExtension, MetaExtension};
use cpex_core::manager::PluginManager;

use apl_cpex::{register_apl, AplOptions};

async fn manager_with(yaml: &str) -> Arc<PluginManager> {
    let mgr = Arc::new(PluginManager::default());
    register_apl(&mgr, AplOptions::in_process());
    mgr.load_config_yaml(yaml).expect("load_config_yaml");
    mgr.initialize().await.expect("initialize");
    mgr
}

/// A generic-HTTP request: reserved entity coordinates + an `http`
/// extension carrying the request method.
fn http_request(method: &str) -> Extensions {
    let mut meta = MetaExtension::default();
    meta.entity_type = Some(ENTITY_HTTP.to_string());
    meta.entity_name = Some(ENTITY_NAME_GLOBAL.to_string());
    let http = HttpExtension {
        method: Some(method.to_string()),
        ..Default::default()
    };
    Extensions {
        meta: Some(Arc::new(meta)),
        http: Some(Arc::new(http)),
        ..Default::default()
    }
}

fn payload() -> MessagePayload {
    MessagePayload {
        message: Message::text(Role::User, "hi"),
    }
}

// APL predicate:action form: deny when the method is not GET. (Comparisons
// use this form; `require(...)` is truthiness-only.)
const GET_ONLY: &str = r#"
plugin_settings:
  routing_enabled: true
global:
  apl:
    policy:
      - "http.method != 'GET': deny"
"#;

#[tokio::test]
async fn global_policy_allows_matching_http_request() {
    let mgr = manager_with(GET_ONLY).await;
    let (res, _bg) = mgr
        .invoke_named::<CmfHook>(HOOK_CMF_HTTP_REQUEST, payload(), http_request("GET"), None)
        .await;
    assert!(
        res.continue_processing,
        "GET must be allowed by the global policy; violation = {:?}",
        res.violation
    );
}

#[tokio::test]
async fn global_policy_denies_nonmatching_http_request() {
    let mgr = manager_with(GET_ONLY).await;
    let (res, _bg) = mgr
        .invoke_named::<CmfHook>(HOOK_CMF_HTTP_REQUEST, payload(), http_request("POST"), None)
        .await;
    assert!(
        !res.continue_processing,
        "POST must be denied by the global policy"
    );
}

/// A route-level `response:` block (transpiled `denyWith`) surfaces custom
/// status/body/headers on the violation `details` map (U2) when the global
/// policy denies.
#[tokio::test]
async fn global_policy_deny_carries_custom_response() {
    const YAML: &str = r#"
plugin_settings:
  routing_enabled: true
global:
  apl:
    policy:
      - "http.method != 'GET': deny"
  response:
    status: 403
    body: "{\"error\":\"forbidden\"}"
    headers:
      X-Reason: "method-not-allowed"
"#;
    let mgr = manager_with(YAML).await;
    let (res, _bg) = mgr
        .invoke_named::<CmfHook>(
            HOOK_CMF_HTTP_REQUEST,
            payload(),
            http_request("DELETE"),
            None,
        )
        .await;
    assert!(!res.continue_processing, "DELETE must be denied");
    let v = res.violation.expect("deny must surface a violation");
    assert_eq!(v.details.get("http.status"), Some(&serde_json::json!(403)));
    assert_eq!(
        v.details.get("http.body"),
        Some(&serde_json::json!("{\"error\":\"forbidden\"}"))
    );
    assert_eq!(
        v.details.get("http.headers"),
        Some(&serde_json::json!({ "X-Reason": "method-not-allowed" }))
    );
}
