// Location: ./crates/cpex-openshell-middleware/tests/service.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Xiaokui Shu
//
// Structural tests for the CPEX OpenShell middleware service. These act as an
// OpenShell supervisor: they build `HttpRequestEvaluation` protos and assert the
// `HttpRequestResult` decision. They use structural policy only (no IdP), so
// they run without Keycloak; the identity gate and cross-call taint block
// are exercised end-to-end against real Keycloak JWTs in the demo.

use std::collections::BTreeMap;
use std::sync::Arc;

use cpex::embed::CpexAuthorizer;
use cpex::MemorySessionStore;
use cpex_openshell_middleware::config::RestToolMap;
use cpex_openshell_middleware::proto::supervisor_middleware_server::SupervisorMiddleware;
use cpex_openshell_middleware::proto::{
    Decision, HttpHeader, HttpRequestEvaluation, HttpRequestTarget, RequestContext,
    SupervisorMiddlewareOperation, SupervisorMiddlewarePhase, ValidateConfigRequest,
};
use cpex_openshell_middleware::service::CpexMiddlewareService;

// A structural bundle: an open route, an authentication-gated route, and an
// args-conditional deny route. No identity plugin, so `require(authenticated)`
// denies whenever no subject is resolved (the anonymous case here).
const BUNDLE: &str = r#"
routes:
  - tool: open_tool
    authorization:
      pre_invocation: []

  - tool: gated_tool
    authorization:
      pre_invocation:
        - "require(authenticated)"

  - tool: send_email
    authorization:
      pre_invocation:
        - "args.external == \"true\": deny('external recipients blocked', 'email.external_blocked')"
"#;

async fn service(bundle: &str) -> CpexMiddlewareService {
    let authorizer = CpexAuthorizer::from_bundle_yaml(bundle, Arc::new(MemorySessionStore::new()))
        .await
        .expect("bundle should load");
    CpexMiddlewareService::new(Arc::new(authorizer))
}

/// Build an MCP `tools/call` evaluation for `tool` with the given args object.
fn mcp_eval(tool: &str, args: serde_json::Value) -> HttpRequestEvaluation {
    let body = serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": tool, "arguments": args },
    }))
    .unwrap();
    HttpRequestEvaluation {
        phase: SupervisorMiddlewarePhase::PreCredentials as i32,
        context: Some(RequestContext {
            request_id: "req-1".into(),
            sandbox_id: "sbx-test".into(),
            originating_process: None,
        }),
        config: None,
        target: Some(HttpRequestTarget {
            scheme: "http".into(),
            host: "hr-mcp".into(),
            port: 9100,
            method: "POST".into(),
            path: "/mcp".into(),
            query: String::new(),
        }),
        headers: Vec::new(),
        body,
        middleware_name: "cpex-authorizer".into(),
    }
}

fn header(name: &str, value: &str) -> HttpHeader {
    HttpHeader {
        name: name.into(),
        value: value.into(),
    }
}

#[tokio::test]
async fn open_route_allows() {
    let svc = service(BUNDLE).await;
    let result = svc.evaluate(mcp_eval("open_tool", serde_json::json!({}))).await;
    assert_eq!(result.decision, Decision::Allow as i32);
}

#[tokio::test]
async fn gated_route_denies_anonymous() {
    // No identity plugin and no X-CPEX-Identity header → no subject →
    // require(authenticated) denies.
    let svc = service(BUNDLE).await;
    let result = svc.evaluate(mcp_eval("gated_tool", serde_json::json!({}))).await;
    assert_eq!(result.decision, Decision::Deny as i32);
}

#[tokio::test]
async fn args_conditional_deny_and_allow() {
    let svc = service(BUNDLE).await;

    // Matching arg → deny.
    let denied = svc
        .evaluate(mcp_eval("send_email", serde_json::json!({ "external": "true" })))
        .await;
    assert_eq!(denied.decision, Decision::Deny as i32);
    assert_eq!(denied.reason_code, "email_external_blocked");

    // Non-matching arg → allow (exercises arg flow into the CMF payload).
    let allowed = svc
        .evaluate(mcp_eval("send_email", serde_json::json!({ "external": "false" })))
        .await;
    assert_eq!(allowed.decision, Decision::Allow as i32);
}

#[tokio::test]
async fn unmapped_operation_denies() {
    // A REST request (no JSON-RPC body) with no REST tool map maps to no tool →
    // fail closed (no unevaluated bytes forwarded).
    let svc = service(BUNDLE).await;
    let mut eval = mcp_eval("open_tool", serde_json::json!({}));
    eval.body = b"not json-rpc".to_vec();
    let result = svc.evaluate(eval).await;
    assert_eq!(result.decision, Decision::Deny as i32);
    assert_eq!(result.reason_code, "cpex_no_tool_mapping");
}

#[tokio::test]
async fn rest_map_projects_args() {
    // A REST GET whose tool map projects a query param into args, driving the
    // same args-conditional route the MCP leg uses. Proves REST/MCP parity.
    let svc = service(BUNDLE).await;
    let config = serde_json::json!({
        "routes": [{
            "host": "hr-mcp",
            "method": "GET",
            "path": "/send_email",
            "tool": "send_email",
            "query_args": ["external"]
        }]
    });
    let mut eval = HttpRequestEvaluation {
        phase: SupervisorMiddlewarePhase::PreCredentials as i32,
        context: Some(RequestContext {
            request_id: "req-2".into(),
            sandbox_id: "sbx-test".into(),
            originating_process: None,
        }),
        config: Some(json_to_struct(&config)),
        target: Some(HttpRequestTarget {
            scheme: "http".into(),
            host: "hr-mcp".into(),
            port: 9100,
            method: "GET".into(),
            path: "/send_email".into(),
            query: "external=true".into(),
        }),
        headers: Vec::new(),
        body: Vec::new(),
        middleware_name: "cpex-authorizer".into(),
    };
    let denied = svc.evaluate(eval.clone()).await;
    assert_eq!(denied.decision, Decision::Deny as i32, "external=true must deny");

    eval.target.as_mut().unwrap().query = "external=false".into();
    let allowed = svc.evaluate(eval).await;
    assert_eq!(allowed.decision, Decision::Allow as i32, "external=false must allow");
}

#[tokio::test]
async fn identity_read_only_from_dedicated_header() {
    // An Authorization header is never treated as identity: the gated route
    // still denies even with a (would-be) bearer present, because identity is
    // read only from X-CPEX-Identity (and OpenShell strips Authorization anyway).
    let svc = service(BUNDLE).await;
    let mut eval = mcp_eval("gated_tool", serde_json::json!({}));
    eval.headers = vec![header("authorization", "Bearer some.jwt.here")];
    let result = svc.evaluate(eval).await;
    assert_eq!(result.decision, Decision::Deny as i32);
}

#[tokio::test]
async fn describe_advertises_single_v1_binding() {
    let svc = service(BUNDLE).await;
    let manifest = svc
        .describe(tonic::Request::new(()))
        .await
        .expect("describe")
        .into_inner();
    assert_eq!(manifest.bindings.len(), 1);
    let b = &manifest.bindings[0];
    assert_eq!(b.operation, SupervisorMiddlewareOperation::HttpRequest as i32);
    assert_eq!(b.phase, SupervisorMiddlewarePhase::PreCredentials as i32);
    assert!(b.max_body_bytes > 0);
}

#[tokio::test]
async fn validate_config_accepts_good_map_rejects_duplicate() {
    let svc = service(BUNDLE).await;

    let good = serde_json::json!({
        "routes": [{ "host": "h", "method": "GET", "path": "/a", "tool": "open_tool" }]
    });
    let ok = svc
        .validate_config(tonic::Request::new(ValidateConfigRequest {
            config: Some(json_to_struct(&good)),
            middleware_name: "cpex-authorizer".into(),
        }))
        .await
        .expect("validate")
        .into_inner();
    assert!(ok.valid, "reason: {}", ok.reason);

    let dup = serde_json::json!({
        "routes": [
            { "host": "h", "method": "GET", "path": "/a", "tool": "open_tool" },
            { "host": "h", "method": "GET", "path": "/a", "tool": "gated_tool" }
        ]
    });
    let bad = svc
        .validate_config(tonic::Request::new(ValidateConfigRequest {
            config: Some(json_to_struct(&dup)),
            middleware_name: "cpex-authorizer".into(),
        }))
        .await
        .expect("validate")
        .into_inner();
    assert!(!bad.valid);
}

#[tokio::test]
async fn shipped_bundles_load() {
    // The demo bundles must parse and initialize (structural check; the JWKS
    // endpoint is not contacted at load time).
    for path in ["bundle/examples/bundle-cel.yaml", "bundle/examples/bundle-cedar.yaml"] {
        let yaml = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        CpexAuthorizer::from_bundle_yaml(&yaml, Arc::new(MemorySessionStore::new()))
            .await
            .unwrap_or_else(|e| panic!("bundle {path} should load: {e}"));
    }
}

#[test]
fn rest_tool_map_parses() {
    let cfg = serde_json::json!({
        "routes": [{ "host": "h", "method": "POST", "path": "/x", "tool": "t", "body_args": ["a"] }]
    });
    let map = RestToolMap::from_config_json(&cfg).expect("parse");
    map.validate().expect("valid");
    let (tool, args) = map
        .resolve("h", "POST", "/x", "", br#"{"a": 1, "b": 2}"#)
        .expect("resolve");
    assert_eq!(tool, "t");
    assert_eq!(args.get("a"), Some(&serde_json::json!(1)));
    assert_eq!(args.get("b"), None, "only declared body_args are projected");
}

/// Minimal serde_json::Value → prost_types::Struct for building test configs.
fn json_to_struct(value: &serde_json::Value) -> prost_types::Struct {
    let mut fields = BTreeMap::new();
    if let serde_json::Value::Object(map) = value {
        for (k, v) in map {
            fields.insert(k.clone(), json_to_prost_value(v));
        }
    }
    prost_types::Struct { fields }
}

fn json_to_prost_value(value: &serde_json::Value) -> prost_types::Value {
    use prost_types::value::Kind;
    let kind = match value {
        serde_json::Value::Null => Kind::NullValue(0),
        serde_json::Value::Bool(b) => Kind::BoolValue(*b),
        serde_json::Value::Number(n) => Kind::NumberValue(n.as_f64().unwrap_or(0.0)),
        serde_json::Value::String(s) => Kind::StringValue(s.clone()),
        serde_json::Value::Array(a) => Kind::ListValue(prost_types::ListValue {
            values: a.iter().map(json_to_prost_value).collect(),
        }),
        serde_json::Value::Object(_) => Kind::StructValue(json_to_struct(value)),
    };
    prost_types::Value { kind: Some(kind) }
}
