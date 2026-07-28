// Location: ./crates/cpex/tests/embed_authorizer.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// Tests for the host embedding API (`cpex::embed`). These act as a host:
// they build CMF tool payloads and drive the hook-agnostic `invoke` /
// `resolve_identity` surface. They use only structural policy (no IdP), so
// they run without Keycloak; the identity-, delegation-, taint-, and
// elicitation-dependent flows are exercised end-to-end in the OpenShell demo.

#![cfg(feature = "cpex-builtins")]

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::{json, Value};

use cpex::cpex_core::cmf::content::{ToolCall, ToolResult};
use cpex::cpex_core::cmf::enums::Role;
use cpex::cpex_core::cmf::{ContentPart, Message, MessagePayload};
use cpex::cpex_core::extensions::{Extensions, MetaExtension};
use cpex::cpex_core::hooks::payload::PluginPayload;
use cpex::embed::{CpexAuthorizer, Outcome};
use cpex::MemorySessionStore;

const HOOK_PRE: &str = "cmf.tool_pre_invoke";
const HOOK_POST: &str = "cmf.tool_post_invoke";

// A structural bundle (no identity plugin): an open route, an
// authentication-gated route, an args-conditional deny route, and a route
// with an unconditional redaction pipeline.
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
        - "args.external == true: deny('external recipients blocked', 'email.external_blocked')"

  - tool: read_doc
    authorization:
      pre_invocation: []
    result:
      secret: "str | redact(!authenticated)"

  - tool: plain_read
    authorization:
      pre_invocation: []
"#;

async fn authorizer(bundle: &str) -> CpexAuthorizer {
    CpexAuthorizer::from_bundle_yaml(bundle, Arc::new(MemorySessionStore::new()))
        .await
        .expect("bundle should load")
}

fn tool_ext(name: &str) -> Extensions {
    Extensions {
        meta: Some(Arc::new(MetaExtension {
            entity_type: Some("tool".into()),
            entity_name: Some(name.into()),
            ..Default::default()
        })),
        ..Default::default()
    }
}

fn pre_payload(tool: &str, args: Value) -> Box<dyn PluginPayload> {
    let arguments: HashMap<String, Value> = match args {
        Value::Object(m) => m.into_iter().collect(),
        _ => HashMap::new(),
    };
    Box::new(MessagePayload {
        message: Message::with_content(
            Role::User,
            vec![ContentPart::ToolCall {
                content: ToolCall {
                    tool_call_id: "t".into(),
                    name: tool.into(),
                    arguments,
                    namespace: None,
                },
            }],
        ),
    })
}

fn post_payload(tool: &str, result: Value) -> Box<dyn PluginPayload> {
    Box::new(MessagePayload {
        message: Message::with_content(
            Role::Tool,
            vec![ContentPart::ToolResult {
                content: ToolResult {
                    tool_call_id: "t".into(),
                    tool_name: tool.into(),
                    content: result,
                    is_error: false,
                },
            }],
        ),
    })
}

fn tool_result(payload: &dyn PluginPayload) -> Value {
    payload
        .as_any()
        .downcast_ref::<MessagePayload>()
        .and_then(|mp| mp.message.get_tool_results().into_iter().next())
        .map(|tr| tr.content.clone())
        .expect("payload should carry a tool result")
}

// The OpenShell demo bundle (F1 cross-call taint block + F2 identity gate),
// authored in the embed's APL format. Kept in sync with the demo's
// `bundle.yaml`; this test proves the format loads (construction does not need
// a live IdP — JWKS is fetched lazily at request time).
const OPENSHELL_DEMO_BUNDLE: &str = r#"
plugins:
  - name: keycloak
    kind: identity/jwt
    hooks: [identity.resolve]
    config:
      claim_mapper: standard
      trusted_issuers:
        - issuer: "http://localhost:8081/realms/cpex-demo"
          audiences: ["praxis-gateway", "account"]
          algorithms: ["RS256"]
          decoding_key:
            kind: jwks_url
            url: "http://localhost:8081/realms/cpex-demo/protocol/openid-connect/certs"
            insecure_http: true
          leeway_seconds: 60
  - name: workday-oauth
    kind: delegator/oauth
    hooks: [token.delegate]
    on_error: fail
    capabilities: [read_inbound_credentials, write_delegated_tokens]
    config:
      token_endpoint: "http://localhost:8081/realms/cpex-demo/protocol/openid-connect/token"
      insecure_http: true
      client_id: "praxis-gateway"
      client_secret_source:
        kind: literal
        secret: "praxis-gateway-secret"
      timeout_seconds: 5
      default_outbound_header: "Authorization"
  - name: audit-log
    kind: audit/logger
    hooks: [cmf.tool_pre_invoke]
    capabilities: [read_subject, read_meta, read_delegated_tokens]
    config:
      destination: stderr

routes:
  - tool: get_compensation
    authentication: [keycloak]
    authorization:
      pre_invocation:
        - "require(role.hr)"
        - "delegate(workday-oauth, target: workday-api, audience: workday-api, permissions: [read_compensation])"
        - "taint(secret, session)"
        - "run(audit-log)"

  - tool: send_email
    authentication: [keycloak]
    authorization:
      pre_invocation:
        - "require(authenticated)"
        - "security.labels contains \"secret\": deny('write-down blocked: this session read secret data', 'session_tainted')"
        - "run(audit-log)"
"#;

#[tokio::test]
async fn openshell_demo_bundle_loads() {
    // The demo bundle (identity/jwt + audit + taint/deny routes) must construct
    // cleanly with the bundled builtins wired.
    let cpex = CpexAuthorizer::from_bundle_yaml(
        OPENSHELL_DEMO_BUNDLE,
        Arc::new(MemorySessionStore::new()),
    )
    .await;
    assert!(cpex.is_ok(), "demo bundle should load: {:?}", cpex.err());
}

#[tokio::test]
async fn construction_rejects_malformed_bundle() {
    let err = CpexAuthorizer::from_bundle_yaml(
        "routes: [ this is not valid yaml",
        Arc::new(MemorySessionStore::new()),
    )
    .await;
    assert!(err.is_err(), "malformed bundle must fail construction");
}

#[tokio::test]
async fn open_route_allows() {
    let cpex = authorizer(BUNDLE).await;
    let outcome = cpex
        .invoke(HOOK_PRE, pre_payload("open_tool", json!({})), tool_ext("open_tool"))
        .await;
    assert!(outcome.is_allow(), "open route should allow");
}

#[tokio::test]
async fn authenticated_gate_denies_anonymous() {
    let cpex = authorizer(BUNDLE).await;
    let outcome = cpex
        .invoke(HOOK_PRE, pre_payload("gated_tool", json!({})), tool_ext("gated_tool"))
        .await;
    assert!(
        matches!(outcome, Outcome::Deny { .. }),
        "require(authenticated) must deny an anonymous caller"
    );
}

#[tokio::test]
async fn args_conditional_deny_and_allow() {
    let cpex = authorizer(BUNDLE).await;

    let denied = cpex
        .invoke(
            HOOK_PRE,
            pre_payload("send_email", json!({"external": true})),
            tool_ext("send_email"),
        )
        .await;
    match denied {
        Outcome::Deny { code, .. } => assert_eq!(code, "email.external_blocked"),
        _ => panic!("external recipient should be denied"),
    }

    let allowed = cpex
        .invoke(
            HOOK_PRE,
            pre_payload("send_email", json!({"external": false})),
            tool_ext("send_email"),
        )
        .await;
    assert!(allowed.is_allow(), "internal recipient should be allowed");
}

#[tokio::test]
async fn redaction_transforms_payload() {
    let cpex = authorizer(BUNDLE).await;
    let outcome = cpex
        .invoke(
            HOOK_POST,
            post_payload("read_doc", json!({"secret": "topsecret", "keep": "ok"})),
            tool_ext("read_doc"),
        )
        .await;
    match outcome {
        Outcome::Allow {
            payload: Some(p), ..
        } => {
            let result = tool_result(p.as_ref());
            assert_ne!(
                result.get("secret").and_then(Value::as_str),
                Some("topsecret"),
                "the secret field must be redacted"
            );
            assert_eq!(
                result.get("keep").and_then(Value::as_str),
                Some("ok"),
                "non-redacted fields pass through"
            );
        },
        _ => panic!("redaction-eligible post phase should allow with a transformed payload"),
    }
}

#[tokio::test]
async fn no_transform_passes_content_through_unchanged() {
    // A route with no `result:` pipeline allows and returns the pipeline's
    // resulting payload with content unchanged. The API surfaces the
    // pipeline's own payload and never fabricates a "transformed" result from
    // the input, which is what lets a host fail closed if a
    // redaction-eligible route ever yields no usable payload.
    let cpex = authorizer(BUNDLE).await;
    let outcome = cpex
        .invoke(
            HOOK_POST,
            post_payload("plain_read", json!({"anything": "here"})),
            tool_ext("plain_read"),
        )
        .await;
    match outcome {
        Outcome::Allow {
            payload: Some(p), ..
        } => {
            let result = tool_result(p.as_ref());
            assert_eq!(
                result.get("anything").and_then(Value::as_str),
                Some("here"),
                "content passes through unchanged when no result pipeline runs"
            );
        },
        _ => panic!("plain route should allow with a pass-through payload"),
    }
}
