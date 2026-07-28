// Location: ./crates/cpex/tests/live_marquee.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// Live marquee test for the OpenShell path-2 demo bundle (F1 + F2), driven
// through the embed API against a REAL Keycloak (the Praxis `cpex-demo` realm).
// This proves the bundle + identity resolution + cross-call session taint
// actually ENFORCE with real JWTs — the CPEX side of the marquee — independent
// of the OpenShell proxy wiring.
//
// Requires Keycloak up and the persona tokens in the environment; skips
// cleanly when unset so ordinary `cargo test` is unaffected:
//
//   BOB_JWT=$(../praxis-demos/demos/cpex/mint-token.sh bob) \
//   ALICE_JWT=$(../praxis-demos/demos/cpex/mint-token.sh alice) \
//   cargo test -p cpex --features builtins --test live_marquee -- --nocapture

#![cfg(feature = "cpex-builtins")]

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::{json, Value};

use cpex::cpex_core::cmf::content::ToolCall;
use cpex::cpex_core::cmf::enums::Role;
use cpex::cpex_core::cmf::{ContentPart, Message, MessagePayload};
use cpex::cpex_core::extensions::{AgentExtension, Extensions, MetaExtension};
use cpex::cpex_core::hooks::payload::PluginPayload;
use cpex::embed::{CpexAuthorizer, Outcome};
use cpex::MemorySessionStore;

const HOOK_PRE: &str = "cmf.tool_pre_invoke";

// The exact OpenShell demo bundle (kept in sync with the fork's bundle.yaml).
const BUNDLE: &str = r#"
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
  - name: audit-log
    kind: audit/logger
    hooks: [cmf.tool_pre_invoke]
    capabilities: [read_subject, read_meta]
    config:
      destination: stderr

routes:
  - tool: get_compensation
    authentication: [keycloak]
    authorization:
      pre_invocation:
        - "require(role.hr)"
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

fn payload(tool: &str, args: Value) -> Box<dyn PluginPayload> {
    let arguments: HashMap<String, Value> = match args {
        Value::Object(m) => m.into_iter().collect(),
        _ => HashMap::new(),
    };
    Box::new(MessagePayload {
        message: Message::with_content(
            Role::User,
            vec![ContentPart::ToolCall {
                content: ToolCall {
                    tool_call_id: "live".into(),
                    name: tool.into(),
                    arguments,
                    namespace: None,
                },
            }],
        ),
    })
}

fn base_ext(tool: &str, session_id: &str) -> Extensions {
    Extensions {
        meta: Some(Arc::new(MetaExtension {
            entity_type: Some("tool".into()),
            entity_name: Some(tool.into()),
            ..Default::default()
        })),
        agent: Some(Arc::new(AgentExtension {
            session_id: Some(session_id.into()),
            ..Default::default()
        })),
        ..Default::default()
    }
}

// Resolve identity for `token`, then pre-invoke `tool` in `session`.
async fn call(cpex: &CpexAuthorizer, token: &str, tool: &str, session: &str) -> Outcome {
    let ext = base_ext(tool, session);
    let ext = cpex
        .resolve_identity(token, ext)
        .await
        .unwrap_or_else(|denied| {
            // Identity resolution itself denied — surface it as the outcome.
            panic!("identity resolution failed unexpectedly: {denied:?}");
        });
    cpex.invoke(HOOK_PRE, payload(tool, json!({})), ext).await
}

#[tokio::test]
async fn live_marquee_f1_f2() {
    let (Ok(bob), Ok(alice)) = (std::env::var("BOB_JWT"), std::env::var("ALICE_JWT")) else {
        eprintln!("SKIP live_marquee_f1_f2: set BOB_JWT and ALICE_JWT (mint against Keycloak)");
        return;
    };

    let cpex = CpexAuthorizer::from_bundle_yaml(BUNDLE, Arc::new(MemorySessionStore::new()))
        .await
        .expect("demo bundle loads");

    // F2: Bob (HR) is allowed on get_compensation; this also taints his session.
    let bob_session = "sandbox:bob-demo";
    let r = call(&cpex, &bob, "get_compensation", bob_session).await;
    assert!(
        r.is_allow(),
        "F2: Bob (role.hr) should be allowed on get_compensation, got {r:?}"
    );

    // F1: Bob's SAME session now attempts send_email — denied on the taint,
    // even though nothing about the email itself is disallowed.
    let r = call(&cpex, &bob, "send_email", bob_session).await;
    match r {
        Outcome::Deny { code, .. } => assert_eq!(
            code, "session_tainted",
            "F1: send_email must be denied by the session taint"
        ),
        other => panic!("F1: expected session_tainted deny, got {other:?}"),
    }

    // F2: Alice (engineer, no HR role) is denied on get_compensation.
    let r = call(&cpex, &alice, "get_compensation", "sandbox:alice-demo").await;
    assert!(
        matches!(r, Outcome::Deny { .. }),
        "F2: Alice (no role.hr) should be denied on get_compensation, got {r:?}"
    );

    eprintln!("live_marquee_f1_f2: F1 (taint exfil block) and F2 (identity gate) both enforced");
}
