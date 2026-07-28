// Location: ./crates/cpex/tests/live_elicitation.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// Live CIBA elicitation test for the OpenShell path-2 demo, driven through the
// embed API against the REAL Praxis stack (Keycloak with the CIBA channel SPI +
// the auth-channel approval service on :5001). It proves the human-in-the-loop
// differentiator end to end: a sensitive tool call SUSPENDS (Outcome::Pending)
// pending an out-of-band manager approval, and RESUMES to Allow once the
// approval lands, with the resume correlated by the elicitation id.
//
// Requires the full stack up (docker compose up keycloak auth-channel valkey)
// and Bob's token in the environment; skips cleanly when unset:
//
//   BOB_JWT=$(../praxis-demos/demos/cpex/mint-token.sh bob) \
//   cargo test -p cpex --features builtins --test live_elicitation -- --nocapture

#![cfg(feature = "cpex-builtins")]

use std::collections::HashMap;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use cpex::cpex_core::cmf::content::ToolCall;
use cpex::cpex_core::cmf::enums::Role;
use cpex::cpex_core::cmf::{ContentPart, Message, MessagePayload};
use cpex::cpex_core::extensions::{AgentExtension, Extensions, HttpExtension, MetaExtension};
use cpex::cpex_core::hooks::payload::PluginPayload;
use cpex::embed::{CpexAuthorizer, Outcome};
use cpex::MemorySessionStore;

const HOOK_PRE: &str = "cmf.tool_pre_invoke";
// Public resume contract: the agent echoes this header with the elicitation id
// from a prior pending response to continue (Check) rather than re-dispatch.
const ELICITATION_ID_HEADER: &str = "X-Policy-Elicitation-Id";
const AUTH_CHANNEL: &str = "http://localhost:5001";

// The elicitation slice of the OpenShell demo bundle (kept in sync with the
// fork's bundle.yaml adjust_compensation route). Over the $10k threshold, the
// route requires the caller's manager to approve out-of-band over OIDC CIBA.
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
  - name: manager-approver
    kind: elicitation/ciba
    hooks: [elicit]
    on_error: fail
    config:
      backchannel_endpoint: "http://localhost:8081/realms/cpex-demo/protocol/openid-connect/ext/ciba/auth"
      token_endpoint: "http://localhost:8081/realms/cpex-demo/protocol/openid-connect/token"
      insecure_http: true
      client_id: "praxis-gateway"
      client_secret_source:
        kind: literal
        secret: "praxis-gateway-secret"
      scope: openid
      approver_claim: preferred_username
      default_requested_expiry_seconds: 120

routes:
  - tool: adjust_compensation
    authentication: [keycloak]
    authorization:
      pre_invocation:
        - "require(role.hr)"
        - when: "args.amount > 10000"
          do:
            - "require_approval(manager-approver, from: claim.manager, channel: \"ciba\", scope: \"args.amount <= 25000\", purpose: \"Approve a compensation adjustment\", timeout: 24h)"
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

// Base extensions for the tool, optionally carrying a resume elicitation id in
// the HTTP request headers (what the agent would echo on retry).
fn base_ext(tool: &str, session_id: &str, resume_id: Option<&str>) -> Extensions {
    let http = resume_id.map(|id| {
        let mut h = HttpExtension::default();
        h.set_request_header(ELICITATION_ID_HEADER, id);
        Arc::new(h)
    });
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
        http,
        ..Default::default()
    }
}

// Query the auth-channel for a pending request for `approver` and approve it.
// Returns true when an approval was posted.
fn auto_approve(approver: &str) -> bool {
    for _ in 0..20 {
        let out = Command::new("curl")
            .args(["-fsS", &format!("{AUTH_CHANNEL}/pending?login_hint={approver}")])
            .output();
        if let Ok(out) = out {
            if let Ok(parsed) = serde_json::from_slice::<Value>(&out.stdout) {
                if let Some(id) = parsed
                    .as_array()
                    .and_then(|a| a.first())
                    .and_then(|e| e.get("auth_req_id"))
                    .and_then(Value::as_str)
                {
                    let _ = Command::new("curl")
                        .args(["-fsS", "-X", "POST", &format!("{AUTH_CHANNEL}/approve/{id}")])
                        .output();
                    return true;
                }
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    false
}

#[tokio::test]
async fn live_elicitation_suspends_then_resumes_on_approval() {
    let Ok(bob) = std::env::var("BOB_JWT") else {
        eprintln!("SKIP live_elicitation_suspends_then_resumes_on_approval: set BOB_JWT (mint against Keycloak)");
        return;
    };

    let cpex = CpexAuthorizer::from_bundle_yaml(BUNDLE, Arc::new(MemorySessionStore::new()))
        .await
        .expect("elicitation bundle loads");

    let session = "sandbox:bob-elicitation";
    let amount = json!({ "amount": 25000, "employee_id": "EMP-001234" });

    // 1. Dispatch: an over-threshold adjustment suspends pending approval.
    let ext = base_ext("adjust_compensation", session, None);
    let ext = cpex
        .resolve_identity(&bob, ext)
        .await
        .unwrap_or_else(|denied| panic!("identity resolution failed unexpectedly: {denied:?}"));
    let outcome = cpex
        .invoke(HOOK_PRE, payload("adjust_compensation", amount.clone()), ext)
        .await;
    let (eid, approver) = match outcome {
        Outcome::Pending { elicitation_id, approver } => (elicitation_id, approver),
        other => panic!("expected a pending elicitation on the over-threshold ask, got {other:?}"),
    };
    assert!(!eid.is_empty(), "pending must carry an elicitation id to resume");
    eprintln!("live_elicitation: suspended pending approval from {approver} (elicitation_id={eid})");

    // 2. The manager approves out-of-band (drive the auth-channel programmatically).
    assert!(
        auto_approve(&approver),
        "auth-channel should surface and approve the pending request for {approver}"
    );
    eprintln!("live_elicitation: approved as {approver} via the auth-channel");

    // 3. Resume: re-invoke echoing the elicitation id until it clears to Allow.
    //    Keycloak enforces a CIBA polling interval, so poll slower than that.
    let mut resumed = false;
    for attempt in 1..=20 {
        let ext = base_ext("adjust_compensation", session, Some(&eid));
        let ext = cpex
            .resolve_identity(&bob, ext)
            .await
            .unwrap_or_else(|denied| panic!("identity resolution failed on resume: {denied:?}"));
        let outcome = cpex
            .invoke(HOOK_PRE, payload("adjust_compensation", amount.clone()), ext)
            .await;
        match outcome {
            Outcome::Allow { .. } => {
                eprintln!("live_elicitation: resume attempt {attempt} cleared to Allow");
                resumed = true;
                break;
            },
            Outcome::Pending { .. } => {
                eprintln!("live_elicitation: resume attempt {attempt} still pending, waiting");
                tokio::time::sleep(Duration::from_secs(6)).await;
            },
            Outcome::Deny { code, reason } => {
                panic!("resume denied unexpectedly: {code}: {reason}");
            },
        }
    }
    assert!(resumed, "the approved elicitation should resume to Allow");
    eprintln!("live_elicitation: CIBA suspend -> approve -> resume proven end to end");
}
