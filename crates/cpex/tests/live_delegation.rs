// Location: ./crates/cpex/tests/live_delegation.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// Live delegation test for the OpenShell path-2 demo bundle, driven through
// the embed API against a REAL Keycloak (the Praxis `cpex-demo` realm). It
// proves the RFC 8693 token-exchange differentiator: a `delegate(...)` step on
// get_compensation trades the caller's inbound token for an audience-scoped
// downstream token, and that minted token lands in the returned extensions
// where a host adapter can attach it to the upstream request.
//
// Requires Keycloak up (with token-exchange wired for the workday-api
// audience) and Bob's token in the environment; skips cleanly when unset so
// ordinary `cargo test` is unaffected:
//
//   BOB_JWT=$(../praxis-demos/demos/cpex/mint-token.sh bob) \
//   cargo test -p cpex --features builtins --test live_delegation -- --nocapture

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

// The delegating slice of the OpenShell demo bundle (kept in sync with the
// fork's bundle.yaml get_compensation route). The workday-oauth delegator
// exchanges the caller's inbound token for a workday-api-audience token.
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

routes:
  - tool: get_compensation
    authentication: [keycloak]
    authorization:
      pre_invocation:
        - "require(role.hr)"
        - "delegate(workday-oauth, target: workday-api, audience: workday-api, permissions: [read_compensation])"
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

#[tokio::test]
async fn live_delegation_mints_audience_scoped_token() {
    let Ok(bob) = std::env::var("BOB_JWT") else {
        eprintln!("SKIP live_delegation_mints_audience_scoped_token: set BOB_JWT (mint against Keycloak)");
        return;
    };

    let cpex = CpexAuthorizer::from_bundle_yaml(BUNDLE, Arc::new(MemorySessionStore::new()))
        .await
        .expect("delegation bundle loads");

    // Bob (HR) calls get_compensation. The route requires role.hr (passes) and
    // then delegates: the workday-oauth plugin exchanges Bob's inbound token
    // for a workday-api-audience token via Keycloak's RFC 8693 endpoint.
    let ext = base_ext("get_compensation", "sandbox:bob-delegation");
    let ext = cpex
        .resolve_identity(&bob, ext)
        .await
        .unwrap_or_else(|denied| panic!("identity resolution failed unexpectedly: {denied:?}"));
    let outcome = cpex.invoke(HOOK_PRE, payload("get_compensation", json!({})), ext).await;

    let Outcome::Allow { extensions, .. } = outcome else {
        panic!("delegation route should allow for Bob (role.hr), got {outcome:?}");
    };

    // The minted downstream token lands in raw_credentials.delegated_tokens.
    let raw = extensions
        .raw_credentials
        .as_ref()
        .expect("delegation should populate raw_credentials");
    assert_eq!(
        raw.delegated_tokens.len(),
        1,
        "exactly one delegated token should be minted"
    );
    let minted = raw
        .delegated_tokens
        .values()
        .next()
        .expect("one minted token");
    assert_eq!(
        minted.audience, "workday-api",
        "the minted token must be scoped to the workday-api audience"
    );
    assert!(
        !minted.token.is_empty(),
        "the minted token must carry real credential bytes for upstream attachment"
    );
    assert!(
        minted.outbound_header.eq_ignore_ascii_case("authorization"),
        "the minted token targets the Authorization header for upstream attachment"
    );

    eprintln!(
        "live_delegation: minted workday-api token (outbound_header={}, scopes={:?}) via RFC 8693 exchange",
        minted.outbound_header, minted.scopes
    );
}
