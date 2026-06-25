// Location: ./builtins/plugins/elicitation-ciba/tests/ciba_e2e.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Integration tests for the CIBA elicitation handler against a mock OP
// (mockito). Exercises the real request shapes and the lifecycle mapping
// for dispatch → check → validate without a live Keycloak.

use std::collections::HashSet;

use base64::Engine;
use serde_json::json;

use cpex_core::context::PluginContext;
use cpex_core::elicitation::{
    ElicitationOp, ElicitationOutcomeKind, ElicitationPayload, ElicitationStatusKind,
};
use cpex_core::hooks::payload::Extensions;
use cpex_core::hooks::trait_def::HookHandler;
use cpex_core::plugin::{OnError, PluginConfig, PluginMode};

use cpex_plugin_elicitation_ciba::CibaApprover;

// ---------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------

fn approver(server_url: &str) -> CibaApprover {
    let cfg = PluginConfig {
        name: "manager-approver".to_string(),
        kind: "elicitation/ciba".to_string(),
        description: None,
        author: None,
        version: None,
        hooks: vec!["elicit".to_string()],
        mode: PluginMode::Sequential,
        priority: 10,
        on_error: OnError::Fail,
        capabilities: HashSet::new(),
        tags: Vec::new(),
        conditions: Vec::new(),
        config: Some(json!({
            "backchannel_endpoint": format!("{server_url}/ciba/auth"),
            "token_endpoint": format!("{server_url}/token"),
            "client_id": "cpex-gateway",
            "client_secret_source": { "kind": "literal", "secret": "shh" },
            // mockito serves http:// — allow it for the test only.
            "insecure_http": true,
        })),
    };
    CibaApprover::new(cfg).expect("construct approver")
}

async fn run(approver: &CibaApprover, payload: ElicitationPayload) -> ElicitationPayload {
    let ext = Extensions::default();
    let mut ctx = PluginContext::new();
    let result = approver.handle(&payload, &ext, &mut ctx).await;
    assert!(
        result.continue_processing,
        "handler denied: {:?}",
        result.violation
    );
    result
        .modified_payload
        .expect("handler returned an ElicitationPayload")
}

/// Build a fake id_token whose payload carries `preferred_username`.
fn fake_id_token(username: &str) -> String {
    let payload = json!({ "preferred_username": username, "sub": "u-1" });
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&payload).unwrap());
    format!("aaa.{b64}.sig")
}

// ---------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------

#[tokio::test]
async fn dispatch_posts_backchannel_and_returns_auth_req_id() {
    let mut server = mockito::Server::new_async().await;
    let m = server
        .mock("POST", "/ciba/auth")
        // Assert the CIBA request shape: login_hint + binding_message.
        // The purpose "Approve raise" is sanitized to a Keycloak-valid,
        // space-free correlation code before it goes on the wire.
        .match_body(mockito::Matcher::AllOf(vec![
            mockito::Matcher::UrlEncoded("login_hint".into(), "alice@corp.com".into()),
            mockito::Matcher::UrlEncoded("binding_message".into(), "Approve-raise".into()),
            mockito::Matcher::UrlEncoded("scope".into(), "openid".into()),
        ]))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(json!({ "auth_req_id": "REQ-123", "expires_in": 300, "interval": 5 }).to_string())
        .create_async()
        .await;

    let app = approver(&server.url());
    let payload = ElicitationPayload::new(ElicitationOp::Dispatch, "approval", "alice@corp.com")
        .with_purpose("Approve raise");
    let out = run(&app, payload).await;

    m.assert_async().await;
    assert_eq!(out.id.as_deref(), Some("REQ-123"));
    assert_eq!(out.status, Some(ElicitationStatusKind::Pending));
    assert_eq!(out.approver.as_deref(), Some("alice@corp.com"));
    assert!(out.expires_at.is_some());
}

#[tokio::test]
async fn check_authorization_pending_maps_to_pending() {
    let mut server = mockito::Server::new_async().await;
    let m = server
        .mock("POST", "/token")
        .match_body(mockito::Matcher::UrlEncoded("auth_req_id".into(), "REQ-123".into()))
        .with_status(400)
        .with_header("content-type", "application/json")
        .with_body(json!({ "error": "authorization_pending" }).to_string())
        .create_async()
        .await;

    let app = approver(&server.url());
    let payload = ElicitationPayload::new(ElicitationOp::Check, "approval", "")
        .with_elicitation_id("REQ-123");
    let out = run(&app, payload).await;

    m.assert_async().await;
    assert_eq!(out.status, Some(ElicitationStatusKind::Pending));
    assert!(out.outcome.is_none());
}

#[tokio::test]
async fn check_success_maps_to_resolved_approved() {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("POST", "/token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({ "access_token": "at", "id_token": fake_id_token("alice@corp.com") })
                .to_string(),
        )
        .create_async()
        .await;

    let app = approver(&server.url());
    let payload = ElicitationPayload::new(ElicitationOp::Check, "approval", "")
        .with_elicitation_id("REQ-123");
    let out = run(&app, payload).await;

    assert_eq!(out.status, Some(ElicitationStatusKind::Resolved));
    assert_eq!(out.outcome, Some(ElicitationOutcomeKind::Approved));
}

#[tokio::test]
async fn check_access_denied_maps_to_resolved_denied() {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("POST", "/token")
        .with_status(400)
        .with_body(json!({ "error": "access_denied" }).to_string())
        .create_async()
        .await;

    let app = approver(&server.url());
    let payload = ElicitationPayload::new(ElicitationOp::Check, "approval", "")
        .with_elicitation_id("REQ-123");
    let out = run(&app, payload).await;

    assert_eq!(out.status, Some(ElicitationStatusKind::Resolved));
    assert_eq!(out.outcome, Some(ElicitationOutcomeKind::Denied));
}

#[tokio::test]
async fn check_expired_token_maps_to_expired() {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("POST", "/token")
        .with_status(400)
        .with_body(json!({ "error": "expired_token" }).to_string())
        .create_async()
        .await;

    let app = approver(&server.url());
    let payload = ElicitationPayload::new(ElicitationOp::Check, "approval", "")
        .with_elicitation_id("REQ-123");
    let out = run(&app, payload).await;

    assert_eq!(out.status, Some(ElicitationStatusKind::Expired));
}

#[tokio::test]
async fn full_flow_dispatch_check_validate_approves() {
    // One approver instance across all three ops, so the in-memory
    // correlation store carries the expected approver + cached token.
    let mut server = mockito::Server::new_async().await;
    let _auth = server
        .mock("POST", "/ciba/auth")
        .with_status(200)
        .with_body(json!({ "auth_req_id": "REQ-9", "expires_in": 300 }).to_string())
        .create_async()
        .await;
    let _tok = server
        .mock("POST", "/token")
        .with_status(200)
        .with_body(
            json!({ "id_token": fake_id_token("alice@corp.com") }).to_string(),
        )
        .create_async()
        .await;

    let app = approver(&server.url());

    // 1. dispatch — login_hint = the resolved approver.
    let d = run(
        &app,
        ElicitationPayload::new(ElicitationOp::Dispatch, "approval", "alice@corp.com")
            .with_purpose("Approve raise"),
    )
    .await;
    let id = d.id.clone().expect("dispatch id");

    // 2. check — approved.
    let c = run(
        &app,
        ElicitationPayload::new(ElicitationOp::Check, "approval", "")
            .with_elicitation_id(&id),
    )
    .await;
    assert_eq!(c.outcome, Some(ElicitationOutcomeKind::Approved));

    // 3. validate — token's preferred_username matches the login_hint.
    let v = run(
        &app,
        ElicitationPayload::new(ElicitationOp::Validate, "approval", "")
            .with_elicitation_id(&id),
    )
    .await;
    assert_eq!(v.valid, Some(true));
    assert_eq!(v.approver.as_deref(), Some("alice@corp.com"));
}

#[tokio::test]
async fn validate_rejects_approver_mismatch() {
    let mut server = mockito::Server::new_async().await;
    let _auth = server
        .mock("POST", "/ciba/auth")
        .with_status(200)
        .with_body(json!({ "auth_req_id": "REQ-x", "expires_in": 300 }).to_string())
        .create_async()
        .await;
    // The token comes back naming a DIFFERENT user than the login_hint.
    let _tok = server
        .mock("POST", "/token")
        .with_status(200)
        .with_body(json!({ "id_token": fake_id_token("mallory@corp.com") }).to_string())
        .create_async()
        .await;

    let app = approver(&server.url());
    let d = run(
        &app,
        ElicitationPayload::new(ElicitationOp::Dispatch, "approval", "alice@corp.com"),
    )
    .await;
    let id = d.id.unwrap();
    let _ = run(
        &app,
        ElicitationPayload::new(ElicitationOp::Check, "approval", "").with_elicitation_id(&id),
    )
    .await;
    let v = run(
        &app,
        ElicitationPayload::new(ElicitationOp::Validate, "approval", "").with_elicitation_id(&id),
    )
    .await;

    assert_eq!(v.valid, Some(false));
    assert!(v.reason.unwrap().contains("approver mismatch"));
}
