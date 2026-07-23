// Location: ./builtins/plugins/delegator-oauth/tests/oauth_e2e.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// End-to-end tests for `OAuthDelegator` against a `mockito`-backed
// fake IdP. Exercises the full handler path:
// `mgr.invoke_named::<TokenDelegateHook>(...)` → delegator builds
// RFC 8693 form body → POSTs to mock IdP → mock returns response
// → delegator translates into a `RawDelegatedToken` → host
// extracts via `from_pipeline_result`.
//
// Scenarios:
//   * happy path — minted token populated with audience + scopes + expiry
//   * IdP returns 400 with `invalid_grant` — surfaces `delegation.idp_rejected`
//   * IdP unreachable — surfaces `delegation.idp_unreachable`
//   * Request body shape — mockito's matcher verifies we send the
//     correct RFC 8693 fields
//   * actor_token — present on the wire when the payload carries one
//     (Mode B), fully absent when it doesn't
//   * subject role — a workload subject (Mode A) is attributed
//     `AsGateway`, not `OnBehalfOfUser`

use std::sync::Arc;

use cpex_core::delegation::{
    AttenuationConfig, AuthEnforcedBy, DelegationPayload, DelegationSubject, TargetType,
    TokenDelegateHook, HOOK_TOKEN_DELEGATE,
};
use cpex_core::extensions::raw_credentials::{DelegationMode, TokenRole};
use cpex_core::hooks::payload::Extensions;
use cpex_core::manager::PluginManager;
use cpex_core::plugin::{OnError, PluginConfig, PluginMode};

use cpex_plugin_delegator_oauth::OAuthDelegator;

use mockito::{Matcher, Server};
use serde_json::json;

// =====================================================================
// Fixtures
// =====================================================================

fn plugin_config(token_endpoint: &str) -> PluginConfig {
    PluginConfig {
        name: "oauth-delegator".into(),
        kind: "test".into(),
        hooks: vec![HOOK_TOKEN_DELEGATE.into()],
        mode: PluginMode::Sequential,
        priority: 10,
        on_error: OnError::Fail,
        config: Some(json!({
            "token_endpoint": token_endpoint,
            "client_id": "gateway-client",
            "client_secret_source": {
                "kind": "literal",
                "secret": "test-secret",
            },
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "timeout_seconds": 2,
            "default_outbound_header": "Authorization",
            // wiremock binds to http://127.0.0.1 — opt in to plaintext
            // for the test. Production deployments must omit this.
            "insecure_http": true,
        })),
        ..Default::default()
    }
}

fn build_payload(target: &str, audience: &str, scopes: &[&str]) -> DelegationPayload {
    DelegationPayload::new("caller-bearer-token-bytes", target)
        .with_target_type(TargetType::Tool)
        .with_target_audience(audience)
        .with_required_permissions(scopes.iter().map(|s| s.to_string()).collect())
        .with_auth_enforced_by(AuthEnforcedBy::Target)
        .with_route_attenuation(AttenuationConfig {
            capabilities: vec!["audit".into()],
            resource_template: None,
            actions: Vec::new(),
            ttl_seconds: Some(120),
        })
}

async fn build_manager(token_endpoint: &str) -> Arc<PluginManager> {
    let cfg = plugin_config(token_endpoint);
    let delegator = OAuthDelegator::new(cfg.clone()).expect("delegator constructs");
    let mgr = Arc::new(PluginManager::default());
    mgr.register_handler_for_names::<TokenDelegateHook, _>(
        Arc::new(delegator),
        cfg,
        &[HOOK_TOKEN_DELEGATE],
    )
    .unwrap();
    mgr.initialize().await.unwrap();
    mgr
}

async fn invoke(
    mgr: &Arc<PluginManager>,
    payload: DelegationPayload,
) -> cpex_core::executor::PipelineResult {
    let (result, _bg) = mgr
        .invoke_named::<TokenDelegateHook>(
            HOOK_TOKEN_DELEGATE,
            payload,
            Extensions::default(),
            None,
        )
        .await;
    result
}

// =====================================================================
// Scenarios
// =====================================================================

/// Happy path: mock IdP responds with a fresh access_token; the
/// delegator translates it into a `RawDelegatedToken` populated
/// with the requested audience, the effective scopes, and an
/// expiry derived from `expires_in`.
#[tokio::test]
async fn happy_path_mints_delegated_token() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/oauth/token")
        .match_header("content-type", "application/x-www-form-urlencoded")
        // Expect the form fields RFC 8693 requires.
        .match_body(Matcher::AllOf(vec![
            Matcher::UrlEncoded(
                "grant_type".into(),
                "urn:ietf:params:oauth:grant-type:token-exchange".into(),
            ),
            Matcher::UrlEncoded(
                "subject_token".into(),
                "caller-bearer-token-bytes".into(),
            ),
            Matcher::UrlEncoded(
                "audience".into(),
                "https://hr.example.com".into(),
            ),
        ]))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "access_token": "minted-downstream-jwt",
                "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "expires_in": 300,
                "scope": "read:compensation audit",
            })
            .to_string(),
        )
        .create_async()
        .await;

    let mgr = build_manager(&format!("{}/oauth/token", server.url())).await;
    let payload = build_payload(
        "get_compensation",
        "https://hr.example.com",
        &["read:compensation"],
    );

    let result = invoke(&mgr, payload).await;
    assert!(
        result.continue_processing,
        "happy path should mint a token: violation = {:?}",
        result.violation,
    );

    let final_payload = DelegationPayload::from_pipeline_result(&result)
        .expect("delegation payload should be present");
    let token = final_payload
        .delegated_token
        .as_ref()
        .expect("delegated_token populated");

    assert_eq!(&*token.token, "minted-downstream-jwt");
    assert_eq!(token.audience, "https://hr.example.com");
    assert_eq!(token.outbound_header, "Authorization");
    // Effective scopes come from the IdP's `scope` field.
    assert!(token.scopes.contains(&"read:compensation".to_string()));
    assert!(token.scopes.contains(&"audit".to_string()));

    // Mode is OnBehalfOfUser by default for RFC 8693 exchange.
    assert!(matches!(
        final_payload.delegation_mode,
        Some(DelegationMode::OnBehalfOfUser),
    ));

    // TTL respects the route hint (120s) — IdP's expires_in was 300,
    // but the route asked to cap at 120, so effective is 120.
    let ttl_left = (token.expires_at - chrono::Utc::now()).num_seconds();
    assert!(
        ttl_left <= 120 && ttl_left > 100,
        "ttl should reflect min(idp_ttl, route_hint); got {ttl_left}s",
    );

    mock.assert_async().await;
}

/// IdP returns a 400 with the standard `error` / `error_description`
/// shape — delegator surfaces `delegation.idp_rejected` carrying the
/// IdP's machine-readable code.
#[tokio::test]
async fn idp_rejection_surfaces_error_code() {
    let mut server = Server::new_async().await;
    server
        .mock("POST", "/oauth/token")
        .with_status(400)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "error": "invalid_grant",
                "error_description": "subject_token is not active",
            })
            .to_string(),
        )
        .create_async()
        .await;

    let mgr = build_manager(&format!("{}/oauth/token", server.url())).await;
    let payload = build_payload("tool", "https://downstream.example.com", &["read"]);

    let result = invoke(&mgr, payload).await;
    assert!(!result.continue_processing);
    let violation = result.violation.expect("rejection should surface");
    assert_eq!(violation.code, "delegation.idp_rejected");
    assert!(
        violation.reason.contains("invalid_grant"),
        "reason should include IdP's error code; got: {}",
        violation.reason,
    );
    assert!(
        violation.reason.contains("not active"),
        "reason should include the error_description; got: {}",
        violation.reason,
    );
}

/// IdP unreachable (mockito server stopped) — delegator surfaces
/// `delegation.idp_unreachable` rather than panicking.
#[tokio::test]
async fn idp_unreachable_surfaces_violation() {
    // Use a localhost URL that should be unreachable (no listener
    // on that port). The `127.0.0.1:1` port-1 trick: port 1 isn't
    // bound by typical systems and connection refusal is fast.
    let mgr = build_manager("http://127.0.0.1:1/oauth/token").await;
    let payload = build_payload("tool", "https://downstream.example.com", &["read"]);

    let result = invoke(&mgr, payload).await;
    assert!(!result.continue_processing);
    let violation = result.violation.expect("rejection should surface");
    // Either `idp_unreachable` (connection refused) or `idp_timeout`
    // (if the OS decides to slow-fail) — both are valid outcomes
    // for "IdP isn't there." The test accepts either.
    assert!(
        violation.code == "delegation.idp_unreachable"
            || violation.code == "delegation.idp_timeout",
        "expected idp_unreachable or idp_timeout; got {}",
        violation.code,
    );
}

/// Empty bearer token — fails fast at the handler entry before
/// touching the network. Verifies the input-validation path.
#[tokio::test]
async fn empty_bearer_token_rejects_without_network() {
    let mgr = build_manager("http://this-must-not-be-called/oauth/token").await;
    let payload =
        DelegationPayload::new("", "tool").with_target_audience("https://downstream.example.com");

    let result = invoke(&mgr, payload).await;
    assert!(!result.continue_processing);
    let violation = result.violation.expect("rejection should surface");
    assert_eq!(violation.code, "delegation.bad_request");
    assert!(violation.reason.contains("empty bearer_token"));
}

/// Missing target audience — fails fast (RFC 8693 requires
/// `audience` for downstream scoping).
#[tokio::test]
async fn missing_audience_rejects_without_network() {
    let mgr = build_manager("http://this-must-not-be-called/oauth/token").await;
    let payload = DelegationPayload::new("some-token", "tool"); // no audience

    let result = invoke(&mgr, payload).await;
    assert!(!result.continue_processing);
    let violation = result.violation.expect("rejection should surface");
    assert_eq!(violation.code, "delegation.bad_request");
    assert!(violation.reason.contains("target_audience"));
}

/// IdP grants narrower scopes than requested — delegator emits the
/// documented `delegation.scope_too_broad` code rather than silently
/// proceeding. Without this check, a route that requested
/// `read+write` and got back only `read` would mint a token the
/// downstream call can't actually use, leaving the policy author
/// with no observable signal about *why* the call failed downstream.
#[tokio::test]
async fn idp_narrower_scope_surfaces_scope_too_broad() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/oauth/token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "access_token": "narrower-token",
                "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "expires_in": 300,
                // Asked for both, got only `read`.
                "scope": "read",
            })
            .to_string(),
        )
        .create_async()
        .await;

    let mgr = build_manager(&format!("{}/oauth/token", server.url())).await;
    let payload = build_payload("tool", "https://downstream.example.com", &["read", "write"]);

    let result = invoke(&mgr, payload).await;
    assert!(
        !result.continue_processing,
        "narrower IdP grant must NOT silently succeed",
    );
    let violation = result.violation.expect("rejection should surface");
    assert_eq!(violation.code, "delegation.scope_too_broad");
    assert!(
        violation.reason.contains("write"),
        "reason should name the missing scope: {}",
        violation.reason,
    );

    mock.assert_async().await;
}

/// Sanity check: when the IdP grants exactly the requested set, the
/// scope check passes. Pins the "no false positive" half of the
/// scope_too_broad behaviour.
#[tokio::test]
async fn idp_exact_scope_match_succeeds() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/oauth/token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "access_token": "ok-token",
                "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "expires_in": 300,
                "scope": "read write",
            })
            .to_string(),
        )
        .create_async()
        .await;

    let mgr = build_manager(&format!("{}/oauth/token", server.url())).await;
    let payload = build_payload("tool", "https://downstream.example.com", &["read", "write"]);

    let result = invoke(&mgr, payload).await;
    assert!(
        result.continue_processing,
        "exact scope match should mint a token; violation = {:?}",
        result.violation,
    );
    mock.assert_async().await;
}

// =====================================================================
// RFC 8693 actor_token / subject-role attribution
// =====================================================================

/// Standard 200 response body, factored out so the actor tests can
/// focus on what they're actually asserting (the request side).
fn ok_token_response() -> String {
    json!({
        "access_token": "minted-downstream-jwt",
        "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "expires_in": 300,
        "scope": "read:compensation",
    })
    .to_string()
}

/// Mode B — user subject + workload actor. The delegator must put the
/// SVID on the wire as RFC 8693 §2.1 `actor_token`, tagged with the
/// configured `actor_token_type`, alongside the user's `subject_token`.
/// This is the "gateway acting on behalf of a user" shape, and the
/// minted token still speaks for the user.
#[tokio::test]
async fn actor_token_reaches_the_idp_when_the_payload_carries_one() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/oauth/token")
        .match_body(Matcher::AllOf(vec![
            // The user is still the subject...
            Matcher::UrlEncoded("subject_token".into(), "caller-bearer-token-bytes".into()),
            // ...and the workload SVID rides along as the actor.
            Matcher::UrlEncoded("actor_token".into(), "workload.svid.bytes".into()),
            Matcher::UrlEncoded(
                "actor_token_type".into(),
                "urn:ietf:params:oauth:token-type:jwt".into(),
            ),
        ]))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(ok_token_response())
        .create_async()
        .await;

    let mgr = build_manager(&format!("{}/oauth/token", server.url())).await;
    let payload = build_payload(
        "get_compensation",
        "https://hr.example.com",
        &["read:compensation"],
    )
    .with_actor(TokenRole::CallerWorkload, "workload.svid.bytes");

    let result = invoke(&mgr, payload).await;
    assert!(
        result.continue_processing,
        "actor-token exchange should mint a token; violation = {:?}",
        result.violation,
    );

    let final_payload = DelegationPayload::from_pipeline_result(&result)
        .expect("delegation payload should be present");
    // Subject is the user, so the token still speaks for the user
    // even though a workload actor was recorded.
    assert!(matches!(
        final_payload.delegation_mode,
        Some(DelegationMode::OnBehalfOfUser),
    ));

    // If the actor fields hadn't been sent, the matcher above would
    // have failed to match and this assertion would fire.
    mock.assert_async().await;
}

/// The negative half: a payload with no actor must produce a plain
/// single-token exchange. Asserted by rejecting any request whose body
/// mentions `actor_token` at all — a stray empty `actor_token=` field
/// would confuse strict IdPs, so "absent" has to mean absent.
#[tokio::test]
async fn absent_actor_leaves_no_actor_fields_on_the_wire() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/oauth/token")
        .match_request(|req| {
            let body = req.body().expect("request has a body");
            !String::from_utf8_lossy(body).contains("actor_token")
        })
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(ok_token_response())
        .create_async()
        .await;

    let mgr = build_manager(&format!("{}/oauth/token", server.url())).await;
    // No `.with_actor_token(...)` — the ordinary single-token case.
    let payload = build_payload(
        "get_compensation",
        "https://hr.example.com",
        &["read:compensation"],
    );

    let result = invoke(&mgr, payload).await;
    assert!(
        result.continue_processing,
        "single-token exchange should still succeed; violation = {:?}",
        result.violation,
    );
    mock.assert_async().await;
}

/// `subject: gateway` — the gateway holds the access to the
/// downstream (the "gateway owns the tool credentials" deployment)
/// and calls it as itself. There is no inbound credential to
/// exchange, so this must switch to an RFC 6749 §4.4
/// `client_credentials` grant rather than a token exchange: no
/// `subject_token`, and the gateway's identity proven by the Basic
/// auth header it already sends.
#[tokio::test]
async fn gateway_subject_uses_client_credentials_not_token_exchange() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/oauth/token")
        .match_body(Matcher::AllOf(vec![
            Matcher::UrlEncoded("grant_type".into(), "client_credentials".into()),
            Matcher::UrlEncoded("audience".into(), "https://hr.example.com".into()),
        ]))
        // A token exchange sends subject_token; this must not.
        .match_request(|req| {
            let body = req.body().expect("request has a body");
            !String::from_utf8_lossy(body).contains("subject_token")
        })
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(ok_token_response())
        .create_async()
        .await;

    let mgr = build_manager(&format!("{}/oauth/token", server.url())).await;
    // Note the empty bearer token: for a gateway subject that is the
    // expected state, not the "caller forgot the credential" error.
    let payload = DelegationPayload::new("", "get_compensation")
        .with_subject(DelegationSubject::Gateway)
        .with_target_audience("https://hr.example.com")
        .with_required_permissions(vec!["read:compensation".into()]);

    let result = invoke(&mgr, payload).await;
    assert!(
        result.continue_processing,
        "gateway-subject exchange should mint a token; violation = {:?}",
        result.violation,
    );

    let final_payload = DelegationPayload::from_pipeline_result(&result)
        .expect("delegation payload should be present");
    assert!(
        matches!(
            final_payload.delegation_mode,
            Some(DelegationMode::AsGateway),
        ),
        "gateway subject must be attributed to the gateway, got {:?}",
        final_payload.delegation_mode,
    );
    mock.assert_async().await;
}

/// An empty bearer token is still an error for every subject that
/// *does* have an inbound credential. Pins the boundary: the
/// gateway's exemption must not silently swallow a genuinely missing
/// workload or user token.
#[tokio::test]
async fn empty_bearer_still_rejected_for_non_gateway_subjects() {
    let mgr = build_manager("https://unused.example.com/oauth/token").await;
    let payload = DelegationPayload::new("", "get_compensation")
        .with_subject(DelegationSubject::CallerWorkload)
        .with_target_audience("https://hr.example.com");

    let result = invoke(&mgr, payload).await;
    assert!(
        !result.continue_processing,
        "a missing credential must still be an error for a workload subject",
    );
    assert_eq!(
        result.violation.expect("violation surfaced").code,
        "delegation.bad_request",
    );
}

/// `actor_token` is a token-exchange parameter with no meaning under
/// `client_credentials`, so a gateway-subject call must not send it
/// even when the payload carries one — an IdP receiving both would be
/// getting a malformed request.
#[tokio::test]
async fn gateway_subject_never_sends_actor_token() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/oauth/token")
        .match_request(|req| {
            let body = req.body().expect("request has a body");
            !String::from_utf8_lossy(body).contains("actor_token")
        })
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(ok_token_response())
        .create_async()
        .await;

    let mgr = build_manager(&format!("{}/oauth/token", server.url())).await;
    let payload = DelegationPayload::new("", "get_compensation")
        .with_subject(DelegationSubject::Gateway)
        .with_actor(TokenRole::CallerWorkload, "workload.svid.bytes")
        .with_target_audience("https://hr.example.com")
        .with_required_permissions(vec!["read:compensation".into()]);

    let result = invoke(&mgr, payload).await;
    assert!(
        result.continue_processing,
        "should still mint; violation = {:?}",
        result.violation,
    );
    mock.assert_async().await;
}

/// Mode A — the calling agent exchanges its own SVID, no user
/// anywhere in the request. The minted credential speaks for that
/// agent, so `delegation_mode` must be `AsCallerWorkload`:
/// `apply_to_extensions` keys the delegated-token cache off this, and
/// filing the token under a user identity that never participated
/// would be wrong.
///
/// Specifically *not* `AsGateway` — that mode belongs to the
/// gateway's own `this_workload` identity, which is a different
/// principal from whichever agent happens to be calling.
#[tokio::test]
async fn workload_subject_mints_as_caller_workload_not_on_behalf_of_user() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/oauth/token")
        .match_body(Matcher::UrlEncoded(
            "subject_token".into(),
            "caller-bearer-token-bytes".into(),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(ok_token_response())
        .create_async()
        .await;

    let mgr = build_manager(&format!("{}/oauth/token", server.url())).await;
    let payload = build_payload(
        "get_compensation",
        "https://hr.example.com",
        &["read:compensation"],
    )
    .with_subject(DelegationSubject::CallerWorkload);

    let result = invoke(&mgr, payload).await;
    assert!(
        result.continue_processing,
        "workload-subject exchange should mint a token; violation = {:?}",
        result.violation,
    );

    let final_payload = DelegationPayload::from_pipeline_result(&result)
        .expect("delegation payload should be present");
    assert!(
        matches!(
            final_payload.delegation_mode,
            Some(DelegationMode::AsCallerWorkload),
        ),
        "workload subject must be attributed to the calling agent, got {:?}",
        final_payload.delegation_mode,
    );
    mock.assert_async().await;
}
