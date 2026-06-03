// Location: ./crates/apl-delegator-oauth/tests/oauth_e2e.rs
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

use std::sync::Arc;

use cpex_core::delegation::{
    AttenuationConfig, AuthEnforcedBy, DelegationPayload, TargetType, TokenDelegateHook,
    HOOK_TOKEN_DELEGATE,
};
use cpex_core::extensions::raw_credentials::DelegationMode;
use cpex_core::hooks::payload::Extensions;
use cpex_core::manager::PluginManager;
use cpex_core::plugin::{OnError, PluginConfig, PluginMode};

use apl_delegator_oauth::OAuthDelegator;

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
    let payload = build_payload(
        "tool",
        "https://downstream.example.com",
        &["read"],
    );

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
    let payload = build_payload(
        "tool",
        "https://downstream.example.com",
        &["read"],
    );

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
    let payload = DelegationPayload::new("", "tool")
        .with_target_audience("https://downstream.example.com");

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
    let payload = build_payload(
        "tool",
        "https://downstream.example.com",
        &["read", "write"],
    );

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
    let payload = build_payload(
        "tool",
        "https://downstream.example.com",
        &["read", "write"],
    );

    let result = invoke(&mgr, payload).await;
    assert!(
        result.continue_processing,
        "exact scope match should mint a token; violation = {:?}",
        result.violation,
    );
    mock.assert_async().await;
}
