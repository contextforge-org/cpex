// Location: ./crates/cpex-ffi/tests/egress.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// Outbound HTTP through the transport `cpex_apl_install` builds: the
// private-destination flag, the egress-denied codes builtins report when
// it is off, and Vault secret refresh over the same transport.

mod common;

use std::collections::HashMap;
use std::os::raw::{c_char, c_int};
use std::ptr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use jsonwebtoken::jwk::{Jwk, JwkSet, KeyAlgorithm, PublicKeyUse};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::json;

use cpex_ffi::{
    CPEX_APL_ALLOW_PRIVATE_DESTINATIONS, PAYLOAD_IDENTITY, RC_INVALID_HANDLE, RC_INVALID_INPUT,
    RC_OK, RC_PIPELINE_ERROR, cpex_free_bytes, cpex_refresh_secrets, cpex_secrets_last_success,
};
use praxis_policy_core::delegation::{DelegationPayload, HOOK_TOKEN_DELEGATE, TokenDelegateHook};
use praxis_policy_core::extensions::Extensions;
use praxis_policy_core::identity::{IdentityPayload, TokenSource};

use common::{Engine, MockServer, block_on, capture_warnings, warnings_containing};

const AUD: &str = "test-api";
const JWKS_PATH: &str = "/realms/test/certs";

// ---------------------------------------------------------------------
// identity-jwt with a jwks_url
// ---------------------------------------------------------------------

/// A fresh P-256 key, its JWKS document, and a signer.
struct Signer {
    key: EncodingKey,
    jwks: String,
}

impl Signer {
    fn new() -> Self {
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .expect("generate P-256 key");
        let key = EncodingKey::from_ec_der(pkcs8.as_ref());
        let mut jwk = Jwk::from_encoding_key(&key, Algorithm::ES256).expect("public JWK");
        jwk.common.key_id = Some("k1".into());
        jwk.common.public_key_use = Some(PublicKeyUse::Signature);
        jwk.common.key_algorithm = Some(KeyAlgorithm::ES256);
        let jwks = serde_json::to_string(&JwkSet { keys: vec![jwk] }).expect("JWKS");
        Self { key, jwks }
    }

    fn token(&self, issuer: &str) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("k1".into());
        let claims = json!({
            "iss": issuer,
            "aud": AUD,
            "sub": "alice@corp.com",
            "iat": now,
            "exp": now + 300,
        });
        encode(&header, &claims, &self.key).expect("sign JWT")
    }
}

fn jwt_config(issuer: &str, jwks_url: &str) -> String {
    format!(
        r#"
engine_settings:
  dispatch: hooks
plugins:
  - name: jwt
    kind: identity/jwt
    hooks: [identity.resolve]
    capabilities: [perform_http]
    config:
      role: user
      header: Authorization
      trusted_issuers:
        - issuer: "{issuer}"
          audiences: ["{AUD}"]
          algorithms: ["ES256"]
          decoding_key:
            kind: jwks_url
            url: "{jwks_url}"
            insecure_http: true
      claim_mapper: standard
"#
    )
}

fn identity_payload(token: &str) -> Vec<u8> {
    let headers = HashMap::from([("authorization".to_owned(), format!("Bearer {token}"))]);
    let payload = IdentityPayload::new(token, TokenSource::Bearer)
        .with_source_header("Authorization")
        .with_headers(headers);
    rmp_serde::to_vec_named(&payload).expect("encode identity payload")
}

#[test]
fn jwks_on_loopback_validates_when_private_destinations_are_allowed() {
    let signer = Signer::new();
    let server = MockServer::start();
    server.set(JWKS_PATH, 200, &signer.jwks);
    let issuer = "https://idp.allowed.test";

    let engine = Engine::installed(CPEX_APL_ALLOW_PRIVATE_DESTINATIONS);
    assert_eq!(
        engine.load(&jwt_config(issuer, &server.url(JWKS_PATH))),
        RC_OK
    );
    assert_eq!(engine.initialize(), RC_OK);
    assert!(server.hits(JWKS_PATH) >= 1, "initialize fetched the JWKS");

    let (rc, result) = engine.invoke(
        "identity.resolve",
        PAYLOAD_IDENTITY,
        &identity_payload(&signer.token(issuer)),
    );
    assert_eq!(rc, RC_OK);
    let result = result.expect("result");
    assert!(
        result.continue_processing,
        "token must validate: {:?}",
        result.violation
    );
    assert_eq!(result.payload_type, PAYLOAD_IDENTITY);
    let resolved: IdentityPayload =
        rmp_serde::from_slice(result.modified_payload.as_ref().expect("resolved identity"))
            .expect("decode identity");
    let subject = resolved.subject.expect("subject populated");
    assert_eq!(subject.id.as_deref(), Some("alice@corp.com"));
}

#[test]
fn jwks_on_loopback_soft_fails_when_private_destinations_are_blocked() {
    capture_warnings();
    let signer = Signer::new();
    let server = MockServer::start();
    server.set(JWKS_PATH, 200, &signer.jwks);
    let issuer = "https://idp.blocked.test";

    let engine = Engine::installed(0);
    assert_eq!(
        engine.load(&jwt_config(issuer, &server.url(JWKS_PATH))),
        RC_OK
    );
    assert_eq!(
        engine.initialize(),
        RC_OK,
        "a refused JWKS fetch soft-fails"
    );
    assert!(
        !warnings_containing(&["initial JWKS fetch failed", issuer]).is_empty(),
        "initialize must warn about the failed fetch"
    );

    let (rc, result) = engine.invoke(
        "identity.resolve",
        PAYLOAD_IDENTITY,
        &identity_payload(&signer.token(issuer)),
    );
    assert_eq!(rc, RC_OK);
    let result = result.expect("result");
    assert!(!result.continue_processing);
    assert_eq!(result.violation_code(), Some("auth.jwks_unavailable"));
    assert_eq!(
        server.hits(JWKS_PATH),
        0,
        "nothing reached the loopback server"
    );
}

/// The first install fixes the transport: a second call with the
/// private-destination flag does not open loopback egress.
#[test]
fn a_second_install_does_not_change_the_egress_policy() {
    let signer = Signer::new();
    let server = MockServer::start();
    server.set(JWKS_PATH, 200, &signer.jwks);
    let issuer = "https://idp.reinstall.test";

    let engine = Engine::installed(0);
    assert_eq!(
        unsafe { cpex_ffi::cpex_apl_install(engine.0, CPEX_APL_ALLOW_PRIVATE_DESTINATIONS) },
        RC_OK
    );
    assert_eq!(
        engine.load(&jwt_config(issuer, &server.url(JWKS_PATH))),
        RC_OK
    );
    assert_eq!(engine.initialize(), RC_OK);

    let (_, result) = engine.invoke(
        "identity.resolve",
        PAYLOAD_IDENTITY,
        &identity_payload(&signer.token(issuer)),
    );
    assert_eq!(
        result.expect("result").violation_code(),
        Some("auth.jwks_unavailable")
    );
    assert_eq!(server.hits(JWKS_PATH), 0);
}

// ---------------------------------------------------------------------
// delegator-oauth
// ---------------------------------------------------------------------

#[test]
fn oauth_token_exchange_to_a_private_endpoint_is_egress_denied() {
    let server = MockServer::start();
    server.set(
        "/oauth/token",
        200,
        r#"{"access_token":"minted","token_type":"Bearer","expires_in":300}"#,
    );
    let yaml = format!(
        r#"
engine_settings:
  dispatch: hooks
plugins:
  - name: oauth
    kind: delegator/oauth
    hooks: [token.delegate]
    capabilities: [perform_http, read_inbound_credentials, write_delegated_tokens]
    config:
      token_endpoint: "{}"
      insecure_http: true
      client_id: gateway
      client_secret_source: {{ kind: literal, secret: test-secret }}
      subject_token_type: "urn:ietf:params:oauth:token-type:access_token"
      timeout_seconds: 2
      default_outbound_header: Authorization
"#,
        server.url("/oauth/token")
    );

    let engine = Engine::installed(0);
    assert_eq!(engine.load(&yaml), RC_OK);
    assert_eq!(engine.initialize(), RC_OK);

    // The FFI has no delegation payload type, so drive the hook on the
    // FFI-built engine directly.
    let payload = DelegationPayload::new("caller-bearer-token", "workday-api")
        .with_target_audience("workday-api");
    let (result, _bg) = block_on(engine.inner().engine.invoke_named::<TokenDelegateHook>(
        HOOK_TOKEN_DELEGATE,
        payload,
        Extensions::default(),
        None,
    ));
    assert!(!result.continue_processing);
    let violation = result.violation.expect("a denial");
    assert_eq!(violation.code, "delegation.egress_denied", "{violation:?}");
    assert_eq!(server.hits("/oauth/token"), 0);
}

// ---------------------------------------------------------------------
// Vault secret refresh
// ---------------------------------------------------------------------

const VAULT_LOGIN: &str = "/v1/auth/approle/login";
const VAULT_KV: &str = "/v1/secret/data/app";

fn vault_server(password: &str) -> MockServer {
    let server = MockServer::start();
    server.set(
        VAULT_LOGIN,
        200,
        r#"{"auth":{"client_token":"hvs.test","lease_duration":3600,"renewable":true}}"#,
    );
    set_password(&server, password);
    server
}

fn set_password(server: &MockServer, password: &str) {
    server.set(
        VAULT_KV,
        200,
        &json!({ "data": { "data": { "password": password } } }).to_string(),
    );
}

fn vault_config(address: &str) -> String {
    format!(
        r#"
engine_settings:
  dispatch: hooks
secrets:
  providers:
    vault-dev:
      kind: vault
      address: "{address}"
      insecure_http: true
      allow_insecure_literal: true
      auth:
        method: approle
        role_id: role-id
        secret_id: {{ literal: secret-id }}
  values:
    db_password:
      provider: vault-dev
      ref: "secret/app#password"
"#
    )
}

#[derive(Debug, serde::Deserialize)]
struct Report {
    updated: Vec<String>,
    unchanged: u64,
    failed: Vec<Failure>,
}

#[derive(Debug, serde::Deserialize)]
struct Failure {
    secret: String,
    provider: String,
    kind: String,
    message: String,
}

fn refresh(engine: &Engine) -> Report {
    let mut out: *mut u8 = ptr::null_mut();
    let mut len: c_int = 0;
    unsafe {
        assert_eq!(cpex_refresh_secrets(engine.0, &mut out, &mut len), RC_OK);
        let report = rmp_serde::from_slice(std::slice::from_raw_parts(out, len as usize))
            .expect("decode refresh report");
        cpex_free_bytes(out, len);
        report
    }
}

fn last_success(engine: &Engine, provider: &str) -> i64 {
    let mut ms: i64 = -1;
    let rc = unsafe {
        cpex_secrets_last_success(
            engine.0,
            provider.as_ptr() as *const c_char,
            provider.len() as c_int,
            &mut ms,
        )
    };
    assert_eq!(rc, RC_OK);
    ms
}

#[test]
fn vault_refresh_picks_up_a_rotated_value() {
    let server = vault_server("first");
    let engine = Engine::installed(CPEX_APL_ALLOW_PRIVATE_DESTINATIONS);
    assert_eq!(engine.load(&vault_config(&server.origin())), RC_OK);
    assert_eq!(engine.initialize(), RC_OK);
    assert_eq!(server.hits(VAULT_KV), 1, "initialize read the value");
    let at_init = last_success(&engine, "vault-dev");
    assert!(at_init > 0, "initialization counts as a success");
    assert_eq!(last_success(&engine, "not-declared"), 0);

    let report = refresh(&engine);
    assert!(report.updated.is_empty(), "{report:?}");
    assert_eq!(report.unchanged, 1);
    assert!(report.failed.is_empty());

    set_password(&server, "rotated");
    // Let the clock move so the new stamp is strictly later.
    block_on(async { tokio::time::sleep(Duration::from_millis(5)).await });
    let report = refresh(&engine);
    assert_eq!(report.updated, vec!["db_password".to_owned()], "{report:?}");
    assert_eq!(report.unchanged, 0);
    assert!(report.failed.is_empty());
    let after_rotation = last_success(&engine, "vault-dev");
    assert!(after_rotation > at_init, "{after_rotation} > {at_init}");

    // A backend outage keeps the last-good value, names the failure, and
    // retains the last-success stamp for staleness checks.
    server.set(VAULT_KV, 503, r#"{"errors":["sealed"]}"#);
    let report = refresh(&engine);
    assert_eq!(report.failed.len(), 1, "{report:?}");
    let failure = &report.failed[0];
    assert_eq!(failure.secret, "db_password");
    assert_eq!(failure.provider, "vault-dev");
    assert_eq!(failure.kind, "backend", "{}", failure.message);
    assert!(
        !failure.message.contains("rotated"),
        "no secret in the message"
    );
    assert_eq!(last_success(&engine, "vault-dev"), after_rotation);

    // Recovery stamps it again.
    set_password(&server, "rotated");
    let report = refresh(&engine);
    assert!(report.failed.is_empty(), "{report:?}");
    assert!(last_success(&engine, "vault-dev") >= after_rotation);
}

#[test]
fn vault_on_loopback_is_refused_without_the_flag() {
    let server = vault_server("first");
    let engine = Engine::installed(0);
    assert_eq!(engine.load(&vault_config(&server.origin())), RC_OK);
    assert_eq!(
        engine.initialize(),
        RC_PIPELINE_ERROR,
        "the secret cannot resolve"
    );
    assert_eq!(server.hits(VAULT_LOGIN), 0);
}

#[test]
fn refresh_without_secrets_returns_an_empty_report() {
    let engine = Engine::installed(0);
    assert_eq!(engine.initialize(), RC_OK);
    let report = refresh(&engine);
    assert!(report.updated.is_empty() && report.failed.is_empty());
    assert_eq!(report.unchanged, 0);
    assert_eq!(last_success(&engine, "vault-dev"), 0);
}

#[test]
fn secret_entry_points_validate_their_arguments() {
    let mut out: *mut u8 = ptr::null_mut();
    let mut len: c_int = 0;
    let mut ms: i64 = 0;
    let name = "vault-dev";
    unsafe {
        assert_eq!(
            cpex_refresh_secrets(ptr::null(), &mut out, &mut len),
            RC_INVALID_HANDLE
        );
        assert!(out.is_null() && len == 0);
        assert_eq!(
            cpex_secrets_last_success(ptr::null(), name.as_ptr() as *const c_char, 9, &mut ms),
            RC_INVALID_HANDLE
        );
        let engine = Engine::installed(0);
        assert_eq!(
            cpex_refresh_secrets(engine.0, ptr::null_mut(), &mut len),
            RC_INVALID_INPUT
        );
        assert_eq!(
            cpex_secrets_last_success(engine.0, ptr::null(), 0, &mut ms),
            RC_INVALID_INPUT
        );
        assert_eq!(
            cpex_secrets_last_success(engine.0, name.as_ptr() as *const c_char, 9, ptr::null_mut()),
            RC_INVALID_INPUT
        );
    }
}
