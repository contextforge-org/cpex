// Location: ./builtins/plugins/identity-jwt/tests/jwks_url_e2e.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// End-to-end test for `DecodingKeySource::JwksUrl` + the async
// resolution path:
//
//   1. Construct a JwtIdentityResolver with `decoding_key.kind:
//      jwks_url` pointing at a mockito server. The resolver carries
//      the issuer config in `pending_jwks`; `trusted_issuers` is
//      empty (no inline keys).
//   2. Call `plugin.initialize().await` — this is the async hook the
//      host's `PluginManager::initialize()` drives. It triggers the
//      JWKS HTTP fetch.
//   3. Mint a JWT with the corresponding private key, hand it to the
//      resolver, assert the subject is populated. Proves the
//      fetched JWKS key was wired into the trusted-issuer list.
//
// Also covers: missing-initialize sad path (the resolver returns
// `untrusted_issuer` because the JwksUrl-deferred issuer never made
// it into `trusted_issuers`).

use std::sync::Arc;

use cpex_core::hooks::payload::Extensions;
use cpex_core::identity::{IdentityHook, IdentityPayload, TokenSource, HOOK_IDENTITY_RESOLVE};
use cpex_core::manager::PluginManager;
use cpex_core::plugin::{OnError, PluginConfig, PluginMode};

use cpex_plugin_identity_jwt::{DecodingKeySource, JwtIdentityResolver};

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use mockito::Server;
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Value};

const ISS: &str = "https://idp.test.local";
const AUD: &str = "test-api";

/// Build a JWKS JSON document from a single RSA public key. The
/// `kid` is fixed and the key declares `use=sig, alg=RS256` so the
/// resolver picks it via the "first signing-use key" rule.
fn build_jwks(public: &RsaPublicKey) -> Value {
    use base64::Engine;
    let n_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(public.n().to_bytes_be());
    let e_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(public.e().to_bytes_be());
    json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": "test-key-1",
            "n": n_b64,
            "e": e_b64,
        }]
    })
}

fn mint_jwt(private_pem: &str, claims: Value) -> String {
    // Set `kid` so the resolver's KeyStore lookup hits — the JWKS
    // entry exposed by the mock server uses the same kid value
    // ("test-key-1", see `jwks_body`).
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key-1".into());
    let key = EncodingKey::from_rsa_pem(private_pem.as_bytes())
        .expect("build EncodingKey from RSA PEM");
    encode(&header, &claims, &key).expect("sign JWT")
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn resolver_config(jwks_url: &str) -> PluginConfig {
    PluginConfig {
        name: "jwt-via-jwks".into(),
        kind: "test".into(),
        hooks: vec![HOOK_IDENTITY_RESOLVE.into()],
        mode: PluginMode::Sequential,
        priority: 10,
        on_error: OnError::Fail,
        config: Some(json!({
            "role": "user",
            "header": "Authorization",
            "trusted_issuers": [{
                "issuer": ISS,
                "audiences": [AUD],
                "algorithms": ["RS256"],
                // mockito serves over http://127.0.0.1 — opt in to
                // plaintext for this test. Production deployments
                // must omit `insecure_http`.
                "decoding_key": { "kind": "jwks_url", "url": jwks_url, "insecure_http": true },
                "leeway_seconds": 60,
            }],
            "claim_mapper": "standard",
        })),
        ..Default::default()
    }
}

/// Verify that a JWT signed by the JWKS-published key validates
/// after `initialize()` resolves the JWKS URL.
#[tokio::test(flavor = "multi_thread")]
async fn initialize_fetches_jwks_and_validates_token() {
    // 1. Generate a keypair and serve its public key as a JWKS.
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA");
    let pub_key = RsaPublicKey::from(&priv_key);
    let priv_pem = priv_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("encode private PEM")
        .to_string();
    let jwks_body = build_jwks(&pub_key).to_string();
    // Suppress unused-import warning on EncodeRsaPublicKey — only
    // exists to keep the trait in scope for callers that want
    // alternate PEM exports.
    let _ = pub_key.to_pkcs1_pem(LineEnding::LF);

    let mut server = Server::new_async().await;
    let mock = server
        .mock("GET", "/realms/test/protocol/openid-connect/certs")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(jwks_body)
        .expect(1)
        .create_async()
        .await;

    let jwks_url = format!("{}/realms/test/protocol/openid-connect/certs", server.url());

    // 2. Build the resolver. JwksUrl source → trusted_issuers is
    //    empty until initialize() runs.
    let cfg = resolver_config(&jwks_url);
    let resolver = Arc::new(JwtIdentityResolver::new(cfg.clone()).expect("constructs"));

    // 3. Wire into a PluginManager and call initialize. The
    //    manager's initialize() drives plugin.initialize(), which
    //    triggers the async JWKS fetch.
    let mgr = Arc::new(PluginManager::default());
    mgr.register_handler_for_names::<IdentityHook, _>(
        Arc::clone(&resolver),
        cfg,
        &[HOOK_IDENTITY_RESOLVE],
    )
    .unwrap();
    mgr.initialize().await.expect("initialize succeeds");

    // 4. Mint a JWT, dispatch, assert subject populated.
    let token = mint_jwt(
        &priv_pem,
        json!({
            "sub": "alice@corp.com",
            "iss": ISS,
            "aud": AUD,
            "exp": now_unix() + 300,
            "iat": now_unix(),
            "roles": ["hr"],
        }),
    );

    let mut headers = std::collections::HashMap::new();
    headers.insert("Authorization".to_string(), format!("Bearer {token}"));

    let payload = IdentityPayload::new(token.clone(), TokenSource::Bearer)
        .with_source_header("Authorization")
        .with_headers(headers);

    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(HOOK_IDENTITY_RESOLVE, payload, Extensions::default(), None)
        .await;
    assert!(
        result.continue_processing,
        "valid JWT (JWKS-resolved key) should pass: violation = {:?}",
        result.violation
    );
    let identity =
        IdentityPayload::from_pipeline_result(&result).expect("identity payload present");
    let subject = identity.subject.as_ref().expect("subject populated");
    assert_eq!(subject.id.as_deref(), Some("alice@corp.com"));
    assert!(subject.roles.contains("hr"));

    // 5. The mock recorded one (and only one) GET — proves we did
    //    a real network fetch.
    mock.assert_async().await;
}

/// Without `initialize()`, the issuer config sits in `pending_jwks`
/// and `trusted_issuers` is empty — a token signed by the JWKS key
/// gets `auth.untrusted_issuer` rather than silently passing. This
/// is the deliberate fail-loud mode: hosts must call
/// `PluginManager::initialize()`.
#[tokio::test(flavor = "multi_thread")]
async fn skipping_initialize_rejects_with_untrusted_issuer() {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA");
    let pub_key = RsaPublicKey::from(&priv_key);
    let priv_pem = priv_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("encode private PEM")
        .to_string();

    let mut server = Server::new_async().await;
    let _mock = server
        .mock("GET", "/realms/test/protocol/openid-connect/certs")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(build_jwks(&pub_key).to_string())
        // We expect ZERO calls — the test never calls initialize.
        .expect(0)
        .create_async()
        .await;

    let jwks_url = format!("{}/realms/test/protocol/openid-connect/certs", server.url());
    let cfg = resolver_config(&jwks_url);
    let resolver = Arc::new(JwtIdentityResolver::new(cfg.clone()).expect("constructs"));

    let mgr = Arc::new(PluginManager::default());
    mgr.register_handler_for_names::<IdentityHook, _>(
        Arc::clone(&resolver),
        cfg,
        &[HOOK_IDENTITY_RESOLVE],
    )
    .unwrap();
    // Deliberately SKIP mgr.initialize() — we want to prove the
    // pending JwksUrl issuer never made it into trusted_issuers.

    let token = mint_jwt(
        &priv_pem,
        json!({
            "sub": "alice",
            "iss": ISS,
            "aud": AUD,
            "exp": now_unix() + 300,
        }),
    );
    let mut headers = std::collections::HashMap::new();
    headers.insert("Authorization".to_string(), format!("Bearer {token}"));

    let payload = IdentityPayload::new(token, TokenSource::Bearer)
        .with_source_header("Authorization")
        .with_headers(headers);
    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(HOOK_IDENTITY_RESOLVE, payload, Extensions::default(), None)
        .await;
    assert!(
        !result.continue_processing,
        "no initialize() should yield deny (JWKS issuer never wired)",
    );
    let v = result.violation.expect("violation should be reported");
    assert_eq!(v.code, "auth.untrusted_issuer");
}

// =====================================================================
// P0-5 Slice A: kid-based key selection + JWKS fetch timeout
// =====================================================================

/// Build a JWKS containing two RSA keys with distinct `kid`s. Used by
/// the rotation / kid-selection tests below to prove the resolver
/// picks the key matching the inbound token's header, not the first
/// listed.
fn build_jwks_two_keys(
    pub_a: &RsaPublicKey,
    kid_a: &str,
    pub_b: &RsaPublicKey,
    kid_b: &str,
) -> Value {
    use base64::Engine;
    let make_entry = |k: &RsaPublicKey, kid: &str| {
        json!({
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": kid,
            "n": base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(k.n().to_bytes_be()),
            "e": base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(k.e().to_bytes_be()),
        })
    };
    json!({
        "keys": [
            make_entry(pub_a, kid_a),
            make_entry(pub_b, kid_b),
        ]
    })
}

/// Mint a JWT with a specific `kid` in the header. Distinct from
/// `mint_jwt` (which uses the default test kid) so the kid-selection
/// tests can control which key the resolver should select.
fn mint_jwt_with_kid(private_pem: &str, kid: &str, claims: Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.into());
    let key = EncodingKey::from_rsa_pem(private_pem.as_bytes())
        .expect("build EncodingKey from RSA PEM");
    encode(&header, &claims, &key).expect("sign JWT")
}

/// JWKS publishes two keys with distinct kids. A token signed by
/// key B with header `kid=key-b` must validate against key B, not
/// against the first-listed key A. Pre-Slice-A code would pick the
/// first key (A) and reject the valid token as signature_invalid.
#[tokio::test(flavor = "multi_thread")]
async fn kid_selects_correct_key_when_jwks_has_multiple() {
    let mut rng = rand::thread_rng();
    let priv_a = RsaPrivateKey::new(&mut rng, 2048).expect("rsa a");
    let priv_b = RsaPrivateKey::new(&mut rng, 2048).expect("rsa b");
    let pub_a = RsaPublicKey::from(&priv_a);
    let pub_b = RsaPublicKey::from(&priv_b);
    let priv_pem_b = priv_b
        .to_pkcs8_pem(LineEnding::LF)
        .expect("encode private PEM b")
        .to_string();

    let jwks_body = build_jwks_two_keys(&pub_a, "key-a", &pub_b, "key-b").to_string();

    let mut server = Server::new_async().await;
    let _mock = server
        .mock("GET", "/realms/test/protocol/openid-connect/certs")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(jwks_body)
        .create_async()
        .await;
    let jwks_url = format!("{}/realms/test/protocol/openid-connect/certs", server.url());

    let cfg = resolver_config(&jwks_url);
    let resolver = Arc::new(JwtIdentityResolver::new(cfg.clone()).expect("constructs"));
    let mgr = Arc::new(PluginManager::default());
    mgr.register_handler_for_names::<IdentityHook, _>(
        Arc::clone(&resolver),
        cfg,
        &[HOOK_IDENTITY_RESOLVE],
    )
    .unwrap();
    mgr.initialize().await.expect("initialize");

    // Token signed by B, with kid=key-b. The resolver must select
    // key B from the JWKS (not first-listed key A).
    let token = mint_jwt_with_kid(
        &priv_pem_b,
        "key-b",
        json!({
            "sub": "alice",
            "iss": ISS,
            "aud": AUD,
            "exp": now_unix() + 300,
            "iat": now_unix(),
        }),
    );
    let mut headers = std::collections::HashMap::new();
    headers.insert("Authorization".into(), format!("Bearer {token}"));
    let payload = IdentityPayload::new(token, TokenSource::Bearer)
        .with_source_header("Authorization")
        .with_headers(headers);
    let (result, _) = mgr
        .invoke_named::<IdentityHook>(HOOK_IDENTITY_RESOLVE, payload, Extensions::default(), None)
        .await;
    assert!(
        result.continue_processing,
        "kid-matched token must verify: violation = {:?}",
        result.violation,
    );
}

/// Token's `kid` header doesn't match any key the JWKS knows about.
/// Must yield `auth.unknown_kid` — distinct from
/// `auth.signature_invalid` so operators can tell rotation lag
/// from forgery at the audit layer.
#[tokio::test(flavor = "multi_thread")]
async fn unknown_kid_yields_unknown_kid_violation() {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa");
    let pub_key = RsaPublicKey::from(&priv_key);
    let priv_pem = priv_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("encode private PEM")
        .to_string();

    // JWKS publishes a single key with kid=test-key-1.
    let jwks_body = build_jwks(&pub_key).to_string();
    let mut server = Server::new_async().await;
    let _mock = server
        .mock("GET", "/realms/test/protocol/openid-connect/certs")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(jwks_body)
        .create_async()
        .await;
    let jwks_url = format!("{}/realms/test/protocol/openid-connect/certs", server.url());

    let cfg = resolver_config(&jwks_url);
    let resolver = Arc::new(JwtIdentityResolver::new(cfg.clone()).expect("constructs"));
    let mgr = Arc::new(PluginManager::default());
    mgr.register_handler_for_names::<IdentityHook, _>(
        Arc::clone(&resolver),
        cfg,
        &[HOOK_IDENTITY_RESOLVE],
    )
    .unwrap();
    mgr.initialize().await.expect("initialize");

    // Token signed by the right private key, but its header
    // declares `kid=stale-key` — which is what the IdP would do
    // post-rotation if we haven't refreshed yet.
    let token = mint_jwt_with_kid(
        &priv_pem,
        "stale-key",
        json!({
            "sub": "alice",
            "iss": ISS,
            "aud": AUD,
            "exp": now_unix() + 300,
            "iat": now_unix(),
        }),
    );
    let mut headers = std::collections::HashMap::new();
    headers.insert("Authorization".into(), format!("Bearer {token}"));
    let payload = IdentityPayload::new(token, TokenSource::Bearer)
        .with_source_header("Authorization")
        .with_headers(headers);
    let (result, _) = mgr
        .invoke_named::<IdentityHook>(HOOK_IDENTITY_RESOLVE, payload, Extensions::default(), None)
        .await;
    assert!(!result.continue_processing);
    let v = result.violation.expect("violation reported");
    assert_eq!(v.code, "auth.unknown_kid");
    assert!(
        v.reason.contains("stale-key"),
        "reason should name the missing kid: {}",
        v.reason,
    );
}

/// JWKS endpoint accepts the TCP connection but stalls indefinitely
/// on the HTTP response — the kind of slow-loris pattern a hostile
/// or simply broken IdP could exhibit. The fetch must time out
/// rather than hanging `initialize()` forever.
#[tokio::test(flavor = "multi_thread")]
async fn jwks_fetch_times_out_when_endpoint_stalls() {
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;

    // Stand up a tiny TCP listener that accepts connections, reads
    // the request headers, and then deliberately never sends a
    // response body. The JWKS fetch should give up after the
    // configured timeout (~5s) rather than waiting forever.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral");
    let addr = listener.local_addr().expect("listener addr");
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                // Drain a bit of request data, then send a partial
                // status line and stop. Reqwest will sit waiting
                // for body bytes that never arrive.
                let mut buf = [0u8; 512];
                let _ = tokio::io::AsyncReadExt::read(&mut sock, &mut buf).await;
                let _ = sock
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n")
                    .await;
                // Hold the connection open without writing the
                // 100-byte body. Sleep beyond the resolver's
                // overall timeout to confirm timeout-not-receive.
                tokio::time::sleep(Duration::from_secs(15)).await;
            });
        }
    });

    let url = format!("http://{addr}/jwks");
    let src = DecodingKeySource::JwksUrl {
        url: url.clone(),
        insecure_http: true,
        refresh_secs: 3600,
    };

    let started = std::time::Instant::now();
    let outcome = src.build_async().await;
    let elapsed = started.elapsed();

    // The wall-clock bound is the load-bearing assertion: a slow
    // / hostile JWKS must not hang `build_async` indefinitely. The
    // exact error string reqwest surfaces for a deadline elapsed
    // varies across platforms and reqwest versions — sometimes
    // "timeout", sometimes "body read failed: error decoding
    // response body" (when the body stream gets cut by the
    // deadline). We accept any Err outcome and rely on elapsed
    // time as the contract.
    match outcome {
        Err(_e) => {}
        Ok(_store) => panic!("stalled JWKS must not produce a KeyStore"),
    }
    // 5s overall timeout + 2s margin for setup / scheduler jitter.
    assert!(
        elapsed < Duration::from_secs(8),
        "fetch should have given up promptly; took {elapsed:?}",
    );
}

// =====================================================================
// P0-5 Slice B: soft-fail at boot + periodic JWKS refresh
// =====================================================================

/// JWKS endpoint is unreachable at gateway boot. The plugin must
/// `initialize()` cleanly (no Err — soft-fail) so the gateway
/// doesn't crash on a transient IdP outage. Subsequent verify
/// calls against tokens for that issuer must surface
/// `auth.jwks_unavailable` — a clear, distinct code so operators
/// see "JWKS issue at IdP X" rather than the alarming
/// `auth.signature_invalid` they'd see if we silently used an
/// empty key.
#[tokio::test(flavor = "multi_thread")]
async fn jwks_unreachable_at_initialize_soft_fails() {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa");
    let priv_pem = priv_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("encode private PEM")
        .to_string();

    // Point at 127.0.0.1:1 — port 1 isn't bound by typical systems,
    // so the TCP connect fails fast. The fetch timeout would also
    // catch a slow endpoint; here we just want "unreachable."
    let jwks_url = "http://127.0.0.1:1/jwks".to_string();
    let cfg = resolver_config(&jwks_url);
    let resolver = Arc::new(JwtIdentityResolver::new(cfg.clone()).expect("constructs"));
    let mgr = Arc::new(PluginManager::default());
    mgr.register_handler_for_names::<IdentityHook, _>(
        Arc::clone(&resolver),
        cfg,
        &[HOOK_IDENTITY_RESOLVE],
    )
    .unwrap();

    // The gateway boots — initialize returns Ok even though the
    // JWKS fetch failed. This is the soft-fail invariant.
    mgr.initialize().await.expect("initialize must NOT propagate JWKS failure");

    // A token signed by the right key fails verify with
    // `auth.jwks_unavailable` rather than crashing or returning
    // the wrong code. The resolver's KeyStore is empty until
    // refresh succeeds (which it won't, in this test).
    let token = mint_jwt_with_kid(
        &priv_pem,
        "test-key-1",
        json!({
            "sub": "alice",
            "iss": ISS,
            "aud": AUD,
            "exp": now_unix() + 300,
            "iat": now_unix(),
        }),
    );
    let mut headers = std::collections::HashMap::new();
    headers.insert("Authorization".into(), format!("Bearer {token}"));
    let payload = IdentityPayload::new(token, TokenSource::Bearer)
        .with_source_header("Authorization")
        .with_headers(headers);
    let (result, _) = mgr
        .invoke_named::<IdentityHook>(HOOK_IDENTITY_RESOLVE, payload, Extensions::default(), None)
        .await;
    assert!(!result.continue_processing);
    let v = result.violation.expect("violation reported");
    assert_eq!(v.code, "auth.jwks_unavailable");
    assert!(
        v.reason.contains(ISS),
        "reason should name the affected issuer: {}",
        v.reason,
    );
}

/// Initial JWKS publishes key A; the mock then rotates to key B.
/// A token signed by B with `kid=key-b` is initially rejected
/// (KeyStore only knows A). After the refresh interval ticks,
/// the resolver's KeyStore swaps in B and the same token
/// validates. Pins both:
///   - that refresh runs without restart
///   - that whole-store replacement actually swaps (not merges,
///     not silently drops the update)
#[tokio::test(flavor = "multi_thread")]
async fn jwks_refresh_picks_up_rotated_key() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    let mut rng = rand::thread_rng();
    let priv_a = RsaPrivateKey::new(&mut rng, 2048).expect("rsa a");
    let priv_b = RsaPrivateKey::new(&mut rng, 2048).expect("rsa b");
    let pub_a = RsaPublicKey::from(&priv_a);
    let pub_b = RsaPublicKey::from(&priv_b);
    let priv_pem_b = priv_b
        .to_pkcs8_pem(LineEnding::LF)
        .expect("encode private PEM b")
        .to_string();

    let jwks_a = build_jwks(&pub_a).to_string();
    let jwks_b = {
        use base64::Engine;
        json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": "key-b",
                "n": base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(pub_b.n().to_bytes_be()),
                "e": base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(pub_b.e().to_bytes_be()),
            }]
        })
        .to_string()
    };

    // Track how many times the JWKS endpoint has been hit so we
    // can flip the response body after the first fetch.
    let fetch_count = Arc::new(AtomicUsize::new(0));

    let mut server = Server::new_async().await;
    let count_for_mock = Arc::clone(&fetch_count);
    let jwks_b_clone = jwks_b.clone();
    let _mock = server
        .mock("GET", "/realms/test/protocol/openid-connect/certs")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body_from_request(move |_req| {
            let n = count_for_mock.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                jwks_a.clone().into_bytes()
            } else {
                jwks_b_clone.clone().into_bytes()
            }
        })
        .expect_at_least(2)
        .create_async()
        .await;
    let jwks_url = format!("{}/realms/test/protocol/openid-connect/certs", server.url());

    // Resolver config with a short refresh — 1 second keeps the
    // test wall-clock low. The default 600s wouldn't fire inside
    // the test window. Built inline rather than via
    // `resolver_config(...)` because we need the `refresh_secs`
    // field which the shared helper doesn't expose.
    let cfg = PluginConfig {
        name: "jwt-via-jwks".into(),
        kind: "test".into(),
        hooks: vec![HOOK_IDENTITY_RESOLVE.into()],
        mode: PluginMode::Sequential,
        priority: 10,
        on_error: OnError::Fail,
        config: Some(json!({
            "role": "user",
            "header": "Authorization",
            "trusted_issuers": [{
                "issuer": ISS,
                "audiences": [AUD],
                "algorithms": ["RS256"],
                "decoding_key": {
                    "kind": "jwks_url",
                    "url": jwks_url,
                    "insecure_http": true,
                    "refresh_secs": 1,
                },
                "leeway_seconds": 60,
            }],
            "claim_mapper": "standard",
        })),
        ..Default::default()
    };

    let resolver = Arc::new(JwtIdentityResolver::new(cfg.clone()).expect("constructs"));
    let mgr = Arc::new(PluginManager::default());
    mgr.register_handler_for_names::<IdentityHook, _>(
        Arc::clone(&resolver),
        cfg,
        &[HOOK_IDENTITY_RESOLVE],
    )
    .unwrap();
    mgr.initialize().await.expect("initialize");

    // Token signed by B, with kid=key-b. Pre-refresh, the
    // resolver only knows key A → `auth.unknown_kid`.
    let make_payload = || {
        let token = mint_jwt_with_kid(
            &priv_pem_b,
            "key-b",
            json!({
                "sub": "alice",
                "iss": ISS,
                "aud": AUD,
                "exp": now_unix() + 300,
                "iat": now_unix(),
            }),
        );
        let mut headers = std::collections::HashMap::new();
        headers.insert("Authorization".into(), format!("Bearer {token}"));
        IdentityPayload::new(token, TokenSource::Bearer)
            .with_source_header("Authorization")
            .with_headers(headers)
    };

    let (pre, _) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            make_payload(),
            Extensions::default(),
            None,
        )
        .await;
    assert!(!pre.continue_processing, "key-b token should not validate before refresh");
    assert_eq!(
        pre.violation.expect("violation").code,
        "auth.unknown_kid",
        "pre-refresh: kid mismatch should report unknown_kid",
    );

    // Wait long enough for the refresh task to fire at least once.
    // 1s refresh interval + a generous margin for scheduler jitter.
    // Poll the same verify in a loop until it succeeds or we time
    // out — avoids a flaky fixed sleep.
    let deadline = std::time::Instant::now() + Duration::from_secs(8);
    let mut succeeded = false;
    while std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let (r, _) = mgr
            .invoke_named::<IdentityHook>(
                HOOK_IDENTITY_RESOLVE,
                make_payload(),
                Extensions::default(),
                None,
            )
            .await;
        if r.continue_processing {
            succeeded = true;
            break;
        }
    }
    assert!(
        succeeded,
        "refresh task should have swapped in key-b within 8s of a 1s-interval refresh",
    );
}
