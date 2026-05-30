// Location: ./crates/apl-identity-jwt/tests/jwks_url_e2e.rs
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

use apl_identity_jwt::JwtIdentityResolver;

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
    let header = Header::new(Algorithm::RS256);
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
                "decoding_key": { "kind": "jwks_url", "url": jwks_url },
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
