// Location: ./builtins/plugins/identity-jwt/tests/jwt_e2e.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// End-to-end tests for `JwtIdentityResolver` against a real RSA
// keypair + signed JWTs. Exercises the full handler path:
// `mgr.invoke_named::<IdentityHook>(...)` → resolver decodes /
// validates / maps claims → host extracts the populated
// `IdentityPayload` via `from_pipeline_result`.
//
// Scenarios:
//   * happy path: valid signed token resolves to a populated subject
//   * untrusted issuer (token signed correctly but `iss` not in config)
//   * expired token (`exp` in the past)
//   * audience mismatch
//   * signature tamper
//
// Keypair is generated once per test process (RSA 2048 takes
// ~50-100ms; one-time cost) and shared across tests via OnceLock.

use std::sync::Arc;
use std::sync::OnceLock;

use cpex_core::extensions::raw_credentials::{TokenKind, TokenRole};
use cpex_core::hooks::payload::Extensions;
use cpex_core::identity::{IdentityHook, IdentityPayload, TokenSource, HOOK_IDENTITY_RESOLVE};
use cpex_core::manager::PluginManager;
use cpex_core::plugin::{OnError, PluginConfig, PluginMode};

use apl_identity_jwt::JwtIdentityResolver;

use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};

use serde_json::{json, Value};

const TEST_ISSUER: &str = "https://idp.test.local";
const TEST_AUDIENCE: &str = "test-api";

// =====================================================================
// Test fixtures
// =====================================================================

struct Keypair {
    private_pem: String,
    public_pem: String,
}

/// Process-global keypair. Generated once on first access; RSA 2048
/// is ~50-100ms which we don't want to pay per-test.
fn keypair() -> &'static Keypair {
    static KP: OnceLock<Keypair> = OnceLock::new();
    KP.get_or_init(|| {
        let mut rng = rand::thread_rng();
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA");
        let pub_key = RsaPublicKey::from(&priv_key);
        Keypair {
            private_pem: priv_key
                .to_pkcs8_pem(LineEnding::LF)
                .expect("encode private PEM")
                .to_string(),
            public_pem: pub_key
                .to_public_key_pem(LineEnding::LF)
                .expect("encode public PEM"),
        }
    })
}

/// Sign `claims` as an RS256 JWT using the test private key. JWT
/// payload is whatever JSON the caller hands in.
fn mint_jwt(claims: Value) -> String {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    let header = Header::new(Algorithm::RS256);
    let key = EncodingKey::from_rsa_pem(keypair().private_pem.as_bytes())
        .expect("build EncodingKey from test private PEM");
    encode(&header, &claims, &key).expect("sign JWT")
}

/// Construct a `PluginConfig` whose `config:` block declares the
/// test public key as the trusted-issuer signing material. Mirrors
/// what an operator writes in unified-config YAML.
fn resolver_plugin_config() -> PluginConfig {
    let plugin_config = json!({
        "trusted_issuers": [{
            "issuer": TEST_ISSUER,
            "audiences": [TEST_AUDIENCE],
            "algorithms": ["RS256"],
            "decoding_key": {
                "kind": "pem",
                "pem": keypair().public_pem,
            },
            "leeway_seconds": 60,
        }],
        "claim_mapper": "standard",
    });
    PluginConfig {
        name: "jwt-resolver".into(),
        kind: "test".into(),
        hooks: vec![HOOK_IDENTITY_RESOLVE.into()],
        mode: PluginMode::Sequential,
        priority: 10,
        on_error: OnError::Fail,
        config: Some(plugin_config),
        ..Default::default()
    }
}

/// Build the PluginManager + register the resolver + initialize.
/// All four scenarios share this skeleton.
async fn build_manager() -> Arc<PluginManager> {
    let cfg = resolver_plugin_config();
    let resolver = JwtIdentityResolver::new(cfg.clone()).expect("resolver should construct");

    let mgr = Arc::new(PluginManager::default());
    mgr.register_handler_for_names::<IdentityHook, _>(
        Arc::new(resolver),
        cfg,
        &[HOOK_IDENTITY_RESOLVE],
    )
    .unwrap();
    mgr.initialize().await.unwrap();
    mgr
}

/// Run a token through the full handler pipeline.
async fn invoke(token: String) -> cpex_core::executor::PipelineResult {
    let mgr = build_manager().await;
    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            IdentityPayload::new(token, TokenSource::Bearer),
            Extensions::default(),
            None,
        )
        .await;
    result
}

fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

// =====================================================================
// Scenarios
// =====================================================================

/// Happy path: valid signed token resolves to a populated subject,
/// raw token lands in `raw_credentials.inbound_tokens[User]`.
#[tokio::test]
async fn valid_jwt_resolves_subject() {
    let token = mint_jwt(json!({
        "sub": "alice@corp.com",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "iat": now_unix(),
        "roles": ["hr", "reader"],
        "email": "alice@corp.com",
    }));

    let result = invoke(token.clone()).await;
    assert!(
        result.continue_processing,
        "valid token should resolve: violation = {:?}",
        result.violation,
    );

    let identity = IdentityPayload::from_pipeline_result(&result)
        .expect("payload should be present");
    let subject = identity.subject.as_ref().expect("subject populated");
    assert_eq!(subject.id.as_deref(), Some("alice@corp.com"));
    assert!(subject.roles.contains("hr"));
    assert!(subject.roles.contains("reader"));
    // `email` was not a reserved claim, lands under subject.claims
    assert_eq!(
        subject.claims.get("email"),
        Some(&"alice@corp.com".to_string()),
    );

    // Raw token stashed for forwarding plugins.
    let raw = identity
        .raw_credentials
        .as_ref()
        .expect("raw_credentials populated");
    let user_token = raw
        .inbound_tokens
        .get(&TokenRole::User)
        .expect("user-role token present");
    assert_eq!(&*user_token.token, &token);
    assert!(matches!(user_token.kind, TokenKind::Jwt));
}

/// Token correctly signed by the test key but its `iss` doesn't
/// match any trusted issuer in our config → `auth.untrusted_issuer`.
/// This is the path where the peek-at-iss step does its job.
#[tokio::test]
async fn untrusted_issuer_rejects() {
    let token = mint_jwt(json!({
        "sub": "alice",
        "iss": "https://hacker.example.com",  // not in trusted_issuers list
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
    }));

    let result = invoke(token).await;
    assert!(!result.continue_processing);
    let v = result.violation.expect("rejection should surface");
    assert_eq!(v.code, "auth.untrusted_issuer");
}

/// `exp` claim is one hour in the past → `auth.token_expired`.
/// Leeway is 60s so a 1h-stale token is unambiguously rejected.
#[tokio::test]
async fn expired_token_rejects() {
    let token = mint_jwt(json!({
        "sub": "alice",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() - 3600,
    }));

    let result = invoke(token).await;
    assert!(!result.continue_processing);
    let v = result.violation.expect("rejection should surface");
    assert_eq!(v.code, "auth.token_expired");
}

/// `aud` doesn't match the configured audience → `auth.audience_mismatch`.
#[tokio::test]
async fn wrong_audience_rejects() {
    let token = mint_jwt(json!({
        "sub": "alice",
        "iss": TEST_ISSUER,
        "aud": "some-other-api",  // not the configured TEST_AUDIENCE
        "exp": now_unix() + 300,
    }));

    let result = invoke(token).await;
    assert!(!result.continue_processing);
    let v = result.violation.expect("rejection should surface");
    assert_eq!(v.code, "auth.audience_mismatch");
}

/// Tamper with the signature bytes → signature verification fails →
/// `auth.signature_invalid`. The load-bearing test for the security
/// story; if this passes, the cryptographic validation is wired
/// correctly through the whole pipeline.
#[tokio::test]
async fn tampered_signature_rejects() {
    let valid = mint_jwt(json!({
        "sub": "alice",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
    }));
    // Flip a char in the middle of the signature segment. We
    // can't tamper with the *last* char because base64url
    // encoding of a 256-byte RSA-2048 signature requires its last
    // char to encode 4 trailing-bit zeros — only `{A, Q, g, w}`
    // satisfy that. A naive flip to an out-of-set char produces
    // invalid base64 (decoder error → `auth.malformed_header`)
    // rather than valid bytes that fail signature verification.
    // Middle-segment chars don't have the trailing-bit constraint.
    let parts: Vec<&str> = valid.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT should have three segments");
    let sig = parts[2];
    let mut sig_chars: Vec<char> = sig.chars().collect();
    let target_idx = sig_chars.len() / 2; // well into the middle
    let original = sig_chars[target_idx];
    // Pick a replacement that's different but in the same charset.
    let replacement = if original == 'A' { 'B' } else { 'A' };
    sig_chars[target_idx] = replacement;
    let new_sig: String = sig_chars.into_iter().collect();
    let tampered = format!("{}.{}.{}", parts[0], parts[1], new_sig);

    let result = invoke(tampered).await;
    assert!(!result.continue_processing);
    let v = result.violation.expect("rejection should surface");
    assert_eq!(v.code, "auth.signature_invalid");
}

/// Token with no `iss` claim at all → `auth.malformed_header` from
/// the peek step (we can't pick a trusted issuer without `iss`).
#[tokio::test]
async fn missing_iss_rejects() {
    let token = mint_jwt(json!({
        "sub": "alice",
        // no iss
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
    }));

    let result = invoke(token).await;
    assert!(!result.continue_processing);
    let v = result.violation.expect("rejection should surface");
    assert_eq!(v.code, "auth.malformed_header");
}
