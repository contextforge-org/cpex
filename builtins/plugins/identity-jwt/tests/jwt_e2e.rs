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

use cpex_plugin_identity_jwt::JwtIdentityResolver;

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

/// Role-aware variant of [`resolver_plugin_config`]. `role` and
/// `header` are the two knobs that decide which identity slot a
/// resolver instance fills and where it reads its token from — one
/// instance per inbound credential, so a deployment expecting a user
/// JWT *and* a workload SVID wires two.
fn resolver_plugin_config_for(role: &str, header: &str) -> PluginConfig {
    let mut cfg = resolver_plugin_config();
    match cfg.config.as_mut() {
        Some(Value::Object(map)) => {
            map.insert("role".into(), json!(role));
            map.insert("header".into(), json!(header));
        },
        other => panic!("resolver config should be a JSON object, got {other:?}"),
    }
    cfg
}

/// Build the PluginManager + register the resolver + initialize.
/// All four scenarios share this skeleton.
async fn build_manager() -> Arc<PluginManager> {
    build_manager_with(resolver_plugin_config()).await
}

async fn build_manager_with(cfg: PluginConfig) -> Arc<PluginManager> {
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
    invoke_with(resolver_plugin_config(), token, TokenSource::Bearer).await
}

async fn invoke_with(
    cfg: PluginConfig,
    token: String,
    source: TokenSource,
) -> cpex_core::executor::PipelineResult {
    let mgr = build_manager_with(cfg).await;
    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            IdentityPayload::new(token, source),
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

    let identity =
        IdentityPayload::from_pipeline_result(&result).expect("payload should be present");
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

// ---------------------------------------------------------------------
// Workload role — SPIFFE JWT-SVID ingress
// ---------------------------------------------------------------------

/// A resolver configured with `role: workload` is the ingress for the
/// caller's SPIFFE JWT-SVID. It must land the mapped identity in
/// `caller_workload` (the *calling agent*, distinct from the gateway's
/// own `this_workload`) and stash the raw bytes under
/// `TokenRole::CallerWorkload` — the slot a `delegate(...)` step reads from
/// when a route says `subject: workload` or `actor: workload`.
///
/// The stash is tagged `TokenKind::SpiffeJwt`, not the generic `Jwt`:
/// reaching this point means `map_workload` already accepted the
/// SPIFFE-shaped `sub`, so the wire format is known, and consumers
/// that branch on kind shouldn't have to re-parse the token to learn
/// what the resolver already established.
#[tokio::test]
async fn workload_svid_resolves_caller_workload_and_stashes_as_spiffe_jwt() {
    let svid = mint_jwt(json!({
        // SPIFFE JWT-SVID convention: the SPIFFE ID lives in `sub`.
        "sub": "spiffe://corp.example/ns/default/sa/payroll-agent",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "iat": now_unix(),
    }));

    let result = invoke_with(
        resolver_plugin_config_for("workload", "X-Workload-Token"),
        svid.clone(),
        TokenSource::SpiffeJwtSvid,
    )
    .await;
    assert!(
        result.continue_processing,
        "valid SVID should resolve: violation = {:?}",
        result.violation,
    );

    let identity =
        IdentityPayload::from_pipeline_result(&result).expect("payload should be present");

    // Lands in caller_workload — the inbound peer — not subject.
    let workload = identity
        .caller_workload
        .as_ref()
        .expect("caller_workload populated");
    assert_eq!(
        workload.spiffe_id.as_deref(),
        Some("spiffe://corp.example/ns/default/sa/payroll-agent"),
    );
    assert_eq!(workload.trust_domain.as_deref(), Some("corp.example"));
    assert!(
        identity.subject.is_none(),
        "a workload-role resolver must not populate the user slot",
    );

    // Stashed under the Workload role, tagged as a SPIFFE JWT-SVID,
    // and attributed to the header it arrived on.
    let raw = identity
        .raw_credentials
        .as_ref()
        .expect("raw_credentials populated");
    let workload_token = raw
        .inbound_tokens
        .get(&TokenRole::CallerWorkload)
        .expect("workload-role token present");
    assert_eq!(&*workload_token.token, &svid);
    assert_eq!(workload_token.source_header, "X-Workload-Token");
    assert!(
        matches!(workload_token.kind, TokenKind::SpiffeJwt),
        "workload SVID should be tagged SpiffeJwt, got {:?}",
        workload_token.kind,
    );
}

/// A `role: workload` resolver handed a perfectly valid *user* JWT
/// must refuse it rather than filing a non-SPIFFE identity into the
/// workload slot. Guards the boundary that makes `subject: workload`
/// meaningful: whatever is in that slot really is an attested
/// workload.
#[tokio::test]
async fn workload_role_rejects_a_non_spiffe_token() {
    let user_jwt = mint_jwt(json!({
        "sub": "alice@corp.com",  // no spiffe:// prefix
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "iat": now_unix(),
    }));

    let result = invoke_with(
        resolver_plugin_config_for("workload", "X-Workload-Token"),
        user_jwt,
        TokenSource::SpiffeJwtSvid,
    )
    .await;

    assert!(
        !result.continue_processing,
        "a non-SPIFFE token must not resolve as a workload",
    );
    let violation = result.violation.expect("violation surfaced");
    assert_eq!(violation.code, "auth.mapping_failed");
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
