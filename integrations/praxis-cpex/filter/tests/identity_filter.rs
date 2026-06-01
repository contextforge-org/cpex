// Location: ./integrations/praxis-cpex/filter/tests/identity_filter.rs
// SPDX-License-Identifier: Apache-2.0
//
// Slice-A end-to-end test for `CpexFilter`. Wires a real JWT, a real
// `apl-identity-jwt` resolver loaded via YAML, and a hand-built
// Praxis `HttpFilterContext`, then exercises three scenarios:
//
//   1. Valid JWT → FilterAction::Continue
//   2. Missing `Authorization` header → FilterAction::Reject(401)
//   3. Tampered signature → FilterAction::Reject(401) with violation header

use std::sync::OnceLock;
use std::time::Instant;

use cpex_praxis_filter::{CpexFilter, CpexFilterConfig};

use http::{HeaderMap, Method, Uri};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use praxis_filter::{FilterAction, HttpFilter, HttpFilterContext, Request};
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Value};

// =====================================================================
// Fixtures
// =====================================================================

struct Keypair {
    private_pem: String,
    public_pem: String,
}

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

const TEST_ISSUER: &str = "https://idp.test.local";
const TEST_AUDIENCE: &str = "test-api";

fn mint_jwt(claims: Value) -> String {
    let header = Header::new(Algorithm::RS256);
    let key = EncodingKey::from_rsa_pem(keypair().private_pem.as_bytes())
        .expect("build EncodingKey");
    encode(&header, &claims, &key).expect("sign JWT")
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock should not be before unix epoch")
        .as_secs() as i64
}

/// Write a CPEX YAML config file into a tempdir using the test
/// keypair's public PEM as the trusted-issuer signing material.
/// Returns the path so callers can hand it to `CpexFilter::new`.
fn write_cpex_config() -> (tempfile::TempDir, String) {
    let dir = tempfile::TempDir::new().expect("create tempdir");
    let cfg_path = dir.path().join("cpex.yaml");

    // Indent the public PEM to fit under the `pem: |` block scalar.
    let indented_pem = keypair()
        .public_pem
        .lines()
        .map(|l| format!("              {l}"))
        .collect::<Vec<_>>()
        .join("\n");

    let yaml = format!(
        r#"plugins:
  - name: jwt-resolver
    kind: identity/jwt
    hooks:
      - identity.resolve
    mode: sequential
    priority: 10
    on_error: fail
    config:
      trusted_issuers:
        - issuer: "{TEST_ISSUER}"
          audiences: ["{TEST_AUDIENCE}"]
          algorithms: ["RS256"]
          decoding_key:
            kind: pem
            pem: |
{indented_pem}
          leeway_seconds: 60
      claim_mapper: standard
"#
    );

    std::fs::write(&cfg_path, yaml).expect("write cpex.yaml");
    let path_str = cfg_path.to_str().expect("utf8 path").to_string();
    (dir, path_str)
}

fn make_request(headers: HeaderMap) -> Request {
    Request {
        method: Method::POST,
        uri: "/".parse::<Uri>().unwrap(),
        headers,
    }
}

/// Build a minimal HttpFilterContext referencing the given Request.
/// Mirrors Praxis's internal test_utils::make_filter_context (which
/// is pub(crate) so we can't import it).
fn make_ctx<'a>(req: &'a Request) -> HttpFilterContext<'a> {
    HttpFilterContext {
        body_done_indices: Vec::new(),
        branch_iterations: std::collections::HashMap::new(),
        client_addr: None,
        cluster: None,
        downstream_tls: false,
        executed_filter_indices: Vec::new(),
        extra_request_headers: Vec::new(),
        request_headers_to_remove: Vec::new(),
        request_headers_to_set: Vec::new(),
        filter_metadata: std::collections::HashMap::new(),
        filter_results: std::collections::HashMap::new(),
        health_registry: None,
        kv_stores: None,
        request: req,
        request_body_bytes: 0,
        request_body_mode: praxis_filter::BodyMode::Stream,
        request_start: Instant::now(),
        response_body_bytes: 0,
        response_body_mode: praxis_filter::BodyMode::Stream,
        response_header: None,
        response_headers_modified: false,
        rewritten_path: None,
        selected_endpoint_index: None,
        upstream: None,
    }
}

async fn build_filter() -> (tempfile::TempDir, CpexFilter) {
    let (dir, path) = write_cpex_config();
    let cfg = CpexFilterConfig {
        config_path: path,
        token_header: "Authorization".to_string(),
        body_access: Default::default(),
    };
    let filter = CpexFilter::new(cfg).expect("filter should construct");
    (dir, filter)
}

// =====================================================================
// Scenarios
// =====================================================================

#[tokio::test(flavor = "multi_thread")]
async fn valid_jwt_continues() {
    let (_dir, filter) = build_filter().await;

    let token = mint_jwt(json!({
        "sub": "alice@corp.com",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "iat": now_unix(),
        "roles": ["hr"],
    }));

    let mut headers = HeaderMap::new();
    headers.insert(
        "Authorization",
        format!("Bearer {token}").parse().unwrap(),
    );
    let req = make_request(headers);
    let mut ctx = make_ctx(&req);

    let action = filter.on_request(&mut ctx).await.expect("filter ok");
    assert!(
        matches!(action, FilterAction::Continue),
        "valid JWT should produce Continue, got {action:?}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_token_rejects_401() {
    let (_dir, filter) = build_filter().await;

    let req = make_request(HeaderMap::new()); // no Authorization
    let mut ctx = make_ctx(&req);

    let action = filter.on_request(&mut ctx).await.expect("filter ok");
    match action {
        FilterAction::Reject(rej) => {
            assert_eq!(rej.status, 401, "missing token should be 401");
            let body = rej.body.expect("rejection should carry a body");
            let msg = std::str::from_utf8(&body).unwrap();
            assert!(
                msg.contains("auth.malformed_header") || msg.contains("auth"),
                "rejection body should mention an auth violation code: got {msg:?}",
            );
        }
        other => panic!("expected Reject, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn tampered_signature_rejects_401() {
    let (_dir, filter) = build_filter().await;

    let valid = mint_jwt(json!({
        "sub": "alice@corp.com",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
    }));
    let parts: Vec<&str> = valid.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT should have three segments");
    let sig = parts[2];
    let mut sig_chars: Vec<char> = sig.chars().collect();
    let target_idx = sig_chars.len() / 2;
    let original = sig_chars[target_idx];
    let replacement = if original == 'A' { 'B' } else { 'A' };
    sig_chars[target_idx] = replacement;
    let new_sig: String = sig_chars.into_iter().collect();
    let tampered = format!("{}.{}.{}", parts[0], parts[1], new_sig);

    let mut headers = HeaderMap::new();
    headers.insert(
        "Authorization",
        format!("Bearer {tampered}").parse().unwrap(),
    );
    let req = make_request(headers);
    let mut ctx = make_ctx(&req);

    let action = filter.on_request(&mut ctx).await.expect("filter ok");
    match action {
        FilterAction::Reject(rej) => {
            assert_eq!(rej.status, 401, "bad signature should be 401");
            let violation_header = rej
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("X-Cpex-Violation"));
            assert!(
                violation_header.is_some(),
                "rejection should carry X-Cpex-Violation header",
            );
        }
        other => panic!("expected Reject, got {other:?}"),
    }
}
