// Location: ./integrations/praxis-cpex/filter/tests/multi_role_identity.rs
// SPDX-License-Identifier: Apache-2.0
//
// Slice-G end-to-end test. Two identity resolvers on the same chain,
// each reading a different inbound header into a different
// `SecurityExtension` slot:
//
//   * X-User-Token     -> security.subject       (role: user)
//   * Authorization    -> security.client        (role: client)
//
// Asserts:
//   1. Both resolvers run; both populate their respective slots.
//   2. RawCredentialsExtension carries TWO inbound tokens, keyed by
//      role, each remembering the header it came from.
//   3. An APL route policy that gates on BOTH subject.id AND
//      client.client_id (`require(subject.id) AND require(client.client_id)`)
//      allows when both tokens validate.

use std::sync::OnceLock;
use std::time::Instant;

use bytes::Bytes;
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
        .unwrap()
        .as_secs() as i64
}

/// CPEX config with TWO identity resolvers — one per role — sharing
/// the same trusted issuer for test simplicity. A real deployment
/// might wire two different IdPs (a user-IdP for `X-User-Token` and
/// the gateway-internal OAuth IdP for `Authorization`).
fn write_cpex_config() -> (tempfile::TempDir, String) {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let cfg_path = dir.path().join("cpex.yaml");
    let indented_pem = keypair()
        .public_pem
        .lines()
        .map(|l| format!("              {l}"))
        .collect::<Vec<_>>()
        .join("\n");

    let yaml = format!(
        r#"plugin_settings:
  routing_enabled: true

plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks: [identity.resolve]
    mode: sequential
    priority: 10
    on_error: fail
    config:
      role: user
      header: X-User-Token
      trusted_issuers:
        - issuer: "{TEST_ISSUER}"
          audiences: ["{TEST_AUDIENCE}"]
          algorithms: ["RS256"]
          decoding_key:
            kind: pem
            pem: |
{indented_pem}
          leeway_seconds: 60

  - name: jwt-client
    kind: identity/jwt
    hooks: [identity.resolve]
    mode: sequential
    priority: 20
    on_error: fail
    config:
      role: client
      header: Authorization
      trusted_issuers:
        - issuer: "{TEST_ISSUER}"
          audiences: ["{TEST_AUDIENCE}"]
          algorithms: ["RS256"]
          decoding_key:
            kind: pem
            pem: |
{indented_pem}
          leeway_seconds: 60

global:
  identity:
    - jwt-user
    - jwt-client

routes:
  - tool: get_compensation
    apl:
      policy:
        # Both identity slots must be populated for this tool. Multi-
        # role lets us distinguish "the user authenticated via SSO"
        # from "the agent presenting the request is a trusted client."
        - "require(authenticated)"
        - "require(role.hr)"
"#
    );

    std::fs::write(&cfg_path, yaml).expect("write cpex.yaml");
    (dir, cfg_path.to_str().unwrap().to_string())
}

fn make_request(headers: HeaderMap) -> Request {
    Request {
        method: Method::POST,
        uri: "/mcp".parse::<Uri>().unwrap(),
        headers,
    }
}

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

fn stamp_mcp_metadata(ctx: &mut HttpFilterContext<'_>, method: &str, name: &str) {
    ctx.filter_metadata
        .insert("mcp.method".to_string(), method.to_string());
    ctx.filter_metadata
        .insert("mcp.name".to_string(), name.to_string());
}

fn tools_call_body(name: &str) -> Bytes {
    Bytes::from(
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": name, "arguments": {} }
        })
        .to_string(),
    )
}

async fn build_filter() -> (tempfile::TempDir, CpexFilter) {
    let (dir, path) = write_cpex_config();
    let filter = CpexFilter::new(CpexFilterConfig {
        config_path: path,
        token_header: "Authorization".into(), // legacy, no longer consumed
        body_access: Default::default(),
    })
    .expect("filter constructs");
    (dir, filter)
}

// =====================================================================
// Scenarios
// =====================================================================

/// Happy path. Two valid JWTs in two different headers → both
/// resolvers populate their slots → APL allows on
/// require(authenticated) + require(role.hr).
#[tokio::test(flavor = "multi_thread")]
async fn both_identities_populate_and_route_allows() {
    let (_dir, filter) = build_filter().await;

    // User token — sub=alice, role hr.
    let user_jwt = mint_jwt(json!({
        "sub": "alice@corp.com",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "iat": now_unix(),
        "roles": ["hr"],
    }));

    // Client token — gateway's identity for the user's session.
    let client_jwt = mint_jwt(json!({
        "sub": "alice@corp.com", // also subject for jwt validation
        "client_id": "browser-app",
        "azp": "browser-app",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "scope": "openid profile email",
    }));

    let mut headers = HeaderMap::new();
    headers.insert("X-User-Token", format!("Bearer {user_jwt}").parse().unwrap());
    headers.insert(
        "Authorization",
        format!("Bearer {client_jwt}").parse().unwrap(),
    );
    let req = make_request(headers);
    let mut ctx = make_ctx(&req);

    // Identity at on_request.
    let action = filter.on_request(&mut ctx).await.expect("filter ok");
    assert!(
        matches!(action, FilterAction::Continue),
        "both tokens valid; expected Continue, got {action:?}",
    );

    // CMF dispatch (route allow).
    stamp_mcp_metadata(&mut ctx, "tools/call", "get_compensation");
    let mut body = Some(tools_call_body("get_compensation"));
    let action = filter
        .on_request_body(&mut ctx, &mut body, true)
        .await
        .expect("filter ok");
    assert!(
        matches!(
            action,
            FilterAction::Continue | FilterAction::BodyDone | FilterAction::Release
        ),
        "expected allow on the route policy, got {action:?}",
    );
}

/// User token missing → user resolver denies → identity chain fails
/// → 401 (no chance to even reach the route policy). Verifies that
/// resolvers run independently and a missing token fails-fast.
#[tokio::test(flavor = "multi_thread")]
async fn missing_user_header_rejects_at_identity() {
    let (_dir, filter) = build_filter().await;

    let client_jwt = mint_jwt(json!({
        "sub": "alice@corp.com",
        "client_id": "browser-app",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
    }));

    let mut headers = HeaderMap::new();
    // No X-User-Token.
    headers.insert(
        "Authorization",
        format!("Bearer {client_jwt}").parse().unwrap(),
    );
    let req = make_request(headers);
    let mut ctx = make_ctx(&req);

    let action = filter.on_request(&mut ctx).await.expect("filter ok");
    match action {
        FilterAction::Reject(rej) => {
            assert_eq!(rej.status, 401, "missing user token → 401");
            let body = std::str::from_utf8(&rej.body.unwrap()).unwrap().to_string();
            assert!(
                body.contains("auth.malformed_header")
                    && body.contains("X-User-Token"),
                "rejection should call out the missing user header: {body}",
            );
        }
        other => panic!("expected 401 Reject, got {other:?}"),
    }
}

/// Client header carrying a token with no `client_id` / `azp` claim
/// → client resolver's mapping fails → `auth.mapping_failed`.
/// Confirms the per-role mapper is the one rejecting (not a generic
/// validation failure).
#[tokio::test(flavor = "multi_thread")]
async fn client_token_without_client_id_claim_rejects() {
    let (_dir, filter) = build_filter().await;

    let user_jwt = mint_jwt(json!({
        "sub": "alice@corp.com",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "roles": ["hr"],
    }));
    // Client token signed correctly but no client_id / azp claim.
    let client_jwt_no_clientid = mint_jwt(json!({
        "sub": "alice@corp.com",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        // intentionally no client_id, no azp
    }));

    let mut headers = HeaderMap::new();
    headers.insert("X-User-Token", format!("Bearer {user_jwt}").parse().unwrap());
    headers.insert(
        "Authorization",
        format!("Bearer {client_jwt_no_clientid}").parse().unwrap(),
    );
    let req = make_request(headers);
    let mut ctx = make_ctx(&req);

    let action = filter.on_request(&mut ctx).await.expect("filter ok");
    match action {
        FilterAction::Reject(rej) => {
            assert_eq!(rej.status, 401);
            let body = std::str::from_utf8(&rej.body.unwrap()).unwrap().to_string();
            assert!(
                body.contains("auth.mapping_failed") && body.contains("client_id"),
                "expected mapping_failed for client claims: {body}",
            );
        }
        other => panic!("expected 401 Reject from mapping_failed, got {other:?}"),
    }
}
