// Location: ./integrations/praxis-cpex/filter/tests/delegation_filter.rs
// SPDX-License-Identifier: Apache-2.0
//
// Slice-D end-to-end test. Exercises the full pipeline through to
// outbound credential attachment:
//
//   1. JWT identity resolves (apl-identity-jwt)
//   2. APL route policy fires (`require(role.hr)` + a `delegate(...)`
//      step targeting our mocked OAuth IdP)
//   3. OAuthDelegator POSTs an RFC 8693 token-exchange to mockito
//   4. Mocked IdP returns a "minted-downstream-token"
//   5. Our filter pulls that minted token from
//      `cmf_result.modified_extensions.raw_credentials.delegated_tokens`
//      and pushes it onto `ctx.request_headers_to_set` so the upstream
//      sees `Authorization: Bearer minted-downstream-token`
//
// The point: prove that what the upstream service sees is the
// IdP-minted, audience-scoped token — NOT the user's original bearer.

use std::sync::OnceLock;
use std::time::Instant;

use bytes::Bytes;
use cpex_praxis_filter::{CpexFilter, CpexFilterConfig};

use http::{HeaderMap, Method, Uri};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use mockito::{Matcher, Server, ServerGuard};
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

/// Write a CPEX YAML that includes both the JWT identity resolver
/// and the OAuth delegator, plus an APL route that fires
/// `delegate(workday-oauth, ...)` after the `require(role.hr)` guard.
fn write_cpex_config(idp_token_endpoint: &str) -> (tempfile::TempDir, String) {
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

  - name: workday-oauth
    kind: delegator/oauth
    hooks:
      - token.delegate
    mode: sequential
    priority: 20
    on_error: fail
    # Scoped credential capabilities — the delegator NEEDS to read
    # the inbound bearer (to forward as RFC 8693 `subject_token`)
    # and write the minted token back into `raw_credentials.
    # delegated_tokens`. Declaring them here keeps the bearer scoped
    # to this specific delegator rather than leaking it into the
    # AplRouteHandler's baseline (visible to every predicate / PDP /
    # step in the route).
    capabilities:
      - read_inbound_credentials
      - write_delegated_tokens
    config:
      token_endpoint: "{idp_token_endpoint}"
      client_id: "praxis-gateway"
      client_secret_source:
        kind: literal
        secret: "test-only-secret"
      timeout_seconds: 2
      default_outbound_header: "Authorization"

global:
  identity:
    - jwt-resolver

routes:
  - tool: get_compensation
    apl:
      policy:
        - "require(role.hr)"
        - "delegate(workday-oauth, target: workday-api, audience: workday-api, permissions: [read_compensation])"
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
            "params": { "name": name, "arguments": { "employee_id": "E001" } }
        })
        .to_string(),
    )
}

/// Spin up a mock IdP that responds to RFC 8693 token-exchange
/// requests with a fixed minted access_token. The server lifetime
/// is tied to the returned guard — drop it after the test finishes.
async fn mock_idp(minted_token: &str) -> (ServerGuard, String) {
    let mut server = Server::new_async().await;
    server
        .mock("POST", "/oauth/token")
        .match_header("content-type", "application/x-www-form-urlencoded")
        .match_body(Matcher::AllOf(vec![
            Matcher::UrlEncoded(
                "grant_type".into(),
                "urn:ietf:params:oauth:grant-type:token-exchange".into(),
            ),
            Matcher::UrlEncoded("audience".into(), "workday-api".into()),
        ]))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "access_token": minted_token,
                "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "expires_in": 300,
                "scope": "read_compensation",
            })
            .to_string(),
        )
        .create_async()
        .await;
    let token_endpoint = format!("{}/oauth/token", server.url());
    (server, token_endpoint)
}

// =====================================================================
// Scenarios
// =====================================================================

/// Happy path. Alice carries `role.hr`, calls `tools/call(get_compensation)`,
/// APL allows + fires the delegate step, the mock IdP returns a token,
/// and our filter attaches it as `Authorization: Bearer <minted>` on
/// the upstream request via `request_headers_to_set`.
#[tokio::test(flavor = "multi_thread")]
async fn alice_gets_delegated_token_attached_to_upstream() {
    let (_idp, token_endpoint) = mock_idp("minted-downstream-token-for-workday").await;

    let (_dir, cfg_path) = write_cpex_config(&token_endpoint);
    let filter = CpexFilter::new(CpexFilterConfig {
        config_path: cfg_path,
        token_header: "Authorization".into(),
        body_access: Default::default(),
    })
    .expect("filter constructs");

    let user_jwt = mint_jwt(json!({
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
        format!("Bearer {user_jwt}").parse().unwrap(),
    );
    let req = make_request(headers);
    let mut ctx = make_ctx(&req);

    // Identity pre-check.
    let action = filter.on_request(&mut ctx).await.expect("filter ok");
    assert!(matches!(action, FilterAction::Continue));

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
        "expected allow after delegate; got {action:?}",
    );

    // The point of the slice: minted token is on the upstream request.
    let authz = ctx
        .request_headers_to_set
        .iter()
        .find(|(k, _)| k == http::header::AUTHORIZATION);
    let (_name, value) = authz.expect(
        "Authorization header should be set on upstream from the minted delegated token",
    );
    assert_eq!(
        value.to_str().unwrap(),
        "Bearer minted-downstream-token-for-workday",
        "upstream should see the IdP-minted token, NOT the user's original JWT",
    );
}

/// When the delegator's `default_outbound_header` differs from the
/// inbound `Authorization` header, the filter must:
///   * SET the delegated token at the new outbound header
///   * REMOVE the inbound `Authorization` (don't leak the user's IdP
///     token to a downstream that has its own audience-scoped token)
///
/// Without the strip-on-mismatch logic, the upstream would see
/// BOTH the user's JWT in `Authorization` AND the minted token in
/// `X-Workday-Token` — a credential leak.
#[tokio::test(flavor = "multi_thread")]
async fn outbound_header_mismatch_strips_inbound_authz() {
    use std::collections::HashMap;

    let (_idp, token_endpoint) = mock_idp("minted-downstream-token").await;

    // Same shape as write_cpex_config but override
    // default_outbound_header to a non-Authorization slot.
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
  - name: jwt-resolver
    kind: identity/jwt
    hooks: [identity.resolve]
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

  - name: workday-oauth
    kind: delegator/oauth
    hooks: [token.delegate]
    mode: sequential
    priority: 20
    on_error: fail
    capabilities:
      - read_inbound_credentials
      - write_delegated_tokens
    config:
      token_endpoint: "{token_endpoint}"
      client_id: "praxis-gateway"
      client_secret_source: {{ kind: literal, secret: "x" }}
      timeout_seconds: 2
      default_outbound_header: "X-Workday-Token"

global:
  identity:
    - jwt-resolver

routes:
  - tool: get_compensation
    apl:
      policy:
        - "require(role.hr)"
        - "delegate(workday-oauth, target: workday-api, audience: workday-api, permissions: [read_compensation])"
"#,
    );
    std::fs::write(&cfg_path, yaml).unwrap();
    let filter = CpexFilter::new(CpexFilterConfig {
        config_path: cfg_path.to_str().unwrap().to_string(),
        token_header: "Authorization".into(),
        body_access: Default::default(),
    })
    .expect("filter constructs");

    let token = mint_jwt(json!({
        "sub": "alice@corp.com",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "roles": ["hr"],
    }));
    let mut headers = HeaderMap::new();
    headers.insert("Authorization", format!("Bearer {token}").parse().unwrap());
    let req = make_request(headers);
    let mut ctx = make_ctx(&req);

    let _ = filter.on_request(&mut ctx).await.unwrap();
    stamp_mcp_metadata(&mut ctx, "tools/call", "get_compensation");
    let mut body = Some(tools_call_body("get_compensation"));
    let action = filter
        .on_request_body(&mut ctx, &mut body, true)
        .await
        .unwrap();
    assert!(matches!(
        action,
        FilterAction::Continue | FilterAction::BodyDone | FilterAction::Release
    ));

    // The minted token landed on the new outbound header.
    let outbound: HashMap<String, String> = ctx
        .request_headers_to_set
        .iter()
        .map(|(k, v)| (k.as_str().to_ascii_lowercase(), v.to_str().unwrap().to_string()))
        .collect();
    assert_eq!(
        outbound.get("x-workday-token").map(String::as_str),
        Some("Bearer minted-downstream-token"),
        "expected X-Workday-Token set on upstream",
    );
    // The inbound user JWT is NOT propagated.
    assert!(
        ctx.request_headers_to_remove
            .iter()
            .any(|h| h == http::header::AUTHORIZATION),
        "expected Authorization to be in request_headers_to_remove (don't leak user JWT)",
    );
}

/// Bob lacks `role.hr` — the `require(role.hr)` guard fails BEFORE the
/// `delegate(...)` step runs, so no IdP exchange happens and no
/// delegated token is attached. We verify both: 403 deny, and no
/// Authorization rewrite on the upstream.
#[tokio::test(flavor = "multi_thread")]
async fn bob_denied_before_delegation_runs() {
    let (idp, token_endpoint) = mock_idp("should-never-be-issued").await;

    let (_dir, cfg_path) = write_cpex_config(&token_endpoint);
    let filter = CpexFilter::new(CpexFilterConfig {
        config_path: cfg_path,
        token_header: "Authorization".into(),
        body_access: Default::default(),
    })
    .expect("filter constructs");

    let user_jwt = mint_jwt(json!({
        "sub": "bob@corp.com",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "iat": now_unix(),
        "roles": ["engineering"], // no hr
    }));

    let mut headers = HeaderMap::new();
    headers.insert(
        "Authorization",
        format!("Bearer {user_jwt}").parse().unwrap(),
    );
    let req = make_request(headers);
    let mut ctx = make_ctx(&req);

    let _ = filter.on_request(&mut ctx).await.expect("filter ok");
    stamp_mcp_metadata(&mut ctx, "tools/call", "get_compensation");
    let mut body = Some(tools_call_body("get_compensation"));

    let action = filter
        .on_request_body(&mut ctx, &mut body, true)
        .await
        .expect("filter ok");
    match action {
        FilterAction::Reject(rej) => {
            assert_eq!(rej.status, 403);
        }
        other => panic!("expected 403 for Bob, got {other:?}"),
    }
    // No upstream header rewrite happened.
    assert!(
        !ctx.request_headers_to_set
            .iter()
            .any(|(k, _)| k == http::header::AUTHORIZATION),
        "Bob's denied request shouldn't carry an Authorization rewrite",
    );

    // mockito's drop checks if any unmatched mocks were registered;
    // we have one registered but it shouldn't have been hit.
    drop(idp);
}
