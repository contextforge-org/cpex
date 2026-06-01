// Location: ./integrations/praxis-cpex/filter/tests/cmf_policy_filter.rs
// SPDX-License-Identifier: Apache-2.0
//
// Slice-B end-to-end test. Verifies the full CpexFilter pipeline:
//
//   1. Identity (JWT → subject + roles in Extensions)
//   2. MCP method/name read from ctx.filter_metadata
//   3. JSON-RPC body parsed → CMF MessagePayload with typed ContentPart
//   4. APL route policy (`require(role.hr)` on `tool: get_compensation`)
//      evaluates against the resolved subject's roles
//   5. Allow → Continue / Deny → Reject(403)
//
// We simulate Praxis's `mcp` filter by stamping `mcp.method` and
// `mcp.name` into ctx.filter_metadata before calling on_request_body
// — in a real chain that's what Praxis does upstream of us.

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
// Fixtures (shared shape with identity_filter.rs)
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

fn write_cpex_config_with_route() -> (tempfile::TempDir, String) {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let cfg_path = dir.path().join("cpex.yaml");

    let indented_pem = keypair()
        .public_pem
        .lines()
        .map(|l| format!("              {l}"))
        .collect::<Vec<_>>()
        .join("\n");

    // jwt-resolver wired via `global.identity` (the principled shape
    // for "this resolver applies to every route by default"). APL
    // policy on `tool: get_compensation` requires `role.hr`.
    // `routing_enabled: true` activates the route-aware dispatch
    // path so global.identity actually steers identity selection.
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

global:
  identity:
    - jwt-resolver

routes:
  - tool: get_compensation
    apl:
      policy:
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

async fn build_filter() -> (tempfile::TempDir, CpexFilter) {
    let (dir, path) = write_cpex_config_with_route();
    let cfg = CpexFilterConfig {
        config_path: path,
        token_header: "Authorization".to_string(),
        body_access: Default::default(),
    };
    let filter = CpexFilter::new(cfg).expect("filter should construct");
    (dir, filter)
}

/// Simulate Praxis's `mcp` filter having run upstream by stamping
/// the metadata it would set.
fn stamp_mcp_metadata(
    ctx: &mut HttpFilterContext<'_>,
    method: &str,
    name: &str,
) {
    ctx.filter_metadata
        .insert("mcp.method".to_string(), method.to_string());
    ctx.filter_metadata
        .insert("mcp.name".to_string(), name.to_string());
}

fn tools_call_body(name: &str, employee_id: &str) -> Bytes {
    Bytes::from(
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": { "employee_id": employee_id }
            }
        })
        .to_string(),
    )
}

// =====================================================================
// Scenarios
// =====================================================================

#[tokio::test(flavor = "multi_thread")]
async fn alice_with_role_hr_allowed_through_cmf() {
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

    // on_request — identity succeeds, Continue.
    let action = filter.on_request(&mut ctx).await.expect("filter ok");
    assert!(
        matches!(action, FilterAction::Continue),
        "identity should allow Alice: got {action:?}",
    );

    // Praxis mcp filter runs here in real chain — simulate it.
    stamp_mcp_metadata(&mut ctx, "tools/call", "get_compensation");
    let mut body = Some(tools_call_body("get_compensation", "E001"));

    // on_request_body — APL `require(role.hr)` should pass.
    let action = filter
        .on_request_body(&mut ctx, &mut body, true)
        .await
        .expect("filter ok");
    assert!(
        matches!(
            action,
            FilterAction::Continue | FilterAction::BodyDone | FilterAction::Release
        ),
        "Alice should be allowed through CMF: got {action:?}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn bob_without_role_hr_denied_with_403() {
    let (_dir, filter) = build_filter().await;

    let token = mint_jwt(json!({
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
        format!("Bearer {token}").parse().unwrap(),
    );
    let req = make_request(headers);
    let mut ctx = make_ctx(&req);

    // Identity passes (token is valid).
    let action = filter.on_request(&mut ctx).await.expect("filter ok");
    assert!(matches!(action, FilterAction::Continue));

    // mcp metadata, body — same as Alice.
    stamp_mcp_metadata(&mut ctx, "tools/call", "get_compensation");
    let mut body = Some(tools_call_body("get_compensation", "E001"));

    let action = filter
        .on_request_body(&mut ctx, &mut body, true)
        .await
        .expect("filter ok");
    match action {
        FilterAction::Reject(rej) => {
            assert_eq!(rej.status, 403, "policy deny should be 403");
            let violation = rej
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("X-Cpex-Violation"));
            assert!(
                violation.is_some(),
                "rejection should carry X-Cpex-Violation header for policy deny",
            );
        }
        other => panic!("expected Reject(403) for Bob, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn no_mcp_metadata_skips_cmf_dispatch() {
    // Non-MCP traffic on a chain that includes cpex (e.g., operator
    // mistakenly enabled cpex on a non-JSON-RPC path). Our filter
    // should allow through — identity passed, no metadata means no
    // entity to evaluate.
    let (_dir, filter) = build_filter().await;

    let token = mint_jwt(json!({
        "sub": "alice@corp.com",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "roles": ["hr"],
    }));

    let mut headers = HeaderMap::new();
    headers.insert(
        "Authorization",
        format!("Bearer {token}").parse().unwrap(),
    );
    let req = make_request(headers);
    let mut ctx = make_ctx(&req);

    // No stamp_mcp_metadata call — ctx.filter_metadata stays empty.
    let action = filter.on_request(&mut ctx).await.expect("filter ok");
    assert!(matches!(action, FilterAction::Continue));

    let mut body = Some(Bytes::from_static(b"not json-rpc, just plain bytes"));
    let action = filter
        .on_request_body(&mut ctx, &mut body, true)
        .await
        .expect("filter ok");
    assert!(
        matches!(action, FilterAction::Continue | FilterAction::BodyDone),
        "no mcp metadata should bypass CMF and allow: got {action:?}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn non_entity_method_skips_cmf_dispatch() {
    // tools/list, initialize, etc. have no entity_name to gate on —
    // identity gates them; CMF dispatch is skipped.
    let (_dir, filter) = build_filter().await;

    let token = mint_jwt(json!({
        "sub": "alice@corp.com",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        // No roles at all — would fail require(role.hr) if CMF fired.
    }));

    let mut headers = HeaderMap::new();
    headers.insert(
        "Authorization",
        format!("Bearer {token}").parse().unwrap(),
    );
    let req = make_request(headers);
    let mut ctx = make_ctx(&req);

    let _ = filter.on_request(&mut ctx).await.expect("filter ok");
    stamp_mcp_metadata(&mut ctx, "tools/list", "");
    let mut body = Some(Bytes::from_static(
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
    ));

    let action = filter
        .on_request_body(&mut ctx, &mut body, true)
        .await
        .expect("filter ok");
    assert!(
        matches!(action, FilterAction::Continue | FilterAction::BodyDone),
        "tools/list should bypass CMF: got {action:?}",
    );
}
