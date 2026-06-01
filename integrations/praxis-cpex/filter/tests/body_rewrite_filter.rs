// Location: ./integrations/praxis-cpex/filter/tests/body_rewrite_filter.rs
// SPDX-License-Identifier: Apache-2.0
//
// Slice-F end-to-end test for body rewriting. Verifies the
// CMF→JSON-RPC re-serialization path:
//
//   1. ReadWrite mode + APL `redact(args.ssn)` step → upstream body's
//      params.arguments has `ssn` stripped, other fields preserved
//   2. ReadOnly mode + same step → upstream body bytes UNCHANGED
//      (mutation discarded at executor merge boundary)
//   3. No mutator on route → body bytes pass through byte-identical

use std::sync::OnceLock;
use std::time::Instant;

use bytes::Bytes;
use cpex_praxis_filter::{BodyAccessMode, CpexFilter, CpexFilterConfig};

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

/// CPEX config with an args pipeline that redacts `ssn` unless the
/// caller has `perm.view_ssn`. For our tests Alice doesn't carry the
/// perm, so the redact fires.
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
  - name: jwt-resolver
    kind: identity/jwt
    hooks: [identity.resolve]
    mode: sequential
    priority: 10
    on_error: fail
    config:
      role: user
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
    - jwt-resolver

routes:
  - tool: get_employee
    apl:
      policy:
        - "require(role.hr)"
      args:
        # `!perm.view_ssn` → if caller does NOT have view_ssn, the
        # redact stage strips ssn from args. `str` is the type
        # validator (no transform on its own).
        ssn: "str | redact(!perm.view_ssn)"
"#
    );

    std::fs::write(&cfg_path, yaml).expect("write cpex.yaml");
    (dir, cfg_path.to_str().unwrap().to_string())
}

fn build_filter(body_access: BodyAccessMode) -> (tempfile::TempDir, CpexFilter) {
    let (dir, path) = write_cpex_config();
    let filter = CpexFilter::new(CpexFilterConfig {
        config_path: path,
        token_header: "Authorization".into(),
        body_access,
    })
    .expect("filter constructs");
    (dir, filter)
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

fn tools_call_body() -> Bytes {
    Bytes::from(
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "get_employee",
                "arguments": {
                    "employee_id": "E001",
                    "ssn": "555-12-3456"
                }
            }
        })
        .to_string(),
    )
}

fn alice_jwt() -> String {
    mint_jwt(json!({
        "sub": "alice@corp.com",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "iat": now_unix(),
        "roles": ["hr"],
        // No `perm.view_ssn` → redact fires.
    }))
}

// =====================================================================
// Scenarios
// =====================================================================

/// ReadWrite mode: APL redacts `ssn`, our filter re-serializes the
/// JSON-RPC body, and the upstream receives a body without `ssn`.
/// `employee_id` is preserved.
#[tokio::test(flavor = "multi_thread")]
async fn read_write_redacts_ssn_from_upstream_body() {
    let (_dir, filter) = build_filter(BodyAccessMode::ReadWrite);

    let mut headers = HeaderMap::new();
    headers.insert(
        "Authorization",
        format!("Bearer {}", alice_jwt()).parse().unwrap(),
    );
    let req = make_request(headers);
    let mut ctx = make_ctx(&req);
    let _ = filter.on_request(&mut ctx).await.unwrap();
    stamp_mcp_metadata(&mut ctx, "tools/call", "get_employee");

    let mut body = Some(tools_call_body());
    let action = filter
        .on_request_body(&mut ctx, &mut body, true)
        .await
        .expect("filter ok");
    assert!(
        matches!(
            action,
            FilterAction::Continue | FilterAction::BodyDone | FilterAction::Release
        ),
        "expected allow path, got {action:?}",
    );

    let new_body = body.expect("body present");
    let envelope: Value = serde_json::from_slice(&new_body).expect("rewritten body is JSON");
    let params = envelope.get("params").expect("params present");
    let args = params.get("arguments").expect("arguments present");
    // `redact` preserves the key but replaces the value with the
    // redaction marker — the field's presence is itself information
    // (the upstream knows "this field was here, just hidden"), so
    // policies that need full stripping should use `omit` instead.
    let ssn = args.get("ssn").expect("ssn key preserved");
    assert_eq!(
        ssn,
        &Value::String("[REDACTED]".to_string()),
        "ssn value should be replaced with redaction marker, got: {ssn}",
    );
    assert_eq!(
        args.get("employee_id"),
        Some(&Value::String("E001".to_string())),
        "untouched fields should pass through",
    );
    // JSON-RPC envelope preserved (jsonrpc, id, method, params.name).
    assert_eq!(envelope.get("jsonrpc"), Some(&Value::String("2.0".to_string())));
    assert_eq!(envelope.get("method"), Some(&Value::String("tools/call".to_string())));
    assert_eq!(params.get("name"), Some(&Value::String("get_employee".to_string())));
}

/// ReadOnly mode (default): same APL redact step runs, but Praxis
/// discards the mutation at the body-access boundary. The upstream
/// body is byte-identical to the inbound one — including the `ssn`
/// the operator's policy meant to strip.
///
/// This is the deliberate "you opted out, you pay the consequences"
/// behavior. Operators who want redaction to take effect must
/// declare `body_access: read_write`.
#[tokio::test(flavor = "multi_thread")]
async fn read_only_discards_mutation_keeps_body_unchanged() {
    let (_dir, filter) = build_filter(BodyAccessMode::ReadOnly);

    let mut headers = HeaderMap::new();
    headers.insert(
        "Authorization",
        format!("Bearer {}", alice_jwt()).parse().unwrap(),
    );
    let req = make_request(headers);
    let mut ctx = make_ctx(&req);
    let _ = filter.on_request(&mut ctx).await.unwrap();
    stamp_mcp_metadata(&mut ctx, "tools/call", "get_employee");

    let original = tools_call_body();
    let mut body = Some(original.clone());
    let action = filter
        .on_request_body(&mut ctx, &mut body, true)
        .await
        .expect("filter ok");
    assert!(matches!(
        action,
        FilterAction::Continue | FilterAction::BodyDone | FilterAction::Release
    ));

    let final_body = body.expect("body present");
    assert_eq!(
        final_body, original,
        "ReadOnly mode should leave the body byte-identical",
    );
}

/// Sanity: a route without any args pipeline → no mutation → body
/// passes through unchanged even in ReadWrite mode (we only rewrite
/// when modified_payload is Some).
#[tokio::test(flavor = "multi_thread")]
async fn no_mutator_passes_body_through_in_read_write() {
    // Different CPEX config — no args block.
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
      role: user
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
    - jwt-resolver

routes:
  - tool: get_employee
    apl:
      policy:
        - "require(role.hr)"
"#
    );
    std::fs::write(&cfg_path, &yaml).unwrap();
    let filter = CpexFilter::new(CpexFilterConfig {
        config_path: cfg_path.to_str().unwrap().to_string(),
        token_header: "Authorization".into(),
        body_access: BodyAccessMode::ReadWrite,
    })
    .expect("filter constructs");

    let mut headers = HeaderMap::new();
    headers.insert(
        "Authorization",
        format!("Bearer {}", alice_jwt()).parse().unwrap(),
    );
    let req = make_request(headers);
    let mut ctx = make_ctx(&req);
    let _ = filter.on_request(&mut ctx).await.unwrap();
    stamp_mcp_metadata(&mut ctx, "tools/call", "get_employee");

    let original = tools_call_body();
    let mut body = Some(original.clone());
    let _ = filter
        .on_request_body(&mut ctx, &mut body, true)
        .await
        .expect("filter ok");

    let final_body = body.expect("body present");
    assert_eq!(
        final_body, original,
        "no mutator → body passes through byte-identical",
    );
}
