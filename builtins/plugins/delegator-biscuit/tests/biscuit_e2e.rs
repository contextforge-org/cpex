// Location: ./builtins/plugins/delegator-biscuit/tests/biscuit_e2e.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// End-to-end tests for `BiscuitDelegator` on a `PolicyEngine`. Each
// test loads a PPE config document through a test-local factory,
// generates a root keypair in-process, mints an authority-only
// biscuit (the "inbound"), dispatches `token.delegate`, and verifies
// that the resulting attenuated biscuit is well-formed: the root key
// still verifies the chain, and the new delegation block carries the
// expected `delegated_to` / `audience` / `operation` / time checks.

use std::sync::Arc;

use biscuit_auth::{
    builder::{AuthorizerBuilder, BlockBuilder},
    Biscuit, KeyPair,
};
use chrono::Utc;

use praxis_policy_core::delegation::{
    AttenuationConfig, AuthEnforcedBy, DelegationPayload, TargetType, TokenDelegateHook,
    HOOK_TOKEN_DELEGATE,
};
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::error::PluginError;
use praxis_policy_core::executor::PipelineResult;
use praxis_policy_core::extensions::raw_credentials::DelegationMode;
use praxis_policy_core::factory::{PluginFactory, PluginInstance};
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::hooks::TypedHandlerAdapter;
use praxis_policy_core::plugin::PluginConfig;

use cpex_plugin_delegator_biscuit::BiscuitDelegator;

use serde_json::json;

// =====================================================================
// Fixtures
// =====================================================================

const KIND: &str = "delegator/biscuit";

struct Roots {
    keypair: KeyPair,
}

fn roots() -> &'static Roots {
    use std::sync::OnceLock;
    static ROOTS: OnceLock<Roots> = OnceLock::new();
    ROOTS.get_or_init(|| Roots {
        keypair: KeyPair::new(),
    })
}

/// Test-local factory: builds a `BiscuitDelegator` from the plugin's
/// config entry and registers it on `token.delegate`, the same way a
/// host wires any delegator kind into the engine.
struct BiscuitDelegatorFactory;

impl PluginFactory for BiscuitDelegatorFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let delegator = Arc::new(BiscuitDelegator::new(config.clone())?);
        let handler = Arc::new(TypedHandlerAdapter::<TokenDelegateHook, _>::new(
            Arc::clone(&delegator),
        ));
        Ok(PluginInstance {
            plugin: delegator,
            handlers: vec![(HOOK_TOKEN_DELEGATE, handler)],
        })
    }
}

/// Mint a fresh authority-only biscuit carrying the given Datalog
/// (capabilities the principal holds). Returns base64-encoded
/// biscuit ready to hand to the delegator as `bearer_token`.
fn mint_inbound_biscuit(authority_datalog: &str) -> String {
    let builder = BlockBuilder::new()
        .code(authority_datalog)
        .expect("authority Datalog parses");
    Biscuit::builder()
        .merge(builder)
        .build(&roots().keypair)
        .expect("biscuit builds")
        .to_base64()
        .expect("biscuit serializes")
}

/// PPE config document for one biscuit delegator. Delegation is
/// host-dispatched (`invoke_named`), not reached from a policy step,
/// so the document uses hook dispatch and the plugin declares the
/// `token.delegate` hook itself. The delegator reads nothing from
/// the request extensions, so it declares no capabilities.
fn config_yaml(root_key_hex: &str, outbound_header: &str, ttl_seconds: u64) -> String {
    format!(
        r#"
engine_settings:
  dispatch: hooks
plugins:
  - name: biscuit-delegator
    kind: {KIND}
    hooks: [{HOOK_TOKEN_DELEGATE}]
    mode: sequential
    on_error: fail
    config:
      root_public_key:
        kind: hex
        hex: "{root_key_hex}"
      default_outbound_header: {outbound_header}
      default_ttl_seconds: {ttl_seconds}
"#
    )
}

fn load_engine(yaml: &str) -> Result<Arc<PolicyEngine>, Box<PluginError>> {
    let engine = Arc::new(PolicyEngine::default());
    engine.register_factory(KIND, Box::new(BiscuitDelegatorFactory));
    engine.load_config_yaml(yaml)?;
    Ok(engine)
}

async fn build_engine_with(outbound_header: &str, ttl_seconds: u64) -> Arc<PolicyEngine> {
    let pub_hex = hex::encode(roots().keypair.public().to_bytes());
    let engine =
        load_engine(&config_yaml(&pub_hex, outbound_header, ttl_seconds)).expect("config loads");
    engine.initialize().await.expect("engine initializes");
    engine
}

async fn build_engine() -> Arc<PolicyEngine> {
    build_engine_with("Authorization", 300).await
}

fn build_payload(
    inbound: String,
    target: &str,
    audience: &str,
    perms: &[&str],
) -> DelegationPayload {
    DelegationPayload::new(inbound, target)
        .with_target_type(TargetType::Tool)
        .with_target_audience(audience)
        .with_required_permissions(perms.iter().map(|s| s.to_string()).collect())
        .with_auth_enforced_by(AuthEnforcedBy::Target)
        .with_route_attenuation(AttenuationConfig {
            capabilities: vec!["audit".into()],
            resource_template: None,
            actions: Vec::new(),
            ttl_seconds: Some(120),
        })
}

async fn invoke(engine: &Arc<PolicyEngine>, payload: DelegationPayload) -> PipelineResult {
    let (result, _bg) = engine
        .invoke_named::<TokenDelegateHook>(
            HOOK_TOKEN_DELEGATE,
            payload,
            Extensions::default(),
            None,
        )
        .await;
    result
}

/// Pull the `check if time($t), $t <= N` bound out of a block's
/// printed Datalog.
fn expiry_bound(block_source: &str) -> i64 {
    let marker = "$t <= ";
    let start = block_source
        .find(marker)
        .expect("delegation block carries a time-bound check")
        + marker.len();
    let digits: String = block_source[start..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().expect("time bound is an integer")
}

// =====================================================================
// Scenarios
// =====================================================================

/// Happy path: inbound biscuit + delegation request → attenuated
/// biscuit that still verifies against the root key and carries
/// the expected facts/checks in the new block.
#[tokio::test]
async fn happy_path_attenuates_biscuit() {
    let inbound = mint_inbound_biscuit(
        r#"
        right("read");
        right("audit");
        "#,
    );

    let engine = build_engine().await;
    let payload = build_payload(
        inbound.clone(),
        "get_compensation",
        "https://hr.example.com",
        &["read"],
    );

    let result = invoke(&engine, payload).await;
    assert!(
        result.continue_processing,
        "happy path should mint a token: violation = {:?}",
        result.violation,
    );

    let final_payload = DelegationPayload::from_pipeline_result(&result)
        .expect("delegation payload should be present");
    let minted = final_payload
        .delegated_token
        .as_ref()
        .expect("delegated_token populated");

    assert_eq!(minted.audience, "https://hr.example.com");
    assert_eq!(minted.outbound_header, "Authorization");
    // The minted bytes are a NEW (longer) biscuit — appending a
    // block grows the serialized form.
    assert_ne!(&*minted.token, &inbound);
    assert!(minted.token.len() > inbound.len());

    // Verify the chain: the attenuated biscuit must still validate
    // against our root public key.
    let attenuated = Biscuit::from_base64(&*minted.token, roots().keypair.public())
        .expect("attenuated biscuit verifies against root");

    // The new biscuit should have one more block than the original.
    let original =
        Biscuit::from_base64(&inbound, roots().keypair.public()).expect("inbound verifies");
    assert_eq!(attenuated.block_count(), original.block_count() + 1);

    // Authorize against the matching operation — should succeed
    // because the delegation block adds `check if operation("read")`
    // and the verifier provides that fact. The Datalog `time(...)`
    // fact must be in the past relative to our `check if time(...)
    // <= expires_at` predicate, so we pick a tiny value.
    let mut authorizer = AuthorizerBuilder::new()
        .code(r#"operation("read"); time(0); allow if true;"#)
        .expect("authorizer policy parses")
        .build(&attenuated)
        .expect("authorizer builds against attenuated biscuit");
    authorizer
        .authorize()
        .expect("authorizer should allow with matching operation");

    // Mode = OnBehalfOfUser per the biscuit attenuation convention.
    assert!(matches!(
        final_payload.delegation_mode,
        Some(DelegationMode::OnBehalfOfUser),
    ));

    // Metadata records the delegator family — useful for audit.
    assert_eq!(
        final_payload.metadata.get("delegator"),
        Some(&json!("biscuit")),
    );
}

/// Verifier presents a non-matching operation → the
/// `check if operation("read")` from our delegation block fails
/// → authorizer denies. Pins the scope-narrowing invariant: the
/// downstream service can't use the minted token for operations
/// it wasn't granted.
#[tokio::test]
async fn attenuated_token_denies_wrong_operation() {
    let inbound = mint_inbound_biscuit(r#"right("read");"#);
    let engine = build_engine().await;
    let payload = build_payload(
        inbound,
        "get_compensation",
        "https://hr.example.com",
        &["read"],
    );

    let result = invoke(&engine, payload).await;
    assert!(result.continue_processing);
    let final_payload = DelegationPayload::from_pipeline_result(&result).unwrap();
    let minted = final_payload.delegated_token.as_ref().unwrap();

    let attenuated = Biscuit::from_base64(&*minted.token, roots().keypair.public()).unwrap();
    // Verifier presents `operation("write")` — should fail because
    // our delegation block checks for `operation("read")`.
    let mut authorizer = AuthorizerBuilder::new()
        .code(r#"operation("write"); time(0); allow if true;"#)
        .unwrap()
        .build(&attenuated)
        .unwrap();
    let res = authorizer.authorize();
    assert!(
        res.is_err(),
        "attenuated token should deny `write` when delegation only allows `read`",
    );
}

/// Inbound biscuit signed by a DIFFERENT root key than our config
/// trusts → verification fails at parse time → `delegation.token_invalid`.
#[tokio::test]
async fn wrong_root_key_rejects() {
    // Mint with a foreign keypair — NOT the one our delegator trusts.
    let foreign = KeyPair::new();
    let foreign_biscuit = Biscuit::builder()
        .merge(BlockBuilder::new().code(r#"right("read");"#).unwrap())
        .build(&foreign)
        .unwrap()
        .to_base64()
        .unwrap();

    let engine = build_engine().await;
    let payload = build_payload(
        foreign_biscuit,
        "tool",
        "https://downstream.example.com",
        &["read"],
    );

    let result = invoke(&engine, payload).await;
    assert!(!result.continue_processing);
    let v = result.violation.expect("rejection should surface");
    assert_eq!(v.code, "delegation.token_invalid");
}

/// Empty bearer token → fast-fail input validation, no biscuit
/// parsing attempted.
#[tokio::test]
async fn empty_bearer_token_rejects() {
    let engine = build_engine().await;
    let payload =
        DelegationPayload::new("", "tool").with_target_audience("https://downstream.example.com");

    let result = invoke(&engine, payload).await;
    assert!(!result.continue_processing);
    let v = result.violation.expect("rejection should surface");
    assert_eq!(v.code, "delegation.bad_request");
    assert!(v.reason.contains("empty bearer_token"));
}

/// Missing target audience — biscuit attenuation needs an audience
/// to scope the delegation block.
#[tokio::test]
async fn missing_audience_rejects() {
    let inbound = mint_inbound_biscuit(r#"right("read");"#);
    let engine = build_engine().await;
    let payload = DelegationPayload::new(inbound, "tool"); // no audience

    let result = invoke(&engine, payload).await;
    assert!(!result.continue_processing);
    let v = result.violation.expect("rejection should surface");
    assert_eq!(v.code, "delegation.bad_request");
    assert!(v.reason.contains("target_audience"));
}

/// Garbage (non-biscuit) bearer token → parse / verify fails →
/// `delegation.token_invalid`.
#[tokio::test]
async fn malformed_bearer_token_rejects() {
    let engine = build_engine().await;
    let payload = build_payload(
        "this-is-not-a-biscuit".to_string(),
        "tool",
        "https://downstream.example.com",
        &["read"],
    );

    let result = invoke(&engine, payload).await;
    assert!(!result.continue_processing);
    let v = result.violation.expect("rejection should surface");
    assert_eq!(v.code, "delegation.token_invalid");
}

/// The appended delegation block's caveats follow the config and the
/// request: the block names the target and audience, checks each
/// required permission, and bounds time at the shorter of the
/// configured default TTL and the route hint. The minted token uses
/// the configured outbound header.
#[tokio::test]
async fn delegation_block_caveats_match_config() {
    let inbound = mint_inbound_biscuit(r#"right("read"); right("write");"#);
    // Default TTL (60s) is shorter than the route hint (120s), so
    // the configured default wins.
    let engine = build_engine_with("X-AIP-Token", 60).await;
    let payload = build_payload(
        inbound,
        "get_compensation",
        "https://hr.example.com",
        &["read", "write"],
    );

    let before = Utc::now().timestamp();
    let result = invoke(&engine, payload).await;
    let after = Utc::now().timestamp();
    assert!(
        result.continue_processing,
        "delegation should succeed: violation = {:?}",
        result.violation,
    );

    let final_payload = DelegationPayload::from_pipeline_result(&result).unwrap();
    let minted = final_payload.delegated_token.as_ref().unwrap();
    assert_eq!(minted.outbound_header, "X-AIP-Token");
    assert_eq!(minted.scopes, vec!["read", "write", "audit"]);

    let attenuated = Biscuit::from_base64(&*minted.token, roots().keypair.public()).unwrap();
    let last = attenuated.block_count() - 1;
    let block = attenuated
        .print_block_source(last)
        .expect("delegation block prints");

    assert!(
        block.contains(r#"delegated_to("get_compensation");"#),
        "{block}"
    );
    assert!(
        block.contains(r#"audience("https://hr.example.com");"#),
        "{block}"
    );
    assert!(block.contains(r#"check if operation("read");"#), "{block}");
    assert!(block.contains(r#"check if operation("write");"#), "{block}");
    // Route capabilities are recorded as token scopes, not caveats.
    assert!(!block.contains(r#"operation("audit")"#), "{block}");

    let bound = expiry_bound(&block);
    assert!(
        (before + 60..=after + 60).contains(&bound),
        "time bound {bound} should be now + 60s (window {before}..={after})",
    );

    // A verifier past the bound is denied by the time caveat.
    let mut late = AuthorizerBuilder::new()
        .code(format!(
            r#"operation("read"); operation("write"); time({}); allow if true;"#,
            bound + 1
        ))
        .unwrap()
        .build(&attenuated)
        .unwrap();
    assert!(
        late.authorize().is_err(),
        "token must be unusable past its time bound",
    );
}

/// A root key that is not a valid Ed25519 public key fails at plugin
/// construction, so the config never loads, and the error names the
/// plugin and the offending field.
#[tokio::test]
async fn invalid_root_key_fails_plugin_initialization() {
    for (bad_hex, expect) in [
        ("deadbeef", "32 bytes"),
        ("not-hex-at-all", "isn't valid hex"),
    ] {
        let Err(err) = load_engine(&config_yaml(bad_hex, "Authorization", 300)) else {
            panic!("an invalid root key must fail to load ({bad_hex})");
        };
        let msg = err.to_string();
        assert!(
            matches!(*err, PluginError::Config { .. }),
            "expected a config error, got {err:?}",
        );
        assert!(msg.contains("biscuit-delegator"), "names the plugin: {msg}");
        assert!(msg.contains("root_public_key"), "names the field: {msg}");
        assert!(msg.contains(expect), "explains the fault: {msg}");
    }
}
