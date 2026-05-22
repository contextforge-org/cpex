// Location: ./crates/apl-delegator-biscuit/tests/biscuit_e2e.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// End-to-end tests for `BiscuitDelegator`. Generates a root keypair
// in-process, mints an authority-only biscuit (the "inbound"), runs
// the delegator's `handle()`, and verifies that the resulting
// attenuated biscuit is well-formed: the root key still verifies
// the chain, and the new delegation block carries the expected
// `delegated_to` / `audience` / `operation` checks.

use std::sync::Arc;

use biscuit_auth::{
    builder::{AuthorizerBuilder, BlockBuilder},
    Biscuit, KeyPair,
};

use cpex_core::delegation::{
    AttenuationConfig, AuthEnforcedBy, DelegationPayload, TargetType, TokenDelegateHook,
    HOOK_TOKEN_DELEGATE,
};
use cpex_core::extensions::raw_credentials::DelegationMode;
use cpex_core::hooks::payload::Extensions;
use cpex_core::manager::PluginManager;
use cpex_core::plugin::{OnError, PluginConfig, PluginMode};

use apl_delegator_biscuit::BiscuitDelegator;

use serde_json::json;

// =====================================================================
// Fixtures
// =====================================================================

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

fn plugin_config() -> PluginConfig {
    let pub_hex = hex::encode(roots().keypair.public().to_bytes());
    PluginConfig {
        name: "biscuit-delegator".into(),
        kind: "test".into(),
        hooks: vec![HOOK_TOKEN_DELEGATE.into()],
        mode: PluginMode::Sequential,
        priority: 10,
        on_error: OnError::Fail,
        config: Some(json!({
            "root_public_key": { "kind": "hex", "hex": pub_hex },
            "default_outbound_header": "Authorization",
            "default_ttl_seconds": 300,
        })),
        ..Default::default()
    }
}

async fn build_manager() -> Arc<PluginManager> {
    let cfg = plugin_config();
    let delegator = BiscuitDelegator::new(cfg.clone()).expect("delegator constructs");
    let mgr = Arc::new(PluginManager::default());
    mgr.register_handler_for_names::<TokenDelegateHook, _>(
        Arc::new(delegator),
        cfg,
        &[HOOK_TOKEN_DELEGATE],
    )
    .unwrap();
    mgr.initialize().await.unwrap();
    mgr
}

fn build_payload(inbound: String, target: &str, audience: &str, perms: &[&str]) -> DelegationPayload {
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

async fn invoke(
    mgr: &Arc<PluginManager>,
    payload: DelegationPayload,
) -> cpex_core::executor::PipelineResult {
    let (result, _bg) = mgr
        .invoke_named::<TokenDelegateHook>(
            HOOK_TOKEN_DELEGATE,
            payload,
            Extensions::default(),
            None,
        )
        .await;
    result
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

    let mgr = build_manager().await;
    let payload = build_payload(
        inbound.clone(),
        "get_compensation",
        "https://hr.example.com",
        &["read"],
    );

    let result = invoke(&mgr, payload).await;
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
    let original = Biscuit::from_base64(&inbound, roots().keypair.public())
        .expect("inbound verifies");
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
    let mgr = build_manager().await;
    let payload = build_payload(
        inbound,
        "get_compensation",
        "https://hr.example.com",
        &["read"],
    );

    let result = invoke(&mgr, payload).await;
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

    let mgr = build_manager().await;
    let payload = build_payload(
        foreign_biscuit,
        "tool",
        "https://downstream.example.com",
        &["read"],
    );

    let result = invoke(&mgr, payload).await;
    assert!(!result.continue_processing);
    let v = result.violation.expect("rejection should surface");
    assert_eq!(v.code, "delegation.token_invalid");
}

/// Empty bearer token → fast-fail input validation, no biscuit
/// parsing attempted.
#[tokio::test]
async fn empty_bearer_token_rejects() {
    let mgr = build_manager().await;
    let payload = DelegationPayload::new("", "tool")
        .with_target_audience("https://downstream.example.com");

    let result = invoke(&mgr, payload).await;
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
    let mgr = build_manager().await;
    let payload = DelegationPayload::new(inbound, "tool"); // no audience

    let result = invoke(&mgr, payload).await;
    assert!(!result.continue_processing);
    let v = result.violation.expect("rejection should surface");
    assert_eq!(v.code, "delegation.bad_request");
    assert!(v.reason.contains("target_audience"));
}

/// Garbage (non-biscuit) bearer token → parse / verify fails →
/// `delegation.token_invalid`.
#[tokio::test]
async fn malformed_bearer_token_rejects() {
    let mgr = build_manager().await;
    let payload = build_payload(
        "this-is-not-a-biscuit".to_string(),
        "tool",
        "https://downstream.example.com",
        &["read"],
    );

    let result = invoke(&mgr, payload).await;
    assert!(!result.continue_processing);
    let v = result.violation.expect("rejection should surface");
    assert_eq!(v.code, "delegation.token_invalid");
}
