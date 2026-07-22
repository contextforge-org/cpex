// Location: ./crates/cpex-core/tests/delegation_e2e.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// End-to-end test for the TokenDelegate hook family.
//
// Verifies the host-explicit dispatch model: an outbound caller
// (typically a forwarding-proxy plugin) constructs a
// `DelegationPayload`, calls
// `mgr.invoke_named::<TokenDelegateHook>(...)`, and reads the
// minted credential out of the returned `PipelineResult`. No
// bespoke method on `PluginManager` — `invoke_named` works
// uniformly because Sequential-phase threading already does the
// right thing for the unified `DelegationPayload`.
//
// Tests cover:
//   - Single-handler mint: one plugin produces a `RawDelegatedToken`.
//   - Two-handler chain: handler A declines (`delegated_token == None`),
//     handler B mints — proves Sequential-phase threading carries
//     A's null contribution into B's input.
//   - Rejection: handler returns `deny()`; pipeline halts.
//   - `from_pipeline_result` returns `None` on deny.
//   - Full host flow: invoke delegate, apply to Extensions, observe
//     `Extensions.raw_credentials.delegated_tokens` populated under
//     the synthesized `DelegationKey`.

use std::sync::Arc;

use async_trait::async_trait;

use chrono::{Duration as ChronoDuration, Utc};

use cpex_core::context::PluginContext;
use cpex_core::delegation::{
    AttenuationConfig, AuthEnforcedBy, DelegationPayload, TargetType, TokenDelegateHook,
    HOOK_TOKEN_DELEGATE,
};
use cpex_core::error::PluginError;
use cpex_core::extensions::raw_credentials::{DelegationKey, DelegationMode, RawDelegatedToken};
use cpex_core::extensions::{SecurityExtension, SubjectExtension};
use cpex_core::hooks::payload::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::manager::PluginManager;
use cpex_core::plugin::{OnError, Plugin, PluginConfig, PluginMode};

// =====================================================================
// Plugin fixtures
// =====================================================================

/// Minimal RFC-8693-style stub. Doesn't actually exchange anything
/// — just constructs a `RawDelegatedToken` by combining the caller's
/// bearer token with the target audience. Real handlers would call
/// out to an IdP; we only care about wiring here.
struct StubExchanger {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for StubExchanger {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<TokenDelegateHook> for StubExchanger {
    async fn handle(
        &self,
        payload: &DelegationPayload,
        _ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<DelegationPayload> {
        assert!(
            !payload.bearer_token().is_empty(),
            "exchanger expected non-empty bearer token",
        );

        // Use the route's TTL hint if present; otherwise default to
        // 300s. Real handlers would also take min(route_hint,
        // idp_response_expires_in).
        let ttl_secs = payload
            .route_attenuation()
            .and_then(|a| a.ttl_seconds)
            .unwrap_or(300);
        let audience = payload
            .target_audience()
            .unwrap_or("https://example.com/default")
            .to_string();
        // Effective scopes: combine route-attenuation capabilities
        // with required_permissions. Real exchangers may narrow
        // further based on the IdP's response.
        let mut scopes = payload.required_permissions().to_vec();
        if let Some(att) = payload.route_attenuation() {
            for cap in &att.capabilities {
                if !scopes.contains(cap) {
                    scopes.push(cap.clone());
                }
            }
        }

        let minted = RawDelegatedToken::new(
            format!("stub-exchanged({})", payload.bearer_token()),
            "Authorization",
            audience,
            scopes,
            Utc::now() + ChronoDuration::seconds(ttl_secs as i64),
        );
        let mut updated = payload.clone();
        updated.delegated_token = Some(minted);
        updated.minted_at = Some(Utc::now());
        PluginResult::modify_payload(updated)
    }
}

/// A handler that always declines — leaves `delegated_token` as
/// `None`. Used to verify chaining: in a chain with a declining
/// primary + a minting fallback, the fallback should see the
/// declined state and mint.
struct DecliningHandler {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for DecliningHandler {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<TokenDelegateHook> for DecliningHandler {
    async fn handle(
        &self,
        payload: &DelegationPayload,
        _ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<DelegationPayload> {
        // Returns the payload unchanged — leaves output slots None,
        // signals "this handler had nothing to contribute."
        let mut updated = payload.clone();
        updated
            .metadata
            .insert("declined_by".into(), serde_json::json!("declining-handler"));
        PluginResult::modify_payload(updated)
    }
}

/// Fallback minter — runs after a declining handler. Asserts that
/// the prior handler's `metadata` contribution survived through
/// Sequential-phase threading (i.e. we see "declined_by") and
/// produces a token in spite of the prior decline.
struct FallbackMinter {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for FallbackMinter {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<TokenDelegateHook> for FallbackMinter {
    async fn handle(
        &self,
        payload: &DelegationPayload,
        _ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<DelegationPayload> {
        assert!(
            payload.delegated_token.is_none(),
            "fallback minter expected no prior token in chain test",
        );
        assert!(
            payload.metadata.contains_key("declined_by"),
            "fallback minter expected prior handler's metadata in chain",
        );
        let mut updated = payload.clone();
        updated.delegated_token = Some(RawDelegatedToken::new(
            "fallback-token",
            "Authorization",
            payload
                .target_audience()
                .unwrap_or("https://fallback.example.com")
                .to_string(),
            vec!["read".into()],
            Utc::now() + ChronoDuration::seconds(60),
        ));
        PluginResult::modify_payload(updated)
    }
}

/// Handler that rejects unconditionally. Used to verify the
/// rejection path through `PluginResult::deny`.
struct RejectingHandler {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for RejectingHandler {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<TokenDelegateHook> for RejectingHandler {
    async fn handle(
        &self,
        _payload: &DelegationPayload,
        _ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<DelegationPayload> {
        PluginResult::deny(cpex_core::error::PluginViolation::new(
            "delegation.scope_too_broad",
            "requested scopes exceed inbound credential's authorization",
        ))
    }
}

// =====================================================================
// Helpers
// =====================================================================

fn config(name: &str, priority: i32) -> PluginConfig {
    PluginConfig {
        name: name.to_string(),
        kind: "test".to_string(),
        description: None,
        author: None,
        version: None,
        hooks: vec![HOOK_TOKEN_DELEGATE.to_string()],
        mode: PluginMode::Sequential,
        priority,
        on_error: OnError::Fail,
        capabilities: Default::default(),
        tags: Vec::new(),
        conditions: Vec::new(),
        config: None,
    }
}

/// Build the kind of payload a forwarding-proxy plugin would construct
/// just before making a downstream call.
fn build_payload(target: &str, audience: &str, permissions: &[&str]) -> DelegationPayload {
    DelegationPayload::new("eyJ.caller.tok", target)
        .with_target_type(TargetType::Tool)
        .with_target_audience(audience)
        .with_required_permissions(permissions.iter().map(|s| s.to_string()).collect())
        .with_auth_enforced_by(AuthEnforcedBy::Target)
        .with_route_attenuation(AttenuationConfig {
            capabilities: vec!["audit".into()],
            resource_template: Some("hr://employees/{{ args.id }}".into()),
            actions: vec!["read".into()],
            ttl_seconds: Some(120),
        })
}

fn extract_delegation(result: &cpex_core::executor::PipelineResult) -> DelegationPayload {
    DelegationPayload::from_pipeline_result(result)
        .expect("PipelineResult had no DelegationPayload — denied or wrong hook type")
}

// =====================================================================
// Scenarios
// =====================================================================

/// Single handler runs, mints a `RawDelegatedToken`. Host receives
/// the populated payload via `from_pipeline_result`.
#[tokio::test]
async fn single_handler_mints_token() {
    let mgr = Arc::new(PluginManager::default());
    let cfg = config("stub-exchanger", 10);
    let plugin = Arc::new(StubExchanger { cfg: cfg.clone() });
    mgr.register_handler_for_names::<TokenDelegateHook, _>(plugin, cfg, &[HOOK_TOKEN_DELEGATE])
        .unwrap();
    mgr.initialize().await.unwrap();

    let (result, _bg) = mgr
        .invoke_named::<TokenDelegateHook>(
            HOOK_TOKEN_DELEGATE,
            build_payload(
                "get_compensation",
                "https://hr.example.com",
                &["read:compensation"],
            ),
            Extensions::default(),
            None,
        )
        .await;
    assert!(result.continue_processing);

    let final_payload = extract_delegation(&result);
    let token = final_payload
        .delegated_token
        .as_ref()
        .expect("handler should have minted a token");

    assert_eq!(token.audience, "https://hr.example.com");
    assert_eq!(token.outbound_header, "Authorization");
    assert!(token.scopes.contains(&"read:compensation".to_string()));
    // Route attenuation contributed `audit` capability.
    assert!(token.scopes.contains(&"audit".to_string()));
    // TTL respects the route hint (120s) — token must expire in
    // roughly 120s, not 300s default.
    let ttl_left = (token.expires_at - Utc::now()).num_seconds();
    assert!(
        ttl_left <= 120 && ttl_left > 100,
        "token TTL should reflect route hint (~120s); got {}s",
        ttl_left,
    );
    // Input fields preserved through clone.
    assert_eq!(final_payload.bearer_token(), "eyJ.caller.tok");
    assert_eq!(final_payload.target_name(), "get_compensation");
}

/// Two-handler chain: declining primary + minting fallback. Proves
/// Sequential-phase threading carries the declining handler's
/// metadata contribution into the fallback handler, and that the
/// fallback's output replaces the lack of a token from the primary.
#[tokio::test]
async fn declining_then_fallback_chain_mints_token() {
    let mgr = Arc::new(PluginManager::default());

    let declining_cfg = config("declining-handler", 10);
    let declining = Arc::new(DecliningHandler {
        cfg: declining_cfg.clone(),
    });
    mgr.register_handler_for_names::<TokenDelegateHook, _>(
        declining,
        declining_cfg,
        &[HOOK_TOKEN_DELEGATE],
    )
    .unwrap();

    let fallback_cfg = config("fallback-minter", 20);
    let fallback = Arc::new(FallbackMinter {
        cfg: fallback_cfg.clone(),
    });
    mgr.register_handler_for_names::<TokenDelegateHook, _>(
        fallback,
        fallback_cfg,
        &[HOOK_TOKEN_DELEGATE],
    )
    .unwrap();

    mgr.initialize().await.unwrap();

    let (result, _bg) = mgr
        .invoke_named::<TokenDelegateHook>(
            HOOK_TOKEN_DELEGATE,
            build_payload(
                "downstream-tool",
                "https://downstream.example.com",
                &["read"],
            ),
            Extensions::default(),
            None,
        )
        .await;
    assert!(result.continue_processing);

    let final_payload = extract_delegation(&result);
    // Fallback minted a token.
    let token = final_payload
        .delegated_token
        .as_ref()
        .expect("fallback should have minted");
    assert_eq!(&*token.token, "fallback-token");
    // Declining handler's metadata survived.
    assert_eq!(
        final_payload.metadata.get("declined_by"),
        Some(&serde_json::json!("declining-handler")),
    );
}

/// Rejecting handler short-circuits via `PluginResult::deny`. Pipeline
/// halts; violation surfaces in `PipelineResult.violation`.
#[tokio::test]
async fn rejecting_handler_halts_pipeline() {
    let mgr = Arc::new(PluginManager::default());
    let cfg = config("rejecting-handler", 10);
    let plugin = Arc::new(RejectingHandler { cfg: cfg.clone() });
    mgr.register_handler_for_names::<TokenDelegateHook, _>(plugin, cfg, &[HOOK_TOKEN_DELEGATE])
        .unwrap();
    mgr.initialize().await.unwrap();

    let (result, _bg) = mgr
        .invoke_named::<TokenDelegateHook>(
            HOOK_TOKEN_DELEGATE,
            build_payload("tool", "https://aud.example.com", &["read"]),
            Extensions::default(),
            None,
        )
        .await;
    assert!(!result.continue_processing);
    // from_pipeline_result returns None on deny — host's signal that
    // no token was minted.
    assert!(DelegationPayload::from_pipeline_result(&result).is_none());
    let violation = result.violation.expect("rejection should surface");
    assert_eq!(violation.code, "delegation.scope_too_broad");
}

/// Full host-side flow: a request already has a resolved subject in
/// `Extensions.security.subject` (from a prior IdentityResolve pass);
/// the outbound forwarding plugin invokes TokenDelegate; the host
/// applies the result back to Extensions; the minted token now lives
/// in `Extensions.raw_credentials.delegated_tokens` keyed by a
/// `DelegationKey` that incorporates the subject id.
#[tokio::test]
async fn apply_to_extensions_writes_delegated_token_keyed_by_subject() {
    let mgr = Arc::new(PluginManager::default());
    let cfg = config("stub-exchanger", 10);
    let plugin = Arc::new(StubExchanger { cfg: cfg.clone() });
    mgr.register_handler_for_names::<TokenDelegateHook, _>(plugin, cfg, &[HOOK_TOKEN_DELEGATE])
        .unwrap();
    mgr.initialize().await.unwrap();

    // Initial extensions: identity has already populated subject.
    let initial_ext = Extensions {
        security: Some(Arc::new(SecurityExtension {
            subject: Some(SubjectExtension {
                id: Some("alice@corp.com".into()),
                ..Default::default()
            }),
            ..Default::default()
        })),
        ..Default::default()
    };

    let (result, _bg) = mgr
        .invoke_named::<TokenDelegateHook>(
            HOOK_TOKEN_DELEGATE,
            build_payload(
                "get_compensation",
                "https://hr.example.com",
                &["read:compensation"],
            ),
            initial_ext.clone(),
            None,
        )
        .await;
    assert!(result.continue_processing);

    let delegation = extract_delegation(&result);
    let updated_ext = delegation.apply_to_extensions(initial_ext);

    // Minted token now lives in Extensions.raw_credentials.delegated_tokens.
    let raw = updated_ext
        .raw_credentials
        .as_ref()
        .expect("raw_credentials slot populated");
    assert_eq!(raw.delegated_tokens.len(), 1);

    // The key is synthesized from (subject.id, audience, scopes, mode).
    let expected_key = DelegationKey {
        subject_id: "alice@corp.com".into(),
        audience: "https://hr.example.com".into(),
        // Order matches what StubExchanger produces (required_permissions
        // first, then attenuation capabilities).
        scopes: vec!["read:compensation".into(), "audit".into()],
        mode: DelegationMode::OnBehalfOfUser,
    };
    assert!(
        raw.delegated_tokens.contains_key(&expected_key),
        "delegated_tokens missing expected key; saw keys: {:?}",
        raw.delegated_tokens.keys().collect::<Vec<_>>(),
    );

    // Subject from the prior identity pass survived apply.
    let sec = updated_ext.security.as_ref().unwrap();
    assert_eq!(
        sec.subject.as_ref().unwrap().id.as_deref(),
        Some("alice@corp.com"),
    );
}

/// Load-bearing integration test: the full host flow from token
/// delegation through downstream CMF dispatch correctly cap-gates
/// the `delegated_tokens` slot.
///
/// Mirrors the `cap_gating_post_apply_through_cmf_dispatch`
/// test but for the *outbound* leg:
///   1. TokenDelegate handler mints a downstream credential.
///   2. Host applies the resolved payload back to `Extensions` via
///      `apply_to_extensions` — the minted token lands in
///      `Extensions.raw_credentials.delegated_tokens`.
///   3. Host invokes `cmf.tool_pre_invoke` (the next outbound step,
///      typically where a forwarding proxy attaches the credential).
///      Two registered CMF plugins:
///        - `DelegatedTokenReader` declares `read_delegated_tokens`
///          — must observe one minted token.
///        - `DelegatedTokenBlind` declares no credential capability
///          — must observe `raw_credentials == None` because
///          `filter_extensions` strips the slot.
///
/// Validates the symmetric story to identity's `read_inbound_credentials`
/// gating: only forwarding plugins (audit-trail consumers, proxies)
/// that explicitly declare the cap can see the minted credentials.
#[tokio::test]
async fn cap_gating_post_apply_through_cmf_dispatch() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use cpex_core::cmf::enums::Role;
    use cpex_core::cmf::{CmfHook, Message, MessagePayload};

    // ----- CMF plugin WITH read_delegated_tokens -----
    struct DelegatedTokenReader {
        cfg: PluginConfig,
        saw_token_count: Arc<AtomicUsize>,
    }
    #[async_trait]
    impl Plugin for DelegatedTokenReader {
        fn config(&self) -> &PluginConfig {
            &self.cfg
        }
    }
    impl HookHandler<CmfHook> for DelegatedTokenReader {
        async fn handle(
            &self,
            _payload: &MessagePayload,
            ext: &Extensions,
            _ctx: &mut PluginContext,
        ) -> PluginResult<MessagePayload> {
            let n = ext
                .raw_credentials
                .as_ref()
                .map(|r| r.delegated_tokens.len())
                .unwrap_or(0);
            self.saw_token_count.store(n, Ordering::SeqCst);
            PluginResult::allow()
        }
    }

    // ----- CMF plugin WITHOUT credential caps -----
    struct DelegatedTokenBlind {
        cfg: PluginConfig,
        saw_any: Arc<AtomicBool>,
    }
    #[async_trait]
    impl Plugin for DelegatedTokenBlind {
        fn config(&self) -> &PluginConfig {
            &self.cfg
        }
    }
    impl HookHandler<CmfHook> for DelegatedTokenBlind {
        async fn handle(
            &self,
            _payload: &MessagePayload,
            ext: &Extensions,
            _ctx: &mut PluginContext,
        ) -> PluginResult<MessagePayload> {
            self.saw_any
                .store(ext.raw_credentials.is_some(), Ordering::SeqCst);
            PluginResult::allow()
        }
    }

    // ----- Wire everything up -----
    let mgr = Arc::new(PluginManager::default());

    // TokenDelegate handler.
    let td_cfg = config("stub-exchanger", 10);
    let td_plugin = Arc::new(StubExchanger {
        cfg: td_cfg.clone(),
    });
    mgr.register_handler_for_names::<TokenDelegateHook, _>(
        td_plugin,
        td_cfg,
        &[HOOK_TOKEN_DELEGATE],
    )
    .unwrap();

    // CMF reader — declares read_delegated_tokens. Also declares
    // read_subject so the handler can verify subject still visible
    // through the request lifecycle.
    let reader_saw_count = Arc::new(AtomicUsize::new(usize::MAX));
    let reader_cfg = PluginConfig {
        name: "delegated-reader".into(),
        kind: "test".into(),
        description: None,
        author: None,
        version: None,
        hooks: vec!["cmf.tool_pre_invoke".into()],
        mode: PluginMode::Sequential,
        priority: 10,
        on_error: OnError::Fail,
        capabilities: ["read_delegated_tokens", "read_subject"]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        tags: Vec::new(),
        conditions: Vec::new(),
        config: None,
    };
    mgr.register_handler_for_names::<CmfHook, _>(
        Arc::new(DelegatedTokenReader {
            cfg: reader_cfg.clone(),
            saw_token_count: Arc::clone(&reader_saw_count),
        }),
        reader_cfg,
        &["cmf.tool_pre_invoke"],
    )
    .unwrap();

    // CMF blind — no cred caps.
    let blind_saw = Arc::new(AtomicBool::new(false));
    let blind_cfg = PluginConfig {
        name: "delegated-blind".into(),
        kind: "test".into(),
        description: None,
        author: None,
        version: None,
        hooks: vec!["cmf.tool_pre_invoke".into()],
        mode: PluginMode::Sequential,
        priority: 20,
        on_error: OnError::Fail,
        capabilities: Default::default(),
        tags: Vec::new(),
        conditions: Vec::new(),
        config: None,
    };
    mgr.register_handler_for_names::<CmfHook, _>(
        Arc::new(DelegatedTokenBlind {
            cfg: blind_cfg.clone(),
            saw_any: Arc::clone(&blind_saw),
        }),
        blind_cfg,
        &["cmf.tool_pre_invoke"],
    )
    .unwrap();

    mgr.initialize().await.unwrap();

    // ----- Host flow -----
    // 1. Initial Extensions has a subject (typically from a prior
    //    IdentityResolve pass).
    let initial_ext = Extensions {
        security: Some(Arc::new(SecurityExtension {
            subject: Some(SubjectExtension {
                id: Some("alice@corp.com".into()),
                ..Default::default()
            }),
            ..Default::default()
        })),
        ..Default::default()
    };

    // 2. Token delegation.
    let (td_result, _bg) = mgr
        .invoke_named::<TokenDelegateHook>(
            HOOK_TOKEN_DELEGATE,
            build_payload(
                "get_compensation",
                "https://hr.example.com",
                &["read:compensation"],
            ),
            initial_ext.clone(),
            None,
        )
        .await;
    assert!(td_result.continue_processing);
    let delegation =
        DelegationPayload::from_pipeline_result(&td_result).expect("delegation should have minted");

    // 3. Apply.
    let updated_ext = delegation.apply_to_extensions(initial_ext);

    // 4. Dispatch through CMF.
    let cmf_payload = MessagePayload {
        message: Message::text(Role::User, "fetch compensation"),
    };
    let (cmf_result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", cmf_payload, updated_ext, None)
        .await;
    assert!(
        cmf_result.continue_processing,
        "CMF dispatch should not be blocked: violation = {:?}",
        cmf_result.violation,
    );

    // ----- Verifications -----
    // Plugin with cap saw the minted token.
    assert_eq!(
        reader_saw_count.load(Ordering::SeqCst),
        1,
        "DelegatedTokenReader with read_delegated_tokens should see 1 token",
    );
    // Plugin without cap saw no raw_credentials at all.
    assert!(
        !blind_saw.load(Ordering::SeqCst),
        "DelegatedTokenBlind without credential caps must NOT see raw_credentials",
    );
}

// PluginError kept imported so a future test wanting to assert on a
// specific error variant can use it without an extra `use` line.
#[allow(dead_code)]
fn _force_plugin_error_link(_e: PluginError) {}
