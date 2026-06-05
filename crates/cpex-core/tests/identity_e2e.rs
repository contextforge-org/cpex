// Location: ./crates/cpex-core/tests/identity_e2e.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// End-to-end test for the IdentityResolve hook family — sub-step B
// of slice 2.
//
// Verifies the host-explicit dispatch model: the host constructs an
// `IdentityPayload`, calls `mgr.invoke_named::<IdentityHook>(...)`,
// and reads the populated identity slots back out of the returned
// `PipelineResult.modified_payload`. No bespoke `resolve_identity`
// method on `PluginManager` — `invoke_named` works for `IdentityHook`
// like every other hook, because Sequential-phase threading already
// does the right thing for the unified `IdentityPayload`
// (input + accumulator in one struct).
//
// Tests cover:
//   - Single-handler resolve: one plugin populates `subject`.
//   - Two-handler chain: plugin A populates `subject`, plugin B
//     receives A's output and populates `caller_workload`. Final
//     payload carries both — proves Sequential-phase threading.
//   - In-band rejection: a handler sets `rejected = true`; the
//     pipeline halts; status + reason flow back to the caller.

use std::sync::Arc;

use async_trait::async_trait;

use cpex_core::context::PluginContext;
use cpex_core::error::PluginError;
use cpex_core::extensions::{SubjectExtension, WorkloadIdentity};
use cpex_core::hooks::payload::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::identity::{IdentityHook, IdentityPayload, TokenSource, HOOK_IDENTITY_RESOLVE};
use cpex_core::manager::PluginManager;
use cpex_core::plugin::{OnError, Plugin, PluginConfig, PluginMode};

// =====================================================================
// Plugin fixtures
// =====================================================================

/// A fake JWT resolver. Doesn't actually validate anything — just
/// asserts a non-empty `raw_token()` and writes a hard-coded subject.
/// Real resolvers would parse + validate the token; for wiring tests
/// we only care that the handler receives the right payload shape
/// and that its output flows back through Sequential-phase threading.
struct SubjectResolver {
    cfg: PluginConfig,
    subject_id: String,
}

#[async_trait]
impl Plugin for SubjectResolver {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<IdentityHook> for SubjectResolver {
    async fn handle(
        &self,
        payload: &IdentityPayload,
        _ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<IdentityPayload> {
        assert!(
            !payload.raw_token().is_empty(),
            "subject resolver expected a non-empty token",
        );
        let mut updated = payload.clone();
        updated.subject = Some(SubjectExtension {
            id: Some(self.subject_id.clone()),
            ..Default::default()
        });
        PluginResult::modify_payload(updated)
    }
}

/// Workload resolver. Pulls a SPIFFE-ID out of (in real life)
/// `X-Forwarded-Client-Cert`; here we read it from the
/// `IdentityPayload.headers()` map and hand-roll a `WorkloadIdentity`.
/// Critical assertion for the chaining test: when this runs *after*
/// `SubjectResolver`, it must see `payload.subject` already populated
/// — proves Sequential-phase threading carries plugin 1's output
/// forward into plugin 2's input.
struct WorkloadResolver {
    cfg: PluginConfig,
    require_prior_subject: bool,
}

#[async_trait]
impl Plugin for WorkloadResolver {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<IdentityHook> for WorkloadResolver {
    async fn handle(
        &self,
        payload: &IdentityPayload,
        _ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<IdentityPayload> {
        if self.require_prior_subject {
            assert!(
                payload.subject.is_some(),
                "workload resolver expected prior subject in chained run",
            );
        }
        let spiffe_id = payload
            .headers()
            .get("x-spiffe-id")
            .cloned()
            .unwrap_or_else(|| "spiffe://example.com/unknown".to_string());
        let mut updated = payload.clone();
        updated.caller_workload = Some(WorkloadIdentity {
            spiffe_id: Some(spiffe_id),
            trust_domain: Some("example.com".to_string()),
            ..Default::default()
        });
        PluginResult::modify_payload(updated)
    }
}

/// Handler that always rejects. Used to verify the in-band rejection
/// pathway: setting `rejected = true` on the returned payload (and
/// using `PluginResult::deny`) must halt the pipeline.
struct RejectingResolver {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for RejectingResolver {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<IdentityHook> for RejectingResolver {
    async fn handle(
        &self,
        _payload: &IdentityPayload,
        _ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<IdentityPayload> {
        PluginResult::deny(cpex_core::error::PluginViolation::new(
            "auth.expired",
            "token expired",
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
        hooks: vec![HOOK_IDENTITY_RESOLVE.to_string()],
        mode: PluginMode::Sequential,
        priority,
        on_error: OnError::Fail,
        capabilities: Default::default(),
        tags: Vec::new(),
        conditions: Vec::new(),
        config: None,
    }
}

/// Build the payload the way a host normally would: raw token from
/// `Authorization`, headers preserved, source set. Identity handlers
/// downstream read these via the public accessors.
fn build_payload(token: &str) -> IdentityPayload {
    let mut headers = std::collections::HashMap::new();
    headers.insert(
        "authorization".to_string(),
        format!("Bearer {}", token),
    );
    headers.insert(
        "x-spiffe-id".to_string(),
        "spiffe://example.com/agent-1".to_string(),
    );
    IdentityPayload::new(token, TokenSource::Bearer)
        .with_source_header("Authorization")
        .with_headers(headers)
}

/// Shortcut around `IdentityPayload::from_pipeline_result` for tests
/// that know the result must be present and well-typed.
fn extract_identity(result: &cpex_core::executor::PipelineResult) -> IdentityPayload {
    IdentityPayload::from_pipeline_result(result)
        .expect("PipelineResult had no IdentityPayload — denied or wrong hook type")
}

// =====================================================================
// Scenarios
// =====================================================================

/// Single handler runs, populates subject. Host receives an
/// `IdentityPayload` with subject populated; input fields survive
/// the chain unchanged.
#[tokio::test]
async fn single_resolver_populates_subject() {
    let mgr = Arc::new(PluginManager::default());
    let cfg = config("subject-resolver", 10);
    let plugin = Arc::new(SubjectResolver {
        cfg: cfg.clone(),
        subject_id: "alice@corp.com".to_string(),
    });
    mgr.register_handler::<IdentityHook, _>(plugin, cfg).unwrap();
    mgr.initialize().await.unwrap();

    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            build_payload("eyJ.fake.jwt"),
            Extensions::default(),
            None,
        )
        .await;

    assert!(result.continue_processing, "pipeline should allow");
    let final_payload = extract_identity(&result);

    // Output populated by the handler.
    assert_eq!(
        final_payload.subject.as_ref().unwrap().id.as_deref(),
        Some("alice@corp.com"),
    );

    // Input fields preserved through Sequential threading + clone.
    assert_eq!(final_payload.raw_token(), "eyJ.fake.jwt");
    assert_eq!(final_payload.source_header(), Some("Authorization"));
}

/// Two handlers in priority order. Handler 1 writes subject; handler
/// 2 — running after — must see subject already populated (via the
/// `require_prior_subject` assertion in its handler). Final payload
/// carries both contributions.
///
/// This is the load-bearing test for the whole design: it proves
/// that Sequential-phase threading is exactly what the multi-handler
/// composition model needs, without any framework changes beyond
/// what already exists for CMF.
#[tokio::test]
async fn two_resolvers_chain_populates_both_slots() {
    let mgr = Arc::new(PluginManager::default());

    let subject_cfg = config("subject-resolver", 10);
    let subject = Arc::new(SubjectResolver {
        cfg: subject_cfg.clone(),
        subject_id: "alice@corp.com".to_string(),
    });
    mgr.register_handler::<IdentityHook, _>(subject, subject_cfg)
        .unwrap();

    let workload_cfg = config("workload-resolver", 20); // runs after subject
    let workload = Arc::new(WorkloadResolver {
        cfg: workload_cfg.clone(),
        require_prior_subject: true,
    });
    mgr.register_handler::<IdentityHook, _>(workload, workload_cfg)
        .unwrap();

    mgr.initialize().await.unwrap();

    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            build_payload("eyJ.fake.jwt"),
            Extensions::default(),
            None,
        )
        .await;

    assert!(result.continue_processing, "pipeline should allow");
    let final_payload = extract_identity(&result);

    // Subject from plugin 1 survived plugin 2's pass.
    assert_eq!(
        final_payload.subject.as_ref().unwrap().id.as_deref(),
        Some("alice@corp.com"),
    );

    // Workload added by plugin 2.
    let workload = final_payload
        .caller_workload
        .as_ref()
        .expect("workload resolver should have populated caller_workload");
    assert_eq!(
        workload.spiffe_id.as_deref(),
        Some("spiffe://example.com/agent-1"),
    );

    // Original input fields still intact.
    assert_eq!(final_payload.raw_token(), "eyJ.fake.jwt");
}

/// Rejecting handler short-circuits the pipeline. `continue_processing`
/// is `false`; the violation surfaces in `PipelineResult.violation`.
/// Hosts use this to skip downstream tool invocation and return
/// a 401/403 to the client.
#[tokio::test]
async fn rejecting_resolver_halts_pipeline() {
    let mgr = Arc::new(PluginManager::default());
    let cfg = config("rejecting-resolver", 10);
    let plugin = Arc::new(RejectingResolver { cfg: cfg.clone() });
    mgr.register_handler::<IdentityHook, _>(plugin, cfg).unwrap();
    mgr.initialize().await.unwrap();

    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            build_payload("eyJ.expired.jwt"),
            Extensions::default(),
            None,
        )
        .await;

    assert!(!result.continue_processing, "rejection should halt");
    let violation = result.violation.expect("rejected → violation present");
    assert_eq!(violation.code, "auth.expired");
    assert_eq!(violation.reason, "token expired");
}

/// Full host-side flow: invoke identity, apply the resolved payload
/// back to the `Extensions`, observe that the identity slots are now
/// populated on `Extensions.security.*` / `Extensions.raw_credentials`.
/// Downstream `cmf.tool_pre_invoke` would now see the resolved subject
/// — that's the whole point of having an identity hook.
///
/// Also exercises the slice-1 invariant that pre-existing security
/// fields (labels, classification) survive the apply step — the
/// host shouldn't lose its earlier annotations just because identity
/// landed.
#[tokio::test]
async fn apply_to_extensions_populates_security_and_preserves_existing_fields() {
    use cpex_core::extensions::SecurityExtension;
    use cpex_core::extensions::raw_credentials::{
        RawCredentialsExtension, RawInboundToken, TokenKind, TokenRole,
    };

    // ----- Handler: produces a subject + a RawCredentialsExtension -----
    struct FullResolver {
        cfg: PluginConfig,
    }
    #[async_trait]
    impl Plugin for FullResolver {
        fn config(&self) -> &PluginConfig {
            &self.cfg
        }
    }
    impl HookHandler<IdentityHook> for FullResolver {
        async fn handle(
            &self,
            payload: &IdentityPayload,
            _ext: &Extensions,
            _ctx: &mut PluginContext,
        ) -> PluginResult<IdentityPayload> {
            let token_bytes = payload.raw_token().to_string();
            let mut updated = payload.clone();
            updated.subject = Some(SubjectExtension {
                id: Some("alice@corp.com".into()),
                ..Default::default()
            });
            // Stash the validated token under TokenRole::User so a
            // forwarding plugin can re-attach it later.
            let mut raw = RawCredentialsExtension::default();
            raw.inbound_tokens.insert(
                TokenRole::User,
                RawInboundToken::new(token_bytes, "Authorization", TokenKind::Jwt),
            );
            updated.raw_credentials = Some(raw);
            PluginResult::modify_payload(updated)
        }
    }

    let mgr = Arc::new(PluginManager::default());
    let cfg = config("full-resolver", 10);
    let plugin = Arc::new(FullResolver { cfg: cfg.clone() });
    mgr.register_handler::<IdentityHook, _>(plugin, cfg).unwrap();
    mgr.initialize().await.unwrap();

    // ----- Host's initial Extensions carries a pre-existing label -----
    // We need to verify that applying the identity result doesn't
    // clobber the label — identity should only touch identity slots.
    let mut initial_security = SecurityExtension::default();
    initial_security.add_label("PII");
    initial_security.classification = Some("internal".into());
    let initial_ext = Extensions {
        security: Some(Arc::new(initial_security)),
        ..Default::default()
    };

    // ----- Run identity resolution -----
    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            build_payload("eyJ.fake.jwt"),
            initial_ext.clone(),
            None,
        )
        .await;

    assert!(result.continue_processing);

    // ----- Apply back to Extensions -----
    let final_payload = extract_identity(&result);
    let updated_ext = final_payload.apply_to_extensions(initial_ext);

    // Identity slots populated on security.
    let sec = updated_ext.security.as_ref().expect("security slot present");
    assert_eq!(
        sec.subject.as_ref().unwrap().id.as_deref(),
        Some("alice@corp.com"),
    );

    // Pre-existing fields preserved — this is the load-bearing
    // assertion for the merge-not-replace semantics.
    assert!(sec.has_label("PII"), "pre-existing label survived apply");
    assert_eq!(sec.classification.as_deref(), Some("internal"));

    // RawCredentials surfaced into Extensions.
    let raw = updated_ext
        .raw_credentials
        .as_ref()
        .expect("raw_credentials slot present");
    let user_token = raw
        .inbound_tokens
        .get(&TokenRole::User)
        .expect("user token present");
    assert_eq!(user_token.source_header, "Authorization");
    // Token bytes carried over end-to-end. Note: this only works
    // because RawCredentialsExtension lives in-process — out-of-process
    // serialization would strip the token field.
    assert_eq!(&*user_token.token, "eyJ.fake.jwt");
}

/// When the IdentityHook chain is denied, `from_pipeline_result`
/// returns `None` because the executor produces no `modified_payload`
/// on the deny path. Hosts use this to distinguish "identity
/// resolved" from "identity rejected" without a separate type.
#[tokio::test]
async fn from_pipeline_result_returns_none_on_deny() {
    let mgr = Arc::new(PluginManager::default());
    let cfg = config("rejecter", 10);
    let plugin = Arc::new(RejectingResolver { cfg: cfg.clone() });
    mgr.register_handler::<IdentityHook, _>(plugin, cfg).unwrap();
    mgr.initialize().await.unwrap();

    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            build_payload("eyJ.tok"),
            Extensions::default(),
            None,
        )
        .await;
    assert!(!result.continue_processing);
    assert!(IdentityPayload::from_pipeline_result(&result).is_none());
}

/// Load-bearing integration test: the full host flow from identity
/// resolution through CMF dispatch correctly cap-gates the
/// `raw_credentials` slot.
///
/// Scenario:
///   1. IdentityResolve handler populates `subject` + a
///      RawCredentialsExtension with a User token.
///   2. Host applies the resolved payload back to `Extensions` via
///      `apply_to_extensions`, getting a fully-populated request
///      Extensions container.
///   3. Host invokes `cmf.tool_pre_invoke` against two registered
///      CMF plugins:
///        - `InboundReader` declares `read_inbound_credentials` —
///          must observe `raw_credentials` with one token.
///        - `InboundBlind` declares no credential capability —
///          must observe `raw_credentials == None` because the
///          executor's `filter_extensions` strips the slot.
///
/// Proves end-to-end that cap-gating is honored when the identity
/// hook's output flows through the host's apply-then-dispatch path.
/// The unit tests in `extensions/filter.rs` exercise the gate in
/// isolation; this test pins the wiring through the real executor.
#[tokio::test]
async fn cap_gating_post_apply_through_cmf_dispatch() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;

    use cpex_core::cmf::enums::Role;
    use cpex_core::cmf::{CmfHook, Message, MessagePayload};
    use cpex_core::extensions::raw_credentials::{
        RawCredentialsExtension, RawInboundToken, TokenKind, TokenRole,
    };
    use cpex_core::extensions::SecurityExtension;

    // ----- Identity resolver: populates subject + one inbound token -----
    struct FullResolver {
        cfg: PluginConfig,
    }
    #[async_trait]
    impl Plugin for FullResolver {
        fn config(&self) -> &PluginConfig {
            &self.cfg
        }
    }
    impl HookHandler<IdentityHook> for FullResolver {
        async fn handle(
            &self,
            payload: &IdentityPayload,
            _ext: &Extensions,
            _ctx: &mut PluginContext,
        ) -> PluginResult<IdentityPayload> {
            let token = payload.raw_token().to_string();
            let mut updated = payload.clone();
            updated.subject = Some(SubjectExtension {
                id: Some("alice@corp.com".into()),
                ..Default::default()
            });
            let mut raw = RawCredentialsExtension::default();
            raw.inbound_tokens.insert(
                TokenRole::User,
                RawInboundToken::new(token, "Authorization", TokenKind::Jwt),
            );
            updated.raw_credentials = Some(raw);
            PluginResult::modify_payload(updated)
        }
    }

    // ----- CMF plugin WITH read_inbound_credentials -----
    // Writes 1 if it saw a token, 0 if it saw none.
    struct InboundReader {
        cfg: PluginConfig,
        saw_token_count: Arc<AtomicUsize>,
        saw_subject_id: Arc<Mutex<Option<String>>>,
    }
    #[async_trait]
    impl Plugin for InboundReader {
        fn config(&self) -> &PluginConfig {
            &self.cfg
        }
    }
    impl HookHandler<CmfHook> for InboundReader {
        async fn handle(
            &self,
            _payload: &MessagePayload,
            ext: &Extensions,
            _ctx: &mut PluginContext,
        ) -> PluginResult<MessagePayload> {
            // Should see the token — plugin declared the cap.
            let n = ext
                .raw_credentials
                .as_ref()
                .map(|r| r.inbound_tokens.len())
                .unwrap_or(0);
            self.saw_token_count.store(n, Ordering::SeqCst);
            // Subject also visible — read_subject gives id+type baseline.
            let id = ext
                .security
                .as_ref()
                .and_then(|s| s.subject.as_ref())
                .and_then(|s| s.id.clone());
            *self.saw_subject_id.lock().unwrap() = id;
            PluginResult::allow()
        }
    }

    // ----- CMF plugin WITHOUT credential caps -----
    // Records whether it observed raw_credentials (it shouldn't).
    struct InboundBlind {
        cfg: PluginConfig,
        saw_any_credentials: Arc<AtomicBool>,
    }
    #[async_trait]
    impl Plugin for InboundBlind {
        fn config(&self) -> &PluginConfig {
            &self.cfg
        }
    }
    impl HookHandler<CmfHook> for InboundBlind {
        async fn handle(
            &self,
            _payload: &MessagePayload,
            ext: &Extensions,
            _ctx: &mut PluginContext,
        ) -> PluginResult<MessagePayload> {
            // raw_credentials must be None — filter_extensions strips
            // the slot when neither sub-cap is held.
            self.saw_any_credentials
                .store(ext.raw_credentials.is_some(), Ordering::SeqCst);
            PluginResult::allow()
        }
    }

    // ----- Wire it all up -----
    let mgr = Arc::new(PluginManager::default());

    // IdentityHook handler.
    let id_cfg = config("full-resolver", 10);
    mgr.register_handler::<IdentityHook, _>(
        Arc::new(FullResolver {
            cfg: id_cfg.clone(),
        }),
        id_cfg,
    )
    .unwrap();

    // CMF plugins. Both register against cmf.tool_pre_invoke; they
    // run in priority order during the same invoke.
    let reader_saw_count = Arc::new(AtomicUsize::new(usize::MAX)); // sentinel
    let reader_saw_subject = Arc::new(Mutex::new(None));
    let reader_cfg = PluginConfig {
        name: "inbound-reader".into(),
        kind: "test".into(),
        description: None,
        author: None,
        version: None,
        hooks: vec!["cmf.tool_pre_invoke".into()],
        mode: PluginMode::Sequential,
        priority: 10,
        on_error: OnError::Fail,
        capabilities: ["read_inbound_credentials", "read_subject"]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        tags: Vec::new(),
        conditions: Vec::new(),
        config: None,
    };
    mgr.register_handler_for_names::<CmfHook, _>(
        Arc::new(InboundReader {
            cfg: reader_cfg.clone(),
            saw_token_count: Arc::clone(&reader_saw_count),
            saw_subject_id: Arc::clone(&reader_saw_subject),
        }),
        reader_cfg,
        &["cmf.tool_pre_invoke"],
    )
    .unwrap();

    let blind_saw_creds = Arc::new(AtomicBool::new(false));
    let blind_cfg = PluginConfig {
        name: "inbound-blind".into(),
        kind: "test".into(),
        description: None,
        author: None,
        version: None,
        hooks: vec!["cmf.tool_pre_invoke".into()],
        mode: PluginMode::Sequential,
        priority: 20,
        on_error: OnError::Fail,
        capabilities: Default::default(), // no caps
        tags: Vec::new(),
        conditions: Vec::new(),
        config: None,
    };
    mgr.register_handler_for_names::<CmfHook, _>(
        Arc::new(InboundBlind {
            cfg: blind_cfg.clone(),
            saw_any_credentials: Arc::clone(&blind_saw_creds),
        }),
        blind_cfg,
        &["cmf.tool_pre_invoke"],
    )
    .unwrap();

    mgr.initialize().await.unwrap();

    // ----- Host flow -----
    // 1. Initial Extensions carrying a label — verifies later that
    //    apply_to_extensions doesn't clobber pre-existing security
    //    fields when populating identity slots.
    let mut initial_security = SecurityExtension::default();
    initial_security.add_label("PII");
    let initial_ext = Extensions {
        security: Some(Arc::new(initial_security)),
        ..Default::default()
    };

    // 2. Identity resolution.
    let (id_result, _bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            build_payload("eyJ.fake.jwt"),
            initial_ext.clone(),
            None,
        )
        .await;
    assert!(id_result.continue_processing);
    let identity = IdentityPayload::from_pipeline_result(&id_result)
        .expect("identity should have resolved");

    // 3. Apply.
    let updated_ext = identity.apply_to_extensions(initial_ext);

    // 4. Dispatch through CMF. Both plugins run; each sees the
    //    capability-filtered view of `updated_ext`.
    let cmf_payload = MessagePayload {
        message: Message::text(Role::User, "fetch sensitive data"),
    };
    let (cmf_result, _bg) = mgr
        .invoke_named::<CmfHook>(
            "cmf.tool_pre_invoke",
            cmf_payload,
            updated_ext,
            None,
        )
        .await;
    assert!(
        cmf_result.continue_processing,
        "CMF dispatch should not be blocked: violation = {:?}",
        cmf_result.violation,
    );

    // ----- Verifications -----
    // Plugin with cap saw the inbound token.
    assert_eq!(
        reader_saw_count.load(Ordering::SeqCst),
        1,
        "InboundReader with read_inbound_credentials should see 1 token",
    );
    // Plugin with cap also saw the resolved subject (read_subject baseline).
    assert_eq!(
        reader_saw_subject.lock().unwrap().as_deref(),
        Some("alice@corp.com"),
    );
    // Plugin without cap saw nothing — filter_extensions stripped the slot.
    assert!(
        !blind_saw_creds.load(Ordering::SeqCst),
        "InboundBlind without credential caps must NOT see raw_credentials",
    );
}

// PluginError import only exists to keep the dev-dep on cpex-core
// honest if a future test needs it; unused for now.
#[allow(dead_code)]
fn _force_plugin_error_link(_e: PluginError) {}
