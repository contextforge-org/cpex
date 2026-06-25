// Location: ./builtins/plugins/elicitation-ciba/tests/live_keycloak.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Phase 0 verification — runs the *automatable* half of the CIBA flow
// (dispatch → check-pending) against a REAL Keycloak, so "Phase 0
// verified" is a repeatable test, not just the manual runbook
// (`docs/keycloak-ciba-phase0-runbook.md`).
//
// The approval step (§5.3 of the runbook) is decoupled and human-driven,
// so it can't be asserted here — but dispatch + the first poll exercise
// the realm/client/auth config end-to-end, which is what usually breaks.
//
// `#[ignore]` by default. To run against a Keycloak configured per the
// runbook:
//
//   CIBA_BACKCHANNEL_ENDPOINT=http://localhost:8080/realms/corp/protocol/openid-connect/ext/ciba/auth \
//   CIBA_TOKEN_ENDPOINT=http://localhost:8080/realms/corp/protocol/openid-connect/token \
//   CIBA_CLIENT_ID=cpex-gateway \
//   CIBA_CLIENT_SECRET=<secret> \
//   CIBA_LOGIN_HINT=alice \
//   cargo test -p cpex-plugin-elicitation-ciba --test live_keycloak -- --ignored --nocapture

use std::collections::HashSet;

use serde_json::json;

use cpex_core::context::PluginContext;
use cpex_core::elicitation::{ElicitationOp, ElicitationPayload, ElicitationStatusKind};
use cpex_core::hooks::payload::Extensions;
use cpex_core::hooks::trait_def::HookHandler;
use cpex_core::plugin::{OnError, PluginConfig, PluginMode};

use cpex_plugin_elicitation_ciba::CibaApprover;

/// Read a required env var, or `None` (so the test skips cleanly).
fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

#[tokio::test]
#[ignore = "requires a live Keycloak configured per docs/keycloak-ciba-phase0-runbook.md"]
async fn live_dispatch_then_pending() {
    let (Some(backchannel), Some(token), Some(client_id), Some(secret), Some(login_hint)) = (
        env("CIBA_BACKCHANNEL_ENDPOINT"),
        env("CIBA_TOKEN_ENDPOINT"),
        env("CIBA_CLIENT_ID"),
        env("CIBA_CLIENT_SECRET"),
        env("CIBA_LOGIN_HINT"),
    ) else {
        eprintln!("SKIP: set CIBA_BACKCHANNEL_ENDPOINT / _TOKEN_ENDPOINT / _CLIENT_ID / _CLIENT_SECRET / _LOGIN_HINT");
        return;
    };

    let insecure = backchannel.starts_with("http://") || token.starts_with("http://");
    let cfg = PluginConfig {
        name: "manager-approver".to_string(),
        kind: "elicitation/ciba".to_string(),
        description: None,
        author: None,
        version: None,
        hooks: vec!["elicit".to_string()],
        mode: PluginMode::Sequential,
        priority: 10,
        on_error: OnError::Fail,
        capabilities: HashSet::new(),
        tags: Vec::new(),
        conditions: Vec::new(),
        config: Some(json!({
            "backchannel_endpoint": backchannel,
            "token_endpoint": token,
            "client_id": client_id,
            "client_secret_source": { "kind": "literal", "secret": secret },
            "insecure_http": insecure,
        })),
    };
    let approver = CibaApprover::new(cfg).expect("construct approver");
    let ext = Extensions::default();

    // 1. dispatch → backchannel auth request (runbook §5.1).
    let dispatch = ElicitationPayload::new(ElicitationOp::Dispatch, "approval", &login_hint)
        .with_purpose("Phase 0 verification — please ignore");
    let mut ctx = PluginContext::new();
    let out = approver.handle(&dispatch, &ext, &mut ctx).await;
    assert!(out.continue_processing, "dispatch denied: {:?}", out.violation);
    let dispatched = out.modified_payload.expect("dispatch payload");
    let id = dispatched.id.clone().expect("Keycloak returned an auth_req_id");
    assert_eq!(dispatched.status, Some(ElicitationStatusKind::Pending));
    assert_eq!(dispatched.approver.as_deref(), Some(login_hint.as_str()));
    eprintln!("dispatch OK — auth_req_id = {id}");

    // 2. check → token poll before approval (runbook §5.2). Without a
    //    completed decoupled approval this must report Pending.
    let check = ElicitationPayload::new(ElicitationOp::Check, "approval", "")
        .with_elicitation_id(&id);
    let mut ctx = PluginContext::new();
    let out = approver.handle(&check, &ext, &mut ctx).await;
    assert!(out.continue_processing, "check denied: {:?}", out.violation);
    let checked = out.modified_payload.expect("check payload");
    assert_eq!(
        checked.status,
        Some(ElicitationStatusKind::Pending),
        "expected authorization_pending before approval; got {:?}",
        checked.status
    );
    eprintln!("check OK — status = Pending (no approval yet, as expected)");
}
