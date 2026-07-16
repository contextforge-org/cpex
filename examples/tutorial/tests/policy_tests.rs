// Location: ./examples/tutorial/tests/policy_tests.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// Module 10, Testing your policy.
//
//   cargo test -p cpex-tutorial
//
// These tests show how to unit-test APL without a live IdP or backend.
// You load a policy into a manager, drive routes through `mediate()` with
// a fake backend, and assert on the outcome. Table-driven cases keep the
// allow/deny matrix readable and make a new case one line.
//
// Anonymous callers are enough to exercise structural predicates
// (require(authenticated), argument guards, result pipelines), so these
// run in plain CI with no Keycloak. For identity-dependent rules you would
// mint tokens the way the module binaries do.

use std::sync::Arc;

use cpex::PluginManager;
use cpex_tutorial::backends;
use cpex_tutorial::{mediate, Caller, Outcome};

use serde_json::{json, Value};

/// Load a policy string into a ready-to-use manager.
async fn manager_with(policy: &str) -> Arc<PluginManager> {
    let mgr = Arc::new(PluginManager::default());
    cpex::install_builtins(&mgr);
    mgr.load_config_yaml(policy).expect("policy should load");
    mgr.initialize().await.expect("initialize");
    mgr
}

/// A single table row: call `tool` with `args` and expect allow or deny.
struct Case {
    tool: &'static str,
    args: Value,
    want_allowed: bool,
    want_code: Option<&'static str>,
}

async fn run_case(mgr: &Arc<PluginManager>, c: &Case) {
    let outcome = mediate(mgr, &Caller::anonymous(), c.tool, c.args.clone(), |a| {
        backends::dispatch(c.tool, a)
    })
    .await;
    match (&outcome, c.want_allowed) {
        (Outcome::Allowed { .. }, true) => {},
        (Outcome::Denied { code, .. }, false) => {
            if let Some(want) = c.want_code {
                assert_eq!(code, want, "wrong deny code for {}", c.tool);
            }
        },
        (got, _) => panic!(
            "{}: expected allowed={}, got {:?}",
            c.tool, c.want_allowed, got
        ),
    }
}

const M01: &str = include_str!("../policies/m01.yaml");
const M04: &str = include_str!("../policies/m04.yaml");

#[tokio::test]
async fn module1_gates_by_authentication() {
    let mgr = manager_with(M01).await;
    let cases = [
        Case {
            tool: "get_compensation",
            args: json!({ "employee_id": "e-1001" }),
            want_allowed: false,
            want_code: None,
        },
        Case {
            tool: "search_repos",
            args: json!({ "visibility": "public" }),
            want_allowed: true,
            want_code: None,
        },
    ];
    for c in &cases {
        run_case(&mgr, c).await;
    }
}

#[tokio::test]
async fn module4_external_email_denied_with_custom_code() {
    let mgr = manager_with(M04).await;
    let cases = [
        Case {
            tool: "send_email",
            args: json!({ "to": "x@evil.example", "subject": "hi", "external": true }),
            want_allowed: false,
            want_code: Some("email.external_blocked"),
        },
        Case {
            tool: "send_email",
            args: json!({ "to": "x@corp.example", "subject": "hi", "external": false }),
            want_allowed: false, // anonymous, so require(authenticated) halts it
            want_code: None,
        },
    ];
    for c in &cases {
        run_case(&mgr, c).await;
    }
}
