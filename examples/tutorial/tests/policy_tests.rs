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
// You load a policy into an engine, drive routes through `mediate()` with
// a fake backend, and assert on the outcome. Table-driven cases keep the
// allow/deny matrix readable and make a new case one line.
//
// Anonymous callers are enough to exercise structural predicates
// (require(authenticated), argument guards, result pipelines), so these
// run in plain CI with no Keycloak. For identity-dependent rules you would
// mint tokens the way the module binaries do.

use std::sync::Arc;

use cpex::PolicyEngine;
use cpex_tutorial::backends;
use cpex_tutorial::{Caller, Outcome, mediate};

use serde_json::{Value, json};

/// Load a policy string into a ready-to-use engine.
async fn engine_with(policy: &str) -> Arc<PolicyEngine> {
    let engine = Arc::new(PolicyEngine::default());
    cpex::install_builtins(&engine);
    cpex_tutorial::install_http_transport(&engine);
    cpex_tutorial::audit::register(&engine);
    engine.load_config_yaml(policy).expect("policy should load");
    engine.initialize().await.expect("initialize");
    engine
}

/// A single table row: call `tool` with `args` and expect allow or deny.
struct Case {
    tool: &'static str,
    args: Value,
    want_allowed: bool,
    want_code: Option<&'static str>,
}

async fn run_case(engine: &Arc<PolicyEngine>, c: &Case) {
    let outcome = mediate(engine, &Caller::anonymous(), c.tool, c.args.clone(), |a| {
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
    let engine = engine_with(M01).await;
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
        run_case(&engine, c).await;
    }
}

#[tokio::test]
async fn module4_external_email_denied_with_custom_code() {
    let engine = engine_with(M04).await;
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
        run_case(&engine, c).await;
    }
}

// ---------------------------------------------------------------------------
// Every module's policy loads.
//
// Loading is where the engine checks a policy's shape: unknown or removed
// keys, plugins no step reaches, steps naming plugins nobody declared, and
// capabilities a plugin needs but does not declare. The modules above only
// load two policies, and most module binaries need the IdP to run, so this
// test loads every policy offline. It does not call `initialize()`, which is
// where the identity plugins fetch their JWKS from the IdP.
// ---------------------------------------------------------------------------

use cpex::prelude::{
    CmfHook, Extensions, HookHandler, MessagePayload, Plugin, PluginConfig, PluginContext,
    PluginError, PluginFactory, PluginInstance, PluginResult, TypedHandlerAdapter,
};
use ppe::praxis_policy_core::elicitation::{ElicitationHook, ElicitationPayload};

/// Stand-in for the plugins modules 8 and 9 define in their own binaries.
/// Loading only needs a factory for the `kind` and a handler on the right
/// hook; this one never runs.
struct Stub {
    cfg: PluginConfig,
}

#[async_trait::async_trait]
impl Plugin for Stub {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for Stub {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        _ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        PluginResult::allow()
    }
}

impl HookHandler<ElicitationHook> for Stub {
    async fn handle(
        &self,
        _payload: &ElicitationPayload,
        _ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<ElicitationPayload> {
        PluginResult::allow()
    }
}

struct StubFactory {
    hook: &'static str,
}

impl PluginFactory for StubFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let plugin = Arc::new(Stub {
            cfg: config.clone(),
        });
        let handler: Arc<dyn cpex::prelude::AnyHookHandler> = if self.hook == "elicit" {
            Arc::new(TypedHandlerAdapter::<ElicitationHook, _>::new(
                plugin.clone(),
            ))
        } else {
            Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(plugin.clone()))
        };
        Ok(PluginInstance {
            plugin,
            handlers: vec![(self.hook, handler)],
        })
    }
}

#[test]
fn every_module_policy_loads() {
    let policies = [
        ("m01", include_str!("../policies/m01.yaml")),
        ("m02", include_str!("../policies/m02.yaml")),
        ("m03", include_str!("../policies/m03.yaml")),
        ("m04", include_str!("../policies/m04.yaml")),
        ("m05", include_str!("../policies/m05.yaml")),
        ("m06", include_str!("../policies/m06.yaml")),
        ("m07", include_str!("../policies/m07.yaml")),
        ("m08", include_str!("../policies/m08.yaml")),
        ("m09", include_str!("../policies/m09.yaml")),
        ("m11", include_str!("../policies/m11.yaml")),
        ("m12", include_str!("../policies/m12.yaml")),
        ("m13", include_str!("../policies/m13.yaml")),
        ("m14", include_str!("../policies/m14.yaml")),
        ("m15", include_str!("../policies/m15.yaml")),
        ("m16", include_str!("../policies/m16.yaml")),
        ("m17", include_str!("../policies/m17.yaml")),
        ("m18", include_str!("../policies/m18.yaml")),
        ("capstone", include_str!("../policies/capstone.yaml")),
        (
            "capstone-nodeleg",
            include_str!("../policies/capstone-nodeleg.yaml"),
        ),
    ];
    // Module 18's attribute file path is relative to the repo root, where the
    // module binaries run; tests run from the crate directory.
    let attributes_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/policies/attributes/");
    let mut failures = Vec::new();
    for (name, yaml) in policies {
        let yaml = yaml.replace("examples/tutorial/policies/attributes/", attributes_dir);
        let engine = Arc::new(PolicyEngine::default());
        engine.register_factory(
            "business-hours",
            Box::new(StubFactory {
                hook: "cmf.tool_pre_invoke",
            }),
        );
        engine.register_factory("approval-channel", Box::new(StubFactory { hook: "elicit" }));
        cpex::install_builtins(&engine);
        cpex_tutorial::install_http_transport(&engine);
        cpex_tutorial::audit::register(&engine);
        if let Err(e) = engine.load_config_yaml(&yaml) {
            failures.push(format!("{name}: {e}"));
        }
    }
    assert!(
        failures.is_empty(),
        "policies failed to load:\n{}",
        failures.join("\n")
    );
}
