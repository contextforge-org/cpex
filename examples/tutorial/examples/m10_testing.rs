// Location: ./examples/tutorial/examples/m10_testing.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// Tutorial module 10, Testing your policy.
//
//   cargo run -p cpex-tutorial --example m10_testing
//   cargo test -p cpex-tutorial                        # the real tests
//
// Policy is code, so test it like code. You load a policy, drive routes
// through mediate() with a fake backend, and assert the outcome. No IdP or
// real service needed for structural rules. This binary runs a small
// allow/deny table; tests/policy_tests.rs does the same as real cargo
// tests you can wire into CI.

use std::sync::Arc;

use cpex::PluginManager;
use cpex_tutorial::backends;
use cpex_tutorial::ui;
use cpex_tutorial::{mediate, Caller};

use serde_json::json;

const M04: &str = include_str!("../policies/m04.yaml");

#[tokio::main]
async fn main() {
    ui::module_banner("Module 10: Testing your policy");

    let mgr = Arc::new(PluginManager::default());
    cpex::install_builtins(&mgr);
    mgr.load_config_yaml(M04).expect("policy should load");
    mgr.initialize().await.expect("initialize");

    // A table of expectations. Each row is a policy assertion.
    let cases = [
        (
            "send_email",
            json!({ "to": "x@evil.example", "external": true }),
            false,
        ),
        (
            "send_email",
            json!({ "to": "x@corp.example", "external": false }),
            false,
        ),
    ];

    let mut all_passed = true;
    for (tool, args, want_allowed) in cases {
        ui::scenario(&format!(
            "{tool} {args} → expect {}",
            if want_allowed { "ALLOW" } else { "DENY" }
        ));
        let outcome = mediate(&mgr, &Caller::anonymous(), tool, args, |a| {
            backends::dispatch(tool, a)
        })
        .await;
        ui::print_outcome(&outcome);
        all_passed &= ui::expect(&outcome, want_allowed);
    }

    println!("Same assertions live in tests/policy_tests.rs; run `cargo test -p cpex-tutorial`.");
    ui::finish_check(all_passed);
}
