// Location: ./examples/tutorial/examples/m01_hello.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// Tutorial module 1, Hello, enforcement.
//
//   cargo run -p cpex-tutorial --example m01_hello
//   cargo run -p cpex-tutorial --example m01_hello -- --check
//
// The smallest possible CPEX host: build a PolicyEngine, install the
// builtins, load a policy, and dispatch two operations through it. No IdP
// yet, every caller is anonymous. You will see one route deny (it
// requires an authenticated caller) and one route allow (it has no rule).
// The Rust below never decides anything; the policy in policies/m01.yaml
// does.

use std::sync::Arc;

use cpex::PolicyEngine;
use cpex_tutorial::backends;
use cpex_tutorial::ui;
use cpex_tutorial::{Caller, mediate};

use serde_json::json;

/// The policy for this module. Resolved at compile time relative to the
/// crate so the example runs from any working directory.
const POLICY: &str = include_str!("../policies/m01.yaml");

#[tokio::main]
async fn main() {
    ui::module_banner("Module 1: Hello, enforcement");

    // --- Set up the enforcement point (the same steps a real host writes) ---
    let engine = Arc::new(PolicyEngine::default());
    cpex::install_builtins(&engine);
    // The HTTP transport builtins use to reach an IdP. Module 1 calls no IdP,
    // but every module installs it the same way; see `install_http_transport`.
    cpex_tutorial::install_http_transport(&engine);
    engine
        .load_config_yaml(POLICY)
        .expect("policy m01.yaml should load");
    engine.initialize().await.expect("initialize");

    // Everyone is anonymous in module 1, no token.
    let caller = Caller::anonymous();
    let mut all_passed = true;

    // --- Scenario 1: a gated route. require(authenticated) fails for an
    //     anonymous caller, so the backend never runs. ---
    ui::scenario("anonymous → get_compensation (route requires authentication)");
    let outcome = mediate(
        &engine,
        &caller,
        "get_compensation",
        json!({ "employee_id": "e-1001" }),
        backends::get_compensation,
    )
    .await;
    ui::print_outcome(&outcome);
    all_passed &= ui::expect(&outcome, false);

    // --- Scenario 2: an open route. No rule blocks it, so it allows and
    //     returns the backend's result. ---
    ui::scenario("anonymous → search_repos (route has no rule)");
    let outcome = mediate(
        &engine,
        &caller,
        "search_repos",
        json!({ "visibility": "public" }),
        backends::search_repos,
    )
    .await;
    ui::print_outcome(&outcome);
    all_passed &= ui::expect(&outcome, true);

    println!("The route decided the outcome, the code above treated both calls identically.");
    ui::finish_check(all_passed);
}
