// Location: ./examples/tutorial/examples/m02_identity.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// Tutorial module 2, Who's calling? (Identity)
//
// Prerequisite: the tutorial IdP must be running.
//   docker compose -f examples/tutorial/idp/docker-compose.yml up -d
//
//   cargo run -p cpex-tutorial --example m02_identity
//   cargo run -p cpex-tutorial --example m02_identity -- --check
//
// We mint real JWTs from Keycloak for two personas and call the same HR
// route with each:
//   * alice (hr role, view_ssn permission), ALLOWED.
//   * evan  (engineer role)               , DENIED by require(role.hr).
//   * a garbage token                     , DENIED at token validation,
//                                            before any authorization rule.

use std::sync::Arc;

use cpex::PluginManager;
use cpex_tutorial::backends;
use cpex_tutorial::idp;
use cpex_tutorial::ui;
use cpex_tutorial::{mediate, Caller};

use serde_json::json;

const POLICY: &str = include_str!("../policies/m02.yaml");

#[tokio::main]
async fn main() {
    ui::module_banner("Module 2: Who's calling? (Identity)");

    let mgr = Arc::new(PluginManager::default());
    cpex::install_builtins(&mgr);
    mgr.load_config_yaml(POLICY)
        .expect("policy m02.yaml should load");
    mgr.initialize().await.expect("initialize");

    let alice = match idp::mint_token("alice", "alice").await {
        Ok(t) => Caller::with_token(t),
        Err(e) => {
            eprintln!("\x1b[31m{e}\x1b[0m");
            std::process::exit(1);
        },
    };
    let evan = match idp::mint_token("evan", "evan").await {
        Ok(t) => Caller::with_token(t),
        Err(e) => {
            eprintln!("\x1b[31m{e}\x1b[0m");
            std::process::exit(1);
        },
    };

    let mut all_passed = true;

    ui::scenario("alice (hr) → get_compensation");
    let outcome = mediate(
        &mgr,
        &alice,
        "get_compensation",
        json!({ "employee_id": "e-1001" }),
        backends::get_compensation,
    )
    .await;
    ui::print_outcome(&outcome);
    all_passed &= ui::expect(&outcome, true);

    ui::scenario("evan (engineer) → get_compensation (fails require(role.hr))");
    let outcome = mediate(
        &mgr,
        &evan,
        "get_compensation",
        json!({ "employee_id": "e-1001" }),
        backends::get_compensation,
    )
    .await;
    ui::print_outcome(&outcome);
    all_passed &= ui::expect(&outcome, false);

    ui::scenario("garbage token → get_compensation (rejected at validation)");
    let bogus = Caller::with_token("not.a.jwt");
    let outcome = mediate(
        &mgr,
        &bogus,
        "get_compensation",
        json!({ "employee_id": "e-1001" }),
        backends::get_compensation,
    )
    .await;
    ui::print_outcome(&outcome);
    all_passed &= ui::expect(&outcome, false);

    println!("Same route, same code, the token the caller presented decided the outcome.");
    ui::finish_check(all_passed);
}
