// Location: ./examples/tutorial/examples/m11_groups.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Tutorial module 11, Organizing policy (Groups).
//
// Prerequisite: the tutorial IdP must be running.
//   docker compose -f examples/tutorial/idp/docker-compose.yml up -d
//
//   cargo run -p cpex-tutorial --example m11_groups
//   cargo run -p cpex-tutorial --example m11_groups -- --check
//
// Three routes share one `identified` group that resolves the caller's token
// with `keycloak`. The resolver is written once, not per route. Each route
// then adds only its own authorization, so policy still decides every outcome
// per caller: alice (hr) clears the hr route, evan (engineer) clears the
// engineering route, and either may send email.

use std::sync::Arc;

use cpex::PluginManager;
use cpex_tutorial::backends;
use cpex_tutorial::idp;
use cpex_tutorial::ui;
use cpex_tutorial::{mediate, Caller};

use serde_json::json;

const POLICY: &str = include_str!("../policies/m11.yaml");

async fn token(user: &str) -> Caller {
    match idp::mint_token(user, user).await {
        Ok(t) => Caller::with_token(t),
        Err(e) => {
            eprintln!("\x1b[31m{e}\x1b[0m");
            std::process::exit(1);
        },
    }
}

#[tokio::main]
async fn main() {
    ui::module_banner("Module 11: Organizing policy (Groups)");

    let mgr = Arc::new(PluginManager::default());
    cpex::install_builtins(&mgr);
    mgr.load_config_yaml(POLICY)
        .expect("policy m11.yaml should load");
    mgr.initialize().await.expect("initialize");

    let alice = token("alice").await;
    let evan = token("evan").await;
    let mut all_passed = true;

    ui::scenario(
        "alice (hr) → get_compensation (group resolves her token, require(role.hr) passes)",
    );
    let o = mediate(
        &mgr,
        &alice,
        "get_compensation",
        json!({ "employee_id": "e-1001" }),
        backends::get_compensation,
    )
    .await;
    ui::print_outcome(&o);
    all_passed &= ui::expect(&o, true);

    ui::scenario("evan (engineer) → get_compensation (resolved by the same group, denied at require(role.hr))");
    let o = mediate(
        &mgr,
        &evan,
        "get_compensation",
        json!({ "employee_id": "e-1001" }),
        backends::get_compensation,
    )
    .await;
    ui::print_outcome(&o);
    all_passed &= ui::expect(&o, false);

    // The engineering route: same group, a different requirement.
    ui::scenario("evan (engineer) → search_repos (same group, require(role.engineer) passes)");
    let o = mediate(
        &mgr,
        &evan,
        "search_repos",
        json!({ "visibility": "internal" }),
        backends::search_repos,
    )
    .await;
    ui::print_outcome(&o);
    all_passed &= ui::expect(&o, true);

    ui::scenario("alice (hr) → search_repos (denied at require(role.engineer))");
    let o = mediate(
        &mgr,
        &alice,
        "search_repos",
        json!({ "visibility": "internal" }),
        backends::search_repos,
    )
    .await;
    ui::print_outcome(&o);
    all_passed &= ui::expect(&o, false);

    ui::scenario(
        "alice (hr) → send_email (group resolves her token; require(authenticated) passes)",
    );
    let o = mediate(
        &mgr,
        &alice,
        "send_email",
        json!({ "to": "coworker@corp.example", "subject": "lunch" }),
        backends::send_email,
    )
    .await;
    ui::print_outcome(&o);
    all_passed &= ui::expect(&o, true);

    println!("One group carried the shared resolver for all three routes; each route added only its own authorization.");
    ui::finish_check(all_passed);
}
