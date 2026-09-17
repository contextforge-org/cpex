// Location: ./examples/tutorial/examples/m12_subjects.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Tutorial module 12, Delegation subjects (who the downstream call speaks for).
//
// Prerequisite: the tutorial IdP must be running.
//   docker compose -f examples/tutorial/idp/docker-compose.yml up -d
//
//   cargo run -p cpex-tutorial --example m12_subjects
//   cargo run -p cpex-tutorial --example m12_subjects -- --check
//
// Two routes mint a downstream token differently:
//   * get_compensation uses `subject: user`: it exchanges the CALLER's token,
//     so an anonymous request has nothing to exchange and delegation fails.
//   * search_repos uses `subject: this_workload`: it mints a token as the
//     GATEWAY (client_credentials), so it works with no caller at all.

use std::sync::Arc;

use cpex::PluginManager;
use cpex_tutorial::backends;
use cpex_tutorial::idp;
use cpex_tutorial::ui;
use cpex_tutorial::{mediate, Caller};

use serde_json::json;

const POLICY: &str = include_str!("../policies/m12.yaml");

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
    ui::module_banner("Module 12: Delegation subjects (who the call speaks for)");

    let mgr = Arc::new(PluginManager::default());
    cpex::install_builtins(&mgr);
    mgr.load_config_yaml(POLICY)
        .expect("policy m12.yaml should load");
    mgr.initialize().await.expect("initialize");

    let alice = token("alice").await;
    let anon = Caller::anonymous();
    let mut all_passed = true;

    // subject: user, on behalf of the caller. Needs a caller token to exchange.
    ui::scenario("alice → get_compensation (subject: user, exchanges alice's token)");
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

    ui::scenario(
        "anonymous → get_compensation (subject: user, no token to exchange, delegation fails)",
    );
    let o = mediate(
        &mgr,
        &anon,
        "get_compensation",
        json!({ "employee_id": "e-1001" }),
        backends::get_compensation,
    )
    .await;
    ui::print_outcome(&o);
    all_passed &= ui::expect(&o, false);

    // subject: this_workload, as the gateway itself. No caller token needed.
    ui::scenario(
        "anonymous → search_repos (subject: this_workload, gateway mints via client_credentials)",
    );
    let o = mediate(
        &mgr,
        &anon,
        "search_repos",
        json!({ "visibility": "internal" }),
        backends::search_repos,
    )
    .await;
    ui::print_outcome(&o);
    all_passed &= ui::expect(&o, true);

    ui::scenario("alice → search_repos (subject: this_workload, same result: the caller's identity is not used)");
    let o = mediate(
        &mgr,
        &alice,
        "search_repos",
        json!({ "visibility": "internal" }),
        backends::search_repos,
    )
    .await;
    ui::print_outcome(&o);
    all_passed &= ui::expect(&o, true);

    println!("`subject:` chooses whose authority the downstream token carries: the caller (user) or the gateway itself (this_workload).");
    ui::finish_check(all_passed);
}
