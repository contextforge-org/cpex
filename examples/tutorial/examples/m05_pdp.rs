// Location: ./examples/tutorial/examples/m05_pdp.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// Tutorial module 5, Delegating decisions (PDP).
//
// Prerequisite: the tutorial IdP must be running.
//   docker compose -f examples/tutorial/idp/docker-compose.yml up -d
//
//   cargo run -p cpex-tutorial --example m05_pdp
//   cargo run -p cpex-tutorial --example m05_pdp -- --check
//
// The route hands its decision to the CEL PDP. One expression captures a
// rule that would be awkward as a list of require()s: engineers may search
// internal repos only, security may search anything.

use std::sync::Arc;
use std::time::Duration;

use cpex::PluginManager;
use cpex_tutorial::backends;
use cpex_tutorial::idp;
use cpex_tutorial::ui;
use cpex_tutorial::{mediate, Caller};

use serde_json::json;

const POLICY: &str = include_str!("../policies/m05.yaml");

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
    ui::module_banner("Module 5: Delegating decisions (PDP)");

    let mgr = Arc::new(PluginManager::default());
    cpex::install_builtins(&mgr);
    mgr.load_config_yaml(POLICY)
        .expect("policy m05.yaml should load");
    mgr.initialize().await.expect("initialize");

    if let Err(e) = idp::wait_until_ready(Duration::from_secs(60)).await {
        eprintln!("\x1b[31m{e}\x1b[0m");
        std::process::exit(if ui::check_mode() { 1 } else { 0 });
    }

    let evan = token("evan").await;
    let sam = token("sam").await;
    let mut all_passed = true;

    ui::scenario("evan (engineer) → search_repos internal (CEL allows)");
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

    ui::scenario("evan (engineer) → search_repos public (CEL denies: engineers internal-only)");
    let o = mediate(
        &mgr,
        &evan,
        "search_repos",
        json!({ "visibility": "public" }),
        backends::search_repos,
    )
    .await;
    ui::print_outcome(&o);
    all_passed &= ui::expect(&o, false);

    ui::scenario("sam (security) → search_repos public (CEL allows: security reads any)");
    let o = mediate(
        &mgr,
        &sam,
        "search_repos",
        json!({ "visibility": "public" }),
        backends::search_repos,
    )
    .await;
    ui::print_outcome(&o);
    all_passed &= ui::expect(&o, true);

    println!("One CEL expression captured a rule that mixes role and argument. The PDP decided; CPEX enforced.");
    ui::finish_check(all_passed);
}
