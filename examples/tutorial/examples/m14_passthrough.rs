// Location: ./examples/tutorial/examples/m14_passthrough.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Tutorial module 14, Passthrough (forward the caller's token, mint nothing).
//
// Prerequisite: the tutorial IdP must be running.
//   docker compose -f examples/tutorial/idp/docker-compose.yml up -d
//
//   cargo run -p cpex-tutorial --example m14_passthrough
//   cargo run -p cpex-tutorial --example m14_passthrough -- --check
//
// The route has NO delegate step. CPEX validates the caller's token inbound
// and forwards it as-is, the zero-leg case. Contrast modules 6/13, which
// mint a fresh scoped token. Here the caller's own token flows downstream.

use std::sync::Arc;

use cpex::PluginManager;
use cpex_tutorial::backends;
use cpex_tutorial::idp;
use cpex_tutorial::ui;
use cpex_tutorial::{mediate, Caller};

use serde_json::json;

const POLICY: &str = include_str!("../policies/m14.yaml");

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
    ui::module_banner("Module 14: Passthrough (forward the caller's token, mint nothing)");

    let mgr = Arc::new(PluginManager::default());
    cpex::install_builtins(&mgr);
    mgr.load_config_yaml(POLICY)
        .expect("policy m14.yaml should load");
    mgr.initialize().await.expect("initialize");

    let alice = token("alice").await;
    let anon = Caller::anonymous();
    let mut all_passed = true;

    // No delegate step runs, so the token alice presented is what would flow
    // downstream.
    ui::scenario("alice → search_repos (validated and forwarded, no token minted)");
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

    // Passthrough still needs a valid inbound token to forward.
    ui::scenario("anonymous → search_repos (no token to forward, require(authenticated) denies)");
    let o = mediate(
        &mgr,
        &anon,
        "search_repos",
        json!({ "visibility": "internal" }),
        backends::search_repos,
    )
    .await;
    ui::print_outcome(&o);
    all_passed &= ui::expect(&o, false);

    println!(
        "No delegate step: CPEX validated the caller's token and forwarded it unchanged. Choose this only when that token is already scoped for the downstream."
    );
    ui::finish_check(all_passed);
}
