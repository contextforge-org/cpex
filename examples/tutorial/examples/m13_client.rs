// Location: ./examples/tutorial/examples/m13_client.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Tutorial module 13, Delegation subject: client (the agent scopes its OWN token).
//
// Prerequisite: the tutorial IdP must be running.
//   docker compose -f examples/tutorial/idp/docker-compose.yml up -d
//
//   cargo run -p cpex-tutorial --example m13_client
//   cargo run -p cpex-tutorial --example m13_client -- --check
//
// The caller is not a person: the agent authenticates to the IdP as its own
// OAuth client (client_credentials) and arrives holding a token that speaks
// for itself. `subject: client` scopes THAT token down to the github-api
// audience, a one-leg RFC 8693 exchange. Like subject: user, it needs an
// inbound credential, so an anonymous request has nothing to exchange.

use std::sync::Arc;

use cpex::PluginManager;
use cpex_tutorial::backends;
use cpex_tutorial::idp;
use cpex_tutorial::ui;
use cpex_tutorial::{mediate, Caller};

use serde_json::json;

const POLICY: &str = include_str!("../policies/m13.yaml");

/// Mint a token for the agent authenticating as the `cpex-agent` OAuth client.
async fn agent_caller() -> Caller {
    match idp::mint_client_token("cpex-agent", "agent-dev-secret").await {
        Ok(t) => Caller::with_token(t),
        Err(e) => {
            eprintln!("\x1b[31m{e}\x1b[0m");
            std::process::exit(1);
        },
    }
}

#[tokio::main]
async fn main() {
    ui::module_banner("Module 13: Delegation subject: client (the agent scopes its own token)");

    let mgr = Arc::new(PluginManager::default());
    cpex::install_builtins(&mgr);
    mgr.load_config_yaml(POLICY)
        .expect("policy m13.yaml should load");
    mgr.initialize().await.expect("initialize");

    let agent = agent_caller().await;
    let anon = Caller::anonymous();
    let mut all_passed = true;

    // subject: client scopes the agent's OWN token. Needs an inbound client token.
    ui::scenario(
        "agent (cpex-agent client) → search_repos (subject: client, scopes the agent's own token)",
    );
    let o = mediate(
        &mgr,
        &agent,
        "search_repos",
        json!({ "visibility": "internal" }),
        backends::search_repos,
    )
    .await;
    ui::print_outcome(&o);
    all_passed &= ui::expect(&o, true);

    ui::scenario(
        "anonymous → search_repos (subject: client, no client token to exchange, delegation fails)",
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
    all_passed &= ui::expect(&o, false);

    println!("`subject: client` scopes the CALLER's own client token: an agent acting as itself, not on behalf of a user.");
    ui::finish_check(all_passed);
}
