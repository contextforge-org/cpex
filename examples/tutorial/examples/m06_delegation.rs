// Location: ./examples/tutorial/examples/m06_delegation.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// Tutorial module 6, Scoped credentials (Delegation).
//
// Prerequisite: the tutorial IdP must be running.
//   docker compose -f examples/tutorial/idp/docker-compose.yml up -d
//
//   cargo run -p cpex-tutorial --example m06_delegation
//   cargo run -p cpex-tutorial --example m06_delegation -- --check
//
// The route mints a downstream, audience-scoped token for the caller with
// a real OAuth 2.0 token exchange (RFC 8693) against Keycloak, then gates
// on whether the exchange succeeded. alice (hr) gets a workday-api token
// and proceeds; evan (engineer) is stopped at require(role.hr) before any
// delegation happens.

use std::sync::Arc;

use cpex::PluginManager;
use cpex_tutorial::backends;
use cpex_tutorial::idp;
use cpex_tutorial::ui;
use cpex_tutorial::{mediate, Caller};

use serde_json::json;

const POLICY: &str = include_str!("../policies/m06.yaml");

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
    ui::module_banner("Module 6: Scoped credentials (Delegation)");

    let mgr = Arc::new(PluginManager::default());
    cpex::install_builtins(&mgr);
    mgr.load_config_yaml(POLICY)
        .expect("policy m06.yaml should load");
    mgr.initialize().await.expect("initialize");

    let alice = token("alice").await;
    let evan = token("evan").await;
    let mut all_passed = true;

    ui::scenario("alice (hr) → get_compensation (delegate mints a workday-api token, then allow)");
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

    ui::scenario("evan (engineer) → get_compensation (denied at require(role.hr), no delegation)");
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

    println!("Delegation is a policy step: the caller's token was exchanged for a downstream-scoped one before the backend call.");
    ui::finish_check(all_passed);
}
