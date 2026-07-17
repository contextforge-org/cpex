// Location: ./examples/tutorial/examples/m07_tainting.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// Tutorial module 7, Information flow (Tainting).
//
// Prerequisite: the tutorial IdP must be running.
//   docker compose -f examples/tutorial/idp/docker-compose.yml up -d
//
//   cargo run -p cpex-tutorial --example m07_tainting
//   cargo run -p cpex-tutorial --example m07_tainting -- --check
//
// The same send_email call is allowed in a fresh session and denied in a
// session that previously read compensation. Reading tainted the session;
// the later send is blocked by the session's history, not its content.

use std::sync::Arc;

use cpex::PluginManager;
use cpex_tutorial::backends;
use cpex_tutorial::idp;
use cpex_tutorial::ui;
use cpex_tutorial::{mediate, Caller};

use serde_json::json;

const POLICY: &str = include_str!("../policies/m07.yaml");

#[tokio::main]
async fn main() {
    ui::module_banner("Module 7: Information flow (Tainting)");

    let mgr = Arc::new(PluginManager::default());
    cpex::install_builtins(&mgr);
    mgr.load_config_yaml(POLICY)
        .expect("policy m07.yaml should load");
    mgr.initialize().await.expect("initialize");

    let token = match idp::mint_token("alice", "alice").await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("\x1b[31m{e}\x1b[0m");
            std::process::exit(1);
        },
    };
    let mut all_passed = true;

    // Fresh session: nothing read yet, so the email is allowed.
    let clean = Caller::with_token(token.clone()).in_session("session-clean");
    ui::scenario("alice, fresh session → send_email (nothing tainted yet)");
    let o = mediate(
        &mgr,
        &clean,
        "send_email",
        json!({ "to": "coworker@corp.example", "subject": "lunch" }),
        backends::send_email,
    )
    .await;
    ui::print_outcome(&o);
    all_passed &= ui::expect(&o, true);

    // A second session: read compensation first (taints the session)...
    let working = Caller::with_token(token.clone()).in_session("session-hr-work");
    ui::scenario("alice, session-hr-work → get_compensation (taints session 'secret')");
    let o = mediate(
        &mgr,
        &working,
        "get_compensation",
        json!({ "employee_id": "e-1001" }),
        backends::get_compensation,
    )
    .await;
    ui::print_outcome(&o);
    all_passed &= ui::expect(&o, true);

    // ...then the SAME send_email is denied, because the session is tainted.
    ui::scenario("alice, session-hr-work → send_email (write-down blocked)");
    let o = mediate(
        &mgr,
        &working,
        "send_email",
        json!({ "to": "coworker@corp.example", "subject": "lunch" }),
        backends::send_email,
    )
    .await;
    ui::print_outcome(&o);
    all_passed &= ui::expect(&o, false);

    println!("Identical send_email call: allowed in the clean session, denied after the same session read secret data.");
    ui::finish_check(all_passed);
}
