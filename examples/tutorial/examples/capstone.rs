// Location: ./examples/tutorial/examples/capstone.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// Tutorial capstone, the three-backend agent.
//
// Prerequisite: the tutorial IdP must be running.
//   docker compose -f examples/tutorial/idp/docker-compose.yml up -d
//
//   cargo run -p cpex-tutorial --example capstone
//   cargo run -p cpex-tutorial --example capstone -- --check
//
// The full scenario from the Overview, assembled from every module: one
// agent, three backends (HR, repos, email), three callers, one policy.
// The two headline behaviors:
//   * Same request, different result: alice (view_ssn) sees the full HR
//     record; dana (no view_ssn) sees it with the SSN redacted; evan is
//     denied outright.
//   * Information follows the session: reading compensation taints the
//     session, so a later email in that session is refused.

use std::sync::Arc;

use cpex::PluginManager;
use cpex_tutorial::backends;
use cpex_tutorial::idp;
use cpex_tutorial::ui;
use cpex_tutorial::{mediate, Caller, Outcome};

use serde_json::json;

const POLICY: &str = include_str!("../policies/capstone.yaml");
const POLICY_NODELEG: &str = include_str!("../policies/capstone-nodeleg.yaml");

async fn token(user: &str) -> String {
    match idp::mint_token(user, user).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("\x1b[31m{e}\x1b[0m");
            std::process::exit(1);
        },
    }
}

/// Does the returned record still contain the real SSN?
fn ssn_visible(outcome: &Outcome) -> bool {
    matches!(outcome, Outcome::Allowed { result }
        if result.get("ssn").and_then(|v| v.as_str()) == Some("521-38-7710"))
}

#[tokio::main]
async fn main() {
    ui::module_banner("Capstone: the three-backend agent");

    // Readers who skipped module 6 (delegation) can run the variant that
    // drops the delegate step: `-- --no-delegation`.
    let no_deleg = std::env::args().any(|a| a == "--no-delegation");
    let policy = if no_deleg { POLICY_NODELEG } else { POLICY };
    if no_deleg {
        println!("(running the no-delegation variant)\n");
    }

    let mgr = Arc::new(PluginManager::default());
    cpex::install_builtins(&mgr);
    mgr.load_config_yaml(policy)
        .expect("capstone policy should load");
    mgr.initialize().await.expect("initialize");

    let alice = token("alice").await;
    let dana = token("dana").await;
    let evan = token("evan").await;
    let sam = token("sam").await;
    let mut all_passed = true;

    // --- Same request, different result ---
    println!("\x1b[1mSame request, different result\x1b[0m\n");

    ui::scenario("alice (hr, view_ssn) → get_compensation");
    let o = mediate(
        &mgr,
        &Caller::with_token(&alice).in_session("s-alice"),
        "get_compensation",
        json!({ "employee_id": "e-1001" }),
        backends::get_compensation,
    )
    .await;
    ui::print_outcome(&o);
    all_passed &= ui::expect(&o, true) && ssn_visible(&o);

    ui::scenario("dana (hr, no view_ssn) → get_compensation (SSN redacted)");
    let o = mediate(
        &mgr,
        &Caller::with_token(&dana).in_session("s-dana"),
        "get_compensation",
        json!({ "employee_id": "e-1001" }),
        backends::get_compensation,
    )
    .await;
    ui::print_outcome(&o);
    all_passed &= ui::expect(&o, true) && !ssn_visible(&o);

    ui::scenario("evan (engineer) → get_compensation (denied, not HR)");
    let o = mediate(
        &mgr,
        &Caller::with_token(&evan).in_session("s-evan"),
        "get_compensation",
        json!({ "employee_id": "e-1001" }),
        backends::get_compensation,
    )
    .await;
    ui::print_outcome(&o);
    all_passed &= ui::expect(&o, false);

    // --- Repo search: CEL decision ---
    println!("\x1b[1mRepo search decided by CEL\x1b[0m\n");

    ui::scenario("evan (engineer) → search_repos internal (allowed)");
    let o = mediate(
        &mgr,
        &Caller::with_token(&evan).in_session("s-evan"),
        "search_repos",
        json!({ "visibility": "internal" }),
        backends::search_repos,
    )
    .await;
    ui::print_outcome(&o);
    all_passed &= ui::expect(&o, true);

    ui::scenario("sam (security) → search_repos public (allowed)");
    let o = mediate(
        &mgr,
        &Caller::with_token(&sam).in_session("s-sam"),
        "search_repos",
        json!({ "visibility": "public" }),
        backends::search_repos,
    )
    .await;
    ui::print_outcome(&o);
    all_passed &= ui::expect(&o, true);

    // --- Information follows the session ---
    println!("\x1b[1mInformation follows the session\x1b[0m\n");

    ui::scenario("dana, fresh session → send_email (allowed: nothing read yet)");
    let o = mediate(
        &mgr,
        &Caller::with_token(&dana).in_session("s-clean"),
        "send_email",
        json!({ "to": "team@corp.example", "subject": "sync" }),
        backends::send_email,
    )
    .await;
    ui::print_outcome(&o);
    all_passed &= ui::expect(&o, true);

    ui::scenario("dana, same session as her HR read → send_email (write-down blocked)");
    let o = mediate(
        &mgr,
        &Caller::with_token(&dana).in_session("s-dana"),
        "send_email",
        json!({ "to": "team@corp.example", "subject": "sync" }),
        backends::send_email,
    )
    .await;
    ui::print_outcome(&o);
    all_passed &= ui::expect(&o, false);

    println!("One policy, one unchanged application. Identity, permission, and session history produced every outcome.");
    ui::finish_check(all_passed);
}
