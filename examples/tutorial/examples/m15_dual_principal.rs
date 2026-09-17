// Location: ./examples/tutorial/examples/m15_dual_principal.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Tutorial module 15, Dual-principal delegation (who authorized vs. who acted).
//
// Prerequisite: the tutorial IdP must be running.
//   docker compose -f examples/tutorial/idp/docker-compose.yml up -d
//
//   cargo run -p cpex-tutorial --example m15_dual_principal
//   cargo run -p cpex-tutorial --example m15_dual_principal -- --check
//
// Two principals arrive on every call: the human on X-User-Token (the
// subject) and the agent on Authorization (the actor). `subject: user,
// actor: client` mints a token FOR the user and names the agent as the
// acting party. CPEX puts the actor on the wire per RFC 8693 delegation;
// Keycloak's exchange honors only the subject and drops `act` (see the doc).

use std::sync::Arc;

use cpex::PluginManager;
use cpex_tutorial::backends;
use cpex_tutorial::idp;
use cpex_tutorial::ui;
use cpex_tutorial::{mediate, Caller};

use serde_json::json;

const POLICY: &str = include_str!("../policies/m15.yaml");

/// Fatal helper: mint a token or print the IdP hint and exit.
async fn user_token(user: &str) -> String {
    idp::mint_token(user, user).await.unwrap_or_else(|e| {
        eprintln!("\x1b[31m{e}\x1b[0m");
        std::process::exit(1);
    })
}

async fn agent_token() -> String {
    idp::mint_client_token("cpex-agent", "agent-dev-secret")
        .await
        .unwrap_or_else(|e| {
            eprintln!("\x1b[31m{e}\x1b[0m");
            std::process::exit(1);
        })
}

#[tokio::main]
async fn main() {
    ui::module_banner("Module 15: Dual-principal delegation (who authorized vs. who acted)");

    let mgr = Arc::new(PluginManager::default());
    cpex::install_builtins(&mgr);
    mgr.load_config_yaml(POLICY)
        .expect("policy m15.yaml should load");
    mgr.initialize().await.expect("initialize");

    let alice = user_token("alice").await;
    let agent = agent_token().await;
    let mut all_passed = true;

    // Both principals present: alice authorizes (role.hr on the subject),
    // the agent is named as the actor. The exchange goes through.
    ui::scenario(
        "alice (X-User-Token) + agent (Authorization) → get_compensation (subject: user, actor: client)",
    );
    let both = Caller::with_token(agent.clone()).with_credential("X-User-Token", alice.clone());
    let o = mediate(
        &mgr,
        &both,
        "get_compensation",
        json!({ "employee_id": "e-1001" }),
        backends::get_compensation,
    )
    .await;
    ui::print_outcome(&o);
    all_passed &= ui::expect(&o, true);

    // Only the user, no agent: a dual-principal route needs BOTH credentials,
    // so the missing actor token on Authorization denies at identity.
    ui::scenario("alice only, no agent token → get_compensation (actor credential missing)");
    let user_only = Caller::anonymous().with_credential("X-User-Token", alice.clone());
    let o = mediate(
        &mgr,
        &user_only,
        "get_compensation",
        json!({ "employee_id": "e-1001" }),
        backends::get_compensation,
    )
    .await;
    ui::print_outcome(&o);
    all_passed &= ui::expect(&o, false);

    // The guardrail: `actor:` with `subject: this_workload` is invalid, since that
    // grant carries no actor_token. CPEX denies the step rather than silently
    // dropping the actor. No caller is needed; the check precedes the exchange.
    ui::scenario(
        "sync_index (subject: this_workload + actor: client) → rejected as an invalid combo",
    );
    let o = mediate(
        &mgr,
        &Caller::anonymous(),
        "sync_index",
        json!({}),
        |_: &serde_json::Value| json!({ "synced": true }),
    )
    .await;
    ui::print_outcome(&o);
    all_passed &= ui::expect(&o, false);

    println!("`subject:` is who the token speaks FOR; `actor:` is who is DOING it. Both principals ride one exchange.");
    ui::finish_check(all_passed);
}
