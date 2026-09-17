// Location: ./examples/tutorial/examples/m16_workload.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Tutorial module 16, Workload identity (the agent proves itself with an SVID).
//
// Prerequisites: the tutorial IdP AND the SPIRE overlay must be running, and
// Keycloak must be wired to trust SPIRE:
//   docker compose -f examples/tutorial/idp/docker-compose.yml \
//     -f examples/tutorial/idp/docker-compose.spire.yml up -d
//   ./examples/tutorial/idp/spire/setup-spiffe.sh
//
//   cargo run -p cpex-tutorial --example m16_workload
//   cargo run -p cpex-tutorial --example m16_workload -- --check
//
// The caller is a workload with a SPIFFE identity. It presents its ES256
// JWT-SVID (minted by SPIRE) on X-Workload-Token: no user, no client secret.
// CPEX validates it against SPIRE's JWKS -> caller_workload, then runs the
// two-leg delegation: leg 1 turns the SVID into an IdP token (jwt-spiffe
// client_assertion), leg 2 exchanges that for a github-api-scoped token.

use std::sync::Arc;

use cpex::PluginManager;
use cpex_tutorial::backends;
use cpex_tutorial::idp;
use cpex_tutorial::ui;
use cpex_tutorial::{mediate, Caller};

use serde_json::json;

const POLICY: &str = include_str!("../policies/m16.yaml");
const SPIFFE_ID: &str = "spiffe://cpex.tutorial/agent/hr-copilot";

#[tokio::main]
async fn main() {
    ui::module_banner("Module 16: Workload identity (the agent proves itself with an SVID)");

    let mgr = Arc::new(PluginManager::default());
    cpex::install_builtins(&mgr);
    mgr.load_config_yaml(POLICY)
        .expect("policy m16.yaml should load");
    mgr.initialize().await.expect("initialize");

    // Mint the agent's SVID off SPIRE. This is the agent's identity credential
    // an ES256 JWT signed by SPIRE, audience = the tutorial realm issuer.
    let svid = idp::mint_svid(SPIFFE_ID).unwrap_or_else(|e| {
        eprintln!("\x1b[31m{e}\x1b[0m");
        std::process::exit(1);
    });
    let mut all_passed = true;

    // The agent presents ONLY its SVID (no user, no client token). CPEX
    // validates it -> caller_workload, then brokers a scoped token in two legs.
    ui::scenario(
        "agent (SVID on X-Workload-Token) → search_repos (subject: caller_workload, two-leg)",
    );
    let agent = Caller::anonymous().with_credential("X-Workload-Token", svid);
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

    // No SVID: the route authenticates by the workload token alone, so an
    // anonymous request has no identity to broker from.
    ui::scenario("anonymous → search_repos (no SVID, so nothing to broker from)");
    let o = mediate(
        &mgr,
        &Caller::anonymous(),
        "search_repos",
        json!({ "visibility": "internal" }),
        backends::search_repos,
    )
    .await;
    ui::print_outcome(&o);
    all_passed &= ui::expect(&o, false);

    println!(
        "The agent proved itself with a SPIFFE SVID and never held the downstream token: CPEX brokered it in two legs."
    );
    ui::finish_check(all_passed);
}
