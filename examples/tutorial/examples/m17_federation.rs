// Location: ./examples/tutorial/examples/m17_federation.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Tutorial module 17, Multi-issuer identity (trust more than one IdP).
//
// Prerequisite: the tutorial IdP must be running (it imports both the home
// realm `cpex-tutorial` and the partner realm `cpex-partner`).
//   docker compose -f examples/tutorial/idp/docker-compose.yml up -d
//
//   cargo run -p cpex-tutorial --example m17_federation
//   cargo run -p cpex-tutorial --example m17_federation -- --check
//
// One resolver trusts two issuers. A token is validated against the JWKS of
// whichever trusted issuer its `iss` claim names; a token from an issuer in
// neither list is rejected with auth.untrusted_issuer.

use std::sync::Arc;

use cpex::PluginManager;
use cpex_tutorial::backends;
use cpex_tutorial::idp;
use cpex_tutorial::ui;
use cpex_tutorial::{mediate, Caller};

use serde_json::json;

const POLICY: &str = include_str!("../policies/m17.yaml");

/// Fatal helper: unwrap a minted token or print the IdP hint and exit.
fn or_exit(r: Result<String, String>) -> String {
    r.unwrap_or_else(|e| {
        eprintln!("\x1b[31m{e}\x1b[0m");
        std::process::exit(1);
    })
}

#[tokio::main]
async fn main() {
    ui::module_banner("Module 17: Multi-issuer identity (trust more than one IdP)");

    let mgr = Arc::new(PluginManager::default());
    cpex::install_builtins(&mgr);
    mgr.load_config_yaml(POLICY)
        .expect("policy m17.yaml should load");
    mgr.initialize().await.expect("initialize");

    // Home realm: alice, minted from cpex-tutorial.
    let alice = Caller::with_token(or_exit(idp::mint_token("alice", "alice").await));
    // Partner realm: pat, minted from a DIFFERENT issuer (cpex-partner).
    let pat = Caller::with_token(or_exit(
        idp::mint_token_in_realm("cpex-partner", "cpex-partner-app", "pat", "pat").await,
    ));
    // A valid JWT from an issuer the resolver does NOT trust (Keycloak's
    // built-in master realm).
    let outsider = Caller::with_token(or_exit(
        idp::mint_token_in_realm("master", "admin-cli", "admin", "admin").await,
    ));
    let mut all_passed = true;

    ui::scenario("alice (home realm cpex-tutorial) → get_compensation (issuer #1, role.hr)");
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
        "pat (partner realm cpex-partner) → get_compensation (issuer #2, validated on ITS keys)",
    );
    let o = mediate(
        &mgr,
        &pat,
        "get_compensation",
        json!({ "employee_id": "e-1001" }),
        backends::get_compensation,
    )
    .await;
    ui::print_outcome(&o);
    all_passed &= ui::expect(&o, true);

    ui::scenario("outsider (master realm, an untrusted issuer) → get_compensation (rejected)");
    let o = mediate(
        &mgr,
        &outsider,
        "get_compensation",
        json!({ "employee_id": "e-1001" }),
        backends::get_compensation,
    )
    .await;
    ui::print_outcome(&o);
    all_passed &= ui::expect(&o, false);

    println!("One resolver, two trusted issuers: CPEX validates each token on the keys of the issuer its `iss` names, and rejects the rest.");
    ui::finish_check(all_passed);
}
