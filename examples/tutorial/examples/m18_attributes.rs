// Location: ./examples/tutorial/examples/m18_attributes.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Tutorial module 18, Static attributes (operator facts in the data.* tree).
//
// Prerequisite: the tutorial IdP must be running.
//   docker compose -f examples/tutorial/idp/docker-compose.yml up -d
//
// Run from the repo root (the policy's attribute_files path is relative to it):
//   cargo run -p cpex-tutorial --example m18_attributes
//   cargo run -p cpex-tutorial --example m18_attributes -- --check
//
// An operator's per-tool kill switch lives in a data file, loaded into the
// data.* tree. The same caller reaches one tool and is refused another: the
// difference is a fact in that file, not anything about the request.

use std::sync::Arc;

use cpex::PluginManager;
use cpex_tutorial::backends;
use cpex_tutorial::idp;
use cpex_tutorial::ui;
use cpex_tutorial::{mediate, Caller};

use serde_json::json;

const POLICY: &str = include_str!("../policies/m18.yaml");

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
    ui::module_banner("Module 18: Static attributes (operator facts in the data.* tree)");

    let mgr = Arc::new(PluginManager::default());
    cpex::install_builtins(&mgr);
    mgr.load_config_yaml(POLICY)
        .expect("policy m18.yaml should load (run from the repo root so attribute_files resolves)");
    mgr.initialize().await.expect("initialize");

    let alice = token("alice").await;
    let mut all_passed = true;

    // Same caller, two tools. get_compensation is switched OFF in the data
    // file, so it's refused. Nothing about alice changed.
    ui::scenario("alice → get_compensation (data.controls says this tool is disabled)");
    let o = mediate(
        &mgr,
        &alice,
        "get_compensation",
        json!({ "employee_id": "e-1001" }),
        backends::get_compensation,
    )
    .await;
    ui::print_outcome(&o);
    all_passed &= ui::expect(&o, false);

    // search_repos is switched ON in the same file, so the same caller passes.
    ui::scenario("alice → search_repos (data.controls says this tool is enabled)");
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

    println!("Same caller, opposite outcomes, decided by an operator fact in a data file, read as data.*, not by anything in the request.");
    ui::finish_check(all_passed);
}
