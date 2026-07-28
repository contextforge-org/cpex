// Location: ./examples/tutorial/examples/m04_effects.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// Tutorial module 4, Effects and sequencing.
//
//   cargo run -p cpex-tutorial --example m04_effects
//   cargo run -p cpex-tutorial --example m04_effects -- --check
//
// A route's pre_invocation is an ordered list of effects that halts on the
// first denial. This module sends two emails through the same route:
//   * one to an external recipient, the hand-written deny() guard blocks
//     it with a custom reason code, AFTER the audit plugin already ran;
//   * one to an internal recipient, the guard passes, but the anonymous
//     caller then fails require(authenticated).
// Watch stderr for the audit-log line: it fires on both calls because it
// sits before the denials. Effects before a deny still happen.

use std::sync::Arc;

use cpex::PluginManager;
use cpex_tutorial::backends;
use cpex_tutorial::ui;
use cpex_tutorial::{mediate, Caller, Outcome};

use serde_json::json;

const POLICY: &str = include_str!("../policies/m04.yaml");

#[tokio::main]
async fn main() {
    ui::module_banner("Module 4: Effects and sequencing");

    let mgr = Arc::new(PluginManager::default());
    cpex::install_builtins(&mgr);
    mgr.load_config_yaml(POLICY)
        .expect("policy m04.yaml should load");
    mgr.initialize().await.expect("initialize");

    let caller = Caller::anonymous();
    let mut all_passed = true;

    // --- Scenario 1: external recipient. audit runs, then the custom
    //     deny() guard halts with code `email.external_blocked`. ---
    ui::scenario("send_email to an external recipient (custom deny guard halts)");
    let outcome = mediate(
        &mgr,
        &caller,
        "send_email",
        json!({ "to": "attacker@evil.example", "subject": "hi", "external": true }),
        backends::send_email,
    )
    .await;
    ui::print_outcome(&outcome);
    all_passed &= ui::expect(&outcome, false);
    if let Outcome::Denied { code, .. } = &outcome {
        let matched = code == "email.external_blocked";
        println!(
            "  denial carried the custom reason code we wrote in policy: {code} {}",
            if matched { "✓" } else { "(unexpected)" }
        );
        all_passed &= matched;
    }
    println!();

    // --- Scenario 2: internal recipient. The external guard passes, so
    //     the pipeline reaches require(authenticated), which denies our
    //     anonymous caller with a different code. Proof of ordering. ---
    ui::scenario("send_email to an internal recipient (guard passes, auth check halts)");
    let outcome = mediate(
        &mgr,
        &caller,
        "send_email",
        json!({ "to": "coworker@corp.example", "subject": "hi", "external": false }),
        backends::send_email,
    )
    .await;
    ui::print_outcome(&outcome);
    all_passed &= ui::expect(&outcome, false);

    println!("The audit line above (stderr) fired on BOTH calls, effects before a deny still run.");
    ui::finish_check(all_passed);
}
