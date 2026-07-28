// Location: ./examples/tutorial/examples/m03_shaping.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// Tutorial module 3, Shaping data.
//
//   cargo run -p cpex-tutorial --example m03_shaping
//   cargo run -p cpex-tutorial --example m03_shaping -- --check
//
// The route allows the call, then transforms the *result* with a field
// pipeline: redact ssn without view_ssn, redact salary without the hr
// role, always mask employee_id. This module runs anonymously, so both
// redactions fire, the SSN and salary come back redacted while the rest
// of the record passes through. In module 2+ an HR caller with the right
// permission sees the full record from this same policy.

use std::sync::Arc;

use cpex::PluginManager;
use cpex_tutorial::backends;
use cpex_tutorial::ui;
use cpex_tutorial::{mediate, Caller, Outcome};

use serde_json::json;

const POLICY: &str = include_str!("../policies/m03.yaml");

#[tokio::main]
async fn main() {
    ui::module_banner("Module 3: Shaping data");

    let mgr = Arc::new(PluginManager::default());
    cpex::install_builtins(&mgr);
    mgr.load_config_yaml(POLICY)
        .expect("policy m03.yaml should load");
    mgr.initialize().await.expect("initialize");

    let caller = Caller::anonymous();
    let mut all_passed = true;

    ui::scenario("anonymous → get_compensation (result pipeline redacts ssn + salary, masks id)");
    let outcome = mediate(
        &mgr,
        &caller,
        "get_compensation",
        json!({ "employee_id": "e-1001" }),
        backends::get_compensation,
    )
    .await;
    ui::print_outcome(&outcome);

    // The call is allowed, but the sensitive fields must be transformed.
    all_passed &= ui::expect(&outcome, true);
    // Field-level verification runs under --check only, so an interactive
    // "Try it" run (e.g. minting alice, where the SSN is meant to appear)
    // stays quiet; the printed result above already shows what was shaped.
    if ui::check_mode() {
        if let Outcome::Allowed { result } = &outcome {
            let ssn = result.get("ssn").and_then(|v| v.as_str()).unwrap_or("");
            let id = result
                .get("employee_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let ssn_redacted = ssn != "521-38-7710";
            let id_masked = id != "e-1001";
            all_passed &= ssn_redacted && id_masked;
        }
    }
    println!();

    println!(
        "Redaction happens on the way OUT, the backend returned the full record; policy shaped it."
    );
    ui::finish_check(all_passed);
}
