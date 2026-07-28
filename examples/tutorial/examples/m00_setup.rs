// Location: ./examples/tutorial/examples/m00_setup.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// Tutorial module 0, Setup & orientation.
//
//   cargo run -p cpex-tutorial --example m00_setup
//
// A do-nothing-to-your-system check: it confirms the crate builds and
// tells you whether the tutorial IdP is reachable, so you know what you
// can run. Modules 0 and 1 need no IdP; module 2 onward do.

use std::time::Duration;

use cpex_tutorial::idp;
use cpex_tutorial::ui;

#[tokio::main]
async fn main() {
    ui::module_banner("Module 0: Setup & orientation");

    println!("CPEX is a policy enforcement runtime for AI agents: a deterministic");
    println!("reference monitor that sits between an agent and every tool it calls.");
    println!("In this tutorial you build that enforcement point up one capability at");
    println!("a time, changing only POLICY, never the host code.\n");

    println!("Each module is a runnable binary:");
    println!("  cargo run -p cpex-tutorial --example m01_hello");
    println!(
        "  cargo run -p cpex-tutorial --example m01_hello -- --check   # scripted assertions\n"
    );

    print!("Checking the tutorial IdP (Keycloak) ... ");
    match idp::wait_until_ready(Duration::from_secs(2)).await {
        Ok(()) => {
            println!("\x1b[32mup\x1b[0m at {}", idp::issuer());
            println!("You're ready for every module.");
        },
        Err(_) => {
            println!("\x1b[33mnot running\x1b[0m");
            println!("Modules 0–1 work without it. For module 2 onward, start it:");
            println!("  docker compose -f examples/tutorial/idp/docker-compose.yml up -d");
        },
    }
    println!("\nNext: module 1, the smallest possible enforcement point.");
}
