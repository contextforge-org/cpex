// Location: ./examples/tutorial/examples/wait_for_idp.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// A readiness probe for the tutorial Keycloak realm.
//
//   cargo run -p cpex-tutorial --example wait_for_idp
//
// Polls the realm's OIDC discovery endpoint until it answers, then exits 0;
// exits 1 if it does not come up in time. This is the single place readiness
// is gated: `make tutorial-check` runs it once after `docker compose up`, so
// the IdP-backed modules do not each have to wait. The JWT plugin fetches
// JWKS at manager initialize(), so the realm must be serving before any
// module starts — running this probe first guarantees that.

use std::time::Duration;

use cpex_tutorial::idp;

#[tokio::main]
async fn main() {
    match idp::wait_until_ready(Duration::from_secs(90)).await {
        Ok(()) => {
            println!("tutorial IdP is ready at {}", idp::issuer());
        },
        Err(e) => {
            eprintln!("\x1b[31m{e}\x1b[0m");
            eprintln!(
                "Start it with:\n  docker compose -f examples/tutorial/idp/docker-compose.yml up -d"
            );
            std::process::exit(1);
        },
    }
}
