// Location: ./bindings/python/src/builtins.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// Builtin, transport and secret-provider wiring for a `PolicyEngine`,
// matching what `cpex_apl_install` does over the C FFI.
//
// Must run on the **same `Arc`** that is later passed to
// `load_config_yaml`, so the APL visitor's `Weak<PolicyEngine>` upgrades
// during load.

use std::sync::Arc;

use praxis_policy::{HyperTransport, install_builtins, registry_with_vault};
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::http::HttpTransport;

/// Install the bundled builtins, one outbound HTTP transport and the
/// secret providers on `engine`.
///
/// What it installs:
///   - plugin factories: `identity/jwt`, `identity/api-key`,
///     `delegator/oauth`, `elicitation/ciba`
///   - PDP factories for `global.pdp[]`: `cedar-direct`, `cel`, `opa`
///   - session store factory for `global.session_store`: `valkey`
///   - the APL config visitor
///   - one `HyperTransport` for builtins that declare `perform_http`
///   - secret providers `env`, `file` and `vault`, with Vault using the
///     same transport instance
///
/// With `allow_private_destinations` the transport may reach private,
/// loopback and link-local addresses; without it such requests are
/// refused. This is a host decision; no policy document can turn it on.
///
/// Call it once per engine: PPE's `install_builtins` appends a new APL
/// visitor on every call, so a second install would walk `apl:` blocks
/// twice. `PolicyEngine::new` is the only caller.
pub fn install(engine: &Arc<PolicyEngine>, allow_private_destinations: bool) {
    install_builtins(engine);

    let mut hyper = HyperTransport::new();
    if allow_private_destinations {
        hyper = hyper.with_allow_private_destinations();
    }
    let transport: Arc<dyn HttpTransport> = Arc::new(hyper);
    // Both setters are set-once and log their own warning when a
    // transport or registry is already present.
    let _ = engine.set_http_transport(Arc::clone(&transport));
    let _ = engine.set_secret_providers(registry_with_vault(transport));
}
