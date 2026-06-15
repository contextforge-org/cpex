// Location: ./bindings/python/src/builtins.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// Register the bundled APL plugin factories and the APL config visitor on a
// `PluginManager`. Must be called on the **same `Arc`** that will later be
// passed to `load_config_yaml` so the APL visitor's `Weak<PluginManager>`
// upgrades correctly during load.
//
// Mirrors `crates/cpex-ffi/src/apl.rs:56` exactly — any new bundled factory
// added to cpex-ffi should be added here too.
//
// Ordering (per apl.rs header comment):
//   PluginManager::default()
//     → register_builtin_factories (this function)
//       → load_config_yaml
//         → initialize

use std::sync::Arc;

use cpex_core::manager::PluginManager;

pub fn register_builtin_factories(manager: &Arc<PluginManager>) {
    // Plugin factories — registered by `kind` string. Must happen before
    // load_config_yaml so the manager can instantiate plugins whose YAML
    // `kind:` matches.
    manager.register_factory(
        apl_pii_scanner::KIND,
        Box::new(apl_pii_scanner::PiiScannerFactory),
    );
    manager.register_factory(
        apl_audit_logger::KIND,
        Box::new(apl_audit_logger::AuditLoggerFactory),
    );
    manager.register_factory(
        apl_identity_jwt::KIND,
        Box::new(apl_identity_jwt::JwtIdentityFactory),
    );
    manager.register_factory(
        apl_delegator_oauth::KIND,
        Box::new(apl_delegator_oauth::OAuthDelegatorFactory),
    );

    // APL config visitor + PDP factories.
    let mut opts = apl_cpex::AplOptions::in_process();
    opts.pdp_factories = vec![Arc::new(apl_pdp_cedar_direct::CedarDirectPdpFactory::new())];
    apl_cpex::register_apl(manager, opts);

    // Cedarling-backed identity + PDP seams (opt-in; heavy deps).
    #[cfg(feature = "cedarling")]
    {
        // Wire Cedarling factories when the feature is enabled.
        // Keep in sync with cpex-ffi's cedarling feature block in apl.rs.
        let _ = manager; // suppress unused-variable warning if no-op
    }
}
