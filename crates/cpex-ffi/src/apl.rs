// Location: ./crates/cpex-ffi/src/apl.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// APL (Attribute Policy Language) FFI wiring.
//
// `cpex_apl_install` registers the bundled APL plugin factories and
// installs the APL config visitor on a manager so that a subsequent
// `cpex_load_config` walks `apl:` blocks and installs per-route handlers.
//
// Registration is explicit (no inventory/ctor magic): each factory is
// referenced here so its object code survives in `libcpex_ffi.a`. Adding
// a new bundled factory means adding a `register_factory` call below.
//
// Ordering: call AFTER `cpex_manager_new_default` and BEFORE
// `cpex_load_config`. The config visitor must be registered before the
// config is loaded, and the one-shot `cpex_manager_new(yaml)` path loads
// during construction — so APL is only supported via the default-manager
// flow:
//
//   cpex_manager_new_default
//     → cpex_apl_install
//       → cpex_load_config
//         → cpex_initialize

use std::os::raw::c_int;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

use crate::{CpexManagerInner, RC_INVALID_HANDLE, RC_OK, RC_PANIC};

/// Register the bundled APL plugin factories and install the APL config
/// visitor (in-process defaults: memory session store, default baseline
/// capabilities) on `mgr`.
///
/// Bundled plugin factories (registered by `kind`):
///   - `validator/pii-scan`  → apl-pii-scanner
///   - `audit/logger`        → apl-audit-logger
///   - `identity/jwt`        → apl-identity-jwt
///   - `delegator/oauth`     → apl-delegator-oauth
///
/// Bundled PDP factory (consulted for `global.apl.pdp[]` entries):
///   - `cedar-direct`        → apl-pdp-cedar-direct
///
/// With the `cedarling` cargo feature, the Cedarling-backed identity and
/// PDP seams are additionally wired.
///
/// Returns `RC_OK` on success, `RC_INVALID_HANDLE` if `mgr` is null, or
/// `RC_PANIC` if registration panicked (caught at the FFI boundary).
///
/// # Safety
/// `mgr` must be a valid handle returned by `cpex_manager_new_default`
/// (or `cpex_manager_new`) and not yet shut down.
#[no_mangle]
pub unsafe extern "C" fn cpex_apl_install(mgr: *const CpexManagerInner) -> c_int {
    let inner = match mgr.as_ref() {
        Some(m) => m,
        None => return RC_INVALID_HANDLE,
    };

    let result = catch_unwind(AssertUnwindSafe(|| {
        // Plugin factories — registered by `kind` string. Must happen
        // before load_config so the manager can instantiate plugins whose
        // YAML `kind:` matches.
        inner.manager.register_factory(
            apl_pii_scanner::KIND,
            Box::new(apl_pii_scanner::PiiScannerFactory),
        );
        inner.manager.register_factory(
            apl_audit_logger::KIND,
            Box::new(apl_audit_logger::AuditLoggerFactory),
        );
        inner.manager.register_factory(
            apl_identity_jwt::KIND,
            Box::new(apl_identity_jwt::JwtIdentityFactory),
        );
        inner.manager.register_factory(
            apl_delegator_oauth::KIND,
            Box::new(apl_delegator_oauth::OAuthDelegatorFactory),
        );

        // APL config visitor + PDP factories. `pdp_factories` are consulted
        // for `global.apl.pdp[]` entries; cedar-direct is the bundled
        // default. The visitor keeps a Weak<PluginManager> (see
        // CpexManagerInner) that upgrades during load_config_yaml.
        let mut opts = apl_cpex::AplOptions::in_process();
        opts.pdp_factories =
            vec![Arc::new(apl_pdp_cedar_direct::CedarDirectPdpFactory::new())];

        apl_cpex::register_apl(&inner.manager, opts);
    }));

    match result {
        Ok(()) => RC_OK,
        Err(_panic) => {
            tracing::error!("cpex_apl_install: panic caught at FFI boundary");
            RC_PANIC
        }
    }
}
