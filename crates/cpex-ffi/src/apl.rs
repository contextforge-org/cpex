// Location: ./crates/cpex-ffi/src/apl.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// APL (Authorization Policy Language) FFI wiring.
//
// `cpex_apl_install` registers the bundled APL plugin factories and
// installs the APL config visitor on a manager so that a subsequent
// `cpex_load_config` walks `apl:` blocks and installs per-route handlers.
//
// Registration is explicit (no inventory/ctor magic): it delegates to
// `cpex_builtins`, whose `register_builtins` / `builtin_pdps` expand to
// explicit `register_factory` / factory-construction calls, so the object
// code survives in `libcpex_ffi.a`. Which factories are bundled is the
// `cpex-builtins` feature set selected in this crate's Cargo.toml.
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

use crate::{CpexManagerInner, RC_INVALID_HANDLE, RC_OK, RC_PANIC};

/// Register the bundled APL plugin factories and install the APL config
/// visitor (in-process defaults: memory session store, default baseline
/// capabilities) on `mgr`.
///
/// Bundled plugin factories (registered by `kind`, via cpex-builtins):
///   - `validator/pii-scan`  → pii-scanner
///   - `audit/logger`        → audit-logger
///   - `identity/jwt`        → identity-jwt
///   - `delegator/oauth`     → delegator-oauth
///
/// Bundled PDP factories (consulted for `global.apl.pdp[]` entries):
///   - `cedar-direct`        → cedar-direct
///   - `cel`                 → cel
///
/// Bundled session store factory (consulted for `global.apl.session_store`):
///   - `valkey`              → Valkey-backed SessionStore
///
/// The default in-process `MemorySessionStore` stays active unless the config
/// selects a `session_store`.
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
        // YAML `kind:` matches. Delegated to cpex-builtins, whose enabled
        // feature set determines the bundle.
        cpex_builtins::register_builtins(&inner.manager);

        // APL config visitor + PDP / session-store factories. The factory
        // sets are consulted for `global.apl.pdp[]` and
        // `global.apl.session_store` entries; cedar-direct and cel are the
        // bundled PDPs and the Valkey session-store factory is bundled too.
        // Unless the config selects a `session_store`, the in-process
        // MemorySessionStore default stays active. The visitor keeps a
        // Weak<PluginManager> (see CpexManagerInner) that upgrades during
        // load_config_yaml.
        let mut opts = apl_cpex::AplOptions::in_process();
        opts.pdp_factories = cpex_builtins::builtin_pdps();
        opts.session_store_factories = cpex_builtins::builtin_session_store_factories();

        apl_cpex::register_apl(&inner.manager, opts);
    }));

    match result {
        Ok(()) => RC_OK,
        Err(_panic) => {
            tracing::error!("cpex_apl_install: panic caught at FFI boundary");
            RC_PANIC
        },
    }
}
