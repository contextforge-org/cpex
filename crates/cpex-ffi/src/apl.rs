// Location: ./crates/cpex-ffi/src/apl.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// Builtin, transport and secret-provider wiring for the FFI.
//
// `cpex_apl_install` registers PPE's bundled plugin, PDP and session-store
// factories, installs the APL config visitor, installs one outbound HTTP
// transport, and registers the secret providers (env, file, Vault) with
// that same transport. A later `cpex_load_config` then walks `apl:` blocks
// and installs per-route handlers.
//
// Registration is explicit (no inventory/ctor magic): PPE's
// `install_builtins` expands to explicit `register_factory` calls, so the
// object code survives in `libcpex_ffi.a`.
//
// Ordering: call AFTER `cpex_engine_new_default` and BEFORE
// `cpex_load_config`. The config visitor must be registered before the
// config is loaded, and the one-shot `cpex_engine_new(yaml)` path loads
// during construction, so builtins are only available via the default
// engine flow:
//
//   cpex_engine_new_default
//     -> cpex_apl_install
//       -> cpex_load_config
//         -> cpex_initialize

use std::os::raw::c_int;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use praxis_policy::{HyperTransport, install_builtins, registry_with_vault};
use praxis_policy_core::http::HttpTransport;

use crate::{CpexEngineInner, RC_INVALID_HANDLE, RC_INVALID_INPUT, RC_OK, RC_PANIC};

/// `cpex_apl_install` flag: let builtins reach private, loopback and
/// link-local destinations (for example a JWKS endpoint on localhost or
/// an in-cluster Vault). Off by default, which blocks them. This is a
/// host decision; no policy document can turn it on.
pub const CPEX_APL_ALLOW_PRIVATE_DESTINATIONS: u32 = 1;

/// Every flag bit this build understands. Any other bit is rejected with
/// `RC_INVALID_INPUT`, so a host built against a newer flag set fails
/// loudly instead of silently losing a setting.
pub const CPEX_APL_KNOWN_FLAGS: u32 = CPEX_APL_ALLOW_PRIVATE_DESTINATIONS;

/// Install the bundled builtins, the outbound HTTP transport, and the
/// secret providers on `handle`.
///
/// What it installs:
///   - plugin factories: `identity/jwt`, `identity/api-key`,
///     `delegator/oauth`, `elicitation/ciba`
///   - PDP factories for `global.apl.pdp[]`: `cedar-direct`, `cel`, `opa`
///   - session store factory for `global.apl.session_store`: `valkey`
///     (the in-process memory store stays the default)
///   - the APL config visitor
///   - one `HyperTransport` for builtins that declare `perform_http`
///   - secret providers `env`, `file` and `vault`, with Vault using the
///     same transport instance
///
/// `flags` is a bit set of `CPEX_APL_*` values. With
/// `CPEX_APL_ALLOW_PRIVATE_DESTINATIONS` set, the transport may reach
/// private and loopback addresses; without it, such requests are refused
/// and builtins report their egress-denied codes.
///
/// Idempotent per handle: once a call has succeeded or started, later
/// calls do nothing and return `RC_OK`, whatever their flags. The
/// transport and the secret providers are set-once on the engine; if the
/// host already installed either through Rust, the existing one is kept
/// and a warning is logged.
///
/// Returns `RC_OK` on success, `RC_INVALID_HANDLE` if `handle` is null,
/// `RC_INVALID_INPUT` for an unknown flag bit, or `RC_PANIC` if
/// registration panicked (caught at the FFI boundary).
///
/// # Safety
/// `handle` must be a valid handle returned by `cpex_engine_new_default`
/// (or `cpex_engine_new`) and not yet shut down.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cpex_apl_install(handle: *const CpexEngineInner, flags: u32) -> c_int {
    // SAFETY: the caller guarantees `handle` is NULL or a live handle.
    let inner = match unsafe { handle.as_ref() } {
        Some(h) => h,
        None => return RC_INVALID_HANDLE,
    };
    if flags & !CPEX_APL_KNOWN_FLAGS != 0 {
        tracing::error!(
            "cpex_apl_install: unknown flag bits {:#x}",
            flags & !CPEX_APL_KNOWN_FLAGS
        );
        return RC_INVALID_INPUT;
    }

    // Held for the whole install so a concurrent second call waits and
    // then sees the flag, rather than racing ahead to load a config
    // before the factories exist. A poisoned lock means an earlier
    // install panicked part way; treat it as installed.
    let mut installed = match inner.installed.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    if *installed {
        return RC_OK;
    }
    // Set before the work so a panic part way does not let a retry
    // register a second APL visitor.
    *installed = true;

    let allow_private = flags & CPEX_APL_ALLOW_PRIVATE_DESTINATIONS != 0;
    let result = catch_unwind(AssertUnwindSafe(|| {
        install_builtins(&inner.engine);

        let mut hyper = HyperTransport::new();
        if allow_private {
            hyper = hyper.with_allow_private_destinations();
        }
        let transport: Arc<dyn HttpTransport> = Arc::new(hyper);
        // Both setters are set-once and log their own warning when a
        // transport or registry is already present.
        let _ = inner.engine.set_http_transport(Arc::clone(&transport));
        let _ = inner
            .engine
            .set_secret_providers(registry_with_vault(transport));
    }));

    match result {
        Ok(()) => RC_OK,
        Err(_panic) => {
            tracing::error!("cpex_apl_install: panic caught at FFI boundary");
            RC_PANIC
        },
    }
}
