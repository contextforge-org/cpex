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
// that same transport, through `cpex::host::install_host_defaults`. A later
// `cpex_load_config` then walks `apl:` blocks and installs per-route
// handlers.
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

use crate::{CpexEngineInner, RC_INVALID_HANDLE, RC_INVALID_INPUT, RC_OK, RC_PANIC};

/// Where `cpex_apl_install` stands on one handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum InstallState {
    /// No install has run yet.
    #[default]
    NotInstalled,
    /// An install completed.
    Installed,
    /// An install panicked part way. What it left behind is unknown, and a
    /// retry could register a second APL visitor, so the state is final.
    Failed,
}

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
///   - PDP factories for `global.pdp[]`: `cedar-direct`, `cel`, `opa`
///   - session store factory for `global.session_store`: `valkey`
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
/// Idempotent per handle: once a call has succeeded, later calls do
/// nothing and return `RC_OK`, whatever their flags. A call that panicked
/// leaves the engine in an unknown state, so it stays failed: every later
/// call returns `RC_PANIC` and the host should discard the engine. The
/// transport and the secret providers are set-once on the engine; if the
/// host already installed either through Rust, the existing one is kept
/// and a warning is logged.
///
/// Returns `RC_OK` on success, `RC_INVALID_HANDLE` if `handle` is null,
/// `RC_INVALID_INPUT` for an unknown flag bit, or `RC_PANIC` if this or
/// an earlier install on the handle panicked (caught at the FFI
/// boundary).
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
    // then sees the outcome, rather than racing ahead to load a config
    // before the factories exist. The install runs under catch_unwind, so
    // the lock is not poisoned by it; recover the state either way.
    let mut state = match inner.install_state.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    match *state {
        InstallState::Installed => return RC_OK,
        InstallState::Failed => {
            tracing::error!(
                "cpex_apl_install: an earlier install on this handle panicked; discard the engine"
            );
            return RC_PANIC;
        },
        InstallState::NotInstalled => {},
    }

    let allow_private = flags & CPEX_APL_ALLOW_PRIVATE_DESTINATIONS != 0;
    let result = catch_unwind(AssertUnwindSafe(|| {
        #[cfg(test)]
        if inner
            .fail_install
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            panic!("injected install failure");
        }
        cpex::host::install_host_defaults(&inner.engine, allow_private);
    }));

    match result {
        Ok(()) => {
            *state = InstallState::Installed;
            RC_OK
        },
        Err(_panic) => {
            *state = InstallState::Failed;
            tracing::error!("cpex_apl_install: panic caught at FFI boundary");
            RC_PANIC
        },
    }
}
