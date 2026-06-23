// Location: ./crates/cpex/src/lib.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo

//! CPEX host facade.
//!
//! A single dependency that re-exports the CPEX host runtime and the
//! bundled APL plugin factories, each behind a cargo feature. Hosts
//! depend on this crate instead of pinning `apl-cmf`, `apl-cpex`,
//! `apl-pdp-*`, `apl-session-*`, and friends one by one.
//!
//! # Usage
//!
//! ```toml
//! cpex = { version = "0.2.0", features = ["jwt", "oauth", "cedar", "cel", "valkey"] }
//! ```
//!
//! ```no_run
//! use std::sync::Arc;
//! use cpex::PluginManager;
//!
//! let mgr = Arc::new(PluginManager::default());
//! // Register every enabled plugin factory and install the APL config
//! // visitor (in-process defaults) in one call:
//! cpex::install_builtins(&mgr);
//! // ... then load a config that references the enabled `kind`s.
//! ```
//!
//! For finer control, the building blocks are public:
//! [`register_builtin_plugins`] registers the by-kind plugin factories,
//! [`builtin_pdp_factories`] / [`builtin_session_store_factories`] return
//! the enabled factories for an [`AplOptions`] you assemble yourself, and
//! every concrete factory type is re-exported under its feature.
//!
//! # Features
//!
//! `jwt`, `oauth`, `pii`, `audit`, `cedar`, `cel` are on by default.
//! `valkey` (Valkey-backed session store; pulls a redis client and a
//! rustls TLS stack) is opt-in. `full` enables everything.

use std::sync::Arc;

// -----------------------------------------------------------------------------
// Host runtime re-exports (always available)
// -----------------------------------------------------------------------------

// Whole-crate re-exports for advanced use (types not surfaced below).
pub use {apl_cmf, apl_core, apl_cpex, cpex_core};

pub use apl_core::step::PdpFactory;
pub use apl_cpex::{
    register_apl, AplOptions, DispatchCache, MemorySessionStore, SessionStore, SessionStoreFactory,
};
pub use cpex_core::manager::PluginManager;

// -----------------------------------------------------------------------------
// Bundled plugin factories (feature-gated)
// -----------------------------------------------------------------------------

#[cfg(feature = "audit")]
pub use apl_audit_logger::{AuditLoggerFactory, KIND as AUDIT_KIND};
#[cfg(feature = "oauth")]
pub use apl_delegator_oauth::{OAuthDelegatorFactory, KIND as OAUTH_KIND};
#[cfg(feature = "jwt")]
pub use apl_identity_jwt::{JwtIdentityFactory, KIND as JWT_KIND};
#[cfg(feature = "cedar")]
pub use apl_pdp_cedar_direct::CedarDirectPdpFactory;
#[cfg(feature = "cel")]
pub use apl_pdp_cel::CelPdpFactory;
#[cfg(feature = "pii")]
pub use apl_pii_scanner::{PiiScannerFactory, KIND as PII_KIND};
#[cfg(feature = "valkey")]
pub use apl_session_valkey::{ValkeyConfig, ValkeySessionStoreFactory, KIND as VALKEY_KIND};

// -----------------------------------------------------------------------------
// Registration helpers
// -----------------------------------------------------------------------------

/// Register every enabled by-kind plugin factory on `mgr`: identity
/// (`jwt`), delegators (`oauth`), validators (`pii`), and observers
/// (`audit`). Call before loading a config so the manager can
/// instantiate plugins whose YAML `kind:` matches.
///
/// PDP and session-store factories are wired through [`AplOptions`]
/// instead; see [`builtin_pdp_factories`] and
/// [`builtin_session_store_factories`], or use [`install_builtins`].
#[allow(unused_variables)]
pub fn register_builtin_plugins(mgr: &Arc<PluginManager>) {
    #[cfg(feature = "jwt")]
    mgr.register_factory(JWT_KIND, Box::new(JwtIdentityFactory));
    #[cfg(feature = "oauth")]
    mgr.register_factory(OAUTH_KIND, Box::new(OAuthDelegatorFactory));
    #[cfg(feature = "pii")]
    mgr.register_factory(PII_KIND, Box::new(PiiScannerFactory));
    #[cfg(feature = "audit")]
    mgr.register_factory(AUDIT_KIND, Box::new(AuditLoggerFactory));
}

/// The enabled PDP factories, ready to drop into
/// [`AplOptions::pdp_factories`]. A route's `cedar:` or `cel:` step
/// selects which one runs.
// `vec![]` can't replace the conditional pushes: each element is
// `#[cfg]`-gated on its feature, so the set is built incrementally.
#[allow(unused_mut, clippy::vec_init_then_push)]
pub fn builtin_pdp_factories() -> Vec<Arc<dyn PdpFactory>> {
    let mut factories: Vec<Arc<dyn PdpFactory>> = Vec::new();
    #[cfg(feature = "cedar")]
    factories.push(Arc::new(CedarDirectPdpFactory::new()));
    #[cfg(feature = "cel")]
    factories.push(Arc::new(CelPdpFactory::new()));
    factories
}

/// The enabled session-store factories, ready to drop into
/// [`AplOptions::session_store_factories`]. A `global.session_store:
/// { kind: ... }` config block selects one; absent that, the
/// [`MemorySessionStore`] default stays active.
#[allow(unused_mut, clippy::vec_init_then_push)]
pub fn builtin_session_store_factories() -> Vec<Arc<dyn SessionStoreFactory>> {
    let mut factories: Vec<Arc<dyn SessionStoreFactory>> = Vec::new();
    #[cfg(feature = "valkey")]
    factories.push(Arc::new(ValkeySessionStoreFactory::new()));
    factories
}

/// Register every enabled plugin factory and install the APL config
/// visitor on `mgr` with in-process defaults (a [`MemorySessionStore`]
/// and the default baseline capabilities). The enabled PDP and
/// session-store factories are wired in, so a later config load can
/// reference any of them by `kind`.
///
/// This is the one-call path; reach for [`register_builtin_plugins`] and
/// [`AplOptions`] directly when you need to customize capabilities or the
/// default store.
pub fn install_builtins(mgr: &Arc<PluginManager>) {
    register_builtin_plugins(mgr);

    let mut opts = AplOptions::in_process();
    opts.pdp_factories = builtin_pdp_factories();
    opts.session_store_factories = builtin_session_store_factories();

    let _visitor = register_apl(mgr, opts);
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_builtins_runs_without_panic() {
        let mgr = Arc::new(PluginManager::default());
        install_builtins(&mgr);
    }

    #[test]
    fn pdp_factories_track_enabled_features() {
        let expected = cfg!(feature = "cedar") as usize + cfg!(feature = "cel") as usize;
        assert_eq!(
            builtin_pdp_factories().len(),
            expected,
            "one PDP factory per enabled feature",
        );
    }

    #[test]
    fn session_store_factories_track_enabled_features() {
        let expected = cfg!(feature = "valkey") as usize;
        assert_eq!(
            builtin_session_store_factories().len(),
            expected,
            "one session-store factory per enabled feature",
        );
    }
}
