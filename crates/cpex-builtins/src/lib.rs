// Location: ./crates/cpex-builtins/src/lib.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo

//! CPEX built-in extension set.
//!
//! One crate that bundles the first-party plugins, PDPs, and session
//! stores, each behind a cargo feature. A host depends on `cpex-builtins`
//! (directly, or transitively through the `cpex` facade) and selects what
//! compiles in via the feature list:
//!
//! ```toml
//! # the in-process default set
//! cpex-builtins = "0.2"
//! # a minimal subset
//! cpex-builtins = { version = "0.2", default-features = false, features = ["pii-scanner"] }
//! ```
//!
//! Then [`install_builtins`] registers every enabled factory and installs
//! the APL config visitor in one call, or use the building blocks
//! ([`register_builtins`], [`builtin_pdps`],
//! [`builtin_session_store_factories`]) to assemble an [`AplOptions`]
//! yourself.
//!
//! Registration is **explicit** (the [`register_builtins`] macro expands to
//! `#[cfg]`-gated `register_factory` calls), not `inventory`/`linkme`-style
//! link-section discovery — so the factory symbols survive the linker's
//! dead-code GC when this crate is compiled into the `cpex-ffi` staticlib.

use std::sync::Arc;

use apl_core::step::PdpFactory;
use apl_cpex::{register_apl, AplOptions, SessionStoreFactory};
use cpex_core::manager::PluginManager;

// -----------------------------------------------------------------------------
// Feature-gated re-exports of each builtin's factory + KIND
// -----------------------------------------------------------------------------

#[cfg(feature = "cedar-direct")]
pub use cpex_pdp_cedar_direct::CedarDirectPdpFactory;
#[cfg(feature = "cel")]
pub use cpex_pdp_cel::CelPdpFactory;
#[cfg(feature = "audit-logger")]
pub use cpex_plugin_audit_logger::{AuditLoggerFactory, KIND as AUDIT_KIND};
#[cfg(feature = "delegator-oauth")]
pub use cpex_plugin_delegator_oauth::{OAuthDelegatorFactory, KIND as OAUTH_KIND};
#[cfg(feature = "elicitation-ciba")]
pub use cpex_plugin_elicitation_ciba::{CibaApproverFactory, KIND as CIBA_KIND};
#[cfg(feature = "identity-jwt")]
pub use cpex_plugin_identity_jwt::{JwtIdentityFactory, KIND as JWT_KIND};
#[cfg(feature = "pii-scanner")]
pub use cpex_plugin_pii_scanner::{PiiScannerFactory, KIND as PII_KIND};
#[cfg(feature = "valkey")]
pub use cpex_session_valkey::{ValkeyConfig, ValkeySessionStoreFactory, KIND as VALKEY_KIND};

// -----------------------------------------------------------------------------
// Plugin-factory registration (by-kind axis)
// -----------------------------------------------------------------------------

/// Generate [`register_builtins`] from a feature → factory table. Each entry
/// expands to a `#[cfg(feature = ...)]`-gated, **explicit**
/// `register_factory(KIND, Box::new(Factory))` call keyed off the builtin
/// crate's own `KIND` const.
///
/// Explicit calls (vs `inventory`/`linkme` link-section registration) are
/// deliberate: in the `cpex-ffi` staticlib the linker GCs sections nothing
/// references, which would silently drop auto-registered plugins. Naming
/// each factory here keeps its object code alive.
macro_rules! register_builtins {
    ( $( feature $feat:literal => $krate:ident :: $factory:ident ),* $(,)? ) => {
        /// Register every enabled by-kind plugin factory on `mgr`: identity
        /// (`identity-jwt`), delegators (`delegator-oauth`), validators
        /// (`pii-scanner`), and observers (`audit-logger`). Call before
        /// loading a config so the manager can instantiate plugins whose
        /// YAML `kind:` matches.
        ///
        /// PDP and session-store factories are wired through [`AplOptions`]
        /// instead; see [`builtin_pdps`] and
        /// [`builtin_session_store_factories`], or use [`install_builtins`].
        #[allow(unused_variables)]
        pub fn register_builtins(mgr: &Arc<PluginManager>) {
            $(
                #[cfg(feature = $feat)]
                mgr.register_factory($krate::KIND, Box::new($krate::$factory));
            )*
        }
    };
}

register_builtins! {
    feature "identity-jwt"     => cpex_plugin_identity_jwt::JwtIdentityFactory,
    feature "delegator-oauth"  => cpex_plugin_delegator_oauth::OAuthDelegatorFactory,
    feature "elicitation-ciba" => cpex_plugin_elicitation_ciba::CibaApproverFactory,
    feature "pii-scanner"      => cpex_plugin_pii_scanner::PiiScannerFactory,
    feature "audit-logger"     => cpex_plugin_audit_logger::AuditLoggerFactory,
}

// -----------------------------------------------------------------------------
// PDP-factory and session-store axes
// -----------------------------------------------------------------------------

/// The enabled PDP factories, ready to drop into
/// [`AplOptions::pdp_factories`]. A route's `cedar:` or `cel:` step selects
/// which one runs.
// `vec![]` can't replace the conditional pushes: each element is
// `#[cfg]`-gated on its feature, so the set is built incrementally.
#[allow(unused_mut, clippy::vec_init_then_push)]
pub fn builtin_pdps() -> Vec<Arc<dyn PdpFactory>> {
    let mut factories: Vec<Arc<dyn PdpFactory>> = Vec::new();
    #[cfg(feature = "cedar-direct")]
    factories.push(Arc::new(cpex_pdp_cedar_direct::CedarDirectPdpFactory::new()));
    #[cfg(feature = "cel")]
    factories.push(Arc::new(cpex_pdp_cel::CelPdpFactory::new()));
    factories
}

/// The enabled session-store factories, ready to drop into
/// [`AplOptions::session_store_factories`]. A `global.apl.session_store:
/// { kind: ... }` config block selects one; absent that, the in-process
/// `MemorySessionStore` default stays active.
#[allow(unused_mut, clippy::vec_init_then_push)]
pub fn builtin_session_store_factories() -> Vec<Arc<dyn SessionStoreFactory>> {
    let mut factories: Vec<Arc<dyn SessionStoreFactory>> = Vec::new();
    #[cfg(feature = "valkey")]
    factories.push(Arc::new(
        cpex_session_valkey::ValkeySessionStoreFactory::new(),
    ));
    factories
}

// -----------------------------------------------------------------------------
// One-call install
// -----------------------------------------------------------------------------

/// Register every enabled plugin factory and install the APL config visitor
/// on `mgr` with in-process defaults (a `MemorySessionStore` and the default
/// baseline capabilities). The enabled PDP and session-store factories are
/// wired in, so a later config load can reference any of them by `kind`.
///
/// This is the one-call path; reach for [`register_builtins`] and
/// [`AplOptions`] directly when you need to customize capabilities or the
/// default store.
pub fn install_builtins(mgr: &Arc<PluginManager>) {
    register_builtins(mgr);

    let mut opts = AplOptions::in_process();
    opts.pdp_factories = builtin_pdps();
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
        let expected = cfg!(feature = "cedar-direct") as usize + cfg!(feature = "cel") as usize;
        assert_eq!(
            builtin_pdps().len(),
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
