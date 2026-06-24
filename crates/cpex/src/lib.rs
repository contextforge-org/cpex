// Location: ./crates/cpex/src/lib.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo

//! CPEX host facade.
//!
//! A single dependency that re-exports the CPEX host runtime, so hosts
//! depend on this crate instead of pinning `apl-cmf`, `apl-cpex`, and
//! `cpex-core` one by one.
//!
//! By default this is the **engine only** — no builtin plugins are compiled
//! in. The bundled extension set lives in [`cpex-builtins`](cpex_builtins)
//! and is pulled in only when a builtins feature is enabled.
//!
//! # Usage
//!
//! Engine only (register your own factories):
//!
//! ```no_run
//! use std::sync::Arc;
//! use cpex::PluginManager;
//!
//! let mgr = Arc::new(PluginManager::default());
//! // ... register host factories, then `apl_cpex::register_apl(&mgr, opts)`.
//! ```
//!
//! With the bundled builtins (enable the `builtins` or `full` feature):
//!
//! ```ignore
//! use std::sync::Arc;
//! use cpex::PluginManager;
//!
//! let mgr = Arc::new(PluginManager::default());
//! // Register every enabled builtin factory and install the APL config
//! // visitor (in-process defaults) in one call:
//! cpex::install_builtins(&mgr);
//! // ... then load a config that references the enabled `kind`s.
//! ```
//!
//! # Features
//!
//! No plugins are on by default (`cpex = "0.2"` is the engine alone).
//! `builtins` enables the common in-process set; `full` adds the Valkey
//! session store; or pick a granular subset (`jwt`, `oauth`, `pii`,
//! `audit`, `cedar`, `cel`, `valkey`). When any builtins feature is on, the
//! registration helpers and the concrete factory types are re-exported here
//! from [`cpex-builtins`](cpex_builtins).

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
// Bundled extensions (only when a builtins feature pulls in cpex-builtins)
// -----------------------------------------------------------------------------

// The whole aggregator, for advanced use.
#[cfg(feature = "cpex-builtins")]
pub use cpex_builtins;

// Registration helpers — delegated to cpex-builtins, keeping the facade's
// historical names (`register_builtin_plugins`, `builtin_pdp_factories`).
#[cfg(feature = "cpex-builtins")]
pub use cpex_builtins::{
    builtin_pdps as builtin_pdp_factories, builtin_session_store_factories, install_builtins,
    register_builtins as register_builtin_plugins,
};

// Concrete factory types + KIND consts, each behind its facade feature
// (which forwards to the matching cpex-builtins feature).
#[cfg(feature = "cedar")]
pub use cpex_builtins::CedarDirectPdpFactory;
#[cfg(feature = "cel")]
pub use cpex_builtins::CelPdpFactory;
#[cfg(feature = "audit")]
pub use cpex_builtins::{AuditLoggerFactory, AUDIT_KIND};
#[cfg(feature = "jwt")]
pub use cpex_builtins::{JwtIdentityFactory, JWT_KIND};
#[cfg(feature = "oauth")]
pub use cpex_builtins::{OAuthDelegatorFactory, OAUTH_KIND};
#[cfg(feature = "pii")]
pub use cpex_builtins::{PiiScannerFactory, PII_KIND};
#[cfg(feature = "valkey")]
pub use cpex_builtins::{ValkeyConfig, ValkeySessionStoreFactory, VALKEY_KIND};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(all(test, feature = "cpex-builtins"))]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn install_builtins_runs_without_panic() {
        let mgr = Arc::new(PluginManager::default());
        install_builtins(&mgr);
    }
}
