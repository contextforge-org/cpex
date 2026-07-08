// Location: ./crates/cpex/src/lib.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo

//! **CPEX is a policy enforcement runtime for AI agents.**
//!
//! It is a deterministic reference monitor between an agent and every
//! capability it invokes: tools, prompts, resources, inference providers, and
//! A2A methods. Each operation runs through a policy-defined pipeline that can
//! resolve identity, make an authorization decision (delegated to an engine
//! like Cedar or CEL), exchange and reduce credentials before a downstream
//! call, redact inputs and outputs, track information flow across calls, and
//! audit. You write that policy declaratively in APL, the configuration that
//! defines each operation's pipeline; CPEX evaluates and enforces it at the
//! boundary, against state the model cannot observe or forge.
//!
//! - Guide and concepts: <https://contextforge-org.github.io/cpex/>
//! - Source and issues: <https://github.com/contextforge-org/cpex>
//!
//! # This crate
//!
//! `cpex` is the **host facade**: one dependency that re-exports the CPEX
//! runtime (`cpex-core`, `apl-core`, `apl-cmf`, `apl-cpex`), so a host depends
//! on this crate instead of pinning each of them separately.
//!
//! By default it is the **engine only**: no builtin plugins are compiled in.
//! The bundled extension set lives in [`cpex-builtins`](cpex_builtins) and is
//! pulled in only when a builtins feature is enabled.
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
