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
//! pulled in only when a builtins feature is enabled. The out-of-process
//! Python plugin host is separate again, behind `python-host`.
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
//!
//! `python-host` is orthogonal to all of those, and is in neither `builtins`
//! nor `full`. It pulls
//! [`cpex-hosts-python`](cpex_hosts_python), which runs existing Python CPEX
//! plugins out-of-process — one cached virtualenv and one `worker.py`
//! subprocess per plugin — and re-exports [`IsolatedVenvFactory`] and
//! [`ISOLATED_VENV_KIND`] here. Unlike the builtins there is no
//! `install_*` helper: register the factory yourself, because the `kind` is
//! one host serving arbitrarily many Python plugins.
//!
//! ```ignore
//! use cpex::{IsolatedVenvFactory, PluginManager, ISOLATED_VENV_KIND};
//! use cpex::cpex_core::factory::PluginFactoryRegistry;
//!
//! let mut factories = PluginFactoryRegistry::new();
//! factories.register(ISOLATED_VENV_KIND, Box::new(IsolatedVenvFactory));
//! let mgr = PluginManager::from_config(config, &factories)?;
//! // `initialize()` builds each venv and launches its worker — a cold pip
//! // install is measured in minutes, so do it at startup, not on demand.
//! mgr.initialize().await?;
//! ```

// Whole-crate re-exports for advanced use (types not surfaced below).
pub use {apl_cmf, apl_core, apl_cpex, cpex_core};

pub use apl_core::step::PdpFactory;
pub use apl_cpex::{
    register_apl, AplOptions, DispatchCache, MemorySessionStore, SessionStore, SessionStoreFactory,
};
pub use cpex_core::manager::PluginManager;

// The whole aggregator, for advanced use.
#[cfg(feature = "cpex-builtins")]
pub use cpex_builtins;
// The whole Python host crate, for advanced use (venv and worker internals).
#[cfg(feature = "python-host")]
pub use cpex_hosts_python;

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
// The Python host's `KIND` is renamed on re-export: bare `KIND` at the facade
// root says nothing about which plugin kind it is, and the builtins above all
// use a prefixed const.
#[cfg(feature = "python-host")]
pub use cpex_hosts_python::{IsolatedVenvFactory, KIND as ISOLATED_VENV_KIND};

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
#[cfg(all(test, feature = "python-host"))]
mod python_host_tests {
    use super::*;
    use cpex_core::config::parse_config;
    use cpex_core::factory::PluginFactoryRegistry;

    /// A config with one `isolated_venv` plugin, mirroring the YAML shape an
    /// operator writes. No `plugin_dirs`: the host always resolves
    /// `<project root>/plugins` — see `plugin::DEFAULT_PLUGIN_DIR`.
    fn minimal_config_yaml() -> &'static str {
        r#"
plugins:
  - name: pii-filter
    kind: isolated_venv
    hooks: [tool_pre_invoke]
    config:
      class_name: my_pkg.filters.PiiFilter
"#
    }

    /// The facade's re-exported `IsolatedVenvFactory` and kind const are
    /// wired up well enough to instantiate a plugin from config. This stops
    /// at `from_config` deliberately — `initialize()` is what builds the venv
    /// and spawns `worker.py`, which needs a real interpreter and a real
    /// package, so it belongs in cpex-hosts-python's integration tests.
    #[test]
    fn from_config_instantiates_the_python_host() {
        let config = parse_config(minimal_config_yaml()).expect("valid YAML");

        let mut factories = PluginFactoryRegistry::new();
        factories.register(ISOLATED_VENV_KIND, Box::new(IsolatedVenvFactory));

        let mgr = PluginManager::from_config(config, &factories)
            .expect("isolated_venv factory is registered, so instantiation succeeds");

        assert_eq!(mgr.plugin_count(), 1);
        assert!(mgr.has_hooks_for("tool_pre_invoke"));
    }
}
