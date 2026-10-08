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
//! like Cedar, CEL or OPA), exchange and reduce credentials before a downstream
//! call, track information flow across calls, and audit. You write that policy
//! declaratively in APL, the configuration that defines each operation's
//! pipeline; CPEX evaluates and enforces it at the boundary, against state the
//! model cannot observe or forge.
//!
//! - Guide and concepts: <https://contextforge-org.github.io/cpex/>
//! - Source and issues: <https://github.com/contextforge-org/cpex>
//!
//! # This crate
//!
//! `cpex` is the **host facade** over the praxis-policy engine (PPE). It
//! re-exports the whole public surface of [`praxis_policy`], built with every
//! stable builtin and the bundled hyper HTTP transport, so a host depends on
//! this one crate. Every item documented on `praxis_policy` is reachable here
//! under the same name: [`PolicyEngine`], [`install_builtins`], [`prelude`],
//! [`AplOptions`], the builtin factory types, [`HyperTransport`] and
//! [`install_default_http_transport`].
//!
//! Two CPEX-only additions sit on top: the [`host`] module, which holds the
//! wiring the C FFI and the Python wheel share ([`host::install_host_defaults`],
//! [`host::secret_error_kind`], the [`host::REMOVED_HOOKS`] table and the
//! inbound identity check), and the out-of-process Python plugin host, behind
//! the `python-host` feature.
//!
//! # Usage
//!
//! ```no_run
//! use std::sync::Arc;
//! use cpex::PolicyEngine;
//!
//! let engine = Arc::new(PolicyEngine::default());
//! // Register every builtin factory and install the APL config visitor
//! // (in-process defaults) in one call:
//! cpex::install_builtins(&engine);
//! // Builtins that call out over HTTP (JWKS, token exchange, CIBA, Vault)
//! // need a transport. The bundled one refuses private destinations.
//! cpex::install_default_http_transport(&engine);
//! // ... then load a config that references the builtin `kind`s.
//! ```
//!
//! # Features
//!
//! Every stable PPE builtin is always compiled in. The PII scanner and audit
//! logger are not builtins: they are reference plugins a host registers
//! itself.
//!
//! `python-host` pulls `cpex-hosts-python`, which runs existing Python CPEX
//! plugins out-of-process (one cached virtualenv and one `worker.py`
//! subprocess per plugin), and re-exports `IsolatedVenvFactory` and
//! `ISOLATED_VENV_KIND` here. There is no `install_*` helper for it:
//! register the factory yourself, because the `kind` is one host serving
//! arbitrarily many Python plugins.
//!
//! ```ignore
//! use std::sync::Arc;
//! use cpex::{IsolatedVenvFactory, PolicyEngine, ISOLATED_VENV_KIND};
//!
//! let engine = Arc::new(PolicyEngine::default());
//! engine.register_factory(ISOLATED_VENV_KIND, Box::new(IsolatedVenvFactory));
//! engine.load_config_yaml(yaml)?;
//! // `initialize()` builds each venv and launches its worker. A cold pip
//! // install is measured in minutes, so do it at startup, not on demand.
//! engine.initialize().await?;
//! ```

pub mod host;

// The engine's facade, whole and by name, so `cpex::X` resolves for every
// public `praxis_policy::X`.
pub use praxis_policy;
pub use praxis_policy::*;

// The whole Python host crate, for advanced use (venv and worker internals).
#[cfg(feature = "python-host")]
pub use cpex_hosts_python;
// The Python host's `KIND` is renamed on re-export: bare `KIND` at the facade
// root says nothing about which plugin kind it is, and the builtins all use a
// prefixed const.
#[cfg(feature = "python-host")]
pub use cpex_hosts_python::{IsolatedVenvFactory, KIND as ISOLATED_VENV_KIND};

#[cfg(test)]
mod tests {
    use super::*;
    use praxis_policy_core::config::parse_config;
    use std::sync::Arc;

    #[test]
    fn install_builtins_runs_without_panic() {
        let engine = Arc::new(PolicyEngine::default());
        install_builtins(&engine);
    }

    /// A config written against the engine's own schema parses into a
    /// `PolicyConfig` through the facade's re-exported core crate.
    #[test]
    fn policy_config_parses_through_the_facade() {
        let config = parse_config(
            r#"
plugins:
  - name: jwt
    kind: identity/jwt
    hooks: [identity.resolve]
"#,
        )
        .expect("valid config");
        assert_eq!(config.plugins.len(), 1);
        assert_eq!(config.plugins[0].hooks, vec!["identity.resolve".to_owned()]);
    }

    /// The engine rejects the unprefixed hook names older CPEX configs used.
    #[test]
    fn legacy_hook_name_is_rejected() {
        let engine = Arc::new(PolicyEngine::default());
        install_builtins(&engine);
        let err = engine
            .load_config_yaml(
                r#"
plugins:
  - name: jwt
    kind: identity/jwt
    hooks: [tool_pre_invoke]
"#,
            )
            .expect_err("legacy hook names are removed");
        let err = err.to_string();
        assert!(err.contains("'cmf.tool_pre_invoke'"), "{err}");
    }
}

#[cfg(all(test, feature = "python-host"))]
mod python_host_tests {
    use super::*;
    use praxis_policy_core::config::parse_config;
    use praxis_policy_core::factory::PluginFactoryRegistry;

    /// A config with one `isolated_venv` plugin, mirroring the YAML shape an
    /// operator writes. No `plugin_dirs`: the host always resolves
    /// `<project root>/plugins`.
    fn minimal_config_yaml() -> &'static str {
        r#"
engine_settings:
  dispatch: hooks
plugins:
  - name: pii-filter
    kind: isolated_venv
    hooks: [cmf.tool_pre_invoke]
    config:
      class_name: my_pkg.filters.PiiFilter
"#
    }

    /// The facade's re-exported `IsolatedVenvFactory` and kind const are
    /// wired up well enough to instantiate a plugin from config. This stops
    /// at `from_config` deliberately: `initialize()` is what builds the venv
    /// and spawns `worker.py`, which needs a real interpreter and a real
    /// package, so it belongs in cpex-hosts-python's integration tests.
    #[test]
    fn from_config_instantiates_the_python_host() {
        let config = parse_config(minimal_config_yaml()).expect("valid YAML");

        let mut factories = PluginFactoryRegistry::new();
        factories.register(ISOLATED_VENV_KIND, Box::new(IsolatedVenvFactory));

        let engine = PolicyEngine::from_config(config, &factories)
            .expect("isolated_venv factory is registered, so instantiation succeeds");

        assert_eq!(engine.plugin_count(), 1);
        assert!(engine.has_hooks_for("cmf.tool_pre_invoke"));
    }

    /// The documented path: register the facade's factory on an engine, then
    /// load YAML. Covers the identity and delegation hooks too, whose handlers
    /// must pass the engine's hook-family check.
    #[test]
    fn register_factory_then_load_yaml_wires_the_python_host() {
        let engine = std::sync::Arc::new(PolicyEngine::default());
        engine.register_factory(ISOLATED_VENV_KIND, Box::new(IsolatedVenvFactory));
        engine
            .load_config_yaml(
                r#"
engine_settings:
  dispatch: hooks
plugins:
  - name: py-identity
    kind: isolated_venv
    hooks: [identity.resolve, token.delegate, cmf.tool_pre_invoke]
    config:
      class_name: my_pkg.Resolver
"#,
            )
            .expect("the isolated_venv kind resolves through the facade");

        for hook in ["identity.resolve", "token.delegate", "cmf.tool_pre_invoke"] {
            assert!(engine.has_hooks_for(hook), "no handler on {hook}");
        }
    }
}
