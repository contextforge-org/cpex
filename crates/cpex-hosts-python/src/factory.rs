// Location: ./crates/cpex-hosts-python/src/factory.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// The `isolated_venv` plugin factory.
//
// Hosts register this before `PolicyEngine::from_config()`. For each config
// entry whose `kind:` is `isolated_venv`, the engine calls `create()`, which
// parses the venv settings out of the entry's opaque `config` map and returns
// the plugin plus one handler per declared hook.

use std::sync::Arc;

use ppe::praxis_policy_core::{
    error::PluginError,
    factory::{PluginFactory, PluginInstance},
    plugin::PluginConfig,
};

use crate::plugin::{IsolatedPythonPlugin, PythonHookAdapter};

/// `kind:` string operators write in CPEX YAML to declare a Python plugin
/// that runs out-of-process in its own virtualenv.
///
/// This supersedes issue #20's `python://` in-process framing: the host runs
/// the plugin in a subprocess, not via PyO3, so the runtime never links
/// libpython and a plugin crash cannot take the gateway down.
pub const KIND: &str = "isolated_venv";

/// Creates out-of-process Python plugins from `isolated_venv` config entries.
pub struct IsolatedVenvFactory;

/// Whether an entry sets the ignored `plugin_dirs` key in its `config:` block.
///
/// Split out from the warning call so the *decision* is directly assertable —
/// the `tracing::warn!` itself is a no-op without a subscriber, and the
/// workspace carries none in its test profile.
fn declares_ignored_plugin_dirs(config: &PluginConfig) -> bool {
    config
        .config
        .as_ref()
        .and_then(serde_json::Value::as_object)
        .is_some_and(|block| block.contains_key("plugin_dirs"))
}

impl PluginFactory for IsolatedVenvFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        if config.hooks.is_empty() {
            return Err(PluginError::Config {
                message: format!(
                    "plugin '{}' (isolated_venv): `hooks:` must list at least one hook \
                     for the Python plugin to handle (e.g. cmf.tool_pre_invoke)",
                    config.name
                ),
            }
            .boxed());
        }

        // `plugin_dirs` is no longer configurable — the host always uses
        // `<project root>/plugins`. An entry that still sets it would otherwise
        // appear to work while pointing somewhere else entirely, so say so once,
        // naming the plugin.
        if declares_ignored_plugin_dirs(config) {
            tracing::warn!(
                plugin = %config.name,
                "plugin '{}' (isolated_venv) sets `plugin_dirs` in its config block, but the \
                 host always uses '{}' at the project root. Setting ignored — remove it.",
                config.name,
                crate::plugin::DEFAULT_PLUGIN_DIR,
            );
        }

        // Parsing happens here rather than in `initialize()` so a malformed
        // entry fails at config load, while the engine can still report
        // which plugin was bad, instead of midway through a rollback.
        let plugin = Arc::new(IsolatedPythonPlugin::from_config(config)?);

        let handlers: Vec<_> = config
            .hooks
            .iter()
            .map(
                |hook| -> (
                    &'static str,
                    Arc<dyn ppe::praxis_policy_core::registry::AnyHookHandler>,
                ) {
                    // The registry keys handlers by `&'static str`, and hook names
                    // arrive as owned Strings from YAML. Leaking is what
                    // audit-logger does: the set is bounded by config size and
                    // lives as long as the process holds the plugin anyway.
                    let leaked: &'static str = Box::leak(hook.clone().into_boxed_str());
                    (
                        leaked,
                        Arc::new(PythonHookAdapter::new(Arc::clone(&plugin), leaked)),
                    )
                },
            )
            .collect();

        Ok(PluginInstance { plugin, handlers })
    }
}

#[cfg(test)]
mod tests {
    use ppe::PolicyEngine;
    use ppe::praxis_policy_core::config::PolicyConfig;
    use ppe::praxis_policy_core::factory::PluginFactoryRegistry;

    use super::*;

    /// A config with one `isolated_venv` plugin, mirroring the YAML shape an
    /// operator writes. No `plugin_dirs`: the host always resolves
    /// `<project root>/plugins` — see `plugin::DEFAULT_PLUGIN_DIR`.
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

    fn registry() -> PluginFactoryRegistry {
        let mut factories = PluginFactoryRegistry::new();
        factories.register(KIND, Box::new(IsolatedVenvFactory));
        factories
    }

    #[test]
    fn factory_registers_under_isolated_venv_kind() {
        let factories = registry();
        assert!(factories.has(KIND));
        assert_eq!(KIND, "isolated_venv");
    }

    #[test]
    fn loading_an_isolated_venv_config_succeeds() {
        let config: PolicyConfig = serde_yaml::from_str(minimal_config_yaml()).expect("valid YAML");
        let factories = registry();

        // The load path is what would raise "no factory registered for plugin
        // kind 'isolated_venv'" if registration did not take.
        PolicyEngine::from_config(config, &factories)
            .expect("config loads with the factory registered");
    }

    #[test]
    fn missing_class_name_is_a_config_error_not_a_panic() {
        // The block carries only the now-ignored `plugin_dirs`, so this also
        // covers that an ignored key does not mask the missing required one.
        let yaml = r#"
engine_settings:
  dispatch: hooks
plugins:
  - name: broken
    kind: isolated_venv
    hooks: [cmf.tool_pre_invoke]
    config:
      plugin_dirs: ["./plugins"]
"#;
        let config: PolicyConfig = serde_yaml::from_str(yaml).expect("valid YAML");
        // `PolicyEngine` is not Debug, so `expect_err` is unavailable here.
        let Err(err) = PolicyEngine::from_config(config, &registry()) else {
            panic!("a config block without class_name must be rejected");
        };

        assert!(
            matches!(*err, PluginError::Config { .. }),
            "expected a Config error, got: {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("class_name"),
            "the error should name the missing field so an operator can fix it: {msg}"
        );
    }

    #[test]
    fn empty_hooks_list_is_rejected() {
        let yaml = r#"
engine_settings:
  dispatch: hooks
plugins:
  - name: no-hooks
    kind: isolated_venv
    hooks: []
    config:
      class_name: my_pkg.filters.PiiFilter
"#;
        let config: PolicyConfig = serde_yaml::from_str(yaml).expect("valid YAML");
        let Err(err) = PolicyEngine::from_config(config, &registry()) else {
            panic!("a plugin declaring no hooks can never be invoked");
        };
        assert!(matches!(*err, PluginError::Config { .. }));
    }

    #[test]
    fn the_ignored_plugin_dirs_key_is_detected_for_the_warning() {
        // Guards the warning's trigger condition. Without this an operator
        // upgrading gets silence: the key stops working and nothing says so.
        let with_key = PluginConfig {
            name: "legacy".into(),
            kind: KIND.into(),
            hooks: vec!["cmf.tool_pre_invoke".into()],
            config: Some(serde_json::json!({
                "class_name": "my_pkg.P",
                "plugin_dirs": ["/somewhere"],
            })),
            ..Default::default()
        };
        assert!(declares_ignored_plugin_dirs(&with_key));

        let without_key = PluginConfig {
            config: Some(serde_json::json!({ "class_name": "my_pkg.P" })),
            ..with_key.clone()
        };
        assert!(
            !declares_ignored_plugin_dirs(&without_key),
            "a clean config must not warn"
        );

        // An absent block must not panic or warn.
        let no_block = PluginConfig {
            config: None,
            ..with_key
        };
        assert!(!declares_ignored_plugin_dirs(&no_block));
    }

    #[test]
    fn an_ignored_plugin_dirs_key_still_loads() {
        // An operator upgrading from a config that set `plugin_dirs` must not
        // hit a load failure — the key is ignored (with a warning), not
        // rejected. A hard error here would break every existing config.
        let yaml = r#"
engine_settings:
  dispatch: hooks
plugins:
  - name: legacy-dirs
    kind: isolated_venv
    hooks: [cmf.tool_pre_invoke]
    config:
      class_name: my_pkg.filters.PiiFilter
      plugin_dirs: ["/somewhere/else"]
"#;
        let config: PolicyConfig = serde_yaml::from_str(yaml).expect("valid YAML");
        PolicyEngine::from_config(config, &registry())
            .expect("an ignored plugin_dirs key must not fail the load");
    }

    #[test]
    fn one_handler_is_produced_per_declared_hook() {
        let config = PluginConfig {
            name: "multi".into(),
            kind: KIND.into(),
            hooks: vec![
                "cmf.tool_pre_invoke".into(),
                "identity.resolve".into(),
                "token.delegate".into(),
            ],
            config: Some(serde_json::json!({ "class_name": "my_pkg.Multi" })),
            ..Default::default()
        };

        let instance = IsolatedVenvFactory
            .create(&config)
            .expect("a valid multi-hook entry creates an instance");

        assert_eq!(instance.handlers.len(), 3);
        let names: Vec<&str> = instance.handlers.iter().map(|(n, _)| *n).collect();
        assert!(names.contains(&"cmf.tool_pre_invoke"));
        assert!(names.contains(&"identity.resolve"));
        assert!(names.contains(&"token.delegate"));
    }

    #[test]
    fn handlers_pass_the_engine_family_check_on_every_dispatched_hook_family() {
        // The registry refuses a handler whose reported family differs from the
        // hook's. A handler reporting the bare hook name would fail on every
        // `cmf.*` hook, whose family is `cmf`.
        let yaml = r#"
engine_settings:
  dispatch: hooks
plugins:
  - name: py-everything
    kind: isolated_venv
    hooks:
      - cmf.tool_pre_invoke
      - cmf.prompt_pre_invoke
      - identity.resolve
      - token.delegate
    config:
      class_name: my_pkg.Everything
"#;
        let config = ppe::praxis_policy_core::config::parse_config(yaml).expect("valid config");
        let engine = PolicyEngine::from_config(config, &registry())
            .expect("every dispatched hook family accepts the isolated_venv handler");
        for hook in [
            "cmf.tool_pre_invoke",
            "cmf.prompt_pre_invoke",
            "identity.resolve",
            "token.delegate",
        ] {
            assert!(engine.has_hooks_for(hook), "no handler on {hook}");
        }
    }

    #[test]
    fn a_top_level_plugin_dirs_key_fails_the_load() {
        // PPE closed the document's key set. Only the in-plugin `config:` key
        // is tolerated (with a warning); the top-level one is an error naming
        // its replacement.
        let yaml = r#"
plugin_dirs: ["./plugins"]
engine_settings:
  dispatch: hooks
plugins:
  - name: legacy-dirs
    kind: isolated_venv
    hooks: [cmf.tool_pre_invoke]
    config:
      class_name: my_pkg.filters.PiiFilter
"#;
        let err = ppe::praxis_policy_core::config::parse_config(yaml)
            .expect_err("a top-level plugin_dirs key must be rejected");
        assert!(
            matches!(*err, PluginError::Config { .. }),
            "expected a Config error, got: {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("plugin_dirs"),
            "the error should name the key: {msg}"
        );
        assert!(
            msg.contains("register_factory"),
            "the error should name the replacement: {msg}"
        );
    }

    #[test]
    fn a_legacy_hook_name_fails_the_load() {
        let yaml = r#"
engine_settings:
  dispatch: hooks
plugins:
  - name: legacy-hook
    kind: isolated_venv
    hooks: [identity_resolve]
    config:
      class_name: my_pkg.Resolver
"#;
        let err = ppe::praxis_policy_core::config::parse_config(yaml)
            .expect_err("PPE does not dispatch the unprefixed identity hook");
        assert!(err.to_string().contains("identity.resolve"), "{err}");
    }
}
