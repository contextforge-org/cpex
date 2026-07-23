// Location: ./crates/cpex-hosts-python/src/isolated/factory.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// IsolatedPythonPluginAdapterFactory — PluginFactory implementation.
//
// Parses `kind: "isolated_venv://module.ClassName"` YAML config,
// constructs a VenvManager, builds the adapter, and registers one
// BoundHookHandler per declared hook name.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use cpex_core::{
    error::PluginError,
    factory::{PluginFactory, PluginInstance},
    plugin::PluginConfig,
};

use super::adapter::{BoundHookHandler, IsolatedPythonPluginAdapter};
use super::payload::HookPayloadRegistry;
use super::venv::VenvManager;

/// `kind:` prefix operators write in CPEX YAML to declare a
/// subprocess-isolated Python plugin.
///
/// Full URI form: `isolated_venv://module.path.ClassName`
pub const KIND: &str = "isolated_venv";

/// Dotted module path of the worker script inside the installed `cpex`
/// framework. Resolved to an absolute path against a venv's site-packages
/// via [`resolve_worker_script`].
pub const WORKER_MODULE: &str = "cpex.framework.isolated.worker";

/// Resolve `worker.py` from a venv's installed `cpex` framework.
///
/// The worker script ships *inside* the `cpex` package, which is installed
/// into the plugin's venv transitively (via the plugin's self-referencing
/// `requirements.txt`). There is no reliable project-relative path to it, so
/// we ask the venv's own interpreter where the module lives:
///
/// ```text
/// <venv>/bin/python -c "import cpex.framework.isolated.worker as w; print(w.__file__)"
/// ```
///
/// This is robust across Python versions (`lib/python3.X/site-packages`) and
/// platforms (`Lib/site-packages` on Windows). Returns `None` if the venv
/// interpreter is missing or `cpex` is not importable there — the caller
/// surfaces this as a plugin initialization error.
pub fn resolve_worker_script(python_exe: &Path) -> Option<PathBuf> {
    let output = Command::new(python_exe)
        .args([
            "-c",
            &format!("import {WORKER_MODULE} as w; print(w.__file__)"),
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let path = String::from_utf8(output.stdout).ok()?;
    let path = path.trim();
    if path.is_empty() {
        return None;
    }
    Some(PathBuf::from(path))
}

/// Factory for `kind: "isolated_venv"` and `config: class_name: module.ClassName`
///
/// # Registration
///
/// ```rust,ignore
/// let mut factories = PluginFactoryRegistry::new();
/// factories.register(
///     cpex_hosts_python::KIND,
///     Box::new(IsolatedPythonPluginAdapterFactory::new(
///         HookPayloadRegistry::default(),
///     )),
/// );
/// ```
pub struct IsolatedPythonPluginAdapterFactory {
    registry: Arc<HookPayloadRegistry>,
    /// Explicit `worker.py` override. When `None` (the default), the adapter
    /// resolves the worker from its venv's installed `cpex` framework at
    /// initialization time via [`resolve_worker_script`].
    worker_script: Option<PathBuf>,
}

impl IsolatedPythonPluginAdapterFactory {
    /// Create with a pre-populated payload registry.
    ///
    /// The worker script is resolved from each plugin's venv at init time; use
    /// [`with_worker_script`](Self::with_worker_script) to pin an explicit path.
    pub fn new(registry: HookPayloadRegistry) -> Self {
        Self {
            registry: Arc::new(registry),
            worker_script: None,
        }
    }

    /// Pin an explicit path to `worker.py`, bypassing venv resolution.
    ///
    /// Only needed for non-standard cpex installs where the worker is not
    /// importable from the venv, or for tests running against a source tree.
    pub fn with_worker_script(mut self, path: impl Into<PathBuf>) -> Self {
        self.worker_script = Some(path.into());
        self
    }
}

impl PluginFactory for IsolatedPythonPluginAdapterFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        // Validate hooks list.
        if config.hooks.is_empty() {
            return Err(Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (isolated_venv): `hooks:` must list at least one hook name",
                    config.name
                ),
            }));
        }

        // class_name comes from config.config["class_name"] — consistent with
        // IsolatedVenvPlugin and the cpex/templates/isolated cookiecutter.
        let plugin_config_obj = config.config.as_ref().and_then(|v| v.as_object());

        let class_name = plugin_config_obj
            .and_then(|m| m.get("class_name"))
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                Box::new(PluginError::Config {
                    message: format!(
                        "plugin '{}': `config.class_name` is required for isolated_venv plugins",
                        config.name
                    ),
                })
            })?;

        // Read remaining optional config fields (plugin_config_obj already bound above).

        let requirements_file: Option<PathBuf> = plugin_config_obj
            .and_then(|m| m.get("requirements_file"))
            .and_then(|v| v.as_str())
            .map(PathBuf::from);

        // plugin_dirs: use `config.config.plugin_dirs` or derive from class root.
        let plugin_dirs: Vec<String> = plugin_config_obj
            .and_then(|m| m.get("plugin_dirs"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_else(|| vec!["plugins".to_string()]);

        // venv_path: optional override; default = <first plugin_dir>/<class_root>/.venv
        let venv_path: PathBuf = plugin_config_obj
            .and_then(|m| m.get("venv_path"))
            .and_then(|v| v.as_str())
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let class_root = class_name.split('.').next().unwrap_or("plugin").to_string();
                let base = plugin_dirs
                    .first()
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("plugins"));
                base.join(class_root).join(".venv")
            });

        let venv_manager = VenvManager::new(venv_path, requirements_file);

        let adapter = Arc::new(IsolatedPythonPluginAdapter::new(
            config.clone(),
            venv_manager,
            Arc::clone(&self.registry),
            class_name,
            plugin_dirs,
            self.worker_script.clone(),
        ));

        // Register a BoundHookHandler for each declared hook name.
        // Leak the string to satisfy the 'static lifetime requirement of
        // AnyHookHandler::hook_type_name() — same pattern as apl-pii-scanner.
        // PluginConfigs are created once at startup; the leak count is
        // bounded by (plugins × hooks per config).
        let handlers: Vec<_> = config
            .hooks
            .iter()
            .map(
                |h| -> (&'static str, Arc<dyn cpex_core::registry::AnyHookHandler>) {
                    let leaked: &'static str = Box::leak(h.clone().into_boxed_str());
                    let handler: Arc<dyn cpex_core::registry::AnyHookHandler> =
                        Arc::new(BoundHookHandler::new(Arc::clone(&adapter), leaked));
                    (leaked, handler)
                },
            )
            .collect();

        Ok(PluginInstance {
            plugin: adapter,
            handlers,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(class_name: &str, hooks: Vec<&str>) -> PluginConfig {
        PluginConfig {
            name: "test-plugin".to_string(),
            kind: KIND.to_string(),
            hooks: hooks.iter().map(|s| s.to_string()).collect(),
            config: Some(serde_json::json!({
                "class_name": class_name,
                "requirements_file": "tests/fixtures/requirements.txt",
                "plugin_dirs": ["tests/fixtures"]
            })),
            ..Default::default()
        }
    }

    #[test]
    fn create_valid_config_returns_instance() {
        let factory = IsolatedPythonPluginAdapterFactory::new(HookPayloadRegistry::default());
        let config = make_config("echo_plugin.EchoPlugin", vec!["cmf.tool_pre_invoke"]);
        let instance = factory.create(&config).unwrap();
        assert_eq!(instance.handlers.len(), 1);
        assert_eq!(instance.handlers[0].0, "cmf.tool_pre_invoke");
    }

    #[test]
    fn create_multi_hook_produces_multiple_handlers() {
        let factory = IsolatedPythonPluginAdapterFactory::new(HookPayloadRegistry::default());
        let config = make_config(
            "echo_plugin.EchoPlugin",
            vec!["cmf.tool_pre_invoke", "cmf.tool_post_invoke"],
        );
        let instance = factory.create(&config).unwrap();
        assert_eq!(instance.handlers.len(), 2);
    }

    #[test]
    fn create_empty_hooks_returns_error() {
        let factory = IsolatedPythonPluginAdapterFactory::new(HookPayloadRegistry::default());
        let config = make_config("echo_plugin.EchoPlugin", vec![]);
        let result = factory.create(&config);
        assert!(result.is_err(), "expected error for empty hooks");
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        };
        assert!(
            format!("{:?}", err).contains("hooks"),
            "error should mention hooks, got: {:?}",
            err
        );
    }

    #[test]
    fn create_missing_class_name_returns_error() {
        let factory = IsolatedPythonPluginAdapterFactory::new(HookPayloadRegistry::default());
        let mut config = make_config("echo_plugin.EchoPlugin", vec!["cmf.tool_pre_invoke"]);
        // Remove class_name from config.
        if let Some(obj) = config.config.as_mut().and_then(|v| v.as_object_mut()) {
            obj.remove("class_name");
        }
        let result = factory.create(&config);
        assert!(result.is_err());
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        };
        assert!(
            format!("{:?}", err).contains("class_name"),
            "error should mention class_name, got: {:?}",
            err
        );
    }

    #[test]
    fn class_name_read_from_config() {
        let factory = IsolatedPythonPluginAdapterFactory::new(HookPayloadRegistry::default());
        let config = make_config("my_pkg.MyPlugin", vec!["cmf.tool_pre_invoke"]);
        let instance = factory.create(&config).unwrap();
        assert_eq!(instance.handlers[0].0, "cmf.tool_pre_invoke");
    }

    #[test]
    fn hook_type_name_matches_declared_hook() {
        let factory = IsolatedPythonPluginAdapterFactory::new(HookPayloadRegistry::default());
        let config = make_config("echo_plugin.EchoPlugin", vec!["cmf.tool_pre_invoke"]);
        let instance = factory.create(&config).unwrap();
        let hook_name = instance.handlers[0].1.hook_type_name();
        assert_eq!(hook_name, "cmf.tool_pre_invoke");
    }
}
