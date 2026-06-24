// Location: ./builtins/plugins/pii-scanner/src/factory.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor

use std::sync::Arc;

use cpex_core::{
    cmf::CmfHook,
    error::PluginError,
    factory::{PluginFactory, PluginInstance},
    hooks::TypedHandlerAdapter,
    plugin::PluginConfig,
};

use crate::scanner::PiiScanner;

/// `kind:` string operators write in CPEX YAML to declare a PII
/// scanner instance.
pub const KIND: &str = "validator/pii-scan";

/// Factory for `kind: validator/pii-scan`. Instantiates a
/// `PiiScanner` from the `config:` block and registers a handler
/// for every CMF hook name listed in `cfg.hooks`. Operators
/// typically wire it on `cmf.tool_pre_invoke` /
/// `cmf.prompt_pre_invoke` / `cmf.resource_pre_fetch` so it runs
/// before any of those entity types reach the backend.
pub struct PiiScannerFactory;

impl PluginFactory for PiiScannerFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let scanner = Arc::new(PiiScanner::new(config.clone())?);

        // Register the same handler instance against every CMF hook
        // name the operator declared in YAML — same plugin, multiple
        // entry points. Empty hooks list is a config error.
        if config.hooks.is_empty() {
            return Err(Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (apl-pii-scanner): `hooks:` must list at \
                     least one CMF hook to scan on (e.g. cmf.tool_pre_invoke)",
                    config.name
                ),
            }));
        }

        let handlers: Vec<_> = config
            .hooks
            .iter()
            .map(|h| -> (&'static str, _) {
                // Leak the string to get a 'static lifetime — the
                // handler registry stores it that way for cheap
                // comparison. PluginConfigs are read once at startup
                // and live for the process lifetime, so the leak
                // bound is the number of plugin × hook pairs in
                // config (small, bounded).
                let leaked: &'static str = Box::leak(h.clone().into_boxed_str());
                let adapter: Arc<dyn cpex_core::registry::AnyHookHandler> = Arc::new(
                    TypedHandlerAdapter::<CmfHook, _>::new(Arc::clone(&scanner)),
                );
                (leaked, adapter)
            })
            .collect();

        Ok(PluginInstance {
            plugin: scanner,
            handlers,
        })
    }
}
