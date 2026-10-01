// Location: ./builtins/plugins/audit-logger/src/factory.rs
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

use crate::logger::AuditLogger;

/// `kind:` string operators write in CPEX YAML to declare an audit
/// logger instance.
pub const KIND: &str = "audit/logger";

pub struct AuditLoggerFactory;

impl PluginFactory for AuditLoggerFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let logger = Arc::new(AuditLogger::new(config.clone())?);

        // Make the inferred mode explicit in the startup log. Audit-only (no
        // `hooks:`) is the recommended sink mode, so this stays at info rather
        // than warn — but it names the mode unambiguously and points at the
        // typo case, so an operator who *meant* to list hooks and lost them to
        // a YAML slip can catch it in the logs rather than silently getting a
        // sink. (An explicit config flag would remove the inference entirely —
        // tracked for the sink-mode discussion.)
        if config.hooks.is_empty() {
            tracing::info!(
                plugin = %config.name,
                "audit-logger '{}' running in audit-only sink mode (no `hooks:` listed) — \
                 auto-attaches to the executor verdict path; if you meant to observe specific \
                 hooks, list them under `hooks:`",
                config.name,
            );
        } else {
            tracing::info!(
                plugin = %config.name,
                hooks = ?config.hooks,
                "audit-logger '{}' running as a CMF post-hook observer on {:?}",
                config.name,
                config.hooks,
            );
        }

        // With no `hooks:` listed the logger runs in audit-only mode — it
        // registers no CMF post-hook handlers and instead auto-attaches as a
        // decision-audit sink (see `Plugin::as_audit_handler`). Listing hooks
        // keeps the legacy per-hook observation behavior.
        let handlers: Vec<_> = config
            .hooks
            .iter()
            .map(|h| -> (&'static str, _) {
                let leaked: &'static str = Box::leak(h.clone().into_boxed_str());
                let adapter: Arc<dyn cpex_core::registry::AnyHookHandler> =
                    Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(Arc::clone(&logger)));
                (leaked, adapter)
            })
            .collect();

        Ok(PluginInstance {
            plugin: logger,
            handlers,
        })
    }
}
