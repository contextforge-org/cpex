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
