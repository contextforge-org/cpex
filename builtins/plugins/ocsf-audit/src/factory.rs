// Location: ./builtins/plugins/ocsf-audit/src/factory.rs
// Copyright 2026 AI Identity
// SPDX-License-Identifier: Apache-2.0
//
// Factory — registers the emitter under every CMF hook the operator
// lists in `hooks:`. Structurally identical to the upstream
// audit-logger factory (TypedHandlerAdapter<CmfHook, _> per hook name).

use std::sync::Arc;

use cpex_core::{
    cmf::CmfHook,
    error::PluginError,
    factory::{PluginFactory, PluginInstance},
    hooks::TypedHandlerAdapter,
    plugin::PluginConfig,
};

use crate::emitter::OcsfAuditEmitter;

/// `kind:` string operators write in CPEX YAML to declare an OCSF
/// audit emitter instance.
pub const KIND: &str = "audit/ocsf";

pub struct OcsfAuditFactory;

impl PluginFactory for OcsfAuditFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let emitter = Arc::new(OcsfAuditEmitter::new(config.clone())?);

        if config.hooks.is_empty() {
            return Err(Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (cpex-plugin-ocsf-audit): `hooks:` must list at least \
                     one CMF hook to emit on. For audit, prefer the POST hooks: \
                     cmf.tool_post_invoke, cmf.llm_output, cmf.resource_post_fetch, \
                     cmf.prompt_post_invoke. (NOT cmf.prompt_post_fetch — that name \
                     exists in hooks/types.rs but the Rust CMF/APL runtime dispatches \
                     the cmf/constants.rs name, cmf.prompt_post_invoke; a handler on \
                     the _fetch name silently never fires.)",
                    config.name
                ),
            }));
        }

        let handlers: Vec<_> = config
            .hooks
            .iter()
            .map(|h| -> (&'static str, _) {
                let leaked: &'static str = Box::leak(h.clone().into_boxed_str());
                let adapter: Arc<dyn cpex_core::registry::AnyHookHandler> =
                    Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(Arc::clone(&emitter)));
                (leaked, adapter)
            })
            .collect();

        Ok(PluginInstance {
            plugin: emitter,
            handlers,
        })
    }
}
