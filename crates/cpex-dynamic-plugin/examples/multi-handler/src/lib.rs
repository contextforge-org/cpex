// Location: ./crates/cpex-dynamic-plugin/examples/multi-handler/src/lib.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Multi-handler reference plugin. Registers two CmfHook handlers
// with intentionally different verdicts so tests can distinguish
// "which handler fired" from the pipeline outcome alone:
//
//   * `cmf.tool_pre_invoke`  → AllowHandler  → continue_processing = true
//   * `cmf.tool_post_invoke` → DenyHandler   → continue_processing = false,
//                                              violation.code = "test.multi_handler.post_deny"
//
// Pattern A from the README: one Plugin instance, two adapters
// over different `HookHandler<H>` impls. Lets the integration
// tests verify the `#handler` fragment filter works against a
// real multi-handler cdylib.

use std::sync::Arc;

use async_trait::async_trait;

use cpex_core::cmf::{CmfHook, MessagePayload};
use cpex_core::context::PluginContext;
use cpex_core::error::PluginViolation;
use cpex_core::hooks::adapter::TypedHandlerAdapter;
use cpex_core::hooks::payload::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::plugin::{Plugin, PluginConfig};
use cpex_core::registry::AnyHookHandler;

use cpex_dynamic_plugin::{cpex_dynamic_plugin, PluginRegistration};

/// Pre-invoke handler — always allows.
struct AllowOnPre {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for AllowOnPre {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for AllowOnPre {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        _ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        PluginResult::allow()
    }
}

/// Post-invoke handler — always denies with a distinctive code so
/// tests can identify which handler fired by inspecting the
/// violation.
struct DenyOnPost {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for DenyOnPost {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for DenyOnPost {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        _ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        PluginResult::deny(PluginViolation::new(
            "test.multi_handler.post_deny",
            "deny-on-post handler fired",
        ))
    }
}

cpex_dynamic_plugin! {
    |cfg: PluginConfig| -> Result<PluginRegistration, String> {
        // Two distinct plugin structs, one Arc each. The plugin
        // exposed via PluginRegistration is the AllowOnPre — the
        // post handler is technically a separate Plugin instance,
        // but the registration only carries one "primary" Plugin
        // handle for diagnostic purposes. Functionally, both
        // handlers run independently when their respective hooks
        // fire.
        let allow = Arc::new(AllowOnPre { cfg: cfg.clone() });
        let deny = Arc::new(DenyOnPost { cfg: cfg.clone() });

        let allow_adapter: Arc<dyn AnyHookHandler> = Arc::new(
            TypedHandlerAdapter::<CmfHook, _>::new(Arc::clone(&allow)),
        );
        let deny_adapter: Arc<dyn AnyHookHandler> = Arc::new(
            TypedHandlerAdapter::<CmfHook, _>::new(Arc::clone(&deny)),
        );

        Ok(PluginRegistration::new(
            "cpex-dynamic-plugin-multi-handler-example",
            env!("CARGO_PKG_VERSION"),
            allow as Arc<dyn Plugin>,
            vec![
                ("cmf.tool_pre_invoke".to_string(), allow_adapter),
                ("cmf.tool_post_invoke".to_string(), deny_adapter),
            ],
        ))
    }
}
