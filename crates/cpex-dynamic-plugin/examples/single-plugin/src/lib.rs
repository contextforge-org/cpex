// Location: ./crates/cpex-dynamic-plugin/examples/single-plugin/src/lib.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Reference cdylib plugin — the bare-minimum shape a dynamic plugin
// takes. Used as the integration-test fixture for
// `cpex-dynamic-plugin`. Plugin authors write code that looks
// essentially like this.

use std::sync::Arc;

use async_trait::async_trait;

use cpex_core::cmf::{CmfHook, MessagePayload};
use cpex_core::context::PluginContext;
use cpex_core::hooks::adapter::TypedHandlerAdapter;
use cpex_core::hooks::payload::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::plugin::{Plugin, PluginConfig};
use cpex_core::registry::AnyHookHandler;

use cpex_dynamic_plugin::{cpex_dynamic_plugin, PluginRegistration};

/// Minimal allow-everything plugin. Real plugins do more, but the
/// goal here is to prove the load + invoke path through the dlopen
/// boundary works.
struct AllowGate {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for AllowGate {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for AllowGate {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        PluginResult::allow()
    }
}

// The macro generates the `#[no_mangle] pub unsafe extern "C" fn
// cpex_plugin_create(...)` entry point. Plugin author writes a
// closure that builds the registration; macro handles all the
// FFI safety glue (abi-check, config parse, catch_unwind, raw
// pointer ownership transfer).
cpex_dynamic_plugin! {
    |cfg: PluginConfig| -> Result<PluginRegistration, String> {
        let plugin = Arc::new(AllowGate { cfg });
        let adapter: Arc<dyn AnyHookHandler> = Arc::new(
            TypedHandlerAdapter::<CmfHook, _>::new(Arc::clone(&plugin)),
        );
        Ok(PluginRegistration::new(
            "cpex-dynamic-plugin-example",
            env!("CARGO_PKG_VERSION"),
            plugin as Arc<dyn Plugin>,
            vec![("cmf.tool_pre_invoke".to_string(), adapter)],
        ))
    }
}
