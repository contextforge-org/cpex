// Location: ./crates/cpex-dynamic-plugin/examples/multi-plugin/src/lib.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Multi-plugin reference cdylib. Packages two truly distinct
// plugins (different structs, different behaviors, different
// versions) inside one shared library, addressable via the
// operator's `?entry=<name>` URL parameter.
//
// This complements `cpex-dynamic-plugin-multi-handler-example`,
// which has ONE plugin registering MULTIPLE handlers. The two
// shapes are independent:
//
//   * Multi-handler (cpex_dynamic_plugin! singular): one plugin
//     hooks several lifecycle points. One entry point, several
//     `(hook_name, handler)` pairs.
//   * Multi-plugin (cpex_dynamic_plugins! plural): several
//     unrelated plugins shipped in one binary for deployment
//     convenience. Several entry points, one PluginRegistration
//     per call.
//
// Tests use the verdict + violation code to identify which
// entry-point function the host actually called.

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

use cpex_dynamic_plugin::{cpex_dynamic_plugins, PluginRegistration};

// ----- Plugin 1: Allow gate -----

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

fn build_allow(cfg: PluginConfig) -> Result<PluginRegistration, String> {
    let plugin = Arc::new(AllowGate { cfg });
    let adapter: Arc<dyn AnyHookHandler> = Arc::new(
        TypedHandlerAdapter::<CmfHook, _>::new(Arc::clone(&plugin)),
    );
    Ok(PluginRegistration::new(
        "allow-gate",
        "1.0.0",
        plugin as Arc<dyn Plugin>,
        vec![("cmf.tool_pre_invoke".to_string(), adapter)],
    ))
}

// ----- Plugin 2: Deny gate -----

struct DenyGate {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for DenyGate {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for DenyGate {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        PluginResult::deny(PluginViolation::new(
            "test.multi_plugin.deny",
            "deny-gate plugin fired",
        ))
    }
}

fn build_deny(cfg: PluginConfig) -> Result<PluginRegistration, String> {
    let plugin = Arc::new(DenyGate { cfg });
    let adapter: Arc<dyn AnyHookHandler> = Arc::new(
        TypedHandlerAdapter::<CmfHook, _>::new(Arc::clone(&plugin)),
    );
    Ok(PluginRegistration::new(
        "deny-gate",
        "0.5.0",
        plugin as Arc<dyn Plugin>,
        vec![("cmf.tool_pre_invoke".to_string(), adapter)],
    ))
}

// ----- Multi-plugin registration -----
//
// Generates `cpex_plugin_create_allow`, `cpex_plugin_create_deny`,
// and `cpex_plugin_list`. Note: this cdylib does NOT expose the
// default `cpex_plugin_create` symbol — operators MUST use
// `?entry=<name>`. That's deliberate: if you're packaging multiple
// plugins, there's no sensible default.
cpex_dynamic_plugins! {
    allow => {
        name: "Allow Gate",
        version: "1.0.0",
        description: "Always allows; useful for smoke-testing the pipeline",
        create: build_allow,
    },
    deny => {
        name: "Deny Gate",
        version: "0.5.0",
        description: "Always denies with code test.multi_plugin.deny",
        create: build_deny,
    },
}
