// Location: ./examples/tutorial/examples/m09_custom_plugin.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// Tutorial module 9, Write your own plugin.
//
//   cargo run -p cpex-tutorial --example m09_custom_plugin
//   cargo run -p cpex-tutorial --example m09_custom_plugin -- --check
//
// A plugin is a Rust type that implements a hook handler. You register it
// under a `kind`, and policy references it by name with run(...), exactly
// like a builtin. This one is a "business hours" guard: it denies a call
// whose `hour` argument falls outside the open/close window in its config.
//
// The traits come from cpex-sdk (the lean plugin-author crate). The
// factory and handler-adapter plumbing come from cpex-core, the same
// pattern every builtin uses.

use std::sync::Arc;

use async_trait::async_trait;

use cpex::PluginManager;
use cpex_core::factory::{PluginFactory, PluginInstance};
use cpex_core::hooks::adapter::TypedHandlerAdapter;
use cpex_sdk::{
    CmfHook, Extensions, HookHandler, MessagePayload, Plugin, PluginConfig, PluginContext,
    PluginError, PluginResult, PluginViolation,
};

use cpex_tutorial::backends;
use cpex_tutorial::ui;
use cpex_tutorial::{mediate, Caller, Outcome};

use serde_json::json;

const POLICY: &str = include_str!("../policies/m09.yaml");

/// The plugin. Holds its parsed config: the open/close window.
struct BusinessHours {
    cfg: PluginConfig,
    open_hour: u64,
    close_hour: u64,
}

#[async_trait]
impl Plugin for BusinessHours {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for BusinessHours {
    async fn handle(
        &self,
        payload: &MessagePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        // Read the `hour` argument off the tool call.
        let hour = payload
            .message
            .get_tool_calls()
            .into_iter()
            .next()
            .and_then(|tc| tc.arguments.get("hour"))
            .and_then(|v| v.as_u64());

        match hour {
            Some(h) if h >= self.open_hour && h < self.close_hour => PluginResult::allow(),
            Some(h) => PluginResult::deny(PluginViolation::new(
                "office.closed",
                format!(
                    "requested at hour {h}, outside business hours {}-{}",
                    self.open_hour, self.close_hour
                ),
            )),
            None => PluginResult::deny(PluginViolation::new(
                "office.no_hour",
                "request did not carry an `hour` argument",
            )),
        }
    }
}

/// The factory. `install_builtins` and the APL visitor resolve `kind:
/// business-hours` to this, build the plugin, and wire its handler onto
/// the `cmf.tool_pre_invoke` hook.
struct BusinessHoursFactory;

impl PluginFactory for BusinessHoursFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let cfg_val = config.config.clone().unwrap_or_default();
        let open_hour = cfg_val
            .get("open_hour")
            .and_then(|v| v.as_u64())
            .unwrap_or(9);
        let close_hour = cfg_val
            .get("close_hour")
            .and_then(|v| v.as_u64())
            .unwrap_or(17);
        let plugin = Arc::new(BusinessHours {
            cfg: config.clone(),
            open_hour,
            close_hour,
        });
        Ok(PluginInstance {
            plugin: plugin.clone(),
            handlers: vec![(
                "cmf.tool_pre_invoke",
                Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(plugin)),
            )],
        })
    }
}

#[tokio::main]
async fn main() {
    ui::module_banner("Module 9: Write your own plugin");

    let mgr = Arc::new(PluginManager::default());
    // Register the custom factory BEFORE loading config, so the APL visitor
    // can resolve `kind: business-hours` to it.
    mgr.register_factory("business-hours", Box::new(BusinessHoursFactory));
    cpex::install_builtins(&mgr);
    mgr.load_config_yaml(POLICY)
        .expect("policy m09.yaml should load");
    mgr.initialize().await.expect("initialize");

    let caller = Caller::anonymous();
    let mut all_passed = true;

    ui::scenario("get_compensation at 10:00 (within 9-17 window)");
    let o = mediate(
        &mgr,
        &caller,
        "get_compensation",
        json!({ "employee_id": "e-1001", "hour": 10 }),
        backends::get_compensation,
    )
    .await;
    ui::print_outcome(&o);
    all_passed &= ui::expect(&o, true);

    ui::scenario("get_compensation at 22:00 (outside the window)");
    let o = mediate(
        &mgr,
        &caller,
        "get_compensation",
        json!({ "employee_id": "e-1001", "hour": 22 }),
        backends::get_compensation,
    )
    .await;
    ui::print_outcome(&o);
    all_passed &= ui::expect(&o, false);
    if let Outcome::Denied { code, .. } = &o {
        all_passed &= code == "office.closed";
    }

    println!(
        "Your plugin plugs into policy exactly like a builtin: referenced by name with run(...)."
    );
    ui::finish_check(all_passed);
}
