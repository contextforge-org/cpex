// Location: ./builtins/plugins/elicitation-ciba/src/factory.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// `PluginFactory` impl for the CIBA elicitation handler. Lives here
// (alongside the approver) so every host wires it up the same way.
//
// Operators declare it in CPEX YAML as:
//
//     plugins:
//       - name: manager-approver
//         kind: elicitation/ciba
//         hooks: [elicit]
//         config:
//           backchannel_endpoint: https://kc/realms/corp/protocol/openid-connect/ext/ciba/auth
//           token_endpoint:       https://kc/realms/corp/protocol/openid-connect/token
//           client_id: cpex-gateway
//           client_secret_source: { kind: env, name: CIBA_CLIENT_SECRET }
//
// Then policy routes name it: `require_approval(manager-approver, from: claim.manager, ...)`.
//
// Hosts call
// `mgr.register_factory("elicitation/ciba", Box::new(CibaApproverFactory))`
// before loading config.

use std::sync::Arc;

use cpex_core::{
    elicitation::{ElicitationHook, HOOK_ELICIT},
    error::PluginError,
    factory::{PluginFactory, PluginInstance},
    hooks::TypedHandlerAdapter,
    plugin::PluginConfig,
};

use crate::CibaApprover;

/// The plugin `kind:` string operators write in CPEX YAML to declare a
/// CIBA elicitation handler.
pub const KIND: &str = "elicitation/ciba";

/// Factory for `kind: elicitation/ciba` plugins. Instantiates a
/// `CibaApprover` from the `config:` block and registers it on the
/// `elicit` hook.
pub struct CibaApproverFactory;

impl PluginFactory for CibaApproverFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let approver = Arc::new(CibaApprover::new(config.clone())?);
        let handler = Arc::new(TypedHandlerAdapter::<ElicitationHook, _>::new(Arc::clone(
            &approver,
        )));
        Ok(PluginInstance {
            plugin: approver,
            handlers: vec![(HOOK_ELICIT, handler)],
        })
    }
}
