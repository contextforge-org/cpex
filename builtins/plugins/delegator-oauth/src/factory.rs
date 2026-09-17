// Location: ./builtins/plugins/delegator-oauth/src/factory.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// `PluginFactory` impl for the OAuth 2.0 (RFC 8693) token-exchange
// delegator. Lives here (alongside the delegator) so every host —
// Praxis filter, Envoy bridge, CLI runner, test harness — wires it
// up the same way.
//
// Operators declare it in CPEX YAML as:
//
//     plugins:
//       - name: workday-oauth
//         kind: delegator/oauth
//         hooks: [token.delegate]
//         config:
//           token_endpoint: https://idp.example.com/token
//           client_id: praxis-cpex
//           client_secret_source: { kind: env, var: OAUTH_CLIENT_SECRET }
//
// The `kind: delegator/oauth` string is part of this crate's public
// API. Hosts call
// `mgr.register_factory("delegator/oauth", Box::new(OAuthDelegatorFactory))`
// before `load_config_yaml`.

use std::sync::Arc;

use cpex_core::{
    delegation::{TokenDelegateHook, HOOK_TOKEN_DELEGATE},
    error::PluginError,
    factory::{PluginFactory, PluginInstance},
    hooks::TypedHandlerAdapter,
    plugin::PluginConfig,
};

use crate::OAuthDelegator;

/// The plugin `kind:` string operators write in CPEX YAML to declare
/// an OAuth RFC 8693 token-exchange delegator.
pub const KIND: &str = "delegator/oauth";

/// Factory for `kind: delegator/oauth` plugins. Instantiates an
/// `OAuthDelegator` from the `config:` block and registers it on the
/// `token.delegate` hook.
pub struct OAuthDelegatorFactory;

impl PluginFactory for OAuthDelegatorFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let delegator = Arc::new(OAuthDelegator::new(config.clone())?);
        let handler = Arc::new(TypedHandlerAdapter::<TokenDelegateHook, _>::new(
            Arc::clone(&delegator),
        ));
        Ok(PluginInstance {
            plugin: delegator,
            handlers: vec![(HOOK_TOKEN_DELEGATE, handler)],
        })
    }
}
