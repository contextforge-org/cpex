// Location: ./crates/apl-identity-jwt/src/factory.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// `PluginFactory` impl for the JWT identity resolver. Lives in this
// crate (not in any consuming integration) so that every host —
// Praxis filter, Envoy bridge, CLI test harness — wires it up the
// same way.
//
// Operators declare it in CPEX YAML as:
//
//     plugins:
//       - name: jwt-resolver
//         kind: identity/jwt
//         hooks: [identity.resolve]
//         config:
//           trusted_issuers:
//             - issuer: https://idp.example.com
//               audiences: [my-api]
//               algorithms: [RS256]
//               decoding_key: { kind: jwks_url, url: ... }
//
// The `kind: identity/jwt` string is part of this crate's public API.
// Hosts call `mgr.register_factory("identity/jwt", Box::new(JwtIdentityFactory))`
// before `load_config_yaml`.

use std::sync::Arc;

use cpex_core::{
    error::PluginError,
    factory::{PluginFactory, PluginInstance},
    hooks::TypedHandlerAdapter,
    identity::{IdentityHook, HOOK_IDENTITY_RESOLVE},
    plugin::PluginConfig,
};

use crate::JwtIdentityResolver;

/// The plugin `kind:` string operators write in CPEX YAML to declare
/// a JWT identity resolver.
pub const KIND: &str = "identity/jwt";

/// Factory for `kind: identity/jwt` plugins. Instantiates a
/// `JwtIdentityResolver` from the `config:` block and registers it on
/// the `identity.resolve` hook.
pub struct JwtIdentityFactory;

impl PluginFactory for JwtIdentityFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let resolver = Arc::new(JwtIdentityResolver::new(config.clone())?);
        let handler = Arc::new(TypedHandlerAdapter::<IdentityHook, _>::new(Arc::clone(
            &resolver,
        )));
        Ok(PluginInstance {
            plugin: resolver,
            handlers: vec![(HOOK_IDENTITY_RESOLVE, handler)],
        })
    }
}
