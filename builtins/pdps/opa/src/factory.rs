// Location: ./builtins/pdps/opa/src/factory.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// `OpaPdpFactory` — the `PdpFactory` the apl-cpex visitor uses to instantiate
// an `OpaResolver` from a unified-config block:
//
// ```yaml
// global:
//   apl:
//     pdp:
//       - kind: opa
//         on_error: deny          # optional; deny | allow, default deny
//         max_cache_entries: 1024 # optional; cap on distinct inline modules
//         modules:                # global Rego modules (inline and/or files)
//           - |
//             package authz
//             default allow := false
//             allow if input.subject.id == "alice"
// ```
//
// The per-route query (and any inline module) lives in each route's
// `opa: { query: "data.authz.allow" }` step, not in this block. Hosts register
// an instance in `AplOptions.pdp_factories`; the visitor matches it by `kind`.

use std::sync::Arc;

use apl_core::step::{PdpFactory, PdpResolver};

use crate::resolver::OpaResolver;

/// Factory for `OpaResolver`. Reports `kind() = "opa"`; builds resolvers from
/// the unified-config block via [`OpaResolver::from_config`].
#[derive(Default)]
pub struct OpaPdpFactory;

impl OpaPdpFactory {
    pub fn new() -> Self {
        Self
    }
}

impl PdpFactory for OpaPdpFactory {
    fn kind(&self) -> &str {
        "opa"
    }

    fn build(
        &self,
        config: &serde_yaml::Value,
    ) -> Result<Arc<dyn PdpResolver>, Box<dyn std::error::Error + Send + Sync>> {
        let resolver = OpaResolver::from_config(config)?;
        Ok(Arc::new(resolver))
    }
}
