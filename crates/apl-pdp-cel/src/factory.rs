// Location: ./crates/apl-pdp-cel/src/factory.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// `CelPdpFactory` — the `PdpFactory` implementation that lets the apl-cpex
// visitor instantiate `CelResolver` from a unified-config YAML block:
//
// ```yaml
// global:
//   apl:
//     pdp:
//       - kind: cel
//         on_error: deny          # optional; deny | allow, default deny
// ```
//
// The CEL expression itself lives in each route's `cel: { expr: "..." }`
// step, not in this block — so the global config usually just declares the
// resolver exists. Hosts register an instance of this factory in
// `AplOptions.pdp_factories`; the visitor matches it to the block by `kind`.

use std::sync::Arc;

use apl_core::step::{PdpFactory, PdpResolver};

use crate::resolver::CelResolver;

/// Factory for `CelResolver`. Reports `kind() = "cel"`; builds resolvers
/// from the unified-config block via [`CelResolver::from_config`].
#[derive(Default)]
pub struct CelPdpFactory;

impl CelPdpFactory {
    pub fn new() -> Self {
        Self
    }
}

impl PdpFactory for CelPdpFactory {
    fn kind(&self) -> &str {
        "cel"
    }

    fn build(
        &self,
        config: &serde_yaml::Value,
    ) -> Result<Arc<dyn PdpResolver>, Box<dyn std::error::Error + Send + Sync>> {
        let resolver = CelResolver::from_config(config)?;
        Ok(Arc::new(resolver))
    }
}
