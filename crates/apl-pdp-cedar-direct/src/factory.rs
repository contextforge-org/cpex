// Location: ./crates/apl-pdp-cedar-direct/src/factory.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// `CedarDirectPdpFactory` — the `PdpFactory` implementation that lets
// the apl-cpex visitor instantiate `CedarDirectResolver` from a
// unified-config YAML block:
//
// ```yaml
// global:
//   apl:
//     pdp:
//       - kind: cedar-direct
//         dialect: cedar          # optional, defaults to PdpDialect::Cedar
//         policy_text: |          # required (or policy_file)
//           @id("owner-override")
//           permit(...);
// ```
//
// Hosts register an instance of this factory in `AplOptions.pdp_factories`;
// the visitor matches it to the block by `kind` and dispatches.

use std::sync::Arc;

use apl_core::step::{PdpFactory, PdpResolver};

use crate::resolver::CedarDirectResolver;

/// Factory for `CedarDirectResolver`. Reports `kind() = "cedar-direct"`;
/// builds resolvers from the unified-config block via
/// [`CedarDirectResolver::from_config`].
#[derive(Default)]
pub struct CedarDirectPdpFactory;

impl CedarDirectPdpFactory {
    pub fn new() -> Self {
        Self
    }
}

impl PdpFactory for CedarDirectPdpFactory {
    fn kind(&self) -> &str {
        "cedar-direct"
    }

    fn build(
        &self,
        config: &serde_yaml::Value,
    ) -> Result<Arc<dyn PdpResolver>, Box<dyn std::error::Error + Send + Sync>> {
        let resolver = CedarDirectResolver::from_config(config)?;
        Ok(Arc::new(resolver))
    }
}
