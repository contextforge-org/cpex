// Location: ./builtins/session/valkey/src/factory.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// `ValkeySessionStoreFactory` — the `SessionStoreFactory` that lets the
// apl-cpex visitor build a `ValkeySessionStore` from a
// `global.apl.session_store: { kind: valkey, ... }` block. Mirrors the
// PDP factories (CelPdpFactory, CedarDirectPdpFactory).

use std::sync::Arc;

use apl_cpex::{SessionStore, SessionStoreFactory};

use crate::config::ValkeyConfig;
use crate::store::ValkeySessionStore;

/// The `kind:` discriminator this factory builds. Part of the public
/// surface — it is the string operators write in their config.
pub const KIND: &str = "valkey";

/// Factory the host registers via `AplOptions.session_store_factories`.
#[derive(Default)]
pub struct ValkeySessionStoreFactory;

impl ValkeySessionStoreFactory {
    pub fn new() -> Self {
        Self
    }
}

impl SessionStoreFactory for ValkeySessionStoreFactory {
    fn kind(&self) -> &str {
        KIND
    }

    fn build(
        &self,
        config: &serde_yaml::Value,
    ) -> Result<Arc<dyn SessionStore>, Box<dyn std::error::Error + Send + Sync>> {
        let cfg = ValkeyConfig::from_value(config)?;
        let store = ValkeySessionStore::from_config(&cfg)?;
        Ok(Arc::new(store))
    }
}
