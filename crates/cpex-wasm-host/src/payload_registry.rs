// Location: ./crates/cpex-wasm-host/src/payload_registry.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
// PayloadSerializerRegistry — maps payload TypeId ↔ (type_name, serialize, deserialize).
//
// The host registers every payload type it wants to route through the WASM
// boundary here. WasmBridgeHandler calls serialize() to build HookPayload::Custom
// before invocation, and deserialize() to reconstruct a Box<dyn PluginPayload>
// from the guest's returned custom payload.

use std::any::TypeId;
use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};

use cpex_core::hooks::payload::{PluginPayload, WasmSerializablePayload};

// ---------------------------------------------------------------------------
// Internal codec — per-type serialize + deserialize closures
// ---------------------------------------------------------------------------

struct PayloadCodec {
    type_name: &'static str,
    serialize: Arc<dyn Fn(&dyn PluginPayload) -> Result<Vec<u8>> + Send + Sync>,
    deserialize: Arc<dyn Fn(&[u8]) -> Result<Box<dyn PluginPayload>> + Send + Sync>,
}

// ---------------------------------------------------------------------------
// PayloadSerializerRegistry
// ---------------------------------------------------------------------------

/// Registry that maps payload types to their WASM serialization codecs.
///
/// Register every payload type that WASM plugins should be able to receive
/// or return. The registry is built once (at factory creation time) and then
/// shared read-only across all handler invocations via `Arc`.
///
/// # Example
///
/// ```ignore
/// let mut registry = PayloadSerializerRegistry::new();
/// registry.register::<MessagePayload>();
/// registry.register::<ToolInvokePayload>();
/// let registry = Arc::new(registry);
/// ```
#[derive(Default)]
pub struct PayloadSerializerRegistry {
    by_type_id: HashMap<TypeId, PayloadCodec>,
    by_type_name: HashMap<&'static str, TypeId>,
}

impl PayloadSerializerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a payload type. `T` must implement both `PluginPayload` and
    /// `WasmSerializablePayload`. Calling `register` twice for the same type
    /// is idempotent — the second call overwrites the first.
    pub fn register<T>(&mut self)
    where
        T: WasmSerializablePayload + 'static,
    {
        let type_id = TypeId::of::<T>();
        let type_name = T::payload_type_name();

        let codec = PayloadCodec {
            type_name,
            serialize: Arc::new(|payload| {
                let concrete = payload
                    .as_any()
                    .downcast_ref::<T>()
                    .ok_or_else(|| anyhow!("serialize: TypeId matched but downcast failed"))?;
                concrete.to_wasm_bytes().map_err(|e| anyhow!(e))
            }),
            deserialize: Arc::new(|bytes| {
                let value = T::from_wasm_bytes(bytes).map_err(|e| anyhow!(e))?;
                Ok(Box::new(value) as Box<dyn PluginPayload>)
            }),
        };

        self.by_type_name.insert(type_name, type_id);
        self.by_type_id.insert(type_id, codec);
    }

    /// Serialize a type-erased payload to `(type_name, json_bytes)`.
    ///
    /// Returns an error if the payload's concrete type has not been registered.
    pub fn serialize(&self, payload: &dyn PluginPayload) -> Result<(&'static str, Vec<u8>)> {
        let type_id = payload.as_any().type_id();
        let codec = self
            .by_type_id
            .get(&type_id)
            .ok_or_else(|| anyhow!("payload type not registered in PayloadSerializerRegistry"))?;
        let bytes = (codec.serialize)(payload)?;
        Ok((codec.type_name, bytes))
    }

    /// Deserialize a payload from `(type_name, json_bytes)` back to a
    /// `Box<dyn PluginPayload>`.
    ///
    /// Returns an error if `type_name` has not been registered.
    pub fn deserialize(&self, type_name: &str, bytes: &[u8]) -> Result<Box<dyn PluginPayload>> {
        let type_id = self
            .by_type_name
            .get(type_name)
            .ok_or_else(|| anyhow!("unknown payload type '{}' in PayloadSerializerRegistry", type_name))?;
        let codec = self
            .by_type_id
            .get(type_id)
            .ok_or_else(|| anyhow!("codec missing for type '{}'", type_name))?;
        (codec.deserialize)(bytes)
    }

    /// Returns true if the given `TypeId` has a registered codec.
    pub fn contains_type_id(&self, type_id: TypeId) -> bool {
        self.by_type_id.contains_key(&type_id)
    }
}
