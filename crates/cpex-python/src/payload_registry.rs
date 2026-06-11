// Location: ./crates/cpex-python/src/payload_registry.rs
// Copyright (c) 2024-2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Bob (AI Assistant)

//! Payload type registry for dynamic hook dispatch.
//!
//! Maps hook names to payload conversion functions, enabling Python dicts
//! to be converted to the appropriate `Box<dyn PluginPayload>` type based
//! on the hook being invoked.

use std::collections::HashMap;
use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::PyDict;

use cpex_core::cmf::MessagePayload;
use cpex_core::delegation::DelegationPayload;
use cpex_core::hooks::payload::PluginPayload;
use cpex_core::identity::IdentityPayload;

/// Trait for converting Python dicts to typed payloads.
///
/// Each payload type implements this trait to provide conversion logic.
/// The registry stores Arc<dyn PayloadConverter> for each hook name.
pub trait PayloadConverter: Send + Sync {
    /// Convert a Python dict to a boxed PluginPayload.
    ///
    /// # Arguments
    ///
    /// * `py` - Python GIL token
    /// * `dict` - Python dictionary containing payload data
    ///
    /// # Returns
    ///
    /// Boxed trait object implementing PluginPayload
    fn convert(&self, py: Python, dict: &Bound<PyDict>) -> PyResult<Box<dyn PluginPayload>>;
}

/// Converter for CMF Message hooks (MessagePayload).
struct MessagePayloadConverter;

impl PayloadConverter for MessagePayloadConverter {
    fn convert(&self, py: Python, dict: &Bound<PyDict>) -> PyResult<Box<dyn PluginPayload>> {
        // Use Python's json module to convert dict to JSON
        let json_module = py.import_bound("json")?;
        let dumps = json_module.getattr("dumps")?;
        let json_str: String = dumps.call1((dict,))?.extract()?;

        // Deserialize to Message
        let message: cpex_core::cmf::Message = serde_json::from_str(&json_str).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Failed to deserialize MessagePayload: {}",
                e
            ))
        })?;

        Ok(Box::new(MessagePayload { message }))
    }
}

/// Converter for identity resolution hooks (IdentityPayload).
struct IdentityPayloadConverter;

impl PayloadConverter for IdentityPayloadConverter {
    fn convert(&self, py: Python, dict: &Bound<PyDict>) -> PyResult<Box<dyn PluginPayload>> {
        // Use Python's json module to convert dict to JSON
        let json_module = py.import_bound("json")?;
        let dumps = json_module.getattr("dumps")?;
        let json_str: String = dumps.call1((dict,))?.extract()?;

        // Deserialize to IdentityPayload
        let payload: IdentityPayload = serde_json::from_str(&json_str).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Failed to deserialize IdentityPayload: {}",
                e
            ))
        })?;

        Ok(Box::new(payload))
    }
}

/// Converter for token delegation hooks (DelegationPayload).
struct DelegationPayloadConverter;

impl PayloadConverter for DelegationPayloadConverter {
    fn convert(&self, py: Python, dict: &Bound<PyDict>) -> PyResult<Box<dyn PluginPayload>> {
        // Use Python's json module to convert dict to JSON
        let json_module = py.import_bound("json")?;
        let dumps = json_module.getattr("dumps")?;
        let json_str: String = dumps.call1((dict,))?.extract()?;

        // Deserialize to DelegationPayload
        let payload: DelegationPayload = serde_json::from_str(&json_str).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Failed to deserialize DelegationPayload: {}",
                e
            ))
        })?;

        Ok(Box::new(payload))
    }
}

/// Registry mapping hook names to payload converters.
///
/// Initialized once at startup with all known hook types. Thread-safe
/// via Arc for shared access across async tasks.
pub struct PayloadRegistry {
    converters: HashMap<String, Arc<dyn PayloadConverter>>,
}

impl PayloadRegistry {
    /// Create a new payload registry with all built-in hooks registered.
    pub fn new() -> Self {
        let mut registry = Self {
            converters: HashMap::new(),
        };

        // Register CMF hooks (MessagePayload)
        let cmf_converter = Arc::new(MessagePayloadConverter);
        registry.register("cmf.tool_pre_invoke", cmf_converter.clone());
        registry.register("cmf.tool_post_invoke", cmf_converter.clone());
        registry.register("cmf.llm_input", cmf_converter.clone());
        registry.register("cmf.llm_output", cmf_converter.clone());
        registry.register("cmf.prompt_pre_fetch", cmf_converter.clone());
        registry.register("cmf.prompt_post_fetch", cmf_converter.clone());
        registry.register("cmf.resource_pre_fetch", cmf_converter.clone());
        registry.register("cmf.resource_post_fetch", cmf_converter);

        // Register identity hook (IdentityPayload)
        let identity_converter = Arc::new(IdentityPayloadConverter);
        registry.register("identity.resolve", identity_converter.clone());
        registry.register("identity_resolve", identity_converter); // Legacy name

        // Register delegation hook (DelegationPayload)
        let delegation_converter = Arc::new(DelegationPayloadConverter);
        registry.register("token.delegate", delegation_converter.clone());
        registry.register("token_delegate", delegation_converter); // Legacy name

        registry
    }

    /// Register a converter for a specific hook name.
    fn register(&mut self, hook_name: &str, converter: Arc<dyn PayloadConverter>) {
        self.converters.insert(hook_name.to_string(), converter);
    }

    /// Convert a Python dict to a typed payload for the given hook.
    ///
    /// # Arguments
    ///
    /// * `hook_name` - Name of the hook being invoked
    /// * `py` - Python GIL token
    /// * `dict` - Python dictionary containing payload data
    ///
    /// # Returns
    ///
    /// Boxed trait object implementing PluginPayload
    ///
    /// # Errors
    ///
    /// Returns `PyValueError` if:
    /// - Hook name is not registered
    /// - Payload conversion fails (invalid structure, missing fields, etc.)
    pub fn convert(
        &self,
        hook_name: &str,
        py: Python,
        dict: &Bound<PyDict>,
    ) -> PyResult<Box<dyn PluginPayload>> {
        let converter = self.converters.get(hook_name).ok_or_else(|| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Unknown hook: '{}'. Supported hooks: {}",
                hook_name,
                self.supported_hooks().join(", ")
            ))
        })?;

        converter.convert(py, dict)
    }

    /// Get a list of all supported hook names.
    pub fn supported_hooks(&self) -> Vec<String> {
        let mut hooks: Vec<String> = self.converters.keys().cloned().collect();
        hooks.sort();
        hooks
    }

    /// Check if a hook name is registered.
    pub fn is_supported(&self, hook_name: &str) -> bool {
        self.converters.contains_key(hook_name)
    }
}

impl Default for PayloadRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_initialization() {
        let registry = PayloadRegistry::new();

        // Should have 8 CMF hooks + 2 identity + 2 delegation = 12 total
        assert_eq!(registry.converters.len(), 12);

        // Check CMF hooks
        assert!(registry.is_supported("cmf.tool_pre_invoke"));
        assert!(registry.is_supported("cmf.llm_input"));

        // Check identity hooks
        assert!(registry.is_supported("identity.resolve"));
        assert!(registry.is_supported("identity_resolve"));

        // Check delegation hooks
        assert!(registry.is_supported("token.delegate"));
        assert!(registry.is_supported("token_delegate"));
    }

    #[test]
    fn test_unsupported_hook() {
        let registry = PayloadRegistry::new();
        assert!(!registry.is_supported("unknown.hook"));
    }

    #[test]
    fn test_supported_hooks_list() {
        let registry = PayloadRegistry::new();
        let hooks = registry.supported_hooks();

        // Should be sorted
        assert_eq!(hooks[0], "cmf.llm_input");
        assert!(hooks.contains(&"identity.resolve".to_string()));
    }
}

// Made with Bob