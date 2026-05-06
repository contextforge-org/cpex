// Location: ./crates/cpex-core/src/factory.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Plugin factory registry.
//
// Provides a factory pattern for creating plugin instances from
// config. The host registers factories by `kind` name before
// loading config. When the manager processes a config file, it
// looks up the factory for each plugin's `kind` and calls create().
//
// This decouples plugin instantiation from the manager — the
// manager doesn't know how to create a "builtin" vs "wasm" vs
// "python" plugin. The factory does.
//
// Mirrors the Python framework's PluginLoader in
// cpex/framework/loader/plugin.py.

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::PluginError;
use crate::plugin::{Plugin, PluginConfig};
use crate::registry::AnyHookHandler;

// ---------------------------------------------------------------------------
// Plugin Factory Trait
// ---------------------------------------------------------------------------

/// Factory for creating plugin instances from config.
///
/// The host registers factories by `kind` name before loading
/// config. When the manager processes a config file, it looks up
/// the factory for each plugin's `kind` and calls `create()`.
///
/// The factory returns both the plugin and its handler because it
/// knows the concrete types — which handler traits the plugin
/// implements and which hooks it handles.
///
/// # Examples
///
/// ```rust,ignore
/// struct RateLimiterFactory;
///
/// impl PluginFactory for RateLimiterFactory {
///     fn create(&self, config: &PluginConfig)
///         -> Result<PluginInstance, Box<PluginError>>
///     {
///         let plugin = Arc::new(RateLimiter::from_config(config)?);
///         let handler = Arc::new(TypedHandlerAdapter::<RequestHeadersReceived, _>::new(
///             Arc::clone(&plugin),
///         ));
///         Ok(PluginInstance { plugin, handler })
///     }
/// }
///
/// let mut factories = PluginFactoryRegistry::new();
/// factories.register("security/rate_limit", Box::new(RateLimiterFactory));
/// ```
pub trait PluginFactory: Send + Sync {
    /// Create a plugin instance and its handler from config.
    ///
    /// The `config` is the plugin's entry from the YAML file.
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>>;
}

/// A created plugin instance — the plugin and its type-erased handlers.
///
/// Each handler is paired with the hook name it handles. A plugin
/// that implements multiple hook types (e.g., `ToolPreInvoke` and
/// `ToolPostInvoke`) returns one entry per hook.
pub struct PluginInstance {
    /// The plugin implementation.
    pub plugin: Arc<dyn Plugin>,

    /// Type-erased handlers paired with their hook names.
    /// Each entry maps a hook name to the adapter for that hook type.
    pub handlers: Vec<(&'static str, Arc<dyn AnyHookHandler>)>,
}

// ---------------------------------------------------------------------------
// Plugin Factory Registry
// ---------------------------------------------------------------------------

/// Registry of plugin factories keyed by `kind` name.
///
/// The host populates this before calling `PluginManager::from_config()`.
/// Each factory knows how to create plugins of a specific kind.
///
/// # Examples
///
/// ```rust,ignore
/// let mut factories = PluginFactoryRegistry::new();
/// factories.register("builtin/rate_limit", Box::new(RateLimiterFactory));
/// factories.register("builtin/identity", Box::new(IdentityFactory));
///
/// let manager = PluginManager::from_config(path, &factories)?;
/// ```
pub struct PluginFactoryRegistry {
    factories: HashMap<String, Box<dyn PluginFactory>>,
}

impl PluginFactoryRegistry {
    /// Create an empty factory registry.
    pub fn new() -> Self {
        Self {
            factories: HashMap::new(),
        }
    }

    /// Register a factory for a given `kind` name.
    pub fn register(&mut self, kind: impl Into<String>, factory: Box<dyn PluginFactory>) {
        self.factories.insert(kind.into(), factory);
    }

    /// Look up a factory by `kind` name.
    pub fn get(&self, kind: &str) -> Option<&dyn PluginFactory> {
        self.factories.get(kind).map(|f| f.as_ref())
    }

    /// Whether a factory exists for the given `kind`.
    pub fn has(&self, kind: &str) -> bool {
        self.factories.contains_key(kind)
    }

    /// All registered kind names.
    pub fn kinds(&self) -> Vec<&str> {
        self.factories.keys().map(|s| s.as_str()).collect()
    }
}

impl Default for PluginFactoryRegistry {
    fn default() -> Self {
        Self::new()
    }
}
