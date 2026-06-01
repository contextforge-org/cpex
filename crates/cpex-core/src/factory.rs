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
/// # Two dispatch modes
///
/// Factories register under one of two patterns:
///
///   * **Exact-match `kind`** — `register("rate_limiter", factory)`.
///     Matches plugins whose `kind:` is exactly `"rate_limiter"`. This
///     is the standard pattern for in-tree factories.
///   * **Scheme prefix** — `register_scheme("lib", factory)`. Matches
///     plugins whose `kind:` starts with `"lib:"` (e.g.,
///     `kind: "lib:/opt/plugins/foo.so#bar"`). The factory's
///     `create()` receives the full kind string and parses the
///     scheme-specific format itself. Used by dynamic loaders
///     (cdylib, WASM, gRPC) where the kind needs to carry a
///     resource locator alongside the plugin name.
///
/// Exact matches win over scheme matches when both are registered.
///
/// # Examples
///
/// ```rust,ignore
/// let mut factories = PluginFactoryRegistry::new();
/// factories.register("rate_limiter", Box::new(RateLimiterFactory));
/// factories.register_scheme("lib", Box::new(DynamicPluginFactory::new()));
///
/// let manager = PluginManager::from_config(path, &factories)?;
/// ```
pub struct PluginFactoryRegistry {
    /// Factories registered for exact `kind` matches.
    factories: HashMap<String, Box<dyn PluginFactory>>,
    /// Factories registered for `<scheme>:...` style kinds. The
    /// key is the scheme alone (e.g., `"lib"`).
    scheme_factories: HashMap<String, Box<dyn PluginFactory>>,
}

impl PluginFactoryRegistry {
    /// Create an empty factory registry.
    pub fn new() -> Self {
        Self {
            factories: HashMap::new(),
            scheme_factories: HashMap::new(),
        }
    }

    /// Register a factory for a given `kind` name (exact match).
    pub fn register(&mut self, kind: impl Into<String>, factory: Box<dyn PluginFactory>) {
        self.factories.insert(kind.into(), factory);
    }

    /// Register a factory that handles all kinds starting with
    /// `<scheme>:`. The factory's `create()` receives the full
    /// kind string (including the scheme prefix) and is
    /// responsible for parsing the scheme-specific format.
    ///
    /// Example: `register_scheme("lib", ...)` matches plugins with
    /// `kind: "lib:/path/to/foo.so"`, `kind: "lib:/other.so#handler"`,
    /// etc.
    pub fn register_scheme(
        &mut self,
        scheme: impl Into<String>,
        factory: Box<dyn PluginFactory>,
    ) {
        self.scheme_factories.insert(scheme.into(), factory);
    }

    /// Look up a factory by `kind` name. Tries exact match first;
    /// falls back to scheme-prefix match if the kind contains a
    /// `:` separator.
    pub fn get(&self, kind: &str) -> Option<&dyn PluginFactory> {
        if let Some(f) = self.factories.get(kind) {
            return Some(f.as_ref());
        }
        if let Some((scheme, _rest)) = kind.split_once(':') {
            if !scheme.is_empty() {
                return self.scheme_factories.get(scheme).map(|f| f.as_ref());
            }
        }
        None
    }

    /// Whether a factory exists for the given `kind` (exact or
    /// scheme-prefix match).
    pub fn has(&self, kind: &str) -> bool {
        self.get(kind).is_some()
    }

    /// All registered exact-match kind names.
    pub fn kinds(&self) -> Vec<&str> {
        self.factories.keys().map(|s| s.as_str()).collect()
    }

    /// All registered scheme names (without the trailing `:`).
    pub fn schemes(&self) -> Vec<&str> {
        self.scheme_factories.keys().map(|s| s.as_str()).collect()
    }
}

impl Default for PluginFactoryRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::PluginConfig;

    /// Fake factory that records a tag so tests can verify which
    /// factory was dispatched to. `create()` always errors with the
    /// tag embedded — tests look at the error message instead of
    /// constructing real PluginInstances.
    struct TagFactory(&'static str);
    impl PluginFactory for TagFactory {
        fn create(
            &self,
            _config: &PluginConfig,
        ) -> Result<PluginInstance, Box<PluginError>> {
            Err(Box::new(PluginError::Config {
                message: format!("dispatched-to:{}", self.0),
            }))
        }
    }

    fn make_cfg(kind: &str) -> PluginConfig {
        PluginConfig {
            name: "test".into(),
            kind: kind.into(),
            ..Default::default()
        }
    }

    /// Pull the dispatch tag out of a TagFactory error. Uses match
    /// instead of `unwrap_err()` because `PluginInstance` (the Ok
    /// variant) holds `Arc<dyn Plugin>` and doesn't impl Debug.
    fn dispatch_tag(result: Result<PluginInstance, Box<PluginError>>) -> String {
        match result {
            Err(boxed) => match *boxed {
                PluginError::Config { message } => message
                    .strip_prefix("dispatched-to:")
                    .map(String::from)
                    .unwrap_or(message),
                _ => panic!("unexpected error variant"),
            },
            Ok(_) => panic!("TagFactory should always Err"),
        }
    }

    #[test]
    fn exact_match_dispatches_to_registered_factory() {
        let mut reg = PluginFactoryRegistry::new();
        reg.register("rate_limit", Box::new(TagFactory("rate_limit")));
        let factory = reg.get("rate_limit").expect("factory found");
        assert_eq!(dispatch_tag(factory.create(&make_cfg("rate_limit"))), "rate_limit");
    }

    #[test]
    fn unknown_kind_returns_none() {
        let reg = PluginFactoryRegistry::new();
        assert!(reg.get("nonexistent").is_none());
        assert!(!reg.has("nonexistent"));
    }

    #[test]
    fn scheme_match_dispatches_when_no_exact_match() {
        let mut reg = PluginFactoryRegistry::new();
        reg.register_scheme("lib", Box::new(TagFactory("lib-loader")));
        // kind starts with `lib:` → dispatch to scheme factory.
        let factory = reg.get("lib:/opt/plugins/foo.so#bar").expect("factory found");
        assert_eq!(
            dispatch_tag(factory.create(&make_cfg("lib:/opt/plugins/foo.so#bar"))),
            "lib-loader",
        );
    }

    #[test]
    fn exact_match_wins_over_scheme_match() {
        let mut reg = PluginFactoryRegistry::new();
        reg.register("lib", Box::new(TagFactory("exact-lib")));
        reg.register_scheme("lib", Box::new(TagFactory("scheme-lib")));
        let exact = reg.get("lib").unwrap();
        assert_eq!(dispatch_tag(exact.create(&make_cfg("lib"))), "exact-lib");
        let prefixed = reg.get("lib:/path/to.so").unwrap();
        assert_eq!(
            dispatch_tag(prefixed.create(&make_cfg("lib:/path/to.so"))),
            "scheme-lib",
        );
    }

    #[test]
    fn empty_scheme_does_not_match() {
        let mut reg = PluginFactoryRegistry::new();
        reg.register_scheme("", Box::new(TagFactory("would-be-empty")));
        assert!(
            reg.get(":foo").is_none(),
            "leading-colon kind must not dispatch even when empty scheme is registered",
        );
    }

    #[test]
    fn kind_with_colons_in_path_dispatches_correctly() {
        // Windows path with drive-letter colon: `lib:/C:/plugins/foo.dll`.
        // `split_once(':')` splits on the FIRST colon only — scheme is
        // `"lib"`, rest with embedded colons passes through unchanged.
        let mut reg = PluginFactoryRegistry::new();
        reg.register_scheme("lib", Box::new(TagFactory("lib-loader")));
        let factory = reg.get("lib:/C:/plugins/foo.dll").unwrap();
        assert_eq!(
            dispatch_tag(factory.create(&make_cfg("lib:/C:/plugins/foo.dll"))),
            "lib-loader",
        );
    }

    #[test]
    fn schemes_lists_registered_schemes() {
        let mut reg = PluginFactoryRegistry::new();
        reg.register_scheme("lib", Box::new(TagFactory("a")));
        reg.register_scheme("wasm", Box::new(TagFactory("b")));
        let mut names: Vec<&str> = reg.schemes();
        names.sort();
        assert_eq!(names, vec!["lib", "wasm"]);
    }
}
