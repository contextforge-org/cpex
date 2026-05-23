// Location: ./crates/cpex-dynamic-plugin/src/host.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Host-side: `DynamicPluginFactory` implements cpex-core's
// `PluginFactory` and is registered under a scheme (default `"lib"`)
// via `PluginManager::register_factory_scheme(...)`. Operators
// reference dynamic plugins with URL-shaped `kind:` strings:
//
// ```yaml
// plugins:
//   - name: rate-limit
//     kind: "lib:/opt/plugins/rate_limit.so#rate_limit_v1"
//     hooks: [cmf.tool_pre_invoke]
//     capabilities: [read_headers]
//     config:
//       max_per_second: 100      # plugin's OWN config; loader
//                                # concerns stay in `kind:`
// ```
//
// # Flow
//
//   1. Parse `config.kind` as `<scheme>:<path>[#handler]`.
//   2. Validate `scheme` matches `self.scheme`.
//   3. `Library::new(path)` to dlopen, then `Box::leak` the Library
//      so it survives until process exit (see "Why leak" below).
//   4. Bind to `ENTRY_POINT_SYMBOL`.
//   5. Serialize the `PluginConfig` to JSON.
//   6. Call the entry point with `ABI_VERSION` + config bytes +
//      out-pointer.
//   7. Match on `EntryPointResult` → `PluginError::Config` for any
//      error variant (with the variant name embedded for ops
//      diagnostics).
//   8. On `Ok`: `Box::from_raw` the registration; extract
//      `plugin` + `handlers`; optionally filter handlers to just
//      the one named in the `#handler` fragment.
//   9. Build `PluginInstance`.
//
// # Why leak the library
//
// `Arc<dyn Plugin>` and `Arc<dyn AnyHookHandler>` hold vtable
// pointers into the cdylib's text section. If the library is
// unloaded (`Drop` on `Library` → `dlclose`) while ANY of those
// Arcs is still live, the next Arc operation jumps to unmapped
// memory and SIGSEGVs. The Arcs are cloned into the registry and
// can outlive any wrapper struct we'd hand them to, so the only
// safe path is to keep the library mapped for the process
// lifetime.
//
// Memory cost: each loaded cdylib's text section (typically a few
// hundred KB to a few MB) stays resident. Operators load plugins
// at startup and never unload — same model as Bevy and most Rust
// plugin frameworks. Hot-reload would need a reference-counted
// library wrapper coordinated with all derived Arcs; that's its
// own slice.

use std::sync::Arc;

use libloading::Library;

use cpex_core::error::PluginError;
use cpex_core::factory::{PluginFactory, PluginInstance};
use cpex_core::plugin::PluginConfig;

use crate::abi::{
    EntryPointFn, EntryPointResult, PluginRegistration, ABI_VERSION, ENTRY_POINT_SYMBOL,
};

/// Loads Rust cdylib plugins at runtime. Registered under a scheme
/// (default `"lib"`) via `PluginManager::register_factory_scheme`.
/// Operators reference dynamic plugins with URL-shaped `kind:`
/// strings like `"lib:/path/to/plugin.so#handler"`.
pub struct DynamicPluginFactory {
    scheme: String,
}

impl DynamicPluginFactory {
    /// Build with the default scheme `"lib"`.
    pub fn new() -> Self {
        Self {
            scheme: "lib".to_string(),
        }
    }

    /// Override the default scheme. The factory must be registered
    /// under the same scheme via `PluginManager::register_factory_scheme`.
    pub fn with_scheme(mut self, scheme: impl Into<String>) -> Self {
        self.scheme = scheme.into();
        self
    }

    /// Returns the scheme this factory is configured for.
    pub fn scheme(&self) -> &str {
        &self.scheme
    }
}

impl Default for DynamicPluginFactory {
    fn default() -> Self {
        Self::new()
    }
}

/// Parsed kind: `<scheme>:<path>[#handler]`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedKind {
    /// Path to the cdylib file.
    library_path: String,
    /// Optional handler name from the `#` fragment. `None` means
    /// "use all handlers the registration returned." `Some(name)`
    /// means "filter to just the handler registered under that
    /// hook name in the registration."
    handler: Option<String>,
}

/// Parse a `kind:` string into its scheme, path, and optional
/// handler fragment. Returns an error message if the shape is
/// malformed (operator-facing diagnostic).
///
/// Examples:
///   - `lib:/opt/plugins/foo.so`             → path only
///   - `lib:/opt/plugins/foo.so#bar`         → path + handler "bar"
///   - `lib:/C:/plugins/foo.dll`             → Windows path; preserved
///   - `lib:./relative.so`                   → relative path, resolved
///                                              by the OS loader at dlopen time
fn parse_kind(kind: &str, expected_scheme: &str) -> Result<ParsedKind, String> {
    let Some((scheme, rest)) = kind.split_once(':') else {
        return Err(format!(
            "kind '{kind}' missing scheme prefix; expected '{expected_scheme}:<path>[#handler]'",
        ));
    };
    if scheme != expected_scheme {
        return Err(format!(
            "kind '{kind}' has scheme '{scheme}' but factory is registered for scheme '{expected_scheme}'",
        ));
    }
    let (library_path, handler) = match rest.split_once('#') {
        Some((p, h)) => (p.to_string(), Some(h.to_string())),
        None => (rest.to_string(), None),
    };
    if library_path.is_empty() {
        return Err(format!("kind '{kind}' has empty library path"));
    }
    Ok(ParsedKind {
        library_path,
        handler,
    })
}

impl PluginFactory for DynamicPluginFactory {
    fn create(
        &self,
        config: &PluginConfig,
    ) -> Result<PluginInstance, Box<PluginError>> {
        // 1. Parse the kind string.
        let parsed = parse_kind(&config.kind, &self.scheme).map_err(|e| {
            Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (apl-dynamic-plugin): {}",
                    config.name, e
                ),
            })
        })?;

        // 2. dlopen + leak. After this point the library lives until
        //    process exit. `Box::leak` returns a &'static reference;
        //    we hold a raw pointer that we never reclaim.
        //
        //    Safety: `Library::new` is unsafe because loading
        //    arbitrary code is inherently unsafe (the library could
        //    have init constructors that do anything). Operator
        //    chose the path; we trust them to know what they're
        //    loading.
        let library: &'static Library = match unsafe { Library::new(&parsed.library_path) }
        {
            Ok(lib) => Box::leak(Box::new(lib)),
            Err(e) => {
                return Err(Box::new(PluginError::Config {
                    message: format!(
                        "plugin '{}': failed to dlopen '{}': {e}",
                        config.name, parsed.library_path,
                    ),
                }));
            }
        };

        // 3. Bind to the entry-point symbol.
        //
        //    Safety: the cast to `EntryPointFn` is unchecked — if
        //    the symbol exists with a different signature, calls
        //    will silently misbehave. Mitigation: the ABI version
        //    handshake (step 6) catches mismatched plugins.
        let entry: libloading::Symbol<EntryPointFn> = match unsafe {
            library.get::<EntryPointFn>(ENTRY_POINT_SYMBOL)
        } {
            Ok(sym) => sym,
            Err(e) => {
                return Err(Box::new(PluginError::Config {
                    message: format!(
                        "plugin '{}': cdylib '{}' does not export '{}' \
                         (did you use the cpex_dynamic_plugin! macro?): {e}",
                        config.name,
                        parsed.library_path,
                        std::str::from_utf8(ENTRY_POINT_SYMBOL)
                            .unwrap_or("<bad utf8>"),
                    ),
                }));
            }
        };

        // 4. Serialize the PluginConfig the plugin will deserialize.
        let config_bytes = serde_json::to_vec(config).map_err(|e| {
            Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}': failed to serialize PluginConfig for plugin entry point: {e}",
                    config.name,
                ),
            })
        })?;

        // 5. Call the entry point. Out-pointer is what the plugin
        //    writes its `Box::into_raw` registration through.
        let mut out_registration: *mut PluginRegistration = std::ptr::null_mut();
        let result = unsafe {
            entry(
                ABI_VERSION,
                config_bytes.as_ptr(),
                config_bytes.len(),
                &mut out_registration as *mut *mut PluginRegistration,
            )
        };

        // 6. Translate the entry-point result.
        match result {
            EntryPointResult::Ok => {}
            EntryPointResult::AbiMismatch => {
                return Err(Box::new(PluginError::Config {
                    message: format!(
                        "plugin '{}': cdylib '{}' was compiled against a different \
                         cpex-dynamic-plugin ABI version than the host (host: {}). \
                         Rebuild the plugin against the same cpex-core / \
                         cpex-dynamic-plugin versions the host is using.",
                        config.name, parsed.library_path, ABI_VERSION,
                    ),
                }));
            }
            EntryPointResult::ConfigParseError => {
                return Err(Box::new(PluginError::Config {
                    message: format!(
                        "plugin '{}': cdylib '{}' rejected its PluginConfig — \
                         likely a structural mismatch between operator's YAML \
                         and the plugin's expected config schema",
                        config.name, parsed.library_path,
                    ),
                }));
            }
            EntryPointResult::InitializationError => {
                return Err(Box::new(PluginError::Config {
                    message: format!(
                        "plugin '{}': cdylib '{}' failed to initialize (the \
                         plugin's create closure returned an error — check the \
                         cdylib's logs / stderr for details)",
                        config.name, parsed.library_path,
                    ),
                }));
            }
            EntryPointResult::Panic => {
                return Err(Box::new(PluginError::Config {
                    message: format!(
                        "plugin '{}': cdylib '{}' panicked during construction. \
                         Caught at the FFI boundary; check the cdylib's logs / \
                         stderr for the panic message and backtrace",
                        config.name, parsed.library_path,
                    ),
                }));
            }
        }

        if out_registration.is_null() {
            return Err(Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}': cdylib '{}' returned EntryPointResult::Ok but \
                     left out_registration null — plugin's cpex_plugin_create \
                     implementation is buggy",
                    config.name, parsed.library_path,
                ),
            }));
        }

        // 7. Take ownership of the registration.
        //    Safety: plugin wrote a valid `Box::into_raw` pointer
        //    per the ABI contract; we reclaim it here. Same
        //    allocator on both sides (system) per the spec.
        let registration: PluginRegistration =
            *unsafe { Box::from_raw(out_registration) };

        // 8. Optional handler filter: if the kind had a `#handler`
        //    fragment, keep only the matching one.
        let handlers = match parsed.handler {
            None => registration.handlers,
            Some(wanted) => {
                let mut filtered: Vec<(String, Arc<dyn cpex_core::registry::AnyHookHandler>)> =
                    registration
                        .handlers
                        .into_iter()
                        .filter(|(name, _)| name == &wanted)
                        .collect();
                if filtered.is_empty() {
                    return Err(Box::new(PluginError::Config {
                        message: format!(
                            "plugin '{}': cdylib '{}' returned no handler named '{}' \
                             (the `#{}` fragment in the kind selected a handler that \
                             the plugin didn't register)",
                            config.name, parsed.library_path, wanted, wanted,
                        ),
                    }));
                }
                // Reorder so the named handler is first (deterministic).
                filtered.sort_by(|a, b| a.0.cmp(&b.0));
                filtered
            }
        };

        if handlers.is_empty() {
            return Err(Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}': cdylib '{}' returned a PluginRegistration with \
                     zero handlers — plugin must register at least one",
                    config.name, parsed.library_path,
                ),
            }));
        }

        // 9. Convert to PluginInstance shape.
        //    PluginInstance.handlers uses `&'static str` for the
        //    hook name; we transmute via `Box::leak(name.into_boxed_str())`.
        //    The handler-name strings are tiny and we already
        //    accepted the library leak, so adding string leaks is
        //    proportionate.
        let leaked_handlers: Vec<(&'static str, Arc<dyn cpex_core::registry::AnyHookHandler>)> =
            handlers
                .into_iter()
                .map(|(name, handler)| {
                    let leaked: &'static str =
                        Box::leak(name.into_boxed_str());
                    (leaked, handler)
                })
                .collect();

        tracing::info!(
            plugin_name = %config.name,
            library = %parsed.library_path,
            plugin_reported_name = %registration.name,
            plugin_reported_version = %registration.version,
            handler_count = leaked_handlers.len(),
            "loaded dynamic plugin",
        );

        Ok(PluginInstance {
            plugin: registration.plugin,
            handlers: leaked_handlers,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kind_simple() {
        let parsed = parse_kind("lib:/opt/plugins/foo.so", "lib").unwrap();
        assert_eq!(parsed.library_path, "/opt/plugins/foo.so");
        assert_eq!(parsed.handler, None);
    }

    #[test]
    fn parse_kind_with_handler_fragment() {
        let parsed =
            parse_kind("lib:/opt/plugins/foo.so#my_handler", "lib").unwrap();
        assert_eq!(parsed.library_path, "/opt/plugins/foo.so");
        assert_eq!(parsed.handler.as_deref(), Some("my_handler"));
    }

    #[test]
    fn parse_kind_with_relative_path() {
        let parsed = parse_kind("lib:./plugins/foo.so", "lib").unwrap();
        assert_eq!(parsed.library_path, "./plugins/foo.so");
    }

    #[test]
    fn parse_kind_windows_path() {
        // Windows drive-letter colon should pass through — we split
        // on the FIRST colon only.
        let parsed = parse_kind("lib:/C:/plugins/foo.dll", "lib").unwrap();
        assert_eq!(parsed.library_path, "/C:/plugins/foo.dll");
    }

    #[test]
    fn parse_kind_wrong_scheme_errors() {
        let err = parse_kind("wasm:/opt/foo.wasm", "lib").unwrap_err();
        assert!(err.contains("scheme 'wasm'"));
        assert!(err.contains("registered for scheme 'lib'"));
    }

    #[test]
    fn parse_kind_missing_scheme_errors() {
        let err = parse_kind("/opt/foo.so", "lib").unwrap_err();
        assert!(err.contains("missing scheme prefix"));
    }

    #[test]
    fn parse_kind_empty_path_errors() {
        let err = parse_kind("lib:", "lib").unwrap_err();
        assert!(err.contains("empty library path"));
    }

    #[test]
    fn parse_kind_empty_handler_fragment_treated_as_empty_string() {
        // `lib:/foo.so#` → handler = Some("") — unusual but
        // we let the create() filter step catch it via the
        // "no handler named ''" error path.
        let parsed = parse_kind("lib:/foo.so#", "lib").unwrap();
        assert_eq!(parsed.handler.as_deref(), Some(""));
    }
}
