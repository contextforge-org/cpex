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
    EntryPointFn, EntryPointResult, ListFn, PluginManifest, PluginRegistration, ABI_VERSION,
    ENTRY_POINT_SYMBOL, LIST_SYMBOL,
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

/// Parsed kind: `<scheme>:<path>[?entry=<name>][#handler]`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedKind {
    /// Path to the cdylib file.
    library_path: String,
    /// Optional entry-point selector from the `?entry=` query
    /// parameter. `None` means "use the default entry point
    /// `cpex_plugin_create`" (single-plugin cdylib). `Some(name)`
    /// means "look up `cpex_plugin_create_<name>` instead"
    /// (multi-plugin cdylib).
    ///
    /// Validated as a C identifier (`[a-zA-Z_][a-zA-Z0-9_]*`) in
    /// `parse_kind` so we never construct a malformed symbol name.
    entry: Option<String>,
    /// Optional handler name from the `#` fragment. `None` means
    /// "use all handlers the registration returned." `Some(name)`
    /// means "filter to just the handler registered under that
    /// hook name in the registration."
    handler: Option<String>,
}

/// Reject entry names that aren't valid C identifiers. Catches
/// malformed `?entry=` values at the URL-parse stage so we don't
/// construct invalid symbol names or pass weird bytes to dlsym.
///
/// Accepts: starts with letter or underscore, followed by letters,
/// digits, or underscores. Same rule applies to the Rust ident
/// the macro accepts on the plugin side, so the two ends stay in
/// sync.
fn validate_entry_ident(entry: &str) -> Result<(), String> {
    if entry.is_empty() {
        return Err("entry name cannot be empty".to_string());
    }
    let mut chars = entry.chars();
    let first = chars.next().expect("non-empty checked above");
    if !(first.is_ascii_alphabetic() || first == '_') {
        return Err(format!(
            "entry name '{entry}' must start with a letter or underscore (got '{first}')"
        ));
    }
    for c in chars {
        if !(c.is_ascii_alphanumeric() || c == '_') {
            return Err(format!(
                "entry name '{entry}' contains invalid character '{c}'; \
                 only [a-zA-Z0-9_] allowed"
            ));
        }
    }
    Ok(())
}

/// Parse a `kind:` string into its scheme, path, optional entry,
/// and optional handler fragment. Returns an error message if the
/// shape is malformed (operator-facing diagnostic).
///
/// URL component order: `<scheme>:<path>[?<query>][#<fragment>]`.
/// Currently the only recognized query parameter is `entry=<name>`;
/// unknown parameters are rejected (fail-loud beats silently
/// ignoring operator typos).
///
/// Examples:
///   - `lib:/opt/plugins/foo.so`                     → path only
///   - `lib:/opt/plugins/foo.so#bar`                 → path + handler "bar"
///   - `lib:/opt/plugins/foo.so?entry=baz`           → path + entry "baz"
///   - `lib:/opt/plugins/multi.so?entry=baz#bar`     → path + entry + handler
///   - `lib:/C:/plugins/foo.dll`                     → Windows path; preserved
///   - `lib:./relative.so`                           → relative path,
///                                                      resolved by OS loader
fn parse_kind(kind: &str, expected_scheme: &str) -> Result<ParsedKind, String> {
    let Some((scheme, rest)) = kind.split_once(':') else {
        return Err(format!(
            "kind '{kind}' missing scheme prefix; \
             expected '{expected_scheme}:<path>[?entry=<name>][#handler]'",
        ));
    };
    if scheme != expected_scheme {
        return Err(format!(
            "kind '{kind}' has scheme '{scheme}' but factory is registered for scheme '{expected_scheme}'",
        ));
    }
    // Split the fragment off first (it comes last in URL order),
    // then split query off the remaining (path + query) part. This
    // ordering means a `?` inside a fragment (unusual but legal)
    // stays in the fragment, and a `#` in the path is impossible
    // because we'd already have consumed it as the fragment marker.
    let (before_frag, handler) = match rest.split_once('#') {
        Some((b, h)) => (b, Some(h.to_string())),
        None => (rest, None),
    };
    let (library_path, entry) = match before_frag.split_once('?') {
        Some((path, query)) => {
            let entry = parse_query_entry(kind, query)?;
            (path.to_string(), entry)
        }
        None => (before_frag.to_string(), None),
    };
    if library_path.is_empty() {
        return Err(format!("kind '{kind}' has empty library path"));
    }
    if let Some(ref e) = entry {
        validate_entry_ident(e).map_err(|why| format!("kind '{kind}': {why}"))?;
    }
    Ok(ParsedKind {
        library_path,
        entry,
        handler,
    })
}

/// Parse the query string of a kind URL. Only `entry=<name>` is
/// recognized; multiple params would be ambiguous (which one wins?)
/// and unknown keys signal an operator typo we'd rather surface
/// than swallow.
fn parse_query_entry(kind: &str, query: &str) -> Result<Option<String>, String> {
    if query.is_empty() {
        return Ok(None);
    }
    // Reject `&` — we don't support multi-param queries yet, and a
    // bare `&` is almost certainly a copy-paste mistake.
    if query.contains('&') {
        return Err(format!(
            "kind '{kind}' has multi-parameter query '{query}'; \
             only a single 'entry=<name>' parameter is supported"
        ));
    }
    let Some((key, value)) = query.split_once('=') else {
        return Err(format!(
            "kind '{kind}' has malformed query '{query}'; expected 'entry=<name>'"
        ));
    };
    if key != "entry" {
        return Err(format!(
            "kind '{kind}' has unknown query parameter '{key}'; \
             only 'entry=<name>' is recognized"
        ));
    }
    if value.is_empty() {
        return Err(format!(
            "kind '{kind}' has empty 'entry=' value; \
             provide an entry name like 'entry=my_plugin'"
        ));
    }
    Ok(Some(value.to_string()))
}

/// Try to read the cdylib's optional plugin manifest. Returns
/// `Ok(None)` when the cdylib doesn't export the discovery symbol
/// (legacy single-plugin layout) — that's not an error. Returns
/// `Err` when the manifest IS present but its ABI version is wrong;
/// we shouldn't keep going in that case because the entries slice
/// could have a different layout than we expect.
///
/// # Safety
///
/// Caller guarantees `library` outlives any use of the returned
/// reference. In practice we leak the library in `create()`, so the
/// returned `'static` lifetime is honest: the manifest data lives
/// for the rest of the process.
unsafe fn read_manifest(
    library: &'static Library,
) -> Result<Option<&'static PluginManifest>, String> {
    let sym: libloading::Symbol<'_, ListFn> = match unsafe { library.get(LIST_SYMBOL) } {
        Ok(s) => s,
        Err(_) => return Ok(None), // No manifest exported — that's fine.
    };
    let ptr = unsafe { sym() };
    if ptr.is_null() {
        // Plugin exposed the symbol but returned null — treat as
        // "no manifest" rather than an error. Plugin author can do
        // this to disable discovery without removing the symbol.
        return Ok(None);
    }
    let manifest: &'static PluginManifest = unsafe { &*ptr };
    if manifest.abi_version != ABI_VERSION {
        return Err(format!(
            "cdylib's plugin manifest reports ABI version {} but host expects {}",
            manifest.abi_version, ABI_VERSION,
        ));
    }
    Ok(Some(manifest))
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

        // 3a. Read the optional plugin manifest. If the cdylib
        //     exposes one, we use it to:
        //       * Validate the operator's `?entry=` against the
        //         advertised entries.
        //       * Produce a "did you mean..." style error listing
        //         available entries when the operator gets it wrong.
        //     If the cdylib doesn't expose a manifest (single-plugin
        //     layout, or operator chose not to), we fall through to
        //     plain dlsym and surface its error verbatim.
        let manifest = match unsafe { read_manifest(library) } {
            Ok(m) => m,
            Err(e) => {
                return Err(Box::new(PluginError::Config {
                    message: format!(
                        "plugin '{}': cdylib '{}' has an incompatible manifest: {e}. \
                         Rebuild the plugin against the same cpex-dynamic-plugin \
                         version the host is using.",
                        config.name, parsed.library_path,
                    ),
                }));
            }
        };

        // 3b. If the operator specified `?entry=foo` AND the cdylib
        //     advertised a manifest, validate up-front that `foo`
        //     is in the manifest. This gives the friendliest error
        //     message ("available: [bar, baz]") before we even try
        //     dlsym. If the manifest is absent we just skip this
        //     check — the dlsym below will fail with a less helpful
        //     but still actionable error.
        if let (Some(requested), Some(m)) = (&parsed.entry, manifest) {
            if !m.entries.iter().any(|e| e.entry == requested.as_str()) {
                let available: Vec<&str> =
                    m.entries.iter().map(|e| e.entry).collect();
                return Err(Box::new(PluginError::Config {
                    message: format!(
                        "plugin '{}': cdylib '{}' has no entry '{}'. \
                         Available entries: [{}]",
                        config.name,
                        parsed.library_path,
                        requested,
                        available.join(", "),
                    ),
                }));
            }
        }

        // 3c. Build the symbol name. Default = `cpex_plugin_create`
        //     (single-plugin macro); with `?entry=foo` it becomes
        //     `cpex_plugin_create_foo` (multi-plugin macro). The
        //     entry name has already been validated as a C
        //     identifier in `parse_kind`, so we can safely concat
        //     bytes without escaping.
        let symbol_name: Vec<u8> = match &parsed.entry {
            None => ENTRY_POINT_SYMBOL.to_vec(),
            Some(e) => {
                let mut s = Vec::with_capacity(b"cpex_plugin_create_".len() + e.len());
                s.extend_from_slice(b"cpex_plugin_create_");
                s.extend_from_slice(e.as_bytes());
                s
            }
        };

        // 3d. Bind to the entry-point symbol.
        //
        //    Safety: the cast to `EntryPointFn` is unchecked — if
        //    the symbol exists with a different signature, calls
        //    will silently misbehave. Mitigation: the ABI version
        //    handshake (step 6) catches mismatched plugins.
        let entry: libloading::Symbol<EntryPointFn> = match unsafe {
            library.get::<EntryPointFn>(&symbol_name)
        } {
            Ok(sym) => sym,
            Err(e) => {
                let symbol_display = std::str::from_utf8(&symbol_name)
                    .unwrap_or("<bad utf8>");
                let hint = match &parsed.entry {
                    None => "did you use the cpex_dynamic_plugin! macro?".to_string(),
                    Some(entry_name) => match manifest {
                        Some(m) => {
                            let available: Vec<&str> =
                                m.entries.iter().map(|e| e.entry).collect();
                            format!(
                                "available entries per the cdylib's manifest: [{}]",
                                available.join(", "),
                            )
                        }
                        None => format!(
                            "cdylib does not expose a manifest, so the host can't \
                             list available entries — check the plugin's documentation. \
                             You requested entry '{entry_name}'.",
                        ),
                    },
                };
                return Err(Box::new(PluginError::Config {
                    message: format!(
                        "plugin '{}': cdylib '{}' does not export '{}' ({}): {e}",
                        config.name,
                        parsed.library_path,
                        symbol_display,
                        hint,
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
            entry = parsed.entry.as_deref().unwrap_or("<default>"),
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
        assert_eq!(parsed.entry, None);
        assert_eq!(parsed.handler, None);
    }

    #[test]
    fn parse_kind_with_handler_fragment() {
        let parsed =
            parse_kind("lib:/opt/plugins/foo.so#my_handler", "lib").unwrap();
        assert_eq!(parsed.library_path, "/opt/plugins/foo.so");
        assert_eq!(parsed.entry, None);
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

    // ----- ?entry= query-string parsing -----

    #[test]
    fn parse_kind_with_entry_query() {
        let parsed = parse_kind("lib:/opt/multi.so?entry=foo", "lib").unwrap();
        assert_eq!(parsed.library_path, "/opt/multi.so");
        assert_eq!(parsed.entry.as_deref(), Some("foo"));
        assert_eq!(parsed.handler, None);
    }

    #[test]
    fn parse_kind_with_entry_and_handler() {
        // Full URL shape: path + query + fragment.
        let parsed =
            parse_kind("lib:/opt/multi.so?entry=foo#my_handler", "lib").unwrap();
        assert_eq!(parsed.library_path, "/opt/multi.so");
        assert_eq!(parsed.entry.as_deref(), Some("foo"));
        assert_eq!(parsed.handler.as_deref(), Some("my_handler"));
    }

    #[test]
    fn parse_kind_entry_with_underscore_and_digits() {
        // Valid C identifier characters all the way through.
        let parsed =
            parse_kind("lib:/opt/multi.so?entry=rate_limiter_v2", "lib").unwrap();
        assert_eq!(parsed.entry.as_deref(), Some("rate_limiter_v2"));
    }

    #[test]
    fn parse_kind_entry_starting_with_underscore() {
        let parsed = parse_kind("lib:/opt/multi.so?entry=_private", "lib").unwrap();
        assert_eq!(parsed.entry.as_deref(), Some("_private"));
    }

    #[test]
    fn parse_kind_entry_starting_with_digit_errors() {
        // C identifiers can't start with a digit.
        let err = parse_kind("lib:/opt/multi.so?entry=1foo", "lib").unwrap_err();
        assert!(err.contains("must start with a letter or underscore"));
    }

    #[test]
    fn parse_kind_entry_with_invalid_char_errors() {
        let err =
            parse_kind("lib:/opt/multi.so?entry=foo-bar", "lib").unwrap_err();
        assert!(err.contains("invalid character"));
    }

    #[test]
    fn parse_kind_empty_entry_value_errors() {
        let err = parse_kind("lib:/opt/multi.so?entry=", "lib").unwrap_err();
        assert!(err.contains("empty 'entry=' value"));
    }

    #[test]
    fn parse_kind_unknown_query_param_errors() {
        let err =
            parse_kind("lib:/opt/multi.so?other=value", "lib").unwrap_err();
        assert!(err.contains("unknown query parameter 'other'"));
    }

    #[test]
    fn parse_kind_multi_param_query_errors() {
        // `&` separator is rejected — only one param supported.
        let err =
            parse_kind("lib:/opt/multi.so?entry=foo&extra=bar", "lib").unwrap_err();
        assert!(err.contains("multi-parameter query"));
    }

    #[test]
    fn parse_kind_malformed_query_errors() {
        let err = parse_kind("lib:/opt/multi.so?noequalssign", "lib").unwrap_err();
        assert!(err.contains("malformed query"));
    }

    #[test]
    fn parse_kind_empty_query_string_treated_as_no_entry() {
        // Trailing `?` with no content — we treat it as no entry
        // rather than an error, since the operator's intent is
        // clear (just a stray character).
        let parsed = parse_kind("lib:/opt/multi.so?", "lib").unwrap();
        assert_eq!(parsed.entry, None);
    }

    // ----- validate_entry_ident -----

    #[test]
    fn validate_entry_ident_accepts_valid_names() {
        assert!(validate_entry_ident("foo").is_ok());
        assert!(validate_entry_ident("foo_bar").is_ok());
        assert!(validate_entry_ident("_private").is_ok());
        assert!(validate_entry_ident("a").is_ok());
        assert!(validate_entry_ident("rate_limiter_v2").is_ok());
    }

    #[test]
    fn validate_entry_ident_rejects_empty() {
        assert!(validate_entry_ident("").is_err());
    }

    #[test]
    fn validate_entry_ident_rejects_leading_digit() {
        assert!(validate_entry_ident("1foo").is_err());
        assert!(validate_entry_ident("123").is_err());
    }

    #[test]
    fn validate_entry_ident_rejects_special_chars() {
        assert!(validate_entry_ident("foo-bar").is_err());
        assert!(validate_entry_ident("foo.bar").is_err());
        assert!(validate_entry_ident("foo bar").is_err());
        assert!(validate_entry_ident("foo!").is_err());
        assert!(validate_entry_ident("foo$bar").is_err());
    }
}
