// Location: ./crates/apl-core/src/plugin_decl.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Plugin declarations — the parsed shape of the `plugins:` block in a
// unified-config YAML document, plus the per-route override block and
// the 2-layer resolver that merges them.
//
// Spec: `contextforge-plugins-framework-apl/docs/specs/unified-config-proposal.md`,
//   §"Plugin Declaration" (lines 173+)
//   §"Route-Level Plugin Config Overrides" (lines 360+)
//
// Layering, per spec:
//   - Global declaration  (root `plugins:`)             — full shape
//   - Route-level override (`routes.<rt>.plugins.<p>:`) — `config`,
//     `capabilities`, `on_error` only; hooks/kind/source NOT overridable
//   - `EffectivePlugin::resolve(name, registry, route)` merges them.
//
// v0 enforcement: hooks are read from the resolved view (which equals
// the global view since hooks aren't overridable). Config + capability
// overrides are parsed and stored so they survive in the IR for later
// consumers, but not propagated to dispatch yet — capability gating
// and per-call config-override plumbing are tracked separately in the
// APL implementation memory.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// One entry from the root `plugins:` block. The minimal shape apl-core
/// needs to make routing + dispatch decisions; richer CPEX fields
/// (`source`, `priority`, `mode`, transport blocks, `description`,
/// `version`) are captured opaquely under `extra` so the round-trip
/// preserves them without us modeling every variant for v0.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginDeclaration {
    /// Plugin name — referenced from routes by `plugin(name)` and used
    /// as the key in [`PluginRegistry`].
    pub name: String,

    /// Implementation kind. Spec defines a closed set (`builtin`,
    /// `native`, `wasm`, FQN, `external`, `isolated_venv`, PDP kinds)
    /// but we parse as a free string so configs using future kinds
    /// the runtime understands aren't rejected at the apl-core layer.
    pub kind: String,

    /// CPEX hook names this plugin implements. Invokers pick which
    /// hook to dispatch based on this list; v0 uses the first entry,
    /// future versions will choose by invocation context (policy vs
    /// post_policy vs pipe-chain).
    ///
    /// Per spec §"Hook dispatch": NOT overridable per-route.
    #[serde(default)]
    pub hooks: Vec<String>,

    /// Attribute-extension capabilities (`read_subject`, `read_labels`,
    /// `append_labels`, `read_headers`, …). The runtime uses these for
    /// extension filtering before dispatch. v0: parsed but not yet
    /// enforced (capability gating is a separately tracked item).
    #[serde(default)]
    pub capabilities: Vec<String>,

    /// Opaque per-plugin config. Passed to the plugin verbatim by the
    /// CPEX runtime; apl-core doesn't interpret it.
    #[serde(default)]
    pub config: Option<serde_yaml::Value>,

    /// `fail | ignore | disable`. Defaults to `fail` per spec when None.
    #[serde(default)]
    pub on_error: Option<String>,

    /// Catch-all for `source`, `priority`, `mode`, transport blocks,
    /// `description`, `version`, etc. Preserved so a future loader can
    /// read them without re-parsing the YAML.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_yaml::Value>,
}

/// Per-route override block — only the spec-overridable keys. Bare
/// key-value pairs are NOT merged into `config` implicitly (spec line
/// 399): "The override object always uses the same keys as a plugin
/// declaration (`config:`, `capabilities:`, `on_error:`); bare
/// key-value pairs are not merged into `config` implicitly."
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginOverride {
    #[serde(default)]
    pub config: Option<serde_yaml::Value>,

    #[serde(default)]
    pub capabilities: Option<Vec<String>>,

    #[serde(default)]
    pub on_error: Option<String>,
}

/// Registry of plugin declarations, keyed by name. Built by the parser
/// from the root `plugins:` block. Type alias — no methods — so callers
/// can wrap it in `Arc<_>` or borrow it directly without ceremony.
pub type PluginRegistry = HashMap<String, PluginDeclaration>;

/// Plugin shape after layering route-level overrides on top of the
/// global declaration. This is what invokers should consume — calling
/// `EffectivePlugin::resolve` (rather than reading the global directly)
/// ensures future override enforcement lands without re-walking the
/// dispatch sites.
#[derive(Debug, Clone)]
pub struct EffectivePlugin<'a> {
    pub name: &'a str,
    pub kind: &'a str,
    /// NOT overridable per spec — always from the global declaration.
    pub hooks: &'a [String],
    /// Capabilities: route override wins if present, else global.
    /// Borrowed when no override applies; owned (cloned) when override
    /// present. Use [`capabilities`] to read regardless.
    pub capabilities: CapsView<'a>,
    /// Config: route override wins if present, else global. Borrowed
    /// directly; callers that need to own it call `.cloned()`.
    pub config: Option<&'a serde_yaml::Value>,
    /// on_error: route override wins if present, else global.
    pub on_error: Option<&'a str>,
}

/// Internal helper that holds either a borrowed slice from the global
/// declaration or an owned override vec; callers see a slice either way.
#[derive(Debug, Clone)]
pub enum CapsView<'a> {
    /// Cheap path — no override; point at the global's slice.
    Global(&'a [String]),
    /// Override applied — caller-owned copy from the override block.
    Override(&'a [String]),
}

impl<'a> CapsView<'a> {
    pub fn as_slice(&self) -> &'a [String] {
        match self {
            Self::Global(s) | Self::Override(s) => s,
        }
    }
}

impl<'a> EffectivePlugin<'a> {
    /// Merge a global declaration with a per-route override and return
    /// the effective view. Returns `None` if `name` isn't in the
    /// registry — caller decides whether that's an error.
    ///
    /// Spec §"Route-Level Plugin Config Overrides":
    ///   - Override `config` replaces the global `config` entirely.
    ///   - Override `capabilities` replaces global capabilities.
    ///   - Override `on_error` replaces global on_error.
    ///   - Everything else inherits unchanged from the global.
    pub fn resolve(
        name: &str,
        registry: &'a PluginRegistry,
        route_overrides: &'a HashMap<String, PluginOverride>,
    ) -> Option<Self> {
        let global = registry.get(name)?;
        let ovr = route_overrides.get(name);

        let capabilities = match ovr.and_then(|o| o.capabilities.as_deref()) {
            Some(c) => CapsView::Override(c),
            None => CapsView::Global(global.capabilities.as_slice()),
        };
        let config = ovr
            .and_then(|o| o.config.as_ref())
            .or(global.config.as_ref());
        let on_error = ovr
            .and_then(|o| o.on_error.as_deref())
            .or(global.on_error.as_deref());

        Some(Self {
            name: global.name.as_str(),
            kind: global.kind.as_str(),
            hooks: global.hooks.as_slice(),
            capabilities,
            config,
            on_error,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn yaml(s: &str) -> serde_yaml::Value {
        serde_yaml::from_str(s).unwrap()
    }

    fn registry_with(decl: PluginDeclaration) -> PluginRegistry {
        let mut r = PluginRegistry::new();
        r.insert(decl.name.clone(), decl);
        r
    }

    #[test]
    fn resolve_with_no_override_returns_global_values() {
        let registry = registry_with(PluginDeclaration {
            name: "rate_limiter".into(),
            kind: "native".into(),
            hooks: vec!["tool_pre_invoke".into()],
            capabilities: vec!["read_subject".into()],
            config: Some(yaml("max_requests: 100")),
            on_error: Some("fail".into()),
            extra: HashMap::new(),
        });
        let overrides = HashMap::new();

        let eff = EffectivePlugin::resolve("rate_limiter", &registry, &overrides).unwrap();
        assert_eq!(eff.name, "rate_limiter");
        assert_eq!(eff.kind, "native");
        assert_eq!(eff.hooks, &["tool_pre_invoke".to_string()]);
        assert_eq!(eff.capabilities.as_slice(), &["read_subject".to_string()]);
        assert_eq!(eff.on_error, Some("fail"));
        assert!(matches!(eff.capabilities, CapsView::Global(_)));
    }

    #[test]
    fn resolve_with_override_replaces_config_and_capabilities_and_on_error() {
        let registry = registry_with(PluginDeclaration {
            name: "rate_limiter".into(),
            kind: "native".into(),
            hooks: vec!["tool_pre_invoke".into()],
            capabilities: vec!["read_subject".into()],
            config: Some(yaml("max_requests: 100")),
            on_error: Some("fail".into()),
            extra: HashMap::new(),
        });
        let mut overrides = HashMap::new();
        overrides.insert(
            "rate_limiter".to_string(),
            PluginOverride {
                config: Some(yaml("max_requests: 10")),
                capabilities: Some(vec!["read_subject".into(), "read_labels".into()]),
                on_error: Some("ignore".into()),
            },
        );

        let eff = EffectivePlugin::resolve("rate_limiter", &registry, &overrides).unwrap();
        // Hooks NOT overridable — still the global value.
        assert_eq!(eff.hooks, &["tool_pre_invoke".to_string()]);
        // Capabilities/config/on_error — overridden.
        assert_eq!(
            eff.capabilities.as_slice(),
            &["read_subject".to_string(), "read_labels".to_string()]
        );
        assert!(matches!(eff.capabilities, CapsView::Override(_)));
        assert_eq!(eff.on_error, Some("ignore"));
        let cfg = eff.config.expect("config present");
        assert_eq!(cfg["max_requests"], yaml("10"));
    }

    #[test]
    fn resolve_with_partial_override_only_replaces_present_keys() {
        // Per spec line 399: only keys present in the override replace
        // inherited values. An override with just `on_error` inherits
        // config + capabilities from the global.
        let registry = registry_with(PluginDeclaration {
            name: "audit".into(),
            kind: "native".into(),
            hooks: vec!["tool_post_invoke".into()],
            capabilities: vec!["read_labels".into()],
            config: Some(yaml("log_level: info")),
            on_error: Some("ignore".into()),
            extra: HashMap::new(),
        });
        let mut overrides = HashMap::new();
        overrides.insert(
            "audit".to_string(),
            PluginOverride {
                config: None,
                capabilities: None,
                on_error: Some("fail".into()),
            },
        );

        let eff = EffectivePlugin::resolve("audit", &registry, &overrides).unwrap();
        assert_eq!(eff.on_error, Some("fail")); // overridden
        assert_eq!(eff.capabilities.as_slice(), &["read_labels".to_string()]); // inherited
        let cfg = eff.config.expect("config inherited");
        assert_eq!(cfg["log_level"], yaml("info")); // inherited
    }

    #[test]
    fn resolve_returns_none_for_unknown_plugin() {
        let registry = PluginRegistry::new();
        let overrides = HashMap::new();
        assert!(EffectivePlugin::resolve("missing", &registry, &overrides).is_none());
    }
}
