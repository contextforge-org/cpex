// Location: ./integrations/praxis-cpex/filter/src/config.rs
// SPDX-License-Identifier: Apache-2.0
//
// YAML-deserializable config block for the `cpex` HttpFilter. The
// filter slot in a Praxis filter chain looks like:
//
//     filters:
//       - filter: cpex
//         config_path: cpex.yaml
//         body_access: read_only   # or read_write — see below
//
// `config_path` points at a CPEX-shaped YAML (plugins + routes).
//
// Per-credential header routing is handled by the identity plugins
// themselves — each `identity/jwt` instance declares its own
// `role:` + `header:` in the CPEX YAML.
//
// `body_access` controls whether body mutators (APL `redact()` /
// `assign()` on `args.<field>`) take effect on the upstream call.
// Default `read_only` — APL can inspect bodies and gate, but
// mutations are discarded. Set `read_write` to enable the
// MessagePayload → JSON-RPC round-trip that rewrites the body.

use serde::Deserialize;

/// Raw filter config block deserialized from Praxis YAML.
#[derive(Debug, Clone, Deserialize)]
pub struct CpexFilterConfig {
    /// Path to a CPEX YAML config (plugins + routes). Loaded once at
    /// filter init via `PluginManager::load_config_yaml`.
    pub config_path: String,

    /// **Deprecated** — left for back-compat with deployed YAML.
    /// The filter no longer pre-extracts a single token from this
    /// header; each identity plugin instance declares its own
    /// `header:` field instead. Writing it has no effect.
    #[serde(default = "default_token_header")]
    pub token_header: String,

    /// Body-access tier. `ReadOnly` (default) lets APL inspect the
    /// body for routing / policy decisions but discards mutations.
    /// `ReadWrite` enables the CMF → JSON-RPC re-serialization path
    /// so APL field mutators (e.g. `args.ssn: redact(!perm.view_ssn)`)
    /// rewrite the upstream body. Pay the round-trip cost only when
    /// you actually need it.
    #[serde(default)]
    pub body_access: BodyAccessMode,
}

/// What APL field-pipeline mutators on `args.<field>` are allowed
/// to do to the upstream body.
///
/// Mirrors `praxis_filter::BodyAccess` but is operator-configurable
/// because the choice changes pipeline behavior (and cost).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyAccessMode {
    /// Body is buffered for inspection / routing; mutations are
    /// discarded. APL `require()` predicates over body content
    /// (`args.amount > 1000`) work; `redact()` / `assign()` are
    /// silently dropped at the executor's write boundary.
    #[default]
    ReadOnly,

    /// Body is buffered + APL mutations to `args.*` are re-serialized
    /// back into the JSON-RPC body so the upstream sees them. Costs
    /// one JSON parse + serialize per mutated request.
    ReadWrite,
}

fn default_token_header() -> String {
    "Authorization".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults() {
        let cfg: CpexFilterConfig = serde_yaml::from_str("config_path: cpex.yaml").unwrap();
        assert_eq!(cfg.config_path, "cpex.yaml");
        assert_eq!(cfg.token_header, "Authorization");
        assert_eq!(cfg.body_access, BodyAccessMode::ReadOnly);
    }

    #[test]
    fn read_write_opt_in() {
        let yaml = r#"
config_path: cpex.yaml
body_access: read_write
"#;
        let cfg: CpexFilterConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.body_access, BodyAccessMode::ReadWrite);
    }

    #[test]
    fn legacy_token_header_accepted() {
        let yaml = r#"
config_path: cpex.yaml
token_header: X-User-Token
"#;
        let cfg: CpexFilterConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.token_header, "X-User-Token");
    }
}
