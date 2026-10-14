// Location: ./tests/parity/harness/src/spec.rs
// SPDX-License-Identifier: Apache-2.0
//
// Data model for `scenarios/<name>/requests.yaml`. Engine-neutral: nothing
// here names an engine type, so a retargeted harness reads the same files.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::Value;

/// One scenario: a config, the mock upstreams it talks to, the test tokens
/// its callers present, and the ordered request set.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub description: String,
    /// Config file in 0.2.3 form, relative to the scenario directory. Only
    /// the 0.2.3 capture (at the snapshot commit) reads it.
    #[serde(default = "default_config")]
    pub config: String,
    /// The same config migrated to the 0.3.0 form, which this harness loads.
    #[serde(default = "default_ppe_config")]
    pub ppe_config: String,
    /// External services the scenario needs. Only `valkey` is recognized.
    #[serde(default)]
    pub requires: Vec<String>,
    /// Host-registered plugin factory sets (beyond the builtins).
    #[serde(default)]
    pub host_plugins: Vec<String>,
    /// Hook names a `mediate` request dispatches, so a rename table can map
    /// them without touching each request.
    #[serde(default)]
    pub hooks: MediateHooks,
    /// Routes served by the mock HTTP upstream (`{{MOCK_URL}}`).
    #[serde(default)]
    pub mocks: Vec<MockRoute>,
    /// Named test tokens, minted at run time with the test-only keys.
    #[serde(default)]
    pub tokens: BTreeMap<String, TokenSpec>,
    pub requests: Vec<Request>,
}

fn default_config() -> String {
    "config.yaml".to_string()
}

fn default_ppe_config() -> String {
    "config.ppe.yaml".to_string()
}

impl Scenario {
    /// Hook names the fixture's host can dispatch, before any renaming.
    pub fn hook_names(&self) -> BTreeSet<&str> {
        let mut names = BTreeSet::new();
        for request in &self.requests {
            match request {
                Request::Mediate(_) => {
                    names.extend([
                        self.hooks.identity.as_str(),
                        self.hooks.pre.as_str(),
                        self.hooks.post.as_str(),
                    ]);
                },
                Request::Invoke(r) => {
                    names.insert(r.hook.as_str());
                },
            }
        }
        names
    }

    /// Map every hook name a request dispatches through `renames`.
    pub fn apply_hook_renames(&mut self, renames: &HookRenames) {
        for name in [
            &mut self.hooks.identity,
            &mut self.hooks.pre,
            &mut self.hooks.post,
        ] {
            *name = renames.map(name).to_string();
        }
        for req in &mut self.requests {
            if let Request::Invoke(r) = req {
                r.hook = renames.map(&r.hook).to_string();
            }
        }
    }
}

/// The reviewed legacy-to-current hook rename table (`hook-renames.yaml`).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookRenames {
    /// Legacy name to current name.
    #[serde(default, deserialize_with = "unique_renames")]
    pub renames: BTreeMap<String, String>,
    /// Names that are the same in both releases, for the record.
    #[serde(default)]
    pub unchanged: Vec<String>,
    /// PPE hook names deliberately outside the fixture set.
    #[serde(default)]
    pub unused: Vec<String>,
}

fn unique_renames<'de, D>(deserializer: D) -> Result<BTreeMap<String, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct UniqueRenames;
    impl<'de> serde::de::Visitor<'de> for UniqueRenames {
        type Value = BTreeMap<String, String>;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a hook rename map with unique source names")
        }

        fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
        where
            M: serde::de::MapAccess<'de>,
        {
            let mut rows = BTreeMap::new();
            while let Some((source, target)) = map.next_entry::<String, String>()? {
                if rows.insert(source.clone(), target).is_some() {
                    return Err(serde::de::Error::custom(format!(
                        "duplicate hook rename: {source}"
                    )));
                }
            }
            Ok(rows)
        }
    }
    deserializer.deserialize_map(UniqueRenames)
}

impl HookRenames {
    pub fn map<'a>(&'a self, hook: &'a str) -> &'a str {
        self.renames.get(hook).map_or(hook, String::as_str)
    }

    /// Check source totality and target coverage against PPE's authority.
    pub fn validate<'a>(&self, captured: impl IntoIterator<Item = &'a str>) -> Result<(), String> {
        let ppe: BTreeSet<String> = praxis_policy_core::hooks::types::builtin_hook_types()
            .into_iter()
            .map(|hook| hook.as_str().to_string())
            .collect();
        let mut sources: BTreeSet<&str> = self.renames.keys().map(String::as_str).collect();
        for hook in &self.unchanged {
            if !sources.insert(hook) {
                return Err(format!("hook has more than one rename row: {hook}"));
            }
        }
        for hook in captured {
            if !sources.contains(hook) {
                return Err(format!("captured hook has no rename row: {hook}"));
            }
        }
        for (source, target) in cpex::host::REMOVED_HOOKS {
            if self.renames.get(*source).map(String::as_str) != Some(*target) {
                return Err(format!("expected hook rename {source} -> {target}"));
            }
        }
        for (source, target) in &self.renames {
            if cpex::host::removed_hook_replacement(source) != Some(target.as_str()) {
                return Err(format!("unexpected hook rename {source} -> {target}"));
            }
        }
        let targets: BTreeSet<&str> = self
            .renames
            .values()
            .chain(&self.unchanged)
            .map(String::as_str)
            .collect();
        let mut covered = targets.clone();
        for hook in &self.unused {
            if !covered.insert(hook) {
                return Err(format!(
                    "PPE hook is both covered and unused, or repeated: {hook}"
                ));
            }
        }
        for hook in &covered {
            if !ppe.contains(*hook) {
                return Err(format!(
                    "rename target or unused hook is not dispatched by PPE: {hook}"
                ));
            }
        }
        for hook in &ppe {
            if !covered.contains(hook.as_str()) {
                return Err(format!("PPE hook has no target or unused row: {hook}"));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediateHooks {
    #[serde(default = "default_identity_hook")]
    pub identity: String,
    #[serde(default = "default_pre_hook")]
    pub pre: String,
    #[serde(default = "default_post_hook")]
    pub post: String,
}

impl Default for MediateHooks {
    fn default() -> Self {
        Self {
            identity: default_identity_hook(),
            pre: default_pre_hook(),
            post: default_post_hook(),
        }
    }
}

fn default_identity_hook() -> String {
    "identity.resolve".to_string()
}
fn default_pre_hook() -> String {
    "cmf.tool_pre_invoke".to_string()
}
fn default_post_hook() -> String {
    "cmf.tool_post_invoke".to_string()
}

/// A canned upstream response. The first route whose method, path and
/// `form` fields all match, and that has hits left, wins.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MockRoute {
    pub method: String,
    pub path: String,
    /// Form fields that must be present with these exact values.
    #[serde(default)]
    pub form: BTreeMap<String, String>,
    /// Stop matching after this many hits, so a later route for the same
    /// request can answer differently (for example, pending then approved).
    #[serde(default)]
    pub max_hits: Option<u32>,
    #[serde(default = "default_status")]
    pub status: u16,
    /// JSON response body.
    #[serde(default)]
    pub json: Option<Value>,
    /// Harness-generated body. `jwks` serves the public test keys.
    #[serde(default)]
    pub builtin: Option<String>,
}

fn default_status() -> u16 {
    200
}

/// A JWT minted at run time. `claims` are written verbatim; `key` names a
/// test-only signing key (`primary` is published in the mock JWKS, `rogue`
/// is not). `kid` defaults to the key's own id.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenSpec {
    #[serde(default = "default_key")]
    pub key: String,
    #[serde(default)]
    pub kid: Option<String>,
    pub claims: Value,
}

fn default_key() -> String {
    "primary".to_string()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Request {
    /// The host loop: identity hook (when the caller carries a credential),
    /// pre hook, fake backend, post hook.
    Mediate(MediateRequest),
    /// A single hook invocation with an explicit payload and extensions.
    Invoke(InvokeRequest),
}

impl Request {
    pub fn id(&self) -> &str {
        match self {
            Request::Mediate(r) => &r.id,
            Request::Invoke(r) => &r.id,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediateRequest {
    pub id: String,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub caller: Caller,
    pub tool: String,
    #[serde(default)]
    pub args: Value,
    /// What the fake backend returns when the pre phase allows.
    #[serde(default)]
    pub backend: Value,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Caller {
    /// Name of a token in `tokens`, presented as the bearer credential.
    #[serde(default)]
    pub token: Option<String>,
    /// A literal credential string, for malformed-token cases.
    #[serde(default)]
    pub raw_token: Option<String>,
    /// Extra credentials by header name (value is a token name).
    #[serde(default)]
    pub credentials: BTreeMap<String, String>,
    #[serde(default)]
    pub session: Option<String>,
    /// Resume the elicitation a prior request (by id) left pending.
    #[serde(default)]
    pub resume: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvokeRequest {
    pub id: String,
    #[serde(default)]
    pub note: Option<String>,
    pub hook: String,
    /// CMF `MessagePayload` JSON (`{ message: { role, content: [...] } }`).
    pub payload: Value,
    #[serde(default)]
    pub extensions: ExtensionsSpec,
}

/// The extension slots a request can seed. A deliberately small subset.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionsSpec {
    #[serde(default)]
    pub meta: Option<MetaSpec>,
    #[serde(default)]
    pub security: Option<SecuritySpec>,
    #[serde(default)]
    pub http: Option<HttpSpec>,
    #[serde(default)]
    pub agent: Option<AgentSpec>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetaSpec {
    #[serde(default)]
    pub entity_type: Option<String>,
    #[serde(default)]
    pub entity_name: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecuritySpec {
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub subject: Option<SubjectSpec>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectSpec {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub permissions: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpSpec {
    #[serde(default)]
    pub request_headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSpec {
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
}
