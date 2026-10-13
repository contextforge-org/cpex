// Location: ./tests/parity/harness/src/spec.rs
// SPDX-License-Identifier: Apache-2.0
//
// Data model for `scenarios/<name>/requests.yaml`. Engine-neutral: nothing
// here names an engine type, so a retargeted harness reads the same files.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;

/// One scenario: a config, the mock upstreams it talks to, the test tokens
/// its callers present, and the ordered request set.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub description: String,
    /// Config file, relative to the scenario directory.
    #[serde(default = "default_config")]
    pub config: String,
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
