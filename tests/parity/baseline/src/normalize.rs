// Location: ./tests/parity/harness/src/normalize.rs
// SPDX-License-Identifier: Apache-2.0
//
// Snapshot hygiene: drop run-dependent values, scrub credentials, and emit
// JSON with sorted object keys so two runs are byte-identical.

use std::collections::BTreeSet;

use serde_json::{Map, Value};

/// Object keys whose values depend on the wall clock or a random source.
const VOLATILE_KEYS: &[&str] = &[
    "expires_at",
    "timestamp",
    "resolved_at",
    "attested_at",
    "age_seconds",
];

pub const SCRUBBED_TIME: &str = "<time>";
pub const SCRUBBED_TOKEN: &str = "<token>";
pub const SCRUBBED_URL: &str = "{{MOCK_URL}}";

/// Values to scrub wherever they appear: minted tokens, mock-issued tokens,
/// and the per-run mock server URL.
#[derive(Default)]
pub struct Scrubber {
    secrets: BTreeSet<String>,
    mock_url: Option<String>,
}

impl Scrubber {
    pub fn add_secret(&mut self, s: impl Into<String>) {
        let s = s.into();
        if !s.is_empty() {
            self.secrets.insert(s);
        }
    }

    pub fn set_mock_url(&mut self, url: &str) {
        self.mock_url = Some(url.to_string());
    }

    /// Collect every `access_token` / `id_token` / `refresh_token` string in
    /// a mock response body so it can be scrubbed from outcomes.
    pub fn harvest_tokens(&mut self, v: &Value) {
        match v {
            Value::Object(m) => {
                for (k, v) in m {
                    if k.ends_with("_token") {
                        if let Value::String(s) = v {
                            self.add_secret(s.clone());
                        }
                    }
                    self.harvest_tokens(v);
                }
            },
            Value::Array(a) => a.iter().for_each(|v| self.harvest_tokens(v)),
            _ => {},
        }
    }

    pub fn apply(&self, v: Value) -> Value {
        match v {
            Value::Object(m) => {
                let mut out = Map::new();
                for (k, v) in m {
                    let v = if VOLATILE_KEYS.contains(&k.as_str()) && !v.is_null() {
                        Value::String(SCRUBBED_TIME.to_string())
                    } else {
                        self.apply(v)
                    };
                    out.insert(k, v);
                }
                Value::Object(out)
            },
            Value::Array(a) => Value::Array(a.into_iter().map(|v| self.apply(v)).collect()),
            Value::String(s) => Value::String(self.scrub_str(s)),
            other => other,
        }
    }

    fn scrub_str(&self, mut s: String) -> String {
        for secret in self.secrets.iter().rev() {
            if s.contains(secret.as_str()) {
                s = s.replace(secret.as_str(), SCRUBBED_TOKEN);
            }
        }
        if looks_like_jwt(&s) {
            return SCRUBBED_TOKEN.to_string();
        }
        if let Some(url) = &self.mock_url {
            if s.contains(url.as_str()) {
                s = s.replace(url.as_str(), SCRUBBED_URL);
            }
        }
        s
    }
}

/// Three dot-separated base64url segments with a JSON header.
fn looks_like_jwt(s: &str) -> bool {
    let s = s.strip_prefix("Bearer ").unwrap_or(s);
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 3
        && parts[0].starts_with("eyJ")
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// Rebuild every object with keys inserted in sorted order. Works whether or
/// not serde_json's `preserve_order` feature is on in the build.
pub fn canonical(v: Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut entries: Vec<(String, Value)> = m.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            let mut out = Map::new();
            for (k, v) in entries {
                out.insert(k, canonical(v));
            }
            Value::Object(out)
        },
        Value::Array(a) => Value::Array(a.into_iter().map(canonical).collect()),
        other => other,
    }
}

/// Pretty JSON with sorted keys and a trailing newline.
pub fn to_snapshot_string(v: Value) -> String {
    let mut s = serde_json::to_string_pretty(&canonical(v)).expect("JSON value serializes");
    s.push('\n');
    s
}

/// Sorted, de-duplicated string list (for set-valued fields).
pub fn sorted<I, S>(items: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let set: BTreeSet<String> = items.into_iter().map(Into::into).collect();
    set.into_iter().collect()
}
