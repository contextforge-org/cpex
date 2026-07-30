// Location: ./crates/cpex-openshell-middleware/src/config.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Xiaokui Shu
//
// Per-binding service configuration: the closed REST `(host, method, path) ->
// tool` map OpenShell delivers in the middleware config `Struct`. MCP requests
// carry their own tool name (the `tools/call` name), so they need no map; this
// exists only so a plain REST egress can be projected onto a named tool route
// and its args, keeping REST and MCP outcomes identical.
//
// The map is closed (exact host+method+path, no wildcards) on purpose: a tool
// name must not drift from the bundle's `tool:` routes, and an unmapped request
// fails closed rather than forwarding unevaluated bytes.

use std::collections::HashMap;

use serde::Deserialize;

/// One REST route mapped to a CMF tool, with the arg projection that lets
/// args-reading policies (`args.visibility`, …) see the same values the MCP leg
/// would. Field lists name request fields to lift into CMF `args`.
#[derive(Debug, Clone, Deserialize)]
pub struct RestRoute {
    pub host: String,
    pub method: String,
    pub path: String,
    /// Target CMF tool entity name (must match a bundle `tool:` route).
    pub tool: String,
    /// Query-parameter names projected into `args` under the same key.
    #[serde(default)]
    pub query_args: Vec<String>,
    /// JSON body field names (top level) projected into `args` under the same key.
    #[serde(default)]
    pub body_args: Vec<String>,
}

/// The parsed REST tool map. Empty is valid — a deployment that only serves MCP
/// needs no REST routes (every REST request then fails closed as unmapped).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RestToolMap {
    #[serde(default)]
    pub routes: Vec<RestRoute>,
}

impl RestToolMap {
    /// Parse the per-binding config `Struct` (as JSON) into a REST tool map.
    /// An absent or empty config yields an empty (MCP-only) map. Unknown shapes
    /// are a hard error so a misconfigured binding is rejected at
    /// `ValidateConfig`, not silently ignored at request time.
    pub fn from_config_json(value: &serde_json::Value) -> Result<Self, String> {
        if value.is_null() {
            return Ok(Self::default());
        }
        serde_json::from_value(value.clone()).map_err(|e| format!("invalid rest tool map: {e}"))
    }

    /// Resolve a REST request to its tool + projected args. Exact match on
    /// host + method (case-insensitive) + path. `None` when unmapped.
    pub fn resolve(
        &self,
        host: &str,
        method: &str,
        path: &str,
        query: &str,
        body: &[u8],
    ) -> Option<(String, HashMap<String, serde_json::Value>)> {
        let route = self.routes.iter().find(|r| {
            r.host.eq_ignore_ascii_case(host)
                && r.method.eq_ignore_ascii_case(method)
                && r.path == path
        })?;

        let mut args: HashMap<String, serde_json::Value> = HashMap::new();

        if !route.query_args.is_empty() {
            let pairs = parse_query(query);
            for key in &route.query_args {
                if let Some(v) = pairs.get(key) {
                    args.insert(key.clone(), serde_json::Value::String(v.clone()));
                }
            }
        }

        if !route.body_args.is_empty() {
            if let Ok(serde_json::Value::Object(obj)) = serde_json::from_slice::<serde_json::Value>(body) {
                for key in &route.body_args {
                    if let Some(v) = obj.get(key) {
                        args.insert(key.clone(), v.clone());
                    }
                }
            }
        }

        Some((route.tool.clone(), args))
    }

    /// Validate that the map is internally consistent (no duplicate route keys).
    /// Returns a human-readable reason on the first problem.
    pub fn validate(&self) -> Result<(), String> {
        let mut seen = std::collections::HashSet::new();
        for r in &self.routes {
            if r.tool.trim().is_empty() {
                return Err(format!("route {} {} {} has an empty tool name", r.host, r.method, r.path));
            }
            let key = (r.host.to_lowercase(), r.method.to_lowercase(), r.path.clone());
            if !seen.insert(key) {
                return Err(format!(
                    "duplicate REST route for {} {} {}",
                    r.host, r.method, r.path
                ));
            }
        }
        Ok(())
    }
}

/// Minimal `application/x-www-form-urlencoded` query parser (no percent-decode
/// beyond `+` → space; the demo query values are plain tokens). Last value wins.
fn parse_query(query: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        out.insert(k.to_string(), v.replace('+', " "));
    }
    out
}
