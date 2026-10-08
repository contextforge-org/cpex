// Location: ./tests/parity/harness/src/parity.rs
// SPDX-License-Identifier: Apache-2.0
//
// Diff a fresh capture against the recorded 0.2.3 snapshots. Every leaf that
// differs becomes one `Difference`, keyed by scenario, request id and field
// path. A difference is accepted only when `intended-differences.yaml` lists
// it with both values and a cause; an entry that matches nothing is stale
// and is reported too, so the list cannot drift from what the engine does.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::spec::HookRenames;

/// The allow-list of reviewed differences, relative to the root.
pub const INTENDED_DIFFERENCES_FILE: &str = "intended-differences.yaml";

/// Request id under which differences in the `load` block are reported.
pub const LOAD_REQUEST_ID: &str = "<load>";

/// One leaf that differs between the 0.2.3 snapshot and the 0.3.0 capture.
/// A side where the field does not exist is `null`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Difference {
    pub scenario: String,
    pub request: String,
    pub field: String,
    pub before: Value,
    pub after: Value,
}

impl fmt::Display for Difference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} / {} / {}: {} -> {}",
            self.scenario, self.request, self.field, self.before, self.after
        )
    }
}

/// One reviewed entry of the allow-list.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntendedDifference {
    pub scenario: String,
    pub request: String,
    pub field: String,
    /// The 0.2.3 value.
    pub before: Value,
    /// The 0.3.0 value.
    pub after: Value,
    /// Why the value changed.
    pub cause: String,
}

impl IntendedDifference {
    fn matches(&self, d: &Difference) -> bool {
        self.scenario == d.scenario
            && self.request == d.request
            && self.field == d.field
            && self.before == d.before
            && self.after == d.after
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AllowList {
    #[serde(default)]
    differences: Vec<IntendedDifference>,
}

pub fn load_intended(root: &Path) -> Result<Vec<IntendedDifference>, String> {
    let path = root.join(INTENDED_DIFFERENCES_FILE);
    let raw = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let list: AllowList =
        serde_yaml::from_str(&raw).map_err(|e| format!("{}: {e}", path.display()))?;
    if let Some(e) = list.differences.iter().find(|e| e.cause.trim().is_empty()) {
        return Err(format!(
            "{}: entry {} / {} / {} has no cause",
            path.display(),
            e.scenario,
            e.request,
            e.field
        ));
    }
    Ok(list.differences)
}

/// Every difference between a 0.2.3 snapshot and a 0.3.0 capture of the same
/// scenario. Hook names recorded in the 0.2.3 stages are mapped through
/// `renames` first, so a renamed hook alone is not a difference. The
/// top-level `config` path is not compared: it names a different file by
/// design.
pub fn diff_scenario(
    scenario: &str,
    baseline: &Value,
    current: &Value,
    renames: &HookRenames,
) -> Vec<Difference> {
    let mut baseline = baseline.clone();
    rename_stage_hooks(&mut baseline, renames);

    let mut out = Vec::new();
    let mut push = |request: &str, field: String, before: &Value, after: &Value| {
        out.push(Difference {
            scenario: scenario.to_string(),
            request: request.to_string(),
            field,
            before: before.clone(),
            after: after.clone(),
        });
    };

    for key in ["scenario", "description"] {
        diff_value(&baseline[key], &current[key], key, &mut |f, b, a| {
            push("<scenario>", f, b, a);
        });
    }
    diff_value(&baseline["load"], &current["load"], "", &mut |f, b, a| {
        push(LOAD_REQUEST_ID, f, b, a);
    });

    let by_id = |v: &Value| -> BTreeMap<String, Value> {
        v["requests"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|r| r["id"].as_str().map(|id| (id.to_string(), r.clone())))
            .collect()
    };
    let before = by_id(&baseline);
    let after = by_id(current);
    let order: Vec<String> = baseline["requests"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(current["requests"].as_array().into_iter().flatten())
        .filter_map(|r| r["id"].as_str().map(str::to_string))
        .fold(Vec::new(), |mut acc, id| {
            if !acc.contains(&id) {
                acc.push(id);
            }
            acc
        });
    for id in order {
        let b = before.get(&id).unwrap_or(&Value::Null);
        let a = after.get(&id).unwrap_or(&Value::Null);
        diff_value(b, a, "", &mut |f, bv, av| push(&id, f, bv, av));
    }
    out
}

fn rename_stage_hooks(snapshot: &mut Value, renames: &HookRenames) {
    let Some(requests) = snapshot["requests"].as_array_mut() else {
        return;
    };
    for req in requests {
        let Some(stages) = req["stages"].as_array_mut() else {
            continue;
        };
        for stage in stages {
            if let Some(hook) = stage["hook"].as_str() {
                let mapped = renames.map(hook).to_string();
                stage["hook"] = Value::String(mapped);
            }
        }
    }
}

/// Walk both values and report each differing leaf. Objects are compared
/// key by key (a missing key reads as `null`), arrays of equal length
/// element by element; arrays of different length and scalars are compared
/// whole.
fn diff_value(
    before: &Value,
    after: &Value,
    path: &str,
    report: &mut dyn FnMut(String, &Value, &Value),
) {
    match (before, after) {
        (Value::Object(b), Value::Object(a)) => {
            let mut keys: Vec<&String> = b.keys().chain(a.keys()).collect();
            keys.sort();
            keys.dedup();
            for k in keys {
                let bv = b.get(k).unwrap_or(&Value::Null);
                let av = a.get(k).unwrap_or(&Value::Null);
                diff_value(bv, av, &join(path, k), report);
            }
        },
        (Value::Array(b), Value::Array(a)) if b.len() == a.len() => {
            for (i, (bv, av)) in b.iter().zip(a).enumerate() {
                diff_value(bv, av, &format!("{path}[{i}]"), report);
            }
        },
        (b, a) if b == a => {},
        (b, a) => report(path.to_string(), b, a),
    }
}

fn join(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_string()
    } else {
        format!("{path}.{key}")
    }
}

/// Differences checked against the allow-list.
#[derive(Debug, Default)]
pub struct Report {
    /// Every difference found, in scenario and request order.
    pub differences: Vec<Difference>,
    /// Differences no allow-list entry covers.
    pub unexpected: Vec<Difference>,
    /// Allow-list entries that matched no difference.
    pub stale: Vec<IntendedDifference>,
}

impl Report {
    pub fn is_clean(&self) -> bool {
        self.unexpected.is_empty() && self.stale.is_empty()
    }
}

/// Check `differences` for the scenarios in `checked` against `intended`.
/// Entries for scenarios that were not checked (for example a skipped
/// Valkey scenario) are neither used nor stale.
pub fn check(
    differences: Vec<Difference>,
    intended: &[IntendedDifference],
    checked: &[String],
) -> Report {
    let mut used = vec![false; intended.len()];
    let mut unexpected = Vec::new();
    for d in &differences {
        match intended.iter().position(|e| e.matches(d)) {
            Some(i) => used[i] = true,
            None => unexpected.push(d.clone()),
        }
    }
    let stale = intended
        .iter()
        .zip(used)
        .filter(|(e, used)| !used && checked.contains(&e.scenario))
        .map(|(e, _)| e.clone())
        .collect();
    Report {
        differences,
        unexpected,
        stale,
    }
}

/// Render differences as allow-list entries with an empty cause, for review.
pub fn to_allow_list_yaml(differences: &[Difference]) -> String {
    #[derive(Serialize)]
    struct Entry<'a> {
        scenario: &'a str,
        request: &'a str,
        field: &'a str,
        before: &'a Value,
        after: &'a Value,
        cause: &'a str,
    }
    let entries: Vec<Entry<'_>> = differences
        .iter()
        .map(|d| Entry {
            scenario: &d.scenario,
            request: &d.request,
            field: &d.field,
            before: &d.before,
            after: &d.after,
            cause: "",
        })
        .collect();
    serde_yaml::to_string(&entries).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn snapshot(code: &str, hook: &str) -> Value {
        json!({
            "scenario": "s",
            "description": "d",
            "config": "scenarios/s/config.yaml",
            "load": { "ok": true, "upstream_calls": [] },
            "requests": [
                { "id": "r1", "decision": "deny", "code": code,
                  "stages": [{ "hook": hook, "continue": false }] },
            ],
        })
    }

    fn entry(after: &str) -> IntendedDifference {
        IntendedDifference {
            scenario: "s".into(),
            request: "r1".into(),
            field: "code".into(),
            before: json!("a"),
            after: json!(after),
            cause: "test".into(),
        }
    }

    #[test]
    fn a_different_config_path_alone_is_not_a_difference() {
        let a = snapshot("a", "cmf.tool_pre_invoke");
        let mut b = a.clone();
        b["config"] = json!("scenarios/s/config.ppe.yaml");
        assert!(diff_scenario("s", &a, &b, &HookRenames::default()).is_empty());
    }

    #[test]
    fn a_changed_leaf_is_one_difference_with_its_path() {
        let d = diff_scenario(
            "s",
            &snapshot("a", "h"),
            &snapshot("b", "h"),
            &HookRenames::default(),
        );
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].request, "r1");
        assert_eq!(d[0].field, "code");
        assert_eq!(
            (d[0].before.clone(), d[0].after.clone()),
            (json!("a"), json!("b"))
        );
    }

    #[test]
    fn a_renamed_hook_is_not_a_difference() {
        let mut renames = HookRenames::default();
        renames
            .renames
            .insert("tool_pre_invoke".into(), "cmf.tool_pre_invoke".into());
        let d = diff_scenario(
            "s",
            &snapshot("a", "tool_pre_invoke"),
            &snapshot("a", "cmf.tool_pre_invoke"),
            &renames,
        );
        assert!(d.is_empty(), "{d:?}");
    }

    #[test]
    fn a_missing_request_is_reported() {
        let a = snapshot("a", "h");
        let mut b = a.clone();
        b["requests"] = json!([]);
        let d = diff_scenario("s", &a, &b, &HookRenames::default());
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].field, "");
        assert_eq!(d[0].after, Value::Null);
    }

    #[test]
    fn the_allow_list_must_match_both_values() {
        let d = diff_scenario(
            "s",
            &snapshot("a", "h"),
            &snapshot("b", "h"),
            &HookRenames::default(),
        );
        let checked = vec!["s".to_string()];
        assert!(check(d.clone(), &[entry("b")], &checked).is_clean());

        let wrong = check(d, &[entry("c")], &checked);
        assert_eq!(wrong.unexpected.len(), 1);
        assert_eq!(wrong.stale.len(), 1);
    }

    #[test]
    fn entries_for_unchecked_scenarios_are_not_stale() {
        assert!(check(Vec::new(), &[entry("b")], &[]).is_clean());
        assert_eq!(
            check(Vec::new(), &[entry("b")], &["s".into()]).stale.len(),
            1
        );
    }
}
