// Location: ./crates/cpex-core/src/execution_record.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Structured control execution records for enforcement observability.
//
// Every plugin/control evaluated by the executor produces one
// `ControlExecutionRecord`. Records are collected inside the executor
// (not by plugins) from trusted framework state — plugins cannot forge
// identity, duration, or effective decision fields.
//
// Records are returned on `PipelineResult.executions` so host
// applications can derive enforcement telemetry without parsing logs,
// exception strings, or plugin-specific metadata.
//
// Security and cardinality bounds are enforced here:
// - String fields are capped at `MAX_STRING_LEN` bytes (truncated with "…").
// - `config_keys` is capped at `MAX_CONFIG_KEYS` entries.
// - Records per invocation are bounded by the caller; the executor
//   produces at most one record per registered plugin in the selected
//   hook's entry list.
// - Configuration *values* are never included — only key names.

use serde::{Deserialize, Serialize};

use crate::plugin::PluginMode;

/// Maximum byte length for any free-form string in a record.
/// Values that exceed this are truncated and suffixed with "…".
pub const MAX_STRING_LEN: usize = 256;

/// Maximum number of config key names per record.
pub const MAX_CONFIG_KEYS: usize = 64;

/// Execution health of a single control invocation.
///
/// Separate from the allow/deny policy decision — a control can
/// complete successfully and still deny the operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ControlExecutionStatus {
    /// Plugin ran to completion (may have allowed or denied).
    Completed,
    /// Plugin was not invoked — disabled at schedule time.
    Skipped,
    /// Plugin returned an error.
    Error,
    /// Plugin exceeded its per-invocation timeout.
    Timeout,
    /// Plugin task was cancelled (e.g. short-circuit in concurrent phase).
    Cancelled,
    /// Plugin is runtime-disabled (`on_error: disable` tripped previously).
    Disabled,
}

/// Trusted execution record for one control/plugin evaluation.
///
/// All identity, mode, status, duration, and effective decision fields
/// are populated by the executor from `PluginRef.trusted_config` —
/// never from plugin-returned metadata. A plugin cannot forge these fields.
///
/// `requested_allow` / `effective_allow` separation:
/// - `requested_allow`: what the plugin result asked for (None if we never
///   got a result — error / timeout / cancelled).
/// - `effective_allow`: result after execution-mode and `on_error` policy.
///   This is the authoritative per-control outcome.
///
/// Cardinality: free-form string fields (`reason`, `error_code`) are
/// bounded to `MAX_STRING_LEN` bytes. Config key lists are bounded to
/// `MAX_CONFIG_KEYS` entries. Config *values* are never stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlExecutionRecord {
    /// Stable UUID assigned by the registry at registration time.
    pub plugin_id: String,

    /// Human-readable plugin name from the trusted config.
    pub plugin_name: String,

    /// Plugin kind string from the trusted config
    /// (e.g. `"builtin"`, `"python://..."`, `"wasm://..."`).
    pub plugin_kind: String,

    /// Hook name this invocation was dispatched for.
    pub hook_name: String,

    /// Execution mode from the trusted config.
    pub mode: PluginMode,

    /// Execution health — separate from the allow/deny decision.
    pub status: ControlExecutionStatus,

    /// What the plugin result requested (`true` = allow, `false` = deny).
    /// `None` when no result was obtained (error / timeout / cancelled).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_allow: Option<bool>,

    /// Effective decision after execution-mode semantics and `on_error` policy.
    /// This is the authoritative per-control allow/deny outcome.
    pub effective_allow: bool,

    /// Whether the control condition matched, when determinable.
    /// `None` when the framework cannot distinguish "matched-and-allowed"
    /// from "no condition to match".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched: Option<bool>,

    /// Whether this control changed the payload, extensions, or effective
    /// decision. `false` for read-only phases (Audit, Concurrent, FAF).
    pub applied: bool,

    /// Whether a payload modification was accepted by the framework.
    pub payload_modified: bool,

    /// Whether an extension modification was accepted by the framework.
    pub extensions_modified: bool,

    /// Wall-clock execution duration in nanoseconds (monotonic).
    /// Measures from just before `handler.invoke()` to just after it
    /// returns (or errors / times out). Does not include queue or
    /// semaphore wait time.
    pub duration_ns: u64,

    /// Bounded, sanitized reason string from a violation or error.
    /// Truncated to `MAX_STRING_LEN` bytes. May contain user-provided
    /// text — do not log at high verbosity without review.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// Stable low-cardinality error/violation code.
    /// Preferred over free-form text for dashboards and alerting.
    /// Truncated to `MAX_STRING_LEN` bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,

    /// Config key *names* declared in the plugin's trusted config.
    /// Values are never included. Bounded to `MAX_CONFIG_KEYS` entries.
    pub config_keys: Vec<String>,
}

impl ControlExecutionRecord {
    /// Truncate a string to `MAX_STRING_LEN` bytes, appending "…" if truncated.
    /// Respects UTF-8 char boundaries.
    pub(crate) fn truncate(s: &str) -> String {
        if s.len() <= MAX_STRING_LEN {
            s.to_string()
        } else {
            // Walk back to the last valid char boundary at or before the limit.
            let mut end = MAX_STRING_LEN;
            while !s.is_char_boundary(end) {
                end -= 1;
            }
            format!("{}…", &s[..end])
        }
    }

    /// Truncate an optional string.
    pub(crate) fn truncate_opt(s: Option<&str>) -> Option<String> {
        s.map(Self::truncate)
    }

    /// Collect config key names from a `serde_json::Value` config,
    /// bounded to `MAX_CONFIG_KEYS` entries. Never includes values.
    pub(crate) fn collect_config_keys(config: Option<&serde_json::Value>) -> Vec<String> {
        match config {
            Some(serde_json::Value::Object(map)) => map
                .keys()
                .take(MAX_CONFIG_KEYS)
                .map(|k| Self::truncate(k))
                .collect(),
            _ => Vec::new(),
        }
    }
}

/// Aggregate view over a slice of `ControlExecutionRecord`s.
///
/// Convenience methods for common enforcement telemetry counters.
/// Records remain the authoritative source of truth; these are
/// derived counts only.
pub struct ExecutionSummary<'a> {
    records: &'a [ControlExecutionRecord],
}

impl<'a> ExecutionSummary<'a> {
    /// Create a summary view over a record slice.
    pub fn new(records: &'a [ControlExecutionRecord]) -> Self {
        Self { records }
    }

    /// Number of controls that were actually invoked (status = Completed,
    /// Error, or Timeout — excludes Skipped, Cancelled, Disabled).
    pub fn invocation_count(&self) -> usize {
        self.records
            .iter()
            .filter(|r| {
                matches!(
                    r.status,
                    ControlExecutionStatus::Completed
                        | ControlExecutionStatus::Error
                        | ControlExecutionStatus::Timeout
                )
            })
            .count()
    }

    /// Number of controls where `matched = Some(true)`.
    pub fn matched_count(&self) -> usize {
        self.records
            .iter()
            .filter(|r| r.matched == Some(true))
            .count()
    }

    /// Number of controls where `applied = true`.
    pub fn applied_count(&self) -> usize {
        self.records.iter().filter(|r| r.applied).count()
    }

    /// Total number of records returned (including skipped/cancelled).
    pub fn result_count(&self) -> usize {
        self.records.len()
    }

    /// Sum of `duration_ns` across all records (saturating).
    pub fn total_duration_ns(&self) -> u64 {
        self.records
            .iter()
            .fold(0u64, |acc, r| acc.saturating_add(r.duration_ns))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_short_string_unchanged() {
        let s = "hello";
        assert_eq!(ControlExecutionRecord::truncate(s), "hello");
    }

    #[test]
    fn truncate_long_string_at_byte_boundary() {
        let long = "a".repeat(MAX_STRING_LEN + 10);
        let result = ControlExecutionRecord::truncate(&long);
        assert!(result.len() <= MAX_STRING_LEN + "…".len());
        assert!(result.ends_with('…'));
    }

    #[test]
    fn truncate_unicode_respects_char_boundary() {
        // Each '🎉' is 4 bytes. Build a string where truncation would land
        // mid-codepoint without the boundary check.
        let s: String = "🎉".repeat(100);
        let result = ControlExecutionRecord::truncate(&s);
        // Must be valid UTF-8 (String construction would panic otherwise).
        assert!(!result.is_empty());
    }

    #[test]
    fn collect_config_keys_extracts_keys_only() {
        let cfg = serde_json::json!({ "policy_file": "apl/demo/hr.yaml", "timeout": 30 });
        let keys = ControlExecutionRecord::collect_config_keys(Some(&cfg));
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"policy_file".to_string()));
        assert!(keys.contains(&"timeout".to_string()));
    }

    #[test]
    fn collect_config_keys_bounded() {
        let map: serde_json::Map<String, serde_json::Value> = (0..MAX_CONFIG_KEYS + 10)
            .map(|i| (format!("key_{}", i), serde_json::Value::Null))
            .collect();
        let cfg = serde_json::Value::Object(map);
        let keys = ControlExecutionRecord::collect_config_keys(Some(&cfg));
        assert_eq!(keys.len(), MAX_CONFIG_KEYS);
    }

    #[test]
    fn execution_summary_counts() {
        let make = |status: ControlExecutionStatus,
                    matched: Option<bool>,
                    applied: bool,
                    duration_ns: u64|
         -> ControlExecutionRecord {
            ControlExecutionRecord {
                plugin_id: "id".into(),
                plugin_name: "p".into(),
                plugin_kind: "builtin".into(),
                hook_name: "h".into(),
                mode: PluginMode::Sequential,
                status,
                requested_allow: Some(true),
                effective_allow: true,
                matched,
                applied,
                payload_modified: false,
                extensions_modified: false,
                duration_ns,
                reason: None,
                error_code: None,
                config_keys: vec![],
            }
        };

        let records = vec![
            make(ControlExecutionStatus::Completed, Some(true), true, 100),
            make(ControlExecutionStatus::Error, None, false, 50),
            make(ControlExecutionStatus::Skipped, None, false, 0),
            make(ControlExecutionStatus::Cancelled, None, false, 0),
            make(ControlExecutionStatus::Completed, Some(false), false, 200),
        ];

        let summary = ExecutionSummary::new(&records);
        assert_eq!(summary.result_count(), 5);
        assert_eq!(summary.invocation_count(), 3); // Completed×2 + Error×1
        assert_eq!(summary.matched_count(), 1); // only first has matched=Some(true)
        assert_eq!(summary.applied_count(), 1); // only first has applied=true
        assert_eq!(summary.total_duration_ns(), 350);
    }
}
