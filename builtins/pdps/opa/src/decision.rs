// Location: ./builtins/pdps/opa/src/decision.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// Query-result → decision mapping.
//
// A Rego query resolves to a `regorus::Value`. This module turns that value
// into an APL `PdpDecision` per the decision contract:
//
//   - Bool(true)                        → Allow
//   - Bool(false)                       → Deny (query evaluated to false)
//   - Object                            → read the decision field (default
//                                         `allow`) as a bool; true → Allow,
//                                         false → Deny enriched with the
//                                         object's reason/message, violations,
//                                         and rule id
//   - Set / Array (deny-set idiom)      → empty → Allow; non-empty → Deny with
//                                         the elements as violations
//   - Undefined                         → clean Deny (idiomatic "not granted"),
//                                         independent of on_error
//   - anything else, or an object whose → Degenerate: the caller routes this
//     decision field is missing/non-bool  through `on_error`
//
// A Deny carries a human-readable `reason`, a `rule_source` (a policy-supplied
// id when present, else `"opa"`), and diagnostics detailing the cause so an
// auditor can see why without re-running the policy. Diagnostics are bounded in
// both element count and line length, since their content is policy-authored
// and can be derived from arbitrarily large `data`. Truncation is always marked,
// so a bounded diagnostic never reads as a complete one.

use regorus::Value;

use apl_core::evaluator::Decision;
use apl_core::step::PdpDecision;

/// The fallback attribution when a policy does not name a rule id.
const DEFAULT_RULE_SOURCE: &str = "opa";

/// Bounds on the diagnostics one deny may carry. A decision object and a deny
/// set are policy-authored and can derive their elements from a large `data`
/// table, so both the number of lines and the length of each line are capped
/// before an audit sink sees them. Worst case for a single deny is roughly
/// 35 KiB: two capped element lists plus the whole-object line.
const MAX_DIAGNOSTIC_ELEMENTS: usize = 16;
const MAX_DIAGNOSTIC_LEN: usize = 1024;

/// Outcome of mapping a query result. A `Decision` is terminal (allow/deny);
/// `Degenerate` means the value carries no decision and the caller applies
/// `on_error`.
pub(crate) enum Mapped {
    Decision(PdpDecision),
    Degenerate(String),
}

/// Map a successful query result into a decision (or a degenerate marker).
pub(crate) fn map_query_result(value: &Value, decision_field: &str) -> Mapped {
    match value {
        Value::Bool(true) => Mapped::Decision(allow()),
        Value::Bool(false) => Mapped::Decision(deny(
            "OPA query evaluated to false".to_string(),
            DEFAULT_RULE_SOURCE.to_string(),
            Vec::new(),
        )),
        Value::Object(_) => map_object(value, decision_field),
        Value::Set(items) => map_collection(items.iter()),
        Value::Array(items) => map_collection(items.iter()),
        // Undefined is Rego's idiomatic "no rule granted access" — a clean
        // deny, never routed through on_error (so on_error: allow cannot flip
        // an ordinary non-match to allow).
        Value::Undefined => Mapped::Decision(deny(
            "OPA query undefined — request not granted".to_string(),
            DEFAULT_RULE_SOURCE.to_string(),
            Vec::new(),
        )),
        other => Mapped::Degenerate(format!(
            "OPA query returned a value that carries no decision: {}",
            render(other)
        )),
    }
}

/// Object result: the decision boolean comes from `decision_field`.
fn map_object(value: &Value, decision_field: &str) -> Mapped {
    let obj = match value.as_object() {
        Ok(o) => o,
        // Unreachable given the caller's `Value::Object` match; defensive.
        Err(_) => return Mapped::Degenerate("OPA query object was not an object".to_string()),
    };

    let decision = obj
        .get(&Value::from(decision_field))
        .and_then(|v| v.as_bool().ok().copied());

    match decision {
        Some(true) => Mapped::Decision(allow()),
        Some(false) => {
            let reason = get_str(obj, "reason")
                .or_else(|| get_str(obj, "message"))
                .unwrap_or_else(|| "OPA policy denied the request".to_string());
            let rule_source = get_str(obj, "rule_source")
                .or_else(|| get_str(obj, "id"))
                .unwrap_or_else(|| DEFAULT_RULE_SOURCE.to_string());

            let mut diagnostics = Vec::new();
            // Recognized violation lists become individual diagnostics.
            for key in ["violations", "errors"] {
                if let Some(list) = obj.get(&Value::from(key)).and_then(|v| v.as_array().ok()) {
                    diagnostics.extend(bounded_elements(list.iter()));
                }
            }
            // Serialize the whole object so nothing the author returned is lost
            // to the audit trail, even fields we did not specifically read.
            diagnostics.push(bounded(format!("opa: {}", render(value))));

            Mapped::Decision(deny(reason, rule_source, diagnostics))
        },
        None => Mapped::Degenerate(format!(
            "OPA decision object has no boolean `{decision_field}` field: {}",
            render(value)
        )),
    }
}

/// Set/array (deny-set / violation-set idiom): empty → allow, non-empty → deny
/// with the elements as violations.
fn map_collection<'a>(items: impl ExactSizeIterator<Item = &'a Value>) -> Mapped {
    // Count before consuming: the reason reports the true violation count even
    // when the diagnostics below are capped, so an auditor is never told "3
    // violations" when the policy produced 300.
    let total = items.len();
    if total == 0 {
        return Mapped::Decision(allow());
    }
    let reason = format!("OPA policy produced {total} violation(s)");
    Mapped::Decision(deny(
        reason,
        DEFAULT_RULE_SOURCE.to_string(),
        bounded_elements(items),
    ))
}

fn allow() -> PdpDecision {
    PdpDecision {
        decision: Decision::Allow,
        diagnostics: Vec::new(),
    }
}

fn deny(reason: String, rule_source: String, diagnostics: Vec<String>) -> PdpDecision {
    PdpDecision {
        decision: Decision::Deny {
            reason: Some(reason),
            rule_source,
        },
        diagnostics,
    }
}

/// Read an object field as a string, if present and string-typed.
fn get_str(obj: &regorus::value::Object, key: &str) -> Option<String> {
    obj.get(&Value::from(key))
        .and_then(|v| v.as_string().ok())
        .map(|s| s.to_string())
}

/// Cap one diagnostic line, cutting on a UTF-8 boundary and noting how much was
/// dropped so an auditor can tell a bounded line from a complete one.
fn bounded(s: String) -> String {
    if s.len() <= MAX_DIAGNOSTIC_LEN {
        return s;
    }
    let cut = s.floor_char_boundary(MAX_DIAGNOSTIC_LEN);
    format!("{}... [{} more bytes omitted]", &s[..cut], s.len() - cut)
}

/// Render at most [`MAX_DIAGNOSTIC_ELEMENTS`] elements, each capped, followed by
/// a count line when the list was longer.
fn bounded_elements<'a>(items: impl ExactSizeIterator<Item = &'a Value>) -> Vec<String> {
    let total = items.len();
    let mut out: Vec<String> = items
        .take(MAX_DIAGNOSTIC_ELEMENTS)
        .map(|item| bounded(render(item)))
        .collect();
    if total > out.len() {
        out.push(format!("[{} more element(s) omitted]", total - out.len()));
    }
    out
}

/// Render a value for a diagnostic line: a bare string as-is, everything else
/// as compact JSON (falling back to a placeholder if it cannot be rendered).
fn render(value: &Value) -> String {
    if let Ok(s) = value.as_string() {
        return s.to_string();
    }
    value
        .to_json_str()
        .unwrap_or_else(|_| "<unrenderable value>".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn val(json: &str) -> Value {
        Value::from_json_str(json).unwrap()
    }

    fn decision_of(m: Mapped) -> Decision {
        match m {
            Mapped::Decision(d) => d.decision,
            Mapped::Degenerate(c) => panic!("expected a decision, got degenerate: {c}"),
        }
    }

    #[test]
    fn bool_true_allows_false_denies() {
        assert_eq!(
            decision_of(map_query_result(&Value::Bool(true), "allow")),
            Decision::Allow
        );
        assert!(matches!(
            decision_of(map_query_result(&Value::Bool(false), "allow")),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn undefined_is_clean_deny() {
        assert!(matches!(
            decision_of(map_query_result(&Value::Undefined, "allow")),
            Decision::Deny { rule_source, .. } if rule_source == "opa"
        ));
    }

    #[test]
    fn object_allow_true_allows() {
        assert_eq!(
            decision_of(map_query_result(&val(r#"{"allow": true}"#), "allow")),
            Decision::Allow
        );
    }

    #[test]
    fn object_deny_carries_reason_and_violations() {
        let m = map_query_result(
            &val(
                r#"{"allow": false, "reason": "subject not in allowlist", "violations": ["no reader role"]}"#,
            ),
            "allow",
        );
        match m {
            Mapped::Decision(d) => {
                match d.decision {
                    Decision::Deny {
                        reason,
                        rule_source,
                    } => {
                        assert_eq!(reason.as_deref(), Some("subject not in allowlist"));
                        assert_eq!(rule_source, "opa");
                    },
                    other => panic!("expected Deny, got {other:?}"),
                }
                assert!(
                    d.diagnostics.iter().any(|x| x == "no reader role"),
                    "violations must appear in diagnostics; got {:?}",
                    d.diagnostics
                );
            },
            Mapped::Degenerate(c) => panic!("degenerate: {c}"),
        }
    }

    #[test]
    fn object_message_field_used_when_no_reason() {
        let m = map_query_result(&val(r#"{"allow": false, "message": "blocked"}"#), "allow");
        match decision_of(m) {
            Decision::Deny { reason, .. } => assert_eq!(reason.as_deref(), Some("blocked")),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn object_policy_id_becomes_rule_source() {
        let m = map_query_result(
            &val(r#"{"allow": false, "rule_source": "owner-override"}"#),
            "allow",
        );
        match decision_of(m) {
            Decision::Deny { rule_source, .. } => assert_eq!(rule_source, "owner-override"),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn custom_decision_field_is_honored() {
        assert_eq!(
            decision_of(map_query_result(&val(r#"{"permit": true}"#), "permit")),
            Decision::Allow
        );
    }

    #[test]
    fn object_without_decision_field_is_degenerate() {
        assert!(matches!(
            map_query_result(&val(r#"{"note": "hi"}"#), "allow"),
            Mapped::Degenerate(_)
        ));
    }

    #[test]
    fn object_non_bool_decision_field_is_degenerate() {
        assert!(matches!(
            map_query_result(&val(r#"{"allow": "yes"}"#), "allow"),
            Mapped::Degenerate(_)
        ));
    }

    #[test]
    fn empty_array_allows_nonempty_denies() {
        assert_eq!(
            decision_of(map_query_result(&val("[]"), "allow")),
            Decision::Allow
        );
        match decision_of(map_query_result(&val(r#"["blocked: reason"]"#), "allow")) {
            Decision::Deny { rule_source, .. } => assert_eq!(rule_source, "opa"),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn nonempty_set_denies_with_violations() {
        use std::collections::BTreeSet;
        let mut set = BTreeSet::new();
        set.insert(Value::from("no reader role"));
        let m = map_query_result(&Value::from(set), "allow");
        match m {
            Mapped::Decision(d) => {
                assert!(matches!(d.decision, Decision::Deny { .. }));
                assert!(d.diagnostics.iter().any(|x| x == "no reader role"));
            },
            Mapped::Degenerate(c) => panic!("degenerate: {c}"),
        }
    }

    #[test]
    fn string_result_is_degenerate() {
        assert!(matches!(
            map_query_result(&Value::from("hello"), "allow"),
            Mapped::Degenerate(_)
        ));
    }

    #[test]
    fn object_errors_key_lands_in_diagnostics() {
        let m = map_query_result(
            &val(r#"{"allow": false, "errors": ["policy failed", "missing role"]}"#),
            "allow",
        );
        match m {
            Mapped::Decision(d) => {
                assert!(d.diagnostics.iter().any(|x| x == "policy failed"));
                assert!(d.diagnostics.iter().any(|x| x == "missing role"));
            },
            Mapped::Degenerate(c) => panic!("degenerate: {c}"),
        }
    }

    #[test]
    fn object_id_field_is_rule_source_fallback() {
        let m = map_query_result(&val(r#"{"allow": false, "id": "rule-42"}"#), "allow");
        match decision_of(m) {
            Decision::Deny { rule_source, .. } => assert_eq!(rule_source, "rule-42"),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    fn diagnostics_of(m: Mapped) -> Vec<String> {
        match m {
            Mapped::Decision(d) => d.diagnostics,
            Mapped::Degenerate(c) => panic!("expected a decision, got degenerate: {c}"),
        }
    }

    #[test]
    fn oversized_violation_list_is_capped() {
        let violations: Vec<String> = (0..100).map(|i| format!("\"v{i}\"")).collect();
        let m = map_query_result(
            &val(&format!(
                r#"{{"allow": false, "violations": [{}]}}"#,
                violations.join(",")
            )),
            "allow",
        );
        let diagnostics = diagnostics_of(m);
        // Capped elements, one omitted-count line, one whole-object line.
        assert_eq!(diagnostics.len(), MAX_DIAGNOSTIC_ELEMENTS + 2);
        assert!(
            diagnostics
                .iter()
                .any(|d| d == "[84 more element(s) omitted]"),
            "truncation must be marked; got {diagnostics:?}"
        );
    }

    #[test]
    fn oversized_violation_element_is_truncated() {
        let long = "x".repeat(10_000);
        let m = map_query_result(
            &val(&format!(r#"{{"allow": false, "violations": ["{long}"]}}"#)),
            "allow",
        );
        let diagnostics = diagnostics_of(m);
        for line in &diagnostics {
            assert!(
                line.len() < MAX_DIAGNOSTIC_LEN + 64,
                "line of {} bytes exceeds the bound",
                line.len()
            );
        }
        assert!(
            diagnostics.iter().all(|d| d.contains("more bytes omitted")),
            "both the element and the whole-object line must be marked truncated; got \
             {diagnostics:?}"
        );
    }

    /// The deny reason must report the real violation count even when the
    /// diagnostics are capped, so an auditor is never told "16 violations" when
    /// the policy produced 100.
    #[test]
    fn capped_deny_set_reason_reports_true_count() {
        let elements: Vec<String> = (0..100).map(|i| format!("\"v{i}\"")).collect();
        let m = map_query_result(&val(&format!("[{}]", elements.join(","))), "allow");
        match m {
            Mapped::Decision(d) => {
                match d.decision {
                    Decision::Deny { reason, .. } => {
                        assert_eq!(
                            reason.as_deref(),
                            Some("OPA policy produced 100 violation(s)")
                        );
                    },
                    other => panic!("expected Deny, got {other:?}"),
                }
                assert_eq!(d.diagnostics.len(), MAX_DIAGNOSTIC_ELEMENTS + 1);
            },
            Mapped::Degenerate(c) => panic!("degenerate: {c}"),
        }
    }

    #[test]
    fn truncation_cuts_on_utf8_boundary() {
        // Three-byte characters do not divide MAX_DIAGNOSTIC_LEN evenly, so the
        // cut lands mid-character unless the boundary is respected.
        let long = "\u{4e16}".repeat(1_000);
        let out = bounded(long);
        assert!(out.contains("more bytes omitted"));
        assert!(out.len() <= MAX_DIAGNOSTIC_LEN + 64);
    }

    /// The decision field is authoritative: `allow: true` allows even if the
    /// object also carries a populated `violations` list. Pins the documented
    /// precedence so a future change to the object path is a conscious choice.
    #[test]
    fn allow_true_wins_over_populated_violations() {
        assert_eq!(
            decision_of(map_query_result(
                &val(r#"{"allow": true, "violations": ["ignored"]}"#),
                "allow"
            )),
            Decision::Allow
        );
    }
}
