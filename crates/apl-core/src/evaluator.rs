// Location: ./crates/apl-core/src/evaluator.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// APL evaluator — walks the IR against an AttributeBag and returns a Decision.
//
// The evaluator is sync and infallible by design. Missing attributes resolve
// to `false` (DSL spec §2.6); operator type mismatches resolve to `false`.
// The host drives the four phases separately by calling `evaluate_rules` once
// per declared phase — phase orchestration lives in `apl-cpex`.
//
// Semantics anchored in:
//   - DSL spec apl-dsl-spec.md §2 (operators), §3 (actions), §8.1 (require)
//   - apl-design.md §7 (native fast-path, sync inside async outer)

use crate::attributes::{AttributeBag, AttributeValue};
use crate::pipeline::{Pipeline, ScanKind, Stage, TaintEvent, TaintScope, TypeCheck};
use crate::rules::{Action, CompareOp, Condition, Expression, Literal, Rule};
use crate::step::{PdpResolver, PluginInvocation, PluginInvoker, Step};

/// Outcome of evaluating a phase's rule list.
#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    /// No `deny` rule fired. Pipeline proceeds.
    Allow,
    /// A `deny` rule fired. Pipeline halts.
    Deny {
        reason: Option<String>,
        /// `Rule.source` of the rule that produced the deny — for audit logs.
        rule_source: String,
    },
}

/// Evaluate a phase's rules against the bag.
///
/// Spec §3 semantics:
/// - First `deny` halts; subsequent rules don't run.
/// - `allow` rules *do not* short-circuit — evaluation continues.
/// - If no rule denies, the phase resolves to `Decision::Allow`.
pub fn evaluate_rules(rules: &[Rule], bag: &AttributeBag) -> Decision {
    for rule in rules {
        if !eval_expression(&rule.condition, bag) {
            continue;
        }
        match &rule.action {
            Action::Allow => continue,
            Action::Deny { reason } => {
                return Decision::Deny {
                    reason: reason.clone(),
                    rule_source: rule.source.clone(),
                }
            }
        }
    }
    Decision::Allow
}

fn eval_expression(expr: &Expression, bag: &AttributeBag) -> bool {
    match expr {
        Expression::Condition(c) => eval_condition(c, bag),
        Expression::And(parts) => parts.iter().all(|e| eval_expression(e, bag)),
        Expression::Or(parts) => parts.iter().any(|e| eval_expression(e, bag)),
        Expression::Not(inner) => !eval_expression(inner, bag),
        Expression::Always => true,
    }
}

fn eval_condition(cond: &Condition, bag: &AttributeBag) -> bool {
    match cond {
        Condition::IsTrue { key } => bag.get_bool(key).unwrap_or(false),
        Condition::IsFalse { key } => !bag.get_bool(key).unwrap_or(false),
        Condition::Exists { key } => bag.contains(key),
        Condition::Comparison { key, op, value } => eval_comparison(key, *op, value, bag),
        Condition::InSet { value_key, set_key, negate } => {
            let in_set = match (bag.get_string(value_key), bag.get_string_set(set_key)) {
                (Some(s), Some(set)) => set.contains(s),
                _ => false, // missing key or wrong type → not in set
            };
            if *negate { !in_set } else { in_set }
        }
    }
}

fn eval_comparison(key: &str, op: CompareOp, lit: &Literal, bag: &AttributeBag) -> bool {
    let attr = match bag.get(key) {
        Some(v) => v,
        None => return false, // missing → false (spec §2.6)
    };

    match op {
        CompareOp::Contains => match (attr, lit) {
            (AttributeValue::StringSet(_), Literal::String(s)) => bag.set_contains(key, s),
            _ => false,
        },
        CompareOp::Eq => values_eq(attr, lit),
        CompareOp::NotEq => !values_eq(attr, lit),
        CompareOp::Gt | CompareOp::GtEq | CompareOp::Lt | CompareOp::LtEq => {
            numeric_compare(attr, lit, op)
        }
    }
}

fn values_eq(attr: &AttributeValue, lit: &Literal) -> bool {
    match (attr, lit) {
        (AttributeValue::Bool(a), Literal::Bool(b)) => a == b,
        (AttributeValue::Int(a), Literal::Int(b)) => a == b,
        (AttributeValue::Float(a), Literal::Float(b)) => a == b,
        (AttributeValue::String(a), Literal::String(b)) => a == b,
        // Int↔Float promotion for equality (matches AttributeBag::get_float).
        (AttributeValue::Int(a), Literal::Float(b)) => (*a as f64) == *b,
        (AttributeValue::Float(a), Literal::Int(b)) => *a == (*b as f64),
        _ => false,
    }
}

fn numeric_compare(attr: &AttributeValue, lit: &Literal, op: CompareOp) -> bool {
    let (a, b) = match (attr, lit) {
        (AttributeValue::Int(a), Literal::Int(b)) => (*a as f64, *b as f64),
        (AttributeValue::Int(a), Literal::Float(b)) => (*a as f64, *b),
        (AttributeValue::Float(a), Literal::Int(b)) => (*a, *b as f64),
        (AttributeValue::Float(a), Literal::Float(b)) => (*a, *b),
        // Non-numeric operands: order operators don't apply → false (spec §2.3).
        _ => return false,
    };
    match op {
        CompareOp::Gt => a > b,
        CompareOp::GtEq => a >= b,
        CompareOp::Lt => a < b,
        CompareOp::LtEq => a <= b,
        _ => unreachable!("numeric_compare called with non-numeric op"),
    }
}

// =====================================================================
// Async step evaluator (policy: / post_policy: with PDP/plugin/taint)
// =====================================================================

/// Walk a Step list against the bag, dispatching PDP calls via `pdp` and
/// plugin invocations via `plugins`. Returns the phase's overall decision.
///
/// Semantics (DSL §3, §7.5):
/// - `Step::Rule` — same first-deny-wins / allow-continues logic as
///   `evaluate_rules`.
/// - `Step::Pdp` — call resolver; on Allow run `on_allow` reactions and
///   continue; on Deny run `on_deny` reactions and return the deny
///   (reactions can override with their own deny, but cannot turn a deny
///   into an allow).
/// - `Step::Plugin` — invoke; Allow continues, Deny returns.
/// - `Step::Taint` — recognized but not applied here (apl-cpex handles
///   the actual SessionStore writes); the step always continues.
///
/// PDP / plugin errors map to a Deny with the error in the reason, per
/// the design's fail-closed default (DSL §8.9).
pub async fn evaluate_steps(
    steps: &[Step],
    bag: &AttributeBag,
    pdp: &dyn PdpResolver,
    plugins: &dyn PluginInvoker,
) -> StepsEvaluation {
    // Box-pin recursion for async fn (reactions run nested `evaluate_steps`).
    Box::pin(evaluate_steps_inner(steps, bag, pdp, plugins)).await
}

/// Outcome of `evaluate_steps`: the phase's decision plus taints emitted
/// by any plugin steps that ran. Taints are accumulated even when the
/// phase ultimately denies — audit needs to see what the plugins
/// reported before the deny landed. Empty `taints` is the common case
/// (most steps are predicates / PDP calls, not label emitters).
#[derive(Debug, Clone)]
pub struct StepsEvaluation {
    pub decision: Decision,
    pub taints: Vec<crate::pipeline::TaintEvent>,
}

impl StepsEvaluation {
    fn deny(d: Decision, taints: Vec<crate::pipeline::TaintEvent>) -> Self {
        Self { decision: d, taints }
    }
}

async fn evaluate_steps_inner(
    steps: &[Step],
    bag: &AttributeBag,
    pdp: &dyn PdpResolver,
    plugins: &dyn PluginInvoker,
) -> StepsEvaluation {
    let mut taints: Vec<crate::pipeline::TaintEvent> = Vec::new();
    for step in steps {
        match step {
            Step::Rule(rule) => {
                if !eval_expression(&rule.condition, bag) {
                    continue;
                }
                match &rule.action {
                    Action::Allow => continue,
                    Action::Deny { reason } => {
                        return StepsEvaluation::deny(
                            Decision::Deny {
                                reason: reason.clone(),
                                rule_source: rule.source.clone(),
                            },
                            taints,
                        );
                    }
                }
            }

            Step::Pdp { call, on_deny, on_allow } => {
                match pdp.evaluate(call, bag).await {
                    Ok(pdp_result) => match pdp_result.decision {
                        Decision::Allow => {
                            let reaction = Box::pin(evaluate_steps_inner(
                                on_allow, bag, pdp, plugins,
                            )).await;
                            taints.extend(reaction.taints);
                            if let Decision::Deny { .. } = reaction.decision {
                                return StepsEvaluation::deny(reaction.decision, taints);
                            }
                            // Allow + on_allow didn't deny → continue.
                        }
                        deny @ Decision::Deny { .. } => {
                            let reaction = Box::pin(evaluate_steps_inner(
                                on_deny, bag, pdp, plugins,
                            )).await;
                            taints.extend(reaction.taints);
                            // Reactions can override the PDP's deny reason
                            // (e.g., on_deny: [deny "..."]) but cannot turn
                            // deny into allow — if reactions returned Allow,
                            // the PDP's original deny still stands.
                            let final_decision = match reaction.decision {
                                Decision::Deny { .. } => reaction.decision,
                                Decision::Allow => deny,
                            };
                            return StepsEvaluation::deny(final_decision, taints);
                        }
                    },
                    Err(e) => {
                        return StepsEvaluation::deny(
                            Decision::Deny {
                                reason: Some(format!("PDP error: {}", e)),
                                rule_source: format!("pdp:{:?}", call.dialect),
                            },
                            taints,
                        );
                    }
                }
            }

            Step::Plugin { name } => {
                match plugins.invoke(name, bag, PluginInvocation::Step).await {
                    Ok(outcome) => {
                        // Plugins can emit taints regardless of decision —
                        // collect first, then act on the decision.
                        taints.extend(outcome.taints);
                        match outcome.decision {
                            Decision::Allow => continue,
                            deny @ Decision::Deny { .. } => {
                                return StepsEvaluation::deny(deny, taints);
                            }
                        }
                    }
                    Err(e) => {
                        return StepsEvaluation::deny(
                            Decision::Deny {
                                reason: Some(format!("plugin `{}` error: {}", name, e)),
                                rule_source: format!("plugin:{}", name),
                            },
                            taints,
                        );
                    }
                }
            }

            Step::Taint { label, scopes } => {
                // Emit the taint into the phase's accumulator so it flows
                // into `RouteDecision.taints`. Apl-cpex's invoker handles
                // the session-store persistence side at request end —
                // here we only record the event. Scopes come straight from
                // the parser (`taint(label, session, message)` syntax).
                taints.push(crate::pipeline::TaintEvent {
                    label: label.clone(),
                    scopes: scopes.clone(),
                });
                continue;
            }
        }
    }
    StepsEvaluation { decision: Decision::Allow, taints }
}

// =====================================================================
// Pipe-chain evaluator (args: / result: field pipelines)
// =====================================================================

/// Result of running a pipeline against one field's value.
///
/// `Pass`: every stage succeeded; the original value should be kept.
/// `Replace`: a transform produced a new value (also covers conditional
/// `redact` firing).
/// `Omit`: an `omit` stage fired; the field should be dropped from output.
/// `Deny`: a validator failed; pipeline halted; the route should deny.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldOutcome {
    Pass,
    Replace(serde_json::Value),
    Omit,
    Deny { reason: String, stage_index: usize },
}

/// Full result of a pipeline run: value-level outcome plus accumulated
/// taint side effects.
///
/// `taint(...)` stages, plugin invocations, and `scan(...)` stages can all
/// emit taints; the evaluator collects them here and hands them to the host
/// (apl-cpex) for SessionStore writes. Taints accumulate even on `Replace`
/// and `Omit` outcomes; they do not accumulate past a `Deny` (the pipeline
/// halts at the failing stage).
#[derive(Debug, Clone, PartialEq)]
pub struct PipelineEvaluation {
    pub outcome: FieldOutcome,
    pub taints: Vec<TaintEvent>,
}

/// Walk a pipeline against `value` and the bag, applying stages left-to-right.
///
/// Async because pipe-chain `plugin(name)` stages dispatch through
/// `PluginInvoker`, which is async.
///
/// `field_name` is the field this pipeline is attached to (from the wrapping
/// `FieldRule`). It's threaded into `PluginInvocation::Field` when a
/// `Stage::Plugin` fires so the invoker knows which field is in focus.
/// Pass `""` for standalone pipeline runs that aren't part of a field rule.
///
/// `Stage::Validate { name }` is currently a no-op with a TODO — the named
/// validator registry lands in a later step.
pub async fn evaluate_pipeline(
    pipeline: &Pipeline,
    value: &serde_json::Value,
    bag: &AttributeBag,
    plugins: &dyn PluginInvoker,
    field_name: &str,
) -> PipelineEvaluation {
    let mut current = value.clone();
    let mut replaced = false;
    let mut taints: Vec<TaintEvent> = Vec::new();

    for (idx, stage) in pipeline.stages.iter().enumerate() {
        match stage {
            // ----- Validators -----
            Stage::Type(tc) => {
                if !type_check(tc, &current) {
                    return PipelineEvaluation {
                        outcome: FieldOutcome::Deny {
                            reason: format!("expected {:?}, got {}", tc, value_kind(&current)),
                            stage_index: idx,
                        },
                        taints,
                    };
                }
            }
            Stage::Length { min, max } => {
                let Some(s) = current.as_str() else {
                    return PipelineEvaluation {
                        outcome: FieldOutcome::Deny {
                            reason: format!("len(...) requires string value, got {}", value_kind(&current)),
                            stage_index: idx,
                        },
                        taints,
                    };
                };
                let len = s.chars().count();
                if min.map_or(false, |m| len < m) || max.map_or(false, |m| len > m) {
                    return PipelineEvaluation {
                        outcome: FieldOutcome::Deny {
                            reason: format!("length {} outside [{:?}, {:?}]", len, min, max),
                            stage_index: idx,
                        },
                        taints,
                    };
                }
            }
            Stage::Range { min, max } => {
                let Some(n) = current.as_i64() else {
                    return PipelineEvaluation {
                        outcome: FieldOutcome::Deny {
                            reason: format!("range requires integer value, got {}", value_kind(&current)),
                            stage_index: idx,
                        },
                        taints,
                    };
                };
                if min.map_or(false, |m| n < m) || max.map_or(false, |m| n > m) {
                    return PipelineEvaluation {
                        outcome: FieldOutcome::Deny {
                            reason: format!("value {} outside [{:?}, {:?}]", n, min, max),
                            stage_index: idx,
                        },
                        taints,
                    };
                }
            }
            Stage::Enum { values } => {
                let Some(s) = current.as_str() else {
                    return PipelineEvaluation {
                        outcome: FieldOutcome::Deny {
                            reason: format!("enum(...) requires string value, got {}", value_kind(&current)),
                            stage_index: idx,
                        },
                        taints,
                    };
                };
                if !values.iter().any(|v| v == s) {
                    return PipelineEvaluation {
                        outcome: FieldOutcome::Deny {
                            reason: format!("value `{}` not in enum {:?}", s, values),
                            stage_index: idx,
                        },
                        taints,
                    };
                }
            }
            Stage::Regex { pattern } => {
                // Compile-at-eval for now. A future step can swap to a
                // route-level pre-compile cache keyed by pattern.
                let re = match regex::Regex::new(pattern) {
                    Ok(r) => r,
                    Err(e) => {
                        return PipelineEvaluation {
                            outcome: FieldOutcome::Deny {
                                reason: format!("invalid regex `{}`: {}", pattern, e),
                                stage_index: idx,
                            },
                            taints,
                        };
                    }
                };
                let Some(s) = current.as_str() else {
                    return PipelineEvaluation {
                        outcome: FieldOutcome::Deny {
                            reason: format!("regex requires string value, got {}", value_kind(&current)),
                            stage_index: idx,
                        },
                        taints,
                    };
                };
                if !re.is_match(s) {
                    return PipelineEvaluation {
                        outcome: FieldOutcome::Deny {
                            reason: format!("value did not match regex `{}`", pattern),
                            stage_index: idx,
                        },
                        taints,
                    };
                }
            }
            Stage::Validate { name: _ } => {
                // TODO: named-validator dispatch. Needs a ValidatorRegistry
                // (similar to PluginInvoker, but synchronous) — out of scope
                // for this step. For now, validate(name) is a no-op so
                // upstream parsing still works.
            }

            // ----- Transforms -----
            Stage::Mask { keep_last } => {
                let Some(s) = current.as_str() else {
                    return PipelineEvaluation {
                        outcome: FieldOutcome::Deny {
                            reason: format!("mask(...) requires string value, got {}", value_kind(&current)),
                            stage_index: idx,
                        },
                        taints,
                    };
                };
                let chars: Vec<char> = s.chars().collect();
                let keep = (*keep_last).min(chars.len());
                let mask_count = chars.len() - keep;
                let masked: String = std::iter::repeat('*').take(mask_count)
                    .chain(chars.into_iter().skip(mask_count))
                    .collect();
                current = serde_json::Value::String(masked);
                replaced = true;
            }
            Stage::Redact { condition } => {
                let should_redact = match condition {
                    None => true,
                    Some(expr) => eval_expression(expr, bag),
                };
                if should_redact {
                    current = serde_json::Value::String("[REDACTED]".into());
                    replaced = true;
                }
            }
            Stage::Omit => {
                return PipelineEvaluation { outcome: FieldOutcome::Omit, taints };
            }
            Stage::Hash => {
                // Simple deterministic digest — DefaultHasher is fine for
                // de-identification (not for cryptographic use).
                use std::hash::{Hash, Hasher};
                let mut h = std::collections::hash_map::DefaultHasher::new();
                value_for_hash(&current).hash(&mut h);
                current = serde_json::Value::String(format!("hash:{:016x}", h.finish()));
                replaced = true;
            }

            // ----- Effects -----
            Stage::Taint { label, scopes } => {
                taints.push(TaintEvent { label: label.clone(), scopes: scopes.clone() });
            }
            Stage::Plugin { name } => {
                let invocation = PluginInvocation::Field { name: field_name, value: &current };
                match plugins.invoke(name, bag, invocation).await {
                    Ok(outcome) => {
                        // Plugins can emit taints regardless of decision.
                        taints.extend(outcome.taints);
                        match outcome.decision {
                            Decision::Allow => {
                                if let Some(new_value) = outcome.modified_value {
                                    current = new_value;
                                    replaced = true;
                                }
                            }
                            Decision::Deny { reason, rule_source: _ } => {
                                return PipelineEvaluation {
                                    outcome: FieldOutcome::Deny {
                                        reason: reason.unwrap_or_else(
                                            || format!("plugin `{}` denied", name),
                                        ),
                                        stage_index: idx,
                                    },
                                    taints,
                                };
                            }
                        }
                    }
                    Err(e) => {
                        // Fail-closed: plugin dispatch failure halts the pipeline.
                        return PipelineEvaluation {
                            outcome: FieldOutcome::Deny {
                                reason: format!("plugin `{}` error: {}", name, e),
                                stage_index: idx,
                            },
                            taints,
                        };
                    }
                }
            }
            Stage::Scan { kind } => {
                // Spec mapping (apl-dsl-spec §4): scan stages are taint
                // emitters. The actual PII detection / injection signal
                // lives in plugin(...) variants of the same scanners; this
                // stage just records the label so downstream policies can
                // gate on it. `pii.redact` additionally rewrites the value.
                let (label, redact): (&str, bool) = match kind {
                    ScanKind::PiiDetect => ("PII", false),
                    ScanKind::PiiRedact => ("PII", true),
                    ScanKind::InjectionScan => ("injection", false),
                };
                taints.push(TaintEvent {
                    label: label.to_string(),
                    scopes: vec![TaintScope::Session],
                });
                if redact {
                    current = serde_json::Value::String("[REDACTED]".into());
                    replaced = true;
                }
            }
        }
    }

    let outcome = if replaced {
        FieldOutcome::Replace(current)
    } else {
        FieldOutcome::Pass
    };
    PipelineEvaluation { outcome, taints }
}


fn type_check(tc: &TypeCheck, v: &serde_json::Value) -> bool {
    match tc {
        TypeCheck::Str => v.is_string(),
        TypeCheck::Int => v.is_i64(),
        TypeCheck::Bool => v.is_boolean(),
        TypeCheck::Float => v.is_f64() || v.is_i64(),
        TypeCheck::Email => v.as_str().map_or(false, |s| s.contains('@') && s.contains('.')),
        TypeCheck::Url => v.as_str().map_or(false, |s| s.starts_with("http://") || s.starts_with("https://")),
        TypeCheck::Uuid => v.as_str().map_or(false, is_uuid_shape),
    }
}

fn is_uuid_shape(s: &str) -> bool {
    // 8-4-4-4-12 hex with `-` separators.
    let bytes = s.as_bytes();
    if bytes.len() != 36 { return false; }
    for (i, &b) in bytes.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => if b != b'-' { return false; },
            _ => if !b.is_ascii_hexdigit() { return false; },
        }
    }
    true
}

fn value_kind(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(n) if n.is_i64() => "int",
        serde_json::Value::Number(_) => "float",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// Stable byte representation of a value for hashing — serde_json's
/// `to_string` is canonical enough for our use.
fn value_for_hash(v: &serde_json::Value) -> String {
    serde_json::to_string(v).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Action, Condition, Expression, Literal, Rule};
    use std::collections::HashSet;

    fn rule(condition: Expression, action: Action, source: &str) -> Rule {
        Rule { condition, action, source: source.into() }
    }

    fn deny(reason: &str) -> Action {
        Action::Deny { reason: Some(reason.into()) }
    }

    fn cond(c: Condition) -> Expression {
        Expression::Condition(c)
    }

    // ----- Decision-level semantics -----

    #[test]
    fn empty_rules_allow() {
        let bag = AttributeBag::new();
        assert_eq!(evaluate_rules(&[], &bag), Decision::Allow);
    }

    #[test]
    fn first_deny_halts() {
        let mut bag = AttributeBag::new();
        bag.set("a", true);
        bag.set("b", true);

        let rules = vec![
            rule(cond(Condition::IsTrue { key: "a".into() }), deny("first"), "r0"),
            rule(cond(Condition::IsTrue { key: "b".into() }), deny("second"), "r1"),
        ];

        match evaluate_rules(&rules, &bag) {
            Decision::Deny { reason, rule_source } => {
                assert_eq!(reason.as_deref(), Some("first"));
                assert_eq!(rule_source, "r0");
            }
            d => panic!("expected Deny, got {:?}", d),
        }
    }

    #[test]
    fn allow_does_not_short_circuit() {
        // Spec §3: explicit allow continues evaluation. A later deny still fires.
        let mut bag = AttributeBag::new();
        bag.set("ok", true);
        bag.set("bad", true);

        let rules = vec![
            rule(cond(Condition::IsTrue { key: "ok".into() }), Action::Allow, "r0_allow"),
            rule(cond(Condition::IsTrue { key: "bad".into() }), deny("later"), "r1_deny"),
        ];

        match evaluate_rules(&rules, &bag) {
            Decision::Deny { rule_source, .. } => assert_eq!(rule_source, "r1_deny"),
            d => panic!("allow short-circuited; expected later deny, got {:?}", d),
        }
    }

    #[test]
    fn unmatched_rules_dont_fire() {
        let bag = AttributeBag::new(); // "denied" missing → false
        let rules = vec![rule(
            cond(Condition::IsTrue { key: "denied".into() }),
            deny("shouldn't fire"),
            "r0",
        )];
        assert_eq!(evaluate_rules(&rules, &bag), Decision::Allow);
    }

    // ----- Predicate semantics -----

    #[test]
    fn missing_key_is_false() {
        let bag = AttributeBag::new();
        assert!(!eval_condition(&Condition::IsTrue { key: "missing".into() }, &bag));
        assert!(eval_condition(&Condition::IsFalse { key: "missing".into() }, &bag));
        // Comparison on missing → false (spec §2.6).
        assert!(!eval_condition(
            &Condition::Comparison {
                key: "missing".into(),
                op: CompareOp::Eq,
                value: 1_i64.into(),
            },
            &bag,
        ));
    }

    #[test]
    fn and_or_not_combinators() {
        let mut bag = AttributeBag::new();
        bag.set("a", true);
        bag.set("b", false);

        let a = cond(Condition::IsTrue { key: "a".into() });
        let b = cond(Condition::IsTrue { key: "b".into() });

        assert!(eval_expression(&Expression::And(vec![a.clone(), a.clone()]), &bag));
        assert!(!eval_expression(&Expression::And(vec![a.clone(), b.clone()]), &bag));
        assert!(eval_expression(&Expression::Or(vec![a.clone(), b.clone()]), &bag));
        assert!(!eval_expression(&Expression::Or(vec![b.clone(), b.clone()]), &bag));
        assert!(eval_expression(&Expression::Not(Box::new(b)), &bag));
    }

    // ----- Comparison operators -----

    #[test]
    fn int_comparisons() {
        let mut bag = AttributeBag::new();
        bag.set("delegation.depth", 3_i64);

        let cmp = |op| Condition::Comparison {
            key: "delegation.depth".into(),
            op,
            value: 2_i64.into(),
        };
        assert!(eval_condition(&cmp(CompareOp::Gt), &bag));
        assert!(eval_condition(&cmp(CompareOp::GtEq), &bag));
        assert!(!eval_condition(&cmp(CompareOp::Lt), &bag));
        assert!(!eval_condition(&cmp(CompareOp::Eq), &bag));
        assert!(eval_condition(&cmp(CompareOp::NotEq), &bag));
    }

    #[test]
    fn int_to_float_promotion_in_comparison() {
        let mut bag = AttributeBag::new();
        bag.set("delegation.depth", 2_i64);
        // `delegation.depth > 2.5` — int promotes to float for the compare.
        assert!(!eval_condition(
            &Condition::Comparison {
                key: "delegation.depth".into(),
                op: CompareOp::Gt,
                value: 2.5_f64.into(),
            },
            &bag,
        ));
        assert!(eval_condition(
            &Condition::Comparison {
                key: "delegation.depth".into(),
                op: CompareOp::Lt,
                value: 2.5_f64.into(),
            },
            &bag,
        ));
    }

    #[test]
    fn string_equality_no_ordering() {
        let mut bag = AttributeBag::new();
        bag.set("subject.id", "alice");

        assert!(eval_condition(
            &Condition::Comparison {
                key: "subject.id".into(),
                op: CompareOp::Eq,
                value: "alice".into(),
            },
            &bag,
        ));
        // Order operators on strings → false (spec §2.3).
        assert!(!eval_condition(
            &Condition::Comparison {
                key: "subject.id".into(),
                op: CompareOp::Gt,
                value: "alice".into(),
            },
            &bag,
        ));
    }

    #[test]
    fn contains_set_membership() {
        let mut bag = AttributeBag::new();
        bag.set(
            "session.labels",
            HashSet::from(["PII".to_string(), "financial".to_string()]),
        );

        assert!(eval_condition(
            &Condition::Comparison {
                key: "session.labels".into(),
                op: CompareOp::Contains,
                value: "PII".into(),
            },
            &bag,
        ));
        assert!(!eval_condition(
            &Condition::Comparison {
                key: "session.labels".into(),
                op: CompareOp::Contains,
                value: "PHI".into(),
            },
            &bag,
        ));
        // Contains on a non-set attribute → false.
        bag.set("subject.id", "alice");
        assert!(!eval_condition(
            &Condition::Comparison {
                key: "subject.id".into(),
                op: CompareOp::Contains,
                value: "alice".into(),
            },
            &bag,
        ));
    }

    // ----- Realistic end-to-end -----

    #[test]
    fn hr_compensation_scenario() {
        // From the HR demo: alice (hr role + view_ssn perm) requests compensation
        // with delegation.depth = 1. Rules:
        //   1. require(authenticated)
        //   2. require(role.hr | role.finance)
        //   3. delegation.depth > 2 & include_ssn: deny
        //   4. !perm.view_ssn & include_ssn: deny
        let mut bag = AttributeBag::new();
        bag.set("authenticated", true);
        bag.set("role.hr", true);
        bag.set("perm.view_ssn", true);
        bag.set("delegation.depth", 1_i64);
        bag.set("include_ssn", true);

        let rules = vec![
            // require(authenticated) → deny if !authenticated
            rule(
                Expression::Not(Box::new(cond(Condition::IsTrue {
                    key: "authenticated".into(),
                }))),
                deny("not authenticated"),
                "r0",
            ),
            // require(role.hr | role.finance) → deny if neither
            // Desugars to: when !(role.hr | role.finance) do deny
            //             = when (role.hr is false) AND (role.finance is false), deny
            rule(
                Expression::And(vec![
                    cond(Condition::IsFalse { key: "role.hr".into() }),
                    cond(Condition::IsFalse { key: "role.finance".into() }),
                ]),
                deny("not in hr/finance"),
                "r1",
            ),
            // delegation.depth > 2 & include_ssn: deny
            rule(
                Expression::And(vec![
                    cond(Condition::Comparison {
                        key: "delegation.depth".into(),
                        op: CompareOp::Gt,
                        value: 2_i64.into(),
                    }),
                    cond(Condition::IsTrue { key: "include_ssn".into() }),
                ]),
                deny("delegation too deep for SSN"),
                "r2",
            ),
        ];

        assert_eq!(evaluate_rules(&rules, &bag), Decision::Allow);

        // Now make Alice undelegated-but-deep — should still allow at depth=1.
        // Change to depth=3 and the SSN rule fires.
        bag.set("delegation.depth", 3_i64);
        match evaluate_rules(&rules, &bag) {
            Decision::Deny { rule_source, .. } => assert_eq!(rule_source, "r2"),
            d => panic!("expected r2 deny, got {:?}", d),
        }
    }

    // ===================================================================
    // Pipe-chain evaluator tests
    // ===================================================================

    use crate::pipeline::{Stage, TypeCheck};
    use serde_json::json;

    fn make_pipeline(stages: Vec<Stage>) -> crate::pipeline::Pipeline {
        crate::pipeline::Pipeline { stages }
    }

    // Helper: a plugin invoker that's never expected to fire (pipelines
    // without `plugin(...)` stages). Panics if called. Defined alongside
    // the other null fixtures further down in this module.

    async fn run_pipeline(
        p: &crate::pipeline::Pipeline,
        v: &serde_json::Value,
        bag: &AttributeBag,
    ) -> FieldOutcome {
        evaluate_pipeline(p, v, bag, &NullPipelinePlugins, "test_field").await.outcome
    }

    /// Pipeline-test null invoker — distinct from the step-test `NullPlugins`
    /// so each test can panic with a clearer "wrong fixture" message if it
    /// ever does dispatch a plugin call by accident.
    struct NullPipelinePlugins;
    #[async_trait]
    impl PluginInvoker for NullPipelinePlugins {
        async fn invoke(
            &self,
            name: &str,
            _bag: &AttributeBag,
            _invocation: PluginInvocation<'_>,
        ) -> Result<PluginOutcome, PluginError> {
            panic!("NullPipelinePlugins should not dispatch; got plugin({})", name);
        }
    }

    #[tokio::test]
    async fn pipeline_empty_is_pass() {
        let bag = AttributeBag::new();
        let p = make_pipeline(vec![]);
        assert_eq!(run_pipeline(&p, &json!("anything"), &bag).await, FieldOutcome::Pass);
    }

    #[tokio::test]
    async fn pipeline_type_check_passes_and_denies() {
        let bag = AttributeBag::new();
        let p = make_pipeline(vec![Stage::Type(TypeCheck::Str)]);
        assert_eq!(run_pipeline(&p, &json!("hello"), &bag).await, FieldOutcome::Pass);
        match run_pipeline(&p, &json!(42), &bag).await {
            FieldOutcome::Deny { reason, stage_index } => {
                assert!(reason.contains("expected Str"));
                assert_eq!(stage_index, 0);
            }
            other => panic!("expected Deny, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn pipeline_mask_preserves_last_n() {
        let bag = AttributeBag::new();
        let p = make_pipeline(vec![Stage::Mask { keep_last: 4 }]);
        match run_pipeline(&p, &json!("123-45-6789"), &bag).await {
            FieldOutcome::Replace(v) => assert_eq!(v, json!("*******6789")),
            other => panic!("expected Replace, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn pipeline_mask_handles_short_strings() {
        let bag = AttributeBag::new();
        let p = make_pipeline(vec![Stage::Mask { keep_last: 4 }]);
        // keep_last >= length → no mask chars; full string preserved.
        match run_pipeline(&p, &json!("ab"), &bag).await {
            FieldOutcome::Replace(v) => assert_eq!(v, json!("ab")),
            other => panic!("expected Replace, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn pipeline_unconditional_redact() {
        let bag = AttributeBag::new();
        let p = make_pipeline(vec![Stage::Redact { condition: None }]);
        match run_pipeline(&p, &json!("secret"), &bag).await {
            FieldOutcome::Replace(v) => assert_eq!(v, json!("[REDACTED]")),
            other => panic!("expected Replace, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn pipeline_conditional_redact_fires_when_condition_true() {
        // redact(!perm.view_ssn): condition is `!perm.view_ssn`. Missing key
        // → IsTrue is false → `!IsTrue` is true → redact fires.
        let bag = AttributeBag::new();
        let cond = Expression::Not(Box::new(Expression::Condition(Condition::IsTrue {
            key: "perm.view_ssn".into(),
        })));
        let p = make_pipeline(vec![Stage::Redact { condition: Some(cond) }]);
        match run_pipeline(&p, &json!("123-45-6789"), &bag).await {
            FieldOutcome::Replace(v) => assert_eq!(v, json!("[REDACTED]")),
            other => panic!("expected Replace (redact fired), got {:?}", other),
        }
    }

    #[tokio::test]
    async fn pipeline_conditional_redact_skips_when_condition_false() {
        let mut bag = AttributeBag::new();
        bag.set("perm.view_ssn", true);
        let cond = Expression::Not(Box::new(Expression::Condition(Condition::IsTrue {
            key: "perm.view_ssn".into(),
        })));
        let p = make_pipeline(vec![Stage::Redact { condition: Some(cond) }]);
        // perm.view_ssn=true → !true=false → redact skipped → Pass.
        assert_eq!(
            run_pipeline(&p, &json!("123-45-6789"), &bag).await,
            FieldOutcome::Pass,
        );
    }

    #[tokio::test]
    async fn pipeline_omit_short_circuits() {
        let bag = AttributeBag::new();
        let p = make_pipeline(vec![
            Stage::Omit,
            // This stage should never run.
            Stage::Type(TypeCheck::Int),
        ]);
        assert_eq!(run_pipeline(&p, &json!("anything"), &bag).await, FieldOutcome::Omit);
    }

    #[tokio::test]
    async fn pipeline_range_validator() {
        let bag = AttributeBag::new();
        let p = make_pipeline(vec![
            Stage::Type(TypeCheck::Int),
            Stage::Range { min: Some(0), max: Some(1_000_000) },
        ]);
        assert_eq!(run_pipeline(&p, &json!(500_000), &bag).await, FieldOutcome::Pass);
        // Above max → deny.
        match run_pipeline(&p, &json!(2_000_000), &bag).await {
            FieldOutcome::Deny { reason, stage_index } => {
                assert!(reason.contains("outside"));
                assert_eq!(stage_index, 1);
            }
            other => panic!("expected Deny, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn pipeline_length_validator() {
        let bag = AttributeBag::new();
        let p = make_pipeline(vec![Stage::Length { min: None, max: Some(5) }]);
        assert_eq!(run_pipeline(&p, &json!("hi"), &bag).await, FieldOutcome::Pass);
        assert!(matches!(
            run_pipeline(&p, &json!("too long"), &bag).await,
            FieldOutcome::Deny { .. },
        ));
    }

    #[tokio::test]
    async fn pipeline_enum_validator() {
        let bag = AttributeBag::new();
        let p = make_pipeline(vec![Stage::Enum {
            values: vec!["low".into(), "medium".into(), "high".into()],
        }]);
        assert_eq!(run_pipeline(&p, &json!("medium"), &bag).await, FieldOutcome::Pass);
        assert!(matches!(
            run_pipeline(&p, &json!("extreme"), &bag).await,
            FieldOutcome::Deny { .. },
        ));
    }

    #[tokio::test]
    async fn pipeline_uuid_validator() {
        let bag = AttributeBag::new();
        let p = make_pipeline(vec![Stage::Type(TypeCheck::Uuid)]);
        assert_eq!(
            run_pipeline(&p, &json!("550e8400-e29b-41d4-a716-446655440000"), &bag).await,
            FieldOutcome::Pass,
        );
        assert!(matches!(
            run_pipeline(&p, &json!("not-a-uuid"), &bag).await,
            FieldOutcome::Deny { .. },
        ));
    }

    #[tokio::test]
    async fn pipeline_hash_replaces_value() {
        let bag = AttributeBag::new();
        let p = make_pipeline(vec![Stage::Hash]);
        match run_pipeline(&p, &json!("secret"), &bag).await {
            FieldOutcome::Replace(v) => {
                let s = v.as_str().unwrap();
                assert!(s.starts_with("hash:"));
                assert_eq!(s.len(), "hash:".len() + 16);
            }
            other => panic!("expected Replace, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn pipeline_validate_named_is_stub() {
        // `validate(name)` is a no-op until the ValidatorRegistry lands.
        // It should not deny, and should not interrupt subsequent stages.
        let bag = AttributeBag::new();
        let p = make_pipeline(vec![
            Stage::Type(TypeCheck::Str),
            Stage::Validate { name: "ssn_format".into() },
            Stage::Mask { keep_last: 4 },
        ]);
        match run_pipeline(&p, &json!("123-45-6789"), &bag).await {
            FieldOutcome::Replace(v) => assert_eq!(v, json!("*******6789")),
            other => panic!("expected Replace, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn pipeline_validator_short_circuits_before_transform() {
        // If the validator fails, the transform never runs.
        let bag = AttributeBag::new();
        let p = make_pipeline(vec![
            Stage::Type(TypeCheck::Int),  // will fail on a string
            Stage::Mask { keep_last: 4 },
        ]);
        match run_pipeline(&p, &json!("hello"), &bag).await {
            FieldOutcome::Deny { stage_index, .. } => assert_eq!(stage_index, 0),
            other => panic!("expected Deny at stage 0, got {:?}", other),
        }
    }

    // ----- Regex stage -----

    #[tokio::test]
    async fn pipeline_regex_match_passes() {
        let bag = AttributeBag::new();
        let p = make_pipeline(vec![Stage::Regex {
            pattern: r"^\d{3}-\d{2}-\d{4}$".into(),
        }]);
        assert_eq!(run_pipeline(&p, &json!("123-45-6789"), &bag).await, FieldOutcome::Pass);
    }

    #[tokio::test]
    async fn pipeline_regex_no_match_denies() {
        let bag = AttributeBag::new();
        let p = make_pipeline(vec![Stage::Regex {
            pattern: r"^\d{3}-\d{2}-\d{4}$".into(),
        }]);
        match run_pipeline(&p, &json!("not an ssn"), &bag).await {
            FieldOutcome::Deny { reason, stage_index } => {
                assert!(reason.contains("did not match"));
                assert_eq!(stage_index, 0);
            }
            other => panic!("expected Deny, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn pipeline_regex_invalid_pattern_denies() {
        let bag = AttributeBag::new();
        let p = make_pipeline(vec![Stage::Regex { pattern: "(unclosed".into() }]);
        match run_pipeline(&p, &json!("anything"), &bag).await {
            FieldOutcome::Deny { reason, .. } => {
                assert!(reason.contains("invalid regex"));
            }
            other => panic!("expected Deny, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn pipeline_regex_non_string_denies() {
        let bag = AttributeBag::new();
        let p = make_pipeline(vec![Stage::Regex { pattern: r"^\d+$".into() }]);
        match run_pipeline(&p, &json!(42), &bag).await {
            FieldOutcome::Deny { reason, .. } => {
                assert!(reason.contains("requires string"));
            }
            other => panic!("expected Deny on non-string regex input, got {:?}", other),
        }
    }

    // ----- Taint and Scan stages -----

    #[tokio::test]
    async fn pipeline_taint_records_event() {
        let bag = AttributeBag::new();
        let p = make_pipeline(vec![
            Stage::Type(TypeCheck::Str),
            Stage::Taint { label: "PII".into(), scopes: vec![TaintScope::Session] },
            Stage::Mask { keep_last: 4 },
        ]);
        let result = evaluate_pipeline(&p, &json!("123-45-6789"), &bag, &NullPipelinePlugins, "test_field").await;
        assert_eq!(result.outcome, FieldOutcome::Replace(json!("*******6789")));
        assert_eq!(result.taints, vec![TaintEvent {
            label: "PII".into(),
            scopes: vec![TaintScope::Session],
        }]);
    }

    #[tokio::test]
    async fn pipeline_scan_pii_detect_emits_taint() {
        let bag = AttributeBag::new();
        let p = make_pipeline(vec![Stage::Scan { kind: ScanKind::PiiDetect }]);
        let result = evaluate_pipeline(&p, &json!("some text"), &bag, &NullPipelinePlugins, "test_field").await;
        // PII detect: value unchanged, one taint event emitted.
        assert_eq!(result.outcome, FieldOutcome::Pass);
        assert_eq!(result.taints, vec![TaintEvent {
            label: "PII".into(),
            scopes: vec![TaintScope::Session],
        }]);
    }

    #[tokio::test]
    async fn pipeline_scan_pii_redact_replaces_and_taints() {
        let bag = AttributeBag::new();
        let p = make_pipeline(vec![Stage::Scan { kind: ScanKind::PiiRedact }]);
        let result = evaluate_pipeline(&p, &json!("123-45-6789"), &bag, &NullPipelinePlugins, "test_field").await;
        assert_eq!(result.outcome, FieldOutcome::Replace(json!("[REDACTED]")));
        assert_eq!(result.taints.len(), 1);
        assert_eq!(result.taints[0].label, "PII");
    }

    #[tokio::test]
    async fn pipeline_scan_injection_emits_injection_taint() {
        let bag = AttributeBag::new();
        let p = make_pipeline(vec![Stage::Scan { kind: ScanKind::InjectionScan }]);
        let result = evaluate_pipeline(&p, &json!("user input"), &bag, &NullPipelinePlugins, "test_field").await;
        assert_eq!(result.outcome, FieldOutcome::Pass);
        assert_eq!(result.taints[0].label, "injection");
    }

    #[tokio::test]
    async fn pipeline_deny_does_not_accumulate_later_taints() {
        // Pipeline halts at the first failing validator; taints emitted
        // before the failure stick, taints after do not.
        let bag = AttributeBag::new();
        let p = make_pipeline(vec![
            Stage::Taint { label: "before".into(), scopes: vec![TaintScope::Session] },
            Stage::Type(TypeCheck::Int),  // fails on string input
            Stage::Taint { label: "after".into(), scopes: vec![TaintScope::Session] },
        ]);
        let result = evaluate_pipeline(&p, &json!("hello"), &bag, &NullPipelinePlugins, "test_field").await;
        assert!(matches!(result.outcome, FieldOutcome::Deny { .. }));
        assert_eq!(result.taints, vec![TaintEvent {
            label: "before".into(),
            scopes: vec![TaintScope::Session],
        }]);
    }

    // ----- Plugin stage in pipe chain -----

    /// Pipe-context plugin invoker that returns canned outcomes by name.
    struct PipePlugin {
        outcomes: std::collections::HashMap<String, PluginOutcome>,
    }
    #[async_trait]
    impl PluginInvoker for PipePlugin {
        async fn invoke(
            &self,
            name: &str,
            _bag: &AttributeBag,
            _invocation: PluginInvocation<'_>,
        ) -> Result<PluginOutcome, PluginError> {
            self.outcomes
                .get(name)
                .cloned()
                .ok_or_else(|| PluginError::NotFound(name.into()))
        }
    }

    #[tokio::test]
    async fn pipeline_plugin_allow_continues() {
        let bag = AttributeBag::new();
        let plugins = PipePlugin {
            outcomes: std::collections::HashMap::from([
                ("noop".to_string(), PluginOutcome::allow()),
            ]),
        };
        let p = make_pipeline(vec![
            Stage::Type(TypeCheck::Str),
            Stage::Plugin { name: "noop".into() },
            Stage::Mask { keep_last: 4 },
        ]);
        let result = evaluate_pipeline(&p, &json!("123-45-6789"), &bag, &plugins, "compensation").await;
        assert_eq!(result.outcome, FieldOutcome::Replace(json!("*******6789")));
        assert!(result.taints.is_empty());
    }

    #[tokio::test]
    async fn pipeline_plugin_can_replace_value() {
        let bag = AttributeBag::new();
        let plugins = PipePlugin {
            outcomes: std::collections::HashMap::from([
                ("scrubber".to_string(), PluginOutcome {
                    decision: Decision::Allow,
                    taints: vec![TaintEvent {
                        label: "PII".to_string(),
                        scopes: vec![TaintScope::Session],
                    }],
                    modified_value: Some(json!("***scrubbed***")),
                }),
            ]),
        };
        let p = make_pipeline(vec![Stage::Plugin { name: "scrubber".into() }]);
        let result = evaluate_pipeline(&p, &json!("sensitive data"), &bag, &plugins, "notes").await;
        assert_eq!(result.outcome, FieldOutcome::Replace(json!("***scrubbed***")));
        assert_eq!(result.taints, vec![TaintEvent {
            label: "PII".into(),
            scopes: vec![TaintScope::Session],
        }]);
    }

    #[tokio::test]
    async fn pipeline_plugin_deny_halts() {
        let bag = AttributeBag::new();
        let plugins = PipePlugin {
            outcomes: std::collections::HashMap::from([
                ("guard".to_string(), PluginOutcome {
                    decision: Decision::Deny {
                        reason: Some("policy violation".into()),
                        rule_source: "guard".into(),
                    },
                    taints: vec![],
                    modified_value: None,
                }),
            ]),
        };
        let p = make_pipeline(vec![
            Stage::Plugin { name: "guard".into() },
            // Should never run.
            Stage::Mask { keep_last: 4 },
        ]);
        let result = evaluate_pipeline(&p, &json!("data"), &bag, &plugins, "payload").await;
        match result.outcome {
            FieldOutcome::Deny { reason, stage_index } => {
                assert_eq!(reason, "policy violation");
                assert_eq!(stage_index, 0);
            }
            other => panic!("expected Deny, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn pipeline_plugin_missing_fails_closed() {
        let bag = AttributeBag::new();
        let plugins = PipePlugin { outcomes: Default::default() };
        let p = make_pipeline(vec![Stage::Plugin { name: "missing".into() }]);
        let result = evaluate_pipeline(&p, &json!("data"), &bag, &plugins, "payload").await;
        match result.outcome {
            FieldOutcome::Deny { reason, .. } => assert!(reason.contains("missing")),
            other => panic!("expected Deny on missing plugin, got {:?}", other),
        }
    }

    // ===================================================================
    // 5c additions: Exists, InSet, Always
    // ===================================================================

    #[test]
    fn exists_distinguishes_missing_from_falsy() {
        let mut bag = AttributeBag::new();
        bag.set("args.flag", false);
        // Key is present with a falsy value — IsTrue says false, Exists says true.
        assert!(!eval_condition(&Condition::IsTrue { key: "args.flag".into() }, &bag));
        assert!(eval_condition(&Condition::Exists { key: "args.flag".into() }, &bag));
        // Missing key — Exists is false.
        assert!(!eval_condition(&Condition::Exists { key: "args.nonexistent".into() }, &bag));
    }

    #[test]
    fn in_set_member_and_non_member() {
        let mut bag = AttributeBag::new();
        bag.set("subject.type", "user");
        bag.set(
            "allowed_types",
            std::collections::HashSet::from(["user".to_string(), "service".to_string()]),
        );

        assert!(eval_condition(&Condition::InSet {
            value_key: "subject.type".into(),
            set_key: "allowed_types".into(),
            negate: false,
        }, &bag));

        bag.set("subject.type", "agent");
        assert!(!eval_condition(&Condition::InSet {
            value_key: "subject.type".into(),
            set_key: "allowed_types".into(),
            negate: false,
        }, &bag));
    }

    #[test]
    fn in_set_negate() {
        let mut bag = AttributeBag::new();
        bag.set("subject.type", "agent");
        bag.set(
            "blocked_types",
            std::collections::HashSet::from(["service".to_string()]),
        );

        // agent is not in blocked_types → not in → true
        assert!(eval_condition(&Condition::InSet {
            value_key: "subject.type".into(),
            set_key: "blocked_types".into(),
            negate: true,
        }, &bag));
    }

    #[test]
    fn in_set_missing_keys_resolve_to_false() {
        let bag = AttributeBag::new();
        // Both missing → in = false → not in = true (spec §2.6 missing→false
        // applies to the underlying `in` lookup; negate flips it).
        assert!(!eval_condition(&Condition::InSet {
            value_key: "x".into(),
            set_key: "y".into(),
            negate: false,
        }, &bag));
        assert!(eval_condition(&Condition::InSet {
            value_key: "x".into(),
            set_key: "y".into(),
            negate: true,
        }, &bag));
    }

    #[test]
    fn always_evaluates_true() {
        let bag = AttributeBag::new();
        assert!(eval_expression(&Expression::Always, &bag));
    }

    #[test]
    fn always_rule_unconditional_deny() {
        let bag = AttributeBag::new();
        let r = Rule {
            condition: Expression::Always,
            action: Action::Deny { reason: Some("unconditional".into()) },
            source: "test".into(),
        };
        match evaluate_rules(&[r], &bag) {
            Decision::Deny { reason, .. } => assert_eq!(reason.as_deref(), Some("unconditional")),
            d => panic!("expected Deny, got {:?}", d),
        }
    }

    // ===================================================================
    // 5c-v/vi: async step evaluator with mock resolvers
    // ===================================================================

    use crate::step::{
        PdpCall, PdpDecision, PdpDialect, PdpError, PdpResolver, PluginError, PluginInvocation,
        PluginInvoker, PluginOutcome, Step,
    };
    use async_trait::async_trait;

    /// PDP resolver that returns the decision baked into it. Doesn't
    /// inspect call.args — tests assert on call.dialect / on the decision
    /// flow, not on Cedar/OPA-specific arg parsing.
    struct FakePdp {
        decision: Decision,
    }
    #[async_trait]
    impl PdpResolver for FakePdp {
        fn dialect(&self) -> PdpDialect { PdpDialect::Cedar }
        async fn evaluate(
            &self,
            _call: &PdpCall,
            _bag: &AttributeBag,
        ) -> Result<PdpDecision, PdpError> {
            Ok(PdpDecision { decision: self.decision.clone(), diagnostics: vec![] })
        }
    }

    /// PDP resolver that returns an error — exercises fail-closed path.
    struct ErroringPdp;
    #[async_trait]
    impl PdpResolver for ErroringPdp {
        fn dialect(&self) -> PdpDialect { PdpDialect::Cedar }
        async fn evaluate(
            &self,
            _call: &PdpCall,
            _bag: &AttributeBag,
        ) -> Result<PdpDecision, PdpError> {
            Err(PdpError::Dispatch("simulated PDP outage".into()))
        }
    }

    /// Plugin invoker keyed by name → outcome.
    struct FakePlugin {
        decisions: std::collections::HashMap<String, Decision>,
    }
    #[async_trait]
    impl PluginInvoker for FakePlugin {
        async fn invoke(
            &self,
            name: &str,
            _bag: &AttributeBag,
            _invocation: PluginInvocation<'_>,
        ) -> Result<PluginOutcome, PluginError> {
            match self.decisions.get(name) {
                Some(d) => Ok(PluginOutcome {
                    decision: d.clone(),
                    taints: vec![],
                    modified_value: None,
                }),
                None => Err(PluginError::NotFound(name.into())),
            }
        }
    }

    /// Null invoker — fails any plugin call (for PDP-only tests).
    struct NullPlugins;
    #[async_trait]
    impl PluginInvoker for NullPlugins {
        async fn invoke(
            &self,
            name: &str,
            _bag: &AttributeBag,
            _invocation: PluginInvocation<'_>,
        ) -> Result<PluginOutcome, PluginError> {
            Err(PluginError::NotFound(name.into()))
        }
    }

    fn pdp_step(decision_diagnostic_label: &str) -> Step {
        Step::Pdp {
            call: PdpCall {
                dialect: PdpDialect::Cedar,
                args: serde_yaml::Value::String(decision_diagnostic_label.into()),
            },
            on_deny: vec![],
            on_allow: vec![],
        }
    }

    #[tokio::test]
    async fn steps_rule_only_path() {
        let bag = AttributeBag::new();
        let steps = vec![Step::Rule(Rule {
            condition: Expression::Always,
            action: Action::Allow,
            source: "test".into(),
        })];
        let r = evaluate_steps(&steps, &bag, &FakePdp { decision: Decision::Allow }, &NullPlugins).await;
        assert_eq!(r.decision, Decision::Allow);
    }

    #[tokio::test]
    async fn pdp_allow_continues() {
        let bag = AttributeBag::new();
        let steps = vec![pdp_step("dummy")];
        let pdp = FakePdp { decision: Decision::Allow };
        assert_eq!(
            evaluate_steps(&steps, &bag, &pdp, &NullPlugins).await.decision,
            Decision::Allow,
        );
    }

    #[tokio::test]
    async fn pdp_deny_returns_deny() {
        let bag = AttributeBag::new();
        let steps = vec![pdp_step("dummy")];
        let pdp = FakePdp {
            decision: Decision::Deny { reason: Some("forbidden".into()), rule_source: "pdp".into() },
        };
        match evaluate_steps(&steps, &bag, &pdp, &NullPlugins).await.decision {
            Decision::Deny { reason, .. } => assert_eq!(reason.as_deref(), Some("forbidden")),
            d => panic!("expected Deny, got {:?}", d),
        }
    }

    #[tokio::test]
    async fn pdp_on_deny_reaction_can_override_reason() {
        // PDP denies, on_deny reaction includes a more specific deny rule that
        // fires before the PDP's deny is returned.
        let bag = AttributeBag::new();
        let steps = vec![Step::Pdp {
            call: PdpCall { dialect: PdpDialect::Cedar, args: serde_yaml::Value::Null },
            on_deny: vec![Step::Rule(Rule {
                condition: Expression::Always,
                action: Action::Deny { reason: Some("reaction took over".into()) },
                source: "on_deny[0]".into(),
            })],
            on_allow: vec![],
        }];
        let pdp = FakePdp {
            decision: Decision::Deny { reason: Some("pdp original".into()), rule_source: "p".into() },
        };
        match evaluate_steps(&steps, &bag, &pdp, &NullPlugins).await.decision {
            Decision::Deny { reason, rule_source } => {
                assert_eq!(reason.as_deref(), Some("reaction took over"));
                assert_eq!(rule_source, "on_deny[0]");
            }
            d => panic!("expected Deny, got {:?}", d),
        }
    }

    #[tokio::test]
    async fn pdp_on_allow_can_deny() {
        // PDP allows, but an on_allow reaction can still deny (e.g., a
        // taint check that fails). Outcome: deny.
        let bag = AttributeBag::new();
        let steps = vec![Step::Pdp {
            call: PdpCall { dialect: PdpDialect::Cedar, args: serde_yaml::Value::Null },
            on_deny: vec![],
            on_allow: vec![Step::Rule(Rule {
                condition: Expression::Always,
                action: Action::Deny { reason: Some("reaction veto".into()) },
                source: "on_allow[0]".into(),
            })],
        }];
        let pdp = FakePdp { decision: Decision::Allow };
        match evaluate_steps(&steps, &bag, &pdp, &NullPlugins).await.decision {
            Decision::Deny { reason, .. } => assert_eq!(reason.as_deref(), Some("reaction veto")),
            d => panic!("expected Deny, got {:?}", d),
        }
    }

    #[tokio::test]
    async fn pdp_error_is_fail_closed() {
        let bag = AttributeBag::new();
        let steps = vec![pdp_step("dummy")];
        match evaluate_steps(&steps, &bag, &ErroringPdp, &NullPlugins).await.decision {
            Decision::Deny { reason, .. } => {
                assert!(reason.unwrap().contains("PDP error"));
            }
            d => panic!("expected Deny on PDP error, got {:?}", d),
        }
    }

    #[tokio::test]
    async fn plugin_allow_continues_deny_halts() {
        let bag = AttributeBag::new();
        let plugins = FakePlugin {
            decisions: std::collections::HashMap::from([
                ("ok_plugin".to_string(), Decision::Allow),
                ("blocking_plugin".to_string(), Decision::Deny {
                    reason: Some("rate limit hit".into()),
                    rule_source: "plugin".into(),
                }),
            ]),
        };

        let allow_only = vec![Step::Plugin { name: "ok_plugin".into() }];
        assert_eq!(
            evaluate_steps(&allow_only, &bag, &FakePdp { decision: Decision::Allow }, &plugins).await.decision,
            Decision::Allow,
        );

        let with_deny = vec![
            Step::Plugin { name: "ok_plugin".into() },
            Step::Plugin { name: "blocking_plugin".into() },
        ];
        match evaluate_steps(&with_deny, &bag, &FakePdp { decision: Decision::Allow }, &plugins).await.decision {
            Decision::Deny { reason, .. } => assert_eq!(reason.as_deref(), Some("rate limit hit")),
            d => panic!("expected Deny from blocking_plugin, got {:?}", d),
        }
    }

    #[tokio::test]
    async fn plugin_error_is_fail_closed() {
        let bag = AttributeBag::new();
        let plugins = FakePlugin { decisions: Default::default() };
        let steps = vec![Step::Plugin { name: "missing".into() }];
        match evaluate_steps(&steps, &bag, &FakePdp { decision: Decision::Allow }, &plugins).await.decision {
            Decision::Deny { reason, rule_source } => {
                assert!(reason.unwrap().contains("missing"));
                assert!(rule_source.contains("missing"));
            }
            d => panic!("expected Deny, got {:?}", d),
        }
    }

    #[tokio::test]
    async fn taint_step_always_continues_and_accumulates() {
        let bag = AttributeBag::new();
        let steps = vec![
            Step::Taint {
                label: "PII".into(),
                scopes: vec![crate::pipeline::TaintScope::Session],
            },
            // A later rule should still fire — taint doesn't short-circuit.
            Step::Rule(Rule {
                condition: Expression::Always,
                action: Action::Deny { reason: Some("after taint".into()) },
                source: "p[1]".into(),
            }),
        ];
        let eval = evaluate_steps(&steps, &bag, &FakePdp { decision: Decision::Allow }, &NullPlugins).await;
        match eval.decision {
            Decision::Deny { reason, .. } => assert_eq!(reason.as_deref(), Some("after taint")),
            d => panic!("expected Deny from rule after Taint, got {:?}", d),
        }
        // Step::Taint should have been accumulated into the phase's taints
        // before the deny landed — audit needs to see what tainted before
        // the policy halted.
        assert_eq!(eval.taints.len(), 1);
        assert_eq!(eval.taints[0].label, "PII");
        assert_eq!(eval.taints[0].scopes, vec![crate::pipeline::TaintScope::Session]);
    }
}
