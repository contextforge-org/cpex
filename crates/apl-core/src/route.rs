// Location: ./crates/apl-core/src/route.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Phase orchestration: runs `args → policy → result → post_policy` against a
// `CompiledRoute` and a mutable payload, returning a unified decision plus
// accumulated taints.
//
// This is the entry point apl-cpex calls into. Each phase has its own
// evaluator (see `evaluator.rs`); this module's job is to drive them in
// the right order with the right transitions (apply field mutations, halt
// on deny, thread taints across phases).
//
// Phase semantics (anchored in apl-dsl-spec.md §3):
//   - args: walk field rules; Replace/Omit mutate `payload.args`; Deny halts
//   - policy: walk steps; Deny halts
//   - result: only runs if `payload.result.is_some()`; same as args
//   - post_policy: walks steps; the spec leaves room for "observed only"
//     handling, but apl-core surfaces the deny — the host (apl-cpex) chooses
//     whether to enforce it
//
// Missing fields are skipped silently — a pipeline can't transform what
// isn't there. If a route needs to require presence, that's a policy-phase
// `require(exists(args.X))` rule.

use crate::attributes::AttributeBag;
use crate::evaluator::{evaluate_pipeline, evaluate_steps, Decision, FieldOutcome};
use crate::pipeline::TaintEvent;
use crate::rules::CompiledRoute;
use crate::step::{PdpResolver, PluginInvoker};

/// Mutable payload for a route invocation. `args` is the request arguments
/// object; `result` is the response object (`None` on the inbound path,
/// `Some` once the tool/resource has produced a value).
#[derive(Debug, Clone)]
pub struct RoutePayload {
    pub args: serde_json::Value,
    pub result: Option<serde_json::Value>,
}

impl RoutePayload {
    pub fn new(args: serde_json::Value) -> Self {
        Self { args, result: None }
    }

    pub fn with_result(args: serde_json::Value, result: serde_json::Value) -> Self {
        Self { args, result: Some(result) }
    }
}

/// Full outcome of running all four phases for a route.
#[derive(Debug, Clone)]
pub struct RouteDecision {
    pub decision: Decision,
    /// Taints accumulated from any phase. Empty unless a pipeline emitted them.
    pub taints: Vec<TaintEvent>,
    /// True if any args field was rewritten or omitted.
    pub args_modified: bool,
    /// True if any result field was rewritten or omitted.
    pub result_modified: bool,
}

/// Run all four phases against `payload`, mutating it in place.
///
/// On a phase Deny, halts and returns immediately — later phases don't run.
/// Taints accumulated before the halt survive in the result; the spec is
/// explicit that taint side-effects are observable even when the request
/// is ultimately denied (DSL §4 effect ordering).
pub async fn evaluate_route(
    route: &CompiledRoute,
    bag: &AttributeBag,
    payload: &mut RoutePayload,
    pdp: &dyn PdpResolver,
    plugins: &dyn PluginInvoker,
) -> RouteDecision {
    let mut taints: Vec<TaintEvent> = Vec::new();
    let mut args_modified = false;
    let mut result_modified = false;

    // ----- args -----
    for rule in &route.args {
        let Some(current) = get_dotted(&payload.args, &rule.field).cloned() else {
            continue; // missing field → no pipeline to run
        };
        let eval = evaluate_pipeline(&rule.pipeline, &current, bag, plugins, &rule.field).await;
        taints.extend(eval.taints);
        match eval.outcome {
            FieldOutcome::Pass => {}
            FieldOutcome::Replace(new_val) => {
                if set_dotted(&mut payload.args, &rule.field, new_val) {
                    args_modified = true;
                }
            }
            FieldOutcome::Omit => {
                if remove_dotted(&mut payload.args, &rule.field) {
                    args_modified = true;
                }
            }
            FieldOutcome::Deny { reason, stage_index: _ } => {
                return RouteDecision {
                    decision: Decision::Deny {
                        reason: Some(reason),
                        rule_source: rule.source.clone(),
                    },
                    taints,
                    args_modified,
                    result_modified,
                };
            }
        }
    }

    // ----- policy -----
    match evaluate_steps(&route.policy, bag, pdp, plugins).await {
        Decision::Allow => {}
        deny @ Decision::Deny { .. } => {
            return RouteDecision { decision: deny, taints, args_modified, result_modified };
        }
    }

    // ----- result (only when a response payload is present) -----
    if let Some(result) = payload.result.as_mut() {
        for rule in &route.result {
            let Some(current) = get_dotted(result, &rule.field).cloned() else {
                continue;
            };
            let eval = evaluate_pipeline(&rule.pipeline, &current, bag, plugins, &rule.field).await;
            taints.extend(eval.taints);
            match eval.outcome {
                FieldOutcome::Pass => {}
                FieldOutcome::Replace(new_val) => {
                    if set_dotted(result, &rule.field, new_val) {
                        result_modified = true;
                    }
                }
                FieldOutcome::Omit => {
                    if remove_dotted(result, &rule.field) {
                        result_modified = true;
                    }
                }
                FieldOutcome::Deny { reason, stage_index: _ } => {
                    return RouteDecision {
                        decision: Decision::Deny {
                            reason: Some(reason),
                            rule_source: rule.source.clone(),
                        },
                        taints,
                        args_modified,
                        result_modified,
                    };
                }
            }
        }
    }

    // ----- post_policy -----
    let post_decision = evaluate_steps(&route.post_policy, bag, pdp, plugins).await;

    RouteDecision {
        decision: post_decision,
        taints,
        args_modified,
        result_modified,
    }
}

// =====================================================================
// Dotted-path JSON helpers
// =====================================================================

/// Read `root.a.b.c` from a JSON value via dot-separated path. Returns
/// `None` if any segment is missing or the path crosses a non-object.
fn get_dotted<'a>(root: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut cur = root;
    for seg in path.split('.') {
        cur = cur.get(seg)?;
    }
    Some(cur)
}

/// Write to `root.a.b.c` via dot-separated path. Returns true on success;
/// false if the parent path doesn't exist or doesn't resolve to an object.
/// Does not create missing parent objects — that'd hide schema bugs.
fn set_dotted(root: &mut serde_json::Value, path: &str, value: serde_json::Value) -> bool {
    let parts: Vec<&str> = path.split('.').collect();
    let (leaf, parents) = match parts.split_last() {
        Some(x) => x,
        None => return false,
    };
    let mut cur = root;
    for seg in parents {
        let Some(next) = cur.get_mut(*seg) else { return false; };
        if !next.is_object() { return false; }
        cur = next;
    }
    if let serde_json::Value::Object(map) = cur {
        map.insert((*leaf).to_string(), value);
        true
    } else {
        false
    }
}

/// Remove `root.a.b.c` from a JSON value. Returns true if removal happened.
fn remove_dotted(root: &mut serde_json::Value, path: &str) -> bool {
    let parts: Vec<&str> = path.split('.').collect();
    let (leaf, parents) = match parts.split_last() {
        Some(x) => x,
        None => return false,
    };
    let mut cur = root;
    for seg in parents {
        let Some(next) = cur.get_mut(*seg) else { return false; };
        if !next.is_object() { return false; }
        cur = next;
    }
    if let serde_json::Value::Object(map) = cur {
        map.remove(*leaf).is_some()
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::{FieldRule, Pipeline, Stage, TaintScope, TypeCheck};
    use crate::rules::{Action, Expression, Rule};
    use crate::step::{
        PdpCall, PdpDecision, PdpDialect, PdpError, PluginError, PluginInvocation, PluginOutcome,
        Step,
    };
    use async_trait::async_trait;
    use serde_json::json;

    // ----- Fixtures -----

    struct AllowPdp;
    #[async_trait]
    impl PdpResolver for AllowPdp {
        fn dialect(&self) -> PdpDialect { PdpDialect::Cedar }
        async fn evaluate(
            &self,
            _call: &PdpCall,
            _bag: &AttributeBag,
        ) -> Result<PdpDecision, PdpError> {
            Ok(PdpDecision { decision: Decision::Allow, diagnostics: vec![] })
        }
    }

    struct NoPlugins;
    #[async_trait]
    impl PluginInvoker for NoPlugins {
        async fn invoke(
            &self,
            name: &str,
            _bag: &AttributeBag,
            _invocation: PluginInvocation<'_>,
        ) -> Result<PluginOutcome, PluginError> {
            Err(PluginError::NotFound(name.into()))
        }
    }

    fn field_rule(field: &str, stages: Vec<Stage>) -> FieldRule {
        FieldRule {
            field: field.into(),
            pipeline: Pipeline { stages },
            source: format!("test.{}", field),
        }
    }

    fn deny_rule(source: &str, reason: &str) -> Rule {
        Rule {
            condition: Expression::Always,
            action: Action::Deny { reason: Some(reason.into()) },
            source: source.into(),
        }
    }

    // ----- Tests -----

    #[tokio::test]
    async fn empty_route_allows() {
        let route = CompiledRoute::new("noop");
        let bag = AttributeBag::new();
        let mut payload = RoutePayload::new(json!({}));
        let r = evaluate_route(&route, &bag, &mut payload, &AllowPdp, &NoPlugins).await;
        assert_eq!(r.decision, Decision::Allow);
        assert!(!r.args_modified);
        assert!(!r.result_modified);
        assert!(r.taints.is_empty());
    }

    #[tokio::test]
    async fn args_pipeline_mutates_payload() {
        let mut route = CompiledRoute::new("ping");
        route.args.push(field_rule("ssn", vec![Stage::Mask { keep_last: 4 }]));
        let bag = AttributeBag::new();
        let mut payload = RoutePayload::new(json!({ "ssn": "123-45-6789" }));
        let r = evaluate_route(&route, &bag, &mut payload, &AllowPdp, &NoPlugins).await;
        assert_eq!(r.decision, Decision::Allow);
        assert!(r.args_modified);
        assert_eq!(payload.args["ssn"], json!("*******6789"));
    }

    #[tokio::test]
    async fn args_deny_halts_route() {
        let mut route = CompiledRoute::new("ping");
        route.args.push(field_rule(
            "amount",
            vec![
                Stage::Type(TypeCheck::Int),
                Stage::Range { min: Some(0), max: Some(100) },
            ],
        ));
        // Also has a policy rule that would deny — should NOT be reached
        // (args deny short-circuits). If reached, source would be "policy[0]"
        // instead of the args rule's source.
        route.policy.push(Step::Rule(deny_rule("policy[0]", "policy denied too")));

        let bag = AttributeBag::new();
        let mut payload = RoutePayload::new(json!({ "amount": 200 }));
        let r = evaluate_route(&route, &bag, &mut payload, &AllowPdp, &NoPlugins).await;
        match r.decision {
            Decision::Deny { rule_source, .. } => {
                assert!(rule_source.contains("amount"), "expected args rule source, got {}", rule_source);
            }
            d => panic!("expected Deny from args phase, got {:?}", d),
        }
    }

    #[tokio::test]
    async fn args_missing_field_is_skipped() {
        // Pipeline references `compensation`, payload doesn't have it →
        // missing-field rule is skipped silently, route allows.
        let mut route = CompiledRoute::new("ping");
        route.args.push(field_rule("compensation", vec![Stage::Type(TypeCheck::Int)]));
        let bag = AttributeBag::new();
        let mut payload = RoutePayload::new(json!({ "other_field": 5 }));
        let r = evaluate_route(&route, &bag, &mut payload, &AllowPdp, &NoPlugins).await;
        assert_eq!(r.decision, Decision::Allow);
        assert!(!r.args_modified);
    }

    #[tokio::test]
    async fn args_omit_drops_field() {
        let mut route = CompiledRoute::new("ping");
        route.args.push(field_rule("secret", vec![Stage::Omit]));
        let bag = AttributeBag::new();
        let mut payload = RoutePayload::new(json!({ "secret": "xyz", "keep": 1 }));
        let r = evaluate_route(&route, &bag, &mut payload, &AllowPdp, &NoPlugins).await;
        assert_eq!(r.decision, Decision::Allow);
        assert!(r.args_modified);
        assert!(payload.args.get("secret").is_none());
        assert_eq!(payload.args["keep"], json!(1));
    }

    #[tokio::test]
    async fn policy_deny_halts_before_result() {
        let mut route = CompiledRoute::new("ping");
        route.policy.push(Step::Rule(deny_rule("policy[0]", "blocked")));
        // Result rule should never run.
        route.result.push(field_rule("ssn", vec![Stage::Redact { condition: None }]));

        let bag = AttributeBag::new();
        let mut payload = RoutePayload::with_result(json!({}), json!({ "ssn": "123" }));
        let r = evaluate_route(&route, &bag, &mut payload, &AllowPdp, &NoPlugins).await;
        match r.decision {
            Decision::Deny { rule_source, .. } => assert_eq!(rule_source, "policy[0]"),
            d => panic!("expected policy deny, got {:?}", d),
        }
        assert!(!r.result_modified);
        // Result payload not mutated — redact didn't run.
        assert_eq!(payload.result.as_ref().unwrap()["ssn"], json!("123"));
    }

    #[tokio::test]
    async fn result_phase_skipped_when_no_response() {
        let mut route = CompiledRoute::new("ping");
        route.result.push(field_rule("ssn", vec![Stage::Redact { condition: None }]));
        let bag = AttributeBag::new();
        let mut payload = RoutePayload::new(json!({})); // no result
        let r = evaluate_route(&route, &bag, &mut payload, &AllowPdp, &NoPlugins).await;
        assert_eq!(r.decision, Decision::Allow);
        assert!(!r.result_modified);
    }

    #[tokio::test]
    async fn result_pipeline_redacts_field() {
        let mut route = CompiledRoute::new("ping");
        route.result.push(field_rule("ssn", vec![Stage::Redact { condition: None }]));
        let bag = AttributeBag::new();
        let mut payload = RoutePayload::with_result(
            json!({}),
            json!({ "ssn": "123-45-6789", "name": "alice" }),
        );
        let r = evaluate_route(&route, &bag, &mut payload, &AllowPdp, &NoPlugins).await;
        assert_eq!(r.decision, Decision::Allow);
        assert!(r.result_modified);
        let result = payload.result.as_ref().unwrap();
        assert_eq!(result["ssn"], json!("[REDACTED]"));
        assert_eq!(result["name"], json!("alice"));
    }

    #[tokio::test]
    async fn taints_accumulate_across_phases() {
        let mut route = CompiledRoute::new("ping");
        // args emits a taint
        route.args.push(field_rule(
            "input",
            vec![Stage::Taint { label: "args_seen".into(), scopes: vec![TaintScope::Session] }],
        ));
        // result emits a different taint
        route.result.push(field_rule(
            "output",
            vec![Stage::Taint { label: "result_seen".into(), scopes: vec![TaintScope::Message] }],
        ));
        let bag = AttributeBag::new();
        let mut payload = RoutePayload::with_result(
            json!({ "input": "hello" }),
            json!({ "output": "world" }),
        );
        let r = evaluate_route(&route, &bag, &mut payload, &AllowPdp, &NoPlugins).await;
        assert_eq!(r.decision, Decision::Allow);
        let labels: Vec<&str> = r.taints.iter().map(|t| t.label.as_str()).collect();
        assert_eq!(labels, vec!["args_seen", "result_seen"]);
    }

    #[tokio::test]
    async fn nested_field_path_resolves_and_writes() {
        let mut route = CompiledRoute::new("ping");
        route.args.push(field_rule(
            "user.profile.ssn",
            vec![Stage::Mask { keep_last: 4 }],
        ));
        let bag = AttributeBag::new();
        let mut payload = RoutePayload::new(json!({
            "user": { "profile": { "ssn": "123-45-6789", "name": "alice" } }
        }));
        let r = evaluate_route(&route, &bag, &mut payload, &AllowPdp, &NoPlugins).await;
        assert_eq!(r.decision, Decision::Allow);
        assert!(r.args_modified);
        assert_eq!(payload.args["user"]["profile"]["ssn"], json!("*******6789"));
        assert_eq!(payload.args["user"]["profile"]["name"], json!("alice"));
    }

    #[tokio::test]
    async fn nested_field_missing_intermediate_is_skipped() {
        let mut route = CompiledRoute::new("ping");
        route.args.push(field_rule("user.profile.ssn", vec![Stage::Mask { keep_last: 4 }]));
        let bag = AttributeBag::new();
        // `profile` segment is missing → get_dotted returns None → skip.
        let mut payload = RoutePayload::new(json!({ "user": { "name": "alice" } }));
        let r = evaluate_route(&route, &bag, &mut payload, &AllowPdp, &NoPlugins).await;
        assert_eq!(r.decision, Decision::Allow);
        assert!(!r.args_modified);
    }

    #[tokio::test]
    async fn post_policy_runs_after_result() {
        let mut route = CompiledRoute::new("ping");
        // Result mutates a field, then post_policy denies.
        route.result.push(field_rule("ssn", vec![Stage::Redact { condition: None }]));
        route.post_policy.push(Step::Rule(deny_rule("post_policy[0]", "after-the-fact")));

        let bag = AttributeBag::new();
        let mut payload = RoutePayload::with_result(json!({}), json!({ "ssn": "123" }));
        let r = evaluate_route(&route, &bag, &mut payload, &AllowPdp, &NoPlugins).await;
        match r.decision {
            Decision::Deny { rule_source, .. } => assert_eq!(rule_source, "post_policy[0]"),
            d => panic!("expected post_policy deny, got {:?}", d),
        }
        // Result was still mutated before the post_policy deny fired.
        assert!(r.result_modified);
        assert_eq!(payload.result.as_ref().unwrap()["ssn"], json!("[REDACTED]"));
    }

    // ----- Helper unit tests -----

    #[test]
    fn dotted_get_simple_and_nested() {
        let v = json!({ "a": { "b": { "c": 7 } } });
        assert_eq!(get_dotted(&v, "a.b.c"), Some(&json!(7)));
        assert_eq!(get_dotted(&v, "a.b"), Some(&json!({ "c": 7 })));
        assert!(get_dotted(&v, "a.b.x").is_none());
        assert!(get_dotted(&v, "missing").is_none());
    }

    #[test]
    fn dotted_set_overwrites_leaf() {
        let mut v = json!({ "a": { "b": 1 } });
        assert!(set_dotted(&mut v, "a.b", json!(99)));
        assert_eq!(v["a"]["b"], json!(99));
    }

    #[test]
    fn dotted_set_does_not_create_missing_parents() {
        // Strict: if `a.b` parent doesn't exist, set fails (no auto-vivify).
        let mut v = json!({});
        assert!(!set_dotted(&mut v, "a.b", json!(1)));
        assert_eq!(v, json!({}));
    }

    #[test]
    fn dotted_remove_leaf() {
        let mut v = json!({ "a": { "b": 1, "c": 2 } });
        assert!(remove_dotted(&mut v, "a.b"));
        assert_eq!(v, json!({ "a": { "c": 2 } }));
        // Removing a missing leaf returns false.
        assert!(!remove_dotted(&mut v, "a.b"));
    }
}
