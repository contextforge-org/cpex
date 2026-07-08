// Location: ./crates/apl-core/src/evaluator.rs
// Copyright 2026
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

use std::sync::Arc;

use crate::attributes::{AttributeBag, AttributeValue};
use crate::pipeline::{Pipeline, ScanKind, Stage, TaintEvent, TaintScope, TypeCheck};
use crate::rules::{CompareOp, Condition, Effect, Expression, Literal, Rule};
use crate::step::{PdpResolver, PluginInvocation, PluginInvoker};

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
/// - First `deny` halts; subsequent rules / effects don't run.
/// - `allow` effects *do not* short-circuit — evaluation continues to
///   the next effect (then to the next rule).
/// - If no rule denies, the phase resolves to `Decision::Allow`.
///
/// Sync fast path — only handles control effects (`Allow` / `Deny`).
/// Rules containing `Plugin` / `Delegate` / `Taint` effects must go
/// through [`evaluate_steps`] instead, which has the async invoker
/// traits wired up. This function silently skips non-control effects
/// so a rule list mixed with `Plugin` still terminates cleanly on a
/// later `Deny` — but the side effects don't fire. Caller's job to
/// pick the right entry point for the effects in the rules.
pub fn evaluate_rules(rules: &[Rule], bag: &AttributeBag) -> Decision {
    for rule in rules {
        if !eval_expression(&rule.condition, bag) {
            continue;
        }
        for effect in &rule.effects {
            match effect {
                Effect::Allow => continue,
                Effect::Deny { reason, code } => {
                    // `code` override on the effect takes precedence
                    // over the auto-generated rule source position,
                    // so author-stable categories survive YAML edits.
                    let rule_source = code.clone().unwrap_or_else(|| rule.source.clone());
                    return Decision::Deny {
                        reason: reason.clone(),
                        rule_source,
                    };
                },
                // Plugin / Delegate / Taint require the async step
                // path; ignore here. See doc comment above.
                _ => continue,
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
        // An unresolvable interpolated path (a missing request value) is
        // treated as an absent key: `IsTrue`/`Exists`/`Comparison` are
        // false, but `IsFalse` is true (absent is falsy — keeps
        // `require(...)` fail-closed when the keyed lookup can't resolve).
        Condition::IsTrue { key } => bag
            .resolve_key(key)
            .map(|k| bag.get_bool(&k).unwrap_or(false))
            .unwrap_or(false),
        Condition::IsFalse { key } => bag
            .resolve_key(key)
            .map(|k| !bag.get_bool(&k).unwrap_or(false))
            .unwrap_or(true),
        Condition::Exists { key } => bag
            .resolve_key(key)
            .map(|k| bag.contains(&k))
            .unwrap_or(false),
        Condition::Comparison { key, op, value } => match bag.resolve_key(key) {
            Some(k) => eval_comparison(&k, *op, value, bag),
            None => false,
        },
        Condition::InSet {
            value_key,
            set_key,
            negate,
        } => {
            let in_set = match bag.resolve_key(value_key).zip(bag.resolve_key(set_key)) {
                Some((vk, sk)) => match (bag.get_string(&vk), bag.get_string_set(&sk)) {
                    (Some(s), Some(set)) => set.contains(s),
                    _ => false, // missing key or wrong type → not in set
                },
                None => false, // an interpolated key didn't resolve
            };
            if *negate {
                !in_set
            } else {
                in_set
            }
        },
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
        },
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
// Async effect evaluator (policy: / post_policy: walks Vec<Effect>)
// =====================================================================

/// Walk an Effect list against the bag, dispatching PDP calls via `pdp`
/// and plugin invocations via `plugins`. Returns the phase's overall
/// decision.
///
/// Semantics (DSL §3, §7.5):
/// - `Effect::When` — evaluate the condition; if true, run the body in
///   order with the same first-deny-wins logic.
/// - `Effect::Pdp` — call resolver; on Allow run `on_allow` reactions and
///   continue; on Deny run `on_deny` reactions and return the deny
///   (reactions can override with their own deny, but cannot turn a deny
///   into an allow).
/// - `Effect::Plugin` — invoke; Allow continues, Deny returns.
/// - `Effect::Delegate` — mint downstream credential; writes
///   `delegation.granted.*` keys back into the bag; deny-on-failure unless
///   the step's `on_error` overrides.
/// - `Effect::Taint` — record the label; never halts.
/// - `Effect::FieldOp` — apply a pipe chain to `args.X` / `result.X`;
///   may set `args_modified` / `result_modified`.
/// - `Effect::Sequential` — run children in order, halt on first Deny.
/// - `Effect::Parallel` — run children concurrently, abort on first Deny.
/// - `Effect::Allow` — explicit no-op; continues the phase.
/// - `Effect::Deny` — halt with the supplied reason/code.
///
/// PDP / plugin errors map to a Deny with the error in the reason, per
/// the design's fail-closed default (DSL §8.9). Pre-E4 `evaluate_steps`
/// is preserved as a deprecated alias that forwards here.
#[allow(clippy::too_many_arguments)]
pub async fn evaluate_effects(
    effects: &[Effect],
    bag: &mut AttributeBag,
    pdp: &Arc<dyn PdpResolver>,
    plugins: &Arc<dyn PluginInvoker>,
    delegations: &Arc<dyn crate::step::DelegationInvoker>,
    phase: crate::step::DispatchPhase,
    payload: &mut crate::route::RoutePayload,
) -> StepsEvaluation {
    let mut taints: Vec<crate::pipeline::TaintEvent> = Vec::new();
    let mut constraints: Vec<crate::constraint::CandidateConstraint> = Vec::new();
    let mut args_modified = false;
    let mut result_modified = false;
    for effect in effects {
        // Each top-level effect runs against the shared mutable state.
        // `Effect::When` / `Effect::Pdp` handle their own internal
        // walking via dispatch_effect's recursive call.
        let fallback_source = match effect {
            Effect::When { source, .. } => source.as_str(),
            _ => "",
        };
        match Box::pin(dispatch_effect(
            effect,
            fallback_source,
            bag,
            pdp,
            plugins,
            delegations,
            phase,
            &mut taints,
            &mut constraints,
            &mut args_modified,
            &mut result_modified,
            payload,
        ))
        .await
        {
            EffectOutcome::Continue => {},
            EffectOutcome::Halt(decision) => {
                return StepsEvaluation::deny(
                    decision,
                    taints,
                    constraints,
                    args_modified,
                    result_modified,
                );
            },
        }
    }
    StepsEvaluation {
        decision: Decision::Allow,
        taints,
        constraints,
        args_modified,
        result_modified,
    }
}

/// Outcome of `evaluate_effects`: the phase's decision plus taints emitted
/// by any plugin steps that ran. Taints are accumulated even when the
/// phase ultimately denies — audit needs to see what the plugins
/// reported before the deny landed. Empty `taints` is the common case
/// (most steps are predicates / PDP calls, not label emitters).
///
/// `args_modified` / `result_modified` are set when an `Effect::FieldOp`
/// inside a `do:` body successfully mutated the route payload — the
/// orchestrator uses them to OR-into the route-level "did anything
/// change" signals so the host knows to re-serialize the body.
#[derive(Debug, Clone)]
pub struct StepsEvaluation {
    pub decision: Decision,
    pub taints: Vec<crate::pipeline::TaintEvent>,
    /// Backend candidate constraints emitted by any `restrict` effects
    /// that ran. Accumulated even when the phase ultimately denies (same
    /// discipline as `taints`). Empty in the common case — most phases
    /// have no `restrict`. A higher layer (apl-cpex) folds these into a
    /// single `CandidateConstraintExtension` for the host's router.
    pub constraints: Vec<crate::constraint::CandidateConstraint>,
    pub args_modified: bool,
    pub result_modified: bool,
}

impl StepsEvaluation {
    fn deny(
        d: Decision,
        taints: Vec<crate::pipeline::TaintEvent>,
        constraints: Vec<crate::constraint::CandidateConstraint>,
        args_modified: bool,
        result_modified: bool,
    ) -> Self {
        Self {
            decision: d,
            taints,
            constraints,
            args_modified,
            result_modified,
        }
    }
}

/// Outcome of dispatching one effect. Internal control-flow signal —
/// never serialized, never exposed in the IR. Sits between the per-
/// effect dispatch (When / Pdp / Plugin / Delegate / Taint / Allow /
/// Deny / FieldOp / Sequential / Parallel) and the caller's "do I keep
/// walking the effects list or halt?" loop.
enum EffectOutcome {
    /// Effect completed without producing a Deny — caller moves on to
    /// the next effect in the surrounding list.
    Continue,
    /// Effect produced a Deny decision — caller halts the rest of the
    /// surrounding list, the rest of the phase, and the route.
    Halt(Decision),
}

/// Run a single effect against the evaluator's state. Called by both
/// `evaluate_effects` (top-level walk of `policy:` / `post_policy:`)
/// and by recursive arms (Sequential, Parallel, When body, Pdp
/// reactions), so there's exactly one place that knows how each
/// effect kind dispatches.
///
/// `fallback_source` is the rule-source-position string used as the
/// `rule_source` field on a `Decision::Deny` when the effect itself
/// doesn't carry an explicit code (i.e. `Effect::Deny { code: None }`,
/// or a deny coming back from a plugin / delegator without overriding
/// the default).
#[allow(clippy::too_many_arguments)]
async fn dispatch_effect(
    effect: &Effect,
    fallback_source: &str,
    bag: &mut AttributeBag,
    pdp: &Arc<dyn PdpResolver>,
    plugins: &Arc<dyn PluginInvoker>,
    delegations: &Arc<dyn crate::step::DelegationInvoker>,
    phase: crate::step::DispatchPhase,
    taints: &mut Vec<crate::pipeline::TaintEvent>,
    constraints: &mut Vec<crate::constraint::CandidateConstraint>,
    args_modified: &mut bool,
    result_modified: &mut bool,
    payload: &mut crate::route::RoutePayload,
) -> EffectOutcome {
    match effect {
        Effect::Allow => EffectOutcome::Continue,

        Effect::Deny { reason, code } => {
            // Author-supplied code overrides the auto-generated source
            // position. Lets MCP clients dispatch on stable categories
            // (`quota.exceeded`) rather than positional codes that
            // shift with YAML edits.
            let rule_source = code.clone().unwrap_or_else(|| fallback_source.to_string());
            EffectOutcome::Halt(Decision::Deny {
                reason: reason.clone(),
                rule_source,
            })
        },

        Effect::Plugin { name } => {
            match plugins
                .invoke(name, bag, PluginInvocation::Step { phase })
                .await
            {
                Ok(outcome) => {
                    // Plugins can emit taints regardless of decision —
                    // collect first, then act on the decision.
                    taints.extend(outcome.taints);
                    match outcome.decision {
                        Decision::Allow => EffectOutcome::Continue,
                        deny @ Decision::Deny { .. } => EffectOutcome::Halt(deny),
                    }
                },
                Err(e) => EffectOutcome::Halt(Decision::Deny {
                    reason: Some(format!("plugin `{}` error: {}", name, e)),
                    rule_source: format!("plugin:{}", name),
                }),
            }
        },

        Effect::Delegate(delegate_step) => {
            match delegations.delegate(delegate_step).await {
                Ok(outcome) => match &outcome.decision {
                    Decision::Allow => {
                        // Surface granted_* keys into the bag so
                        // downstream rules in this same step list can
                        // read them (`require(delegation.granted.permissions
                        // contains "X")`, etc.).
                        use crate::attributes::AttributeValue;
                        use crate::step::delegation_bag_keys as bk;

                        bag.set(bk::GRANTED, AttributeValue::Bool(true));
                        if !outcome.granted_permissions.is_empty() {
                            let set: std::collections::HashSet<String> =
                                outcome.granted_permissions.iter().cloned().collect();
                            bag.set(bk::GRANTED_PERMISSIONS, AttributeValue::StringSet(set));
                        }
                        if let Some(aud) = &outcome.granted_audience {
                            bag.set(bk::GRANTED_AUDIENCE, aud.clone());
                        }
                        if let Some(exp) = &outcome.granted_expires_at {
                            bag.set(bk::GRANTED_EXPIRES_AT, exp.clone());
                        }
                        EffectOutcome::Continue
                    },
                    Decision::Deny { .. } => {
                        // Apply the step's on_error policy. Default
                        // ("deny") halts; "continue" lets the pipeline
                        // keep going so subsequent rules can branch on
                        // the absent `delegation.granted` flag.
                        let on_error = delegate_step
                            .on_error
                            .as_deref()
                            .unwrap_or("deny")
                            .to_ascii_lowercase();
                        if on_error == "continue" {
                            EffectOutcome::Continue
                        } else {
                            EffectOutcome::Halt(outcome.decision)
                        }
                    },
                },
                Err(e) => {
                    // Transport / lookup failure. on_error treats this
                    // the same way as a plugin-side deny.
                    let on_error = delegate_step
                        .on_error
                        .as_deref()
                        .unwrap_or("deny")
                        .to_ascii_lowercase();
                    if on_error == "continue" {
                        EffectOutcome::Continue
                    } else {
                        EffectOutcome::Halt(Decision::Deny {
                            reason: Some(format!(
                                "delegate `{}` error: {}",
                                delegate_step.plugin_name, e
                            )),
                            rule_source: delegate_step.source.clone(),
                        })
                    }
                },
            }
        },

        Effect::Taint { label, scopes } => {
            // Emit the taint into the phase's accumulator so it flows
            // into `RouteDecision.taints`. Apl-cpex's invoker handles
            // the session-store persistence side at request end — here
            // we only record the event. Scopes come straight from the
            // parser (`taint(label, session, message)` syntax).
            taints.push(crate::pipeline::TaintEvent {
                label: label.clone(),
                scopes: scopes.clone(),
            });
            EffectOutcome::Continue
        },

        Effect::Restrict { spec } => {
            // Resolve any `data.*` field references against this request's
            // bag (design §4.3), then accumulate the literal constraint —
            // same discipline as `Taint`: never halts, always continues.
            // An all-empty result is dropped (the parser rejects a literal
            // empty `restrict:`, but a reference that resolves to nothing
            // could still leave every field unset). Folding / intersection
            // of the accumulated constraints happens at the bridge
            // (apl-cpex → `CandidateConstraintExtension`).
            let constraint = spec.resolve(bag);
            if !constraint.is_empty() {
                constraints.push(constraint);
            }
            EffectOutcome::Continue
        },

        Effect::FieldOp { path, stages } => {
            dispatch_field_op(
                path,
                stages,
                fallback_source,
                bag,
                plugins,
                phase,
                taints,
                args_modified,
                result_modified,
                payload,
            )
            .await
        },

        Effect::Sequential(effects) => {
            // Semantically the same as inlining the list into the
            // enclosing scope — walk in order, stop on first Halt.
            // The variant exists for explicit grouping and to pair
            // with `Parallel` in the IR.
            for inner in effects {
                match Box::pin(dispatch_effect(
                    inner,
                    fallback_source,
                    bag,
                    pdp,
                    plugins,
                    delegations,
                    phase,
                    taints,
                    constraints,
                    args_modified,
                    result_modified,
                    payload,
                ))
                .await
                {
                    EffectOutcome::Continue => continue,
                    halt @ EffectOutcome::Halt(_) => return halt,
                }
            }
            EffectOutcome::Continue
        },

        Effect::Parallel(effects) => {
            // `dispatch_parallel` returns an explicit `BoxFuture<'_, _>`
            // (Send by construction) so the recursive
            // dispatch_effect → dispatch_parallel → dispatch_effect
            // chain doesn't trip the compiler's Send-inference cycle.
            dispatch_parallel(
                effects,
                fallback_source,
                bag,
                pdp,
                plugins,
                delegations,
                phase,
                taints,
                constraints,
                payload,
            )
            .await
        },

        Effect::When {
            condition,
            body,
            source,
        } => {
            // Predicate-gated body — replaces the historical
            // `Step::Rule`. Skip silently when the condition is false;
            // otherwise walk the body in order and halt on first Deny.
            if !eval_expression(condition, bag) {
                return EffectOutcome::Continue;
            }
            for inner in body {
                match Box::pin(dispatch_effect(
                    inner,
                    source,
                    bag,
                    pdp,
                    plugins,
                    delegations,
                    phase,
                    taints,
                    constraints,
                    args_modified,
                    result_modified,
                    payload,
                ))
                .await
                {
                    EffectOutcome::Continue => continue,
                    halt @ EffectOutcome::Halt(_) => return halt,
                }
            }
            EffectOutcome::Continue
        },

        Effect::Pdp {
            call,
            on_allow,
            on_deny,
        } => {
            // External PDP call — replaces `Step::Pdp`. Reactions run
            // through the same dispatch_effect path (recursively).
            match pdp.evaluate(call, bag).await {
                Ok(pdp_result) => match pdp_result.decision {
                    Decision::Allow => {
                        // Walk on_allow; if it ends without a Halt the
                        // PDP allow stands and we continue.
                        for inner in on_allow {
                            match Box::pin(dispatch_effect(
                                inner,
                                fallback_source,
                                bag,
                                pdp,
                                plugins,
                                delegations,
                                phase,
                                taints,
                                constraints,
                                args_modified,
                                result_modified,
                                payload,
                            ))
                            .await
                            {
                                EffectOutcome::Continue => continue,
                                halt @ EffectOutcome::Halt(_) => return halt,
                            }
                        }
                        EffectOutcome::Continue
                    },
                    deny @ Decision::Deny { .. } => {
                        // Reactions can override the PDP's deny reason
                        // (e.g. `on_deny: [deny "..."]`) but cannot
                        // upgrade the deny to allow — if reactions
                        // walked clean, the PDP's original deny stands.
                        for inner in on_deny {
                            if let EffectOutcome::Halt(reaction_decision) =
                                Box::pin(dispatch_effect(
                                    inner,
                                    fallback_source,
                                    bag,
                                    pdp,
                                    plugins,
                                    delegations,
                                    phase,
                                    taints,
                                    constraints,
                                    args_modified,
                                    result_modified,
                                    payload,
                                ))
                                .await
                            {
                                return EffectOutcome::Halt(reaction_decision);
                            }
                        }
                        EffectOutcome::Halt(deny)
                    },
                },
                Err(e) => EffectOutcome::Halt(Decision::Deny {
                    reason: Some(format!("PDP error: {}", e)),
                    rule_source: format!("pdp:{:?}", call.dialect),
                }),
            }
        },
    }
}

/// Run a list of effects concurrently. Each branch gets its own
/// cloned bag and payload — mutations inside a branch don't
/// propagate back to the shared outer state. Taints from every
/// branch are merged into the outer `taints` vec (taints are
/// append-only event logs, safe to concatenate). First Halt by
/// branch index wins; the remaining branches are aborted via
/// `cpex_orchestration::run_branches`'s `short_circuit_on_deny`.
///
/// Config-load already rejected `FieldOp` / `Delegate` here via
/// [`Effect::validate_parallel_purity`], so at runtime we trust the
/// IR not to contain mutation effects.
///
/// # Concurrency model (E3.2)
///
/// Built on [`cpex_orchestration::run_branches`] — the same JoinSet
/// + abort-on-deny primitive `cpex-core`'s executor uses for its
/// concurrent phase. Each branch is `tokio::spawn`ed onto the
/// runtime, so branches get true OS-thread parallelism (vs. the v1
/// implementation's `join_all`, which only interleaved on one
/// task). To meet the `'static + Send` bounds for spawning, the
/// invoker references are `&Arc<dyn ...>` — we `Arc::clone` an
/// owned reference into each branch closure.
///
/// Note: no per-branch timeout. The DSL doesn't expose one, and
/// plugin-level timeouts upstream of this call (in cpex-core's
/// executor) bound individual plugin invocations. If a route ever
/// needs a per-branch budget the orchestration crate already
/// supports `BranchConfig::timeout_per_branch` — wire it through a
/// `Effect::Parallel` extension if/when needed.
// Returns an explicit `BoxFuture` rather than `impl Future` so the
// caller (`dispatch_effect`'s `Effect::Parallel` arm, which is itself
// `async fn`) can break the Send-inference cycle this would otherwise
// introduce: dispatch_effect's opaque return type would depend on
// dispatch_parallel's, and dispatch_parallel spawns futures that
// recursively re-enter dispatch_effect. A concrete `BoxFuture` is
// `Pin<Box<dyn Future + Send + 'a>>` — already Send by construction,
// no inference required.
fn dispatch_parallel<'a>(
    effects: &'a [Effect],
    fallback_source: &'a str,
    bag: &'a AttributeBag,
    pdp: &'a Arc<dyn PdpResolver>,
    plugins: &'a Arc<dyn PluginInvoker>,
    delegations: &'a Arc<dyn crate::step::DelegationInvoker>,
    phase: crate::step::DispatchPhase,
    taints: &'a mut Vec<crate::pipeline::TaintEvent>,
    constraints: &'a mut Vec<crate::constraint::CandidateConstraint>,
    payload: &'a crate::route::RoutePayload,
) -> futures::future::BoxFuture<'a, EffectOutcome> {
    Box::pin(async move {
        use cpex_orchestration::{run_branches, BranchConfig, BranchOutcome, ErasedBranch};

        if effects.is_empty() {
            return EffectOutcome::Continue;
        }

        // Build one spawn-ready branch future per effect. Each branch
        // owns:
        //   * a cloned bag and payload — branch mutations stay local;
        //   * cloned Arcs to the invokers — `'static + Send`, ready for
        //     `tokio::spawn`;
        //   * an owned copy of the effect to evaluate (clone is cheap
        //     for the variants `Parallel` can hold: Allow, Deny, Plugin,
        //     Taint, Sequential, Parallel, When, Pdp).
        type BranchResult = (
            EffectOutcome,
            Vec<crate::pipeline::TaintEvent>,
            Vec<crate::constraint::CandidateConstraint>,
        );
        let mut branches: Vec<ErasedBranch<BranchResult>> = Vec::with_capacity(effects.len());
        for effect in effects.iter() {
            let effect = effect.clone();
            let fallback = fallback_source.to_string();
            let mut branch_bag = bag.clone();
            let mut branch_payload = payload.clone();
            let pdp = Arc::clone(pdp);
            let plugins = Arc::clone(plugins);
            let delegations = Arc::clone(delegations);
            branches.push(Box::pin(async move {
                let mut branch_taints: Vec<crate::pipeline::TaintEvent> = Vec::new();
                let mut branch_constraints: Vec<crate::constraint::CandidateConstraint> =
                    Vec::new();
                let mut branch_args_modified = false;
                let mut branch_result_modified = false;
                let outcome = Box::pin(dispatch_effect(
                    &effect,
                    &fallback,
                    &mut branch_bag,
                    &pdp,
                    &plugins,
                    &delegations,
                    phase,
                    &mut branch_taints,
                    &mut branch_constraints,
                    &mut branch_args_modified,
                    &mut branch_result_modified,
                    &mut branch_payload,
                ))
                .await;
                (outcome, branch_taints, branch_constraints)
            }));
        }

        // `is_deny` short-circuits the moment any branch returns
        // `EffectOutcome::Halt(_)`. The remaining branches get
        // `BranchOutcome::Aborted` and we drop their (already-cancelled)
        // futures. Taints from already-completed branches still land.
        let cfg = BranchConfig {
            timeout_per_branch: None,
            short_circuit_on_deny: true,
        };
        let outcomes = run_branches(branches, cfg, |v: &BranchResult| {
            matches!(v.0, EffectOutcome::Halt(_))
        })
        .await;

        // Aggregate in input order: append every branch's taints; pick
        // the first Halt (by branch index, not wall-clock order) as the
        // overall result. Aborted / panicked branches contribute no
        // taints — they didn't run to completion. A panicked branch is
        // *not* converted into a Halt; we log via `tracing::warn!` and
        // continue. (A misbehaving plugin shouldn't take down the
        // parallel block any more than it would the host process.)
        let mut first_halt: Option<Decision> = None;
        for (idx, outcome) in outcomes.into_iter().enumerate() {
            match outcome {
                BranchOutcome::Completed((effect_outcome, branch_taints, branch_constraints)) => {
                    // Branch state merges back append-only, same as taints:
                    // each branch's `restrict`-emitted constraints land in
                    // the outer accumulator (they intersect at fold time,
                    // so order-independent — safe to concatenate).
                    taints.extend(branch_taints);
                    constraints.extend(branch_constraints);
                    if first_halt.is_none() {
                        if let EffectOutcome::Halt(d) = effect_outcome {
                            first_halt = Some(d);
                        }
                    }
                },
                BranchOutcome::Aborted => {
                    // Short-circuit cancelled this branch — intentional,
                    // no diagnostic needed.
                },
                BranchOutcome::TimedOut => {
                    // Unreachable today (no per-branch timeout
                    // configured). Treat as a no-op if it ever fires
                    // post-config-extension.
                },
                BranchOutcome::Panicked(msg) => {
                    // A panicking branch is a misbehaving plugin/effect;
                    // dropping its output (no Halt, no taints) keeps the
                    // parallel block's other branches intact rather than
                    // taking the whole block down. apl-core has no
                    // tracing dep — host integrations that care can
                    // surface the panic via cpex-core's plugin error
                    // path. `idx`/`msg` are eaten here.
                    let _ = (idx, msg);
                },
            }
        }

        match first_halt {
            Some(d) => EffectOutcome::Halt(d),
            None => EffectOutcome::Continue,
        }
    })
}

/// Apply a `FieldOp` effect — resolve the path in args/result, run
/// the pipeline stages, write the outcome back into the payload.
///
/// Out-of-phase ops are silent no-ops: a Pre-phase rule with
/// `result.X | redact` skips because the result hasn't been produced
/// yet; a Post-phase rule with `args.X | redact` skips because the
/// args were already sent on the wire. This is intentional so the
/// same `when:`/`do:` rule body can be reused across phases without
/// the author needing to branch on phase.
///
/// Missing fields skip silently too (same as the args:/result: phase
/// pipelines) — a pipeline can't transform what isn't there. If the
/// author needs presence semantics, that's a `require(exists(args.X))`
/// upstream of the `do:` body.
#[allow(clippy::too_many_arguments)]
async fn dispatch_field_op(
    path: &str,
    stages: &[crate::pipeline::Stage],
    fallback_source: &str,
    bag: &mut AttributeBag,
    plugins: &Arc<dyn PluginInvoker>,
    phase: crate::step::DispatchPhase,
    taints: &mut Vec<crate::pipeline::TaintEvent>,
    args_modified: &mut bool,
    result_modified: &mut bool,
    payload: &mut crate::route::RoutePayload,
) -> EffectOutcome {
    use crate::route::{get_dotted, remove_dotted, set_dotted};
    use crate::step::DispatchPhase;

    // Pick the right side of the payload based on the path prefix.
    // Out-of-phase ops drop silently (see the doc comment).
    enum Side {
        Args,
        Result,
    }
    let (root, subpath, side) = if let Some(rest) = path.strip_prefix("args.") {
        if !matches!(phase, DispatchPhase::Pre) {
            return EffectOutcome::Continue;
        }
        (&mut payload.args, rest, Side::Args)
    } else if let Some(rest) = path.strip_prefix("result.") {
        if !matches!(phase, DispatchPhase::Post) {
            return EffectOutcome::Continue;
        }
        let Some(result) = payload.result.as_mut() else {
            return EffectOutcome::Continue;
        };
        (result, rest, Side::Result)
    } else {
        return EffectOutcome::Halt(Decision::Deny {
            reason: Some(format!(
                "FieldOp path `{}` must start with `args.` or `result.`",
                path
            )),
            rule_source: fallback_source.to_string(),
        });
    };

    let Some(current) = get_dotted(root, subpath).cloned() else {
        return EffectOutcome::Continue; // missing field → silent no-op
    };

    let pipeline = crate::pipeline::Pipeline {
        stages: stages.to_vec(),
    };
    let eval = evaluate_pipeline(&pipeline, &current, bag, plugins, path, phase).await;
    taints.extend(eval.taints);
    let mark_modified = |side: Side, args: &mut bool, result: &mut bool| match side {
        Side::Args => *args = true,
        Side::Result => *result = true,
    };
    match eval.outcome {
        FieldOutcome::Pass => EffectOutcome::Continue,
        FieldOutcome::Replace(new_val) => {
            if set_dotted(root, subpath, new_val) {
                mark_modified(side, args_modified, result_modified);
            }
            EffectOutcome::Continue
        },
        FieldOutcome::Omit => {
            if remove_dotted(root, subpath) {
                mark_modified(side, args_modified, result_modified);
            }
            EffectOutcome::Continue
        },
        FieldOutcome::Deny {
            reason,
            stage_index: _,
        } => EffectOutcome::Halt(Decision::Deny {
            reason: Some(reason),
            rule_source: fallback_source.to_string(),
        }),
    }
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
    plugins: &Arc<dyn PluginInvoker>,
    field_name: &str,
    phase: crate::step::DispatchPhase,
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
            },
            Stage::Length { min, max } => {
                let Some(s) = current.as_str() else {
                    return PipelineEvaluation {
                        outcome: FieldOutcome::Deny {
                            reason: format!(
                                "len(...) requires string value, got {}",
                                value_kind(&current)
                            ),
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
            },
            Stage::Range { min, max } => {
                let Some(n) = current.as_i64() else {
                    return PipelineEvaluation {
                        outcome: FieldOutcome::Deny {
                            reason: format!(
                                "range requires integer value, got {}",
                                value_kind(&current)
                            ),
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
            },
            Stage::Enum { values } => {
                let Some(s) = current.as_str() else {
                    return PipelineEvaluation {
                        outcome: FieldOutcome::Deny {
                            reason: format!(
                                "enum(...) requires string value, got {}",
                                value_kind(&current)
                            ),
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
            },
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
                    },
                };
                let Some(s) = current.as_str() else {
                    return PipelineEvaluation {
                        outcome: FieldOutcome::Deny {
                            reason: format!(
                                "regex requires string value, got {}",
                                value_kind(&current)
                            ),
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
            },
            Stage::Validate { name } => {
                // Named-validator dispatch is not implemented in this
                // build. The parser rejects `validate(...)` at compile
                // time (parser.rs); this branch covers IR built
                // programmatically bypassing the parser. Same shape
                // as the parser's diagnostic — operators reach for
                // `regex(...)` or `plugin(...)` instead.
                return PipelineEvaluation {
                    outcome: FieldOutcome::Deny {
                        reason: format!(
                            "`validate({})` is not implemented; use `regex(...)` \
                             or `plugin({})` instead",
                            name, name,
                        ),
                        stage_index: idx,
                    },
                    taints,
                };
            },

            // ----- Transforms -----
            Stage::Mask { keep_last } => {
                let Some(s) = current.as_str() else {
                    return PipelineEvaluation {
                        outcome: FieldOutcome::Deny {
                            reason: format!(
                                "mask(...) requires string value, got {}",
                                value_kind(&current)
                            ),
                            stage_index: idx,
                        },
                        taints,
                    };
                };
                let chars: Vec<char> = s.chars().collect();
                let keep = (*keep_last).min(chars.len());
                let mask_count = chars.len() - keep;
                let masked: String = std::iter::repeat('*')
                    .take(mask_count)
                    .chain(chars.into_iter().skip(mask_count))
                    .collect();
                current = serde_json::Value::String(masked);
                replaced = true;
            },
            Stage::Redact { condition } => {
                let should_redact = match condition {
                    None => true,
                    Some(expr) => eval_expression(expr, bag),
                };
                if should_redact {
                    current = serde_json::Value::String("[REDACTED]".into());
                    replaced = true;
                }
            },
            Stage::Omit => {
                return PipelineEvaluation {
                    outcome: FieldOutcome::Omit,
                    taints,
                };
            },
            Stage::Hash => {
                // Simple deterministic digest — DefaultHasher is fine for
                // de-identification (not for cryptographic use).
                use std::hash::{Hash, Hasher};
                let mut h = std::collections::hash_map::DefaultHasher::new();
                value_for_hash(&current).hash(&mut h);
                current = serde_json::Value::String(format!("hash:{:016x}", h.finish()));
                replaced = true;
            },

            // ----- Effects -----
            Stage::Taint { label, scopes } => {
                taints.push(TaintEvent {
                    label: label.clone(),
                    scopes: scopes.clone(),
                });
            },
            Stage::Plugin { name } => {
                let invocation = PluginInvocation::Field {
                    name: field_name,
                    value: &current,
                    phase,
                };
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
                            },
                            Decision::Deny {
                                reason,
                                rule_source: _,
                            } => {
                                return PipelineEvaluation {
                                    outcome: FieldOutcome::Deny {
                                        reason: reason
                                            .unwrap_or_else(|| format!("plugin `{}` denied", name)),
                                        stage_index: idx,
                                    },
                                    taints,
                                };
                            },
                        }
                    },
                    Err(e) => {
                        // Fail-closed: plugin dispatch failure halts the pipeline.
                        return PipelineEvaluation {
                            outcome: FieldOutcome::Deny {
                                reason: format!("plugin `{}` error: {}", name, e),
                                stage_index: idx,
                            },
                            taints,
                        };
                    },
                }
            },
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
            },
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
        TypeCheck::Email => v
            .as_str()
            .map_or(false, |s| s.contains('@') && s.contains('.')),
        TypeCheck::Url => v.as_str().map_or(false, |s| {
            s.starts_with("http://") || s.starts_with("https://")
        }),
        TypeCheck::Uuid => v.as_str().map_or(false, is_uuid_shape),
    }
}

fn is_uuid_shape(s: &str) -> bool {
    // 8-4-4-4-12 hex with `-` separators.
    let bytes = s.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (i, &b) in bytes.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if b != b'-' {
                    return false;
                }
            },
            _ => {
                if !b.is_ascii_hexdigit() {
                    return false;
                }
            },
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
    use crate::rules::{Condition, Expression, Rule};
    use crate::step::{DelegationInvoker, NoopDelegationInvoker};
    use std::collections::HashSet;
    use std::sync::Arc;

    fn rule(condition: Expression, effect: Effect, source: &str) -> Rule {
        Rule::single(condition, effect, source)
    }

    // Wrap stateless test invokers in `Arc<dyn ...>` once per call. The
    // public evaluator API takes `&Arc<dyn PluginInvoker>` so internal
    // dispatch (notably `Effect::Parallel`) can `Arc::clone` an owned,
    // 'static reference into each spawned branch (slice E3.2).
    fn null_pipe_plugins() -> Arc<dyn PluginInvoker> {
        Arc::new(NullPipelinePlugins)
    }
    fn null_plugins() -> Arc<dyn PluginInvoker> {
        Arc::new(NullPlugins)
    }
    fn noop_delegations() -> Arc<dyn DelegationInvoker> {
        Arc::new(NoopDelegationInvoker)
    }

    fn deny(reason: &str) -> Effect {
        Effect::Deny {
            reason: Some(reason.into()),
            code: None,
        }
    }

    fn cond(c: Condition) -> Expression {
        Expression::Condition(c)
    }

    // ----- R3b: data.* path interpolation -----

    /// Parse a predicate and evaluate it against `bag`.
    fn eval_pred(src: &str, bag: &AttributeBag) -> bool {
        let expr = crate::parser::parse_predicate(src).expect("parse predicate");
        eval_expression(&expr, bag)
    }

    fn eu_tenant_bag() -> AttributeBag {
        let mut bag = AttributeBag::new();
        bag.set("subject.tenant", "acme-eu");
        bag.set("data.tenants.acme-eu.data_region", "eu");
        bag.set("data.tenants.acme-us.data_region", "us");
        bag.set("data.org.default_region", "us");
        bag
    }

    #[test]
    fn interpolation_resolves_request_value_into_path() {
        let bag = eu_tenant_bag();
        // subject.tenant = acme-eu → data.tenants.acme-eu.data_region = eu.
        assert!(eval_pred(
            "data.tenants[subject.tenant].data_region == 'eu'",
            &bag
        ));
        assert!(!eval_pred(
            "data.tenants[subject.tenant].data_region == 'us'",
            &bag
        ));
    }

    #[test]
    fn interpolation_picks_up_different_request_value() {
        let mut bag = eu_tenant_bag();
        bag.set("subject.tenant", "acme-us"); // now resolves to the US row
        assert!(eval_pred(
            "data.tenants[subject.tenant].data_region == 'us'",
            &bag
        ));
    }

    #[test]
    fn missing_inner_key_makes_comparison_false() {
        let mut bag = eu_tenant_bag();
        // Drop the request value the bracket indexes on.
        bag = {
            let mut b = AttributeBag::new();
            for (k, v) in bag.iter() {
                if k != "subject.tenant" {
                    b.set(k, v.clone());
                }
            }
            b
        };
        assert!(!eval_pred(
            "data.tenants[subject.tenant].data_region == 'eu'",
            &bag
        ));
    }

    #[test]
    fn missing_inner_key_keeps_require_fail_closed() {
        // `require(X)` desugars to IsFalse(X); an unresolvable path is
        // absent → falsy → IsFalse true → the require denies.
        let bag = AttributeBag::new(); // no subject.tenant, no data.*
        let expr =
            crate::parser::parse_predicate("data.tenants[subject.tenant].data_region").unwrap();
        // Bare identifier predicate is IsTrue → false when unresolvable.
        assert!(!eval_expression(&expr, &bag));
    }

    #[test]
    fn interpolation_works_with_contains_on_a_set() {
        let mut bag = AttributeBag::new();
        bag.set("subject.id", "support-bot");
        bag.set(
            "data.agents.support-bot.allowed_models",
            std::collections::HashSet::from(["vllm/*".to_string(), "anthropic/*".to_string()]),
        );
        assert!(eval_pred(
            "data.agents[subject.id].allowed_models contains 'vllm/*'",
            &bag
        ));
        assert!(!eval_pred(
            "data.agents[subject.id].allowed_models contains 'openai/*'",
            &bag
        ));
    }

    #[test]
    fn numeric_request_value_coerces_into_path() {
        let mut bag = AttributeBag::new();
        bag.set("subject.tier", 2i64);
        bag.set("data.limits.2.max_cost", "cheap");
        assert!(eval_pred("data.limits[subject.tier].max_cost == 'cheap'", &bag));
    }

    #[test]
    fn non_interpolated_keys_still_work() {
        let bag = eu_tenant_bag();
        assert!(eval_pred("data.org.default_region == 'us'", &bag));
        assert!(eval_pred("subject.tenant == 'acme-eu'", &bag));
    }

    // ----- Decision-level semantics -----

    #[test]
    fn empty_rules_allow() {
        let mut bag = AttributeBag::new();
        assert_eq!(evaluate_rules(&[], &bag), Decision::Allow);
    }

    #[test]
    fn first_deny_halts() {
        let mut bag = AttributeBag::new();
        bag.set("a", true);
        bag.set("b", true);

        let rules = vec![
            rule(
                cond(Condition::IsTrue { key: "a".into() }),
                deny("first"),
                "r0",
            ),
            rule(
                cond(Condition::IsTrue { key: "b".into() }),
                deny("second"),
                "r1",
            ),
        ];

        match evaluate_rules(&rules, &bag) {
            Decision::Deny {
                reason,
                rule_source,
            } => {
                assert_eq!(reason.as_deref(), Some("first"));
                assert_eq!(rule_source, "r0");
            },
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
            rule(
                cond(Condition::IsTrue { key: "ok".into() }),
                Effect::Allow,
                "r0_allow",
            ),
            rule(
                cond(Condition::IsTrue { key: "bad".into() }),
                deny("later"),
                "r1_deny",
            ),
        ];

        match evaluate_rules(&rules, &bag) {
            Decision::Deny { rule_source, .. } => assert_eq!(rule_source, "r1_deny"),
            d => panic!("allow short-circuited; expected later deny, got {:?}", d),
        }
    }

    #[test]
    fn unmatched_rules_dont_fire() {
        let mut bag = AttributeBag::new(); // "denied" missing → false
        let rules = vec![rule(
            cond(Condition::IsTrue {
                key: "denied".into(),
            }),
            deny("shouldn't fire"),
            "r0",
        )];
        assert_eq!(evaluate_rules(&rules, &bag), Decision::Allow);
    }

    // ----- Predicate semantics -----

    #[test]
    fn missing_key_is_false() {
        let mut bag = AttributeBag::new();
        assert!(!eval_condition(
            &Condition::IsTrue {
                key: "missing".into()
            },
            &bag
        ));
        assert!(eval_condition(
            &Condition::IsFalse {
                key: "missing".into()
            },
            &bag
        ));
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

        assert!(eval_expression(
            &Expression::And(vec![a.clone(), a.clone()]),
            &bag
        ));
        assert!(!eval_expression(
            &Expression::And(vec![a.clone(), b.clone()]),
            &bag
        ));
        assert!(eval_expression(
            &Expression::Or(vec![a.clone(), b.clone()]),
            &bag
        ));
        assert!(!eval_expression(
            &Expression::Or(vec![b.clone(), b.clone()]),
            &bag
        ));
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
                    cond(Condition::IsFalse {
                        key: "role.hr".into(),
                    }),
                    cond(Condition::IsFalse {
                        key: "role.finance".into(),
                    }),
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
                    cond(Condition::IsTrue {
                        key: "include_ssn".into(),
                    }),
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
        evaluate_pipeline(
            p,
            v,
            bag,
            &null_pipe_plugins(),
            "test_field",
            crate::step::DispatchPhase::Pre,
        )
        .await
        .outcome
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
            panic!(
                "NullPipelinePlugins should not dispatch; got plugin({})",
                name
            );
        }
    }

    #[tokio::test]
    async fn pipeline_empty_is_pass() {
        let mut bag = AttributeBag::new();
        let p = make_pipeline(vec![]);
        assert_eq!(
            run_pipeline(&p, &json!("anything"), &bag).await,
            FieldOutcome::Pass
        );
    }

    #[tokio::test]
    async fn pipeline_type_check_passes_and_denies() {
        let mut bag = AttributeBag::new();
        let p = make_pipeline(vec![Stage::Type(TypeCheck::Str)]);
        assert_eq!(
            run_pipeline(&p, &json!("hello"), &bag).await,
            FieldOutcome::Pass
        );
        match run_pipeline(&p, &json!(42), &bag).await {
            FieldOutcome::Deny {
                reason,
                stage_index,
            } => {
                assert!(reason.contains("expected Str"));
                assert_eq!(stage_index, 0);
            },
            other => panic!("expected Deny, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn pipeline_mask_preserves_last_n() {
        let mut bag = AttributeBag::new();
        let p = make_pipeline(vec![Stage::Mask { keep_last: 4 }]);
        match run_pipeline(&p, &json!("123-45-6789"), &bag).await {
            FieldOutcome::Replace(v) => assert_eq!(v, json!("*******6789")),
            other => panic!("expected Replace, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn pipeline_mask_handles_short_strings() {
        let mut bag = AttributeBag::new();
        let p = make_pipeline(vec![Stage::Mask { keep_last: 4 }]);
        // keep_last >= length → no mask chars; full string preserved.
        match run_pipeline(&p, &json!("ab"), &bag).await {
            FieldOutcome::Replace(v) => assert_eq!(v, json!("ab")),
            other => panic!("expected Replace, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn pipeline_unconditional_redact() {
        let mut bag = AttributeBag::new();
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
        let mut bag = AttributeBag::new();
        let cond = Expression::Not(Box::new(Expression::Condition(Condition::IsTrue {
            key: "perm.view_ssn".into(),
        })));
        let p = make_pipeline(vec![Stage::Redact {
            condition: Some(cond),
        }]);
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
        let p = make_pipeline(vec![Stage::Redact {
            condition: Some(cond),
        }]);
        // perm.view_ssn=true → !true=false → redact skipped → Pass.
        assert_eq!(
            run_pipeline(&p, &json!("123-45-6789"), &bag).await,
            FieldOutcome::Pass,
        );
    }

    #[tokio::test]
    async fn pipeline_omit_short_circuits() {
        let mut bag = AttributeBag::new();
        let p = make_pipeline(vec![
            Stage::Omit,
            // This stage should never run.
            Stage::Type(TypeCheck::Int),
        ]);
        assert_eq!(
            run_pipeline(&p, &json!("anything"), &bag).await,
            FieldOutcome::Omit
        );
    }

    #[tokio::test]
    async fn pipeline_range_validator() {
        let mut bag = AttributeBag::new();
        let p = make_pipeline(vec![
            Stage::Type(TypeCheck::Int),
            Stage::Range {
                min: Some(0),
                max: Some(1_000_000),
            },
        ]);
        assert_eq!(
            run_pipeline(&p, &json!(500_000), &bag).await,
            FieldOutcome::Pass
        );
        // Above max → deny.
        match run_pipeline(&p, &json!(2_000_000), &bag).await {
            FieldOutcome::Deny {
                reason,
                stage_index,
            } => {
                assert!(reason.contains("outside"));
                assert_eq!(stage_index, 1);
            },
            other => panic!("expected Deny, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn pipeline_length_validator() {
        let mut bag = AttributeBag::new();
        let p = make_pipeline(vec![Stage::Length {
            min: None,
            max: Some(5),
        }]);
        assert_eq!(
            run_pipeline(&p, &json!("hi"), &bag).await,
            FieldOutcome::Pass
        );
        assert!(matches!(
            run_pipeline(&p, &json!("too long"), &bag).await,
            FieldOutcome::Deny { .. },
        ));
    }

    #[tokio::test]
    async fn pipeline_enum_validator() {
        let mut bag = AttributeBag::new();
        let p = make_pipeline(vec![Stage::Enum {
            values: vec!["low".into(), "medium".into(), "high".into()],
        }]);
        assert_eq!(
            run_pipeline(&p, &json!("medium"), &bag).await,
            FieldOutcome::Pass
        );
        assert!(matches!(
            run_pipeline(&p, &json!("extreme"), &bag).await,
            FieldOutcome::Deny { .. },
        ));
    }

    #[tokio::test]
    async fn pipeline_uuid_validator() {
        let mut bag = AttributeBag::new();
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
        let mut bag = AttributeBag::new();
        let p = make_pipeline(vec![Stage::Hash]);
        match run_pipeline(&p, &json!("secret"), &bag).await {
            FieldOutcome::Replace(v) => {
                let s = v.as_str().unwrap();
                assert!(s.starts_with("hash:"));
                assert_eq!(s.len(), "hash:".len() + 16);
            },
            other => panic!("expected Replace, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn pipeline_validate_named_denies_at_runtime() {
        // `validate(name)` is unimplemented in this build. The parser
        // rejects it at compile time; this test exercises the runtime
        // defense-in-depth path for IR built programmatically. The
        // deny message points operators at the working alternatives
        // (`regex(...)` / `plugin(...)`).
        let mut bag = AttributeBag::new();
        let p = make_pipeline(vec![
            Stage::Type(TypeCheck::Str),
            Stage::Validate {
                name: "ssn_format".into(),
            },
            Stage::Mask { keep_last: 4 },
        ]);
        match run_pipeline(&p, &json!("123-45-6789"), &bag).await {
            FieldOutcome::Deny {
                reason,
                stage_index,
            } => {
                assert_eq!(stage_index, 1, "validate stage is at index 1");
                assert!(
                    reason.contains("not implemented"),
                    "deny reason should explain that validate is unimplemented: {reason}",
                );
                assert!(
                    reason.contains("regex") || reason.contains("plugin"),
                    "deny reason should point at alternatives: {reason}",
                );
            },
            other => panic!("expected Deny on validate(...) stage, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn pipeline_validator_short_circuits_before_transform() {
        // If the validator fails, the transform never runs.
        let mut bag = AttributeBag::new();
        let p = make_pipeline(vec![
            Stage::Type(TypeCheck::Int), // will fail on a string
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
        let mut bag = AttributeBag::new();
        let p = make_pipeline(vec![Stage::Regex {
            pattern: r"^\d{3}-\d{2}-\d{4}$".into(),
        }]);
        assert_eq!(
            run_pipeline(&p, &json!("123-45-6789"), &bag).await,
            FieldOutcome::Pass
        );
    }

    #[tokio::test]
    async fn pipeline_regex_no_match_denies() {
        let mut bag = AttributeBag::new();
        let p = make_pipeline(vec![Stage::Regex {
            pattern: r"^\d{3}-\d{2}-\d{4}$".into(),
        }]);
        match run_pipeline(&p, &json!("not an ssn"), &bag).await {
            FieldOutcome::Deny {
                reason,
                stage_index,
            } => {
                assert!(reason.contains("did not match"));
                assert_eq!(stage_index, 0);
            },
            other => panic!("expected Deny, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn pipeline_regex_invalid_pattern_denies() {
        let mut bag = AttributeBag::new();
        let p = make_pipeline(vec![Stage::Regex {
            pattern: "(unclosed".into(),
        }]);
        match run_pipeline(&p, &json!("anything"), &bag).await {
            FieldOutcome::Deny { reason, .. } => {
                assert!(reason.contains("invalid regex"));
            },
            other => panic!("expected Deny, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn pipeline_regex_non_string_denies() {
        let mut bag = AttributeBag::new();
        let p = make_pipeline(vec![Stage::Regex {
            pattern: r"^\d+$".into(),
        }]);
        match run_pipeline(&p, &json!(42), &bag).await {
            FieldOutcome::Deny { reason, .. } => {
                assert!(reason.contains("requires string"));
            },
            other => panic!("expected Deny on non-string regex input, got {:?}", other),
        }
    }

    // ----- Taint and Scan stages -----

    #[tokio::test]
    async fn pipeline_taint_records_event() {
        let mut bag = AttributeBag::new();
        let p = make_pipeline(vec![
            Stage::Type(TypeCheck::Str),
            Stage::Taint {
                label: "PII".into(),
                scopes: vec![TaintScope::Session],
            },
            Stage::Mask { keep_last: 4 },
        ]);
        let result = evaluate_pipeline(
            &p,
            &json!("123-45-6789"),
            &bag,
            &null_pipe_plugins(),
            "test_field",
            crate::step::DispatchPhase::Pre,
        )
        .await;
        assert_eq!(result.outcome, FieldOutcome::Replace(json!("*******6789")));
        assert_eq!(
            result.taints,
            vec![TaintEvent {
                label: "PII".into(),
                scopes: vec![TaintScope::Session],
            }]
        );
    }

    #[tokio::test]
    async fn pipeline_scan_pii_detect_emits_taint() {
        let mut bag = AttributeBag::new();
        let p = make_pipeline(vec![Stage::Scan {
            kind: ScanKind::PiiDetect,
        }]);
        let result = evaluate_pipeline(
            &p,
            &json!("some text"),
            &bag,
            &null_pipe_plugins(),
            "test_field",
            crate::step::DispatchPhase::Pre,
        )
        .await;
        // PII detect: value unchanged, one taint event emitted.
        assert_eq!(result.outcome, FieldOutcome::Pass);
        assert_eq!(
            result.taints,
            vec![TaintEvent {
                label: "PII".into(),
                scopes: vec![TaintScope::Session],
            }]
        );
    }

    #[tokio::test]
    async fn pipeline_scan_pii_redact_replaces_and_taints() {
        let mut bag = AttributeBag::new();
        let p = make_pipeline(vec![Stage::Scan {
            kind: ScanKind::PiiRedact,
        }]);
        let result = evaluate_pipeline(
            &p,
            &json!("123-45-6789"),
            &bag,
            &null_pipe_plugins(),
            "test_field",
            crate::step::DispatchPhase::Pre,
        )
        .await;
        assert_eq!(result.outcome, FieldOutcome::Replace(json!("[REDACTED]")));
        assert_eq!(result.taints.len(), 1);
        assert_eq!(result.taints[0].label, "PII");
    }

    #[tokio::test]
    async fn pipeline_scan_injection_emits_injection_taint() {
        let mut bag = AttributeBag::new();
        let p = make_pipeline(vec![Stage::Scan {
            kind: ScanKind::InjectionScan,
        }]);
        let result = evaluate_pipeline(
            &p,
            &json!("user input"),
            &bag,
            &null_pipe_plugins(),
            "test_field",
            crate::step::DispatchPhase::Pre,
        )
        .await;
        assert_eq!(result.outcome, FieldOutcome::Pass);
        assert_eq!(result.taints[0].label, "injection");
    }

    #[tokio::test]
    async fn pipeline_deny_does_not_accumulate_later_taints() {
        // Pipeline halts at the first failing validator; taints emitted
        // before the failure stick, taints after do not.
        let mut bag = AttributeBag::new();
        let p = make_pipeline(vec![
            Stage::Taint {
                label: "before".into(),
                scopes: vec![TaintScope::Session],
            },
            Stage::Type(TypeCheck::Int), // fails on string input
            Stage::Taint {
                label: "after".into(),
                scopes: vec![TaintScope::Session],
            },
        ]);
        let result = evaluate_pipeline(
            &p,
            &json!("hello"),
            &bag,
            &null_pipe_plugins(),
            "test_field",
            crate::step::DispatchPhase::Pre,
        )
        .await;
        assert!(matches!(result.outcome, FieldOutcome::Deny { .. }));
        assert_eq!(
            result.taints,
            vec![TaintEvent {
                label: "before".into(),
                scopes: vec![TaintScope::Session],
            }]
        );
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
        let mut bag = AttributeBag::new();
        let plugins: std::sync::Arc<dyn PluginInvoker> = std::sync::Arc::new(PipePlugin {
            outcomes: std::collections::HashMap::from([(
                "noop".to_string(),
                PluginOutcome::allow(),
            )]),
        });
        let p = make_pipeline(vec![
            Stage::Type(TypeCheck::Str),
            Stage::Plugin {
                name: "noop".into(),
            },
            Stage::Mask { keep_last: 4 },
        ]);
        let result = evaluate_pipeline(
            &p,
            &json!("123-45-6789"),
            &bag,
            &plugins,
            "compensation",
            crate::step::DispatchPhase::Pre,
        )
        .await;
        assert_eq!(result.outcome, FieldOutcome::Replace(json!("*******6789")));
        assert!(result.taints.is_empty());
    }

    #[tokio::test]
    async fn pipeline_plugin_can_replace_value() {
        let mut bag = AttributeBag::new();
        let plugins: std::sync::Arc<dyn PluginInvoker> = std::sync::Arc::new(PipePlugin {
            outcomes: std::collections::HashMap::from([(
                "scrubber".to_string(),
                PluginOutcome {
                    decision: Decision::Allow,
                    taints: vec![TaintEvent {
                        label: "PII".to_string(),
                        scopes: vec![TaintScope::Session],
                    }],
                    modified_value: Some(json!("***scrubbed***")),
                },
            )]),
        });
        let p = make_pipeline(vec![Stage::Plugin {
            name: "scrubber".into(),
        }]);
        let result = evaluate_pipeline(
            &p,
            &json!("sensitive data"),
            &bag,
            &plugins,
            "notes",
            crate::step::DispatchPhase::Pre,
        )
        .await;
        assert_eq!(
            result.outcome,
            FieldOutcome::Replace(json!("***scrubbed***"))
        );
        assert_eq!(
            result.taints,
            vec![TaintEvent {
                label: "PII".into(),
                scopes: vec![TaintScope::Session],
            }]
        );
    }

    #[tokio::test]
    async fn pipeline_plugin_deny_halts() {
        let mut bag = AttributeBag::new();
        let plugins: std::sync::Arc<dyn PluginInvoker> = std::sync::Arc::new(PipePlugin {
            outcomes: std::collections::HashMap::from([(
                "guard".to_string(),
                PluginOutcome {
                    decision: Decision::Deny {
                        reason: Some("policy violation".into()),
                        rule_source: "guard".into(),
                    },
                    taints: vec![],
                    modified_value: None,
                },
            )]),
        });
        let p = make_pipeline(vec![
            Stage::Plugin {
                name: "guard".into(),
            },
            // Should never run.
            Stage::Mask { keep_last: 4 },
        ]);
        let result = evaluate_pipeline(
            &p,
            &json!("data"),
            &bag,
            &plugins,
            "payload",
            crate::step::DispatchPhase::Pre,
        )
        .await;
        match result.outcome {
            FieldOutcome::Deny {
                reason,
                stage_index,
            } => {
                assert_eq!(reason, "policy violation");
                assert_eq!(stage_index, 0);
            },
            other => panic!("expected Deny, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn pipeline_plugin_missing_fails_closed() {
        let mut bag = AttributeBag::new();
        let plugins: std::sync::Arc<dyn PluginInvoker> = std::sync::Arc::new(PipePlugin {
            outcomes: Default::default(),
        });
        let p = make_pipeline(vec![Stage::Plugin {
            name: "missing".into(),
        }]);
        let result = evaluate_pipeline(
            &p,
            &json!("data"),
            &bag,
            &plugins,
            "payload",
            crate::step::DispatchPhase::Pre,
        )
        .await;
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
        assert!(!eval_condition(
            &Condition::IsTrue {
                key: "args.flag".into()
            },
            &bag
        ));
        assert!(eval_condition(
            &Condition::Exists {
                key: "args.flag".into()
            },
            &bag
        ));
        // Missing key — Exists is false.
        assert!(!eval_condition(
            &Condition::Exists {
                key: "args.nonexistent".into()
            },
            &bag
        ));
    }

    #[test]
    fn in_set_member_and_non_member() {
        let mut bag = AttributeBag::new();
        bag.set("subject.type", "user");
        bag.set(
            "allowed_types",
            std::collections::HashSet::from(["user".to_string(), "service".to_string()]),
        );

        assert!(eval_condition(
            &Condition::InSet {
                value_key: "subject.type".into(),
                set_key: "allowed_types".into(),
                negate: false,
            },
            &bag
        ));

        bag.set("subject.type", "agent");
        assert!(!eval_condition(
            &Condition::InSet {
                value_key: "subject.type".into(),
                set_key: "allowed_types".into(),
                negate: false,
            },
            &bag
        ));
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
        assert!(eval_condition(
            &Condition::InSet {
                value_key: "subject.type".into(),
                set_key: "blocked_types".into(),
                negate: true,
            },
            &bag
        ));
    }

    #[test]
    fn in_set_missing_keys_resolve_to_false() {
        let mut bag = AttributeBag::new();
        // Both missing → in = false → not in = true (spec §2.6 missing→false
        // applies to the underlying `in` lookup; negate flips it).
        assert!(!eval_condition(
            &Condition::InSet {
                value_key: "x".into(),
                set_key: "y".into(),
                negate: false,
            },
            &bag
        ));
        assert!(eval_condition(
            &Condition::InSet {
                value_key: "x".into(),
                set_key: "y".into(),
                negate: true,
            },
            &bag
        ));
    }

    #[test]
    fn always_evaluates_true() {
        let mut bag = AttributeBag::new();
        assert!(eval_expression(&Expression::Always, &bag));
    }

    #[test]
    fn always_rule_unconditional_deny() {
        let mut bag = AttributeBag::new();
        let r = Rule {
            condition: Expression::Always,
            effects: vec![Effect::Deny {
                reason: Some("unconditional".into()),
                code: None,
            }],
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
        PluginInvoker, PluginOutcome,
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
        fn dialect(&self) -> PdpDialect {
            PdpDialect::Cedar
        }
        async fn evaluate(
            &self,
            _call: &PdpCall,
            _bag: &AttributeBag,
        ) -> Result<PdpDecision, PdpError> {
            Ok(PdpDecision {
                decision: self.decision.clone(),
                diagnostics: vec![],
            })
        }
    }

    /// PDP resolver that returns an error — exercises fail-closed path.
    struct ErroringPdp;
    #[async_trait]
    impl PdpResolver for ErroringPdp {
        fn dialect(&self) -> PdpDialect {
            PdpDialect::Cedar
        }
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

    fn pdp_step(decision_diagnostic_label: &str) -> Effect {
        Effect::Pdp {
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
        let mut bag = AttributeBag::new();
        let steps = vec![Effect::When {
            condition: Expression::Always,
            body: vec![Effect::Allow],
            source: "test".into(),
        }];
        let r = evaluate_effects(
            &steps,
            &mut bag,
            &(Arc::new(FakePdp {
                decision: Decision::Allow,
            }) as Arc<dyn PdpResolver>),
            &null_plugins(),
            &noop_delegations(),
            crate::step::DispatchPhase::Pre,
            &mut crate::route::RoutePayload::new(serde_json::Value::Null),
        )
        .await;
        assert_eq!(r.decision, Decision::Allow);
    }

    #[tokio::test]
    async fn pdp_allow_continues() {
        let mut bag = AttributeBag::new();
        let steps = vec![pdp_step("dummy")];
        let pdp: Arc<dyn PdpResolver> = Arc::new(FakePdp {
            decision: Decision::Allow,
        });
        assert_eq!(
            evaluate_effects(
                &steps,
                &mut bag,
                &pdp,
                &null_plugins(),
                &noop_delegations(),
                crate::step::DispatchPhase::Pre,
                &mut crate::route::RoutePayload::new(serde_json::Value::Null)
            )
            .await
            .decision,
            Decision::Allow,
        );
    }

    #[tokio::test]
    async fn pdp_deny_returns_deny() {
        let mut bag = AttributeBag::new();
        let steps = vec![pdp_step("dummy")];
        let pdp: Arc<dyn PdpResolver> = Arc::new(FakePdp {
            decision: Decision::Deny {
                reason: Some("forbidden".into()),
                rule_source: "pdp".into(),
            },
        });
        match evaluate_effects(
            &steps,
            &mut bag,
            &pdp,
            &null_plugins(),
            &noop_delegations(),
            crate::step::DispatchPhase::Pre,
            &mut crate::route::RoutePayload::new(serde_json::Value::Null),
        )
        .await
        .decision
        {
            Decision::Deny { reason, .. } => assert_eq!(reason.as_deref(), Some("forbidden")),
            d => panic!("expected Deny, got {:?}", d),
        }
    }

    #[tokio::test]
    async fn pdp_on_deny_reaction_can_override_reason() {
        // PDP denies, on_deny reaction includes a more specific deny rule that
        // fires before the PDP's deny is returned.
        let mut bag = AttributeBag::new();
        let steps = vec![Effect::Pdp {
            call: PdpCall {
                dialect: PdpDialect::Cedar,
                args: serde_yaml::Value::Null,
            },
            on_deny: vec![Effect::When {
                condition: Expression::Always,
                body: vec![Effect::Deny {
                    reason: Some("reaction took over".into()),
                    code: None,
                }],
                source: "on_deny[0]".into(),
            }],
            on_allow: vec![],
        }];
        let pdp: Arc<dyn PdpResolver> = Arc::new(FakePdp {
            decision: Decision::Deny {
                reason: Some("pdp original".into()),
                rule_source: "p".into(),
            },
        });
        match evaluate_effects(
            &steps,
            &mut bag,
            &pdp,
            &null_plugins(),
            &noop_delegations(),
            crate::step::DispatchPhase::Pre,
            &mut crate::route::RoutePayload::new(serde_json::Value::Null),
        )
        .await
        .decision
        {
            Decision::Deny {
                reason,
                rule_source,
            } => {
                assert_eq!(reason.as_deref(), Some("reaction took over"));
                assert_eq!(rule_source, "on_deny[0]");
            },
            d => panic!("expected Deny, got {:?}", d),
        }
    }

    #[tokio::test]
    async fn pdp_on_allow_can_deny() {
        // PDP allows, but an on_allow reaction can still deny (e.g., a
        // taint check that fails). Outcome: deny.
        let mut bag = AttributeBag::new();
        let steps = vec![Effect::Pdp {
            call: PdpCall {
                dialect: PdpDialect::Cedar,
                args: serde_yaml::Value::Null,
            },
            on_deny: vec![],
            on_allow: vec![Effect::When {
                condition: Expression::Always,
                body: vec![Effect::Deny {
                    reason: Some("reaction veto".into()),
                    code: None,
                }],
                source: "on_allow[0]".into(),
            }],
        }];
        let pdp: Arc<dyn PdpResolver> = Arc::new(FakePdp {
            decision: Decision::Allow,
        });
        match evaluate_effects(
            &steps,
            &mut bag,
            &pdp,
            &null_plugins(),
            &noop_delegations(),
            crate::step::DispatchPhase::Pre,
            &mut crate::route::RoutePayload::new(serde_json::Value::Null),
        )
        .await
        .decision
        {
            Decision::Deny { reason, .. } => assert_eq!(reason.as_deref(), Some("reaction veto")),
            d => panic!("expected Deny, got {:?}", d),
        }
    }

    #[tokio::test]
    async fn pdp_error_is_fail_closed() {
        let mut bag = AttributeBag::new();
        let steps = vec![pdp_step("dummy")];
        match evaluate_effects(
            &steps,
            &mut bag,
            &(Arc::new(ErroringPdp) as Arc<dyn PdpResolver>),
            &null_plugins(),
            &noop_delegations(),
            crate::step::DispatchPhase::Pre,
            &mut crate::route::RoutePayload::new(serde_json::Value::Null),
        )
        .await
        .decision
        {
            Decision::Deny { reason, .. } => {
                assert!(reason.unwrap().contains("PDP error"));
            },
            d => panic!("expected Deny on PDP error, got {:?}", d),
        }
    }

    #[tokio::test]
    async fn plugin_allow_continues_deny_halts() {
        let mut bag = AttributeBag::new();
        let plugins: std::sync::Arc<dyn PluginInvoker> = std::sync::Arc::new(FakePlugin {
            decisions: std::collections::HashMap::from([
                ("ok_plugin".to_string(), Decision::Allow),
                (
                    "blocking_plugin".to_string(),
                    Decision::Deny {
                        reason: Some("rate limit hit".into()),
                        rule_source: "plugin".into(),
                    },
                ),
            ]),
        });

        let allow_only = vec![Effect::Plugin {
            name: "ok_plugin".into(),
        }];
        assert_eq!(
            evaluate_effects(
                &allow_only,
                &mut bag,
                &(Arc::new(FakePdp {
                    decision: Decision::Allow
                }) as Arc<dyn PdpResolver>),
                &plugins,
                &noop_delegations(),
                crate::step::DispatchPhase::Pre,
                &mut crate::route::RoutePayload::new(serde_json::Value::Null)
            )
            .await
            .decision,
            Decision::Allow,
        );

        let with_deny = vec![
            Effect::Plugin {
                name: "ok_plugin".into(),
            },
            Effect::Plugin {
                name: "blocking_plugin".into(),
            },
        ];
        match evaluate_effects(
            &with_deny,
            &mut bag,
            &(Arc::new(FakePdp {
                decision: Decision::Allow,
            }) as Arc<dyn PdpResolver>),
            &plugins,
            &noop_delegations(),
            crate::step::DispatchPhase::Pre,
            &mut crate::route::RoutePayload::new(serde_json::Value::Null),
        )
        .await
        .decision
        {
            Decision::Deny { reason, .. } => assert_eq!(reason.as_deref(), Some("rate limit hit")),
            d => panic!("expected Deny from blocking_plugin, got {:?}", d),
        }
    }

    #[tokio::test]
    async fn plugin_error_is_fail_closed() {
        let mut bag = AttributeBag::new();
        let plugins: std::sync::Arc<dyn PluginInvoker> = std::sync::Arc::new(FakePlugin {
            decisions: Default::default(),
        });
        let steps = vec![Effect::Plugin {
            name: "missing".into(),
        }];
        match evaluate_effects(
            &steps,
            &mut bag,
            &(Arc::new(FakePdp {
                decision: Decision::Allow,
            }) as Arc<dyn PdpResolver>),
            &plugins,
            &noop_delegations(),
            crate::step::DispatchPhase::Pre,
            &mut crate::route::RoutePayload::new(serde_json::Value::Null),
        )
        .await
        .decision
        {
            Decision::Deny {
                reason,
                rule_source,
            } => {
                assert!(reason.unwrap().contains("missing"));
                assert!(rule_source.contains("missing"));
            },
            d => panic!("expected Deny, got {:?}", d),
        }
    }

    #[tokio::test]
    async fn taint_step_always_continues_and_accumulates() {
        let mut bag = AttributeBag::new();
        let steps = vec![
            Effect::Taint {
                label: "PII".into(),
                scopes: vec![crate::pipeline::TaintScope::Session],
            },
            // A later rule should still fire — taint doesn't short-circuit.
            Effect::When {
                condition: Expression::Always,
                body: vec![Effect::Deny {
                    reason: Some("after taint".into()),
                    code: None,
                }],
                source: "p[1]".into(),
            },
        ];
        let eval = evaluate_effects(
            &steps,
            &mut bag,
            &(Arc::new(FakePdp {
                decision: Decision::Allow,
            }) as Arc<dyn PdpResolver>),
            &null_plugins(),
            &noop_delegations(),
            crate::step::DispatchPhase::Pre,
            &mut crate::route::RoutePayload::new(serde_json::Value::Null),
        )
        .await;
        match eval.decision {
            Decision::Deny { reason, .. } => assert_eq!(reason.as_deref(), Some("after taint")),
            d => panic!("expected Deny from rule after Taint, got {:?}", d),
        }
        // Step::Taint should have been accumulated into the phase's taints
        // before the deny landed — audit needs to see what tainted before
        // the policy halted.
        assert_eq!(eval.taints.len(), 1);
        assert_eq!(eval.taints[0].label, "PII");
        assert_eq!(
            eval.taints[0].scopes,
            vec![crate::pipeline::TaintScope::Session]
        );
    }

    // ----- R1: restrict effect accumulation -----

    fn restrict_regions(regions: &[&str]) -> Effect {
        use crate::constraint::{RestrictSpec, StringSetSpec};
        Effect::Restrict {
            spec: RestrictSpec {
                allow_regions: Some(StringSetSpec::Literal(
                    regions.iter().map(|s| s.to_string()).collect(),
                )),
                ..Default::default()
            },
        }
    }

    async fn eval(effects: &[Effect], bag: &mut AttributeBag) -> StepsEvaluation {
        evaluate_effects(
            effects,
            bag,
            &(Arc::new(FakePdp {
                decision: Decision::Allow,
            }) as Arc<dyn PdpResolver>),
            &null_plugins(),
            &noop_delegations(),
            crate::step::DispatchPhase::Pre,
            &mut crate::route::RoutePayload::new(serde_json::Value::Null),
        )
        .await
    }

    #[tokio::test]
    async fn restrict_accumulates_and_continues() {
        // `restrict` never halts; a later rule still runs, and the
        // constraint lands in `constraints`.
        let mut bag = AttributeBag::new();
        let effects = vec![restrict_regions(&["eu"]), Effect::Allow];
        let e = eval(&effects, &mut bag).await;
        assert_eq!(e.decision, Decision::Allow);
        assert_eq!(e.constraints.len(), 1);
        assert_eq!(
            e.constraints[0].allow_regions.as_deref(),
            Some(&["eu".to_string()][..])
        );
    }

    #[tokio::test]
    async fn restrict_accumulates_even_when_phase_denies() {
        // Same discipline as taint — a constraint emitted before a deny
        // still surfaces (audit / the host may still want it).
        let mut bag = AttributeBag::new();
        let effects = vec![
            restrict_regions(&["eu"]),
            Effect::Deny {
                reason: Some("later".into()),
                code: None,
            },
        ];
        let e = eval(&effects, &mut bag).await;
        assert!(matches!(e.decision, Decision::Deny { .. }));
        assert_eq!(e.constraints.len(), 1);
    }

    #[tokio::test]
    async fn restrict_gated_by_when_only_fires_when_true() {
        // The composition-layer gate: constraint emits only if `when` holds.
        let gated = |key: &str| Effect::When {
            condition: Expression::Condition(Condition::IsTrue { key: key.into() }),
            body: vec![restrict_regions(&["eu"])],
            source: "p[0]".into(),
        };

        let mut off = AttributeBag::new();
        assert!(eval(&[gated("eu_resident")], &mut off).await.constraints.is_empty());

        let mut on = AttributeBag::new();
        on.set("eu_resident", true);
        assert_eq!(eval(&[gated("eu_resident")], &mut on).await.constraints.len(), 1);
    }

    #[tokio::test]
    async fn restrict_inside_parallel_merges_back() {
        // A `restrict` in one parallel branch merges into the outer
        // accumulator, alongside a sibling branch's work.
        let mut bag = AttributeBag::new();
        let effects = vec![Effect::Parallel(vec![
            Effect::Allow,
            restrict_regions(&["eu"]),
        ])];
        let e = eval(&effects, &mut bag).await;
        assert_eq!(e.decision, Decision::Allow);
        assert_eq!(e.constraints.len(), 1);
        assert_eq!(
            e.constraints[0].allow_regions.as_deref(),
            Some(&["eu".to_string()][..])
        );
    }

    fn restrict_allow_models_ref(path: &str) -> Effect {
        use crate::constraint::{RestrictSpec, StringSetSpec};
        Effect::Restrict {
            spec: RestrictSpec {
                allow_models: Some(StringSetSpec::Ref(path.to_string())),
                ..Default::default()
            },
        }
    }

    #[tokio::test]
    async fn restrict_ref_resolves_from_data_tree() {
        // A `data.*` reference resolves the caller's allow-list from the
        // static tree at eval time — one rule, per-caller value.
        let mut bag = AttributeBag::new();
        bag.set("subject.id", "support-bot");
        bag.set(
            "data.agents.support-bot.allowed_models",
            std::collections::HashSet::from(["vllm/*".to_string(), "anthropic/*".to_string()]),
        );
        let effects = vec![restrict_allow_models_ref("data.agents[subject.id].allowed_models")];
        let e = eval(&effects, &mut bag).await;
        assert_eq!(e.constraints.len(), 1);
        // Resolved to the tree's set (sorted).
        assert_eq!(
            e.constraints[0].allow_models.as_deref(),
            Some(&["anthropic/*".to_string(), "vllm/*".to_string()][..])
        );
    }

    #[tokio::test]
    async fn restrict_ref_picks_up_different_caller() {
        let mut bag = AttributeBag::new();
        bag.set("subject.id", "research-bot");
        bag.set(
            "data.agents.research-bot.allowed_models",
            std::collections::HashSet::from(["openai/*".to_string()]),
        );
        let effects = vec![restrict_allow_models_ref("data.agents[subject.id].allowed_models")];
        let e = eval(&effects, &mut bag).await;
        assert_eq!(
            e.constraints[0].allow_models.as_deref(),
            Some(&["openai/*".to_string()][..])
        );
    }

    #[tokio::test]
    async fn restrict_ref_absent_resolves_to_empty_fail_closed() {
        // No subject.id / no tree entry → the allow-list resolves to the
        // empty set: a real (impossible) constraint that the host's
        // on_empty then decides, never silently unconstrained.
        let mut bag = AttributeBag::new();
        let effects = vec![restrict_allow_models_ref("data.agents[subject.id].allowed_models")];
        let e = eval(&effects, &mut bag).await;
        assert_eq!(e.constraints.len(), 1);
        assert_eq!(e.constraints[0].allow_models.as_deref(), Some(&[][..]));
    }

    // ----- E2: FieldOp end-to-end through evaluate_steps -----

    #[tokio::test]
    async fn field_op_in_do_redacts_args_during_pre_phase() {
        // Sketches the demo case: when condition holds, redact args.ssn
        // — verifies the dispatcher walks effects, lifts the FieldOp
        // out, and rewrites the payload.
        let mut bag = AttributeBag::new();
        // Predicate is the rule's `when:`; here we make it always true.
        let stages = vec![Stage::Redact { condition: None }];
        let rule = Rule {
            condition: Expression::Always,
            effects: vec![Effect::FieldOp {
                path: "args.ssn".into(),
                stages,
            }],
            source: "demo.policy[0]".into(),
        };
        let steps = vec![Effect::from(rule)];
        let mut payload = crate::route::RoutePayload::new(json!({
            "ssn": "123-45-6789",
            "name": "Jane",
        }));

        let eval = evaluate_effects(
            &steps,
            &mut bag,
            &(Arc::new(FakePdp {
                decision: Decision::Allow,
            }) as Arc<dyn PdpResolver>),
            &null_plugins(),
            &noop_delegations(),
            crate::step::DispatchPhase::Pre,
            &mut payload,
        )
        .await;

        assert_eq!(eval.decision, Decision::Allow);
        assert!(eval.args_modified, "FieldOp should flag args_modified");
        // The ssn field should now read `[REDACTED]` (the stock value
        // the Stage::Redact applier writes when no when-clause is set).
        assert_eq!(
            payload.args.get("ssn").and_then(|v| v.as_str()),
            Some("[REDACTED]")
        );
        // Other fields untouched.
        assert_eq!(
            payload.args.get("name").and_then(|v| v.as_str()),
            Some("Jane")
        );
    }

    #[tokio::test]
    async fn field_op_targeting_result_in_pre_phase_is_skipped() {
        // A `result.X | ...` op encountered during the Pre phase is a
        // no-op — the result hasn't been produced yet. Same rule body
        // can be reused across phases without branching.
        let mut bag = AttributeBag::new();
        let stages = vec![Stage::Redact { condition: None }];
        let rule = Rule {
            condition: Expression::Always,
            effects: vec![Effect::FieldOp {
                path: "result.ssn".into(),
                stages,
            }],
            source: "demo.policy[0]".into(),
        };
        let mut payload = crate::route::RoutePayload::new(json!({}));
        let eval = evaluate_effects(
            &vec![Effect::from(rule)],
            &mut bag,
            &(Arc::new(FakePdp {
                decision: Decision::Allow,
            }) as Arc<dyn PdpResolver>),
            &null_plugins(),
            &noop_delegations(),
            crate::step::DispatchPhase::Pre,
            &mut payload,
        )
        .await;
        assert_eq!(eval.decision, Decision::Allow);
        assert!(!eval.args_modified);
        assert!(!eval.result_modified);
    }

    #[tokio::test]
    async fn field_op_with_invalid_path_denies() {
        // Path missing the `args.` / `result.` prefix is an author bug
        // — fail closed with a clear violation rather than silently
        // doing nothing.
        let mut bag = AttributeBag::new();
        let stages = vec![Stage::Redact { condition: None }];
        let rule = Rule {
            condition: Expression::Always,
            effects: vec![Effect::FieldOp {
                path: "ssn".into(), // missing prefix
                stages,
            }],
            source: "demo.policy[0]".into(),
        };
        let mut payload = crate::route::RoutePayload::new(json!({"ssn": "x"}));
        let eval = evaluate_effects(
            &vec![Effect::from(rule)],
            &mut bag,
            &(Arc::new(FakePdp {
                decision: Decision::Allow,
            }) as Arc<dyn PdpResolver>),
            &null_plugins(),
            &noop_delegations(),
            crate::step::DispatchPhase::Pre,
            &mut payload,
        )
        .await;
        match eval.decision {
            Decision::Deny {
                reason,
                rule_source,
            } => {
                assert!(reason.unwrap_or_default().contains("must start with"));
                assert_eq!(rule_source, "demo.policy[0]");
            },
            other => panic!("expected Deny, got {:?}", other),
        }
    }

    // ----- E3: Sequential / Parallel orchestration -----

    #[tokio::test]
    async fn sequential_runs_effects_in_order_until_deny() {
        // A Sequential block runs each effect in order. Allow-only
        // effects pass through; the first Deny halts the rest of the
        // sequential body AND the parent step.
        let mut bag = AttributeBag::new();
        let mut payload = crate::route::RoutePayload::new(json!({}));

        let rule = Rule {
            condition: Expression::Always,
            effects: vec![Effect::Sequential(vec![
                Effect::Allow,
                Effect::Deny {
                    reason: Some("blocked by sequential".into()),
                    code: Some("seq.test".into()),
                },
                Effect::Allow, // unreachable
            ])],
            source: "test.policy[0]".into(),
        };

        let eval = evaluate_effects(
            &vec![Effect::from(rule)],
            &mut bag,
            &(Arc::new(FakePdp {
                decision: Decision::Allow,
            }) as Arc<dyn PdpResolver>),
            &null_plugins(),
            &noop_delegations(),
            crate::step::DispatchPhase::Pre,
            &mut payload,
        )
        .await;

        match eval.decision {
            Decision::Deny {
                reason,
                rule_source,
            } => {
                assert_eq!(reason.as_deref(), Some("blocked by sequential"));
                // The `code` override on the effect won — `seq.test`
                // rather than the rule's `test.policy[0]` source.
                assert_eq!(rule_source, "seq.test");
            },
            other => panic!("expected Deny, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn parallel_allows_when_no_branch_denies() {
        // Both branches are no-op Allow → overall Continue → route Allow.
        let mut bag = AttributeBag::new();
        let mut payload = crate::route::RoutePayload::new(json!({}));

        let rule = Rule {
            condition: Expression::Always,
            effects: vec![Effect::Parallel(vec![
                Effect::Allow,
                Effect::Taint {
                    label: "audit_branch".into(),
                    scopes: vec![crate::pipeline::TaintScope::Session],
                },
            ])],
            source: "test.policy[0]".into(),
        };

        let eval = evaluate_effects(
            &vec![Effect::from(rule)],
            &mut bag,
            &(Arc::new(FakePdp {
                decision: Decision::Allow,
            }) as Arc<dyn PdpResolver>),
            &null_plugins(),
            &noop_delegations(),
            crate::step::DispatchPhase::Pre,
            &mut payload,
        )
        .await;

        assert_eq!(eval.decision, Decision::Allow);
        // Taints from parallel branches accumulate into the outer.
        assert_eq!(eval.taints.len(), 1);
        assert_eq!(eval.taints[0].label, "audit_branch");
    }

    #[tokio::test]
    async fn parallel_denies_when_any_branch_denies() {
        // One Allow, one Deny — overall Deny.
        let mut bag = AttributeBag::new();
        let mut payload = crate::route::RoutePayload::new(json!({}));

        let rule = Rule {
            condition: Expression::Always,
            effects: vec![Effect::Parallel(vec![
                Effect::Allow,
                Effect::Deny {
                    reason: Some("branch 1 denied".into()),
                    code: None,
                },
            ])],
            source: "test.policy[0]".into(),
        };

        let eval = evaluate_effects(
            &vec![Effect::from(rule)],
            &mut bag,
            &(Arc::new(FakePdp {
                decision: Decision::Allow,
            }) as Arc<dyn PdpResolver>),
            &null_plugins(),
            &noop_delegations(),
            crate::step::DispatchPhase::Pre,
            &mut payload,
        )
        .await;

        match eval.decision {
            Decision::Deny { reason, .. } => {
                assert_eq!(reason.as_deref(), Some("branch 1 denied"));
            },
            other => panic!("expected Deny, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn parallel_picks_first_index_halt_not_first_to_complete() {
        // When two branches both deny, the one with the lower index
        // in the effects list wins — not the one that physically
        // finishes first.
        let mut bag = AttributeBag::new();
        let mut payload = crate::route::RoutePayload::new(json!({}));

        let rule = Rule {
            condition: Expression::Always,
            effects: vec![Effect::Parallel(vec![
                Effect::Deny {
                    reason: Some("idx-0".into()),
                    code: None,
                },
                Effect::Deny {
                    reason: Some("idx-1".into()),
                    code: None,
                },
            ])],
            source: "test.policy[0]".into(),
        };

        let eval = evaluate_effects(
            &vec![Effect::from(rule)],
            &mut bag,
            &(Arc::new(FakePdp {
                decision: Decision::Allow,
            }) as Arc<dyn PdpResolver>),
            &null_plugins(),
            &noop_delegations(),
            crate::step::DispatchPhase::Pre,
            &mut payload,
        )
        .await;

        match eval.decision {
            Decision::Deny { reason, .. } => {
                assert_eq!(reason.as_deref(), Some("idx-0"), "lower-index halt wins");
            },
            other => panic!("expected Deny, got {:?}", other),
        }
    }
}
