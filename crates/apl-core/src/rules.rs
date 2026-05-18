// Location: ./crates/apl-core/src/rules.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// APL intermediate representation.
//
// The compiler (later) produces a `CompiledRoute` per route_key from
// YAML / database / any other ConfigSource. The evaluator (later)
// consumes the IR plus an AttributeBag and returns a decision.
//
// IR types are kept small and pure-data — no dependencies on cpex-core
// extensions, no evaluation logic. See docs/specs/apl-design.md §7.

use serde::{Deserialize, Serialize};

/// Comparison operators in DSL predicates.
///
/// `In` / `NotIn` are intentionally absent: the DSL spec §2.4 has them as
/// `value_key in set_key` — both sides are attribute references, not a
/// key-vs-literal shape. They'll land as a dedicated `Condition` variant
/// when the parser arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompareOp {
    Eq,
    NotEq,
    Gt,
    GtEq,
    Lt,
    LtEq,
    /// `<set_key> contains <literal>` — left is a StringSet attribute,
    /// right is a string literal.
    Contains,
}

/// Right-hand side of a comparison.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Literal {
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
}

impl From<bool> for Literal { fn from(v: bool) -> Self { Literal::Bool(v) } }
impl From<i64>  for Literal { fn from(v: i64)  -> Self { Literal::Int(v)  } }
impl From<f64>  for Literal { fn from(v: f64)  -> Self { Literal::Float(v) } }
impl From<&str> for Literal { fn from(v: &str) -> Self { Literal::String(v.to_string()) } }
impl From<String> for Literal { fn from(v: String) -> Self { Literal::String(v) } }

/// Leaf predicate.
///
/// `Comparison` covers `key op value`. The truthiness checks are split out
/// (`IsTrue` / `IsFalse`) because they're the most common form — `authenticated`,
/// `role.hr`, `delegated`.
///
/// The DSL's `require(...)` keyword is **not** represented here — it's a
/// rule-level shorthand for "deny when the condition fails," and the parser
/// desugars it into `Not` / `And` / `Or` over `IsFalse` expressions plus
/// an `Action::Deny`. See DSL spec §8.1 desugarings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Condition {
    Comparison { key: String, op: CompareOp, value: Literal },
    IsTrue { key: String },
    IsFalse { key: String },
    /// DSL `exists(key)` — true iff the key is present in the
    /// AttributeBag, regardless of its value. Distinct from `IsTrue`
    /// (which only succeeds for truthy values). Per DSL §2.2.
    Exists { key: String },
    /// DSL `value_key in set_key` (negate=false) / `value_key not in set_key`
    /// (negate=true). Both operands are attribute keys, not literals — the
    /// scalar at `value_key` is checked for membership in the StringSet at
    /// `set_key`. Per DSL §2.4. Returns `false` if either key is missing or
    /// the types don't match (scalar must resolve to a string).
    InSet { value_key: String, set_key: String, negate: bool },
}

/// Compound predicate.
///
/// `Always` is the implicit-true predicate for bare-effect rules
/// (DSL §3.1): `- plugin(rate_limiter)` / `- taint(audit)` / unconditional
/// `- deny` / `- allow`. It's never produced by predicate-string parsing
/// — only by rule-level forms where no `when:` is supplied.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Expression {
    Condition(Condition),
    And(Vec<Expression>),
    Or(Vec<Expression>),
    Not(Box<Expression>),
    Always,
}

/// What happens when a rule's condition holds.
///
/// Only the two first-class spec actions are represented: `Allow`
/// (explicit allow, evaluation continues) and `Deny` (terminal, with an
/// optional reason). The DSL spec §3 has no `Audit` or `DenyActions`
/// action — audit is `plugin(audit_logger)` (a future `Step` variant),
/// and downstream-action denial maps to taint labels or reaction blocks.
///
/// Field-transform actions (`mask` / `redact` / `omit` / `hash`), PDP
/// calls (`cedar:(…)`, `opa(…)`, `authzen(…)`, `nemo(…)`), and plugin
/// invocations (`plugin(name)`) are rule-level *steps* in the spec, not
/// actions — they land as a separate `Step` enum when the parser arrives.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Deny { reason: Option<String> },
}

/// One compiled rule: a predicate plus the effect when it matches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub condition: Expression,
    pub action: Action,
    /// Human-readable source (original YAML line, file path, etc.).
    /// Surfaces in audit logs and policy violation diagnostics.
    pub source: String,
}

/// One of the four lifecycle phases the evaluator runs per route.
///
/// See docs/specs/apl-design.md §3 — the `PolicyEvaluator` trait has one
/// async method per phase. `declared_phases()` lets the host skip phases
/// the route doesn't use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Args,
    Policy,
    Result,
    PostPolicy,
}

/// Bit-packed set of phases a route declared.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PhaseSet(u8);

impl PhaseSet {
    pub fn new() -> Self { Self(0) }

    pub fn insert(&mut self, p: Phase) {
        self.0 |= Self::bit(p);
    }

    pub fn contains(&self, p: Phase) -> bool {
        self.0 & Self::bit(p) != 0
    }

    pub fn is_empty(&self) -> bool { self.0 == 0 }

    fn bit(p: Phase) -> u8 {
        match p {
            Phase::Args => 0b0001,
            Phase::Policy => 0b0010,
            Phase::Result => 0b0100,
            Phase::PostPolicy => 0b1000,
        }
    }
}

/// Compiler output for a single route.
///
/// One `CompiledRoute` per route_key. The compiler merges global / default /
/// tag / route-specific rules from the config hierarchy down into these four
/// phase lists before the evaluator sees them — the IR has no notion of
/// "tag rules" or "route overrides," only "steps that fire in phase P."
///
/// `args` and `result` are per-field pipelines (validators + transforms).
/// `policy` and `post_policy` are step lists — predicate-and-action rules
/// plus PDP calls, plugin invocations, and taint effects. See
/// apl-dsl-spec §1.2 / §4 / §7.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CompiledRoute {
    pub route_key: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<crate::pipeline::FieldRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy: Vec<crate::step::Step>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub result: Vec<crate::pipeline::FieldRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub post_policy: Vec<crate::step::Step>,
    /// Per-plugin overrides declared on this route's `plugins:` block.
    /// Keyed by plugin name; merged at dispatch time via
    /// `EffectivePlugin::resolve(name, registry, &this.plugin_overrides)`.
    /// Per spec only `config`, `capabilities`, `on_error` are overridable;
    /// hooks/kind/source always come from the global declaration.
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub plugin_overrides: std::collections::HashMap<String, crate::plugin_decl::PluginOverride>,
}

impl CompiledRoute {
    pub fn new(route_key: impl Into<String>) -> Self {
        Self { route_key: route_key.into(), ..Default::default() }
    }

    /// Which phases this route uses. Empty phases are not declared.
    pub fn declared_phases(&self) -> PhaseSet {
        let mut set = PhaseSet::new();
        if !self.args.is_empty() { set.insert(Phase::Args); }
        if !self.policy.is_empty() { set.insert(Phase::Policy); }
        if !self.result.is_empty() { set.insert(Phase::Result); }
        if !self.post_policy.is_empty() { set.insert(Phase::PostPolicy); }
        set
    }

    /// Apply a more-specific policy layer on top of this one. Used by
    /// orchestrators (apl-cpex's visitor) to stack the unified-config
    /// hierarchy least-to-most-specific:
    ///
    /// ```text
    /// effective = CompiledRoute::default()
    /// effective.apply_layer(global_block)
    /// effective.apply_layer(default_block)
    /// effective.apply_layer(tag_block)
    /// effective.apply_layer(route_block)
    /// ```
    ///
    /// Each call adds the parameter on top of what's already there;
    /// `more_specific` wins on collisions because it represents a
    /// later/narrower layer in the inheritance chain.
    ///
    /// Merge semantics:
    /// - **`policy` / `post_policy`**: `more_specific`'s steps append
    ///   *after* self's. Earlier layers run first — globals deny before
    ///   route-specific rules get a chance.
    /// - **`args` / `result`**: per-field; if both layers declare the
    ///   same field, `more_specific`'s rule replaces self's. Fields
    ///   only in self stay; fields only in `more_specific` are added.
    /// - **`plugin_overrides`**: HashMap merge; `more_specific` wins
    ///   on key collisions, otherwise prefix's entries fill gaps.
    ///
    /// `self.route_key` is preserved — apply_layer doesn't overwrite
    /// identity, just policy content.
    pub fn apply_layer(&mut self, more_specific: CompiledRoute) {
        // policy / post_policy: more_specific's steps append AFTER self.
        // Order of accumulated calls = order of evaluation.
        self.policy.extend(more_specific.policy);
        self.post_policy.extend(more_specific.post_policy);

        // args: more_specific wins on field collision — drop any self.args
        // entries the new layer redefines, then push the new layer's.
        let ms_fields: std::collections::HashSet<String> =
            more_specific.args.iter().map(|f| f.field.clone()).collect();
        self.args.retain(|f| !ms_fields.contains(&f.field));
        self.args.extend(more_specific.args);

        // result: same shape as args.
        let ms_result_fields: std::collections::HashSet<String> =
            more_specific.result.iter().map(|f| f.field.clone()).collect();
        self.result.retain(|f| !ms_result_fields.contains(&f.field));
        self.result.extend(more_specific.result);

        // plugin_overrides: HashMap::extend overwrites on key collision,
        // which is exactly the more_specific-wins semantic.
        self.plugin_overrides.extend(more_specific.plugin_overrides);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_set_basic() {
        let mut set = PhaseSet::new();
        assert!(set.is_empty());
        set.insert(Phase::Policy);
        set.insert(Phase::Result);
        assert!(set.contains(Phase::Policy));
        assert!(set.contains(Phase::Result));
        assert!(!set.contains(Phase::Args));
        assert!(!set.contains(Phase::PostPolicy));
        assert!(!set.is_empty());
    }

    #[test]
    fn compiled_route_declared_phases() {
        let mut route = CompiledRoute::new("get_compensation");
        assert!(route.declared_phases().is_empty());

        route.policy.push(crate::step::Step::Rule(Rule {
            condition: Expression::Condition(Condition::IsTrue {
                key: "authenticated".into(),
            }),
            action: Action::Allow,
            source: "policy[0]".into(),
        }));
        let phases = route.declared_phases();
        assert!(phases.contains(Phase::Policy));
        assert!(!phases.contains(Phase::Args));
    }

    #[test]
    fn literal_from_impls() {
        // From impls keep test/builder code readable.
        let r = Rule {
            condition: Expression::Condition(Condition::Comparison {
                key: "delegation.depth".into(),
                op: CompareOp::Gt,
                value: 2_i64.into(),
            }),
            action: Action::Deny { reason: Some("too deep".into()) },
            source: "policy[0]".into(),
        };
        if let Expression::Condition(Condition::Comparison { value, .. }) = r.condition {
            assert_eq!(value, Literal::Int(2));
        } else {
            panic!("expected Comparison");
        }
    }

    #[test]
    fn rule_serde_roundtrip() {
        let r = Rule {
            condition: Expression::And(vec![
                Expression::Condition(Condition::IsTrue { key: "authenticated".into() }),
                Expression::Condition(Condition::Comparison {
                    key: "delegation.depth".into(),
                    op: CompareOp::LtEq,
                    value: 3_i64.into(),
                }),
            ]),
            action: Action::Allow,
            source: "policy[1]".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: Rule = serde_json::from_str(&json).unwrap();
        // No PartialEq on Rule (would force PartialEq on Action's variants
        // with floats etc.); spot-check the discriminator path instead.
        assert!(matches!(back.action, Action::Allow));
        assert_eq!(back.source, "policy[1]");
    }

    #[test]
    fn compiled_route_serde_skips_empty_phases() {
        let route = CompiledRoute::new("ping");
        let json = serde_json::to_string(&route).unwrap();
        // Empty phase vecs should not serialize — keeps audit logs clean.
        assert_eq!(json, r#"{"route_key":"ping"}"#);
    }

    #[test]
    fn apply_layer_appends_policy_and_post_policy_in_evaluation_order() {
        // Start with global (least specific), then layer route on top.
        // After: global.policy[0] runs first, route.policy[0] runs second.
        let mut effective = CompiledRoute::new("route.get_compensation");
        // Seed effective with global content (simulating having already
        // applied the global layer once).
        effective.policy.push(crate::step::Step::Rule(Rule {
            condition: Expression::Always,
            action: Action::Allow,
            source: "global.policy[0]".into(),
        }));
        effective.post_policy.push(crate::step::Step::Rule(Rule {
            condition: Expression::Always,
            action: Action::Allow,
            source: "global.post_policy[0]".into(),
        }));

        // Now apply the route-specific layer on top.
        let mut route_layer = CompiledRoute::new("ignored");
        route_layer.policy.push(crate::step::Step::Rule(Rule {
            condition: Expression::Always,
            action: Action::Allow,
            source: "route.policy[0]".into(),
        }));
        route_layer.post_policy.push(crate::step::Step::Rule(Rule {
            condition: Expression::Always,
            action: Action::Allow,
            source: "route.post_policy[0]".into(),
        }));

        effective.apply_layer(route_layer);

        // global ran first, route ran second — first-deny-wins respects
        // the hierarchy.
        assert_eq!(effective.policy.len(), 2);
        match &effective.policy[0] {
            crate::step::Step::Rule(r) => assert_eq!(r.source, "global.policy[0]"),
            _ => panic!(),
        }
        match &effective.policy[1] {
            crate::step::Step::Rule(r) => assert_eq!(r.source, "route.policy[0]"),
            _ => panic!(),
        }
        assert_eq!(effective.post_policy.len(), 2);

        // route_key preserved (apply_layer doesn't touch identity).
        assert_eq!(effective.route_key, "route.get_compensation");
    }

    #[test]
    fn apply_layer_args_more_specific_wins_on_field_collision() {
        use crate::pipeline::{FieldRule, Pipeline, Stage, TypeCheck};

        // Start with the default (less specific) layer.
        let mut effective = CompiledRoute::new("route.X");
        effective.args.push(FieldRule {
            field: "id".into(),
            pipeline: Pipeline { stages: vec![Stage::Type(TypeCheck::Str)] },
            source: "default.args.id".into(),
        });
        effective.args.push(FieldRule {
            field: "trace_id".into(),
            pipeline: Pipeline { stages: vec![Stage::Type(TypeCheck::Str)] },
            source: "default.args.trace_id".into(),
        });

        // Layer route (more specific) on top — it redefines `id`.
        let mut route_layer = CompiledRoute::new("ignored");
        route_layer.args.push(FieldRule {
            field: "id".into(),
            pipeline: Pipeline { stages: vec![Stage::Type(TypeCheck::Uuid)] },
            source: "route.args.id".into(),
        });

        effective.apply_layer(route_layer);

        assert_eq!(effective.args.len(), 2);
        // `id` is now the route's (Uuid), not the default's (Str).
        let id_rule = effective.args.iter().find(|f| f.field == "id").unwrap();
        assert!(matches!(id_rule.pipeline.stages[0], Stage::Type(TypeCheck::Uuid)));
        assert_eq!(id_rule.source, "route.args.id");
        // `trace_id` survives from the default — route didn't touch it.
        let trace = effective.args.iter().find(|f| f.field == "trace_id").unwrap();
        assert_eq!(trace.source, "default.args.trace_id");
    }

    #[test]
    fn apply_layer_plugin_overrides_more_specific_wins() {
        use crate::plugin_decl::PluginOverride;

        // Default (less specific) layer.
        let mut effective = CompiledRoute::new("route.X");
        effective.plugin_overrides.insert(
            "rate_limiter".into(),
            PluginOverride { on_error: Some("ignore".into()), ..Default::default() },
        );
        effective.plugin_overrides.insert(
            "audit_logger".into(),
            PluginOverride { on_error: Some("ignore".into()), ..Default::default() },
        );

        // Route (more specific) layer overrides rate_limiter.
        let mut route_layer = CompiledRoute::new("ignored");
        route_layer.plugin_overrides.insert(
            "rate_limiter".into(),
            PluginOverride { on_error: Some("fail".into()), ..Default::default() },
        );

        effective.apply_layer(route_layer);

        assert_eq!(effective.plugin_overrides.len(), 2);
        assert_eq!(
            effective.plugin_overrides["rate_limiter"].on_error.as_deref(),
            Some("fail"),
            "route's override wins on collision",
        );
        // audit_logger untouched — route didn't redefine it.
        assert_eq!(
            effective.plugin_overrides["audit_logger"].on_error.as_deref(),
            Some("ignore"),
        );
    }

    #[test]
    fn apply_layer_chained_walks_hierarchy_in_specificity_order() {
        // Build effective policy by applying layers least-to-most-specific.
        // Mirrors how AplConfigVisitor will compose global/default/tag/route.
        let mut effective = CompiledRoute::new("route.get_compensation");

        let mut global = CompiledRoute::default();
        global.policy.push(crate::step::Step::Rule(Rule {
            condition: Expression::Always,
            action: Action::Allow,
            source: "global.policy[0]".into(),
        }));

        let mut default = CompiledRoute::default();
        default.policy.push(crate::step::Step::Rule(Rule {
            condition: Expression::Always,
            action: Action::Allow,
            source: "default.policy[0]".into(),
        }));

        let mut tag = CompiledRoute::default();
        tag.policy.push(crate::step::Step::Rule(Rule {
            condition: Expression::Always,
            action: Action::Allow,
            source: "tag.hr.policy[0]".into(),
        }));

        let mut route = CompiledRoute::default();
        route.policy.push(crate::step::Step::Rule(Rule {
            condition: Expression::Always,
            action: Action::Allow,
            source: "route.policy[0]".into(),
        }));

        effective.apply_layer(global);
        effective.apply_layer(default);
        effective.apply_layer(tag);
        effective.apply_layer(route);

        // Order of calls = order of evaluation. global runs first,
        // route runs last (first-deny-wins lets globals deny early).
        let sources: Vec<&str> = effective
            .policy
            .iter()
            .map(|s| match s {
                crate::step::Step::Rule(r) => r.source.as_str(),
                _ => "<not-rule>",
            })
            .collect();
        assert_eq!(
            sources,
            vec![
                "global.policy[0]",
                "default.policy[0]",
                "tag.hr.policy[0]",
                "route.policy[0]",
            ]
        );
    }
}
