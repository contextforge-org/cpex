// Location: ./crates/apl-core/src/rules.rs
// Copyright 2026
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

impl From<bool> for Literal {
    fn from(v: bool) -> Self {
        Literal::Bool(v)
    }
}
impl From<i64> for Literal {
    fn from(v: i64) -> Self {
        Literal::Int(v)
    }
}
impl From<f64> for Literal {
    fn from(v: f64) -> Self {
        Literal::Float(v)
    }
}
impl From<&str> for Literal {
    fn from(v: &str) -> Self {
        Literal::String(v.to_string())
    }
}
impl From<String> for Literal {
    fn from(v: String) -> Self {
        Literal::String(v)
    }
}

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
    Comparison {
        key: String,
        op: CompareOp,
        value: Literal,
    },
    IsTrue {
        key: String,
    },
    IsFalse {
        key: String,
    },
    /// DSL `exists(key)` — true iff the key is present in the
    /// AttributeBag, regardless of its value. Distinct from `IsTrue`
    /// (which only succeeds for truthy values). Per DSL §2.2.
    Exists {
        key: String,
    },
    /// DSL `value_key in set_key` (negate=false) / `value_key not in set_key`
    /// (negate=true). Both operands are attribute keys, not literals — the
    /// scalar at `value_key` is checked for membership in the StringSet at
    /// `set_key`. Per DSL §2.4. Returns `false` if either key is missing or
    /// the types don't match (scalar must resolve to a string).
    InSet {
        value_key: String,
        set_key: String,
        negate: bool,
    },
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

/// One thing a matching rule does. Mirrors DSL spec §3 effect classes:
///
///   * Control — `Allow`, `Deny`
///   * Label — `Taint`
///   * Host — `Plugin`, `Delegate`
///
/// Content effects (`redact`, `mask`, `omit`, `hash`) and orchestration
/// (`Sequential`, `Parallel`) land in later slices (E2 / E3).
///
/// PDP calls (`cedar:(…)`, `opa(…)`, …) remain top-level [`Step`]
/// variants for now; folding them into `Effect` is an E4 cleanup.
///
/// # Inside a `Vec<Effect>` (a rule's `effects` body)
///
///   * `Allow` is a no-op — lets evaluation continue to the next effect
///     in the list, then to the next step in `policy:`.
///   * `Deny` short-circuits the rest of the list, the rest of the
///     `policy:` block, and the route. The `reason` propagates into
///     the violation message.
///   * `Plugin` / `Delegate` dispatch identically to their top-level
///     `Step` counterparts (same invoker traits).
///   * `Taint` accumulates into the phase's taint events.
///
/// [`Step`]: crate::step::Step
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Allow,
    Deny {
        reason: Option<String>,
        /// Author-supplied stable violation code. When `Some`, it
        /// overrides the rule's auto-generated source-position code
        /// (`routes.tool:X.apl.policy[N]`) downstream. Useful when
        /// MCP clients want to dispatch on category (`quota.exceeded`,
        /// `delegation.depth_exceeded`) rather than position, or when
        /// multiple routes share a deny category that should
        /// aggregate consistently in audit dashboards. When `None`,
        /// the evaluator falls back to `rule.source` as the code —
        /// matches the historical behavior.
        ///
        /// Parser shape: `deny('reason', 'code')` (two positional
        /// arguments) or the structured `deny: { reason: ..., code: ... }`
        /// map form.
        code: Option<String>,
    },
    Plugin {
        name: String,
    },
    Delegate(crate::step::DelegateStep),
    /// Elicitation effect — dispatch a question to a human (approval,
    /// confirmation, step-up, …) through a channel plugin, hold pending
    /// state across the agent's retries, validate the response, resume.
    /// The elicitation analogue of `Delegate`. See
    /// `docs/apl-manager-approval-ciba-design.md` and
    /// [`crate::step::ElicitStep`].
    Elicit(crate::step::ElicitStep),
    Taint {
        label: String,
        scopes: Vec<crate::pipeline::TaintScope>,
    },
    /// Content effect (DSL §3) — apply a pipe chain (`redact`, `mask`,
    /// `omit`, `hash`, validators, transforms) to a field in the
    /// route's args or result. The author writes
    /// `result.salary | redact` inside a `do:` body; the parser
    /// splits the dotted path from the pipeline.
    ///
    /// `path` must start with `args.` or `result.` — the evaluator
    /// dispatches the lookup against `RoutePayload.args` or
    /// `RoutePayload.result`. A FieldOp inside a Pre-phase route's
    /// `do:` that targets `result.X` is a no-op (the result hasn't
    /// been produced yet); same goes for a Post-phase rule that
    /// targets `args.X` (the args are already on the wire). The
    /// evaluator silently skips out-of-phase ops so the same
    /// `when:`/`do:` shape can describe both phases without
    /// branching.
    FieldOp {
        path: String,
        stages: Vec<crate::pipeline::Stage>,
    },
    /// Run a list of effects in declaration order, stopping on the
    /// first Deny. Semantically equivalent to inlining the list into
    /// the enclosing scope; the variant exists to make grouping
    /// explicit and to pair with `Parallel`.
    Sequential(Vec<Effect>),
    /// Run a list of effects concurrently. Any Deny → overall Deny.
    /// Taints from all branches accumulate. Bag and payload mutations
    /// inside parallel branches are **discarded** when the branch
    /// completes — each branch gets a clone of the state, never the
    /// shared mutable original. Plugins inside `Parallel` can still
    /// emit taints (those merge); any other mutation they try to make
    /// (bag writes, args/result rewrites) vanishes.
    ///
    /// Config-load rejects `FieldOp` and `Delegate` directly inside
    /// `Parallel` (recursively), since both would silently drop their
    /// effect. The escape valve is `Sequential`.
    Parallel(Vec<Effect>),
    /// Predicate-gated body. `body` runs in order when `condition`
    /// evaluates to true; any Deny in the body halts the surrounding
    /// phase. Replaces the historical `Step::Rule(Rule)` shape —
    /// `when:` / `do:` directly desugars to this. A bare `require(X)`
    /// or `deny(X)` shorthand compiles to `When { condition: X,
    /// body: vec![Effect::Allow / Deny] }`.
    ///
    /// `source` is the human-readable origin (e.g. `"routes.X.policy[2]"`)
    /// surfaced in `Decision::Deny.rule_source` when the body denies
    /// without supplying its own code.
    When {
        condition: Expression,
        body: Vec<Effect>,
        source: String,
    },
    /// External PDP call. `on_allow` / `on_deny` are reaction effect
    /// lists fired against the PDP's decision (DSL §7.5). Replaces
    /// `Step::Pdp { ... }` — `args`-shape stays identical.
    Pdp {
        call: crate::step::PdpCall,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        on_allow: Vec<Effect>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        on_deny: Vec<Effect>,
    },
}

impl Effect {
    /// Walk this effect (and any nested effects) checking whether any
    /// node would mutate route state. Used by the config-load
    /// validator to reject `FieldOp` / `Delegate` inside `Parallel`
    /// since both would silently drop their effect in a discarded
    /// branch.
    pub fn contains_mutation(&self) -> bool {
        match self {
            // `Elicit` has an external side effect (posts to a channel,
            // registers an intent) — like `Delegate` it must not sit in
            // a `Parallel` branch that could be silently discarded.
            Effect::FieldOp { .. } | Effect::Delegate(_) | Effect::Elicit(_) => true,
            Effect::Sequential(effects) | Effect::Parallel(effects) => {
                effects.iter().any(Effect::contains_mutation)
            },
            Effect::When { body, .. } => body.iter().any(Effect::contains_mutation),
            Effect::Pdp {
                on_allow, on_deny, ..
            } => {
                on_allow.iter().any(Effect::contains_mutation)
                    || on_deny.iter().any(Effect::contains_mutation)
            },
            Effect::Allow | Effect::Deny { .. } | Effect::Plugin { .. } | Effect::Taint { .. } => {
                false
            },
        }
    }

    /// Walk the effect tree rejecting any `FieldOp` / `Delegate` that
    /// lives directly or transitively under a `Parallel` node. Returns
    /// the path string of the first violation found (or `Ok(())` if
    /// the tree is clean). Run at config-load.
    pub fn validate_parallel_purity(&self) -> Result<(), String> {
        match self {
            Effect::Parallel(effects) => {
                for e in effects {
                    if e.contains_mutation() {
                        return Err(format!(
                            "`parallel:` contains a mutation effect ({:?}); \
                             use `sequential:` for ordered mutations",
                            e
                        ));
                    }
                    // Still validate nested parallels even if this one
                    // is "clean at the top" — e.g. parallel → sequential
                    // → parallel(field_op) is still illegal.
                    e.validate_parallel_purity()?;
                }
                Ok(())
            },
            Effect::Sequential(effects) => {
                for e in effects {
                    e.validate_parallel_purity()?;
                }
                Ok(())
            },
            Effect::When { body, .. } => {
                for e in body {
                    e.validate_parallel_purity()?;
                }
                Ok(())
            },
            Effect::Pdp {
                on_allow, on_deny, ..
            } => {
                for e in on_allow.iter().chain(on_deny.iter()) {
                    e.validate_parallel_purity()?;
                }
                Ok(())
            },
            _ => Ok(()),
        }
    }
}

/// One compiled rule: a predicate plus the effects to fire when it
/// matches.
///
/// `effects` is always non-empty for parser-produced rules. The
/// historical "single Allow/Deny" cases are represented by a one-element
/// `Vec` — slightly more allocation than a flat enum, but keeps one
/// dispatch path instead of two and eliminates the ambiguity of having
/// both `Action::Allow` and `Effect::Allow` in the IR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub condition: Expression,
    pub effects: Vec<Effect>,
    /// Human-readable source (original YAML line, file path, etc.).
    /// Surfaces in audit logs and policy violation diagnostics.
    pub source: String,
}

impl Rule {
    /// Construct a single-effect rule. Convenience for the common
    /// `Allow` / `Deny` shapes that don't need a `vec![]` at the
    /// call site.
    pub fn single(condition: Expression, effect: Effect, source: impl Into<String>) -> Self {
        Self {
            condition,
            effects: vec![effect],
            source: source.into(),
        }
    }
}

/// `Rule` is structurally identical to `Effect::When`. The From impl lets
/// callers that already hold a `Rule` (notably the parser's inner helpers
/// and the test fixtures) drop a `.into()` instead of re-spelling all
/// three fields. Bridges the few remaining producers while the migration
/// completes; will probably stay long-term because the parser still
/// builds Rule incrementally before deciding it's an Effect::When.
impl From<Rule> for Effect {
    fn from(r: Rule) -> Effect {
        Effect::When {
            condition: r.condition,
            body: r.effects,
            source: r.source,
        }
    }
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
    pub fn new() -> Self {
        Self(0)
    }

    pub fn insert(&mut self, p: Phase) {
        self.0 |= Self::bit(p);
    }

    pub fn contains(&self, p: Phase) -> bool {
        self.0 & Self::bit(p) != 0
    }

    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }

    fn bit(p: Phase) -> u8 {
        match p {
            Phase::Args => 0b0001,
            Phase::Policy => 0b0010,
            Phase::Result => 0b0100,
            Phase::PostPolicy => 0b1000,
        }
    }
}

/// Custom response to attach when a route's policy denies (e.g., equivalent
/// to a Kuadrant `AuthPolicy` `response.unauthorized` `denyWith`).
/// Carried on the route and surfaced on the deny outcome's
/// `details` map by the host (apl-cpex), so a host can render a custom
/// HTTP response. All fields optional; an absent block leaves the host's
/// default denial response unchanged.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DenyResponse {
    /// HTTP status to use for the denial (e.g. 403, 302).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Response body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// Response headers (e.g. `Location` for a redirect, `WWW-Authenticate`).
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub headers: std::collections::BTreeMap<String, String>,
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
    pub policy: Vec<Effect>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub result: Vec<crate::pipeline::FieldRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub post_policy: Vec<Effect>,
    /// Per-plugin overrides declared on this route's `plugins:` block.
    /// Keyed by plugin name; merged at dispatch time via
    /// `EffectivePlugin::resolve(name, registry, &this.plugin_overrides)`.
    /// Per spec only `config`, `capabilities`, `on_error` are overridable;
    /// hooks/kind/source always come from the global declaration.
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub plugin_overrides: std::collections::HashMap<String, crate::plugin_decl::PluginOverride>,

    /// Custom denial response (transpiled `denyWith`). Most-specific layer
    /// wins on collision. `None` leaves the host's default denial behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<DenyResponse>,
}

impl CompiledRoute {
    pub fn new(route_key: impl Into<String>) -> Self {
        Self {
            route_key: route_key.into(),
            ..Default::default()
        }
    }

    /// Which phases this route uses. Empty phases are not declared.
    pub fn declared_phases(&self) -> PhaseSet {
        let mut set = PhaseSet::new();
        if !self.args.is_empty() {
            set.insert(Phase::Args);
        }
        if !self.policy.is_empty() {
            set.insert(Phase::Policy);
        }
        if !self.result.is_empty() {
            set.insert(Phase::Result);
        }
        if !self.post_policy.is_empty() {
            set.insert(Phase::PostPolicy);
        }
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
        let ms_result_fields: std::collections::HashSet<String> = more_specific
            .result
            .iter()
            .map(|f| f.field.clone())
            .collect();
        self.result.retain(|f| !ms_result_fields.contains(&f.field));
        self.result.extend(more_specific.result);

        // plugin_overrides: HashMap::extend overwrites on key collision,
        // which is exactly the more_specific-wins semantic.
        self.plugin_overrides.extend(more_specific.plugin_overrides);

        // response: deliberately NOT layered. A custom denial response is
        // scope-local — the entity-less HTTP handler carries the `global`
        // block directly, and an entity route carries only its own
        // `response:`. Propagating it here let a `global` catch-all
        // `denyWith` leak onto every inherited entity (MCP tool / llm /
        // prompt / resource) denial with no way to opt back out. Callers
        // set `response` explicitly at the scope that owns it.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_layer_does_not_propagate_response() {
        // `response` is scope-local and must never cross a layer boundary —
        // a `global` catch-all denyWith must not leak onto entity routes.
        let mut base = CompiledRoute::new("tool:x");
        base.response = Some(DenyResponse {
            status: Some(401),
            ..Default::default()
        });

        let mut layer = CompiledRoute::new("tool:x");
        layer.response = Some(DenyResponse {
            status: Some(403),
            body: Some("forbidden".to_string()),
            ..Default::default()
        });
        base.apply_layer(layer);
        // base keeps its own response; the layer's is dropped.
        assert_eq!(base.response.as_ref().unwrap().status, Some(401));

        // A layer's response never populates an empty base either.
        let mut empty = CompiledRoute::new("tool:x");
        let mut with_resp = CompiledRoute::new("tool:x");
        with_resp.response = Some(DenyResponse {
            status: Some(418),
            ..Default::default()
        });
        empty.apply_layer(with_resp);
        assert!(empty.response.is_none());
    }

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

        route.policy.push(Effect::When {
            condition: Expression::Condition(Condition::IsTrue {
                key: "authenticated".into(),
            }),
            body: vec![Effect::Allow],
            source: "policy[0]".into(),
        });
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
            effects: vec![Effect::Deny {
                reason: Some("too deep".into()),
                code: None,
            }],
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
                Expression::Condition(Condition::IsTrue {
                    key: "authenticated".into(),
                }),
                Expression::Condition(Condition::Comparison {
                    key: "delegation.depth".into(),
                    op: CompareOp::LtEq,
                    value: 3_i64.into(),
                }),
            ]),
            effects: vec![Effect::Allow],
            source: "policy[1]".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: Rule = serde_json::from_str(&json).unwrap();
        // No PartialEq on Rule (would force PartialEq on Action's variants
        // with floats etc.); spot-check the discriminator path instead.
        assert!(matches!(back.effects.as_slice(), [Effect::Allow]));
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
        effective.policy.push(Effect::When {
            condition: Expression::Always,
            body: vec![Effect::Allow],
            source: "global.policy[0]".into(),
        });
        effective.post_policy.push(Effect::When {
            condition: Expression::Always,
            body: vec![Effect::Allow],
            source: "global.post_policy[0]".into(),
        });

        // Now apply the route-specific layer on top.
        let mut route_layer = CompiledRoute::new("ignored");
        route_layer.policy.push(Effect::When {
            condition: Expression::Always,
            body: vec![Effect::Allow],
            source: "route.policy[0]".into(),
        });
        route_layer.post_policy.push(Effect::When {
            condition: Expression::Always,
            body: vec![Effect::Allow],
            source: "route.post_policy[0]".into(),
        });

        effective.apply_layer(route_layer);

        // global ran first, route ran second — first-deny-wins respects
        // the hierarchy.
        assert_eq!(effective.policy.len(), 2);
        match &effective.policy[0] {
            Effect::When { source, .. } => assert_eq!(source, "global.policy[0]"),
            _ => panic!(),
        }
        match &effective.policy[1] {
            Effect::When { source, .. } => assert_eq!(source, "route.policy[0]"),
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
            pipeline: Pipeline {
                stages: vec![Stage::Type(TypeCheck::Str)],
            },
            source: "default.args.id".into(),
        });
        effective.args.push(FieldRule {
            field: "trace_id".into(),
            pipeline: Pipeline {
                stages: vec![Stage::Type(TypeCheck::Str)],
            },
            source: "default.args.trace_id".into(),
        });

        // Layer route (more specific) on top — it redefines `id`.
        let mut route_layer = CompiledRoute::new("ignored");
        route_layer.args.push(FieldRule {
            field: "id".into(),
            pipeline: Pipeline {
                stages: vec![Stage::Type(TypeCheck::Uuid)],
            },
            source: "route.args.id".into(),
        });

        effective.apply_layer(route_layer);

        assert_eq!(effective.args.len(), 2);
        // `id` is now the route's (Uuid), not the default's (Str).
        let id_rule = effective.args.iter().find(|f| f.field == "id").unwrap();
        assert!(matches!(
            id_rule.pipeline.stages[0],
            Stage::Type(TypeCheck::Uuid)
        ));
        assert_eq!(id_rule.source, "route.args.id");
        // `trace_id` survives from the default — route didn't touch it.
        let trace = effective
            .args
            .iter()
            .find(|f| f.field == "trace_id")
            .unwrap();
        assert_eq!(trace.source, "default.args.trace_id");
    }

    #[test]
    fn apply_layer_plugin_overrides_more_specific_wins() {
        use crate::plugin_decl::PluginOverride;

        // Default (less specific) layer.
        let mut effective = CompiledRoute::new("route.X");
        effective.plugin_overrides.insert(
            "rate_limiter".into(),
            PluginOverride {
                on_error: Some("ignore".into()),
                ..Default::default()
            },
        );
        effective.plugin_overrides.insert(
            "audit_logger".into(),
            PluginOverride {
                on_error: Some("ignore".into()),
                ..Default::default()
            },
        );

        // Route (more specific) layer overrides rate_limiter.
        let mut route_layer = CompiledRoute::new("ignored");
        route_layer.plugin_overrides.insert(
            "rate_limiter".into(),
            PluginOverride {
                on_error: Some("fail".into()),
                ..Default::default()
            },
        );

        effective.apply_layer(route_layer);

        assert_eq!(effective.plugin_overrides.len(), 2);
        assert_eq!(
            effective.plugin_overrides["rate_limiter"]
                .on_error
                .as_deref(),
            Some("fail"),
            "route's override wins on collision",
        );
        // audit_logger untouched — route didn't redefine it.
        assert_eq!(
            effective.plugin_overrides["audit_logger"]
                .on_error
                .as_deref(),
            Some("ignore"),
        );
    }

    #[test]
    fn apply_layer_chained_walks_hierarchy_in_specificity_order() {
        // Build effective policy by applying layers least-to-most-specific.
        // Mirrors how AplConfigVisitor will compose global/default/tag/route.
        let mut effective = CompiledRoute::new("route.get_compensation");

        let mut global = CompiledRoute::default();
        global.policy.push(Effect::When {
            condition: Expression::Always,
            body: vec![Effect::Allow],
            source: "global.policy[0]".into(),
        });

        let mut default = CompiledRoute::default();
        default.policy.push(Effect::When {
            condition: Expression::Always,
            body: vec![Effect::Allow],
            source: "default.policy[0]".into(),
        });

        let mut tag = CompiledRoute::default();
        tag.policy.push(Effect::When {
            condition: Expression::Always,
            body: vec![Effect::Allow],
            source: "tag.hr.policy[0]".into(),
        });

        let mut route = CompiledRoute::default();
        route.policy.push(Effect::When {
            condition: Expression::Always,
            body: vec![Effect::Allow],
            source: "route.policy[0]".into(),
        });

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
                Effect::When { source, .. } => source.as_str(),
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

    // ----- E3: parallel-purity validation -----

    #[test]
    fn validate_parallel_pure_block_passes() {
        // A parallel block of read-only effects validates clean.
        let effect = Effect::Parallel(vec![
            Effect::Plugin {
                name: "rate_limiter".into(),
            },
            Effect::Plugin {
                name: "audit".into(),
            },
            Effect::Allow,
        ]);
        assert!(effect.validate_parallel_purity().is_ok());
    }

    #[test]
    fn validate_parallel_rejects_field_op() {
        // FieldOp would silently lose its mutation in a discarded
        // branch — config-load surfaces this loudly.
        let effect = Effect::Parallel(vec![
            Effect::Plugin {
                name: "audit".into(),
            },
            Effect::FieldOp {
                path: "args.ssn".into(),
                stages: vec![],
            },
        ]);
        let err = effect.validate_parallel_purity().unwrap_err();
        assert!(err.contains("mutation"), "got: {}", err);
        assert!(err.contains("FieldOp"), "should name the offender: {}", err);
    }

    #[test]
    fn validate_parallel_rejects_delegate() {
        // Same reason as FieldOp — the minted token would land in a
        // bag that gets discarded.
        let delegate = Effect::Delegate(crate::step::DelegateStep {
            plugin_name: "workday".into(),
            config_override: None,
            on_error: None,
            source: "test".into(),
        });
        let effect = Effect::Parallel(vec![Effect::Allow, delegate]);
        let err = effect.validate_parallel_purity().unwrap_err();
        assert!(err.contains("mutation"));
    }

    #[test]
    fn validate_parallel_recurses_into_nested_parallel() {
        // `parallel → sequential → parallel(field_op)` — the inner
        // parallel still illegal. Recursion must catch it.
        let inner_parallel = Effect::Parallel(vec![Effect::FieldOp {
            path: "args.x".into(),
            stages: vec![],
        }]);
        let outer = Effect::Parallel(vec![Effect::Sequential(vec![
            Effect::Allow,
            inner_parallel,
        ])]);
        assert!(outer.validate_parallel_purity().is_err());
    }

    #[test]
    fn validate_top_level_sequential_allows_mutations() {
        // FieldOp / Delegate are allowed under Sequential (or at top
        // level) — only Parallel rejects them.
        let effect = Effect::Sequential(vec![
            Effect::FieldOp {
                path: "args.ssn".into(),
                stages: vec![],
            },
            Effect::Allow,
        ]);
        assert!(effect.validate_parallel_purity().is_ok());
    }

    #[test]
    fn validate_contains_mutation_classifies_each_variant() {
        // White-box check on the helper so future Effect additions
        // get flagged here when they should be classified.
        assert!(!Effect::Allow.contains_mutation());
        assert!(!Effect::Deny {
            reason: None,
            code: None
        }
        .contains_mutation());
        assert!(!Effect::Plugin { name: "x".into() }.contains_mutation());
        assert!(!Effect::Taint {
            label: "x".into(),
            scopes: vec![],
        }
        .contains_mutation());

        assert!(Effect::FieldOp {
            path: "args.x".into(),
            stages: vec![],
        }
        .contains_mutation());
        assert!(Effect::Delegate(crate::step::DelegateStep {
            plugin_name: "x".into(),
            config_override: None,
            on_error: None,
            source: "x".into(),
        })
        .contains_mutation());

        // Composite — mutates iff any child mutates.
        let pure_seq = Effect::Sequential(vec![Effect::Allow]);
        assert!(!pure_seq.contains_mutation());
        let dirty_seq = Effect::Sequential(vec![Effect::FieldOp {
            path: "args.x".into(),
            stages: vec![],
        }]);
        assert!(dirty_seq.contains_mutation());
    }
}
