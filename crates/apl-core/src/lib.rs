// Location: ./crates/apl-core/src/lib.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// APL core — Attribute Policy Language compiler + evaluator.
//
// This crate is the language nucleus. It does not depend on CPEX directly;
// the bridge from cpex-core extensions into the AttributeBag lives in
// `apl-cmf`, and the `PolicyEvaluator` implementation lives in `apl-cpex`.
//
// See docs/specs/apl-design.md for the full design.

#![doc = "APL — Attribute Policy Language. See docs/specs/apl-design.md."]

pub mod attributes;
pub mod evaluator;
pub mod parser;
pub mod pipeline;
pub mod plugin_decl;
pub mod route;
pub mod rules;
pub mod step;

pub use attributes::{AttributeBag, AttributeExtractor, AttributeValue};
pub use evaluator::{
    evaluate_pipeline, evaluate_rules, evaluate_steps, Decision, FieldOutcome, PipelineEvaluation,
};
pub use parser::{
    compile_config, compile_policy_block_value, parse_pipeline, parse_predicate, parse_rule,
    CompiledConfig, ConfigYaml, ParseError, RouteYaml,
};
pub use pipeline::{FieldRule, Pipeline, ScanKind, Stage, TaintEvent, TaintScope, TypeCheck};
pub use plugin_decl::{
    CapsView, EffectivePlugin, PluginDeclaration, PluginOverride, PluginRegistry,
};
pub use route::{evaluate_post, evaluate_pre, evaluate_route, RouteDecision, RoutePayload};
pub use rules::{
    Action, CompareOp, CompiledRoute, Condition, Expression, Literal, Phase, PhaseSet, Rule,
};
pub use step::{
    PdpCall, PdpDecision, PdpDialect, PdpError, PdpResolver, PluginError, PluginInvocation,
    PluginInvoker, PluginOutcome, Step,
};
