// Location: ./crates/apl-core/src/lib.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// APL core — Authorization Policy Language compiler + evaluator.
//
// This crate is the language nucleus. It does not depend on CPEX directly;
// the bridge from cpex-core extensions into the AttributeBag lives in
// `apl-cmf`, and the `PolicyEvaluator` implementation lives in `apl-cpex`.
//
// See docs/specs/apl-design.md for the full design.

#![doc = "APL — Authorization Policy Language. See docs/specs/apl-design.md."]

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
    evaluate_effects, evaluate_pipeline, evaluate_rules, Decision, FieldOutcome, PipelineEvaluation,
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
    CompareOp, CompiledRoute, Condition, DenyResponse, Effect, Expression, Literal, Phase,
    PhaseSet, Rule,
};
pub use step::{
    delegation_bag_keys, elicitation_bag_keys, AutoApprovingElicitor, DelegateStep,
    DelegationError, DelegationInvoker, DelegationOutcome, DispatchPhase, ElicitKind, ElicitStep,
    ElicitationDispatch, ElicitationError, ElicitationInvoker, ElicitationOutcome,
    ElicitationStatus, ElicitationValidation, NoopDelegationInvoker, NoopElicitationInvoker,
    PdpCall, PdpDecision, PdpDialect, PdpError, PdpFactory, PdpResolver, PendingElicitation,
    PluginError, PluginInvocation, PluginInvoker, PluginOutcome,
};
