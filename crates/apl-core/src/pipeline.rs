// Location: ./crates/apl-core/src/pipeline.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Pipe-chain IR for APL `args:` and `result:` phases.
//
// A field-level pipeline is a sequence of `Stage`s separated by `|` in the
// DSL. Validators (str/int/range/...) check the field's value and can fail
// the request; transforms (mask/redact/omit/hash) modify the value; effects
// (taint) record side information.
//
// Grounded in apl-dsl-spec.md §4.
//
// Stages whose evaluator behavior is deferred to step 5c (taint dispatch,
// plugin invocation, regex/named validators, scan placeholders) are still
// represented in the IR so the parser can produce them — the evaluator
// recognizes them and returns a clear "deferred" signal rather than crashing.

use serde::{Deserialize, Serialize};

use crate::rules::Expression;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypeCheck {
    Str,
    Int,
    Bool,
    Float,
    Email,
    Url,
    Uuid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaintScope {
    Session,
    Message,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanKind {
    PiiRedact,
    PiiDetect,
    InjectionScan,
}

/// One stage in a pipe chain.
///
/// Stages execute left-to-right against a single field value. Validators
/// halt the pipeline on failure; transforms produce a new value; effects
/// (taint) annotate without changing the value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    // ----- Validators (halt with deny on failure) -----
    Type(TypeCheck),
    /// `regex("pattern")` — parser captures the pattern; evaluator stubbed
    /// until we add the `regex` crate dependency.
    Regex { pattern: String },
    /// `validate(name)` — named validator dispatch; evaluator stubbed.
    Validate { name: String },
    /// `len(..N)`, `len(N..M)`, `len(N..)` — string length bounds.
    Length { min: Option<usize>, max: Option<usize> },
    /// Bare range literal `N..M`, `..M`, `N..`, with optional `k`/`K`/`m`/`M`
    /// numeric suffixes. Integer-only per DSL §4.3.
    Range { min: Option<i64>, max: Option<i64> },
    /// `enum(a, b, c)` — value must equal one of the listed strings.
    Enum { values: Vec<String> },

    // ----- Transforms (produce a new value) -----
    /// `mask(N)` — replace all but last N chars with `*`.
    Mask { keep_last: usize },
    /// `redact` (unconditional) or `redact(!condition)` (conditional).
    /// Replaces value with `[REDACTED]` when condition is true (or always,
    /// if no condition).
    Redact { condition: Option<Expression> },
    /// `omit` — drop the field from output entirely. No conditional form
    /// per DSL §4.1 — use a policy rule for conditional omit.
    Omit,
    /// `hash` — replace value with a hash digest.
    Hash,

    // ----- Effects (deferred to step 5c — IR captured, eval stubbed) -----
    Taint { label: String, scopes: Vec<TaintScope> },
    Plugin { name: String },
    Scan { kind: ScanKind },
}

/// Sequence of stages applied to one field's value.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Pipeline {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stages: Vec<Stage>,
}

impl Pipeline {
    pub fn new() -> Self { Self::default() }
    pub fn push(&mut self, stage: Stage) { self.stages.push(stage); }
    pub fn is_empty(&self) -> bool { self.stages.is_empty() }
}

/// Attaches a pipeline to a specific field name in the args or result phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldRule {
    pub field: String,
    pub pipeline: Pipeline,
    /// Source location (e.g., `"get_compensation.result.ssn"`) for audit.
    pub source: String,
}

/// A taint label produced as a side effect of running a pipeline.
///
/// The evaluator accumulates these in `PipelineEvaluation.taints`; the host
/// (apl-cpex) drains them and writes to the actual SessionStore. Same shape
/// as `Stage::Taint`'s fields, but lives at the evaluator boundary because
/// it also carries taints emitted by plugin invocations and scan stages
/// — not just literal `taint(...)` stages.
#[derive(Debug, Clone, PartialEq)]
pub struct TaintEvent {
    pub label: String,
    pub scopes: Vec<TaintScope>,
}
