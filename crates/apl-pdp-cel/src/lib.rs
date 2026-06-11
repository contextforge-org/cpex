// Location: ./crates/apl-pdp-cel/src/lib.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// apl-pdp-cel — `PdpResolver` over the `cel` (Common Expression Language)
// interpreter.
//
// # Where this lives in the stack
//
//   APL evaluator (apl-core)
//        │  `cel:(expr: "...")` step
//        ▼
//   PdpRouter (apl-cpex)        — dispatches by dialect (PdpDialect::Cel)
//        │  resolver.evaluate(call, bag)
//        ▼
//   CelResolver                 — THIS CRATE
//        │  bag → CEL activation, compile-once / eval-many
//        ▼
//   cel::Program::execute       — clarkmcc's CEL interpreter
//
// # Inputs (`PdpCall.args`)
//
// APL routes call CEL like:
//
// ```yaml
// policy:
//   - cel:
//       expr: |
//         subject.id in ["alice", "bob"]
//         && delegation.depth <= 2
//         && !("compensation" in session.labels)
//     on_deny:
//       - deny("cel policy denied access")
//     on_allow:
//       - taint(audit_pass, session)
// ```
//
// Required key: `expr` (a string). Any other keys in `args` (e.g.
// `resource`, `context`) are surfaced to the expression as additional
// top-level CEL variables, mirroring how `cedar:` exposes resource/context.
//
// # The attribute vocabulary (bag → CEL activation)
//
// APL's `AttributeBag` is a flat namespace of dotted keys
// (`subject.id`, `role.hr`, `delegation.depth`, `session.labels`). The
// resolver rebuilds those into nested CEL maps so authors write natural
// field selection:
//
//   - `subject.id`          → string         `subject.id == "alice"`
//   - `role.hr` (=true)      → bool           `role.hr`
//   - `delegation.depth`     → int            `delegation.depth <= 2`
//   - `session.labels`       → list(string)   `"PII" in session.labels`
//   - `intent.confidence`    → double         `intent.confidence > 0.9`
//
// See `activation::bag_to_context` for the exact mapping and the
// leaf-vs-namespace collision rule.
//
// # Decision contract
//
// The expression MUST evaluate to a boolean. `true → Allow`,
// `false → Deny`. A non-boolean result, an undeclared-variable reference,
// a compile error, or any other evaluation error is **fail-closed → Deny**
// with the cause in `PdpDecision.diagnostics` (matches APL's PDP
// fail-closed default; DSL §8.9). Operators can flip a *missing-variable*
// to allow-through via `on_error: allow` in the PDP config block, but the
// default is `deny`.
//
// # Compile cache
//
// Each distinct `expr` string compiles to a `cel::Program` exactly once;
// the resolver caches programs keyed by source string and reuses them on
// every subsequent call. Because APL compiles route YAML once at config
// load, a given route's `cel:` expression compiles a single time over the
// process lifetime.

pub mod activation;
pub mod error;
pub mod factory;
pub mod resolver;

pub use error::BuildError;
pub use factory::CelPdpFactory;
pub use resolver::{CelResolver, OnError};
