// Location: ./builtins/pdps/cel/src/lib.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// cpex-pdp-cel — `PdpResolver` over the `cel` (Common Expression Language)
// interpreter.
//
// # Where this lives in the stack
//
//   APL evaluator (apl-core)
//        │  `cel: { expr: "..." }` step
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
// The canonical step form is the block-map shown above (`cel: { expr:
// "..." }`); it's what the integration tests and most policies use. The
// parser also accepts the call form `cel:(expr: "...")` — both compile to
// the same `PdpCall`. Prefer the map form in new policy: it reads cleanly
// when the `expr` spans multiple lines.
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
// fail-closed default). Operators can flip a *runtime* error
// (undeclared variable, type error, non-boolean) to allow-through via
// `on_error: allow` in the PDP config block, but the default is `deny`.
// Compile errors are never flippable — see `resolver::OnError`.
//
// "Non-boolean" means the expression's top-level value is anything other
// than `true`/`false`. Common author mistakes:
//
//   - `subject.id`                  → a string  → degenerate → Deny
//   - `delegation.depth`            → an int    → degenerate → Deny
//   - `subject.roles`               → a list    → degenerate → Deny
//   - `has(session.token) ? 1 : 0`  → an int    → degenerate → Deny
//
// Note CEL `null` is its own value, distinct from `false`: an expression
// that yields `null` (e.g. an optional field selected without a guard) is
// non-boolean and therefore Deny under the default — it is NOT treated as
// a `false` policy decision. Guard optional fields with `has(...)` and
// compare explicitly (`has(role.reader) && role.reader`) so the result is
// always a real boolean.
//
// # CEL vs Cedar (which backend?)
//
// Reach for **cel** when the decision is a self-contained boolean
// predicate over the common attribute vocabulary, authored inline in the
// route YAML, with no external policy store — relevance / consistency /
// lightweight ABAC. Reach for **cedar / opa** when policy
// lives outside the route (versioned/signed policy sets, central
// management) or needs the full entity/relationship model. CEL trades
// Cedar's policy-set machinery for zero-glue, in-line expressiveness.
//
// # Synchronous by design
//
// CEL evaluation here is synchronous and side-effect-free — no network,
// no I/O, no async. That's deliberate: attribute resolution and any
// side-effecting work (remote lookups, credential exchange) belong in APL
// plugin steps that populate the bag *before* the `cel:` step runs. There
// is no async-CEL path, and custom functions registered via
// `CelResolver::with_functions` should likewise stay pure and fast — they
// run inline on every evaluation while the activation context is held.
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
