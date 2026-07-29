---
date: 2026-07-28
topic: opa-rego-pdp-builtin
---

# OPA/Rego PDP Builtin (regorus)

## Summary

Add an embedded OPA/Rego PDP builtin (`cpex-pdp-opa`), backed by the pure-Rust `regorus` interpreter, that evaluates Rego policy in-process and returns allow/deny — a fourth builtin PDP alongside cedar-direct, cel, and external OPA. Rego modules are declared globally and/or inline per route step; each step names the query; the request `AttributeBag` becomes the Rego `input`; external `data` tables load at build; and when a policy returns a rich decision object, its reason and violation fields flow into the CPEX policy violation on Deny.

---

## Problem Frame

Operators who have standardized on OPA/Rego have no in-process option in CPEX today. Their only choices are to rewrite policy in Cedar or CEL, or stand up an external OPA server and pay a network hop plus a sidecar to run on every request. Teams with existing, versioned Rego policy sets cannot reuse them without either a rewrite or operational overhead that the other builtin PDPs (cedar-direct, cel) do not impose. The gap is felt most by operators porting an established Rego policy base into a deployment model that otherwise runs entirely in-process.

`PdpDialect::Opa` already exists in apl-core but has no resolver behind it, so the dialect is declarable yet non-functional.

---

## Actors

- A1. Operator: owns the deployment. Configures the `global.pdp` block — declares the `opa` PDP, loads shared modules and external `data`, sets `on_error` and the decision-field name.
- A2. Policy author: writes the Rego modules and chooses each route step's query. May be the same person as the operator or a separate policy team owning a versioned policy set.

---

## Key Flows

- F1. Evaluate a request against embedded Rego
  - **Trigger:** A route with an `opa:` step reaches the PDP stage during request handling.
  - **Actors:** A1 (configured the engine), A2 (authored the policy)
  - **Steps:** The resolver maps the request `AttributeBag` into the Rego `input` document; resolves the step's inline module (if any) on top of the globally prepared modules and `data`; evaluates the step's query; interprets the result (boolean, or decision object) into allow/deny.
  - **Outcome:** The pipeline continues on allow, or raises a CPEX policy violation on deny carrying the policy's reason and any violations.
  - **Covered by:** R1, R4, R5, R6, R7, R8, R9

- F2. Load policy at configuration time
  - **Trigger:** Host calls `load_config_yaml`; the apl-cpex visitor finds a `kind: opa` block and dispatches to the factory.
  - **Actors:** A1
  - **Steps:** The factory reads the block, parses and prepares the global modules and `data` once, constructs the resolver. A parse error in a global module surfaces at load time.
  - **Outcome:** A ready `OpaResolver` is registered; the operator sees bad global policy at deploy time, not first request.
  - **Covered by:** R2, R3, R10

---

## Requirements

**Crate and wiring**
- R1. New crate `cpex-pdp-opa` providing `OpaResolver` implementing `PdpResolver` with `dialect() -> PdpDialect::Opa`, and `OpaPdpFactory` implementing `PdpFactory` with `kind() = "opa"`, built from the `global.pdp` config block. Mirrors the shape of `cpex-pdp-cel`.
- R2. The crate is apl-core-only at compile time; apl-cpex and cpex-core are dev-dependencies used only for end-to-end tests, matching cel and cedar-direct.
- R3. An optional `opa` feature in `cpex-builtins` pulls exactly this one crate (one feature → one crate), is registered in `builtin_pdps`, and is added to the `default` feature set.

**Policy source (hybrid)**
- R4. Rego modules may be declared in the global `pdp` block as module text and/or files. Global modules are parsed and prepared once at factory build (compile-once / eval-many).
- R5. Rego modules may also be supplied inline in an `opa:` route step. Inline modules are compiled and cached per distinct module source, with a bounded cache using the workspace "cap + reject + log, never evict" convention.
- R6. Global and inline modules are additive for a step's evaluation. A package-name collision between a global and an inline module is a loud fail-closed error, not a silent override.

**Inputs and data**
- R7. The request `AttributeBag` maps to the Rego `input` document, reusing the bag→nested-namespace mapping the CEL resolver already applies (flat dotted keys become nested `input` fields).
- R8. The global block can load external `data` documents (inline JSON and/or files) into the engine's `data` root at build, so policies can read static lookup tables (e.g. `data.roles[input.subject.id]`).

**Decision contract**
- R9. Each `opa:` step carries a required `query` (e.g. `data.authz.allow`); there is no implicit default query.
- R10. The query result may be a bare boolean or a decision object. A bare boolean is allow/deny directly. For an object, the allow/deny boolean is read from a decision field named `allow` by default, overridable in the config block.
- R11. On Deny, when the query returned a decision object, its human-readable fields enrich the CPEX policy violation: a `reason` or `message` string becomes the Deny `reason`; a `violations` or `errors` list appends to `PdpDecision.diagnostics`; a policy-supplied id field becomes the `rule_source` (else `"opa"`); and any remaining object fields are serialized into diagnostics so nothing the author returned is dropped. This reuses the same attribution channel cedar-direct uses for its policy-id reasons.
- R12. `on_error: deny | allow` governs degenerate runtime outcomes (undefined query result, non-boolean/absent decision field, eval error), defaulting to `deny`. A Rego parse/compile error always denies regardless of `on_error`, matching CEL's compile-vs-runtime asymmetry.

---

## Acceptance Examples

- AE1. **Covers R1, R4, R9, R10.** Given a route with an `opa:` step and a Rego module that allows the request, when the PDP step evaluates, then the resolver returns allow and the pipeline continues.
- AE2. **Covers R12.** Given an `opa` PDP configured with `on_error: deny`, when policy evaluation errors, then the request is denied.
- AE3. **Covers R11.** Given a policy whose query returns `{ "allow": false, "reason": "subject not in allowlist", "violations": [...] }`, when the step evaluates, then the request is denied and the Deny reason carries "subject not in allowlist" with the violations in diagnostics.
- AE4. **Covers R10, R12.** Given a query that resolves to a non-boolean and no recognized decision field, when the step evaluates under default `on_error`, then the outcome is treated as degenerate and denied.
- AE5. **Covers R12.** Given a global module with a Rego syntax error, when the config loads, then the parse error surfaces at configuration time (and any request that reaches such policy denies regardless of `on_error`).
- AE6. **Covers R8.** Given external `data` declaring `roles.alice = ["reader"]` and a policy that allows when the subject holds `reader`, when subject `alice` makes a request, then the request is allowed.

---

## Success Criteria

- An operator with an existing Rego policy set can drop a `kind: opa` block plus route `opa:` steps into their config and get in-process allow/deny decisions with no sidecar, no network hop, and no rewrite.
- Denials produced by rich Rego decision objects are legible in CPEX violations — the reason and violations reach the operator without re-running the policy under debug.
- A downstream implementer can build the crate from this doc without inventing product behavior: the policy-source model, input/data mapping, decision contract, and error semantics are all specified and anchored to existing cel/cedar precedent.

---

## Scope Boundaries

- External/remote OPA over HTTP, OPA bundles, and the OPA management API — this is the embedded path only; remote OPA remains its own dialect.
- Hot-reloading modules or `data` at runtime — configuration is loaded once at build, same as cedar-direct.
- Structured obligations/advice semantics beyond reason and violations text — v1 surfaces them as diagnostics but does not enforce obligations.
- Rego `print`/trace debug surfaces and custom builtin registration beyond what regorus provides by default.

---

## Key Decisions

- Hybrid policy source (global + inline modules) rather than global-only (cedar) or inline-only (cel): supports both central versioned policy sets and quick per-route rules, at the cost of a larger config and test surface than either single model.
- Decision contract accepts an object, not just a boolean: lets rich Rego decisions map onto the existing `Decision::Deny { reason, rule_source }` + `diagnostics` fields, giving operators legible violations instead of an opaque deny — the same benefit cedar's policy-id attribution provides.
- Default decision field `allow`, overridable: matches the most common Rego convention (`default allow = false`) while not forcing it on policies that name the field differently.
- `regorus` (Apache-2.0, pure Rust): no sidecar, no C/network dependency, and no `deny.toml` license allow-list change.
- Fail-closed defaults mirroring cel/cedar: `on_error` defaults to deny; parse/compile errors are never flippable to allow.

---

## Dependencies / Assumptions

- `PdpDialect::Opa` and `PdpDialect::from_key("opa")` already exist in apl-core (verified) and only need a resolver behind them.
- `regorus` is not yet in the workspace `Cargo.lock` (verified absent) and will be added as a dependency of the new crate.
- The bag→nested-namespace mapping in the cel resolver's `activation.rs` is a reusable template for building the Rego `input` document; the exact reuse mechanism (shared helper vs. crate-local port) is a planning decision.

---

## Outstanding Questions

### Deferred to Planning

- [Affects R7][Technical] Whether the bag→`input` mapping is factored into a shared helper or ported into the opa crate, and how `StringSet`/float/int types translate into regorus values.
- [Affects R5, R6][Technical] Exact inline-module cache key and the precise collision-detection point (load vs. eval) for global-vs-inline package clashes.
- [Affects R11][Needs research] regorus's result surface for object-valued queries and undefined results — how to distinguish "undefined" from "false" from "object" in its return type.
- [Affects R8][Technical] Config shape for `data` (inline map vs. `data_files` list) and file-path resolution relative to the config.
