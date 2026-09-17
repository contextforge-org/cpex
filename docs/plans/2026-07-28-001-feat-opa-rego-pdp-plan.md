---
title: "feat: OPA/Rego PDP builtin (regorus)"
type: feat
status: completed
date: 2026-07-28
deepened: 2026-07-29
origin: docs/brainstorms/opa-rego-pdp-builtin-requirements.md
---

# feat: OPA/Rego PDP builtin (regorus)

## Summary

Build a new `cpex-pdp-opa` crate that evaluates Rego in-process via `regorus`, mirroring `cpex-pdp-cel`'s layout. The resolver prepares a base `regorus::Engine` at factory build (global modules + `data`), then clones it per request to set `input` and evaluate the query — sidestepping regorus's `&mut self` eval with cheap Rc/Arc-backed clones. Inline modules use a bounded inline-module cache of prepared engines; wiring touches the root `Cargo.toml`, `cpex-builtins`, and nothing in apl-core.

---

## Problem Frame

Operators standardized on OPA/Rego have no in-process PDP option in CPEX today — only Cedar, CEL, or an external OPA server over HTTP. `PdpDialect::Opa` exists in apl-core but has no resolver behind it. See origin for the full motivation and product decisions (`docs/brainstorms/opa-rego-pdp-builtin-requirements.md`).

---

## Requirements

**Crate and wiring**
- R1. New crate `cpex-pdp-opa` with `OpaResolver` (`dialect() -> PdpDialect::Opa`) and `OpaPdpFactory` (`kind() = "opa"`), built from the `global.pdp` block. (origin R1)
- R2. Crate is apl-core-only at compile time; apl-cpex/cpex-core are dev-deps for e2e tests. (origin R2)
- R3. Optional `opa` feature in `cpex-builtins` pulls exactly this crate, registered in `builtin_pdps`, added to `default`. (origin R3)

**Policy source (hybrid)**
- R4. Modules declarable globally (text and/or files), parsed once at factory build. (origin R4)
- R5. Modules also suppliable inline in the `opa:` step, compiled-cached per distinct source with a bounded cap+reject+log cache. (origin R5)
- R6. Global + inline modules are additive and merge per Rego package semantics (same-package modules combine, as in OPA); the resolver does not treat package reuse as an error. (origin R6, reframed — Rego package merge is legitimate, not a collision)

**Inputs and data**
- R7. `AttributeBag` → Rego `input`, reusing CEL's nested-namespace mapping. (origin R7)
- R8. Global block loads external `data` (inline JSON and/or files) into the engine's `data` root at build. (origin R8)

**Decision contract**
- R9. Each `opa:` step carries a required `query`; no implicit default. (origin R9)
- R10. Query result may be a bare boolean, a decision object, or a set/array. Boolean is allow/deny directly. An object's allow/deny bit comes from a field named `allow` by default, overridable in config. A set/array follows the deny-set/violation-set idiom: empty → allow, non-empty → deny (elements become violations). (origin R10, extended to cover set/array so `deny[msg]`-style policies work without a wrapping query)
- R11. On Deny from a decision object, reason/message → Deny `reason`; violations/errors list → diagnostics; policy-supplied id → `rule_source` (else `"opa"`); remaining fields serialized into diagnostics. For a set/array deny, the elements become the violations in diagnostics. (origin R11)
- R12. `on_error: deny | allow` (default deny) governs genuine runtime errors and non-boolean/non-object/non-set degenerate values; parse/compile errors always deny. An undefined query result is a clean deny independent of `on_error` (matching OPA's undefined-is-not-granted semantics), not a degenerate outcome. (origin R12)

**Origin actors:** A1 (operator — configures global block), A2 (policy author — writes Rego + query)
**Origin flows:** F1 (evaluate a request against embedded Rego), F2 (load policy at configuration time)
**Origin acceptance examples:** AE1 (allow), AE2 (deny on error), AE3 (rich object deny), AE4 (non-boolean degenerate), AE5 (parse error at load), AE6 (external data)

---

## Scope Boundaries

- External/remote OPA over HTTP, bundles, management API — embedded path only.
- Hot-reloading modules or `data` at runtime — config loaded once at build.
- Structured obligations/advice enforcement beyond reason + violations text.
- Rego `print`/trace debug surfaces and custom builtin registration beyond regorus defaults.

### Deferred to Follow-Up Work

- Merging extra `opa:` step keys (beyond `query`/`module`) into the `input` document: future iteration — v1 `input` is bag-derived only.
- regorus `compile_with_entrypoint`/`CompiledPolicy` precompiled-artifact path: revisit only if profiling shows clone-per-request is too costly.

---

## Context & Research

### Relevant Code and Patterns

- `builtins/pdps/cel/src/lib.rs`, `resolver.rs`, `factory.rs`, `activation.rs`, `error.rs` — the closest template for crate layout, compile cache (`DEFAULT_MAX_CACHE_ENTRIES`, cap+reject+log), `on_error`, bag→nested mapping, and the `KNOWN_KEYS` config-rejection loop + `on_error` parse (`resolver.rs:215-249`).
- `builtins/pdps/cedar-direct/src/resolver.rs:118-172` — text-vs-file tuple pattern for `policy_text`/`policy_file` and `schema_text`/`schema_file`; `read_yaml_string` helper (`:262-266`). Mirror for `modules`/`module_files` and `data`/`data_files`.
- `builtins/pdps/cedar-direct/src/decision.rs:53-123` — decision mapping: `diagnostics` = full firing vector, `rule_source` = first (with fallback), `reason` = `Some(String)`.
- `builtins/pdps/cedar-direct/src/error.rs:26-67` — `BuildError` shape (`ConfigShape`, `PolicyFile { path, source }`, `PolicyParse`, etc.).
- `crates/apl-core/src/evaluator.rs:26-35` — `Decision::{Allow, Deny { reason: Option<String>, rule_source: String }}`.
- `crates/apl-core/src/step.rs` — `PdpDecision { decision, diagnostics: Vec<String> }` (`:808`), `PdpResolver`/`PdpFactory` traits (`:337`, `:364`), `PdpDialect::Opa` + `from_key("opa")` already present (`:300`, `:322`).
- `crates/apl-core/src/attributes.rs:32-40, 79-159` — `AttributeValue::{Bool,Int,Float,String,StringSet}`; `AttributeBag::iter()` yields `(&str, &AttributeValue)`.
- `crates/cpex-builtins/src/lib.rs:37-40, 98-105, 149-157` — re-export, `builtin_pdps()` pushes, factory-count test — every wiring edit site.
- `builtins/pdps/cel/tests/visitor_cel_config.rs` — full e2e harness (`build_manager_with_yaml` at `:83-106`, `AplOptions` field set, request construction, allow/deny assertions, negative config test at `:169-194`).

### Institutional Learnings

- No `docs/solutions/` knowledge base exists in this repo; the cel/cedar crates are the authoritative prior art. (A scratch note `.sketchpad/new_issue_opa-pdp.md` exists but is an unvetted draft.)

### External References

- regorus 0.11.0 (crates.io, docs.rs). Tri-licensed `MIT AND Apache-2.0 AND BSD-3-Clause` — Apache-2.0 is on `deny.toml`'s allow-list; pure Rust in the default build; published on crates.io (satisfies `deny.toml`'s crates.io-only source rule).
- Key API facts driving the design:
  - `Engine::new()`; `add_policy(path: String, rego: String) -> Result<String>` (incremental, `&mut self`); `add_data_json(&str) -> Result<()>` / `add_data(Value)` (merges, conflicts error).
  - `set_input(Value)` / `set_input_json(&str)` and **all `eval_*` methods take `&mut self`** — no shared-immutable eval path.
  - `Engine: Clone`, cheap (Rc/Arc-backed); the `arc` feature makes it `Send`/`Sync`.
  - `eval_rule("data.authz.allow".into()) -> Result<Value>`; non-matching query → `Value::Undefined` (distinct from `Value::Bool(false)`).
  - `Value::{Null,Bool,Number,String,Array,Set,Object,Undefined}` with `as_bool`/`as_object`/`as_string`/`to_json_str` helpers.
  - Errors are type-erased `anyhow::Error`: parse/compile errors surface at `add_policy` time, runtime errors at `eval` time — distinguishable only by call site.

---

## Key Technical Decisions

- **Base engine + clone-per-request concurrency model.** The resolver holds one base `Engine` prepared with global modules + `data`. `evaluate` clones the base, sets input, evaluates. Chosen over a mutex (serializes requests) or an engine pool (added complexity) because clones are Rc/Arc-cheap. Requires enabling regorus's `arc` feature so `OpaResolver` is `Send`/`Sync` as `PdpResolver` demands.
- **`eval_rule` as the evaluation entry point**, not `eval_bool_query`/`eval_allow_query`, because it returns `Value::Undefined` distinctly — required to separate undefined from a legitimate `false`.
- **Parse-vs-runtime classification by call site.** Since regorus uses `anyhow`, we cannot match error variants. A failure at `add_policy` time is a compile error → always deny (mirrors CEL's `compile_error_decision`); a failure at `eval` time is a runtime error → routes through `on_error`. Global modules therefore fail at config load (fail-fast startup); inline modules fail at cache-build.
- **Undefined → clean Deny, independent of `on_error`.** An undefined query result is Rego's idiomatic "not granted" path (an `allow` rule with no `default` that didn't match), so it denies unconditionally rather than routing through `on_error`. Routing it through `on_error` would let `on_error: allow` flip an ordinary non-match to Allow, inverting Rego's safe-by-default semantics. `on_error` is reserved for genuine eval errors and non-bool/non-object/non-set degenerate values.
- **Decision contract accepts set/array (deny-set idiom).** Beyond boolean and object, a set/array result is interpreted empty-means-allow / non-empty-means-deny, so `deny[msg]`/`violation[...]` policies (Gatekeeper, conftest) work as-is without a wrapping `allow { count(deny)==0 }` query. This preserves the "drop in existing Rego, no rewrite" success criterion for the dominant Rego authoring style.
- **Package reuse is not a collision.** Global and inline modules merge per Rego package semantics (same-package modules combine, as OPA does natively); the resolver does not treat package-name reuse as an error, because that is normal Rego, not a fault.
- **Planning IDs stay out of the codebase.** R#/U#/AE#/F# identifiers and references to this plan or the origin requirements doc must not leak into commit messages, source, rustdocs, or test names — the code and its history must read as self-contained. Traceability lives in this plan only.
- **Bag→input logic ported from CEL's `activation.rs`** into the opa crate (not a shared helper — keeps the crate apl-core-only and avoids coupling), emitting a regorus input object and preserving CEL's StringSet→sorted-array and whole-float→int coercions.
- **Config parsing = cedar's text-vs-file tuple matching + CEL's `KNOWN_KEYS` rejection + `on_error` match**, extended to `["kind", "modules", "module_files", "data", "data_files", "decision_field", "on_error"]`.
- **regorus pinned with `default-features = false` + explicit feature allow-list.** regorus's `default` (`full-opa`) enables `http.send`, `net`, `opa.runtime`, `jsonschema`, and a `mimalloc` C allocator. The PDP opts out and enables only what it needs, keeping the build pure-Rust (so the `deny.toml` license posture holds) and denying inline policy authors network/environment builtins — mirroring the CEL crate's explicit-feature rationale. The `http`/`net`/`opa-runtime` exclusion is a security default, not a size optimization.

---

## Open Questions

### Resolved During Planning

- Concurrency under regorus's `&mut self` eval: resolved — base engine + clone-per-request with the `arc` feature.
- How to distinguish undefined from false: resolved — `eval_rule` returns `Value::Undefined`.
- Parse vs runtime error classification: resolved — by call site, not error variant.
- regorus license/source acceptability: resolved — Apache-2.0, crates.io, no `deny.toml` change (pure-Rust build preserved by pinning `default-features = false`, which drops the `mimalloc` C allocator).
- Set/array (deny-set) query results: resolved — supported in v1 as empty-means-allow / non-empty-means-deny (R10).
- Undefined query result: resolved — clean Deny independent of `on_error` (R12), not a degenerate outcome.
- Global-vs-inline "package collision": resolved — not an error; same-package modules merge per Rego semantics (R6 reframed).

### Deferred to Implementation

- Exact inline-module cache key (raw source string vs. normalized) and whether the cached unit is a prepared `Engine` clone or the module text re-added on each base clone — settle when wiring the cache against the real API.
- Exact `regorus::Value` → diagnostics rendering for unrecognized decision-object fields and for set/array elements (likely `to_json_str`), confirmed against the real `Value` API during implementation.
- Whether a set/array result is distinguished from an object result via `Value::Set`/`Value::Array` vs `Value::Object` matching — confirm regorus's `Value` variants for a `deny[msg]` set at eval time.
- Whether input is built as a `regorus::Value` directly or via a JSON string + `set_input_json` — pick the path that best surfaces construction correctness.

---

## Output Structure

    builtins/pdps/opa/
    ├── Cargo.toml
    ├── src/
    │   ├── lib.rs          # crate docs + module re-exports
    │   ├── factory.rs      # OpaPdpFactory (kind = "opa")
    │   ├── resolver.rs     # OpaResolver: base engine, clone-per-request, decision contract, on_error
    │   ├── input.rs        # AttributeBag -> regorus input (ported from cel activation.rs)
    │   ├── decision.rs     # Value (bool | object) -> PdpDecision; rich-object -> violation mapping
    │   └── error.rs        # BuildError
    └── tests/
        └── visitor_opa_config.rs   # e2e: YAML -> visitor -> factory -> resolver -> allow/deny

---

## Implementation Units

**Cross-cutting constraint (all units):** Requirement and plan-document identifiers (R#, U#, AE#, F#) and references to these planning documents must NOT appear in commit messages, source code, rustdoc comments, or test names. Code and commits stand on their own — describe the behavior, not the plan artifact. These IDs are traceability aids for planning and review only. (The `Requirements`/`Covers AE#` annotations in the units below live in this plan; they do not travel into the diff.)

- U1. **Scaffold the crate and wire it into the workspace**

**Goal:** Create `cpex-pdp-opa` as an empty-but-compiling crate registered in the workspace and `cpex-builtins`, so later units build against real wiring.

**Requirements:** R1, R2, R3

**Dependencies:** None

**Files:**
- Create: `builtins/pdps/opa/Cargo.toml`
- Create: `builtins/pdps/opa/src/lib.rs` (module stubs + re-exports)
- Modify: `Cargo.toml` (root) — add `builtins/pdps/opa` to `[workspace] members` and `default-members`, and add `cpex-pdp-opa = { path = "builtins/pdps/opa", version = "0.2.2" }` to `[workspace.dependencies]`
- Modify: `crates/cpex-builtins/Cargo.toml` — add `opa = ["dep:cpex-pdp-opa"]` feature, add `"opa"` to `default`, add `cpex-pdp-opa = { workspace = true, optional = true }`
- Modify: `crates/cpex-builtins/src/lib.rs` — `#[cfg(feature = "opa")] pub use cpex_pdp_opa::OpaPdpFactory;`, push in `builtin_pdps()`, add `+ cfg!(feature = "opa") as usize` to the factory-count test

**Approach:**
- Mirror `builtins/pdps/cel/Cargo.toml`: inherit workspace package fields, `apl-core`/`async-trait`/`serde_yaml`/`thiserror`/`tracing` as workspace deps, `apl-cmf`/`apl-cpex`/`cpex-core`/`tokio` as dev-deps, `[lints] workspace = true`.
- Pin `regorus = { version = "0.11", default-features = false, features = ["arc", ...] }`. `default-features = false` is deliberate: regorus's `default` set (`full-opa`) enables `http.send`, `net`, `opa.runtime`, `jsonschema`, and the `mimalloc` C allocator. Enable `arc` (load-bearing — without it the base `Engine` is not `Send`/`Sync`) plus only the minimal builtin features the PDP needs, and **exclude** `http`, `net`, and `opa-runtime` so inline policy authors (the less-trusted A2 actor) cannot reach network egress or environment introspection. Enumerate the exact feature list against regorus 0.11's feature table during implementation, mirroring how `builtins/pdps/cel/Cargo.toml` pins CEL features explicitly with a comment. Add `serde_json` if the input path uses JSON.
- Do NOT edit apl-core: `PdpDialect::Opa` and `from_key("opa")` already exist.

**Patterns to follow:**
- `builtins/pdps/cel/Cargo.toml`, `builtins/pdps/cedar-direct/Cargo.toml`, root `Cargo.toml` members/default-members/dependencies blocks, `crates/cpex-builtins/src/lib.rs:37-40, 98-105, 149-157`.

**Test scenarios:**
- Integration: `cargo build -p cpex-pdp-opa` and `cargo build -p cpex-builtins --features opa` compile.
- Covers AE (wiring precondition for all): the `cpex-builtins` factory-count test passes with `opa` enabled, asserting `builtin_pdps()` includes the opa factory.

**Verification:**
- Workspace builds with the new crate; `cpex-builtins` default features include `opa`; factory-count test green.

---

- U2. **AttributeBag → Rego input mapping**

**Goal:** Translate the flat dotted `AttributeBag` into a nested regorus `input` document.

**Requirements:** R7

**Dependencies:** U1

**Files:**
- Create: `builtins/pdps/opa/src/input.rs`
- Modify: `builtins/pdps/opa/src/lib.rs` (expose module)

**Approach:**
- Port CEL's `activation.rs` tree-builder: split dotted keys into nested maps; namespace-wins-on-leaf-collision with a `tracing::warn!`.
- Map `AttributeValue`: `Bool`/`Int`/`Float`/`String` to scalars; `StringSet` to a sorted array (stable indexing); whole-number `Float` coerced to integer, matching CEL's `float_to_value`.
- Emit a regorus input object (build `regorus::Value` directly, or a `serde_json::Value`/JSON string fed to `set_input_json` — see deferred question).

**Patterns to follow:**
- `builtins/pdps/cel/src/activation.rs` (tree build, collision rule, type coercions).

**Test scenarios:**
- Happy path: dotted keys (`subject.id`, `subject.type`) become nested fields readable as `input.subject.id`.
- Happy path: `Bool`/`Int`/`Float`/`String` scalars round-trip to the right regorus value.
- Edge case: `StringSet` becomes a sorted array; `input.session.labels[0]` is deterministic.
- Edge case: whole-number float (`2.0`) maps to an integer so `input.delegation.depth == 2` holds.
- Edge case: leaf/namespace collision (`delegation` scalar + `delegation.depth`) resolves namespace-wins.
- Edge case: empty bag produces an empty (but valid) input object.

**Verification:**
- Unit tests build an input from a bag and assert a small Rego snippet reads the expected nested fields.

---

- U3. **Config parsing and base-engine preparation (`from_config`)**

**Goal:** Parse the `global.pdp` block and build a base `Engine` loaded with global modules and external `data`, failing loudly at load on bad config or unparseable Rego.

**Requirements:** R4, R6, R8, R10, R12

**Dependencies:** U1

**Files:**
- Create: `builtins/pdps/opa/src/error.rs` (`BuildError`)
- Create: `builtins/pdps/opa/src/resolver.rs` (`OpaResolver`, `OnError`, `from_config`, base-engine field)
- Modify: `builtins/pdps/opa/src/lib.rs`

**Approach:**
- `BuildError` mirrors cedar's: `ConfigShape(String)`, `ModuleFile { path, source }`, `ModuleParse(String)`, `DataFile { path, source }`, `DataParse(String)`.
- `from_config`: require a mapping; reject unknown keys via a `KNOWN_KEYS` loop (`["kind", "modules", "module_files", "data", "data_files", "decision_field", "on_error"]`); parse `on_error` (`deny`|`allow`, default deny) exactly as CEL; read `decision_field` (default `allow`).
- Modules: accept `modules` (list of inline text) and/or `module_files` (list of paths, read via `std::fs::read_to_string` → `ModuleFile`). Add each to the base engine via `add_policy`; a parse failure here is a load-time `ModuleParse` error (fail-fast startup).
- Data: accept `data` (inline mapping serialized to JSON) and/or `data_files`; load via `add_data_json`/`add_data`; a merge conflict is a load error.
- Store the prepared base `Engine`, `on_error`, and `decision_field` on the resolver, plus an empty inline-module cache field whose get-or-build semantics are defined in U4.

**Patterns to follow:**
- `builtins/pdps/cedar-direct/src/resolver.rs:118-172` (text-vs-file tuple, file-read error mapping), `builtins/pdps/cel/src/resolver.rs:215-249` (KNOWN_KEYS + on_error), `builtins/pdps/cedar-direct/src/error.rs`.

**Test scenarios:**
- Happy path: config with one inline module + one data block builds a resolver.
- Covers AE6: external `data` (`roles.alice = ["reader"]`) loads and is readable by a policy.
- Covers AE5: a module with a Rego syntax error yields a `BuildError::ModuleParse` at `from_config`.
- Error path: unknown key (`on_errr`) rejected with a message naming the key.
- Error path: `on_error: maybe` rejected; `on_error: allow` parses to `OnError::Allow`.
- Error path: `module_files` path that doesn't exist → `ModuleFile` error naming the path.
- Edge case: `decision_field` override is read and stored.

**Verification:**
- Unit tests cover build success, each config-shape rejection, and load-time parse failure.

---

- U4. **Decision contract: evaluate query and map result (incl. rich objects)**

**Goal:** Implement `PdpResolver::evaluate` — clone the base (plus any inline module), set input, `eval_rule` the query, and map `Value` (boolean, object, set/array, or undefined) to a `PdpDecision`, honoring `on_error`.

**Requirements:** R5, R6, R9, R10, R11, R12

**Dependencies:** U2, U3

**Files:**
- Create: `builtins/pdps/opa/src/decision.rs` (Value → PdpDecision, rich-object mapping)
- Modify: `builtins/pdps/opa/src/resolver.rs` (`evaluate`, inline-module cache, `dialect()`)
- Modify: `builtins/pdps/opa/src/lib.rs`

**Approach:**
- Read `query` (required) and optional `module` from `call.args`; a missing `query` is a `PdpError::Dispatch` (author bug), mirroring CEL's missing-`expr`.
- Inline module path: get-or-build a prepared engine (base clone + `add_policy(inline)`) from a bounded cache keyed by module source (cap+reject+log, never evict). `add_policy` failure here = compile error = always deny. A same-package inline module merges with the global module per Rego semantics — this is expected, not an error.
- No inline module: clone the base directly.
- Set input (from U2), `eval_rule(query)`:
  - `Value::Bool(true)` → Allow; `Value::Bool(false)` → Deny (`reason` "query evaluated to false", `rule_source` "opa").
  - `Value::Object` → read `decision_field` (default `allow`) as bool. `true` → Allow. `false`/deny → build Deny and enrich: `reason`/`message` string → Deny `reason`; `violations`/`errors` array → diagnostics; policy id field → `rule_source` (else "opa"); remaining fields serialized (e.g. `to_json_str`) into diagnostics.
  - `Value::Set`/`Value::Array` (deny-set idiom) → empty → Allow; non-empty → Deny with the elements as violations in diagnostics (`rule_source` "opa").
  - `Value::Undefined` → clean Deny (`reason` "query undefined — not granted", `rule_source` "opa"), independent of `on_error`.
  - missing/non-bool decision field on an object, or any other non-bool/non-object/non-set value → degenerate → `on_error`.
  - `Err(...)` from eval → runtime error → `on_error`.
- `on_error` decision + compile-error decision helpers mirror CEL (`error!` logging on allow-through and on compile errors).

**Technical design:** *(directional guidance, not implementation spec)*

    eval_rule(query) ->
      Bool(true)                      => Allow
      Bool(false)                     => Deny{reason, rule_source:"opa"}
      Object(o) => match o[decision_field].as_bool()
                     Some(true)       => Allow
                     Some(false)      => Deny + enrich(o)   // reason/message, violations, id, rest
                     None             => on_error(degenerate)
      Set/Array empty                 => Allow
      Set/Array non-empty             => Deny{violations: elements, rule_source:"opa"}
      Undefined                       => Deny{reason:"undefined — not granted"}  // NOT on_error
      other (non-bool/object/set)     => on_error(degenerate)
      Err(e)                          => on_error(runtime)
    // add_policy(inline) failure     => compile error => always Deny
    // same-package global+inline modules merge (Rego semantics) — not an error

**Patterns to follow:**
- `builtins/pdps/cel/src/resolver.rs` (`evaluate`, `on_error_decision`, `compile_error_decision`, compile cache cap+reject+log), `builtins/pdps/cedar-direct/src/decision.rs` (diagnostics/rule_source/reason contract).

**Test scenarios:**
- Covers AE1: boolean-`true` policy → Allow, pipeline continues.
- Happy path: boolean-`false` policy → Deny with `rule_source` "opa".
- Covers AE3: object `{ allow:false, reason:"...", violations:[...] }` → Deny; reason carried, violations in diagnostics.
- Happy path: object with a policy id field → `rule_source` is that id.
- Edge case: object `{ allow:true }` → Allow.
- Happy path (deny-set idiom): a `deny[msg]` policy with an empty deny set → Allow; with a non-empty deny set → Deny with the messages as violations in diagnostics.
- Covers AE4: object with a missing/non-bool decision field, or any other non-bool/object/set value, under default `on_error` → Deny (degenerate).
- Covers AE2: eval runtime error under `on_error: deny` → Deny; under `on_error: allow` → Allow.
- Edge case: `Value::Undefined` (no matching rule, no `default`) → clean Deny even under `on_error: allow` (undefined does not fail open).
- Error path: inline module with a syntax error → always Deny even with `on_error: allow`.
- Error path: missing `query` in step args → `PdpError::Dispatch`.
- Edge case: inline-module cache cap reached → new module rejected → routed through `on_error`; cached module still evaluates.
- Integration: a same-package inline module merges with a global module (Rego semantics) and can reference a global-module/`data` value — no error on package reuse.
- Concurrency: many threads sharing one `Arc<OpaResolver>` evaluate the same query and get correct per-request decisions (exercises clone-per-request under the `arc` feature).

**Verification:**
- Unit tests cover every branch of the decision map, on_error both ways, compile-vs-runtime asymmetry, cache cap, and concurrent evaluation.

---

- U5. **End-to-end visitor wiring test**

**Goal:** Prove an operator dropping a `kind: opa` block plus an `opa:` route step into YAML gets a real allow/deny decision through the apl-cpex visitor, with no Rust glue.

**Requirements:** R1, R3, R9 (and exercises AE1, AE2)

**Dependencies:** U4

**Files:**
- Create: `builtins/pdps/opa/tests/visitor_opa_config.rs`

**Approach:**
- Mirror `builtins/pdps/cel/tests/visitor_cel_config.rs`: `build_manager_with_yaml` wiring `pdp_factories: vec![Arc::new(OpaPdpFactory::new())]` in the full `AplOptions` field set; `load_config_yaml`; `initialize`; construct a request with `SecurityExtension`/`MetaExtension`; invoke `cmf.tool_pre_invoke`; assert on `continue_processing` and `violation`.
- YAML declares `global.apl.pdp: [{ kind: opa, modules: [ ... ] }]` and a route `opa: { query: "data.authz.allow" }`.
- Include a negative config test: malformed `on_error` (or unknown key) rejected at `load_config_yaml`.

**Patterns to follow:**
- `builtins/pdps/cel/tests/visitor_cel_config.rs` end to end.

**Test scenarios:**
- Covers AE1: allow — subject the policy permits → `continue_processing` true.
- Covers AE2 / R12: a route whose query errors or denies → `continue_processing` false, `violation` present.
- Error path: malformed config rejected at load with a message naming the offending field.

**Verification:**
- `cargo test -p cpex-pdp-opa` green; the resolver is built by the visitor from YAML, never constructed directly in the test.

---

## System-Wide Impact

- **Interaction graph:** New PDP dialect on the existing `PdpRouter` dispatch path; no change to routing logic — `PdpDialect::Opa` already routes. Only new registration in `cpex-builtins`.
- **Error propagation:** Config/parse errors surface at `load_config_yaml` (via `BuildError` → visitor → `PluginError::Config`); runtime/degenerate outcomes become `PdpDecision` Deny/Allow, never panics.
- **State lifecycle risks:** Per-request engine clones are isolated; no shared mutable state. The inline-module cache grows bounded (cap+reject+log, never evict).
- **API surface parity:** Mirrors cel/cedar's `PdpResolver`/`PdpFactory` contract exactly; `on_error` semantics identical to cel.
- **Integration coverage:** The e2e visitor test (U5) proves the YAML→decision path that unit tests can't.
- **Unchanged invariants:** apl-core is untouched (`PdpDialect::Opa` pre-exists); cel/cedar crates and tests are unchanged; `deny.toml` unchanged (regorus is Apache-2.0 on the allow-list, crates.io-sourced).

---

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| regorus 0.11 API differs from researched signatures (owned `String` args, `enable_tracing` arity, `arc` feature name) | U1 pins the version and enables `arc`; adapt call sites against docs.rs 0.11 during implementation; deferred questions flag the uncertain spots. |
| Clone-per-request cost under load | Clones are Rc/Arc-backed and cheap by design; `compile_with_entrypoint` is a documented fallback if profiling demands it (deferred). |
| A transitive regorus dep carries a non-allow-listed license | Run `cargo deny check` (make audit) in U1; if a transitive license is off-list, surface it before merge — do not silently edit `deny.toml`. |
| `add_policy` on a per-request clone re-parses inline modules (perf) | Inline-module cache holds prepared engines so parsing happens once per distinct source, not per request. |

---

## Sources & References

- **Origin document:** [docs/brainstorms/opa-rego-pdp-builtin-requirements.md](docs/brainstorms/opa-rego-pdp-builtin-requirements.md)
- Related code: `builtins/pdps/cel/`, `builtins/pdps/cedar-direct/`, `crates/cpex-builtins/src/lib.rs`, `crates/apl-core/src/step.rs`, `crates/apl-core/src/evaluator.rs`, `crates/apl-core/src/attributes.rs`
- Related issue: contextforge-org/cpex#137
- External docs: regorus 0.11.0 — https://docs.rs/regorus/0.11.0/regorus/struct.Engine.html , https://crates.io/crates/regorus
