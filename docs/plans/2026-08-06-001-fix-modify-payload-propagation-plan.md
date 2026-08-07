---
title: "fix: propagate plugin payload mutations exactly instead of inferring them"
type: fix
status: implemented
date: 2026-08-06
origin: https://github.com/contextforge-org/cpex/issues/151
---

## Implementation Note

One premise in this plan was wrong, and the fix is larger than planned because of it.

The plan (following the issue) assumed `CmfPluginInvoker` already knew whether a plugin returned a mutation, because `result.modified_payload` is `Some` in that case. It isn't a signal: `PipelineResult::allowed_with` sets `modified_payload: Some(payload)` on **every** allowed pipeline, carrying the final payload whether or not any plugin touched it. Reading `is_some()` reports a mutation on every request.

Acceptance is only observable inside `Executor::run_serial_phase`, at `*payload = mp`. So the signal is recorded there and surfaced as a new `PipelineResult::payload_modified` field, which the invoker reads. That contradicts this plan's "no change to the executor" scope boundary; the alternative was comparing serialized payloads, which is both slower and back to inferring. Hosts get the same exact signal as a side effect.

This also exposed a fourth bug the plan didn't predict: because the old code keyed off `modified_payload.is_some()`, **every** `plugin(...)` stage in a field pipeline reported a new field value, mutation or not — so a non-mutating plugin stage overwrote its field with the message's concatenated text. Fixed by the same gate.

Two smaller deviations:

- U4 and U5 landed in one commit. Switching the branch conditions to the decision's flags leaves `pre_args` / `pre_result` unused until the merge consumes them, so splitting them would mean committing code that doesn't compile.
- The field readback reports no change when the field's value is unchanged, not only when the field is absent. Returning the current value would mark the field replaced on every mutating dispatch, which sets `args_modified` and forces a needless write-back.

# fix: propagate plugin payload mutations exactly instead of inferring them

## Summary

`AplRouteHandler::invoke` decides whether to emit `modified_payload` by diffing `Message::get_text_content()` before and after route evaluation (`crates/apl-cpex/src/route_handler.rs:478`). That accessor reads only `ContentPart::Text`, so a plugin that mutates a `ToolResult`, `ToolCall`, `Resource`, `Thinking`, or any other non-text variant produces a payload the handler classifies as unchanged and drops. The plugin reports success and the host forwards the original bytes.

The reported bug is one instance of a pattern that repeats three more times in the same twenty lines: mutation is *inferred* from values rather than *signalled* by the code that performed it. This plan fixes all four instances.

1. Direct `modify_payload` mutations are detected by a text diff, so non-text mutations are dropped. (the reported bug)
2. The `args:` write-back replaces `ToolCall.arguments` wholesale, so a pipeline edit silently clobbers a plugin's argument mutation. The `result:` write-back has the same shape.
3. Pipeline modification is detected by re-extracting and diffing, even though `RouteDecision` already carries `args_modified` / `result_modified` and the handler ignores them.
4. A plugin invoked as a pipeline field stage reports its new field value as `Value::String(get_text_content())`, which is wrong for any structured field: a per-key stage on `args.city` gets back the concatenation of every text part in the message.

Every fix replaces an inference with the signal that already exists at the site that knows the answer.

---

## Documentation and Traceability Constraint

**Applies to every unit below, without exception.**

Identifiers from this plan and from any requirements document (`R1`, `U2`, `D3`, `AE4`, and any similar scheme) must not appear in:

- source code or code comments
- rustdoc / doc comments
- test names or test comments
- commit messages
- the PR title, description, or review replies
- `CHANGELOG.md`

Doc IDs are planning artifacts. They are noise to a future reader of the code and they rot the moment this document changes or is deleted. Describe the behavior in plain terms instead. If traceability matters, express the behavior itself clearly and let the issue number (`#151`) carry the external link. The `Requirements:` annotations inside the units below live in this document only; they do not travel into the diff.

---

## Problem Frame

Verified against `main` at `d21593c`. Branch `fix/payload_mutations` is currently identical to `main`, so nothing is started.

### The reported defect

The decision chain in `AplRouteHandler::invoke` has three branches (`crates/apl-cpex/src/route_handler.rs:454-484`):

1. `route_payload.args != pre_args`: an APL `args:` pipeline rewrote a field.
2. Post phase only, `pre_result != route_payload.result`: a `result:` pipeline rewrote the upstream response.
3. `msg_payload.message.get_text_content() != final_payload.message.get_text_content()`: intended to catch a plugin calling `modify_payload` directly.

Branch 3 is broken. `Message::get_text_content()` (`crates/cpex-core/src/cmf/message.rs:82-92`) matches only `ContentPart::Text`, while `ContentPart` (`crates/cpex-core/src/cmf/content.rs:227-275`) has twelve variants: `Text`, `Thinking`, `ToolCall`, `ToolResult`, `Resource`, `ResourceRef`, `PromptRequest`, `PromptResult`, `Image`, `Video`, `Audio`, `Document`. Eleven of twelve can be mutated with no effect on the branch condition.

Severity is highest for redaction and sanitization plugins, which are exactly the plugins that rewrite `ToolResult.content`. The failure is fail-open on the security-relevant path: the plugin's telemetry says it redacted, and the unredacted value goes downstream.

### The write-back clobber

`pre_args` and `route_payload.args` are both projections of the *pre-evaluation* message. When an `args:` pipeline changes any key, branch 1 calls `write_args_back_to_message(&mut updated.message, &route_payload.args)` (`crates/apl-cpex/src/route_handler.rs:454-462`, helper at `:724-747`), which replaces `ToolCall.arguments` wholesale with the pipeline's args object. A plugin's own rewrite of `ToolCall.arguments` is not in that object, so it is overwritten. Fixing branch 3 does not help: branch 1 wins the `if/else` chain, and its write is total rather than differential.

`write_result_back_to_message` (`:771-782`) has the identical shape against `ToolResult.content`, so a `result:` pipeline edit clobbers a plugin's tool-result redaction in the Post phase. That is the same user-visible symptom as the reported bug, reached by a different path.

### The ignored pipeline signals

`RouteDecision` already carries `args_modified` and `result_modified` (`crates/apl-core/src/route.rs:76-79`), set by the only code that can rewrite those values: the section pipelines (`crates/apl-core/src/route.rs:110-155`, `:202-240`) and `do:`-block field ops (`crates/apl-core/src/evaluator.rs:1112-1190`), all of which set the flag exactly when `set_dotted` / `remove_dotted` reports a write. `AplRouteHandler` never reads either flag. It re-extracts `pre_args` / `pre_result` from the pre-evaluation message and diffs. Two allocations per request to recompute something the decision already states.

### The field-stage value projection

For `PluginInvocation::Field`, `CmfPluginInvoker::invoke` returns `modified_value = Some(Value::String(modified.message.get_text_content()))` (`crates/apl-cpex/src/cmf_invoker.rs:336-339`). The evaluator assigns that straight onto the field (`crates/apl-core/src/evaluator.rs:1442-1460`).

For a text-shaped message with a whole-message field, that is coherent: the projection *is* the field. For a structured tool call it is wrong in a way that is worse than lossy. A route with `args: city | plugin(scrubber)` sets `args.city` to the concatenated text of the entire message. Nothing warns.

A second inconsistency sits underneath it: the `name` handed to `PluginInvocation::Field` is root-relative from section pipelines (`rule.field`, e.g. `city`) but prefixed from `do:`-block field ops (the full `path`, e.g. `args.city`, `crates/apl-core/src/evaluator.rs:1163`). Any invoker that wants to read a field back by name has to guess which convention it got, and stripping an `args.` prefix defensively would corrupt a legitimate argument named `args`.

### Two facts that shape the fixes

- The ground truth for a plugin mutation already exists. `CmfPluginInvoker::invoke` downcasts `result.modified_payload` and, on success, writes it into `self.payload` (`crates/apl-cpex/src/cmf_invoker.rs:332-341`). That is the only site in the crate that mutates the shared payload: `DelegationPluginInvoker` and `ElicitationPluginInvoker` share the extensions `Mutex` but never the payload. A flag set there is complete.
- The diff-based alternative is expensive. `Message`, `ContentPart`, `ToolCall`, `ToolResult`, `Resource`, and the other nine payload structs derive only `Debug, Clone, Serialize, Deserialize`. Comparing content vectors means adding `PartialEq` across all of them and committing to structural equality as a public API property of the CMF types.

---

## Requirements

**Direct mutation propagation**
- R1. A plugin mutation delivered via `PluginResult::modify_payload` reaches `ErasedResultFields.modified_payload` regardless of which `ContentPart` variant it touched.
- R2. Detection is an explicit signal recorded where the mutation is accepted, not a value diff computed later.
- R3. A dropped mutation (downcast failure) still warns and still reports "not modified". The invoker never claims a mutation it did not accept.

**Composition with pipelines**
- R4. A plugin mutation and a pipeline mutation in the same request both survive, including when both target `ToolCall.arguments` (Pre) or `ToolResult.content` (Post).
- R5. Pipeline write-back applies only what the pipeline changed, leaving the rest of the plugin-mutated message intact.
- R6. Pipeline modification is read from `RouteDecision.args_modified` / `result_modified` rather than re-derived by diffing.

**Field-stage dispatch**
- R7. A plugin invoked as a pipeline field stage reports a new value for *that field*, not the message's concatenated text.
- R8. `PluginInvocation::Field.name` has one documented convention across all call sites: a path relative to the args or result root, with the phase selecting the root.
- R9. When the field cannot be located in the mutated payload, the invoker reports no field change. The payload mutation still propagates via R1, so nothing is lost.
- R10. Existing behavior is preserved for text-shaped messages, where the whole projection is the field value.

**Hygiene**
- R11. `Message::get_text_content()` carries a doc note that it is a text accessor and not a change detector, so the next caller does not repeat this.

---

## Scope Boundaries

- No change to `PluginResult`, `ErasedResultFields`, the executor, or the FFI boundary.
- No `PartialEq` derives on CMF payload types.
- No change to `Message::get_text_content()` behavior. Docs only.
- No new hook, no new capability, no config surface.
- Python-side `CopyOnWriteList` / `CopyOnWriteDict` equality bugs (#135, #54) are the same defect family but a different codebase and mechanism. Not touched.

### Known Limitation, Documented Not Fixed

Field pipelines and the shared request payload are not synchronized mid-pipeline. Earlier stages (`mask`, `redact`, `hash`) mutate `route_payload.args` only, so a later `plugin(...)` stage in the same chain is handed a payload whose arguments still hold the *original* values. After this plan the readback is field-precise and the payload mutation propagates, so no data is lost, but a field-stage plugin still does not see its own pipeline's in-progress edits.

Fixing that means writing interim pipeline state into the shared payload before dispatch, which changes what every downstream `pre_invocation:` plugin sees. That is a semantic decision with its own blast radius. File it as a separate issue; do not fold it in here. Add a `// Known limitation:` comment at the dispatch site describing the behavior in plain terms, with no reference to this document.

---

## Key Technical Decisions

**D1. Explicit flag on the invoker, not a content diff.** Matches the issue's recommendation and the maintainer's confirmation. Exact instead of approximate, and it removes the content-shape dependency rather than widening it. The diff alternative would need `PartialEq` on twelve payload structs and would still be a guess about intent.

**D2. `AtomicBool`, not `Mutex<bool>`.** The read happens in `AplRouteHandler::invoke` after evaluation and must not introduce an `await` inside the existing branch chain. Store with `Ordering::Release` at the mutation site, load with `Ordering::Acquire` in the accessor, so a mutation written from a `dispatch_parallel` branch task is visible to the reader.

**D3. Set the flag whenever a mutation is accepted, even if the returned payload is byte-identical.** The flag answers "did a plugin return a payload?", which is the question the handler needs. A false positive costs one redundant body re-serialization; a false negative is the bug being fixed. `extensions_changed` already documents the same fail-safe tradeoff (`crates/apl-cpex/src/route_handler.rs:784-786`).

**D4. Replace branch 3's condition outright rather than OR-ing the flag with the text diff.** The text diff can only be true when a plugin returned a payload, which is exactly when the flag is true. Keeping both leaves a dead heuristic reading as if it were load-bearing.

**D5. Differential write-back, computed as a three-way merge.** Base is the args projected from the plugin-mutated payload; `pre_args` and `route_payload.args` bracket what the pipeline changed. Walk the pre/post pair recursively, apply only differing leaves and removals onto the base. With no plugin mutation the base equals `pre_args`, so the result is byte-identical to today's wholesale write, which makes existing tests the regression guard.

**D6. Fix the field-name convention in apl-core rather than normalizing defensively in the invoker.** Stripping an `args.` prefix in the invoker would corrupt a legitimate argument named `args`. One line in `dispatch_field_op` makes both call sites root-relative, and the phase already tells the invoker which root to project. The name is informational to CMF plugins today (the invoker is its only structural consumer), so the change is low risk.

**D7. Field readback projects the mutated message the same way APL projected the original.** Pre uses the args projection, Post uses the result projection. If the projection is an object, read the field's dotted path; if it is a scalar (a text-shaped message), the projection itself is the field value. That second rule is what preserves R10 and keeps the existing text tests green.

**D8. Ship as one PR, in the unit order below, one commit per unit.** The units are individually revertable, and the first two carry the reported fix. If the fix needs cherry-picking to a patch release, U1 and U2 alone are sufficient and self-contained.

---

## Implementation Units

Reminder: no plan or requirement identifiers in code, comments, rustdoc, test names, or commit messages. See "Documentation and Traceability Constraint" above.

### U1. Record payload mutation on `CmfPluginInvoker`

**Goal:** the invoker exposes whether any plugin in this request returned a payload mutation it accepted.

**Requirements:** R2, R3 &nbsp;·&nbsp; **Dependencies:** none

**Files:** `crates/apl-cpex/src/cmf_invoker.rs`

**Approach:**
- Add `payload_modified: AtomicBool` next to `payload` (`:85`), initialized `false` in `for_request`. Document it as request-scoped, sticky once set, and the authoritative answer to "did a plugin mutate the payload", so callers never infer it from content.
- In the `Some(modified)` arm (`:333-341`), immediately after `*self.payload.lock().await = modified.clone();`, store `true` with `Ordering::Release`.
- Do **not** set it in the downcast-failure arm. That path already warns and drops the mutation; claiming "modified" there would forward an unmutated payload while asserting it changed.
- Add `pub fn payload_was_modified(&self) -> bool` loading with `Ordering::Acquire`. Sync, not async, so the caller uses it inside the existing branch chain without restructuring.
- Extend the module-level request-scoped-state docs (`:16-24`) with one line on the flag.

**Patterns to follow:** accessor shape of `current_payload` / `current_extensions` (`:157-166`).

**Test scenarios** (`crates/apl-cpex/tests/cmf_invoker_dispatch.rs`, which already has `ModifyPluginFactory` and `payload_with_text`):
- Fresh invoker reports `false` before any dispatch.
- After dispatch to a plugin returning `modify_payload`, reports `true`.
- After dispatch to a plugin returning a plain allow, stays `false`.
- A plugin whose `modified_payload` is not a `MessagePayload` leaves the flag `false`. If the typed hook signature makes a foreign payload unconstructible from a test, say so in a test-module comment instead of leaving the case silently uncovered.

**Verification:** `cargo test -p apl-cpex --test cmf_invoker_dispatch`.

---

### U2. Consult the flag in `AplRouteHandler`

**Goal:** the reported bug is fixed. Mutations to any `ContentPart` variant propagate.

**Requirements:** R1 &nbsp;·&nbsp; **Dependencies:** U1

**Files:** `crates/apl-cpex/src/route_handler.rs`

**Approach:**
- Replace the condition at `:478` with `invoker.payload_was_modified()`. Rewrite the branch comment: a plugin mutated the payload directly, the invoker recorded it, pass the invoker's view through. State plainly why a text diff cannot detect this, since the existing comment is correct about intent while the code is not.
- Add a `tracing::debug!` on that branch with the route key. The two pipeline branches are inferable from their inputs; this one was invisible.
- Leave branch ordering alone. U5 fixes the composition problem inside branches 1 and 2.

**Test scenarios** (`crates/apl-cpex/tests/end_to_end_route.rs`, using the `register_apl` + `invoke_named::<CmfHook>` pattern at `:660-728`, which returns a typed `PluginResult<MessagePayload>` whose `modified_payload` is directly assertable):
- Regression, the reported bug: a `pre_invocation` plugin rewrites only `ContentPart::ToolResult.content` to `[REDACTED]` and leaves every `Text` part alone. `modified_payload` is `Some` and carries the redacted value. Fails before this unit, passes after.
- Same for `ContentPart::ToolCall.arguments` on a pre route.
- Same for `ContentPart::Thinking`, the cheapest proof the fix is variant-agnostic rather than a `ToolResult` special case.
- Text-only mutation still propagates.
- A plugin that allows without mutating, on a route with no pipelines, yields `modified_payload: None`, so the flag has not made every request look modified.
- Post phase: a plugin rewriting `ToolResult.content` in `post_invocation` propagates.

**Verification:** `cargo test -p apl-cpex`.

---

### U3. Extract a shared message-projection module

**Goal:** one home for the message-to-JSON projections, so the invoker and the handler cannot drift apart on field semantics.

**Requirements:** enabler for R5, R7 &nbsp;·&nbsp; **Dependencies:** none (land after U2 to keep the fix commit small)

**Files:**
- Create: `crates/apl-cpex/src/message_projection.rs`
- Modify: `crates/apl-cpex/src/route_handler.rs`, `crates/apl-cpex/src/lib.rs`

**Approach:**
- Move `extract_args_from_message`, `extract_result_from_message`, `write_args_back_to_message`, `write_result_back_to_message`, and `rewrite_message_text` out of `route_handler.rs` (`:712-782` and the text helper) into the new module, `pub(crate)`, keeping their existing doc comments.
- Module doc states the contract both consumers depend on: which `ContentPart` each projection reads, that Pre projects args and Post projects result, and that the write-back functions are the inverse of the extractors.
- Pure move. No behavior change in this unit.

**Test scenarios:**
- Unit tests for round-tripping each projection: tool-call args extract then write back yields the original message; tool-result likewise; a text-only message falls through to the text path.
- Existing `apl-cpex` suite passes unchanged.

**Verification:** `cargo test -p apl-cpex`, `make lint`.

---

### U4. Read pipeline modification from the decision

**Goal:** branches 1 and 2 stop re-deriving what `RouteDecision` already states.

**Requirements:** R6 &nbsp;·&nbsp; **Dependencies:** U2

**Files:** `crates/apl-cpex/src/route_handler.rs`

**Approach:**
- Gate branch 1 on `decision.args_modified` and branch 2 on `matches!(self.phase, Phase::Post) && decision.result_modified`.
- Keep the `pre_args` / `pre_result` extraction. It stops being the detector and becomes the merge input U5 needs. Retitle the comment accordingly, so the next reader does not think it is still driving the decision.
- Note in the branch comment that these flags are set by `set_dotted` / `remove_dotted` succeeding, which is the only way those values change.

**Behavior note:** a pipeline that writes a field back to the value it already held sets `args_modified` while the old diff saw equality. Such a request now emits `modified_payload` where it previously emitted `None`. Fail-safe, and consistent with D3. Call it out in the PR description.

**Test scenarios:**
- Existing args-pipeline and result-pipeline tests pass unchanged.
- A `redact` stage whose condition is false leaves `modified_payload` as `None` (the flag is not set when no write happened).
- A pipeline stage that writes an identical value emits `modified_payload: Some`, asserted deliberately so the behavior note is pinned by a test rather than by prose.

**Verification:** `cargo test -p apl-cpex`.

---

### U5. Differential write-back for args and result

**Goal:** a pipeline edit no longer clobbers a plugin's mutation to the same content part.

**Requirements:** R4, R5 &nbsp;·&nbsp; **Dependencies:** U3, U4

**Files:** `crates/apl-cpex/src/route_handler.rs`, `crates/apl-cpex/src/message_projection.rs`

**Approach:**
- Add `apply_changed_paths(base: &mut Value, pre: &Value, post: &Value)` to the projection module. Walk `pre` and `post` in parallel: for a differing or added leaf, write it into `base` at that path; for a key present in `pre` and absent in `post`, remove it from `base`. Objects recurse; arrays and scalars are leaves (whole-value replacement), matching `set_dotted`'s object-only path semantics (`crates/apl-core/src/route.rs:334-361`).
- Branch 1 becomes: project args from the plugin-mutated `final_payload` as the base, apply the changed paths from `pre_args` to `route_payload.args`, write the merged object back with `write_args_back_to_message`.
- Branch 2 does the same against the result projection.
- Keep the existing non-object fallbacks (`args.as_str()` to `rewrite_message_text`) untouched.
- With no plugin mutation the base equals `pre_args`, so the merged output is byte-identical to today's wholesale write. State that invariant in the function's doc comment, in plain terms.

**Test scenarios:**
- An `args:` stage rewrites key `a` while a plugin rewrites key `b` on `ToolCall.arguments`: both survive. Fails before this unit.
- A `result:` stage rewrites one field while a plugin redacts a different field of `ToolResult.content`: both survive.
- Pipeline-only route: outcome identical to pre-change behavior.
- Plugin-only route: branch 3 still handles it, and the merge does not run.
- An `omit` stage removes a key while a plugin mutates another: the key is gone and the mutation survives.
- Nested dotted field (`args.user.name`) merges without disturbing sibling keys.
- Bare-string args with no structured entity part: text fallback still applies.

**Verification:** `cargo test -p apl-cpex`, and confirm no existing pipeline test needed an expectation change. Any test whose expectation moves is a finding to explain in the PR, not to silently update.

---

### U6. Field-precise `modified_value` for pipeline stage plugins

**Goal:** a plugin invoked as a field stage reports a new value for that field, not the message's concatenated text.

**Requirements:** R7, R8, R9, R10 &nbsp;·&nbsp; **Dependencies:** U3

**Files:**
- Modify: `crates/apl-core/src/evaluator.rs`, `crates/apl-core/src/step.rs`, `crates/apl-core/src/route.rs`
- Modify: `crates/apl-cpex/src/cmf_invoker.rs`

**Approach, apl-core side:**
- In `dispatch_field_op`, pass `subpath` (root-relative) to `evaluate_pipeline` instead of the prefixed `path` (`crates/apl-core/src/evaluator.rs:1163`), matching what the section pipelines already pass (`crates/apl-core/src/route.rs:110-155`, `:202-240`). The `path` stays prefixed for deny messages and diagnostics.
- Document the convention on `PluginInvocation::Field.name` (`crates/apl-core/src/step.rs:408-432`): a dotted path relative to the args or result root, with `phase` selecting the root. Document on `PluginOutcome.modified_value` (`:848`) that the value replaces that field only.
- Make `get_dotted` `pub` (`crates/apl-core/src/route.rs:318-329`) so the host bridge reads fields with the same semantics the evaluator writes them. Leave `set_dotted` / `remove_dotted` crate-private; U5's merge does not need them.

**Approach, apl-cpex side:**
- Replace the `PluginInvocation::Field` arm at `crates/apl-cpex/src/cmf_invoker.rs:336-339`. Project the mutated message per phase (Pre: args, Post: result) using the U3 module, then:
  - projection is an object: `get_dotted(&projection, name)`, `Some(value.clone())` when found, `None` when absent.
  - projection is a scalar: the projection itself is the field value, so return it. This is the text-shaped-message case and preserves existing behavior.
- On `None`, log a `tracing::debug!` naming the field, so "plugin mutated something other than this field" is observable rather than silent. The payload mutation still propagates through U1 and U2, which is what makes `None` safe here.
- Add the `// Known limitation:` comment described under Scope Boundaries, in plain terms, no doc IDs.

**Test scenarios:**
- Structured args, the defect: field `city`, a plugin that rewrites `ToolCall.arguments["city"]`, message also carrying text parts. `modified_value` is the new city, not the message text. Fails before this unit.
- Structured args, plugin mutates a different key than the field in focus: `modified_value` is `None` and the pipeline leaves the field alone, while the payload mutation still reaches `modified_payload`.
- Text-shaped message: existing assertions at `crates/apl-cpex/tests/cmf_invoker_dispatch.rs:300-385` pass unchanged.
- Post phase, field on `ToolResult.content`: readback uses the result projection.
- apl-core unit test: a `do:`-block field op on `result.x` reaches the invoker with name `x`, not `result.x`. Assert via a recording `PluginInvoker` test double, the pattern already used at `crates/apl-core/src/evaluator.rs:2637`.
- End to end: a route with `args: city | plugin(scrubber)` where the scrubber redacts the city produces a forwarded payload whose `ToolCall.arguments["city"]` is redacted and whose other arguments are untouched.

**Verification:** `cargo test -p apl-core -p apl-cpex`.

---

### U7. Docs and changelog

**Goal:** the accessor's limits are documented, and the fixes are visible to users on 0.2.2.

**Requirements:** R11 &nbsp;·&nbsp; **Dependencies:** none

**Files:** `crates/cpex-core/src/cmf/message.rs`, `CHANGELOG.md`

**Approach:**
- Extend the rustdoc on `get_text_content` (`:80`) to state it reads only `Text` parts and is therefore not a change-detection or equality signal for a `Message`.
- Changelog entries under `## [0.2.3] - unreleased`, `### Fixed`, matching the existing entry voice. Name the user-visible symptoms: plugin mutations to non-text content parts silently discarded (worst case, an unredacted tool result forwarded after a redaction plugin reported success); a pipeline edit clobbering a plugin's mutation to the same content part; a field-stage plugin's new field value reported as the message's concatenated text. Reference `#151`. No plan or requirement identifiers.
- Under `### Changed`, note the two behavior shifts operators could observe: requests where a pipeline rewrites a field to its existing value now carry a modified payload, and `PluginInvocation::Field.name` is now root-relative from `do:`-block field ops.

**Verification:** `make lint` (rustdoc must survive `-D warnings`).

---

## System-Wide Impact

- `apl-cpex` carries most of the change. `apl-core` gets one line in `dispatch_field_op`, one visibility change, and doc comments. `cpex-core` gets a doc comment.
- No public API removals. `CmfPluginInvoker` gains one method and one private field; `for_request` keeps its signature. `get_dotted` widens from `pub(crate)` to `pub`.
- Behavior visible to hosts: requests where a plugin returned a payload, or where a pipeline wrote a field to its existing value, now carry `modified_payload: Some(..)` where they previously carried `None`. Hosts re-serialize the body in that case, so expect slightly more re-serialization on routes with mutating plugins.
- Behavior visible to plugin authors: a field-stage plugin's `modified_value` is now scoped to the field in focus, and `PluginInvocation::Field.name` is root-relative everywhere. Plugins that ignore `name` and mutate the payload directly are unaffected.
- The FFI path (`crates/cpex-ffi/src/lib.rs:845, 1095`) serializes `modified_payload` when present. Non-Rust plugins were subject to the same drop, since the drop was on the handler side, and are fixed by the same change.

## Risks

- **Widest-reaching unit is U5.** It rewrites a merge path that existing args-pipeline tests depend on. The "pipeline-only route is byte-identical" test is the guard, and any existing test whose expectation moves must be explained rather than updated.
- **U6 touches apl-core.** The field-name convention change is only observable to invokers that read `name`; `CmfPluginInvoker` is the only one in-tree. Grep for other `PluginInvocation::Field` consumers before landing.
- **Unconditional flag setting (D3)** means a plugin that always returns an untouched clone marks every request modified. Fail-safe, cost is re-serialization. If profiling later shows it matters, the narrowing move is a cheap comparison inside the invoker, not a return to content diffing in the handler.
- **Atomic ordering** is the only concurrency-sensitive detail. `dispatch_parallel` runs plugin branches on separate tasks; Release/Acquire plus the existing `Mutex` around the payload covers visibility.
- **Scope creep.** U1 and U2 alone close the reported issue. If review pressure builds, land those two and split U3 through U6 into a follow-up PR rather than letting the fix sit.

## Verification

```
cargo test -p apl-core -p apl-cpex
make lint
make test          # full workspace
```

Manual confirmation of the reported symptom, matching the issue's reproduction: a plugin that redacts only `ToolResult.content` on a `get_weather`-style route, dispatched through `invoke_named::<CmfHook>`, yields a `modified_payload` carrying the redacted content with no throwaway `Text` part appended. The workaround in the issue (appending a dummy `Text` part so the text diff fires) becomes unnecessary; call that out in the PR description so the reporter can delete it.

## Sources & References

- Issue: https://github.com/contextforge-org/cpex/issues/151, plus the maintainer confirmation comment on `main`.
- `crates/apl-cpex/src/route_handler.rs:454-484` (branch chain), `:712-782` (projections and write-backs), `:784-786` (fail-safe precedent).
- `crates/apl-cpex/src/cmf_invoker.rs:332-341` (mutation acceptance), `:336-339` (field projection), `:76-104` (struct), `:157-166` (accessors).
- `crates/apl-core/src/route.rs:67-86` (`RouteDecision` flags), `:110-155` and `:202-240` (section pipelines), `:318-380` (dotted helpers).
- `crates/apl-core/src/evaluator.rs:1112-1190` (`dispatch_field_op`), `:1442-1460` (`Stage::Plugin`).
- `crates/apl-core/src/step.rs:408-432` (`PluginInvocation`), `:848` (`modified_value`).
- `crates/cpex-core/src/cmf/message.rs:82-92` (`get_text_content`), `crates/cpex-core/src/cmf/content.rs:227-275` (`ContentPart` variants).
- Test patterns: `crates/apl-cpex/tests/cmf_invoker_dispatch.rs:300-385`, `crates/apl-cpex/tests/end_to_end_route.rs:660-760`.
