# Extensions wire contract (out-of-process Python plugins)

Status: both sides implemented; **the two have now been exercised against each
other** — once, from a hand-provisioned venv, not yet in CI.

- **Rust host** — `feat/python_plugin_compat_2`,
  `crates/cpex-hosts-python/src/extensions.rs`.
- **Python worker** — `feat/python_plugin_compat_0.1.x`,
  `cpex/framework/isolated/worker.py`. **Not yet released**; see "Reproducing the
  cross-surface run" for how it has to be provisioned into a plugin venv.

Real round-trip coverage landed in
`crates/cpex-hosts-python/tests/config_e2e.rs`
(`config_yaml_dispatches_tool_pre_invoke_to_the_installed_plugin`): populated
`Extensions` cross into an installed plugin's worker subprocess through the
installer-written `plugins/config.yaml`, and the hook runs. That closed item 2 of
the old Remaining work and **overturned the two claims this document made about
the `http` divergence's failure mode** — see "Known divergence: the http slot",
which is still the one place the shapes do not line up, but which fails
differently and more quietly than recorded here before.

Plan: `docs/plans/2026-07-29-003-feat-out-of-process-extensions-delivery-plan.md`

**Relationship to the CMF spec.** `docs/specs/cmf-message-spec.md` §3 is the
normative definition of the extension slots, their mutability tiers, and their
field shapes. This document does not restate it and is not a substitute for it;
it covers only what §3 leaves open — how those slots are framed on a JSON stdio
wire between two processes (field names, omission semantics, header scrubbing,
what "no change" looks like on return). Read §3 first for *what* an extension
is; read this for *how it crosses a process boundary*.

Where the two disagree, each disagreement is called out inline below rather than
resolved silently. There are three: the `delegation` and `raw_credentials` slots
(present in the implementation, absent from §3), the `http` slot's field shape
(§3.5 matches Python, not Rust), and the sensitive-header list (four names here,
three in §3.5). None is a case of this wire deviating from a shape §3 pins down
— they are places §3 has not caught up to the implementation, or where this
transport strips more than the spec's floor requires.

This document pins the contract the two surfaces share, and records the answers
to the plan's Open Questions as resolved against the actual code. It exists
because the two sides land on different branches and ship separately — the worker
as a Python package into each plugin's venv, the host as this crate — so neither
side's source can serve as the other's reference, and a build in hand cannot be
trusted to be the build this contract describes (see the version collision under
"Reproducing the cross-surface run").

Claims here are verified against running code where they can be. Where an earlier
revision recorded an inferred behaviour that turned out to be wrong, the
correction is called out as a correction rather than quietly replaced — the
`http` failure mode was misdescribed for a while precisely because it looked
settled.

## Field names

| Direction | Field | Carrier |
|---|---|---|
| Host → worker | `extensions` | Task JSON, alongside `payload` / `context` / `credential` |
| Worker → host | `modified_extensions` | Response JSON, i.e. the serialized Python `PluginResult` |

The two names differ deliberately. The return field is **not** `extensions`
because the worker's response is a serialized `PluginResult`, and that model
already carries `modified_extensions: Optional[Extensions]`
(`cpex/framework/models.py`) — the same field the in-process Python manager
accumulates in `cpex/framework/manager.py`. Reusing it means an out-of-process
plugin returns extensions exactly the way its in-process equivalent does, and the
worker does not have to invent a second field.

Rust constants: `EXTENSIONS_FIELD` and `MODIFIED_EXTENSIONS_FIELD` in
`crates/cpex-hosts-python/src/extensions.rs`.

## Slots carried

`request`, `agent`, `http`, `security`, `delegation`, `mcp`, `completion`,
`provenance`, `llm`, `framework`, `meta`, `custom`.

Each present slot serializes to the JSON of its own extension sub-model; absent
slots are omitted. The Rust capability-filtered view is the source of truth for
which slots are present inbound — an absent slot means the plugin's capabilities
excluded it.

**`raw_credentials` is never carried.** Its token fields are `#[serde(skip)]` so
it would serialize hollow anyway, and a hollow slot invites a plugin to read
"no credential present" rather than "not on this channel". Raw tokens travel the
capability-gated `credential` DTO (`credentials.rs`) instead.

Note: the plan's slot list omitted `delegation`, **and so does CMF §3.** The
extension tree in that section lists eleven slots and has no `delegation` entry
(nor a `3.x` subsection for it), but it exists in the Rust container
(`crates/cpex-core/src/extensions/container.rs:64`), is monotonic, is gated by
`append_delegation`, and is carried on this wire. `raw_credentials` is likewise
absent from CMF §3 and present in the container.

So the twelve slots above are the *implementation's* set, not §3's. Where this
document and CMF §3 disagree on which slots exist, CMF §3 is behind — it is the
older document and has not been updated for these two. That is a gap in §3 to
close, not a divergence this contract is entitled to resolve by itself; treat
§3 as authoritative on the shape and tiers of the slots it *does* describe, and
this document as authoritative on what actually crosses the wire.

## Sensitive headers

`Authorization`, `Cookie`, `Set-Cookie`, and `X-API-Key` are stripped **in both
directions**, matched case-insensitively (HTTP header names are case-insensitive,
and `HttpExtension`'s own accessors look up that way, so a case-sensitive compare
would pass `authorization` straight through).

Source of truth: `SENSITIVE_HEADERS` in
`crates/cpex-hosts-python/src/extensions.rs`, and `SENSITIVE_HEADERS` in
`cpex/framework/isolated/worker.py`.

Every header map on the slot is scrubbed, not just a request one: a response map
can carry a `Set-Cookie` or an upstream `Authorization` echo just as a request map
carries the inbound credential. Which maps exist depends on the language — see
below.

**This is four names, where CMF §3.5 names three.** The deliberate widening is
`Set-Cookie`, and it is a widening of what gets *stripped* — strictly more
redaction than the spec floor, never less, so it cannot make the channel leakier
than CMF permits. It is here because `response_headers` exists on the Rust slot
and a response map's whole job is carrying `Set-Cookie`; stripping `Cookie`
inbound while forwarding `Set-Cookie` outbound would redact one direction of the
same session credential.

(An earlier revision of this document claimed the opposite — that only the
spec's three were stripped and `Set-Cookie` was deliberately excluded. That was
true of the code when it was written and is no longer; `extensions.rs` carries
`set-cookie` in the list and a test asserts it. Recorded as a correction rather
than silently replaced, per this document's convention.)

CMF §3.5 is the floor, not the ceiling: it says sensitive headers "are stripped
when serialized for external policy engines" and names three. Any further name
added here must be added to *both* surfaces' `SENSITIVE_HEADERS` in the same
change, or the two directions disagree.

## Known divergence: the http slot

**This is the one slot whose shape differs across the two surfaces.** The branches
have now met, and this is the one thing that did not line up — but it did not
announce itself, which is the part worth reading below.

| | Header fields | Other fields |
|---|---|---|
| CMF §3.5 (the spec) | `headers` (single map) | none |
| Rust `HttpExtension` (`crates/cpex-core/src/extensions/http.rs`) | `request_headers`, `response_headers` | `method`, `path`, `host`, `scheme` |
| Python `HttpExtension` (`cpex/framework/extensions/http.py`) | `headers` (single map) | none |

**The spec sides with Python.** CMF §3.5 declares exactly one attribute,
`headers: dict[str, str]`, and none of the request-line fields. So this is not a
symmetric "two implementations drifted" problem: Python matches the spec, and
**Rust is the side that diverged from it** — it split the map in two and added
`method` / `path` / `host` / `scheme` (the latter four shipped in 0.2.1 as the
HTTP request-line attributes, which CMF §3.5 was never updated to describe).

That matters for Remaining work item 1: "pick one shape and adapt the other" is
not a coin flip. Adopting Python's shape means Rust loses `response_headers` and
the four request-line attributes that `http.*` APL predicates already read, so
the realistic resolution is to update CMF §3.5 to the Rust shape and map Python
up to it — not the reverse. That is a spec change and needs the CMF owners, which
is why it is not resolved here.

Consequences, both currently unresolved by design rather than by accident:

- **The slot crosses, validates, and arrives empty — silently, in both
  directions.** This is a correction: this document previously said a
  Rust-serialized `http` slot does *not* validate into the Python model, and that
  `reconstruct_extensions` drops it with a warning. Both claims are wrong, and the
  real behaviour is worse because it is quiet.

  Neither `HttpExtension` sets `extra="forbid"` (Python) or
  `#[serde(deny_unknown_fields)]` (Rust), and both declare their header maps with
  a default. So each side's unknown keys are *ignored* and the missing ones
  *default to empty*:

  | Direction | On the wire | Deserializes to | Warning? |
  |---|---|---|---|
  | Rust → Python | `{"request_headers": {"X-Request-Id": "r1"}}` | `HttpExtension(headers={})` | none |
  | Python → Rust | `{"headers": {"X-Fine": "yes"}}` | `HttpExtension { request_headers: {}, response_headers: {} }` | none |

  Verified empirically against the branch-built worker described under
  "Reproducing the cross-surface run" and against
  `cpex_core::extensions::HttpExtension`, not inferred from the models.

  Two things follow. First, `reconstruct_extensions` calls
  `Extensions.model_validate(known)` on the **whole object at once**, so had the
  slot genuinely failed validation the entire reconstruction would have returned
  `None` and the plugin would have seen *no extensions at all* — not "no `http`,
  but the other eleven". The per-slot degradation this document implied does not
  exist on that path. Second, what actually happens instead is the **hollow slot**
  this contract explicitly rejects for `raw_credentials`: a plugin reading
  `extensions.http.headers` gets `{}` and cannot distinguish "this request had no
  headers" from "the headers did not cross". A dropped slot would at least have
  been honest.

  **A mapping is still needed on one side before the http slot works across the
  boundary.** The other eleven slots line up.

- The stripping code on each side is written against whichever fields the model
  actually declares (`_HTTP_HEADER_FIELDS` in `worker.py`, `sanitize_http` in
  `extensions.rs`), so neither leaks if the shapes change. The Python helper reads
  `model_fields` and scrubs every header map it finds, so it keeps working if the
  Python model later gains the split shape.

  Note this is why the divergence is a correctness bug and not a security one: the
  sensitive-header strip runs *before* serialization, against the fields the
  sending model really has, so `Authorization` never reaches the wire regardless
  of which shape the receiver expects. `config_e2e.rs` asserts exactly that — no
  credential header value appears anywhere in the serialized task JSON.

Note: the plan referred to `http.headers`, which is right for Python and wrong for
Rust. Both are recorded above rather than picking one.

## Mutability tiers on return

Enforced by the Rust executor's copy-on-write merge
(`crates/cpex-core/src/executor.rs`), not by the wire format. The host feeds that
merge; it implements no tier logic.

Tiers themselves are defined by CMF §3.1 and assigned per slot by §3.2 — this
table is not a second source for them. It restates the assignment only to attach
the two columns §3 does not have (the concrete capability string the executor
checks, and what the executor does to a *returned* slot on this wire), and it
adds the `delegation` row §3 is missing. If a tier here disagrees with §3.2, §3.2
wins and this table is stale.

| Slot | Tier | Capability | Behavior |
|---|---|---|---|
| `request`, `agent`, `mcp`, `completion`, `provenance`, `llm`, `framework`, `meta` | Immutable | — | Inbound `Arc` reused; a returned edit is dropped |
| `security` (labels) | Monotonic | `append_labels` | Additive only; executor rejects the return if any label is removed |
| `delegation` | Monotonic | `append_delegation` | Additive only |
| `http` | Guarded | `write_headers` | Applied only with the capability |
| `custom` | Mutable | — | Applied as-is |

Two structural properties the worker side should know about:

1. **Immutable slots reuse the inbound `Arc`.** The executor validates the
   immutable tier with `Arc::ptr_eq` — pointer identity, not value equality. A
   JSON round trip allocates a fresh `Arc` per slot, so deserializing the whole
   object from the wire would fail that check on *every* immutable slot and get
   the entire return rejected, even for a plugin that only touched `custom`. The
   host therefore rebuilds from `cow_copy()` and takes only the writable slots
   from the wire.

   Consequence for plugin authors: returning a modified immutable slot is not an
   error, it is a no-op.

2. **Write authority is a token, not a claim on the wire.** The executor mints a
   `WriteToken` per plugin from its declared capabilities and carries it on the
   inbound view. `WriteToken::new()` is `pub(crate)` to `cpex-core`, so the host
   cannot mint one and a token can never be forged out of worker JSON. A gated
   write with no token behind it is dropped.

## "No change" on return

**Omit the `modified_extensions` field** (or send `null` — the host treats both
identically).

This was the plan's second Open Question, and the answer is forced by
`Arc::ptr_eq`: an echo cannot mean "no change", because a JSON round trip
produces new `Arc`s and an echoed immutable slot is indistinguishable from a
forged one. Omission is the only representation that reads cleanly as "nothing
changed".

Pydantic emits unset Optionals as `null`, so a plugin that touched nothing still
sends every key. An object whose writable slots are all `null` is therefore also
treated as no modification — the host returns `None` rather than handing the
executor a no-op merge to validate.

### Do not read `PipelineResult.modified_extensions` as "something changed"

The host's `None` above is a statement about the *worker's return value*. It does
not survive into the pipeline's result as a `None`, and callers writing assertions
against this channel get this backwards easily enough that it is worth pinning.

`PipelineResult::allowed_with` (`crates/cpex-core/src/executor.rs`) *always*
populates `modified_extensions: Some(extensions)` with the pipeline's final view,
whether or not any plugin wrote anything. So on an allowed pipeline the field is
never `None`, and its presence carries no information.

Two consequences worth knowing before relying on it:

- The doc comment on the field ("`None` if no plugin modified extensions") is
  inaccurate for the allowed path. `extensions_merge_e2e.rs` does observe `None`
  there, but only because its `fake_worker` handler returns `modified_extensions`
  directly rather than going through `allowed_with`.
- The view is the **pipeline's**, not the filtered one any single plugin saw. The
  executor filters per plugin and merges accepted writes back into the unfiltered
  original, so a slot that was correctly stripped on the way *to* a plugin
  reappears in this result. That is correct, not a filter leak.

To assert "the plugin changed nothing", compare the returned view against the
inbound one, as `config_e2e.rs` does.

## Resolved Open Questions

- **Per-slot sub-field mapping.** Serialize through each extension's own
  serde/pydantic model rather than a hand-written mapping, so the shape tracks the
  structs as they evolve. Only `http` is rewritten, to strip sensitive headers.
  Eleven of the twelve slots line up 1:1; `http` does not — see "Known divergence"
  above. Two further corrections to the plan's assumptions: the `delegation` slot
  exists and is carried, and the plan's `http.headers` is right for Python only.

- **"No change" sentinel.** Omit the field. See above.

- **`custom` size bounds.** No separate bound. The existing `max_content_size`
  task/response frame limit (default 10,000,000; enforced in
  `crates/cpex-hosts-python/src/worker.rs` and in the worker's own response check)
  covers `custom` transitively, since it bounds the whole frame.

## Worker-side implementation

Landed on `feat/python_plugin_compat_0.1.x`, unreleased:

- `EXTENSIONS_FIELD` / `MODIFIED_EXTENSIONS_FIELD` / `SENSITIVE_HEADERS` constants
  in `cpex/framework/isolated/worker.py`.
- `reconstruct_extensions` — `model_validate` off the task field; drops unknown
  slots with a warning so a host running ahead of the worker cannot take the
  channel down, and degrades to `None` on a malformed slot rather than failing the
  hook.
- `sanitize_extensions_http` — strips the three sensitive names from every header
  map the model declares, on the way back. Returns the original object untouched
  when nothing was sensitive.
- `process_task` reads the field and passes `extensions=` through
  `execute_hook_scrubbed` to the single `execute_plugin` call site; the framework's
  `_accepts_extensions` then forwards it to 3-arg hooks only.

Verified by `TestExtensionsDelivery` in
`tests/unit/cpex/framework/isolated/test_worker.py` (9 tests) and
`tests/unit/cpex/framework/isolated/test_extensions_e2e.py` (6 tests, real worker
subprocess), with the 3-arg fixture at
`tests/unit/cpex/fixtures/plugins/isolated/extensions_plugin/plugin.py`.

## Cross-surface verification

Demonstrated by
`config_yaml_dispatches_tool_pre_invoke_to_the_installed_plugin` in
`crates/cpex-hosts-python/tests/config_e2e.rs`.

### Reproducing the cross-surface run

`#[ignore]`d because it needs an installed plugin with a built venv, and the
install alone is **not sufficient** — the worker has to be replaced by hand:

```
# 1. Install the plugin. Its venv gets the released cpex, which has no
#    extensions support at all.
cpex plugin --type test-pypi install "cpex-test-plugin@>=0.2.0"

# 2. Overwrite that cpex with the branch build, in *every* plugin venv.
plugins/<plugin_slug>/.venv/bin/pip install \
  "git+https://github.com/contextforge-org/cpex.git@feat/python_plugin_compat_0.1.x"

# 3. Now the test is meaningful.
cargo test -p cpex-hosts-python --test config_e2e -- --ignored --nocapture
```

**Watch the version numbers — they collide.** The branch build self-reports
`0.1.2`, and PyPI also publishes a `cpex` 0.1.2 that is a *different artifact with
no extensions support* (no `EXTENSIONS_FIELD`, no `reconstruct_extensions`).
Nothing in `pip list` or the dist-info version distinguishes them, so a venv can
look correctly provisioned and silently have no extensions channel. Check the
install source, not the version:

```
cat plugins/<slug>/.venv/lib/python*/site-packages/cpex-*.dist-info/direct_url.json
```

A branch-provisioned venv shows `requested_revision:
feat/python_plugin_compat_0.1.x`; a registry install has no `direct_url.json` at
all. The runs recorded in this document used commit `b6f9f7c`.

Step 2 is the reason this is not yet CI-reproducible, and step 3 will regress to a
vacuous pass if a venv is ever rebuilt from the registry — the worker would ignore
the `extensions` field entirely, the hook would still run, and the marker would
still land. See Remaining work item 4.

What the test establishes, and what it deliberately does not:

- **Establishes** that populated `Extensions` cross the boundary into a real
  worker subprocess and are reconstructed there without taking the hook down: the
  plugin's marker file still lands, and a slot shape the worker's Pydantic models
  rejected would instead surface as a validation error in `PipelineResult.errors`
  with no marker. It runs through the installer-written `plugins/config.yaml`, so
  it is the config → factory → registry → executor → worker path an operator
  actually gets, not a test-constructed config.
- **Establishes** the no-capability contract against that real config, which
  declares `capabilities: []`: the gated `agent` and `http` slots and the gated
  `security.labels` sub-field are stripped by `filter_extensions`, while
  unrestricted `request` and `custom` cross. And the sensitive-header strip holds —
  no credential header value appears anywhere in the serialized task JSON.
- **Does not** observe what the plugin received from inside the hook body.
  `cpex-test-plugin`'s hooks are 2-arg `(payload, context)`, and the framework's
  `_accepts_extensions` forwards extensions only to 3-arg hooks, so this plugin
  structurally cannot report on them. Inbound observation and the merge tiers are
  covered by `extensions_merge_e2e.rs`, which has a purpose-built 3-arg fixture and
  explicit capability sets. What `config_e2e.rs` adds is the real config's
  no-capability path and proof the channel survives a genuine worker.

The consequence for the `http` divergence is that it does **not** show up as a
failure in either test suite — both sides validate happily and lose the headers in
silence. It needs a test that asserts a header *value* survives the round trip,
which nothing currently does. See Remaining work item 2.

## Remaining work

1. **Map the `http` slot** across the two shapes (see "Known divergence"). Until
   then the other eleven slots cross correctly and `http` arrives as a
   present-but-empty slot on both sides, with no warning. Pick one shape and adapt
   the other, or teach each side's serializer to emit both keys during a
   transition.

2. **Add a round-trip assertion on a header value.** The gap that let the
   divergence be misdescribed for as long as it was: every existing test asserts
   either on the wire JSON (Rust-shaped, so it passes) or on hook execution
   succeeding (it does), and none asserts that a benign header set on one side is
   readable on the other. A test that sends `X-Request-Id` and requires the plugin
   to read it back would have failed immediately. Blocked on item 1 — write it as a
   failing test first.

3. **Consider `extra="forbid"` / `deny_unknown_fields` on the extension models.**
   The permissive default is what converted a loud shape mismatch into a silent
   one. Strictness here trades the version-skew tolerance
   `reconstruct_extensions` deliberately provides at the *slot* level, so this is a
   real design call and not an obvious win — but the current setting means any
   future field rename degrades the same quiet way.

4. **Make the cross-surface run reproducible.** Two parts, both consequences of
   the hand-provisioned venv in "Reproducing the cross-surface run":

   - **Release the worker**, or teach `cpex plugin install` to accept a git ref, so
     step 2 stops being a manual `pip install` into each venv.
   - **Add a skip guard that checks the worker actually supports the channel.**
     `testing::worker_delivers_extensions` exists for the `CPEX_PYTHON_SOURCE`
     path, but `config_e2e.rs` guards only on the venv's *existence*, so a venv
     carrying the registry `cpex` yields a green test that proves nothing: the
     worker ignores the unknown `extensions` field, the hook runs, the marker
     lands. Grepping the venv's installed `worker.py` for `EXTENSIONS_FIELD` — the
     same check the other guard makes — would turn that into an honest skip.

     Until then, treat a green `config_e2e.rs` as conditional on having verified
     the venv's `direct_url.json`.
