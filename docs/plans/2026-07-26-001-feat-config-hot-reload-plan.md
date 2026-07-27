---
title: "feat: Configuration hot-reload (FileSystemSource)"
type: feat
status: active
date: 2026-07-26
deepened: 2026-07-27
origin: docs/brainstorms/config-hot-reload-requirements.md
---

# feat: Configuration hot-reload (FileSystemSource)

## Summary

Add a filesystem watcher in `cpex-core` that re-reads and reloads config on disk changes through a new async, transactional reload that builds a complete runtime snapshot (plugins with `initialize()` run, plus all visitor/APL annotations) and publishes it with a single atomic swap, so an invalid or partial edit never leaves a request observing a half-applied policy. Reload is **opt-in via a programmatic `PluginManager` activation call** (host supplies the file path, a tokio runtime handle, and a debounce interval); it is off unless the host activates it, and it cannot be enabled from the watched file itself. Reachable in production via a thin activation entry in the FFI and Python bindings, and observable through structured logs, the generation counter, reload metrics, watcher liveness, and a status callback.

---

## Problem Frame

Operators update policy today by editing YAML and rebuilding the manager, which drops in-flight requests and, in Kubernetes, requires a rollout to apply a ConfigMap change. The atomic-swap machinery exists on `PluginManager` (`ArcSwap<RuntimeSnapshot>` + `config_generation()`), but nothing watches the file, and the real reload path (`load_config_yaml`, used by both the FFI and Python bindings) swaps plugins first and then applies APL policy annotations one live swap at a time, with no rollback and no re-initialization of the new plugin instances. See origin: `docs/brainstorms/config-hot-reload-requirements.md`.

---

## Supersedes Origin Decisions

Document review reversed two origin decisions; this plan is now the source of truth for them:

- **Activation is opt-in and programmatic, not on-by-default via config.** Origin R6/R8 specified on-by-default with a `hot_reload` config opt-out that a reload could flip. That is unsafe for an enforcement plane: a config attribute lets anyone who can write the watched file enable watching, and it creates a self-referential start/stop-on-reload. Hot-reload is now **off unless the host calls the programmatic activation API**; there is no config field controlling it. (Origin R6/R8 restated below as R6'/R8'.)
- **Reload safety is a single-atomic-publish requirement, not a preferred-mechanism-with-fallback.** The "capture-prior/restore-on-failure" fallback is struck (it cannot satisfy AE3; see Key Technical Decisions).

The origin brainstorm should be updated to match (offered at handoff).

---

## Requirements

- R1. Watch the loaded config file and reload on change without restarting the process.
- R2. Detect changes for both direct/atomic-rename edits and Kubernetes ConfigMap symlink swaps (watch the containing directory, re-read the canonical path).
- R3. Coalesce rapid event bursts so one logical change triggers at most one reload.
- R4. Build a complete replacement snapshot and publish it with a single atomic swap; a failed or partial reload leaves the previous config serving and never exposes a half-applied policy to any request (success or failure).
- R5. Reload rebuilds the whole config, recreating and re-initializing all plugin instances; in-memory plugin state resets. Document this.
- R6'. **(supersedes origin R6)** Hot-reload is opt-in, activated only through a programmatic `PluginManager` API; it is off by default and cannot be enabled from the watched config file.
- R7. Watching attaches only through the programmatic activation call (which carries the path); ordinary string/path loads that do not call it never watch.
- R8'. **(supersedes origin R8)** The host can start and stop watching through the API; there is no config flag that toggles it.
- R9. Every reload attempt emits a structured log: success with new generation, or rejection with the validation error (without echoing raw file contents).
- R10. The generation counter is exposed and advances exactly once per successful reload, so callers/health checks can confirm a reload landed vs was rejected.
- R11. Reload metrics tracked: successful and failed reload counts, timestamp of last successful reload.
- R12. A reload-status callback/accessor lets an embedding host or admin endpoint react to reload outcomes.
- R13. A watcher-side failure must not crash the process; log and re-establish the watch where possible.
- R14. **(plan-derived)** Reloads are serialized: at most one snapshot-producing operation (watcher-driven reload or host-driven load) runs at a time.
- R15. **(plan-derived)** Reloaded plugin instances are initialized before the snapshot is published (reload is async; the host supplies the runtime handle).
- R16. **(plan-derived)** Watcher liveness is observable: a distinct signal (log + status) when the watch cannot be re-established, separate from reload success/failure, so a silently-dead watcher is distinguishable from "no changes yet."
- R17. **(plan-derived)** A transient empty/truncated/torn read does not silently reload to an empty (zero-plugin) config; such reads are rejected and re-attempted once the file settles.

**Origin actors:** A1 (operator), A2 (CPEX process), A3 (embedding host via cpex-ffi)
**Origin flows:** F1 (successful live reload), F2 (rejected reload)
**Origin acceptance examples (inlined for standalone reading):**
- AE1 (R1, R4): watched file edited to valid config reloads; new requests use the new policy.
- AE2 (R4): a request mid-evaluation finishes on the old config; later requests use the new one.
- AE3 (R4, R9, R10): an invalid edit is rejected, the previous config stays active, generation does not advance, rejection is logged.
- AE4 (R2): a ConfigMap symlink swap is detected and reloaded without a restart.
- AE5 (R6', R8'): watching activates only via the API; the host can stop it.
- AE6 (R3): a burst of writes triggers exactly one reload.

---

## Scope Boundaries

- Multi-file config `include`/embedding is out of scope (issue #104).
- Partial/diffed reload preserving unchanged plugins' in-memory state is out of scope; full rebuild only.
- Signal-based (SIGHUP) or admin-API manual reload triggers are out of scope; the programmatic activation API is the only entry.
- Generalizing into a full `ConfigSource` trait with multiple backends is out of scope; ship the filesystem case on the manager.
- **Semantic policy validation and integrity/provenance gating are out of scope.** Reload validates that a policy parses and compiles, not that it is *correct* or *authorized*. See the trust boundary in Key Technical Decisions. An optional integrity signal (checksum/signature) is possible future work.
- **Boundary reconciliation (see origin scope note):** the origin marked the `cpex-ffi` embedded case out-of-scope as a watch target. Because CPEX only runs embedded (no standalone binary), the watcher lives in `cpex-core` and a *thin activation entry* is added to FFI/Python so the feature is reachable. CPEX owns detection; we are not building host-driven change detection.

---

## Context & Research

### Relevant Code and Patterns

- `crates/cpex-core/src/manager.rs` — `PluginManager` with `runtime: ArcSwap<RuntimeSnapshot>`; `load_config` (clone registry + `instantiate_plugins_into` + `store()` + generation bump); `load_config_yaml` (`self: &Arc<Self>`; calls `load_config` then walks visitors, each calling `annotate_route`; docs say partial load is not rolled back); `annotate_route` (each call is a separate `mutate_runtime` live swap + generation bump); `config_generation()` (`fetch_add(Release)`); `initialize()` (guarded by an `initialized` atomic — a second call is a no-op); `create_override_instance` / `build_override_entries` (the existing pattern that calls `instance.plugin.initialize().await` on freshly created instances — reload must mirror this); `RuntimeSnapshot` is `Clone`; `factories` is `RwLock<PluginFactoryRegistry>` and is **not `Clone`**; manager holds a `TaskTracker`. **cpex-core owns no tokio runtime** (no `Runtime`/`Handle`/`block_on` in the crate; the runtime is the FFI's `SHARED_RUNTIME`).
- `crates/apl-cpex/src/visitor.rs` — the APL visitor calls `mgr.annotate_route(...)` from `visit_route` holding `&Arc<PluginManager>` (line ~772) and mutates its own internal walk state (`global_layer`, `tag_layers`, ~line 515). Both are affected by the staging refactor (R4) and the reload mutex (R14).
- `crates/apl-cpex/src/register.rs` — captures `Weak<PluginManager>` (`Arc::downgrade`, ~line 169); the watcher closure should mirror this to avoid a manager ↔ watcher reference cycle (R13 lifecycle).
- `crates/apl-cpex/src/dispatch_plan.rs` — `DispatchCache` keys plans on `config_generation()` (~line 519); generation read and snapshot build are not atomic, so generation must advance exactly once per reload (R10) to keep cache invalidation correct.
- `crates/cpex-core/src/config.rs` — `CpexConfig`, `PluginSettings`, `parse_config` (note: `parse_config("")` yields a valid zero-plugin `CpexConfig::default()` — the R17 empty-read hazard).
- `crates/cpex-ffi/src/lib.rs` — `cpex_load_config` (~515) parses then calls `load_config_yaml` under `catch_unwind`; owns `SHARED_RUNTIME` (~122); the FFI can hand its runtime handle to the activation entry.
- `bindings/python/src/manager.rs` — reads the config file then calls `load_config_yaml` (~71).
- Tests: integration tests in `crates/cpex-core/tests/` and `crates/apl-cpex/tests/` (e.g. `visitor_e2e.rs::visitor_compile_error_propagates_from_load_config_yaml`). No `tempfile` dev-dep yet; add one.

### Institutional Learnings

- No `docs/solutions/` knowledge base exists; the origin brainstorm is the spec. `docs/content/docs/configuration.md:165` currently states "There is no hot reload or config versioning" and must be corrected (U6). Post-merge, the `notify`-on-ConfigMap behavior and the staging/serialization design are strong `/ce-compound` candidates.

### External References

- `notify` 8.2 + `notify-debouncer-full` 0.7 (current in 2026). Watch the containing directory with `RecursiveMode::Recursive`; on any debounced event re-read the canonical path (do not trust event contents). ConfigMap updates swap the `..data` symlink; a directory watch catches this on Linux inotify where a file-inode watch misses it. macOS FSEvents / Linux-VM-on-macOS may need `PollWatcher`. Debounce ~500ms. Keep the debouncer handle alive for the watcher's lifetime. **This ConfigMap behavior must be validated by a test that performs a real `..data` atomic symlink-rename on the target container runtime (R2/AE4), not assumed.**

---

## Key Technical Decisions

- **True staging, single atomic publish (R4, R10):** a reload builds the complete replacement `RuntimeSnapshot` (plugins + all visitor/APL annotations) off to the side and publishes it with exactly one `store()` and one generation bump. Nothing is published until the full build (including plugin `initialize()` and the visitor walk) succeeds, so no request ever observes new-plugins-with-missing-annotations, and a rejected reload leaves the prior snapshot and generation untouched. The "capture-prior/restore-on-failure" fallback is **rejected**: it does nothing on the success path (where the fail-open window actually occurs) and cannot un-bump the generation on failure, so it fails AE3.
- **Staging requires changing the annotate/visitor path (blast radius):** because visitors call `annotate_route` on the live manager, single-publish requires the visitor walk to accumulate annotations into a staging snapshot rather than swapping live. Prefer extracting a shared staged-build helper used by both first-time load and reload (first load has no prior state, so single-publish is a harmless improvement there). This changes `annotate_route`'s target for the reload path and touches `apl-cpex`'s visitor; it is a deliberate, reviewed change, not "unchanged invariants."
- **Async reload, host-supplied runtime handle (R15):** reload initializes new plugin instances (mirroring `create_override_instance`'s `initialize().await`), so reload is async. Since `cpex-core` owns no runtime, the programmatic activation call takes a tokio `Handle` (the FFI passes `SHARED_RUNTIME`'s handle); the watcher drives reloads on it.
- **Opt-in, programmatic activation only (R6', R7, R8'):** activation is a `PluginManager` method (host supplies path + runtime handle + debounce); off unless called; not controllable from the watched file. This removes the config opt-out field and the self-referential start/stop-on-flip. The watcher closure holds `Weak<PluginManager>` to avoid a reference cycle.
- **Serialize reloads (R14):** a reload/mutation mutex ensures at most one snapshot-producing operation runs at a time, so a watcher reload cannot interleave with a host `cpex_load_config`/`annotate_route` and corrupt visitor state or produce a mixed snapshot.
- **Trust boundary (security):** CPEX validates that a reloaded policy parses and compiles, not that it is semantically correct or authorized. The watched file/directory is assumed writable only by principals authorized to change policy; CPEX performs no content authentication. Opt-in programmatic activation means the watched file cannot enable its own watching. Canonical-path resolution is assumed to stay within the host-controlled config directory; rejection logs must not echo raw file contents (R9).
- **Content-hash guard (R17, churn):** skip the reload (no rebuild, no generation bump, no state reset, no cache eviction) when the canonical file's content hash is unchanged, and reject an empty/zero-plugin parse from a path that previously had plugins. This handles idempotent ConfigMap re-syncs and transient truncated reads.
- **`notify-debouncer-full` over hand-rolled debounce:** it merges rename From/To and dedups create bursts, matching the ConfigMap-swap and atomic-save event shape.

---

## Open Questions

### Resolved During Planning

- Reload path: a new async, transactional reload built on a shared staged helper (not the caller-less `load_config_file`, and not the multi-swap `load_config_yaml` as-is).
- Reachability: core watcher + thin FFI/Python programmatic activation entry (user-confirmed).
- Activation model: opt-in, programmatic, host-supplied runtime handle (user-confirmed; supersedes origin R6/R8).
- Reload safety: true staging, single publish (user-confirmed).
- Default-on posture: reversed to opt-in (user-confirmed).
- Debounce: a parameter of the activation call, default 500ms.

### Deferred to Implementation

- Exact activation method name/signature (e.g. `watch_config_file(self: &Arc<Self>, path, handle, debounce) -> Result<...>`) and how the watcher handle + reload mutex are stored on the manager.
- Exact staging mechanism inside the visitor walk (manager-held "staging" target vs a `ConfigVisitor` signature change) — must deliver single-publish; validated by the concurrent-mid-reload test below.
- Whether the Python binding activation lands in this change or a fast-follow (FFI is the priority surface).
- Whether watcher liveness is a poll (periodic canonical stat/mtime) or backend-driven; R16 requires the observable, not the mechanism.

---

## High-Level Technical Design

> *This illustrates the intended approach and is directional guidance for review, not implementation specification. The implementing agent should treat it as context, not code to reproduce.*

```
Host (FFI / Python) — explicit opt-in
  cpex_watch_config_file(mgr, path, runtime_handle, debounce_ms)
        │
        ▼
  PluginManager::watch_config_file(&Arc, path, handle, debounce)
        │  1. initial staged reload (below)
        │  2. spawn notify-debouncer-full on the handle; closure holds Weak<Self>
        ▼
  notify-debouncer-full  watch(parent_dir, Recursive)
        any event (burst) ──debounce ~500ms──► reload closure (upgrade Weak)
        │  re-read canonical path; if unchanged hash or empty-from-nonempty -> skip/reject
        ▼
  Staged reload  (holds reload mutex; async):
     build new RuntimeSnapshot off-side: instantiate plugins -> initialize().await
        -> run visitor walk accumulating annotations INTO the staging snapshot
        ├─ full success ─► single ArcSwap store ─► generation++ (once) ─► log ok, status(ok), metrics.ok++
        └─ any failure  ─► publish nothing (prev snapshot + generation untouched) ─► log err (no file contents), status(err), metrics.fail++
     watch re-establishment failure ─► loud log + liveness status (distinct from reload failure)
```

---

## Implementation Units

- U1. **Watcher dependency**

**Goal:** Add the watcher dependency and test tooling. (No config field — activation is programmatic.)

**Requirements:** R1

**Dependencies:** None

**Files:**
- Modify: `Cargo.toml` (root `[workspace.dependencies]`: add `notify-debouncer-full = "0.7"`)
- Modify: `crates/cpex-core/Cargo.toml` (add `notify-debouncer-full = { workspace = true }`; add `tempfile` under `[dev-dependencies]`)

**Approach:** Follow the `{ workspace = true }` convention used by `arc-swap`, `tokio`, etc.

**Patterns to follow:** existing workspace-dependency declarations in the root `Cargo.toml`.

**Test scenarios:** Test expectation: none — dependency addition only; exercised by U4's tests.

**Verification:** workspace builds with the new dependency.

---

- U2. **Async transactional (staging) reload**

**Goal:** A reload that builds the full replacement snapshot (plugins initialized + all annotations), publishes it with a single atomic swap and one generation bump, initializes new plugin instances, serializes against other reloads, and leaves the prior config fully serving on any failure.

**Requirements:** R4, R5, R10, R14, R15

**Dependencies:** U1

**Files:**
- Modify: `crates/cpex-core/src/manager.rs` (extract a shared staged-build helper: instantiate plugins into a staging registry, `initialize().await` them, run the visitor walk accumulating annotations into the staging snapshot, then single `store()` + single generation bump; add an async reload entry, e.g. `reload_from_yaml(self: &Arc<Self>, yaml) -> Result<u64, Box<PluginError>>`; add a reload mutex; make first-time load reuse the staged helper)
- Modify: `crates/apl-cpex/src/visitor.rs` (adapt `annotate_route` usage / visitor walk to target the staging snapshot)
- Test: `crates/cpex-core/tests/config_reload_e2e.rs` (new, no-visitor path) and `crates/apl-cpex/tests/` (APL/visitor path)

**Approach:**
- Reuse the clone-then-`instantiate_plugins_into` pattern, then `initialize().await` new instances (mirror `create_override_instance`).
- Accumulate visitor annotations into the staging snapshot; publish once.
- Bump `config_generation()` exactly once, only on full success; clear the routing cache on success.
- Hold the reload mutex across the whole build+publish so concurrent reloads/mutations serialize (R14).
- Full rebuild recreates + reinitializes plugin instances (R5); no state preservation.

**Execution note:** Add a failing test first for the concurrent-mid-reload case: a request loop running across a reload must observe either fully-old or fully-new enforcement, never new-plugins-with-missing-annotations. This is the behavior the staging design exists to guarantee.

**Patterns to follow:** `load_config` (clone + instantiate + single store), `try_mutate_runtime` (publish-only-on-Ok), `create_override_instance` (`initialize().await` on new instances), `annotate_route` / `route_annotations`.

**Test scenarios:**
- Covers AE1. Happy path: valid new YAML reloads atomically; a resolved entity reflects the new config; generation advances by exactly one.
- Covers AE3. Error path (APL): reloading an invalid/uncompilable policy returns Err, the previously compiled policy still resolves, and generation does not advance.
- Covers AE2. Integration: a snapshot `Arc` obtained before reload keeps resolving the old config after the swap.
- Integration (R4, key): a concurrent request loop across a reload never observes a route with new plugins but missing annotations.
- Integration (R15): a plugin whose `initialize()` sets up state is initialized after reload (not left uninitialized).
- Edge case (R14): two concurrent reloads serialize; the final snapshot is one of them, never a mixed one.
- Error path: reloading structurally invalid YAML returns Err; the previous plugin set still resolves.

**Verification:** invalid reloads leave the prior config fully serving with generation unchanged; valid reloads swap atomically with initialized plugins; no mixed snapshot is observable.

---

- U3. **Reload observability: logs, metrics, status callback, liveness**

**Goal:** Make every reload attempt and the watcher's liveness visible.

**Requirements:** R9, R10, R11, R12, R16

**Dependencies:** U2

**Files:**
- Modify: `crates/cpex-core/src/manager.rs` (structured `tracing` on each attempt without echoing file contents; atomic success/failure counters + last-success timestamp with accessors; a registerable status callback invoked after each attempt; a `reload_status()` accessor; a distinct watcher-liveness signal — status + loud `error!` when the watch cannot be re-established)
- Test: `crates/cpex-core/tests/config_reload_e2e.rs` and/or in-module tests

**Approach:**
- `config_generation()` already covers R10; add counters/timestamp as atomics (no new metrics crate).
- Status callback: a stored `Fn(&ReloadOutcome) + Send + Sync` set via a registration method; single registration (replaces prior); invoked synchronously after each attempt; lifetime = manager lifetime. `ReloadOutcome` carries success{generation} or failure{message}.
- Liveness (R16): separate from reload counters; distinguishes "watch is down" from "no changes yet."

**Patterns to follow:** existing `tracing` calls in `manager.rs`; the `generation` atomic.

**Test scenarios:**
- Covers AE3 (observability half). Error path: a failed reload increments the failure counter, does not advance generation, invokes the callback with a failure outcome, and logs without raw file contents.
- Happy path: a successful reload increments the success counter, updates the last-success timestamp, advances generation once, invokes the callback with the new generation.
- Edge case: no callback registered — reload still succeeds and metrics update.
- R16: giving up on watch re-establishment surfaces a distinct liveness signal + loud log.

**Verification:** counters, timestamp, generation, callback, and liveness all reflect the correct outcome.

---

- U4. **FileSystem watcher, programmatic activation, and lifecycle**

**Goal:** A programmatic activation API that watches the config file's directory, debounces, re-reads the canonical path (with content-hash and empty-read guards), drives the transactional reload on the host's runtime handle, and manages watcher lifecycle and error resilience.

**Requirements:** R1, R2, R3, R6', R7, R8', R13, R17

**Dependencies:** U2, U3

**Files:**
- Create: `crates/cpex-core/src/config_watcher.rs`
- Modify: `crates/cpex-core/src/manager.rs` (`watch_config_file(self: &Arc<Self>, path, handle, debounce)`: initial staged reload, then spawn the watcher on `handle`; store a watcher handle in `RwLock<Option<...>>`; a `stop_watching()` method; closure holds `Weak<Self>`) and `crates/cpex-core/src/lib.rs` (module export)
- Test: `crates/cpex-core/tests/config_watcher_e2e.rs` (new; on-disk temp files)

**Approach:**
- `notify-debouncer-full`, watch the parent directory `Recursive`; on any debounced event re-read the canonical path and call the U2 reload on the runtime handle.
- Content-hash guard (R17): skip when unchanged; reject an empty/zero-plugin parse from a path that previously had plugins; on a read/parse error (torn in-place write) schedule one delayed re-read after the file settles.
- Keep the debouncer alive in the manager handle; closure holds `Weak<PluginManager>` (no cycle).
- Opt-in only (R6'/R7): watching exists solely because the host called this method; nothing in the config toggles it. `stop_watching()` tears the watcher down (R8').
- Errors logged and swallowed; a failed reload does not tear down the watch (R13); when re-establishment is impossible, surface the U3 liveness signal.
- Canonical-path resolution assumed within the host-controlled directory (trust boundary); do not log file contents.

**Execution note:** Use a temp directory and real file operations; simulate a ConfigMap swap by building a `..data`-style symlink and atomically renaming it, and run this on the target container runtime to actually validate AE4 rather than assuming inotify behavior.

**Patterns to follow:** external research (directory watch + canonical re-read); `Weak<PluginManager>` capture in `apl-cpex/src/register.rs`; `TaskTracker` for the spawned loop.

**Test scenarios:**
- Covers AE1. Happy path: editing the watched file in place triggers exactly one reload; new requests see the new config.
- Covers AE4. Integration: an atomic `..data` symlink swap (ConfigMap-style) is detected and reloaded without re-establishing a file-level watch. (Gating: run on the container runtime.)
- Covers AE6. Edge case: a burst of writes within the debounce window produces exactly one reload.
- Covers AE5. Happy path: `watch_config_file` activates watching; `stop_watching()` stops it (a later edit does not reload); the config file itself cannot enable watching.
- Error path (R13): the watched file briefly missing (mid-rename) does not crash; the watch survives and the next valid write reloads.
- Edge case (R17): a truncated/empty read does not reload to zero plugins; it is rejected and the settled content reloads on re-read.
- Edge case (churn): an identical-content re-sync is skipped (no generation bump).

**Verification:** direct edits and symlink swaps each reload once; empty/torn reads are rejected; identical re-syncs are skipped; activation is purely programmatic; watcher survives transient errors.

---

- U5. **FFI and Python activation entrypoints**

**Goal:** Let the actual deployers (C-ABI and Python embedders) activate watching, passing the path and a runtime handle.

**Requirements:** R1, R6', R7, R15

**Dependencies:** U4

**Files:**
- Modify: `crates/cpex-ffi/src/lib.rs` (add `cpex_watch_config_file(mgr, path, debounce_ms) -> c_int` that resolves the path, passes `SHARED_RUNTIME`'s handle to `watch_config_file`, wraps in `catch_unwind`; optionally `cpex_stop_watching`)
- Modify: `bindings/python/src/manager.rs` (add `watch_config_file(path, debounce_ms)`; may be fast-followed — see Open Questions)
- Test: `crates/cpex-ffi/tests/` (FFI smoke) and the Python binding suite

**Approach:**
- Thin pass-through supplying the FFI's runtime handle; map errors to existing FFI error codes.
- Leave the string-based `cpex_load_config` unchanged (no watching) for hosts that manage their own config.

**Patterns to follow:** `cpex_load_config` error handling + `catch_unwind` boundary; `SHARED_RUNTIME` handle access in `crates/cpex-ffi/src/lib.rs`.

**Test scenarios:**
- Happy path (FFI): activating with a valid path returns success; a subsequent on-disk edit reloads (generation advances).
- Error path (FFI): a nonexistent path returns the expected error code without panicking across the boundary.
- Happy path (Python): the binding method activates watching against a temp file.

**Verification:** the feature is reachable and functional end-to-end from at least the C-ABI surface.

---

- U6. **Documentation**

**Goal:** Correct the contradicting doc; document activation, trust boundary, caveats, observability, and the automation pattern.

**Requirements:** R5, R6', R9-R12, R16

**Dependencies:** U1, U2, U3, U4, U5

**Files:**
- Modify: `docs/content/docs/configuration.md` (replace the ~line 165 "There is no hot reload" statement; document programmatic opt-in activation, the trust boundary — CPEX applies any compilable policy without semantic/authorization checks and assumes the watched path is writable only by authorized principals — the state-reset caveat, the observability surface, and a recommended CD pattern: a pipeline that pushes a ConfigMap should poll `config_generation()` to confirm the reload landed before declaring rollout success)

**Approach:** operator-facing: how to activate/stop, what a rejected reload looks like (log / unchanged generation / failed-reload metric), the trust assumption, and that reload recreates and reinitializes plugins (state resets).

**Test scenarios:** Test expectation: none — documentation only.

**Verification:** docs no longer contradict the feature; activation, trust boundary, caveats, and the confirm-the-push pattern are discoverable.

---

## System-Wide Impact

- **Interaction graph:** activation flows host → `watch_config_file(path, handle, debounce)` → initial staged reload → spawned watcher → canonical re-read → staged reload → single `ArcSwap` store. FFI/Python gain one activation entry each; the string loaders are unchanged.
- **Error propagation:** parse/validate/instantiate/init/visitor failures publish nothing and leave the prior snapshot + generation untouched; the watcher logs and continues; re-establishment failure raises a distinct liveness signal. FFI maps errors to existing codes under `catch_unwind`.
- **State lifecycle risks:** full rebuild recreates + reinitializes plugin instances and resets in-memory state (R5, documented); the content-hash guard avoids resetting on no-op re-syncs.
- **API surface / blast radius:** the staging refactor changes the reload path's annotation target and touches `apl-cpex`'s visitor (`annotate_route` call site and internal walk state). First-time load is moved onto the same staged helper; its end-state is unchanged but it now publishes atomically (a strict improvement, not a contract break). `config_generation()` consumers (apl-cpex dispatch-plan cache) rely on generation advancing exactly once per reload — U2 guarantees this.
- **Concurrency:** a reload mutex serializes all snapshot-producing operations (watcher- and host-driven); `load_config_yaml`/reload are documented as not safe to call concurrently outside that lock.

---

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| Staging refactor touches `apl-cpex`'s `annotate_route` usage and visitor state (blast radius) | Extract a shared staged-build helper; cover with the concurrent-mid-reload test; single-publish improves first-load too |
| Reloaded plugins left uninitialized | Reload is async and calls `initialize().await` on new instances (R15), mirroring `create_override_instance` |
| Concurrent watcher + host reload corrupt visitor state / mixed snapshot | Reload mutex serializes all snapshot-producing ops (R14) |
| ConfigMap symlink-swap detection assumed rather than proven | Gate on a real `..data` atomic-rename test run on the container runtime (not a local temp dir); `PollWatcher` fallback documented |
| Silently-dead watcher looks identical to "no changes" | Distinct liveness signal + loud log (R16); document CD poll-generation confirmation |
| `notify` backend differences (macOS FSEvents, Linux-VM-on-macOS) | Re-read-on-any-event keeps correctness backend-independent; `PollWatcher` fallback |
| Watcher handle ↔ manager reference cycle | Closure holds `Weak<PluginManager>` (mirrors `apl-cpex/src/register.rs`) |
| Transient empty/truncated read reloads to zero plugins | Reject empty-from-nonempty; content-hash guard; delayed re-read on read/parse error (R17) |
| Semantically wrong-but-valid policy auto-applied | Opt-in programmatic activation (host's explicit choice); documented trust boundary; integrity signal is future work |

---

## Documentation / Operational Notes

- Hosts activate via the programmatic API and pass a runtime handle; the feature is off until they do. A rejected reload is visible via logs, an unchanged generation counter, and the failed-reload metric.
- Recommended automation: a CD pipeline pushing a ConfigMap should poll `config_generation()` (or the status accessor) to confirm the reload landed before declaring rollout success.

---

## Sources & References

- **Origin document:** [docs/brainstorms/config-hot-reload-requirements.md](docs/brainstorms/config-hot-reload-requirements.md) (R6/R8 superseded here — see Supersedes Origin Decisions)
- Related code: `crates/cpex-core/src/manager.rs`, `crates/cpex-core/src/config.rs`, `crates/apl-cpex/src/visitor.rs`, `crates/apl-cpex/src/dispatch_plan.rs`, `crates/cpex-ffi/src/lib.rs`, `bindings/python/src/manager.rs`
- Related issue: #107 (adjacent #104 config include/embedding, out of scope)
- External docs: `notify` 8.2 and `notify-debouncer-full` 0.7 (docs.rs); Kubernetes ConfigMap `..data` atomic symlink-swap behavior
- Doc to correct: `docs/content/docs/configuration.md:165`
