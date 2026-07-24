---
date: 2026-07-24
topic: config-hot-reload
---

# Configuration Hot-Reload (FileSystemSource)

## Summary

Add a file watcher that automatically reloads CPEX configuration on disk changes by calling the existing validate-before-swap load path, robust to both Kubernetes ConfigMap symlink swaps and direct editor saves, on by default with a config opt-out, and observable through structured logs, the generation counter, reload metrics, and a status callback.

---

## Problem Frame

Operators running CPEX in production update policy today by editing the YAML and restarting the process. A restart drops in-flight requests and creates a window where the enforcement plane is unavailable. In Kubernetes the pain is sharper: pushing a new ConfigMap updates the mounted file, but nothing in the pod picks it up, so the operator must trigger a rollout to apply a rule change.

The atomic-swap machinery to avoid this already exists in `crates/cpex-core/src/manager.rs`: `PluginManager` holds `runtime: arc_swap::ArcSwap<RuntimeSnapshot>` and `load_config_file(path)` builds a fresh registry on a clone, validates it, and only stores the new snapshot on success. In-flight requests finish on the old snapshot; new requests pick up the new one. A monotonic `config_generation()` counter bumps on each swap. What is missing is anything that notices a file changed and calls that path. Issue #107 references a `ConfigSource::watch()` seam, but no such trait or watcher exists in the tree today; the swap lives on the manager, not behind a source abstraction.

---

## Actors

- A1. Operator: edits policy YAML on a host/VM or pushes a Kubernetes ConfigMap, and needs the change to take effect without a restart and to know whether it landed.
- A2. CPEX process: the running server that loads config from a file path, watches it, and serves enforcement decisions across reloads.
- A3. Embedding host (via `cpex-ffi`): a process that embeds CPEX and may load config from a string or drive its own reload; out of scope as a watch target but must not be broken.

---

## Key Flows

- F1. Successful live reload
  - **Trigger:** The watched config file changes on disk (editor save, atomic rename, or ConfigMap symlink swap).
  - **Actors:** A1, A2
  - **Steps:** Watcher detects the change, coalesces any event burst, re-reads the canonical path, builds and validates a fresh snapshot, atomically swaps it in, bumps the generation counter, logs success, and records the reload in metrics/status.
  - **Outcome:** New requests are evaluated against the new config; in-flight requests finished on the old config; no restart.
  - **Covered by:** R1, R2, R3, R4, R9, R10, R11

- F2. Rejected reload
  - **Trigger:** The watched file changes to a config that fails to parse or validate.
  - **Actors:** A1, A2
  - **Steps:** Watcher detects the change and attempts a rebuild; validation fails; the swap is skipped; the previous config keeps serving; the failure is logged with the validation error, the generation counter does not advance, and the failure is recorded in metrics/status.
  - **Outcome:** Enforcement stays up on the last-good config; the operator can see the push was rejected and why.
  - **Covered by:** R4, R9, R10, R11, R13

---

## Requirements

**Change detection**
- R1. Watch the config file that was loaded from a file path and reload it on change, without restarting the process.
- R2. Detect changes under both supported deployment modes: direct in-place or atomic-rename edits on a host/VM, and Kubernetes ConfigMap updates that swap the mount via symlink. This requires watching the containing directory and re-resolving the canonical path rather than pinning a single file inode.
- R3. Coalesce rapid event bursts (multi-write editor saves, ConfigMap swaps that emit several events) so one logical change triggers at most one reload.

**Reload semantics**
- R4. Reload reuses the existing validate-before-swap path: build a fresh snapshot, validate it, and atomically swap only on success. A failed parse/validate/build leaves the previously loaded config serving.
- R5. Reload rebuilds the whole `CpexConfig`, recreating all plugin instances; in-memory plugin state (rate-limiter counters, cached connections, etc.) is reset on every reload. This caveat must be documented for operators.

**Activation and lifecycle**
- R6. Hot-reload is on by default and disabled through an opt-out field in the config document. When disabled, no watcher runs.
- R7. Watching attaches only when config is loaded from a file path. Configs loaded from a string and embedding hosts that pass no path never watch.
- R8. A reload whose new config flips the opt-out takes effect: turning it off stops the watcher; turning it back on re-establishes it.
- R13. A watcher-side failure (watched path temporarily missing, transient OS watch error) must not crash the process; it is logged and the watch is re-established where possible.

**Observability**
- R9. Every reload attempt emits a structured log line: success with the new generation number, or rejection with the validation error.
- R10. The generation counter is exposed so callers and health checks can confirm a reload landed (counter advanced) versus was rejected (counter unchanged).
- R11. Reload metrics are tracked: successful and failed reload counts and the timestamp of the last successful reload.
- R12. A reload-status callback or accessor lets an embedding host or admin endpoint react to reload outcomes programmatically.

---

## Acceptance Examples

- AE1. **Covers R1, R4.** Given a CPEX process serving from a watched policy file, when the file is edited on disk to a valid config, then a fresh snapshot is built and atomically swapped in and subsequent requests use the new policy.
- AE2. **Covers R4.** Given a request is mid-evaluation when a reload occurs, when the swap happens, then that request finishes on the old config and later requests use the new one.
- AE3. **Covers R4, R9, R10.** Given a watched policy file, when it is edited to an invalid config, then the swap is rejected, the previous config stays active, the generation counter does not advance, and the rejection is logged with the validation error.
- AE4. **Covers R2.** Given CPEX running in Kubernetes with the config mounted from a ConfigMap, when the ConfigMap is updated (mount swapped via symlink), then the change is detected and reloaded without a pod restart.
- AE5. **Covers R6, R8.** Given hot-reload enabled by default, when a reload applies a config that sets the opt-out, then the watcher stops; when a later change (applied by other means) re-enables it, the watcher is re-established.
- AE6. **Covers R3.** Given an editor that writes the file several times in quick succession, when the burst occurs, then exactly one reload is performed.

---

## Success Criteria

- An operator updates policy in production (ConfigMap push or file edit) and new requests honor the change within seconds, with no restart and no dropped in-flight requests.
- A malformed or invalid edit never takes the enforcement plane down, and the operator can tell it was rejected (log line, unchanged generation, failed-reload metric) rather than silently ignored.
- `ce-plan` can implement without having to invent the change-detection strategy, the activation model, or the observability surface.

---

## Scope Boundaries

- Multi-file config `include`/embedding is out of scope (tracked separately in issue #104).
- Partial or diffed reload that preserves unchanged plugins' in-memory state is out of scope; this feature does a full rebuild.
- A signal-based (SIGHUP) or admin-API manual reload trigger is out of scope; auto-detection covers both stated deployment modes.
- Generalizing into a full `ConfigSource` trait with multiple backends (database, remote, etc.) is out of scope; this ships the filesystem case, and the abstraction can follow if a second source appears.
- Host-driven reload for the `cpex-ffi` embedded case is out of scope as a watch target; embedding hosts that own their config file drive their own reloads.

---

## Key Decisions

- On by default, opt-out rather than opt-in: no-downtime policy updates become the default operator experience, and the risky path (a bad edit) is already contained by validate-before-swap, so defaulting on is safe.
- Full rebuild over instance diffing: matches the existing `load_config_file` behavior and keeps the reference implementation simple; the state-reset caveat is documented instead of engineered around.
- Watch the containing directory and re-resolve the canonical path: the only approach that catches ConfigMap symlink swaps, and it also covers atomic-rename editor saves, so a single mechanism serves both deployment modes.
- Reload metrics ride on the status callback plus `tracing` rather than introducing a metrics crate: no metrics facility exists in the tree today, so avoid a premature dependency and let the host wire outcomes into its own metrics system.

---

## Dependencies / Assumptions

- New dependency: the `notify` crate for filesystem watching (named in issue #107; not currently in the workspace).
- Relies on the existing `PluginManager::load_config_file` validate-before-swap behavior and `config_generation()` counter in `crates/cpex-core/src/manager.rs`.
- `tracing` is the logging surface (already a workspace dependency and used across `cpex-core`).
- Scoped in the Praxis epic alignment work (policy evaluation engine); this is the first concrete config-source implementation.

---

## Outstanding Questions

### Deferred to Planning

- [Affects R3][Technical] Debounce/coalesce interval default, and whether it is tunable via config.
- [Affects R6][Technical] Exact name and location of the opt-out field (for example under `plugin_settings` versus top-level).
- [Affects R1, R13][Technical] Ownership and lifecycle of the watcher thread within `PluginManager` (note `load_config_yaml` already takes `self: &Arc<Self>`).
- [Affects R11, R12][Technical] Whether reload metrics and the status callback are one hook or separate accessors.
- [Affects R2, R4][Needs research] Confirm `notify` behavior on macOS and Linux for symlink-directory swaps, specifically that a containing-directory watch fires on a Kubernetes ConfigMap update.
