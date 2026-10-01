// Location: ./crates/cpex-core/src/executor.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// 5-phase plugin execution engine.
//
// Dispatches plugins in strict phase order:
//   SEQUENTIAL → TRANSFORM → AUDIT → CONCURRENT → FIRE_AND_FORGET
//
// Each phase has different authority (block/modify) and scheduling
// (serial/parallel/background). The executor reads all scheduling
// decisions from PluginRef.trusted_config — never from the plugin.
//
// Extensions are passed separately from the payload and capability-
// filtered per plugin before dispatch. Extension modifications are
// merged back independently from payload modifications.
//
// Error handling respects the plugin's on_error setting:
//   - Fail: propagate error, halt pipeline
//   - Ignore: log error, continue pipeline
//   - Disable: log error, mark plugin disabled, continue
//
// Mirrors the Python framework's PluginExecutor in
// cpex/framework/manager.py.

use std::any::Any;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::time::timeout;
use tracing::{error, warn};

use crate::audit::AuditHandler;
use crate::context::PluginContextTable;
use crate::decision::{DecisionLog, PluginAction, Verdict};
use crate::effect::{DurableEffectLog, EffectEmitter, EffectRecord};
use crate::error::PluginError;
use crate::extensions::filter_extensions;
use crate::hooks::payload::{Extensions, PluginPayload, WriteToken};
use crate::plugin::OnError;
use crate::registry::{group_by_mode, HookEntry};

/// Configuration for the executor.
#[derive(Debug, Clone)]
pub struct ExecutorConfig {
    /// Maximum execution time per plugin in seconds.
    pub timeout_seconds: u64,

    /// Whether to halt on the first deny in concurrent mode.
    pub short_circuit_on_deny: bool,

    /// Hash the payload at pipeline entry for audit content provenance
    /// (`DecisionLog::input_hash`). Off by default — hashing is on the request
    /// path, so it is opt-in.
    pub capture_content_provenance: bool,

    /// Optional host namespace prefixing the audit stream ids
    /// (`"<ns>:decision"` / `"<ns>:effect"`). `None` → the bare per-type
    /// labels. Not YAML-deserialized here (this struct is code-only); the
    /// manager copies it from `plugin_settings.audit_stream_namespace`.
    pub audit_stream_namespace: Option<String>,

    /// Optional host-supplied audit epoch (executor generation id). `Some`
    /// overrides the wall-clock boot epoch; `None` keeps wall-clock. The caller
    /// owns monotonicity across generations — see
    /// [`crate::config::PluginSettings::audit_epoch`]. Code-only (this struct is
    /// not YAML-deserialized), so it never becomes a static file value.
    pub audit_epoch: Option<u64>,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: 30,
            short_circuit_on_deny: true,
            capture_content_provenance: false,
            audit_stream_namespace: None,
            audit_epoch: None,
        }
    }
}

/// Aggregate result from a full hook invocation across all phases.
///
/// Wraps the final payload, extensions, any violation, and the
/// context table. Immutable by design — policy decisions cannot be
/// tampered with after the executor returns them.
///
/// The caller should pass `context_table` into the next hook
/// invocation to preserve per-plugin local state across hooks in
/// the same request lifecycle.
///
/// Background tasks are returned separately as [`BackgroundTasks`]
/// to keep the policy result immutable.
///
/// `#[non_exhaustive]`: this result type keeps gaining fields as the
/// engine grows, so it is sealed against external struct-literal
/// construction and exhaustive destructuring — hosts read it, they don't
/// build it. Construct via [`Self::allowed_with`] / [`Self::denied`] plus
/// the `with_*` builders. New fields can then be added without breaking
/// downstream readers.
#[derive(Debug)]
#[non_exhaustive]
pub struct PipelineResult {
    /// Whether the pipeline should continue processing.
    /// `false` means a plugin denied — the pipeline was halted.
    pub continue_processing: bool,

    /// The final payload after all modifications (type-erased).
    /// `None` if the pipeline was denied before any modifications.
    ///
    /// Note this is `Some` on **every** allowed pipeline, carrying the
    /// final payload whether or not a plugin touched it. To learn
    /// whether anything actually changed, read [`Self::payload_modified`]
    /// — do not compare payload contents, and do not read `is_some()` as
    /// "was modified".
    pub modified_payload: Option<Box<dyn PluginPayload>>,

    /// Whether any plugin's payload modification was accepted into
    /// `modified_payload` above.
    ///
    /// Set by the phases that can modify (sequential, transform) at the
    /// moment a handler's payload replaces the current one, so it
    /// reflects what the executor actually applied: a plugin lacking the
    /// modify capability, or one running in a read-only phase, does not
    /// set it.
    ///
    /// This exists because the fact is knowable only here. A caller
    /// comparing payloads afterwards cannot: the payload types are
    /// type-erased with no equality, and content-shaped comparisons
    /// (e.g. a message's text) are blind to whichever parts they don't
    /// read.
    pub payload_modified: bool,

    /// The final extensions after all modifications.
    /// `None` if no plugin modified extensions.
    pub modified_extensions: Option<Extensions>,

    /// The violation that caused a deny, if any.
    pub violation: Option<crate::error::PluginViolation>,

    /// Errors from plugins that ran with `on_error: ignore` or
    /// `on_error: disable`. These plugins didn't halt the pipeline
    /// (their on_error policy said to continue), but the caller
    /// should still know the errors happened so it can log them in
    /// a structured way, retry the affected plugin, or alert.
    /// Empty when no plugin errored on a non-halt path.
    /// Fire-and-forget errors live in `BackgroundTasks` instead.
    pub errors: Vec<crate::error::PluginErrorRecord>,

    /// Optional metadata aggregated from plugins (telemetry, diagnostics).
    pub metadata: Option<serde_json::Value>,

    /// Plugin contexts indexed by plugin ID. Thread this into the
    /// next hook invocation to preserve per-plugin `local_state`.
    pub context_table: PluginContextTable,

    /// The executor's record of what each plugin did and how the pipeline
    /// ruled. Built executor-side and handed to audit sinks; never exposed
    /// to plugins through `PluginContext`.
    pub decision_log: DecisionLog,
}

impl PipelineResult {
    /// Pipeline completed — all plugins allowed.
    pub fn allowed_with(
        payload: Box<dyn PluginPayload>,
        extensions: Extensions,
        context_table: PluginContextTable,
    ) -> Self {
        Self {
            continue_processing: true,
            modified_payload: Some(payload),
            payload_modified: false,
            modified_extensions: Some(extensions),
            violation: None,
            errors: Vec::new(),
            metadata: None,
            context_table,
            decision_log: DecisionLog::new(),
        }
    }

    /// Record that a plugin's payload modification was applied. Chained
    /// off [`Self::allowed_with`] by the executor, mirroring
    /// [`Self::with_errors`].
    pub fn with_payload_modified(mut self, modified: bool) -> Self {
        self.payload_modified = modified;
        self
    }

    /// Pipeline was denied by a plugin.
    pub fn denied(
        violation: crate::error::PluginViolation,
        extensions: Extensions,
        context_table: PluginContextTable,
    ) -> Self {
        Self {
            continue_processing: false,
            modified_payload: None,
            payload_modified: false,
            modified_extensions: Some(extensions),
            violation: Some(violation),
            errors: Vec::new(),
            metadata: None,
            context_table,
            decision_log: DecisionLog::new(),
        }
    }

    /// Replace the errors vec on a constructed PipelineResult. Used by
    /// the executor to attach errors collected from `on_error: ignore`
    /// / `on_error: disable` plugins.
    pub fn with_errors(mut self, errors: Vec<crate::error::PluginErrorRecord>) -> Self {
        self.errors = errors;
        self
    }

    /// Attach the executor's decision log to a constructed result.
    pub fn with_decision_log(mut self, decision_log: DecisionLog) -> Self {
        self.decision_log = decision_log;
        self
    }

    /// Whether this result represents a denial.
    pub fn is_denied(&self) -> bool {
        !self.continue_processing
    }
}

/// Handles to fire-and-forget background tasks spawned by the executor.
///
/// Returned separately from [`PipelineResult`] so that the policy
/// result stays immutable. If not awaited, tasks complete on their
/// own in the background. Call `wait_for_background_tasks()` when you
/// need to ensure tasks have finished (tests, graceful shutdown,
/// audit flush).
pub struct BackgroundTasks {
    tasks: Vec<(String, tokio::task::JoinHandle<()>)>,
}

impl BackgroundTasks {
    /// Create an empty set of background tasks.
    pub fn empty() -> Self {
        Self { tasks: Vec::new() }
    }

    /// Create from a list of (plugin_name, handle) pairs.
    fn from_handles(tasks: Vec<(String, tokio::task::JoinHandle<()>)>) -> Self {
        Self { tasks }
    }

    /// Whether there are any background tasks.
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    /// Number of background tasks.
    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    /// Wait for all fire-and-forget background tasks to complete.
    ///
    /// Returns a list of errors from any tasks that panicked.
    /// An empty list means all tasks completed successfully.
    ///
    /// Consumes `self` — each task handle can only be awaited once.
    ///
    /// If not called, background tasks still complete on their own.
    /// Use this for tests, graceful shutdown, or when you need to
    /// ensure audit/logging tasks have flushed before proceeding.
    pub async fn wait_for_background_tasks(self) -> Vec<crate::error::PluginError> {
        let mut errors = Vec::new();
        for (plugin_name, handle) in self.tasks {
            if let Err(e) = handle.await {
                errors.push(crate::error::PluginError::Execution {
                    plugin_name,
                    message: format!("background task panicked: {}", e),
                    source: None,
                    code: None,
                    details: std::collections::HashMap::new(),
                    proto_error_code: None,
                });
            }
        }
        errors
    }
}

impl fmt::Debug for BackgroundTasks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackgroundTasks")
            .field("count", &self.tasks.len())
            .finish()
    }
}

/// 5-phase plugin execution engine.
///
/// Dispatches hooks through the phase pipeline:
///
/// ```text
/// SEQUENTIAL → TRANSFORM → AUDIT → CONCURRENT → FIRE_AND_FORGET
/// ```
///
/// The executor's only state is its config and the auto-attached audit
/// sinks; all per-request state comes from the arguments. One executor
/// instance can serve multiple concurrent hook invocations.
#[derive(Clone)]
pub struct Executor {
    config: ExecutorConfig,

    /// Observation-only sinks invoked at the verdict of every pipeline run.
    /// Set when the manager builds the runtime snapshot; empty otherwise.
    /// They receive the decision log but cannot influence the outcome.
    audit_handlers: Vec<Arc<dyn AuditHandler>>,

    /// Durable write-ahead log for irreversible effects. `None` (default) =
    /// ordering-only: effects still emit to the audit sinks, but
    /// `begin_effect` is not crash-safe or fail-closed. Installed from
    /// `plugin_settings.effect_log_path` or programmatically. Opt-in.
    effect_log: Option<Arc<dyn DurableEffectLog>>,

    /// Audit stream identity + counters. `epoch` is the executor's boot time
    /// (Unix nanos), captured once — it scopes the counters so a restart is
    /// distinguishable from a loss and orders records across restarts. Each
    /// record carries its per-type counter (`decision_seq` / `effect_seq`,
    /// gap-free → completeness) and the shared `emission_seq` (global across
    /// both → interleaved order). The counters are `Arc` so copy-on-write
    /// snapshot mutations stay on the same stream.
    epoch: u64,
    decision_seq: Arc<AtomicU64>,
    effect_seq: Arc<AtomicU64>,
    emission_seq: Arc<AtomicU64>,

    /// Optional host namespace prefixing the per-type stream ids
    /// (`"<ns>:decision"` / `"<ns>:effect"`). `None` → the bare labels, so the
    /// default is unchanged. Set by the manager from
    /// `plugin_settings.audit_stream_namespace`.
    stream_namespace: Option<String>,
}

/// Compose a stream id from an optional host namespace and the per-type label.
/// Namespace present → `"<ns>:<kind>"`; absent → the bare label, keeping the
/// default behavior. `:` cannot appear in a Kubernetes resource name, so it
/// never collides with a pod-name namespace.
fn compose_stream_id(namespace: Option<&str>, kind: &str) -> String {
    match namespace {
        Some(ns) => format!("{ns}:{kind}"),
        None => kind.to_string(),
    }
}

impl Executor {
    /// Create a new executor with the given configuration.
    ///
    /// The audit stream identity is read from the config here, at construction:
    /// `audit_epoch` overrides the epoch (else wall-clock), and
    /// `audit_stream_namespace` prefixes both per-type stream ids. Setting it at
    /// `new` — rather than a post-construction setter — means the direct path
    /// (`Executor::new(cfg)`) and the manager's YAML path (which copies the
    /// values into this config in `snapshot_from_config`) behave identically,
    /// and the identity can never change mid-process.
    pub fn new(config: ExecutorConfig) -> Self {
        // Host override, else boot time in Unix nanoseconds — an orderable epoch
        // that needs no persistence. A new executor (restart or config reload)
        // gets a larger value, so a verifier tells a reset from a loss. When a
        // host overrides it, the host owns that monotonicity (see
        // `ExecutorConfig::audit_epoch`).
        let epoch = config.audit_epoch.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0)
        });
        let stream_namespace = config.audit_stream_namespace.clone();
        Self {
            config,
            audit_handlers: Vec::new(),
            effect_log: None,
            epoch,
            decision_seq: Arc::new(AtomicU64::new(0)),
            effect_seq: Arc::new(AtomicU64::new(0)),
            emission_seq: Arc::new(AtomicU64::new(0)),
            stream_namespace,
        }
    }

    /// Install a durable effect log (WAL). When present, `begin_effect` is
    /// crash-safe and fail-closed; when absent, effect auditing is
    /// ordering-only. Builder form, used when constructing from config.
    pub fn with_effect_log(mut self, effect_log: Arc<dyn DurableEffectLog>) -> Self {
        self.effect_log = Some(effect_log);
        self
    }

    /// Install a durable effect log via copy-on-write snapshot mutation — the
    /// manager's programmatic path, mirroring [`Self::push_audit_handler`].
    pub fn set_effect_log(&mut self, effect_log: Arc<dyn DurableEffectLog>) {
        self.effect_log = Some(effect_log);
    }

    /// The installed durable effect log, if any — for the host to run
    /// crash recovery at startup (see `PluginManager::recover_effects`).
    pub fn effect_log(&self) -> Option<Arc<dyn DurableEffectLog>> {
        self.effect_log.clone()
    }

    /// This generation's audit epoch. The manager reads it across a reload to
    /// check the epoch strictly increased (see `snapshot_from_config`).
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Attach observation-only audit sinks, invoked at the verdict of every
    /// pipeline run. Used by the manager when it builds the runtime snapshot.
    pub fn with_audit_handlers(mut self, audit_handlers: Vec<Arc<dyn AuditHandler>>) -> Self {
        self.audit_handlers = audit_handlers;
        self
    }

    /// Append a single audit sink. Used by the manager's
    /// `register_audit_handler` through copy-on-write snapshot mutation.
    pub fn push_audit_handler(&mut self, handler: Arc<dyn AuditHandler>) {
        self.audit_handlers.push(handler);
    }

    /// Invoke every audit sink with the finalized decision, once per pipeline
    /// run. Observation-only — the executor ignores whatever they return.
    /// Assign this decision's stream identity + sequence numbers. The executor
    /// writes its **own** record here — a step distinct from the read-only
    /// handoff in [`Self::emit_audit`] (which takes `&DecisionLog`), so a sink
    /// never receives anything mutable. `decision_seq` is gap-free within the
    /// decision stream (completeness); `emission_seq` is the shared global
    /// counter across decisions and effects (interleaved order). Stamped even
    /// with no sinks — it's a property of the stream and rides on
    /// `PipelineResult.decision_log`.
    fn stamp_decision_stream(&self, decisions: &mut DecisionLog) {
        decisions.set_stream(
            self.epoch,
            compose_stream_id(self.stream_namespace.as_deref(), "decision"),
            self.decision_seq.fetch_add(1, Ordering::Relaxed),
            self.emission_seq.fetch_add(1, Ordering::Relaxed),
        );
    }

    /// Emit a single allow decision record for an invocation that resolved to
    /// zero plugins, keeping the audit stream dense at one record per
    /// invocation. **Cheap no-op when no audit sink is attached** — an
    /// unaudited host pays only a length check, building no record and
    /// consuming no sequence number. The manager calls this at its zero-plugin
    /// short-circuits (which return before reaching `execute`), and `execute`
    /// calls it for a direct empty invocation. Captures the same span /
    /// input-label / input-hash provenance a normal run records at entry, then
    /// stamps and emits.
    pub(crate) async fn emit_empty_allow(
        &self,
        payload: &dyn PluginPayload,
        extensions: &Extensions,
    ) {
        if self.audit_handlers.is_empty() {
            return;
        }
        let mut decisions = DecisionLog::new();
        let request = extensions.request.as_ref();
        decisions.set_span(crate::decision::Span::for_request(
            request.and_then(|r| r.trace_id.as_deref()),
            request.and_then(|r| r.span_id.as_deref()),
        ));
        if let Some(sec) = extensions.security.as_ref() {
            let mut labels: Vec<String> = sec.labels.iter().cloned().collect();
            labels.sort_unstable();
            decisions.set_input_labels(labels);
        }
        if self.config.capture_content_provenance {
            let hash = payload
                .audit_bytes()
                .map(|b| crate::hooks::payload::content_hash(&b));
            decisions.set_input_hash(hash);
        }
        decisions.finalize(Verdict::Allow);
        self.stamp_decision_stream(&mut decisions);
        self.emit_audit(payload, extensions, &decisions).await;
    }

    async fn emit_audit(
        &self,
        payload: &dyn PluginPayload,
        extensions: &Extensions,
        decisions: &DecisionLog,
    ) {
        use futures::FutureExt;
        use std::panic::AssertUnwindSafe;

        if self.audit_handlers.is_empty() {
            return;
        }

        // Observation-only: an audit sink must never crash or hang the
        // request whose verdict is already decided. Contain panics and bound
        // each call; log loudly and move on. A lost audit record is itself a
        // problem (see the durability plan) but that never justifies letting a
        // sink take down the request.
        let timeout_dur = Duration::from_secs(self.config.timeout_seconds);
        for handler in &self.audit_handlers {
            let call =
                AssertUnwindSafe(handler.handle(payload, extensions, decisions)).catch_unwind();
            match timeout(timeout_dur, call).await {
                Ok(Ok(())) => {},
                Ok(Err(_panic)) => {
                    error!(
                        "audit sink '{}' panicked during emit — contained",
                        handler.name()
                    );
                },
                Err(_elapsed) => {
                    error!(
                        "audit sink '{}' exceeded {}s during emit — skipped",
                        handler.name(),
                        timeout_dur.as_secs()
                    );
                },
            }
        }
    }

    /// Execute a hook invocation through the 5-phase pipeline.
    ///
    /// # Arguments
    ///
    /// * `entries` — HookEntries for this hook, sorted by priority.
    /// * `payload` — The typed payload (type-erased as Box<dyn PluginPayload>).
    /// * `extensions` — The full extensions (filtered per plugin before dispatch).
    /// * `context_table` — Optional context table from a previous hook invocation.
    ///   If `None`, fresh contexts are created for each plugin.
    ///
    /// # Returns
    ///
    /// A tuple of:
    /// - `PipelineResult` — immutable policy result with payload,
    ///   extensions, violation, and context table.
    /// - `BackgroundTasks` — handles to fire-and-forget tasks. Call
    ///   `wait_for_background_tasks()` to await them, or drop to let
    ///   them complete in the background.
    pub async fn execute(
        &self,
        entries: &[HookEntry],
        payload: Box<dyn PluginPayload>,
        extensions: Extensions,
        context_table: Option<PluginContextTable>,
        task_tracker: &tokio_util::task::TaskTracker,
    ) -> (PipelineResult, BackgroundTasks) {
        let mut ctx_table = context_table.unwrap_or_default();

        // A hook that resolves to zero plugins is a normal case (nothing is
        // configured for this entity). It still emits exactly one allow record
        // so the audit stream stays dense at one record per invocation — but
        // `emit_empty_allow` is a no-op when no sink is attached, so an
        // unaudited host pays nothing. (The manager short-circuits most
        // zero-plugin invocations before reaching here and calls
        // `emit_empty_allow` itself; this covers a direct `execute(&[], …)`.)
        if entries.is_empty() {
            self.emit_empty_allow(&*payload, &extensions).await;
            return (
                PipelineResult::allowed_with(payload, extensions, ctx_table),
                BackgroundTasks::empty(),
            );
        }

        // Group entries by mode (from trusted_config)
        let (sequential, transform, audit, concurrent, fire_and_forget) = group_by_mode(entries);

        let mut current_payload = payload;
        let mut current_extensions = extensions;
        // Accumulator for errors from `on_error: ignore` / `on_error:
        // disable` plugins across all phases. Surfaced to the caller
        // via `PipelineResult.errors` so swallowed failures stay
        // observable. Halt-condition errors (Fail, deny) skip this and
        // become the violation directly.
        let mut errors: Vec<crate::error::PluginErrorRecord> = Vec::new();
        // Sticky across both modifying phases: true once any handler's
        // payload has been accepted. Reported on the result so callers
        // read an exact signal instead of comparing payload contents.
        let mut payload_modified = false;

        // The executor's private record of what each plugin did and how the
        // pipeline ruled. Threaded through the phases, finalized at each
        // return point, and attached to the result for audit sinks.
        let mut decisions = DecisionLog::new();
        // This interception's node identity in the decision graph: a fresh
        // span whose parent is the request's span (the upstream call that
        // triggered us), within the request's trace (child-span model).
        let request = current_extensions.request.as_ref();
        decisions.set_span(crate::decision::Span::for_request(
            request.and_then(|r| r.trace_id.as_deref()),
            request.and_then(|r| r.span_id.as_deref()),
        ));
        // Capture the taint the request arrived with — the input side of this
        // node's provenance. A sink diffs it against the final labels to see
        // what the pipeline added. Sorted so the record is deterministic.
        if let Some(sec) = current_extensions.security.as_ref() {
            let mut labels: Vec<String> = sec.labels.iter().cloned().collect();
            labels.sort_unstable();
            decisions.set_input_labels(labels);
        }
        // Content-addressed input provenance — the payload's hash at entry,
        // before any plugin mutates it. Opt-in (hashing is on the request
        // path); only the digest is kept, never the bytes.
        if self.config.capture_content_provenance {
            let hash = current_payload
                .audit_bytes()
                .map(|b| crate::hooks::payload::content_hash(&b));
            decisions.set_input_hash(hash);
        }

        if let Some(v) = self
            .run_serial_phase(
                &sequential,
                &mut current_payload,
                &mut current_extensions,
                &mut ctx_table,
                true, // can_block
                true, // can_modify
                "SEQUENTIAL",
                &mut errors,
                &mut decisions,
                &mut payload_modified,
            )
            .await
        {
            decisions.finalize(Verdict::Deny(v.clone()));
            self.stamp_decision_stream(&mut decisions);
            self.emit_audit(&*current_payload, &current_extensions, &decisions)
                .await;
            return (
                PipelineResult::denied(v, current_extensions, ctx_table)
                    .with_errors(errors)
                    .with_decision_log(decisions),
                BackgroundTasks::empty(),
            );
        }

        // Phase 2: TRANSFORM — serial, chained, can modify, cannot block.
        // can_block=false means denials are suppressed (returns None).
        self.run_serial_phase(
            &transform,
            &mut current_payload,
            &mut current_extensions,
            &mut ctx_table,
            false, // can_block
            true,  // can_modify
            "TRANSFORM",
            &mut errors,
            &mut decisions,
            &mut payload_modified,
        )
        .await;

        self.run_ref_phase(
            &audit,
            &*current_payload,
            &current_extensions,
            &ctx_table,
            "AUDIT",
            &mut errors,
        )
        .await;

        if let Some(violation) = self
            .run_concurrent_phase(
                &concurrent,
                &*current_payload,
                &current_extensions,
                &ctx_table,
                &mut errors,
                &mut decisions,
            )
            .await
        {
            decisions.finalize(Verdict::Deny(violation.clone()));
            self.stamp_decision_stream(&mut decisions);
            self.emit_audit(&*current_payload, &current_extensions, &decisions)
                .await;
            return (
                PipelineResult::denied(violation, current_extensions, ctx_table)
                    .with_errors(errors)
                    .with_decision_log(decisions),
                BackgroundTasks::empty(),
            );
        }

        // Phase 5: FIRE_AND_FORGET — background, read-only, ignore results.
        // FAF errors don't go in PipelineResult.errors — they're delivered
        // via BackgroundTasks::wait_for_background_tasks() instead.
        let bg_handles = self.spawn_fire_and_forget(
            &fire_and_forget,
            &*current_payload,
            &current_extensions,
            &ctx_table,
            task_tracker,
        );

        decisions.finalize(Verdict::Allow);
        self.stamp_decision_stream(&mut decisions);
        self.emit_audit(&*current_payload, &current_extensions, &decisions)
            .await;
        (
            PipelineResult::allowed_with(current_payload, current_extensions, ctx_table)
                .with_errors(errors)
                .with_decision_log(decisions)
                .with_payload_modified(payload_modified),
            BackgroundTasks::from_handles(bg_handles),
        )
    }

    /// Run a serial phase — plugins execute one at a time, each seeing
    /// the (possibly modified) payload from the previous.
    ///
    /// The framework retains ownership of the payload. Handlers receive
    /// a borrow and clone only if they modify. Modified payloads in
    /// the result replace the current payload.
    ///
    /// `payload_modified` is set to `true` when a handler's payload is
    /// accepted, and never cleared — this is the only place that fact is
    /// observable, so it's reported out rather than left to be guessed
    /// from the resulting payload's contents.
    ///
    /// Each plugin's context is looked up in the context table (preserving
    /// `local_state` from previous hooks) or created fresh. After execution,
    /// `global_state` changes are merged back so the next plugin sees them.
    #[allow(clippy::too_many_arguments)] // internal phase helper — args have distinct types and meaning
    async fn run_serial_phase(
        &self,
        entries: &[HookEntry],
        payload: &mut Box<dyn PluginPayload>,
        extensions: &mut Extensions,
        ctx_table: &mut PluginContextTable,
        can_block: bool,
        can_modify: bool,
        phase_label: &str,
        errors: &mut Vec<crate::error::PluginErrorRecord>,
        decisions: &mut DecisionLog,
        payload_modified: &mut bool,
    ) -> Option<crate::error::PluginViolation> {
        for entry in entries {
            // Borrow names/ids on the happy path — allocate only when
            // building a violation or stashing the local_state back into
            // the table. Previously `name.to_string()` + `id.to_string()`
            // ran unconditionally on every plugin per invoke.
            let plugin_name = entry.plugin_ref.name();
            let plugin_id = entry.plugin_ref.id();
            let on_error = entry.plugin_ref.trusted_config().on_error;
            let phase = entry.plugin_ref.trusted_config().mode;
            // What this plugin did, recorded after it runs (or inline before a
            // halting return). Defaults to Allowed; the modify and error paths
            // update it.
            let mut action = PluginAction::Allowed;

            // Take this plugin's context out of the table — pulls its stored
            // local_state and seeds global_state from the canonical store.
            // Replaces the previous values().last() seed, which was
            // non-deterministic across HashMap iteration orders.
            let mut ctx = ctx_table.take_context(plugin_id);

            // Filter extensions per plugin based on declared capabilities.
            // Produces a filtered view with None for ungated slots.
            // Also sets write tokens for plugins with write capabilities.
            let capabilities: std::collections::HashSet<String> = entry
                .plugin_ref
                .trusted_config()
                .capabilities
                .iter()
                .cloned()
                .collect();
            let mut filtered = filter_extensions(extensions, &capabilities);

            // Set write tokens based on capabilities
            if capabilities.contains("write_headers") {
                filtered.http_write_token = Some(WriteToken::new());
            }
            if capabilities.contains("append_labels") {
                filtered.labels_write_token = Some(WriteToken::new());
            }
            if capabilities.contains("append_delegation") {
                filtered.delegation_write_token = Some(WriteToken::new());
            }
            // Grant the effect-emit capability the same way — a per-invoke
            // handle on the filtered extensions, only for capable plugins.
            if capabilities.contains("emit_effect") {
                filtered.effect_emitter =
                    crate::effect::EffectEmitterSlot::installed(Arc::new(AuditEffectEmitter {
                        handlers: self.audit_handlers.clone(),
                        plugin_name: plugin_name.to_string(),
                        timeout: Duration::from_secs(self.config.timeout_seconds),
                        // The configured WAL (opt-in). `None` → ordering-only, not
                        // fail-closed; `Some` → durable-before-fanout, fail-closed.
                        durable: self.effect_log.clone(),
                        epoch: self.epoch,
                        stream_seq: self.effect_seq.clone(),
                        emission_seq: self.emission_seq.clone(),
                        stream_namespace: self.stream_namespace.clone(),
                    }));
            }

            // Execute with timeout — handler borrows payload, gets filtered
            // extensions. Contain a panic the same way the concurrent phase
            // does (`catch_unwind`): a panic between `begin_effect` and
            // `complete_effect` would otherwise unwind the whole request
            // future. Collapsing it into a `PluginError` lets `on_error`
            // decide and keeps the pipeline's bookkeeping intact; the orphaned
            // WAL entry is left for recovery to reconcile as `unknown` rather
            // than crashing the request.
            use futures::FutureExt;
            let timeout_dur = Duration::from_secs(self.config.timeout_seconds);
            let result = timeout(
                timeout_dur,
                std::panic::AssertUnwindSafe(entry.handler.invoke(&**payload, &filtered, &mut ctx))
                    .catch_unwind(),
            )
            .await
            .map(|caught| {
                caught.unwrap_or_else(|panic| {
                    let msg = panic
                        .downcast_ref::<&'static str>()
                        .map(|s| s.to_string())
                        .or_else(|| panic.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "unknown panic".to_string());
                    error!("{} plugin '{}' panicked: {}", phase_label, plugin_name, msg);
                    Err(Box::new(crate::error::PluginError::Execution {
                        plugin_name: plugin_name.to_string(),
                        message: format!("task panicked: {msg}"),
                        source: None,
                        code: Some("panic".into()),
                        details: std::collections::HashMap::new(),
                        proto_error_code: None,
                    }))
                })
            });

            match result {
                Ok(Ok(result_box)) => {
                    if let Some(erased) = extract_erased(result_box) {
                        if !erased.continue_processing && can_block {
                            if let Some(mut v) = erased.violation {
                                v.plugin_name = Some(plugin_name.to_string());
                                decisions.record(plugin_name, phase, PluginAction::Denied);
                                return Some(v);
                            }
                        }

                        // A block signalled from a non-blocking phase
                        // (Transform): suppressed by the phase contract
                        // (can_modify, not can_block), but recorded as the
                        // plugin's actual intent — never a plain allow.
                        // Enforcement is unchanged (the pipeline proceeds);
                        // this plugin's modifications are skipped, since it
                        // asked to stop rather than shape.
                        //
                        // Keys on `violation.is_some()`, mirroring the blocking
                        // branch above: a stop signal is only recorded as a
                        // deny / DenyIgnored when it carries a violation. The
                        // `PluginResult` contract documents that a violation is
                        // present whenever `continue_processing` is false, and
                        // `PluginResult::deny()` always sets one — so this holds
                        // for any plugin built through the constructors. A
                        // hand-built stop with no violation would fall through
                        // to allow/modify in either phase; the assert pins that
                        // contract so such a result surfaces in tests rather
                        // than silently reading as an allow.
                        debug_assert!(
                            erased.continue_processing || erased.violation.is_some(),
                            "{} plugin '{}' set continue_processing=false without a violation; \
                             use PluginResult::deny() so the stop is recorded, not read as allow",
                            phase_label,
                            plugin_name,
                        );
                        let deny_ignored =
                            !erased.continue_processing && !can_block && erased.violation.is_some();
                        if deny_ignored {
                            action = PluginAction::DenyIgnored;
                        }

                        // Accept modifications
                        if can_modify && !deny_ignored {
                            if let Some(mp) = erased.modified_payload {
                                *payload = mp;
                                action = PluginAction::ModifiedPayload;
                                *payload_modified = true;
                            }
                            if let Some(mut owned) = erased.modified_extensions {
                                let mut immutable_ok = false;
                                if extensions.validate_immutable(&owned) {
                                    // `merge_owned` enforces the tiers per
                                    // *field*, gated on the write tokens that
                                    // `owned` carries. It is not a slot swap: a
                                    // field with no token keeps its canonical
                                    // value, so an ungated edit is dropped
                                    // rather than merged. Previously this arm
                                    // was reached by a bare `else` that merged
                                    // the plugin's whole capability-filtered
                                    // view over canonical state — a plugin with
                                    // no security capability could wipe the
                                    // pipeline's labels by returning `custom`.
                                    //
                                    // The monotonic label check that used to
                                    // live here moved into `merge_security`,
                                    // where it applies unconditionally instead
                                    // of only when `read_labels` was held.
                                    //
                                    // Authority is re-derived from *this*
                                    // plugin's declared capabilities rather than
                                    // read off the returned value. A handler is
                                    // free to build its `OwnedExtensions` any
                                    // way it likes — apl-cpex's synthetic route
                                    // handler returns `cow_copy()` of a freshly
                                    // accumulated `Extensions`, whose tokens
                                    // `Clone` deliberately drops — so tokens
                                    // surviving the round trip is a statement
                                    // about plumbing, not about permission. The
                                    // capability set is the real grant, and it
                                    // cannot be widened by the return value.
                                    owned.http_write_token = capabilities
                                        .contains("write_headers")
                                        .then(WriteToken::new);
                                    owned.labels_write_token = capabilities
                                        .contains("append_labels")
                                        .then(WriteToken::new);
                                    owned.delegation_write_token = capabilities
                                        .contains("append_delegation")
                                        .then(WriteToken::new);
                                    immutable_ok = true;
                                }
                                // Monotonic security labels: a plugin that can see
                                // labels (`read_labels`) may only add them, never
                                // remove. A plugin without `read_labels` saw an empty
                                // label set in its filtered view, so an absent label
                                // there is not a removal.
                                let labels_ok = !capabilities.contains("read_labels")
                                    || match (&extensions.security, &owned.security) {
                                        (Some(orig), Some(new)) => {
                                            new.labels.is_superset(&orig.labels)
                                        },
                                        _ => true,
                                    };

                                // Candidate-constraint authority: the folded routing
                                // constraint is the policy engine's output. Only a
                                // holder of `write_candidate_constraint` may create,
                                // change, or remove it; any other plugin that alters
                                // the slot (by value) is rejected. A plugin that
                                // leaves it untouched passes (the common case).
                                let constraint_ok =
                                    extensions.candidate_constraint_write_ok(&owned, &capabilities);

                                if !immutable_ok {
                                    warn!(
                                        "{} plugin '{}' violated immutable tier — \
                                         modified an immutable extension slot. \
                                         Extension changes rejected.",
                                        phase_label, plugin_name
                                    );
                                } else if !labels_ok {
                                    warn!(
                                        "{} plugin '{}' violated monotonic tier — \
                                         removed a security label. \
                                         Extension changes rejected.",
                                        phase_label, plugin_name
                                    );
                                } else if !constraint_ok {
                                    warn!(
                                        "{} plugin '{}' lacks `write_candidate_constraint` \
                                         — attempted to modify the policy engine's routing \
                                         constraint. Extension changes rejected.",
                                        phase_label, plugin_name
                                    );
                                } else {
                                    extensions.merge_owned(owned);
                                    if action == PluginAction::Allowed {
                                        action = PluginAction::ModifiedExtensions;
                                    }
                                }
                            }
                        }

                        // Plugin writes to ctx.global_state are committed back
                        // to the canonical store via store_context() below.
                    }
                    // If extract failed or no modifications — payload unchanged
                },
                Ok(Err(e)) => {
                    // A contained panic (from the `catch_unwind` above) carries
                    // code "panic". Surface it with the same "plugin_panic"
                    // violation code the concurrent phase uses, so a host or
                    // sink can distinguish a panic from an ordinary plugin error
                    // by code, regardless of which phase it happened in.
                    let is_panic = matches!(
                        e.as_ref(),
                        crate::error::PluginError::Execution { code: Some(c), .. }
                            if c.as_str() == "panic"
                    );
                    error!("{} plugin '{}' failed: {}", phase_label, plugin_name, e);
                    action = PluginAction::Error(e.to_string());
                    match on_error {
                        OnError::Fail if can_block => {
                            let mut v = crate::error::PluginViolation::new(
                                if is_panic {
                                    "plugin_panic"
                                } else {
                                    "plugin_error"
                                },
                                format!("Plugin '{}' failed: {}", plugin_name, e),
                            );
                            v.plugin_name = Some(plugin_name.to_string());
                            decisions.record(plugin_name, phase, action.clone());
                            return Some(v);
                        },
                        // Any non-halt outcome (Fail-in-non-blocking-phase,
                        // Ignore, Disable): record the error so the caller
                        // sees it in PipelineResult.errors instead of
                        // having to read the warn-log.
                        OnError::Fail => {
                            warn!(
                                "{} plugin '{}' on_error=fail in non-blocking phase — not halting",
                                phase_label, plugin_name,
                            );
                            errors.push((&e).into());
                        },
                        OnError::Ignore => {
                            errors.push((&e).into());
                        },
                        OnError::Disable => {
                            warn!(
                                "{} plugin '{}' disabled after error",
                                phase_label, plugin_name
                            );
                            errors.push((&e).into());
                            entry.plugin_ref.disable();
                        },
                    }
                },
                Err(_) => {
                    error!("{} plugin '{}' timed out", phase_label, plugin_name);
                    action = PluginAction::Error("timed out".to_string());
                    let timeout_err = crate::error::PluginError::Timeout {
                        plugin_name: plugin_name.to_string(),
                        timeout_ms: timeout_dur.as_millis() as u64,
                        proto_error_code: None,
                    };
                    match on_error {
                        OnError::Fail if can_block => {
                            let mut v = crate::error::PluginViolation::new(
                                "plugin_timeout",
                                format!("Plugin '{}' timed out", plugin_name),
                            );
                            v.plugin_name = Some(plugin_name.to_string());
                            decisions.record(plugin_name, phase, action.clone());
                            return Some(v);
                        },
                        OnError::Fail => {
                            warn!(
                                "{} plugin '{}' on_error=fail (timeout) in non-blocking phase — not halting",
                                phase_label, plugin_name,
                            );
                            errors.push((&timeout_err).into());
                        },
                        OnError::Ignore => {
                            errors.push((&timeout_err).into());
                        },
                        OnError::Disable => {
                            warn!(
                                "{} plugin '{}' disabled after timeout",
                                phase_label, plugin_name
                            );
                            errors.push((&timeout_err).into());
                            entry.plugin_ref.disable();
                        },
                    }
                },
            }

            // Record what this plugin did (halting paths recorded inline above
            // and returned before reaching here).
            decisions.record(plugin_name, phase, action);

            // Commit this plugin's context back to the table — replaces the
            // canonical global_state with its (possibly modified) copy and
            // stores the local_state for the next hook invocation. The
            // global_state move is free; only the local_state insert allocates.
            ctx_table.store_context(plugin_id, ctx);
        }

        None // no denial
    }

    /// Run a read-only phase — plugins receive &payload, results discarded.
    async fn run_ref_phase(
        &self,
        entries: &[HookEntry],
        payload: &dyn PluginPayload,
        extensions: &Extensions,
        ctx_table: &PluginContextTable,
        phase_label: &str,
        errors: &mut Vec<crate::error::PluginErrorRecord>,
    ) {
        for entry in entries {
            let plugin_name = entry.plugin_ref.name().to_string();
            let plugin_id = entry.plugin_ref.id();
            let on_error = entry.plugin_ref.trusted_config().on_error;
            // Read-only phase — snapshot the plugin's local_state and the
            // canonical global_state, no merge-back.
            let mut ctx = ctx_table.snapshot_context(plugin_id);
            // Filter extensions per plugin — read-only, no write tokens.
            let capabilities: std::collections::HashSet<String> = entry
                .plugin_ref
                .trusted_config()
                .capabilities
                .iter()
                .cloned()
                .collect();
            let filtered = filter_extensions(extensions, &capabilities);
            let timeout_dur = Duration::from_secs(self.config.timeout_seconds);

            let result = timeout(
                timeout_dur,
                entry.handler.invoke(payload, &filtered, &mut ctx),
            )
            .await;

            // Audit / fire-and-forget cannot block, so OnError::Fail can't
            // halt the pipeline — but OnError::Disable must still take a
            // repeatedly-failing plugin out of rotation. The previous code
            // ignored on_error entirely, so Disable plugins kept failing
            // forever no matter how many invocations errored. All non-halt
            // failures also push a record into PipelineResult.errors.
            match result {
                Ok(Ok(_)) => {}, // read-only — discard result and ext_clone
                Ok(Err(e)) => {
                    warn!(
                        "{} plugin '{}' error (ignored): {}",
                        phase_label, plugin_name, e
                    );
                    errors.push((&e).into());
                    if matches!(on_error, OnError::Disable) {
                        warn!(
                            "{} plugin '{}' disabled after error",
                            phase_label, plugin_name
                        );
                        entry.plugin_ref.disable();
                    }
                },
                Err(_) => {
                    warn!(
                        "{} plugin '{}' timed out (ignored)",
                        phase_label, plugin_name
                    );
                    let timeout_err = crate::error::PluginError::Timeout {
                        plugin_name: plugin_name.clone(),
                        timeout_ms: timeout_dur.as_millis() as u64,
                        proto_error_code: None,
                    };
                    errors.push((&timeout_err).into());
                    if matches!(on_error, OnError::Disable) {
                        warn!(
                            "{} plugin '{}' disabled after timeout",
                            phase_label, plugin_name
                        );
                        entry.plugin_ref.disable();
                    }
                },
            }
        }
    }

    /// Run the concurrent phase — plugins execute truly in parallel.
    /// Returns the first violation if any plugin denies.
    ///
    /// Built on `cpex_orchestration::run_branches`, the workspace's
    /// shared "N async branches with abort-on-deny + per-branch timeout"
    /// primitive (same crate apl-core's `Effect::Parallel` consumes).
    /// Each branch returns a small `BranchData` carrying the plugin's
    /// effective outcome (allow / deny / error). The orchestrator's
    /// `is_deny` predicate inspects that — including the per-plugin
    /// `on_error == Fail` case, which is treated as a halting outcome
    /// so that an erroring/timing-out/panicking Fail-mode plugin
    /// short-circuits the remaining branches the same way an explicit
    /// deny does. Post-loop, we walk the outcomes in input order and
    /// apply each plugin's `on_error` policy (Ignore / Disable) to
    /// non-halting failures.
    async fn run_concurrent_phase(
        &self,
        entries: &[HookEntry],
        payload: &dyn PluginPayload,
        extensions: &Extensions,
        ctx_table: &PluginContextTable,
        errors: &mut Vec<crate::error::PluginErrorRecord>,
        decisions: &mut DecisionLog,
    ) -> Option<crate::error::PluginViolation> {
        use cpex_orchestration::{run_branches, BranchConfig, BranchOutcome, ErasedBranch};

        if entries.is_empty() {
            return None;
        }

        // Per-branch outcome. Carries just enough for post-loop policy
        // application — plugin name / on_error are looked up via
        // `entries[idx]` so we don't have to clone them into the
        // future's captures.
        enum BranchData {
            Allow,
            Deny(Option<crate::error::PluginViolation>),
            Error(Box<PluginError>),
        }

        // Clone the payload once so each spawned task can borrow from
        // an owned, 'static copy. Each task gets its own Arc'd clone.
        let shared_payload: Arc<Box<dyn PluginPayload>> = Arc::new(payload.clone_boxed());
        let timeout_dur = Duration::from_secs(self.config.timeout_seconds);

        // Snapshot per-entry on_error decisions BEFORE moving into
        // futures — `is_deny` needs them at runtime to decide whether
        // an Error outcome halts (Fail) or is logged (Ignore/Disable).
        let on_error_by_idx: Vec<OnError> = entries
            .iter()
            .map(|e| e.plugin_ref.trusted_config().on_error)
            .collect();

        // Build branch futures. Each does the timing-bounded handler
        // invoke and extracts the type-erased result, returning a
        // `BranchData` that the orchestrator's `is_deny` predicate can
        // inspect without further type knowledge.
        let mut branches: Vec<ErasedBranch<BranchData>> = Vec::with_capacity(entries.len());
        for entry in entries.iter() {
            let handler = Arc::clone(&entry.handler);
            let payload_clone = Arc::clone(&shared_payload);
            let plugin_id = entry.plugin_ref.id();
            // Snapshot the plugin's local_state and the canonical global_state.
            // Concurrent plugins do not merge back — each task owns its copy.
            let mut ctx = ctx_table.snapshot_context(plugin_id);
            let plugin_name = entry.plugin_ref.name().to_string();

            // Filter per plugin — each may have different capabilities.
            // Read-only, no write tokens. Wrap in Arc for 'static spawn.
            let capabilities: std::collections::HashSet<String> = entry
                .plugin_ref
                .trusted_config()
                .capabilities
                .iter()
                .cloned()
                .collect();
            let filtered = Arc::new(filter_extensions(extensions, &capabilities));

            branches.push(Box::pin(async move {
                match handler.invoke(&**payload_clone, &filtered, &mut ctx).await {
                    Ok(result_box) => match extract_erased(result_box) {
                        Some(erased) if !erased.continue_processing => {
                            let violation = erased.violation.map(|mut v| {
                                v.plugin_name = Some(plugin_name);
                                v
                            });
                            BranchData::Deny(violation)
                        },
                        // `Some(..)` with continue_processing=true, OR
                        // `None` (downcast failed — historically logged
                        // and treated as Allow) both fall through.
                        _ => BranchData::Allow,
                    },
                    Err(e) => BranchData::Error(e),
                }
            }));
        }

        let cfg = BranchConfig {
            timeout_per_branch: Some(timeout_dur),
            short_circuit_on_deny: self.config.short_circuit_on_deny,
        };

        // `is_deny` halts on explicit Deny only. It can't halt on
        // Error/Timeout/Panic because the predicate sees only the
        // value, not the branch index, so it can't read the per-entry
        // `on_error` policy. Halting on those failures is handled in
        // the post-loop: the first Fail-policy failure becomes the
        // returned violation, and any in-flight tasks drop when the
        // JoinSet inside `run_branches` goes out of scope.
        //
        // The original implementation called `set.abort_all()` on
        // Fail-class errors too. The behavioural difference: the
        // post-loop now waits for all branches to finish (or hit
        // their own timeout) before returning. For the slow-plugin
        // abort test that's fine — that test exercises the Deny
        // path, which still goes through `is_deny` + abort_all.
        let outcomes = run_branches(branches, cfg, |v: &BranchData| {
            matches!(v, BranchData::Deny(_))
        })
        .await;

        // Post-loop: walk outcomes in input order applying per-plugin
        // policy. First halting outcome wins.
        let mut first_violation: Option<crate::error::PluginViolation> = None;

        for (idx, outcome) in outcomes.into_iter().enumerate() {
            let entry = &entries[idx];
            let plugin_name = entry.plugin_ref.name();
            let on_error = on_error_by_idx[idx];

            // Record what this concurrent plugin did, in input order.
            let action = match &outcome {
                BranchOutcome::Completed(BranchData::Allow) => PluginAction::Allowed,
                BranchOutcome::Completed(BranchData::Deny(_)) => PluginAction::Denied,
                BranchOutcome::Completed(BranchData::Error(e)) => {
                    PluginAction::Error(e.to_string())
                },
                BranchOutcome::TimedOut => PluginAction::Error("timed out".to_string()),
                BranchOutcome::Panicked(s) => PluginAction::Error(format!("panicked: {s}")),
                // Cancelled because another branch short-circuited the phase —
                // an intentional abort, recorded as such rather than an error.
                BranchOutcome::Aborted => PluginAction::Aborted,
            };
            decisions.record(plugin_name, entry.plugin_ref.trusted_config().mode, action);

            match outcome {
                BranchOutcome::Completed(BranchData::Allow) => {},
                BranchOutcome::Completed(BranchData::Deny(opt_v)) => {
                    let violation = opt_v.unwrap_or_else(|| {
                        let mut v = crate::error::PluginViolation::new(
                            "concurrent_deny",
                            format!("Plugin '{}' denied", plugin_name),
                        );
                        v.plugin_name = Some(plugin_name.to_string());
                        v
                    });
                    if first_violation.is_none() {
                        first_violation = Some(violation);
                    }
                },
                BranchOutcome::Completed(BranchData::Error(e)) => match on_error {
                    OnError::Fail => {
                        if first_violation.is_none() {
                            let mut v = crate::error::PluginViolation::new(
                                "plugin_error",
                                format!("Plugin '{}' failed: {}", plugin_name, e),
                            );
                            v.plugin_name = Some(plugin_name.to_string());
                            first_violation = Some(v);
                        }
                    },
                    OnError::Ignore => {
                        warn!("CONCURRENT plugin '{}' error (ignored): {}", plugin_name, e);
                        errors.push((&*e).into());
                    },
                    OnError::Disable => {
                        warn!("CONCURRENT plugin '{}' disabled after error", plugin_name);
                        errors.push((&*e).into());
                        entry.plugin_ref.disable();
                    },
                },
                BranchOutcome::TimedOut => {
                    let timeout_err = crate::error::PluginError::Timeout {
                        plugin_name: plugin_name.to_string(),
                        timeout_ms: timeout_dur.as_millis() as u64,
                        proto_error_code: None,
                    };
                    match on_error {
                        OnError::Fail => {
                            if first_violation.is_none() {
                                let mut v = crate::error::PluginViolation::new(
                                    "plugin_timeout",
                                    format!("Plugin '{}' timed out", plugin_name),
                                );
                                v.plugin_name = Some(plugin_name.to_string());
                                first_violation = Some(v);
                            }
                        },
                        OnError::Ignore => {
                            warn!("CONCURRENT plugin '{}' timed out (ignored)", plugin_name);
                            errors.push((&timeout_err).into());
                        },
                        OnError::Disable => {
                            warn!("CONCURRENT plugin '{}' disabled after timeout", plugin_name);
                            errors.push((&timeout_err).into());
                            entry.plugin_ref.disable();
                        },
                    }
                },
                BranchOutcome::Panicked(s) => {
                    error!("CONCURRENT plugin '{}' task panicked: {}", plugin_name, s);
                    let panic_err = crate::error::PluginError::Execution {
                        plugin_name: plugin_name.to_string(),
                        message: format!("task panicked: {}", s),
                        source: None,
                        code: Some("panic".into()),
                        details: std::collections::HashMap::new(),
                        proto_error_code: None,
                    };
                    match on_error {
                        OnError::Fail => {
                            if first_violation.is_none() {
                                let mut v = crate::error::PluginViolation::new(
                                    "plugin_panic",
                                    format!("Plugin '{}' task panicked: {}", plugin_name, s),
                                );
                                v.plugin_name = Some(plugin_name.to_string());
                                first_violation = Some(v);
                            }
                        },
                        OnError::Ignore => {
                            warn!("CONCURRENT plugin '{}' panicked (ignored)", plugin_name);
                            errors.push((&panic_err).into());
                        },
                        OnError::Disable => {
                            warn!("CONCURRENT plugin '{}' disabled after panic", plugin_name);
                            errors.push((&panic_err).into());
                            entry.plugin_ref.disable();
                        },
                    }
                },
                BranchOutcome::Aborted => {
                    // Cancelled because an earlier branch hit a halt
                    // condition under short_circuit_on_deny. Intentional
                    // — no error to record.
                },
            }
        }

        first_violation
    }

    /// Spawn fire-and-forget handlers as background tasks.
    ///
    /// Each handler runs in its own `tokio::spawn` — the pipeline does
    /// not wait for them. Errors and timeouts are logged but have no
    /// effect on the pipeline result.
    ///
    /// Returns the plugin name and join handle for each spawned task
    /// so they can be stored on `PipelineResult` for optional awaiting
    /// via `wait_for_background_tasks()`.
    fn spawn_fire_and_forget(
        &self,
        entries: &[HookEntry],
        payload: &dyn PluginPayload,
        extensions: &Extensions,
        ctx_table: &PluginContextTable,
        task_tracker: &tokio_util::task::TaskTracker,
    ) -> Vec<(String, tokio::task::JoinHandle<()>)> {
        if entries.is_empty() {
            return Vec::new();
        }

        let timeout_dur = Duration::from_secs(self.config.timeout_seconds);

        let mut handles = Vec::with_capacity(entries.len());

        for entry in entries {
            let plugin_name = entry.plugin_ref.name().to_string();
            let handler = Arc::clone(&entry.handler);
            let owned_payload = payload.clone_boxed();
            // Snapshot per plugin so fire-and-forget tasks see their stored
            // local_state from prior hooks, not just an empty context.
            let mut ctx = ctx_table.snapshot_context(entry.plugin_ref.id());
            let dur = timeout_dur;
            let name_for_log = plugin_name.clone();

            // Filter per plugin, read-only, no write tokens
            let capabilities: std::collections::HashSet<String> = entry
                .plugin_ref
                .trusted_config()
                .capabilities
                .iter()
                .cloned()
                .collect();
            let filtered = Arc::new(filter_extensions(extensions, &capabilities));

            // Spawn through TaskTracker so `PluginManager::shutdown()`
            // can drain in-flight fire-and-forget tasks before tearing
            // down. The returned JoinHandle is the same shape as
            // tokio::spawn's, so callers using BackgroundTasks still
            // wait_for_background_tasks() over their own handles.
            let handle = task_tracker.spawn(async move {
                let result =
                    timeout(dur, handler.invoke(&*owned_payload, &filtered, &mut ctx)).await;

                match result {
                    Ok(Ok(_)) => {}, // discard
                    Ok(Err(e)) => {
                        warn!(
                            "FIRE_AND_FORGET plugin '{}' error (ignored): {}",
                            name_for_log, e
                        );
                    },
                    Err(_) => {
                        warn!(
                            "FIRE_AND_FORGET plugin '{}' timed out (ignored)",
                            name_for_log
                        );
                    },
                }
            });

            handles.push((plugin_name, handle));
        }

        handles
    }
}

impl Default for Executor {
    fn default() -> Self {
        Self::new(ExecutorConfig::default())
    }
}

// SerialResult removed — run_serial_phase now returns Option<Violation> directly.

/// Effect emitter the executor grants to `emit_effect`-capable plugins via
/// `Extensions.effect_emitter`. Fans an effect record out to the audit sinks'
/// `on_effect`, isolated (timeout + catch_unwind) exactly like the verdict
/// emit, and stamps the causing plugin (not self-reported).
struct AuditEffectEmitter {
    handlers: Vec<Arc<dyn AuditHandler>>,
    plugin_name: String,
    timeout: Duration,
    /// Write-ahead log. When present, `emit` durably records the effect
    /// before fanning out and fails closed if that write fails. `None` until
    /// slice 3b wires a real WAL — then emit is ordering-only.
    durable: Option<Arc<dyn DurableEffectLog>>,
    /// Boot epoch + counters (shared with the executor). Each emitted record is
    /// stamped with `epoch`, `stream_seq` (gap-free within the effect stream),
    /// and the global `emission_seq` (interleaved order vs decisions).
    epoch: u64,
    stream_seq: Arc<AtomicU64>,
    emission_seq: Arc<AtomicU64>,
    /// Host namespace prefixing the effect stream id (shared with the executor).
    stream_namespace: Option<String>,
}

impl std::fmt::Debug for AuditEffectEmitter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditEffectEmitter")
            .field("plugin_name", &self.plugin_name)
            .field("sinks", &self.handlers.len())
            .finish()
    }
}

#[async_trait]
impl EffectEmitter for AuditEffectEmitter {
    async fn emit(&self, effect: &EffectRecord, ext: &Extensions) -> Result<(), Box<PluginError>> {
        use futures::FutureExt;
        use std::panic::AssertUnwindSafe;

        // Stamp the causing plugin + stream identity/sequences — all set by the
        // framework, not self-reported. `stream_seq` is gap-free within the
        // effect stream (completeness); `emission_seq` is the shared global
        // counter across decisions and effects (interleaved order).
        let mut stamped = effect.clone();
        stamped.plugin_name = Some(self.plugin_name.clone());
        stamped.epoch = Some(self.epoch);
        stamped.stream_id = Some(compose_stream_id(
            self.stream_namespace.as_deref(),
            "effect",
        ));
        stamped.stream_seq = Some(self.stream_seq.fetch_add(1, Ordering::Relaxed));
        stamped.emission_seq = Some(self.emission_seq.fetch_add(1, Ordering::Relaxed));

        // Write-ahead: durably record BEFORE any observer sees it. Fail
        // closed — if the durable write fails, return Err and do NOT fan out;
        // the caller must not perform the act.
        if let Some(log) = &self.durable {
            log.append(&stamped).await?;
        }

        for handler in &self.handlers {
            let call = AssertUnwindSafe(handler.on_effect(&stamped, ext)).catch_unwind();
            match timeout(self.timeout, call).await {
                Ok(Ok(())) => {},
                Ok(Err(_panic)) => {
                    error!(
                        "audit sink '{}' panicked during on_effect — contained",
                        handler.name()
                    );
                },
                Err(_elapsed) => {
                    error!(
                        "audit sink '{}' exceeded {}s during on_effect — skipped",
                        handler.name(),
                        self.timeout.as_secs()
                    );
                },
            }
        }
        Ok(())
    }
}

/// Common fields extracted from a type-erased PluginResult.
///
/// Handlers return `Box<dyn Any>` which wraps this struct. The
/// executor extracts it via [`extract_erased()`] to read the
/// control flow fields without knowing the concrete payload type.
pub struct ErasedResultFields {
    pub continue_processing: bool,
    pub modified_payload: Option<Box<dyn PluginPayload>>,
    pub modified_extensions: Option<crate::hooks::payload::OwnedExtensions>,
    pub violation: Option<crate::error::PluginViolation>,
}

/// Extract erased result fields from a type-erased handler result.
///
/// Takes ownership of the Box — the executor consumes the result.
/// Logs a warning if the downcast fails (indicates a handler returned
/// the wrong type — a framework bug, not a plugin error).
pub fn extract_erased(result: Box<dyn Any + Send + Sync>) -> Option<ErasedResultFields> {
    match result.downcast::<ErasedResultFields>() {
        Ok(b) => Some(*b),
        Err(_) => {
            warn!("extract_erased: downcast failed — handler returned unexpected type");
            None
        },
    }
}

/// Convert a typed `PluginResult<P>` into `ErasedResultFields`.
///
/// Called by `TypedHandlerAdapter` to bridge between the typed
/// result and the executor's type-erased dispatch.
pub fn erase_result<P: crate::hooks::PluginPayload>(
    result: crate::hooks::PluginResult<P>,
) -> Box<dyn Any + Send + Sync> {
    Box::new(ErasedResultFields {
        continue_processing: result.continue_processing,
        modified_payload: result
            .modified_payload
            .map(|p| Box::new(p) as Box<dyn PluginPayload>),
        modified_extensions: result.modified_extensions,
        violation: result.violation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::payload::PluginPayload;
    use crate::hooks::PluginResult;

    #[derive(Debug, Clone)]
    #[allow(dead_code)] // test fixture — typed shape is the point, not field reads
    struct TestPayload {
        value: String,
    }
    crate::impl_plugin_payload!(TestPayload);

    #[test]
    fn test_erase_result_allow() {
        let result: PluginResult<TestPayload> = PluginResult::allow();
        let erased = erase_result(result);
        let fields = extract_erased(erased).unwrap();
        assert!(fields.continue_processing);
        assert!(fields.violation.is_none());
        assert!(fields.modified_payload.is_none());
    }

    #[test]
    fn test_erase_result_deny() {
        let result: PluginResult<TestPayload> =
            PluginResult::deny(crate::error::PluginViolation::new("test", "denied"));
        let erased = erase_result(result);
        let fields = extract_erased(erased).unwrap();
        assert!(!fields.continue_processing);
        assert_eq!(fields.violation.as_ref().unwrap().code, "test");
    }

    #[test]
    fn test_erase_result_modify_payload() {
        let result: PluginResult<TestPayload> = PluginResult::modify_payload(TestPayload {
            value: "modified".into(),
        });
        let erased = erase_result(result);
        let fields = extract_erased(erased).unwrap();
        assert!(fields.continue_processing);
        assert!(fields.modified_payload.is_some());
    }

    #[test]
    fn test_erase_result_modify_extensions() {
        let mut security = crate::extensions::SecurityExtension::default();
        security.add_label("PII");
        let ext = Extensions {
            security: Some(Arc::new(security)),
            ..Default::default()
        };
        let owned = ext.cow_copy();
        let result: PluginResult<TestPayload> = PluginResult::modify_extensions(owned);
        let erased = erase_result(result);
        let fields = extract_erased(erased).unwrap();
        assert!(fields.continue_processing);
        assert!(fields.modified_extensions.is_some());
        let sec = fields
            .modified_extensions
            .as_ref()
            .unwrap()
            .security
            .as_ref()
            .unwrap();
        assert!(sec.has_label("PII"));
    }

    #[test]
    fn test_pipeline_result_allowed() {
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "test".into(),
        });
        let result =
            PipelineResult::allowed_with(payload, Extensions::default(), PluginContextTable::new());
        assert!(result.continue_processing);
        assert!(result.modified_payload.is_some());
        assert!(result.violation.is_none());
        assert!(
            !result.payload_modified,
            "carrying a payload is not the same as a plugin having changed it"
        );
    }

    #[test]
    fn test_pipeline_result_denied() {
        let violation = crate::error::PluginViolation::new("test", "denied");
        let result =
            PipelineResult::denied(violation, Extensions::default(), PluginContextTable::new());
        assert!(!result.continue_processing);
        assert!(result.modified_payload.is_none());
        assert!(result.violation.is_some());
    }

    #[tokio::test]
    async fn test_executor_empty_entries() {
        let executor = Executor::default();
        let tracker = tokio_util::task::TaskTracker::new();
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "test".into(),
        });
        let (result, _) = executor
            .execute(&[], payload, Extensions::default(), None, &tracker)
            .await;
        assert!(result.continue_processing);
        assert!(result.modified_payload.is_some());
    }

    #[tokio::test]
    async fn effect_emit_fails_closed_when_durable_write_fails() {
        use std::sync::Mutex;

        struct FailingLog;
        #[async_trait]
        impl DurableEffectLog for FailingLog {
            async fn append(&self, _e: &EffectRecord) -> Result<(), Box<PluginError>> {
                Err(Box::new(PluginError::Config {
                    message: "wal down".into(),
                }))
            }
        }
        struct OkLog;
        #[async_trait]
        impl DurableEffectLog for OkLog {
            async fn append(&self, _e: &EffectRecord) -> Result<(), Box<PluginError>> {
                Ok(())
            }
        }
        struct CountingSink(Arc<Mutex<usize>>);
        #[async_trait]
        impl AuditHandler for CountingSink {
            async fn handle(&self, _p: &dyn PluginPayload, _e: &Extensions, _d: &DecisionLog) {}
            async fn on_effect(&self, _e: &EffectRecord, _x: &Extensions) {
                *self.0.lock().unwrap() += 1;
            }
        }

        let effect = EffectRecord::prepared("token_mint", "mint", "k");

        // Durable write fails → emit fails closed, NO fan-out to sinks.
        let calls = Arc::new(Mutex::new(0usize));
        let emitter = AuditEffectEmitter {
            handlers: vec![Arc::new(CountingSink(calls.clone()))],
            plugin_name: "delegator".into(),
            timeout: Duration::from_secs(5),
            durable: Some(Arc::new(FailingLog)),
            epoch: 0,
            stream_seq: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            emission_seq: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            stream_namespace: None,
        };
        let res = emitter.emit(&effect, &Extensions::default()).await;
        assert!(res.is_err(), "durable write failed → emit fails closed");
        assert_eq!(
            *calls.lock().unwrap(),
            0,
            "no fan-out when the durable write fails"
        );

        // Durable write succeeds → fan-out proceeds (durable-before-fanout).
        let calls2 = Arc::new(Mutex::new(0usize));
        let emitter2 = AuditEffectEmitter {
            handlers: vec![Arc::new(CountingSink(calls2.clone()))],
            plugin_name: "delegator".into(),
            timeout: Duration::from_secs(5),
            durable: Some(Arc::new(OkLog)),
            epoch: 0,
            stream_seq: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            emission_seq: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            stream_namespace: None,
        };
        let res2 = emitter2.emit(&effect, &Extensions::default()).await;
        assert!(res2.is_ok());
        assert_eq!(*calls2.lock().unwrap(), 1, "durable OK → fan-out proceeds");
    }

    #[test]
    fn compose_stream_id_prefixes_only_when_namespaced() {
        assert_eq!(compose_stream_id(None, "decision"), "decision");
        assert_eq!(compose_stream_id(Some("gw-1"), "decision"), "gw-1:decision");
        assert_eq!(compose_stream_id(Some("gw-1"), "effect"), "gw-1:effect");
    }

    #[test]
    fn stream_identity_from_config_stamps_namespace_and_epoch_on_decisions() {
        use crate::decision::DecisionLog;

        // Host identity set on the ExecutorConfig → namespaced stream id +
        // host-supplied epoch, read at construction.
        let exec = Executor::new(ExecutorConfig {
            audit_stream_namespace: Some("gw-1".to_string()),
            audit_epoch: Some(7),
            ..Default::default()
        });
        let mut log = DecisionLog::new();
        exec.stamp_decision_stream(&mut log);
        assert_eq!(log.stream_id(), Some("gw-1:decision"));
        assert_eq!(log.epoch(), Some(7), "host epoch overrides wall-clock");

        // Default → bare label + CPEX's wall-clock epoch (nonzero, and the
        // two-stream density is unaffected since the type suffix is unchanged).
        let plain = Executor::default();
        let mut log2 = DecisionLog::new();
        plain.stamp_decision_stream(&mut log2);
        assert_eq!(log2.stream_id(), Some("decision"));
        assert!(log2.epoch().unwrap() > 0, "wall-clock epoch by default");
    }

    #[tokio::test]
    async fn with_stream_identity_prefixes_the_effect_stream() {
        use crate::effect::EffectRecord;
        use std::sync::Mutex;

        // A sink that records the stream id stamped onto each effect it sees.
        struct StreamIdSink(Arc<Mutex<Vec<String>>>);
        #[async_trait]
        impl AuditHandler for StreamIdSink {
            async fn handle(&self, _p: &dyn PluginPayload, _e: &Extensions, _d: &DecisionLog) {}
            async fn on_effect(&self, effect: &EffectRecord, _x: &Extensions) {
                self.0
                    .lock()
                    .unwrap()
                    .push(effect.stream_id.clone().unwrap_or_default());
            }
        }

        let seen = Arc::new(Mutex::new(Vec::new()));
        let emitter = AuditEffectEmitter {
            handlers: vec![Arc::new(StreamIdSink(seen.clone()))],
            plugin_name: "delegator".into(),
            timeout: Duration::from_secs(5),
            durable: None,
            epoch: 7,
            stream_seq: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            emission_seq: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            stream_namespace: Some("gw-1".to_string()),
        };
        emitter
            .emit(
                &EffectRecord::prepared("token_mint", "exchange", "k-1"),
                &Extensions::default(),
            )
            .await
            .unwrap();
        assert_eq!(
            seen.lock().unwrap().as_slice(),
            ["gw-1:effect"],
            "effect stream id carries the same namespace, distinct type suffix"
        );
    }
}
