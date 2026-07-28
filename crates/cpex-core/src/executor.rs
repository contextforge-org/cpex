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
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::time::timeout;
use tracing::{error, warn};

use crate::context::PluginContextTable;
use crate::error::PluginError;
use crate::execution_record::{ControlExecutionRecord, ControlExecutionStatus};
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
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: 30,
            short_circuit_on_deny: true,
        }
    }
}

/// Aggregate result from a full hook invocation across all phases.
///
/// Wraps the final payload, extensions, any violation, the context
/// table, and the structured execution ledger. Immutable by design —
/// policy decisions cannot be tampered with after the executor returns.
///
/// The caller should pass `context_table` into the next hook
/// invocation to preserve per-plugin local state across hooks in
/// the same request lifecycle.
///
/// Background tasks are returned separately as [`BackgroundTasks`]
/// to keep the policy result immutable.
#[derive(Debug)]
pub struct PipelineResult {
    /// Whether the pipeline should continue processing.
    /// `false` means a plugin denied — the pipeline was halted.
    pub continue_processing: bool,

    /// The final payload after all modifications (type-erased).
    /// `None` if the pipeline was denied before any modifications.
    pub modified_payload: Option<Box<dyn PluginPayload>>,

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

    /// Ordered execution record for every control evaluated during
    /// this hook invocation. Populated by the executor from trusted
    /// framework state — plugins cannot forge these records.
    ///
    /// Records preserve the deterministic plan order within each serial
    /// phase. Concurrent phase records are appended in input (plan/priority)
    /// order after all branches resolve. Fire-and-forget records appear
    /// last, marked `status = Completed` at spawn time (not completion time).
    pub executions: Vec<ControlExecutionRecord>,
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
            modified_extensions: Some(extensions),
            violation: None,
            errors: Vec::new(),
            metadata: None,
            context_table,
            executions: Vec::new(),
        }
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
            modified_extensions: Some(extensions),
            violation: Some(violation),
            errors: Vec::new(),
            metadata: None,
            context_table,
            executions: Vec::new(),
        }
    }

    /// Replace the errors vec on a constructed PipelineResult. Used by
    /// the executor to attach errors collected from `on_error: ignore`
    /// / `on_error: disable` plugins.
    pub fn with_errors(mut self, errors: Vec<crate::error::PluginErrorRecord>) -> Self {
        self.errors = errors;
        self
    }

    /// Attach execution records collected across all phases.
    pub fn with_executions(mut self, executions: Vec<ControlExecutionRecord>) -> Self {
        self.executions = executions;
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
/// The executor is stateless — all state comes from the arguments.
/// One executor instance can serve multiple concurrent hook invocations.
#[derive(Clone)]
pub struct Executor {
    config: ExecutorConfig,
}

impl Executor {
    /// Create a new executor with the given configuration.
    pub fn new(config: ExecutorConfig) -> Self {
        Self { config }
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

        if entries.is_empty() {
            return (
                PipelineResult::allowed_with(payload, extensions, ctx_table),
                BackgroundTasks::empty(),
            );
        }

        // Group entries by mode (from trusted_config)
        let (sequential, transform, audit, concurrent, fire_and_forget) = group_by_mode(entries);

        // Determine the hook name for records — take it from the first entry.
        let hook_name: String = entries
            .first()
            .map(|e| {
                // All entries in this call share the same hook name (they were
                // looked up from the registry by a single hook type). Use the
                // handler's registered hook type name as the authoritative value.
                e.handler.hook_type_name().to_string()
            })
            .unwrap_or_default();

        let mut current_payload = payload;
        let mut current_extensions = extensions;
        // Accumulator for errors from `on_error: ignore` / `on_error:
        // disable` plugins across all phases. Surfaced to the caller
        // via `PipelineResult.errors` so swallowed failures stay
        // observable. Halt-condition errors (Fail, deny) skip this and
        // become the violation directly.
        let mut errors: Vec<crate::error::PluginErrorRecord> = Vec::new();
        // Accumulator for execution records across all phases.
        let mut executions: Vec<ControlExecutionRecord> = Vec::new();

        if let Some(v) = self
            .run_serial_phase(
                &sequential,
                &mut current_payload,
                &mut current_extensions,
                &mut ctx_table,
                true, // can_block
                true, // can_modify
                "SEQUENTIAL",
                &hook_name,
                &mut errors,
                &mut executions,
            )
            .await
        {
            return (
                PipelineResult::denied(v, current_extensions, ctx_table)
                    .with_errors(errors)
                    .with_executions(executions),
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
            &hook_name,
            &mut errors,
            &mut executions,
        )
        .await;

        self.run_ref_phase(
            &audit,
            &*current_payload,
            &current_extensions,
            &ctx_table,
            "AUDIT",
            &hook_name,
            &mut errors,
            &mut executions,
        )
        .await;

        if let Some(violation) = self
            .run_concurrent_phase(
                &concurrent,
                &*current_payload,
                &current_extensions,
                &ctx_table,
                &hook_name,
                &mut errors,
                &mut executions,
            )
            .await
        {
            return (
                PipelineResult::denied(violation, current_extensions, ctx_table)
                    .with_errors(errors)
                    .with_executions(executions),
                BackgroundTasks::empty(),
            );
        }

        // Phase 5: FIRE_AND_FORGET — background, read-only, ignore results.
        // FAF errors don't go in PipelineResult.errors — they're delivered
        // via BackgroundTasks::wait_for_background_tasks() instead.
        // FAF records are appended here (spawn time) with status=Completed
        // since we don't have completion handles for individual records.
        let bg_handles = self.spawn_fire_and_forget(
            &fire_and_forget,
            &*current_payload,
            &current_extensions,
            &ctx_table,
            &hook_name,
            &mut executions,
            task_tracker,
        );

        (
            PipelineResult::allowed_with(current_payload, current_extensions, ctx_table)
                .with_errors(errors)
                .with_executions(executions),
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
        hook_name: &str,
        errors: &mut Vec<crate::error::PluginErrorRecord>,
        executions: &mut Vec<ControlExecutionRecord>,
    ) -> Option<crate::error::PluginViolation> {
        for entry in entries {
            // Borrow names/ids on the happy path — allocate only when
            // building a violation or stashing the local_state back into
            // the table. Previously `name.to_string()` + `id.to_string()`
            // ran unconditionally on every plugin per invoke.
            let plugin_name = entry.plugin_ref.name();
            let plugin_id = entry.plugin_ref.id();
            let on_error = entry.plugin_ref.trusted_config().on_error;

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

            // Execute with timeout — handler borrows payload, gets filtered extensions.
            // Monotonic timer wraps the invoke call only (no queue/semaphore wait).
            let timeout_dur = Duration::from_secs(self.config.timeout_seconds);
            let start = Instant::now();
            let result = timeout(
                timeout_dur,
                entry.handler.invoke(&**payload, &filtered, &mut ctx),
            )
            .await;
            let duration_ns = start.elapsed().as_nanos().min(u64::MAX as u128) as u64;

            // Snapshot trusted identity fields for the record — sourced from
            // PluginRef (manager-owned), never from plugin-returned metadata.
            let trusted = entry.plugin_ref.trusted_config();
            let config_keys =
                ControlExecutionRecord::collect_config_keys(trusted.config.as_ref());

            match result {
                Ok(Ok(result_box)) => {
                    // Track whether modifications were applied before merging.
                    // Use the data pointer from the fat pointer to compare identity.
                    // as_any() returns &dyn Any (fat ptr); cast to *const () via
                    // the data-pointer half so the comparison is thin-pointer safe.
                    let payload_before =
                        payload.as_any() as *const dyn std::any::Any as *const () as usize;
                    let mut payload_modified = false;
                    let mut extensions_modified = false;

                    let (requested_allow, effective_allow, violation_opt) =
                        if let Some(erased) = extract_erased(result_box) {
                            let req_allow = erased.continue_processing;

                            if !erased.continue_processing && can_block {
                                // Synthesize a default violation when the plugin denied
                                // without providing one — this mirrors the concurrent phase
                                // and ensures the pipeline always halts on deny.
                                let mut v = erased.violation.unwrap_or_else(|| {
                                    let mut v = crate::error::PluginViolation::new(
                                        "deny",
                                        format!("Plugin '{}' denied", plugin_name),
                                    );
                                    v.plugin_name = Some(plugin_name.to_string());
                                    v
                                });
                                v.plugin_name = Some(plugin_name.to_string());
                                executions.push(ControlExecutionRecord {
                                    plugin_id: plugin_id.to_string(),
                                    plugin_name: plugin_name.to_string(),
                                    plugin_kind: ControlExecutionRecord::truncate(
                                        &trusted.kind,
                                    ),
                                    hook_name: hook_name.to_string(),
                                    mode: entry.plugin_ref.mode(),
                                    status: ControlExecutionStatus::Completed,
                                    requested_allow: Some(false),
                                    effective_allow: false,
                                    matched: Some(true),
                                    applied: true,
                                    payload_modified: false,
                                    extensions_modified: false,
                                    duration_ns,
                                    reason: ControlExecutionRecord::truncate_opt(
                                        Some(v.reason.as_str()),
                                    ),
                                    error_code: Some(
                                        ControlExecutionRecord::truncate(&v.code),
                                    ),
                                    config_keys,
                                });
                                return Some(v);
                            }

                            // Accept modifications
                            if can_modify {
                                if let Some(mp) = erased.modified_payload {
                                    // Detect if a new payload object was installed.
                                    let new_ptr =
                                        mp.as_any() as *const dyn std::any::Any as *const () as usize;
                                    *payload = mp;
                                    payload_modified = new_ptr != payload_before;
                                }
                                if let Some(owned) = erased.modified_extensions {
                                    let valid = extensions.validate_immutable(&owned);
                                    if !valid {
                                        warn!(
                                            "{} plugin '{}' violated immutable tier — \
                                             modified an immutable extension slot. \
                                             Extension changes rejected.",
                                            phase_label, plugin_name
                                        );
                                    } else if capabilities.contains("read_labels") {
                                        if let (Some(ref orig_sec), Some(ref new_sec)) =
                                            (&extensions.security, &owned.security)
                                        {
                                            if !new_sec.labels.is_superset(&orig_sec.labels) {
                                                warn!(
                                                    "{} plugin '{}' violated monotonic tier — \
                                                     removed a security label. \
                                                     Extension changes rejected.",
                                                    phase_label, plugin_name
                                                );
                                            } else {
                                                extensions.merge_owned(owned);
                                                extensions_modified = true;
                                            }
                                        } else {
                                            extensions.merge_owned(owned);
                                            extensions_modified = true;
                                        }
                                    } else {
                                        extensions.merge_owned(owned);
                                        extensions_modified = true;
                                    }
                                }
                            }

                            (Some(req_allow), req_allow, None::<crate::error::PluginViolation>)
                        } else {
                            (None, true, None)
                        };

                    let _ = violation_opt; // already handled above via early return
                    executions.push(ControlExecutionRecord {
                        plugin_id: plugin_id.to_string(),
                        plugin_name: plugin_name.to_string(),
                        plugin_kind: ControlExecutionRecord::truncate(&trusted.kind),
                        hook_name: hook_name.to_string(),
                        mode: entry.plugin_ref.mode(),
                        status: ControlExecutionStatus::Completed,
                        requested_allow,
                        effective_allow,
                        matched: requested_allow.map(|a| !a || payload_modified || extensions_modified),
                        applied: payload_modified || extensions_modified || !effective_allow,
                        payload_modified,
                        extensions_modified,
                        duration_ns,
                        reason: None,
                        error_code: None,
                        config_keys,
                    });
                },
                Ok(Err(e)) => {
                    error!("{} plugin '{}' failed: {}", phase_label, plugin_name, e);
                    let (effective_allow, status) = match on_error {
                        OnError::Fail if can_block => {
                            // We're about to return a violation — push the record first.
                            executions.push(ControlExecutionRecord {
                                plugin_id: plugin_id.to_string(),
                                plugin_name: plugin_name.to_string(),
                                plugin_kind: ControlExecutionRecord::truncate(&trusted.kind),
                                hook_name: hook_name.to_string(),
                                mode: entry.plugin_ref.mode(),
                                status: ControlExecutionStatus::Error,
                                requested_allow: None,
                                effective_allow: false,
                                matched: None,
                                applied: true,
                                payload_modified: false,
                                extensions_modified: false,
                                duration_ns,
                                reason: ControlExecutionRecord::truncate_opt(Some(
                                    &e.to_string(),
                                )),
                                error_code: Some("plugin_error".to_string()),
                                config_keys,
                            });
                            let mut v = crate::error::PluginViolation::new(
                                "plugin_error",
                                format!("Plugin '{}' failed: {}", plugin_name, e),
                            );
                            v.plugin_name = Some(plugin_name.to_string());
                            return Some(v);
                        },
                        OnError::Fail => {
                            warn!(
                                "{} plugin '{}' on_error=fail in non-blocking phase — not halting",
                                phase_label, plugin_name,
                            );
                            errors.push((&e).into());
                            (true, ControlExecutionStatus::Error)
                        },
                        OnError::Ignore => {
                            errors.push((&e).into());
                            (true, ControlExecutionStatus::Error)
                        },
                        OnError::Disable => {
                            warn!(
                                "{} plugin '{}' disabled after error",
                                phase_label, plugin_name
                            );
                            errors.push((&e).into());
                            entry.plugin_ref.disable();
                            (true, ControlExecutionStatus::Error)
                        },
                    };
                    executions.push(ControlExecutionRecord {
                        plugin_id: plugin_id.to_string(),
                        plugin_name: plugin_name.to_string(),
                        plugin_kind: ControlExecutionRecord::truncate(&trusted.kind),
                        hook_name: hook_name.to_string(),
                        mode: entry.plugin_ref.mode(),
                        status,
                        requested_allow: None,
                        effective_allow,
                        matched: None,
                        applied: false,
                        payload_modified: false,
                        extensions_modified: false,
                        duration_ns,
                        reason: ControlExecutionRecord::truncate_opt(Some(&e.to_string())),
                        error_code: Some("plugin_error".to_string()),
                        config_keys,
                    });
                },
                Err(_) => {
                    error!("{} plugin '{}' timed out", phase_label, plugin_name);
                    let timeout_err = crate::error::PluginError::Timeout {
                        plugin_name: plugin_name.to_string(),
                        timeout_ms: timeout_dur.as_millis() as u64,
                        proto_error_code: None,
                    };
                    let (effective_allow, status) = match on_error {
                        OnError::Fail if can_block => {
                            executions.push(ControlExecutionRecord {
                                plugin_id: plugin_id.to_string(),
                                plugin_name: plugin_name.to_string(),
                                plugin_kind: ControlExecutionRecord::truncate(&trusted.kind),
                                hook_name: hook_name.to_string(),
                                mode: entry.plugin_ref.mode(),
                                status: ControlExecutionStatus::Timeout,
                                requested_allow: None,
                                effective_allow: false,
                                matched: None,
                                applied: true,
                                payload_modified: false,
                                extensions_modified: false,
                                duration_ns,
                                reason: Some("plugin timed out".to_string()),
                                error_code: Some("plugin_timeout".to_string()),
                                config_keys,
                            });
                            let mut v = crate::error::PluginViolation::new(
                                "plugin_timeout",
                                format!("Plugin '{}' timed out", plugin_name),
                            );
                            v.plugin_name = Some(plugin_name.to_string());
                            return Some(v);
                        },
                        OnError::Fail => {
                            warn!(
                                "{} plugin '{}' on_error=fail (timeout) in non-blocking phase — not halting",
                                phase_label, plugin_name,
                            );
                            errors.push((&timeout_err).into());
                            (true, ControlExecutionStatus::Timeout)
                        },
                        OnError::Ignore => {
                            errors.push((&timeout_err).into());
                            (true, ControlExecutionStatus::Timeout)
                        },
                        OnError::Disable => {
                            warn!(
                                "{} plugin '{}' disabled after timeout",
                                phase_label, plugin_name
                            );
                            errors.push((&timeout_err).into());
                            entry.plugin_ref.disable();
                            (true, ControlExecutionStatus::Timeout)
                        },
                    };
                    executions.push(ControlExecutionRecord {
                        plugin_id: plugin_id.to_string(),
                        plugin_name: plugin_name.to_string(),
                        plugin_kind: ControlExecutionRecord::truncate(&trusted.kind),
                        hook_name: hook_name.to_string(),
                        mode: entry.plugin_ref.mode(),
                        status,
                        requested_allow: None,
                        effective_allow,
                        matched: None,
                        applied: false,
                        payload_modified: false,
                        extensions_modified: false,
                        duration_ns,
                        reason: Some("plugin timed out".to_string()),
                        error_code: Some("plugin_timeout".to_string()),
                        config_keys,
                    });
                },
            }

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
        hook_name: &str,
        errors: &mut Vec<crate::error::PluginErrorRecord>,
        executions: &mut Vec<ControlExecutionRecord>,
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

            let trusted = entry.plugin_ref.trusted_config();
            let config_keys = ControlExecutionRecord::collect_config_keys(trusted.config.as_ref());

            let start = Instant::now();
            let result = timeout(
                timeout_dur,
                entry.handler.invoke(payload, &filtered, &mut ctx),
            )
            .await;
            let duration_ns = start.elapsed().as_nanos().min(u64::MAX as u128) as u64;

            // Audit / fire-and-forget cannot block, so OnError::Fail can't
            // halt the pipeline — but OnError::Disable must still take a
            // repeatedly-failing plugin out of rotation.
            match result {
                Ok(Ok(_)) => {
                    executions.push(ControlExecutionRecord {
                        plugin_id: plugin_id.to_string(),
                        plugin_name: plugin_name.clone(),
                        plugin_kind: ControlExecutionRecord::truncate(&trusted.kind),
                        hook_name: hook_name.to_string(),
                        mode: entry.plugin_ref.mode(),
                        status: ControlExecutionStatus::Completed,
                        requested_allow: Some(true),
                        effective_allow: true,
                        matched: None,
                        applied: false,
                        payload_modified: false,
                        extensions_modified: false,
                        duration_ns,
                        reason: None,
                        error_code: None,
                        config_keys,
                    });
                },
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
                    executions.push(ControlExecutionRecord {
                        plugin_id: plugin_id.to_string(),
                        plugin_name: plugin_name.clone(),
                        plugin_kind: ControlExecutionRecord::truncate(&trusted.kind),
                        hook_name: hook_name.to_string(),
                        mode: entry.plugin_ref.mode(),
                        status: ControlExecutionStatus::Error,
                        requested_allow: None,
                        effective_allow: true,
                        matched: None,
                        applied: false,
                        payload_modified: false,
                        extensions_modified: false,
                        duration_ns,
                        reason: ControlExecutionRecord::truncate_opt(Some(&e.to_string())),
                        error_code: Some("plugin_error".to_string()),
                        config_keys,
                    });
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
                    executions.push(ControlExecutionRecord {
                        plugin_id: plugin_id.to_string(),
                        plugin_name: plugin_name.clone(),
                        plugin_kind: ControlExecutionRecord::truncate(&trusted.kind),
                        hook_name: hook_name.to_string(),
                        mode: entry.plugin_ref.mode(),
                        status: ControlExecutionStatus::Timeout,
                        requested_allow: None,
                        effective_allow: true,
                        matched: None,
                        applied: false,
                        payload_modified: false,
                        extensions_modified: false,
                        duration_ns,
                        reason: Some("plugin timed out".to_string()),
                        error_code: Some("plugin_timeout".to_string()),
                        config_keys,
                    });
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
        hook_name: &str,
        errors: &mut Vec<crate::error::PluginErrorRecord>,
        executions: &mut Vec<ControlExecutionRecord>,
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
            let trusted = entry.plugin_ref.trusted_config();
            let config_keys = ControlExecutionRecord::collect_config_keys(trusted.config.as_ref());
            // Snapshot the configured mode before any on_error handler runs.
            // entry.plugin_ref.mode() returns PluginMode::Disabled once
            // disable() is called, so reading it after the match would record
            // "disabled" instead of the original execution mode ("concurrent").
            let original_mode = trusted.mode;
            // Concurrent branches don't expose per-branch duration — we
            // don't have start times from inside the branch futures.
            // Use 0 to indicate "not measured at this granularity".
            let duration_ns: u64 = 0;

            match outcome {
                BranchOutcome::Completed(BranchData::Allow) => {
                    executions.push(ControlExecutionRecord {
                        plugin_id: entry.plugin_ref.id().to_string(),
                        plugin_name: plugin_name.to_string(),
                        plugin_kind: ControlExecutionRecord::truncate(&trusted.kind),
                        hook_name: hook_name.to_string(),
                        mode: original_mode,
                        status: ControlExecutionStatus::Completed,
                        requested_allow: Some(true),
                        effective_allow: true,
                        matched: None,
                        applied: false,
                        payload_modified: false,
                        extensions_modified: false,
                        duration_ns,
                        reason: None,
                        error_code: None,
                        config_keys,
                    });
                },
                BranchOutcome::Completed(BranchData::Deny(opt_v)) => {
                    let violation = opt_v.unwrap_or_else(|| {
                        let mut v = crate::error::PluginViolation::new(
                            "concurrent_deny",
                            format!("Plugin '{}' denied", plugin_name),
                        );
                        v.plugin_name = Some(plugin_name.to_string());
                        v
                    });
                    executions.push(ControlExecutionRecord {
                        plugin_id: entry.plugin_ref.id().to_string(),
                        plugin_name: plugin_name.to_string(),
                        plugin_kind: ControlExecutionRecord::truncate(&trusted.kind),
                        hook_name: hook_name.to_string(),
                        mode: original_mode,
                        status: ControlExecutionStatus::Completed,
                        requested_allow: Some(false),
                        effective_allow: false,
                        matched: Some(true),
                        applied: true,
                        payload_modified: false,
                        extensions_modified: false,
                        duration_ns,
                        reason: ControlExecutionRecord::truncate_opt(
                            Some(violation.reason.as_str()),
                        ),
                        error_code: Some(ControlExecutionRecord::truncate(&violation.code)),
                        config_keys,
                    });
                    if first_violation.is_none() {
                        first_violation = Some(violation);
                    }
                },
                BranchOutcome::Completed(BranchData::Error(e)) => {
                    let (effective_allow, error_code) = match on_error {
                        OnError::Fail => {
                            if first_violation.is_none() {
                                let mut v = crate::error::PluginViolation::new(
                                    "plugin_error",
                                    format!("Plugin '{}' failed: {}", plugin_name, e),
                                );
                                v.plugin_name = Some(plugin_name.to_string());
                                first_violation = Some(v);
                            }
                            (false, "plugin_error")
                        },
                        OnError::Ignore => {
                            warn!("CONCURRENT plugin '{}' error (ignored): {}", plugin_name, e);
                            errors.push((&*e).into());
                            (true, "plugin_error")
                        },
                        OnError::Disable => {
                            warn!("CONCURRENT plugin '{}' disabled after error", plugin_name);
                            errors.push((&*e).into());
                            entry.plugin_ref.disable();
                            (true, "plugin_error")
                        },
                    };
                    executions.push(ControlExecutionRecord {
                        plugin_id: entry.plugin_ref.id().to_string(),
                        plugin_name: plugin_name.to_string(),
                        plugin_kind: ControlExecutionRecord::truncate(&trusted.kind),
                        hook_name: hook_name.to_string(),
                        mode: original_mode,
                        status: ControlExecutionStatus::Error,
                        requested_allow: None,
                        effective_allow,
                        matched: None,
                        applied: !effective_allow,
                        payload_modified: false,
                        extensions_modified: false,
                        duration_ns,
                        reason: ControlExecutionRecord::truncate_opt(Some(&e.to_string())),
                        error_code: Some(error_code.to_string()),
                        config_keys,
                    });
                },
                BranchOutcome::TimedOut => {
                    let timeout_err = crate::error::PluginError::Timeout {
                        plugin_name: plugin_name.to_string(),
                        timeout_ms: timeout_dur.as_millis() as u64,
                        proto_error_code: None,
                    };
                    let effective_allow = match on_error {
                        OnError::Fail => {
                            if first_violation.is_none() {
                                let mut v = crate::error::PluginViolation::new(
                                    "plugin_timeout",
                                    format!("Plugin '{}' timed out", plugin_name),
                                );
                                v.plugin_name = Some(plugin_name.to_string());
                                first_violation = Some(v);
                            }
                            false
                        },
                        OnError::Ignore => {
                            warn!("CONCURRENT plugin '{}' timed out (ignored)", plugin_name);
                            errors.push((&timeout_err).into());
                            true
                        },
                        OnError::Disable => {
                            warn!("CONCURRENT plugin '{}' disabled after timeout", plugin_name);
                            errors.push((&timeout_err).into());
                            entry.plugin_ref.disable();
                            true
                        },
                    };
                    executions.push(ControlExecutionRecord {
                        plugin_id: entry.plugin_ref.id().to_string(),
                        plugin_name: plugin_name.to_string(),
                        plugin_kind: ControlExecutionRecord::truncate(&trusted.kind),
                        hook_name: hook_name.to_string(),
                        mode: original_mode,
                        status: ControlExecutionStatus::Timeout,
                        requested_allow: None,
                        effective_allow,
                        matched: None,
                        applied: !effective_allow,
                        payload_modified: false,
                        extensions_modified: false,
                        duration_ns,
                        reason: Some("plugin timed out".to_string()),
                        error_code: Some("plugin_timeout".to_string()),
                        config_keys,
                    });
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
                    let effective_allow = match on_error {
                        OnError::Fail => {
                            if first_violation.is_none() {
                                let mut v = crate::error::PluginViolation::new(
                                    "plugin_panic",
                                    format!("Plugin '{}' task panicked: {}", plugin_name, s),
                                );
                                v.plugin_name = Some(plugin_name.to_string());
                                first_violation = Some(v);
                            }
                            false
                        },
                        OnError::Ignore => {
                            warn!("CONCURRENT plugin '{}' panicked (ignored)", plugin_name);
                            errors.push((&panic_err).into());
                            true
                        },
                        OnError::Disable => {
                            warn!("CONCURRENT plugin '{}' disabled after panic", plugin_name);
                            errors.push((&panic_err).into());
                            entry.plugin_ref.disable();
                            true
                        },
                    };
                    executions.push(ControlExecutionRecord {
                        plugin_id: entry.plugin_ref.id().to_string(),
                        plugin_name: plugin_name.to_string(),
                        plugin_kind: ControlExecutionRecord::truncate(&trusted.kind),
                        hook_name: hook_name.to_string(),
                        mode: original_mode,
                        status: ControlExecutionStatus::Error,
                        requested_allow: None,
                        effective_allow,
                        matched: None,
                        applied: !effective_allow,
                        payload_modified: false,
                        extensions_modified: false,
                        duration_ns,
                        reason: Some(ControlExecutionRecord::truncate(&s)),
                        error_code: Some("plugin_panic".to_string()),
                        config_keys,
                    });
                },
                BranchOutcome::Aborted => {
                    // Cancelled because an earlier branch hit a halt
                    // condition under short_circuit_on_deny. Intentional
                    // — record as Cancelled, no error to record.
                    executions.push(ControlExecutionRecord {
                        plugin_id: entry.plugin_ref.id().to_string(),
                        plugin_name: plugin_name.to_string(),
                        plugin_kind: ControlExecutionRecord::truncate(&trusted.kind),
                        hook_name: hook_name.to_string(),
                        mode: original_mode,
                        status: ControlExecutionStatus::Cancelled,
                        requested_allow: None,
                        effective_allow: true, // not evaluated — pipeline may still allow
                        matched: None,
                        applied: false,
                        payload_modified: false,
                        extensions_modified: false,
                        duration_ns,
                        reason: None,
                        error_code: None,
                        config_keys,
                    });
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
        hook_name: &str,
        executions: &mut Vec<ControlExecutionRecord>,
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

            // FAF record is appended at spawn time — status=Completed is
            // optimistic (the actual outcome is unknowable without
            // completion handles per-record). Duration is 0 for the same
            // reason: we haven't run yet. The issue spec documents this
            // explicitly: "fire-and-forget records appear last, marked
            // status=Completed at spawn time".
            let trusted = entry.plugin_ref.trusted_config();
            let config_keys = ControlExecutionRecord::collect_config_keys(trusted.config.as_ref());
            executions.push(ControlExecutionRecord {
                plugin_id: entry.plugin_ref.id().to_string(),
                plugin_name: plugin_name.clone(),
                plugin_kind: ControlExecutionRecord::truncate(&trusted.kind),
                hook_name: hook_name.to_string(),
                mode: entry.plugin_ref.mode(),
                status: ControlExecutionStatus::Completed,
                requested_allow: None,
                effective_allow: true,
                matched: None,
                applied: false,
                payload_modified: false,
                extensions_modified: false,
                duration_ns: 0,
                reason: None,
                error_code: None,
                config_keys,
            });

            // Spawn through TaskTracker so `PluginManager::shutdown()`
            // can drain in-flight fire-and-forget tasks before tearing
            // down.
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
        assert!(result.executions.is_empty(), "no entries → no records");
    }

    // ---------------------------------------------------------------------------
    // Execution record integration tests
    // ---------------------------------------------------------------------------

    use std::sync::Arc;
    use crate::plugin::{OnError, PluginConfig, PluginMode};
    use crate::registry::{AnyHookHandler, HookEntry, PluginRef};
    use crate::context::PluginContext;
    use crate::execution_record::ControlExecutionStatus;
    use async_trait::async_trait;

    fn make_config_for_record(name: &str, mode: PluginMode, on_error: OnError) -> PluginConfig {
        PluginConfig {
            name: name.to_string(),
            kind: "builtin".to_string(),
            mode,
            on_error,
            priority: 100,
            hooks: vec!["test_hook".to_string()],
            ..Default::default()
        }
    }

    struct TestPlugin2 {
        cfg: PluginConfig,
    }

    #[async_trait]
    impl crate::plugin::Plugin for TestPlugin2 {
        fn config(&self) -> &PluginConfig { &self.cfg }
    }

    /// A handler that always allows.
    struct AllowHandler;
    #[async_trait]
    impl AnyHookHandler for AllowHandler {
        async fn invoke(&self, _p: &dyn PluginPayload, _e: &Extensions, _c: &mut PluginContext)
            -> Result<Box<dyn std::any::Any + Send + Sync>, Box<crate::error::PluginError>>
        {
            let result: PluginResult<TestPayload> = PluginResult::allow();
            Ok(erase_result(result))
        }
        fn hook_type_name(&self) -> &'static str { "test_hook" }
    }

    /// A handler that always denies.
    struct DenyHandler;
    #[async_trait]
    impl AnyHookHandler for DenyHandler {
        async fn invoke(&self, _p: &dyn PluginPayload, _e: &Extensions, _c: &mut PluginContext)
            -> Result<Box<dyn std::any::Any + Send + Sync>, Box<crate::error::PluginError>>
        {
            let result: PluginResult<TestPayload> = PluginResult::deny(
                crate::error::PluginViolation::new("test_deny", "test denied"),
            );
            Ok(erase_result(result))
        }
        fn hook_type_name(&self) -> &'static str { "test_hook" }
    }

    /// A handler that always errors.
    struct ErrorHandler;
    #[async_trait]
    impl AnyHookHandler for ErrorHandler {
        async fn invoke(&self, _p: &dyn PluginPayload, _e: &Extensions, _c: &mut PluginContext)
            -> Result<Box<dyn std::any::Any + Send + Sync>, Box<crate::error::PluginError>>
        {
            Err(crate::error::PluginError::Execution {
                plugin_name: "error-plugin".into(),
                message: "deliberate error".into(),
                source: None,
                code: Some("test_error".into()),
                details: std::collections::HashMap::new(),
                proto_error_code: None,
            }.boxed())
        }
        fn hook_type_name(&self) -> &'static str { "test_hook" }
    }

    fn make_entry(name: &str, mode: PluginMode, on_error: OnError, handler: Arc<dyn AnyHookHandler>) -> HookEntry {
        let cfg = make_config_for_record(name, mode, on_error);
        let plugin: Arc<dyn crate::plugin::Plugin> = Arc::new(TestPlugin2 { cfg: cfg.clone() });
        let plugin_ref = Arc::new(PluginRef::new(plugin, cfg));
        HookEntry { plugin_ref, handler }
    }

    #[tokio::test]
    async fn test_execution_record_allow() {
        let executor = Executor::default();
        let tracker = tokio_util::task::TaskTracker::new();
        let entry = make_entry("allow-plugin", PluginMode::Sequential, OnError::Fail,
            Arc::new(AllowHandler));
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "x".into() });
        let (result, _) = executor.execute(&[entry], payload, Extensions::default(), None, &tracker).await;

        assert!(result.continue_processing);
        assert_eq!(result.executions.len(), 1);
        let rec = &result.executions[0];
        assert_eq!(rec.plugin_name, "allow-plugin");
        assert_eq!(rec.hook_name, "test_hook");
        assert_eq!(rec.status, ControlExecutionStatus::Completed);
        assert_eq!(rec.requested_allow, Some(true));
        assert!(rec.effective_allow);
        assert!(!rec.applied);
    }

    #[tokio::test]
    async fn test_execution_record_deny_sequential() {
        let executor = Executor::default();
        let tracker = tokio_util::task::TaskTracker::new();
        let entry = make_entry("deny-plugin", PluginMode::Sequential, OnError::Fail,
            Arc::new(DenyHandler));
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "x".into() });
        let (result, _) = executor.execute(&[entry], payload, Extensions::default(), None, &tracker).await;

        assert!(!result.continue_processing);
        assert_eq!(result.executions.len(), 1);
        let rec = &result.executions[0];
        assert_eq!(rec.plugin_name, "deny-plugin");
        assert_eq!(rec.status, ControlExecutionStatus::Completed);
        assert_eq!(rec.requested_allow, Some(false));
        assert!(!rec.effective_allow);
        assert!(rec.applied);
        assert_eq!(rec.error_code.as_deref(), Some("test_deny"));
    }

    #[tokio::test]
    async fn test_execution_record_error_ignore() {
        let executor = Executor::default();
        let tracker = tokio_util::task::TaskTracker::new();
        let entry = make_entry("error-plugin", PluginMode::Sequential, OnError::Ignore,
            Arc::new(ErrorHandler));
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "x".into() });
        let (result, _) = executor.execute(&[entry], payload, Extensions::default(), None, &tracker).await;

        assert!(result.continue_processing, "Ignore keeps pipeline alive");
        assert_eq!(result.executions.len(), 1);
        let rec = &result.executions[0];
        assert_eq!(rec.status, ControlExecutionStatus::Error);
        assert!(rec.effective_allow, "Ignore → effective allow = true");
        assert_eq!(rec.error_code.as_deref(), Some("plugin_error"));
    }

    #[tokio::test]
    async fn test_execution_record_multiple_allows_preserves_order() {
        let executor = Executor::default();
        let tracker = tokio_util::task::TaskTracker::new();
        let e1 = make_entry("first", PluginMode::Sequential, OnError::Fail, Arc::new(AllowHandler));
        let e2 = make_entry("second", PluginMode::Sequential, OnError::Fail, Arc::new(AllowHandler));
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "x".into() });
        let (result, _) = executor.execute(&[e1, e2], payload, Extensions::default(), None, &tracker).await;

        assert_eq!(result.executions.len(), 2);
        assert_eq!(result.executions[0].plugin_name, "first");
        assert_eq!(result.executions[1].plugin_name, "second");
    }

    #[tokio::test]
    async fn test_execution_record_audit_phase() {
        let executor = Executor::default();
        let tracker = tokio_util::task::TaskTracker::new();
        let entry = make_entry("audit-plugin", PluginMode::Audit, OnError::Fail,
            Arc::new(AllowHandler));
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "x".into() });
        let (result, _) = executor.execute(&[entry], payload, Extensions::default(), None, &tracker).await;

        assert!(result.continue_processing);
        assert_eq!(result.executions.len(), 1);
        let rec = &result.executions[0];
        assert_eq!(rec.plugin_name, "audit-plugin");
        assert_eq!(rec.status, ControlExecutionStatus::Completed);
        assert!(!rec.applied, "audit cannot modify");
        assert!(!rec.payload_modified);
    }

    #[tokio::test]
    async fn test_execution_record_concurrent_allow() {
        let executor = Executor::default();
        let tracker = tokio_util::task::TaskTracker::new();
        let entry = make_entry("concurrent-plugin", PluginMode::Concurrent, OnError::Fail,
            Arc::new(AllowHandler));
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "x".into() });
        let (result, _) = executor.execute(&[entry], payload, Extensions::default(), None, &tracker).await;

        assert!(result.continue_processing);
        assert_eq!(result.executions.len(), 1);
        let rec = &result.executions[0];
        assert_eq!(rec.plugin_name, "concurrent-plugin");
        assert_eq!(rec.status, ControlExecutionStatus::Completed);
        assert!(rec.effective_allow);
    }

    #[tokio::test]
    async fn test_execution_record_concurrent_deny() {
        let executor = Executor::default();
        let tracker = tokio_util::task::TaskTracker::new();
        let entry = make_entry("concurrent-deny", PluginMode::Concurrent, OnError::Fail,
            Arc::new(DenyHandler));
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "x".into() });
        let (result, _) = executor.execute(&[entry], payload, Extensions::default(), None, &tracker).await;

        assert!(!result.continue_processing);
        assert_eq!(result.executions.len(), 1);
        let rec = &result.executions[0];
        assert_eq!(rec.status, ControlExecutionStatus::Completed);
        assert!(!rec.effective_allow);
        assert_eq!(rec.error_code.as_deref(), Some("test_deny"));
    }

    #[tokio::test]
    async fn test_execution_record_faf_spawned() {
        let executor = Executor::default();
        let tracker = tokio_util::task::TaskTracker::new();
        let entry = make_entry("faf-plugin", PluginMode::FireAndForget, OnError::Ignore,
            Arc::new(AllowHandler));
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "x".into() });
        let (result, bg) = executor.execute(&[entry], payload, Extensions::default(), None, &tracker).await;

        // Pipeline allows; FAF record is present at spawn time
        assert!(result.continue_processing);
        assert_eq!(result.executions.len(), 1);
        let rec = &result.executions[0];
        assert_eq!(rec.plugin_name, "faf-plugin");
        assert_eq!(rec.status, ControlExecutionStatus::Completed);
        // duration_ns = 0 at spawn time
        assert_eq!(rec.duration_ns, 0);
        // Clean up background tasks
        tracker.close();
        let _ = bg.wait_for_background_tasks().await;
    }

    #[tokio::test]
    async fn test_execution_record_duration_measured() {
        let executor = Executor::default();
        let tracker = tokio_util::task::TaskTracker::new();
        // Use a handler with a small async sleep to ensure duration > 0
        struct SleepHandler;
        #[async_trait]
        impl AnyHookHandler for SleepHandler {
            async fn invoke(&self, _p: &dyn PluginPayload, _e: &Extensions, _c: &mut PluginContext)
                -> Result<Box<dyn std::any::Any + Send + Sync>, Box<crate::error::PluginError>>
            {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                let result: PluginResult<TestPayload> = PluginResult::allow();
                Ok(erase_result(result))
            }
            fn hook_type_name(&self) -> &'static str { "test_hook" }
        }
        let entry = make_entry("sleep-plugin", PluginMode::Sequential, OnError::Fail,
            Arc::new(SleepHandler));
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "x".into() });
        let (result, _) = executor.execute(&[entry], payload, Extensions::default(), None, &tracker).await;

        assert_eq!(result.executions.len(), 1);
        // At least 1ms = 1_000_000 ns
        assert!(
            result.executions[0].duration_ns >= 1_000_000,
            "duration should be at least 1ms, got {}ns",
            result.executions[0].duration_ns
        );
    }

    #[tokio::test]
    async fn test_execution_record_deny_stops_subsequent() {
        // A deny in sequential phase stops the pipeline — subsequent plugins
        // should NOT have execution records (they weren't invoked).
        let executor = Executor::default();
        let tracker = tokio_util::task::TaskTracker::new();
        let e1 = make_entry("deny-first", PluginMode::Sequential, OnError::Fail, Arc::new(DenyHandler));
        let e2 = make_entry("never-runs", PluginMode::Sequential, OnError::Fail, Arc::new(AllowHandler));
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "x".into() });
        let (result, _) = executor.execute(&[e1, e2], payload, Extensions::default(), None, &tracker).await;

        assert!(!result.continue_processing);
        // Only the denying plugin's record is present; never-runs was not evaluated.
        assert_eq!(result.executions.len(), 1);
        assert_eq!(result.executions[0].plugin_name, "deny-first");
    }

    /// Regression test for Bug 1: a plugin that returns continue_processing=false
    /// without a violation object must still halt the pipeline and produce a record
    /// with effective_allow=false. Previously the inner `if let Some(v)` guard was
    /// missed, causing the deny to be silently swallowed and the plugin recorded as
    /// effective_allow=true.
    #[tokio::test]
    async fn test_execution_record_deny_without_violation_halts_pipeline() {
        struct DenyNoViolationHandler;
        #[async_trait]
        impl AnyHookHandler for DenyNoViolationHandler {
            async fn invoke(
                &self,
                _p: &dyn PluginPayload,
                _e: &Extensions,
                _c: &mut PluginContext,
            ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<crate::error::PluginError>> {
                // Return a deny result with no violation object.
                let mut r: PluginResult<TestPayload> = PluginResult::allow();
                r.continue_processing = false;
                r.violation = None;
                Ok(erase_result(r))
            }
            fn hook_type_name(&self) -> &'static str { "test_hook" }
        }

        let executor = Executor::default();
        let tracker = tokio_util::task::TaskTracker::new();
        let entry = make_entry(
            "no-violation-deny",
            PluginMode::Sequential,
            OnError::Fail,
            Arc::new(DenyNoViolationHandler),
        );
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "x".into() });
        let (result, _) = executor
            .execute(&[entry], payload, Extensions::default(), None, &tracker)
            .await;

        assert!(!result.continue_processing, "pipeline must be halted");
        assert_eq!(result.executions.len(), 1, "one record must be emitted");
        let rec = &result.executions[0];
        assert_eq!(rec.plugin_name, "no-violation-deny");
        assert_eq!(rec.status, ControlExecutionStatus::Completed);
        assert_eq!(rec.requested_allow, Some(false));
        assert!(!rec.effective_allow, "effective_allow must be false");
        assert!(rec.applied, "applied must be true on deny");
        // A synthesized error_code should be present
        assert!(rec.error_code.is_some(), "error_code must be set");
    }

    /// Regression test for Bug 2: concurrent-phase execution records must always
    /// carry the original configured mode ("concurrent"), even when the plugin is
    /// disabled during that same outcome loop via on_error=disable.
    #[tokio::test]
    async fn test_execution_record_concurrent_disable_keeps_original_mode() {
        let executor = Executor::default();
        let tracker = tokio_util::task::TaskTracker::new();
        // ErrorHandler + OnError::Disable → plugin gets disabled during outcome loop
        let entry = make_entry(
            "concurrent-disable",
            PluginMode::Concurrent,
            OnError::Disable,
            Arc::new(ErrorHandler),
        );
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "x".into() });
        let (result, _) = executor
            .execute(&[entry], payload, Extensions::default(), None, &tracker)
            .await;

        // Pipeline continues (Disable doesn't halt), but the plugin is now disabled.
        assert!(result.continue_processing);
        assert_eq!(result.executions.len(), 1);
        let rec = &result.executions[0];
        assert_eq!(rec.plugin_name, "concurrent-disable");
        assert_eq!(rec.status, ControlExecutionStatus::Error);
        // Must be Concurrent, not Disabled
        assert_eq!(
            rec.mode,
            PluginMode::Concurrent,
            "mode must reflect the original configured mode, not the post-disable state"
        );
    }
}
