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
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::timeout;
use tracing::{error, warn};

use crate::context::{PluginContext, PluginContextTable};
use crate::extensions::filter_extensions;
use crate::hooks::payload::{Extensions, PluginPayload, WriteToken};
use crate::plugin::OnError;
use crate::registry::{group_by_mode, HookEntry};

// ---------------------------------------------------------------------------
// Executor Configuration
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Pipeline Result
// ---------------------------------------------------------------------------

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

    /// Optional metadata aggregated from plugins (telemetry, diagnostics).
    pub metadata: Option<serde_json::Value>,

    /// Plugin contexts indexed by plugin ID. Thread this into the
    /// next hook invocation to preserve per-plugin `local_state`.
    pub context_table: PluginContextTable,
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
            metadata: None,
            context_table,
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
            metadata: None,
            context_table,
        }
    }

    /// Whether this result represents a denial.
    pub fn is_denied(&self) -> bool {
        !self.continue_processing
    }
}

// ---------------------------------------------------------------------------
// Background Tasks
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Executor
// ---------------------------------------------------------------------------

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
    ) -> (PipelineResult, BackgroundTasks) {
        let mut ctx_table = context_table.unwrap_or_default();

        if entries.is_empty() {
            return (
                PipelineResult::allowed_with(payload, extensions, ctx_table),
                BackgroundTasks::empty(),
            );
        }

        // Group entries by mode (from trusted_config)
        let (sequential, transform, audit, concurrent, fire_and_forget) =
            group_by_mode(entries);

        let mut current_payload = payload;
        let mut current_extensions = extensions;

        // Phase 1: SEQUENTIAL — serial, chained, can block + modify
        if let Some(v) = self
            .run_serial_phase(
                &sequential,
                &mut current_payload,
                &mut current_extensions,
                &mut ctx_table,
                true,  // can_block
                true,  // can_modify
                "SEQUENTIAL",
            )
            .await
        {
            return (
                PipelineResult::denied(v, current_extensions, ctx_table),
                BackgroundTasks::empty(),
            );
        }

        // Phase 2: TRANSFORM — serial, chained, can modify, cannot block
        // can_block=false means denials are suppressed (returns None)
        self.run_serial_phase(
            &transform,
            &mut current_payload,
            &mut current_extensions,
            &mut ctx_table,
            false, // can_block
            true,  // can_modify
            "TRANSFORM",
        )
        .await;

        // Phase 3: AUDIT — serial, read-only, discard results
        self.run_ref_phase(&audit, &*current_payload, &current_extensions, &ctx_table, "AUDIT")
            .await;

        // Phase 4: CONCURRENT — parallel, can block, cannot modify
        if let Some(violation) = self
            .run_concurrent_phase(&concurrent, &*current_payload, &current_extensions, &ctx_table)
            .await
        {
            return (
                PipelineResult::denied(violation, current_extensions, ctx_table),
                BackgroundTasks::empty(),
            );
        }

        // Phase 5: FIRE_AND_FORGET — background, read-only, ignore results
        let bg_handles = self.spawn_fire_and_forget(
            &fire_and_forget,
            &*current_payload,
            &current_extensions,
            &ctx_table,
        );

        (
            PipelineResult::allowed_with(current_payload, current_extensions, ctx_table),
            BackgroundTasks::from_handles(bg_handles),
        )
    }

    // -----------------------------------------------------------------------
    // Phase 1 & 2: Serial execution (SEQUENTIAL / TRANSFORM)
    // -----------------------------------------------------------------------

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
    async fn run_serial_phase(
        &self,
        entries: &[HookEntry],
        payload: &mut Box<dyn PluginPayload>,
        extensions: &mut Extensions,
        ctx_table: &mut PluginContextTable,
        can_block: bool,
        can_modify: bool,
        phase_label: &str,
    ) -> Option<crate::error::PluginViolation> {
        // Extract current global state from the table (use last plugin's
        // global_state, or start empty). We maintain a running copy that
        // gets set on each plugin's context and merged back after.
        let mut global_state = ctx_table
            .values()
            .last()
            .map(|c| c.global_state.clone())
            .unwrap_or_default();

        for entry in entries {
            let plugin_name = entry.plugin_ref.name().to_string();
            let plugin_id = entry.plugin_ref.id().to_string();
            let on_error = entry.plugin_ref.trusted_config().on_error;

            // Look up existing context (preserves local_state from prior hooks)
            // or create a fresh one. Set global_state to the current running copy.
            let mut ctx = ctx_table.remove(&plugin_id).unwrap_or_default();
            ctx.global_state = global_state.clone();

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

            // Execute with timeout — handler borrows payload, gets filtered extensions
            let timeout_dur = Duration::from_secs(self.config.timeout_seconds);
            let result = timeout(timeout_dur, entry.handler.invoke(&**payload, &filtered, &mut ctx))
                .await;

            match result {
                Ok(Ok(result_box)) => {
                    if let Some(erased) = extract_erased(result_box) {
                        // Check deny
                        if !erased.continue_processing && can_block {
                            if let Some(mut v) = erased.violation {
                                v.plugin_name = Some(plugin_name.clone());
                                return Some(v);
                            }
                        }

                        // Accept modifications
                        if can_modify {
                            if let Some(mp) = erased.modified_payload {
                                *payload = mp;
                            }
                            if let Some(owned) = erased.modified_extensions {
                                // Validate tier constraints before accepting
                                if !extensions.validate_immutable(&owned) {
                                    warn!(
                                        "{} plugin '{}' violated immutable tier — \
                                         modified an immutable extension slot. \
                                         Extension changes rejected.",
                                        phase_label, plugin_name
                                    );
                                } else if let Some(ref orig_sec) = extensions.security {
                                    if let Some(ref new_sec) = owned.security {
                                        if !new_sec.labels.is_superset(&orig_sec.labels) {
                                            warn!(
                                                "{} plugin '{}' violated monotonic tier — \
                                                 removed a security label. \
                                                 Extension changes rejected.",
                                                phase_label, plugin_name
                                            );
                                        } else {
                                            extensions.merge_owned(owned);
                                        }
                                    } else {
                                        extensions.merge_owned(owned);
                                    }
                                } else {
                                    extensions.merge_owned(owned);
                                }
                            }
                        }

                        // Merge global state changes back from the handler.
                        // The handler received &mut PluginContext and may have
                        // written to ctx.global_state directly.
                        if ctx.global_state != global_state {
                            global_state = ctx.global_state.clone();
                        }
                    }
                    // If extract failed or no modifications — payload unchanged
                }
                Ok(Err(e)) => {
                    error!("{} plugin '{}' failed: {}", phase_label, plugin_name, e);
                    match on_error {
                        OnError::Fail => {
                            let mut v = crate::error::PluginViolation::new(
                                "plugin_error",
                                format!("Plugin '{}' failed: {}", plugin_name, e),
                            );
                            v.plugin_name = Some(plugin_name);
                            return Some(v);
                        }
                        OnError::Ignore => {}
                        OnError::Disable => {
                            warn!("{} plugin '{}' disabled after error", phase_label, plugin_name);
                            entry.plugin_ref.disable();
                        }
                    }
                }
                Err(_) => {
                    error!("{} plugin '{}' timed out", phase_label, plugin_name);
                    match on_error {
                        OnError::Fail => {
                            let mut v = crate::error::PluginViolation::new(
                                "plugin_timeout",
                                format!("Plugin '{}' timed out", plugin_name),
                            );
                            v.plugin_name = Some(plugin_name);
                            return Some(v);
                        }
                        OnError::Ignore => {}
                        OnError::Disable => {
                            warn!("{} plugin '{}' disabled after error", phase_label, plugin_name);
                            entry.plugin_ref.disable();
                        }
                    }
                }
            }

            // Store context back into the table (preserves local_state
            // for the next hook invocation via the returned context_table).
            // Note: global_state merging from plugin writes is deferred —
            // handlers currently receive &PluginContext (shared ref) so
            // they can't mutate global_state directly. When we add write-back
            // (via PluginResult or interior mutability), merge here.
            ctx_table.insert(plugin_id, ctx);
        }

        None // no denial
    }

    // -----------------------------------------------------------------------
    // Phase 3 & 5: Read-only execution (AUDIT / FIRE_AND_FORGET)
    // -----------------------------------------------------------------------

    /// Run a read-only phase — plugins receive &payload, results discarded.
    async fn run_ref_phase(
        &self,
        entries: &[HookEntry],
        payload: &dyn PluginPayload,
        extensions: &Extensions,
        ctx_table: &PluginContextTable,
        phase_label: &str,
    ) {
        // Read-only phases get a snapshot of global state but don't merge back.
        let global_state: HashMap<String, serde_json::Value> = ctx_table
            .values()
            .last()
            .map(|c| c.global_state.clone())
            .unwrap_or_default();

        for entry in entries {
            let plugin_name = entry.plugin_ref.name().to_string();
            let plugin_id = entry.plugin_ref.id();
            let mut ctx = ctx_table
                .get(plugin_id)
                .cloned()
                .map(|mut c| { c.global_state = global_state.clone(); c })
                .unwrap_or_else(|| PluginContext::with_global_state(global_state.clone()));
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

            let result = timeout(timeout_dur, entry.handler.invoke(payload, &filtered, &mut ctx))
                .await;

            match result {
                Ok(Ok(_)) => {} // read-only — discard result and ext_clone
                Ok(Err(e)) => {
                    warn!("{} plugin '{}' error (ignored): {}", phase_label, plugin_name, e);
                }
                Err(_) => {
                    warn!("{} plugin '{}' timed out (ignored)", phase_label, plugin_name);
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Phase 4: Concurrent (parallel, fail-fast)
    // -----------------------------------------------------------------------

    /// Run the concurrent phase — plugins execute truly in parallel.
    /// Returns the first violation if any plugin denies.
    async fn run_concurrent_phase(
        &self,
        entries: &[HookEntry],
        payload: &dyn PluginPayload,
        extensions: &Extensions,
        ctx_table: &PluginContextTable,
    ) -> Option<crate::error::PluginViolation> {
        if entries.is_empty() {
            return None;
        }

        // Clone the payload once so each spawned task can borrow from
        // an owned, 'static copy. Each task gets its own Arc'd clone.
        let shared_payload: Arc<Box<dyn PluginPayload>> =
            Arc::new(payload.clone_boxed());
        let timeout_dur = Duration::from_secs(self.config.timeout_seconds);

        // Snapshot global state for all concurrent plugins
        let global_state: HashMap<String, serde_json::Value> = ctx_table
            .values()
            .last()
            .map(|c| c.global_state.clone())
            .unwrap_or_default();

        // Spawn all handlers concurrently — each task returns just
        // the invoke result. We zip outcomes back with entries to
        // access PluginRef for disable() without cloning it into the spawn.
        let mut handles = Vec::with_capacity(entries.len());

        for entry in entries {
            let handler = Arc::clone(&entry.handler);
            let payload_clone = Arc::clone(&shared_payload);
            let plugin_id = entry.plugin_ref.id().to_string();
            let mut ctx = ctx_table
                .get(&plugin_id)
                .cloned()
                .map(|mut c| { c.global_state = global_state.clone(); c })
                .unwrap_or_else(|| PluginContext::with_global_state(global_state.clone()));
            let dur = timeout_dur;

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

            let handle = tokio::spawn(async move {
                timeout(dur, handler.invoke(&**payload_clone, &filtered, &mut ctx)).await
            });

            handles.push(handle);
        }

        // Collect results — zip with entries for PluginRef access
        let outcomes = futures::future::join_all(handles).await;
        let mut denials = Vec::new();

        for (entry, outcome) in entries.iter().zip(outcomes) {
            let plugin_name = entry.plugin_ref.name();
            let on_error = entry.plugin_ref.trusted_config().on_error;

            let result = match outcome {
                Ok(r) => r,
                Err(e) => {
                    error!("CONCURRENT task panicked: {}", e);
                    continue;
                }
            };

            match result {
                Ok(Ok(result_box)) => {
                    if let Some(erased) = extract_erased(result_box) {
                        if !erased.continue_processing {
                            let mut violation = erased.violation.unwrap_or_else(|| {
                                crate::error::PluginViolation::new(
                                    "concurrent_deny",
                                    format!("Plugin '{}' denied", plugin_name),
                                )
                            });
                            violation.plugin_name = Some(plugin_name.to_string());
                            if self.config.short_circuit_on_deny {
                                return Some(violation);
                            }
                            denials.push(violation);
                        }
                    }
                }
                Ok(Err(e)) => match on_error {
                    OnError::Fail => {
                        let mut v = crate::error::PluginViolation::new(
                            "plugin_error",
                            format!("Plugin '{}' failed: {}", plugin_name, e),
                        );
                        v.plugin_name = Some(plugin_name.to_string());
                        return Some(v);
                    }
                    OnError::Ignore => {
                        warn!("CONCURRENT plugin '{}' error (ignored): {}", plugin_name, e);
                    }
                    OnError::Disable => {
                        warn!("CONCURRENT plugin '{}' disabled after error", plugin_name);
                        entry.plugin_ref.disable();
                    }
                },
                Err(_) => match on_error {
                    OnError::Fail => {
                        let mut v = crate::error::PluginViolation::new(
                            "plugin_timeout",
                            format!("Plugin '{}' timed out", plugin_name),
                        );
                        v.plugin_name = Some(plugin_name.to_string());
                        return Some(v);
                    }
                    OnError::Ignore => {
                        warn!("CONCURRENT plugin '{}' timed out (ignored)", plugin_name);
                    }
                    OnError::Disable => {
                        warn!("CONCURRENT plugin '{}' disabled after timeout", plugin_name);
                        entry.plugin_ref.disable();
                    }
                },
            }
        }

        // Return first denial if any were collected (non-short-circuit mode)
        denials.into_iter().next()
    }

    // -----------------------------------------------------------------------
    // Phase 5: Fire-and-Forget (background, no await)
    // -----------------------------------------------------------------------

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
    ) -> Vec<(String, tokio::task::JoinHandle<()>)> {
        if entries.is_empty() {
            return Vec::new();
        }

        let timeout_dur = Duration::from_secs(self.config.timeout_seconds);
        let global_state: HashMap<String, serde_json::Value> = ctx_table
            .values()
            .last()
            .map(|c| c.global_state.clone())
            .unwrap_or_default();

        let mut handles = Vec::with_capacity(entries.len());

        for entry in entries {
            let plugin_name = entry.plugin_ref.name().to_string();
            let handler = Arc::clone(&entry.handler);
            let owned_payload = payload.clone_boxed();
            let mut ctx = PluginContext::with_global_state(global_state.clone());
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

            let handle = tokio::spawn(async move {
                let result = timeout(
                    dur,
                    handler.invoke(&*owned_payload, &filtered, &mut ctx),
                )
                .await;

                match result {
                    Ok(Ok(_)) => {} // discard
                    Ok(Err(e)) => {
                        warn!("FIRE_AND_FORGET plugin '{}' error (ignored): {}", name_for_log, e);
                    }
                    Err(_) => {
                        warn!("FIRE_AND_FORGET plugin '{}' timed out (ignored)", name_for_log);
                    }
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

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

// SerialResult removed — run_serial_phase now returns Option<Violation> directly.

// ---------------------------------------------------------------------------
// Erased Result Extraction
// ---------------------------------------------------------------------------

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
        }
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
        let result: PluginResult<TestPayload> = PluginResult::deny(
            crate::error::PluginViolation::new("test", "denied"),
        );
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
        let sec = fields.modified_extensions.as_ref().unwrap().security.as_ref().unwrap();
        assert!(sec.has_label("PII"));
    }

    #[test]
    fn test_pipeline_result_allowed() {
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "test".into(),
        });
        let result = PipelineResult::allowed_with(
            payload,
            Extensions::default(),
            PluginContextTable::new(),
        );
        assert!(result.continue_processing);
        assert!(result.modified_payload.is_some());
        assert!(result.violation.is_none());
    }

    #[test]
    fn test_pipeline_result_denied() {
        let violation = crate::error::PluginViolation::new("test", "denied");
        let result = PipelineResult::denied(
            violation,
            Extensions::default(),
            PluginContextTable::new(),
        );
        assert!(!result.continue_processing);
        assert!(result.modified_payload.is_none());
        assert!(result.violation.is_some());
    }

    #[tokio::test]
    async fn test_executor_empty_entries() {
        let executor = Executor::default();
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "test".into(),
        });
        let (result, _) = executor
            .execute(&[], payload, Extensions::default(), None)
            .await;
        assert!(result.continue_processing);
        assert!(result.modified_payload.is_some());
    }
}
