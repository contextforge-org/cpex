// Location: ./crates/apl-cpex/src/cmf_invoker.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// `CmfPluginInvoker` — `apl-core::PluginInvoker` impl bound to the CMF
// hook family. Every internal dispatch goes through
// `PluginManager::invoke_named::<CmfHook>(...)`, which compiler-enforces
// that the payload is `MessagePayload` and the result is
// `PluginResult<MessagePayload>`. A future PR that changes the CMF
// payload contract won't compile until this file is updated — that's
// the whole point.
//
// # Hook resolution
//
// The hook name to dispatch is no longer hardcoded — it's looked up
// per-plugin from the APL `PluginRegistry` that was parsed out of the
// config's root `plugins:` block. For each `invoke(name, ...)`:
//   1. `EffectivePlugin::resolve(name, registry, route_overrides)`
//      merges the global plugin declaration with any per-route override
//      block. Hooks are NOT route-overridable per spec, so this step
//      mostly matters for `config` / `capabilities` / `on_error` (those
//      aren't yet propagated to dispatch — deferred items).
//   2. The first entry in the plugin's `hooks:` list is used as the
//      CPEX hook name. v0 plugins are expected to declare one hook;
//      multi-hook plugins will need an invocation-context-based picker
//      (Step vs Field vs pipe-chain), tracked separately.
//   3. If the plugin isn't in the registry, or has no hooks declared,
//      the invoker returns `PluginError` — strict by design so config
//      drift fails fast rather than silently dispatching to the wrong
//      hook.
//
// # Lifetime model
//
// One invoker instance per request. The host (e.g. AuthBridge's
// `cpex-runtime`, or a Rust analogue) pre-builds the `MessagePayload`
// once from its raw inputs, hands it in via [`for_request`], and the
// invoker carries it through every plugin dispatch on the request.
// Mutations from plugins (e.g. PII redaction) are persisted in the
// shared payload so the next plugin in the chain sees the rewritten
// version. After route evaluation, the host calls [`current_payload`]
// to extract the final bytes for body re-serialization.
//
// Background tasks returned by `invoke_named` are dropped for v0; when
// we add audit/fire-and-forget plugin support we'll thread a
// `BackgroundTasks` aggregator into the invoker.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;

use cpex_core::cmf::{CmfHook, MessagePayload};
use cpex_core::hooks::payload::Extensions;
use cpex_core::manager::PluginManager;

use apl_core::attributes::AttributeBag;
use apl_core::evaluator::Decision;
use apl_core::plugin_decl::{EffectivePlugin, PluginOverride, PluginRegistry};
use apl_core::step::{PluginError, PluginInvocation, PluginInvoker, PluginOutcome};

/// Bridges APL plugin dispatch to CMF-family CPEX hooks.
///
/// Carries the request's `MessagePayload` for its entire lifetime so
/// plugin mutations accumulate (one plugin's `[REDACTED]` output is
/// visible to the next plugin in the same route).
pub struct CmfPluginInvoker {
    manager: Arc<PluginManager>,
    extensions: Extensions,
    /// `tokio::sync::Mutex` (not `std::sync::Mutex`) because the lock is
    /// held across await points (the manager's invoke is async, and we
    /// want to prevent two concurrent invocations from racing to update
    /// the same payload).
    payload: Arc<Mutex<MessagePayload>>,
    /// Global plugin declarations from the APL config's root `plugins:`
    /// block. Shared across requests via `Arc` — registry is immutable
    /// after `compile_config`.
    plugins: Arc<PluginRegistry>,
    /// Per-route override block. Cloned in from `CompiledRoute.plugin_overrides`
    /// at request start. Empty in tests that exercise the invoker directly
    /// (no route involved).
    plugin_overrides: HashMap<String, PluginOverride>,
}

impl CmfPluginInvoker {
    /// Construct an invoker bound to one request's payload + extensions
    /// and the parsed plugin registry.
    pub fn for_request(
        manager: Arc<PluginManager>,
        extensions: Extensions,
        payload: MessagePayload,
        plugins: Arc<PluginRegistry>,
    ) -> Self {
        Self {
            manager,
            extensions,
            payload: Arc::new(Mutex::new(payload)),
            plugins,
            plugin_overrides: HashMap::new(),
        }
    }

    /// Attach the per-route plugin override block. Called by the host
    /// after picking the route but before driving `evaluate_route`.
    pub fn with_route_overrides(
        mut self,
        overrides: HashMap<String, PluginOverride>,
    ) -> Self {
        self.plugin_overrides = overrides;
        self
    }

    /// Snapshot the current payload. Call after route evaluation to
    /// extract the final (possibly-mutated) `MessagePayload` for body
    /// re-serialization.
    pub async fn current_payload(&self) -> MessagePayload {
        self.payload.lock().await.clone()
    }

    /// Resolve a plugin name to its CPEX hook name via the registry +
    /// per-route overrides. v0 picks the first hook in the plugin's
    /// declaration; future iterations will select per invocation context.
    fn resolve_hook(&self, plugin_name: &str) -> Result<String, PluginError> {
        let eff = EffectivePlugin::resolve(plugin_name, &self.plugins, &self.plugin_overrides)
            .ok_or_else(|| PluginError::NotFound(plugin_name.to_string()))?;
        let hook = eff.hooks.first().ok_or_else(|| {
            PluginError::Dispatch(format!(
                "plugin '{plugin_name}' declares no `hooks:` — apl-cpex needs at least one"
            ))
        })?;
        Ok(hook.clone())
    }
}

#[async_trait]
impl PluginInvoker for CmfPluginInvoker {
    async fn invoke(
        &self,
        plugin_name: &str,
        _bag: &AttributeBag,
        invocation: PluginInvocation<'_>,
    ) -> Result<PluginOutcome, PluginError> {
        let hook_name = self.resolve_hook(plugin_name)?;

        // Snapshot the current payload — `invoke_named` consumes its
        // argument, so we hand it a clone and keep the canonical copy
        // in shared state for the next dispatch.
        let current = self.payload.lock().await.clone();

        let (result, _bg) = self
            .manager
            .invoke_named::<CmfHook>(&hook_name, current, self.extensions.clone(), None)
            .await;

        // Map deny: violation reason → APL deny reason; plugin code →
        // rule_source for audit attribution.
        let decision = if result.is_denied() {
            let (reason, rule_source) = match result.violation {
                Some(v) => (Some(v.reason), v.code),
                None => (None, "policy.forbidden".to_string()),
            };
            Decision::Deny {
                reason,
                rule_source,
            }
        } else {
            Decision::Allow
        };

        // Promote any plugin-side payload mutation back into the shared
        // request payload so the next plugin in the chain sees it.
        // `PluginPayload` only exposes `as_any` (no owning downcast), so
        // we downcast-ref and clone. `MessagePayload: Clone` makes this
        // cheap relative to the FFI/invoke cost.
        let modified_value = if let Some(mp_boxed) = result.modified_payload.as_ref() {
            match mp_boxed.as_any().downcast_ref::<MessagePayload>() {
                Some(modified) => {
                    *self.payload.lock().await = modified.clone();
                    // For pipe-chain (`Field`) calls, surface the new text
                    // content as `modified_value` so APL's evaluator can
                    // feed it into the next field-pipeline stage. For
                    // Step calls, the modification is internal to the
                    // shared payload and `modified_value` stays None.
                    match invocation {
                        PluginInvocation::Field { .. } => {
                            Some(serde_json::Value::String(
                                modified.message.get_text_content(),
                            ))
                        }
                        PluginInvocation::Step => None,
                    }
                }
                None => {
                    tracing::warn!(
                        plugin = %plugin_name,
                        hook = %hook_name,
                        "CmfPluginInvoker: modified_payload was not MessagePayload \
                         (downcast failed) — dropping the mutation"
                    );
                    None
                }
            }
        } else {
            None
        };

        // v0: taint extraction not wired. When plugins start emitting
        // labels via `result.modified_extensions.security.labels`, we'll
        // diff against `self.extensions.security.labels` and feed the
        // additions into `PluginOutcome.taints`.
        Ok(PluginOutcome {
            decision,
            taints: Vec::new(),
            modified_value,
        })
    }
}
