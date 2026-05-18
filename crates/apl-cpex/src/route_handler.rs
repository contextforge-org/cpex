// Location: ./crates/apl-cpex/src/route_handler.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// `AplRouteHandler` — synthetic plugin that drives APL evaluation when
// cpex-core's `filter_entries_by_route` matches an annotated route. Each
// instance is bound to ONE phase (Pre or Post) so the unified-config
// `cmf.tool_pre_invoke` and `cmf.tool_post_invoke` hooks can carry
// distinct handler logic without an in-handler hook-name discriminator.
//
// # Why a phase-bound handler
//
// The CPEX manager's annotation table is keyed on
// `(entity_type, entity_name, scope, hook_name)`. The visitor registers
// one handler per route per phase; the manager picks the right one based
// on the dispatching hook name. Inside `invoke`, no hook-name plumbing is
// needed — the handler already knows which phase it's running.
//
// # Lifetime / weak manager handle
//
// The handler holds `Weak<PluginManager>` because the manager owns the
// snapshot that owns the annotation that owns the handler — a strong
// reference would create a cycle. Each `invoke` upgrades to `Arc` for
// the duration of the call. If the upgrade fails (manager has been
// dropped) the call returns a configuration error.

use std::sync::{Arc, Weak};

use async_trait::async_trait;
use serde_json::Value;

use cpex_core::cmf::MessagePayload;
use cpex_core::context::PluginContext;
use cpex_core::error::{PluginError, PluginViolation};
use cpex_core::executor::ErasedResultFields;
use cpex_core::extensions::Extensions;
use cpex_core::hooks::PluginPayload;
use cpex_core::manager::PluginManager;
use cpex_core::plugin::{Plugin, PluginConfig};
use cpex_core::registry::AnyHookHandler;

use apl_cmf::BagBuilder;
use apl_core::evaluator::Decision;
use apl_core::plugin_decl::PluginRegistry;
use apl_core::route::{evaluate_post, evaluate_pre, RoutePayload};
use apl_core::rules::CompiledRoute;
use apl_core::step::PdpResolver;

use crate::cmf_invoker::CmfPluginInvoker;
use crate::dispatch_plan::DispatchCache;
use crate::pdp_router::PdpRouter;
use crate::session_store::SessionStore;

/// Which APL phase this handler runs. Pre covers `args` + `policy`; Post
/// covers `result` + `post_policy`. Set once at construction and never
/// changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Pre,
    Post,
}

/// Synthetic plugin that drives APL evaluation for one route + one phase.
///
/// Implements `Plugin` (so cpex-core treats it like any other plugin —
/// mode/capabilities/on_error come from the `PluginConfig` the visitor
/// supplied at `annotate_route` time) and `AnyHookHandler` (so the
/// executor dispatches into it through the normal type-erased path).
pub struct AplRouteHandler {
    config: PluginConfig,
    route: Arc<CompiledRoute>,
    phase: Phase,
    plugin_registry: Arc<PluginRegistry>,
    dispatch_cache: Arc<DispatchCache>,
    session_store: Arc<dyn SessionStore>,
    /// Weak handle to the manager so we can resolve plugin entries +
    /// dispatch into them by-name. `Weak` avoids the
    /// manager↔snapshot↔annotation↔handler cycle.
    manager: Weak<PluginManager>,
    /// PDP resolver. APL routes that don't use `pdp(...)` steps never
    /// touch this. Default is an empty [`PdpRouter`] — any `pdp(...)`
    /// step against an unregistered dialect returns
    /// `PdpError::NoResolver`. Hosts that need Cedar, OPA, NeMo, etc.
    /// install resolvers via [`Self::with_pdp`] or
    /// [`Self::with_pdp_router`].
    pdp: Arc<dyn PdpResolver>,
}

impl AplRouteHandler {
    /// Build a handler. Visitor calls this twice per route — once for
    /// each phase — and passes the resulting `Arc` to `annotate_route`.
    pub fn new(
        config: PluginConfig,
        route: Arc<CompiledRoute>,
        phase: Phase,
        plugin_registry: Arc<PluginRegistry>,
        dispatch_cache: Arc<DispatchCache>,
        session_store: Arc<dyn SessionStore>,
        manager: Weak<PluginManager>,
    ) -> Self {
        Self {
            config,
            route,
            phase,
            plugin_registry,
            dispatch_cache,
            session_store,
            manager,
            pdp: Arc::new(PdpRouter::new()),
        }
    }

    /// Install a `PdpResolver`. Pass a [`PdpRouter`] when the host needs
    /// to support multiple dialects (Cedar + OPA + NeMo) on the same
    /// route — the router dispatches each `pdp(...)` step by dialect.
    /// Pass a single resolver when only one dialect is in use; APL
    /// steps for any other dialect will then return
    /// `PdpError::NoResolver` at evaluation time.
    pub fn with_pdp(mut self, pdp: Arc<dyn PdpResolver>) -> Self {
        self.pdp = pdp;
        self
    }

    /// Sugar for the common "register many resolvers" path. Builds a
    /// [`PdpRouter`], registers each resolver into it, then installs the
    /// router. Equivalent to constructing a `PdpRouter` by hand and
    /// passing it to [`Self::with_pdp`].
    pub fn with_pdp_router(
        mut self,
        resolvers: impl IntoIterator<Item = Arc<dyn PdpResolver>>,
    ) -> Self {
        let mut router = PdpRouter::new();
        for r in resolvers {
            router.register(r);
        }
        self.pdp = Arc::new(router);
        self
    }
}

#[async_trait]
impl Plugin for AplRouteHandler {
    fn config(&self) -> &PluginConfig {
        &self.config
    }
}

#[async_trait]
impl AnyHookHandler for AplRouteHandler {
    async fn invoke(
        &self,
        payload: &dyn PluginPayload,
        extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
        // Downcast to the CMF payload — this handler only registers for
        // cmf.* hook names, so the executor should always hand us a
        // MessagePayload. A mismatch indicates a framework wiring bug.
        let msg_payload = payload
            .as_any()
            .downcast_ref::<MessagePayload>()
            .ok_or_else(|| {
                Box::new(PluginError::Config {
                    message: format!(
                        "AplRouteHandler '{}': payload was not MessagePayload",
                        self.route.route_key
                    ),
                })
            })?;

        let manager = self.manager.upgrade().ok_or_else(|| {
            Box::new(PluginError::Config {
                message: format!(
                    "AplRouteHandler '{}': PluginManager dropped before invoke",
                    self.route.route_key
                ),
            })
        })?;

        // Build (or reuse) the dispatch plan for this route. Cache keyed
        // by `(route_key, manager.config_generation())` — if the manager
        // has reloaded since the last invoke, the next lookup rebuilds.
        let plan = self
            .dispatch_cache
            .get_or_build(&self.route, &self.plugin_registry, &manager)
            .await;

        // CmfPluginInvoker carries the request-scoped payload + extensions
        // under interior mutability so successive plugin calls accumulate
        // mutations. Hydration + persistence are no-ops when there's no
        // session id (the common case for the first request in a session).
        let invoker = CmfPluginInvoker::for_request(
            Arc::clone(&manager),
            extensions.clone(),
            msg_payload.clone(),
            plan,
            Arc::clone(&self.session_store),
        )
        .await;

        // Build the attribute bag. APL predicates read flat keys; the
        // BagBuilder bridges typed CPEX extensions into that namespace.
        // `route.key` lets default/policy-bundle predicates branch on
        // which route they're attached to.
        let post_extensions = invoker.current_extensions().await;
        let bag = BagBuilder::new()
            .with_extensions(&post_extensions)
            .with_route_key(&self.route.route_key)
            .build();

        // v0 RoutePayload: args = the message's text content as a JSON
        // string. Field pipelines operate on `args.<name>` paths; for
        // single-text messages the typical pattern is to declare
        // `args.text:` rules against the whole payload. Result is
        // populated only on the post-invoke path — the host hasn't seen
        // a tool response yet at pre-invoke time.
        let args_value = Value::String(msg_payload.message.get_text_content());
        let mut route_payload = match self.phase {
            Phase::Pre => RoutePayload::new(args_value),
            Phase::Post => RoutePayload::with_result(args_value, Value::Null),
        };

        let decision = match self.phase {
            Phase::Pre => {
                evaluate_pre(
                    &self.route,
                    &bag,
                    &mut route_payload,
                    self.pdp.as_ref(),
                    &invoker,
                )
                .await
            }
            Phase::Post => {
                evaluate_post(
                    &self.route,
                    &bag,
                    &mut route_payload,
                    self.pdp.as_ref(),
                    &invoker,
                )
                .await
            }
        };

        // Commit any session-scoped labels accumulated during this
        // request. No-op when there was no session id.
        invoker.persist_session().await;

        // Surface the final mutated payload + extensions back into the
        // PipelineResult the executor returns to the host. The host's
        // body re-serialization picks up edits made by APL pipelines
        // (e.g. a redact stage that rewrote args.text).
        let final_payload = invoker.current_payload().await;
        let final_extensions = invoker.current_extensions().await;

        let modified_payload: Option<Box<dyn PluginPayload>> =
            if route_payload.args != Value::String(final_payload.message.get_text_content()) {
                // An args pipeline (Pre) or result pipeline (Post) rewrote
                // the text — fold it back into a fresh MessagePayload so
                // downstream readers see the change.
                let mut updated = final_payload.clone();
                if let Some(text) = route_payload.args.as_str() {
                    rewrite_message_text(&mut updated.message, text);
                }
                Some(Box::new(updated) as Box<dyn PluginPayload>)
            } else if msg_payload.message.get_text_content()
                != final_payload.message.get_text_content()
            {
                // A `policy:` plugin mutated the message directly via
                // `modify_payload` (not through a field pipeline). Pass
                // the invoker's view through unchanged.
                Some(Box::new(final_payload) as Box<dyn PluginPayload>)
            } else {
                None
            };

        let modified_extensions = if extensions_changed(extensions, &final_extensions) {
            Some(final_extensions.cow_copy())
        } else {
            None
        };

        let (continue_processing, violation) = match decision.decision {
            Decision::Allow => (true, None),
            Decision::Deny { reason, rule_source } => {
                let code = if rule_source.is_empty() {
                    "policy.deny".to_string()
                } else {
                    rule_source
                };
                let reason = reason.unwrap_or_else(|| "denied by APL".to_string());
                (false, Some(PluginViolation::new(code, reason)))
            }
        };

        Ok(Box::new(ErasedResultFields {
            continue_processing,
            modified_payload,
            modified_extensions,
            violation,
        }))
    }

    fn hook_type_name(&self) -> &'static str {
        // CmfHook::NAME — kept as a literal here to avoid pulling in the
        // HookTypeDef trait just for the constant.
        "cmf"
    }
}

// =====================================================================
// Helpers
// =====================================================================

/// Rewrite the first text part of `msg` with `new_text`. If there is no
/// text part, append one. Mirrors what `MessagePayload`'s normal
/// modify-path does for single-view v0.
fn rewrite_message_text(msg: &mut cpex_core::cmf::Message, new_text: &str) {
    for part in msg.content.iter_mut() {
        if let cpex_core::cmf::ContentPart::Text { text } = part {
            *text = new_text.to_string();
            return;
        }
    }
    msg.content.push(cpex_core::cmf::ContentPart::Text {
        text: new_text.to_string(),
    });
}

/// Cheap pointer-equality check across the few mutable extension slots
/// the executor would care about. False positives (claiming a change
/// when there isn't one) are cheap — the executor re-validates anyway.
fn extensions_changed(before: &Extensions, after: &Extensions) -> bool {
    let security_changed = match (before.security.as_ref(), after.security.as_ref()) {
        (Some(a), Some(b)) => !Arc::ptr_eq(a, b),
        (None, None) => false,
        _ => true,
    };
    let delegation_changed = match (before.delegation.as_ref(), after.delegation.as_ref()) {
        (Some(a), Some(b)) => !Arc::ptr_eq(a, b),
        (None, None) => false,
        _ => true,
    };
    security_changed || delegation_changed
}

