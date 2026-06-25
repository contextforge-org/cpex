// Location: ./crates/apl-cpex/src/route_handler.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor, Fred Araujo
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

use apl_cmf::{extract_args, extract_result, BagBuilder};
use apl_core::evaluator::Decision;
use apl_core::plugin_decl::PluginRegistry;
use apl_core::route::{evaluate_post, evaluate_pre, RoutePayload};
use apl_core::rules::CompiledRoute;
use apl_core::step::PdpResolver;

use crate::cmf_invoker::CmfPluginInvoker;
use crate::delegation_invoker::DelegationPluginInvoker;
use crate::elicitation_invoker::ElicitationPluginInvoker;
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
        // Wrapped in Arc so it can be erased to `Arc<dyn PluginInvoker>`
        // for the apl-core entry points (which take `&Arc<dyn PluginInvoker>`
        // so `dispatch_parallel` can clone an owned, 'static reference into
        // each spawned branch). Inherent-method calls on `CmfPluginInvoker`
        // (e.g. `extensions_arc`, `persist_session`) deref through the Arc.
        // Hydration loads accumulated session labels. A store failure
        // here happens *before* any policy decision, so we fail the
        // request closed immediately (R5/R18, F2): deny with a
        // distinguished violation rather than proceeding as if the
        // session carried no taint. Sessionless traffic never reaches
        // the store, so this only denies session-bearing requests.
        let invoker = match CmfPluginInvoker::for_request(
            Arc::clone(&manager),
            extensions.clone(),
            msg_payload.clone(),
            plan,
            Arc::clone(&self.session_store),
        )
        .await
        {
            Ok(inv) => Arc::new(inv),
            Err(e) => {
                tracing::error!(
                    alarm = "session_store_failure",
                    op = "load",
                    route = %self.route.route_key,
                    error = %e,
                    "session label load failed; failing request closed"
                );
                return Ok(Box::new(ErasedResultFields {
                    continue_processing: false,
                    modified_payload: None,
                    modified_extensions: None,
                    violation: Some(PluginViolation::new(
                        "session.load_failed",
                        "session state could not be loaded",
                    )),
                }));
            },
        };

        // Build the attribute bag. APL predicates read flat keys; the
        // BagBuilder bridges typed CPEX extensions into that namespace.
        // `route.key` lets default/policy-bundle predicates branch on
        // which route they're attached to.
        let post_extensions = invoker.current_extensions().await;
        let mut bag = BagBuilder::new()
            .with_extensions(&post_extensions)
            .with_route_key(&self.route.route_key)
            .build();

        // Build `RoutePayload.args` from the message. Per-content shape:
        //   * ToolCall      → arguments map (JSON Object)
        //   * PromptRequest → arguments map (JSON Object)
        //   * Text-only     → JSON String of concatenated text content
        //
        // Field pipelines operate on `args.<name>` paths. Result starts
        // as Null on Pre (no upstream response yet); the Post phase
        // would extract from a ToolResult / PromptResult — deferred
        // until result-side handling lands.
        let args_value = extract_args_from_message(&msg_payload.message);
        let mut route_payload = match self.phase {
            Phase::Pre => RoutePayload::new(args_value),
            Phase::Post => {
                // Pull the upstream result out of the message so APL
                // `result.<field>` predicates and the `result:`
                // pipeline have something to operate on. Falls back to
                // `Value::Null` when the message has no ToolResult /
                // PromptResult / Resource content (e.g. for hooks that
                // fire on entities without a structured result).
                let result_value = extract_result_from_message(&msg_payload.message);
                RoutePayload::with_result(args_value, result_value)
            },
        };

        // Flatten the call args into the bag under `args.<path>`. APL's
        // own args pipelines read from `route_payload.args` directly,
        // but PDP steps and predicates that reference `${args.X}` /
        // `args.X` resolve through the bag. Mirroring the args here
        // makes both consumers see the same vocabulary the
        // `MessageView` exposes. (Bag-mutation via redact during the
        // args pipeline isn't reflected back into the bag; that's fine
        // — args predicates today read from `route_payload.args`, and
        // the cedar substitution snapshots the pre-args view, which is
        // what an author writing `cedar:(resource.id: ${args.X})` would
        // expect.)
        extract_args(&route_payload.args, &mut bag);
        // Post phase: also project the upstream result into the bag
        // under `result.<path>`. This is what enables predicates like
        // `redact(result.ssn) when !perm.view_ssn` and `require(...)`
        // gates that branch on the result. Pre phases skip this — the
        // result is `None` by construction.
        if matches!(self.phase, Phase::Post) {
            if let Some(result_value) = route_payload.result.as_ref() {
                extract_result(result_value, &mut bag);
            }
        }

        // Slice B: real delegation invoker, sharing the CMF invoker's
        // extensions Mutex so a `delegate(...)` step's writes to
        // raw_credentials / delegation are visible to downstream CMF
        // plugins and to the post phase. Routes that don't declare
        // any `Step::Delegate` won't have entries in the plan's
        // `delegation_entries` map; if such a route accidentally hits
        // `delegate(...)`, the invoker returns `NotFound` and the
        // evaluator translates it via the step's `on_error`.
        let delegations = Arc::new(DelegationPluginInvoker::new(
            Arc::clone(&manager),
            invoker.extensions_arc(),
            invoker.plan_arc(),
        ));

        // Unsized coercion: `Arc<ConcreteType>` → `Arc<dyn Trait>`. The
        // erased forms get borrowed into `evaluate_pre`/`evaluate_post`;
        // `dispatch_parallel` can then `Arc::clone` an owned 'static
        // reference into each branch closure.
        // Elicitation bridge — resolves `require_approval(...)` /
        // `confirm(...)` steps to `ElicitationHook` plugins by name off
        // the same plan, sharing the request's Extensions so the handler
        // reads the same identity. Routes with no elicitation steps have
        // an empty `elicitation_entries` map; an accidental `Effect::Elicit`
        // then returns `NotFound`, handled by the step's `on_error`.
        let elicitations = Arc::new(ElicitationPluginInvoker::new(
            Arc::clone(&manager),
            invoker.extensions_arc(),
            invoker.plan_arc(),
        ));

        let invoker_dyn: Arc<dyn apl_core::step::PluginInvoker> = invoker.clone();
        let delegations_dyn: Arc<dyn apl_core::step::DelegationInvoker> = delegations.clone();
        let elicitations_dyn: Arc<dyn apl_core::step::ElicitationInvoker> = elicitations.clone();

        let decision = match self.phase {
            Phase::Pre => {
                evaluate_pre(
                    &self.route,
                    &mut bag,
                    &mut route_payload,
                    &self.pdp,
                    &invoker_dyn,
                    &delegations_dyn,
                    &elicitations_dyn,
                )
                .await
            },
            Phase::Post => {
                evaluate_post(
                    &self.route,
                    &mut bag,
                    &mut route_payload,
                    &self.pdp,
                    &invoker_dyn,
                    &delegations_dyn,
                    &elicitations_dyn,
                )
                .await
            },
        };

        // Drain Session-scoped taints (from `taint(label, session)` /
        // pipeline `Stage::Taint`) into `extensions.security.labels`
        // so the existing label-diff flow inside `persist_session`
        // picks them up. Message-scoped taints are filtered out by
        // `apply_session_taints` — they need their own destination
        // (see TS2). No-op when no taints emitted.
        invoker.apply_session_taints(&decision.taints).await;

        // Commit any session-scoped labels accumulated during this
        // request. No-op when there was no session id. The result is
        // folded into the decision below (R18) — captured here because
        // `continue_processing`/`violation` are computed after persist.
        let persist_result = invoker.persist_session().await;

        // Surface the final mutated payload + extensions back into the
        // PipelineResult the executor returns to the host. The host's
        // body re-serialization picks up edits made by APL pipelines
        // (e.g. a redact stage that rewrote args.text).
        let final_payload = invoker.current_payload().await;
        let final_extensions = invoker.current_extensions().await;

        // Detect whether the args pipeline mutated the payload by
        // re-extracting from the pre-eval message (msg_payload is
        // still borrowed) and comparing against the post-eval
        // route_payload.args. Re-extraction allocates but mirrors the
        // surrounding pattern and avoids holding a pre-eval clone.
        let pre_args = extract_args_from_message(&msg_payload.message);
        // For Post phase, also detect result mutations from `result:`
        // pipelines. Pre routes don't carry a result so this is None.
        let pre_result = match self.phase {
            Phase::Pre => None,
            Phase::Post => Some(extract_result_from_message(&msg_payload.message)),
        };
        let modified_payload: Option<Box<dyn PluginPayload>> = if route_payload.args != pre_args {
            // An args pipeline (Pre) rewrote a field. Fold the new
            // args back into a fresh MessagePayload so downstream
            // readers (the host's body re-serializer) see the
            // change.
            let mut updated = final_payload.clone();
            write_args_back_to_message(&mut updated.message, &route_payload.args);
            Some(Box::new(updated) as Box<dyn PluginPayload>)
        } else if matches!(self.phase, Phase::Post)
            && pre_result
                .as_ref()
                .zip(route_payload.result.as_ref())
                .map(|(prev, current)| prev != current)
                .unwrap_or(false)
        {
            // A `result:` pipeline rewrote a field in the upstream
            // response. Fold the new result back into the message
            // so the host's response body re-serializer can write
            // it out before forwarding downstream.
            let mut updated = final_payload.clone();
            if let Some(result_value) = route_payload.result.as_ref() {
                write_result_back_to_message(&mut updated.message, result_value);
            }
            Some(Box::new(updated) as Box<dyn PluginPayload>)
        } else if msg_payload.message.get_text_content() != final_payload.message.get_text_content()
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

        // A suspended phase reports `Allow` with a pending bundle — it
        // must NOT forward. The real JSON-RPC `-32120` retry protocol is
        // Phase 5 host/SDK work; until then, fail closed with a
        // distinguished violation that carries the elicitation id so the
        // suspend is visible and the unapproved call never proceeds.
        let pending_elicitation = decision.pending.clone();

        let (mut continue_processing, mut violation) = match decision.decision {
            Decision::Allow => (true, None),
            Decision::Deny {
                reason,
                rule_source,
            } => {
                let code = if rule_source.is_empty() {
                    "policy.deny".to_string()
                } else {
                    rule_source
                };
                let reason = reason.unwrap_or_else(|| "access denied".to_string());
                (false, Some(PluginViolation::new(code, reason)))
            },
        };

        if let Some(p) = &pending_elicitation {
            tracing::info!(
                route = %self.route.route_key,
                elicitation_id = %p.id,
                plugin = %p.plugin_name,
                "policy suspended on pending elicitation; holding request \
                 (real -32120 retry protocol pending Phase 5)"
            );
            continue_processing = false;
            violation = Some(PluginViolation::new(
                "elicitation.pending",
                format!(
                    "awaiting elicitation `{}` via `{}`",
                    p.id, p.plugin_name
                ),
            ));
        }

        // Append fail-closed (R18) with merge precedence:
        //   - decision Allow + append Err → flip to Deny with a
        //     distinguished `session.persist_failed` violation.
        //   - decision Deny + append Err → keep the original policy
        //     violation (preserve attribution); the request is already
        //     denied. The append failure surfaces only as the alarm.
        // The alarm/metric fires on every append failure regardless of
        // decision, since the dangerous residual is a *selective*
        // failure (append rejected while reads still succeed).
        if let Err(e) = persist_result {
            tracing::error!(
                alarm = "session_store_failure",
                op = "append",
                route = %self.route.route_key,
                decision_was_allow = continue_processing,
                error = %e,
                "session label persist failed; failing request closed"
            );
            if continue_processing {
                continue_processing = false;
                violation = Some(PluginViolation::new(
                    "session.persist_failed",
                    "session state could not be persisted",
                ));
            }
        }

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

/// Extract `RoutePayload.args` from a CMF message. v0 maps:
///   * First `ContentPart::ToolCall`      → `arguments` map (Object)
///   * First `ContentPart::PromptRequest` → `arguments` map (Object)
///   * Else (text / no entity parts)      → JSON String of text content
///
/// `args.<field>` APL paths target tool / prompt arguments directly.
/// For text-only messages we fall back to the v0 "args = whole text"
/// shape so `args.text` predicates keep working.
fn extract_args_from_message(msg: &cpex_core::cmf::Message) -> Value {
    use cpex_core::cmf::ContentPart;
    for part in &msg.content {
        match part {
            ContentPart::ToolCall { content } => {
                return Value::Object(
                    content
                        .arguments
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                );
            },
            ContentPart::PromptRequest { content } => {
                return Value::Object(
                    content
                        .arguments
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                );
            },
            _ => {},
        }
    }
    Value::String(msg.get_text_content())
}

/// Inverse of [`extract_args_from_message`]: write `args` back into
/// `msg`'s first ToolCall / PromptRequest argument map, or — for
/// text payloads — into the first text part.
///
/// Silently no-ops when the args shape doesn't match the message
/// content shape (e.g. operator pipeline produced a String for what
/// was originally a ToolCall). The mismatch path is recoverable —
/// the upstream just sees the original unmodified content rather
/// than a malformed rewrite.
fn write_args_back_to_message(msg: &mut cpex_core::cmf::Message, args: &Value) {
    use cpex_core::cmf::ContentPart;
    for part in msg.content.iter_mut() {
        match part {
            ContentPart::ToolCall { content } => {
                if let Some(obj) = args.as_object() {
                    content.arguments = obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                }
                return;
            },
            ContentPart::PromptRequest { content } => {
                if let Some(obj) = args.as_object() {
                    content.arguments = obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                }
                return;
            },
            _ => {},
        }
    }
    // Fall through: no structured entity part — treat as text.
    if let Some(text) = args.as_str() {
        rewrite_message_text(msg, text);
    }
}

/// Extract `RoutePayload.result` from a CMF message. Mirror of
/// [`extract_args_from_message`] for the Post phase. v0 maps:
///   * First `ContentPart::ToolResult` → its `content` JSON value
///   * Else (text / no structured result part) → JSON String of text
///
/// `result.<field>` APL paths target the structured result directly.
fn extract_result_from_message(msg: &cpex_core::cmf::Message) -> Value {
    use cpex_core::cmf::ContentPart;
    for part in &msg.content {
        if let ContentPart::ToolResult { content } = part {
            return content.content.clone();
        }
    }
    Value::String(msg.get_text_content())
}

/// Inverse of [`extract_result_from_message`]: write a mutated
/// `result` back into the message's first `ContentPart::ToolResult.content`,
/// or — for text-only messages — into the first text part. The praxis
/// filter's response-body re-serializer then lifts the new content
/// out of the ContentPart and folds it back into the JSON-RPC
/// `result.content[*].text` payload.
fn write_result_back_to_message(msg: &mut cpex_core::cmf::Message, result: &Value) {
    use cpex_core::cmf::ContentPart;
    for part in msg.content.iter_mut() {
        if let ContentPart::ToolResult { content } = part {
            content.content = result.clone();
            return;
        }
    }
    if let Some(text) = result.as_str() {
        rewrite_message_text(msg, text);
    }
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
    // `delegate(...)` steps write minted tokens into
    // `raw_credentials.delegated_tokens` via the shared Mutex —
    // without this check, a route whose only Extensions mutation is
    // a delegate (no security / delegation chain edit) looks
    // unchanged, so the executor never merges the minted token back
    // and downstream readers (our HttpFilter attaching the token to
    // the upstream request) see nothing.
    let raw_creds_changed = match (
        before.raw_credentials.as_ref(),
        after.raw_credentials.as_ref(),
    ) {
        (Some(a), Some(b)) => !Arc::ptr_eq(a, b),
        (None, None) => false,
        _ => true,
    };
    security_changed || delegation_changed || raw_creds_changed
}
