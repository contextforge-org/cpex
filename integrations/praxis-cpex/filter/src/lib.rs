// Location: ./integrations/praxis-cpex/filter/src/lib.rs
// SPDX-License-Identifier: Apache-2.0
//
// `cpex-praxis-filter` — Praxis `HttpFilter` that embeds the CPEX/APL
// runtime in-process.
//
// # Slice B scope (this revision)
//
// Identity + APL policy on MCP-aware routes.
//
// Pipeline ordering — operators put Praxis's built-in `mcp` filter
// AHEAD of `cpex` in the chain. Praxis already parses JSON-RPC bodies
// and writes `mcp.method` / `mcp.name` to `ctx.filter_metadata`; we
// just consume those values to derive `(entity_type, entity_name)`
// for CMF dispatch. We don't re-implement JSON-RPC parsing.
//
//   on_request:
//     1. Resolve identity from `Authorization` (header-only — body
//        isn't needed for this step, so we deny early on auth failure).
//
//   on_request_body (when end_of_stream):
//     2. mcp filter ran already; its metadata is in `ctx.filter_metadata`.
//     3. Re-resolve identity to build a populated `Extensions` (cheap;
//        JWT verifier hits its key cache).
//     4. If `mcp.method` matches a recognized MCP entity-method,
//        dispatch the corresponding `cmf.*_pre_invoke` hook so APL
//        routes get evaluated.
//     5. Translate CMF deny → 403; allow → Continue. Non-MCP requests
//        (no `mcp.method` metadata) skip the CMF step.
//
// We re-resolve identity in on_request_body rather than thread the
// `Extensions` from on_request — Praxis's `HttpFilterContext` only
// exposes string-keyed metadata stores, and serializing the full
// `Extensions` (subject + roles + claims + raw_credentials) through
// them would be lossy. JWT re-verification is microseconds; the
// simplification is worth it.

#![allow(clippy::module_name_repetitions)]

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;

use cpex_core::{
    cmf::{
        constants::{
            ENTITY_LLM, ENTITY_PROMPT, ENTITY_RESOURCE, ENTITY_TOOL, HOOK_CMF_LLM_INPUT,
            HOOK_CMF_LLM_OUTPUT, HOOK_CMF_PROMPT_POST_INVOKE, HOOK_CMF_PROMPT_PRE_INVOKE,
            HOOK_CMF_RESOURCE_POST_FETCH, HOOK_CMF_RESOURCE_PRE_FETCH, HOOK_CMF_TOOL_POST_INVOKE,
            HOOK_CMF_TOOL_PRE_INVOKE,
        },
        CmfHook, ContentPart, Message, MessagePayload, PromptRequest, ResourceReference,
        ResourceType, Role, ToolCall, ToolResult,
    },
    error::PluginError,
    extensions::MetaExtension,
    hooks::Extensions,
    identity::{IdentityHook, IdentityPayload, TokenSource, HOOK_IDENTITY_RESOLVE},
    manager::PluginManager,
};

use apl_audit_logger::{AuditLoggerFactory, KIND as AUDIT_LOGGER_KIND};
use apl_cpex::{register_apl, AplOptions, DispatchCache, MemorySessionStore};
use apl_delegator_oauth::{OAuthDelegatorFactory, KIND as OAUTH_DELEGATOR_KIND};
use apl_identity_jwt::{JwtIdentityFactory, KIND as JWT_KIND};
use apl_pdp_cedar_direct::CedarDirectPdpFactory;
use apl_pii_scanner::{PiiScannerFactory, KIND as PII_SCANNER_KIND};

use praxis_filter::{
    BodyAccess, BodyMode, FilterAction, FilterError, HttpFilter, HttpFilterContext, Rejection,
};

pub mod config;

pub use config::{BodyAccessMode, CpexFilterConfig};

// -----------------------------------------------------------------------------
// MCP method → entity coords
// -----------------------------------------------------------------------------

/// Recognized MCP entity-bearing methods. Maps an `mcp.method` value
/// (set by Praxis's `mcp` filter from the JSON-RPC body) to:
///   - entity_type    — feeds `MetaExtension.entity_type`
///   - cmf_hook       — `cmf.*_pre_invoke` hook name for dispatch
///
/// Methods that don't carry an entity (e.g. `tools/list`, `initialize`,
/// `prompts/list`) return `None` — for those we run identity but skip
/// CMF dispatch entirely (nothing for APL to evaluate route-wise).
fn entity_for_mcp_method(method: &str) -> Option<(&'static str, &'static str)> {
    match method {
        "tools/call" => Some((ENTITY_TOOL, HOOK_CMF_TOOL_PRE_INVOKE)),
        "prompts/get" => Some((ENTITY_PROMPT, HOOK_CMF_PROMPT_PRE_INVOKE)),
        "resources/read" => Some((ENTITY_RESOURCE, HOOK_CMF_RESOURCE_PRE_FETCH)),
        // LLM completion isn't an MCP method but we leave the variant
        // here so a future LLM-aware filter (prompt_enrich, etc.) can
        // promote a similar metadata key.
        _ => None,
    }
}

/// Post-phase mirror of [`entity_for_mcp_method`]. Maps the same MCP
/// methods to the CMF *post* hook names so `on_response_body` can
/// dispatch `cmf.tool_post_invoke` / `prompt_post_invoke` /
/// `resource_post_fetch` against an APL `result:` pipeline. The
/// method is read from `ctx.filter_metadata` (the praxis `mcp` filter
/// stashes it during the request phase, and it persists across the
/// request/response lifecycle).
fn entity_for_mcp_method_post(method: &str) -> Option<(&'static str, &'static str)> {
    match method {
        "tools/call" => Some((ENTITY_TOOL, HOOK_CMF_TOOL_POST_INVOKE)),
        "prompts/get" => Some((ENTITY_PROMPT, HOOK_CMF_PROMPT_POST_INVOKE)),
        "resources/read" => Some((ENTITY_RESOURCE, HOOK_CMF_RESOURCE_POST_FETCH)),
        _ => None,
    }
}

/// Keep the LLM-output hook name exported for the same reason the
/// pre-side LLM mapping exists — future symmetry once non-MCP LLM
/// traffic gets a post-phase hook of its own.
#[allow(dead_code)]
const _: &str = HOOK_CMF_LLM_OUTPUT;

/// LLM-flavor variant. Today unused — kept so the dispatch logic
/// reads symmetrically when we wire in OpenAI-shaped traffic.
#[allow(dead_code)]
fn entity_for_llm(present: bool) -> Option<(&'static str, &'static str)> {
    if present {
        Some((ENTITY_LLM, HOOK_CMF_LLM_INPUT))
    } else {
        None
    }
}

// -----------------------------------------------------------------------------
// CpexFilter
// -----------------------------------------------------------------------------

/// Praxis filter that runs the CPEX identity + APL policy pipeline
/// against each request. Designed to sit downstream of Praxis's
/// built-in `mcp` filter so MCP method/name are already in metadata
/// when CMF dispatch fires.
pub struct CpexFilter {
    mgr: Arc<PluginManager>,
    /// Kept for diagnostics / future config-driven knobs even though
    /// the filter no longer reads it at request time (per-credential
    /// header routing moved to the identity plugins themselves).
    #[allow(dead_code)]
    cfg: CpexFilterConfig,
}

impl CpexFilter {
    /// Construct a filter from a parsed config. Loads the CPEX YAML
    /// referenced by `cfg.config_path`, registers the bundled plugin
    /// factories + the APL config visitor, and initializes the
    /// manager. Errors abort filter chain construction at server
    /// startup — failing fast is what we want for misconfigured
    /// policy.
    pub fn new(cfg: CpexFilterConfig) -> Result<Self, FilterError> {
        let yaml = std::fs::read_to_string(&cfg.config_path).map_err(|e| -> FilterError {
            format!("cpex: failed to read config_path {}: {e}", cfg.config_path).into()
        })?;

        let mgr = Arc::new(PluginManager::default());
        register_builtin_factories(&mgr);

        // Wire the APL visitor BEFORE load_config_yaml so it walks the
        // routes and installs `AplRouteHandler` annotations on the hook
        // table. Memory session store + the PDP factories this
        // integration ships with. The visitor matches `global.apl.pdp[]`
        // YAML blocks against the factory's `kind()` — `cedar-direct`
        // for `apl-pdp-cedar-direct`, future factories for OPA /
        // Cedarling slot in here similarly.
        //
        // The baseline is the visitor's default read-only set
        // (subject, roles, claims, etc.). Per-plugin caps —
        // `read_inbound_credentials` on the OAuth delegator, etc. —
        // are declared in the plugin's YAML `capabilities:` block;
        // `route_capability_union` in apl-cpex unions those into the
        // synthetic AplRouteHandler so they actually take effect.
        // This keeps credential reads scoped to the plugin that
        // declared the need rather than leaking them to every
        // predicate / PDP / step in the same route.
        register_apl(
            &mgr,
            AplOptions {
                dispatch_cache: Arc::new(DispatchCache::new()),
                session_store: Arc::new(MemorySessionStore::new()),
                pdps: Vec::new(),
                pdp_factories: vec![Arc::new(CedarDirectPdpFactory::new())],
                base_capabilities: None,
            },
        );

        mgr.load_config_yaml(&yaml)
            .map_err(|e: Box<PluginError>| -> FilterError {
                format!("cpex: load_config_yaml failed: {e}").into()
            })?;

        // `initialize()` is async. We block on it during construction
        // because Praxis's `register_filters!` factory signature is
        // synchronous. Praxis invokes this factory before the runtime
        // is fully attached to the current thread, so we can't rely on
        // `Handle::current()` — spin up a single-threaded runtime just
        // to drive plugin init (which is local and quick: plugins
        // finish their `init` step, no I/O).
        let init_rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| -> FilterError {
                format!("cpex: failed to build init runtime: {e}").into()
            })?;
        init_rt
            .block_on(mgr.initialize())
            .map_err(|e: Box<PluginError>| -> FilterError {
                format!("cpex: PluginManager::initialize failed: {e}").into()
            })?;

        Ok(Self { mgr, cfg })
    }

    /// Praxis-side factory hook. Wired via `register_filters!`.
    pub fn from_config(value: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: CpexFilterConfig = serde_yaml::from_value(value.clone())
            .map_err(|e| -> FilterError { format!("cpex: config parse failed: {e}").into() })?;
        let filter = Self::new(cfg)?;
        Ok(Box::new(filter))
    }

    /// Snapshot the request's HTTP headers into a `HashMap<String, String>`.
    /// Identity plugins each read their own configured header from this
    /// map (user from `X-User-Token`, client from `Authorization`,
    /// workload from `X-Workload-Token`, etc.) — the host doesn't
    /// pre-extract a single token.
    ///
    /// Keys are normalized to ASCII lowercase. HTTP header names are
    /// case-insensitive (RFC 7230 §3.2) and our HashMap lookup is
    /// case-sensitive, so without normalization a plugin configured
    /// with `header: "Authorization"` would miss the request's
    /// `authorization` entry. Plugins lowercase their configured
    /// header before lookup to match.
    fn snapshot_headers(ctx: &HttpFilterContext<'_>) -> std::collections::HashMap<String, String> {
        ctx.request
            .headers
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|v| (name.as_str().to_ascii_lowercase(), v.to_string()))
            })
            .collect()
    }

    /// Build a fresh IdentityPayload from request headers — used by
    /// both on_request (early deny) and on_request_body (re-resolve
    /// to populate Extensions for CMF dispatch). Idempotent because
    /// inbound headers don't change between phases.
    ///
    /// `raw_token` is left empty: each registered identity plugin
    /// reads its own configured header from `headers`. The legacy
    /// `token_header` config knob is left in place for back-compat
    /// but not consumed by the filter — plugins specify their own
    /// header via the per-plugin `header:` config.
    fn identity_payload(&self, ctx: &HttpFilterContext<'_>) -> IdentityPayload {
        IdentityPayload::new(String::new(), TokenSource::Bearer)
            .with_headers(Self::snapshot_headers(ctx))
    }

    /// Build the Extensions to feed CMF dispatch. Re-resolves identity
    /// (cheap; JWT verifier hits its in-process key cache) and applies
    /// the resolved subject/roles/claims/raw_credentials to a fresh
    /// `Extensions`. Also stamps `MetaExtension.entity_type` /
    /// `entity_name` so route resolution can match.
    async fn build_cmf_extensions(
        &self,
        ctx: &HttpFilterContext<'_>,
        entity_type: &str,
        entity_name: &str,
    ) -> Result<Extensions, Rejection> {
        let (id_result, _bg) = self
            .mgr
            .invoke_named::<IdentityHook>(
                HOOK_IDENTITY_RESOLVE,
                self.identity_payload(ctx),
                Extensions::default(),
                None,
            )
            .await;
        if !id_result.continue_processing {
            return Err(auth_rejection(id_result.violation.as_ref()));
        }

        let identity = IdentityPayload::from_pipeline_result(&id_result)
            .ok_or_else(|| Rejection::status(500).with_body(
                Bytes::from_static(b"cpex: identity result missing modified payload"),
            ))?;
        let mut ext = identity.apply_to_extensions(Extensions::default());

        // Stamp entity_type / entity_name so the route resolver in
        // cpex-core's filter_entries_by_route picks the right
        // route annotation.
        let mut meta = ext
            .meta
            .as_ref()
            .map(|arc| (**arc).clone())
            .unwrap_or_else(MetaExtension::default);
        meta.entity_type = Some(entity_type.to_string());
        meta.entity_name = Some(entity_name.to_string());
        ext.meta = Some(Arc::new(meta));

        Ok(ext)
    }
}

#[async_trait]
impl HttpFilter for CpexFilter {
    fn name(&self) -> &'static str {
        "cpex"
    }

    fn request_body_access(&self) -> BodyAccess {
        // ReadOnly is the minimum that gets us into `on_request_body`
        // (we need the body phase to fire so we can dispatch CMF
        // after the `mcp` filter populates its metadata). Operators
        // opt into `ReadWrite` via `body_access: read_write` when
        // they want APL field mutators (`redact()` / `assign()` on
        // `args.<field>`) to rewrite the upstream body. Chain-level
        // scoping keeps non-CPEX traffic out of this filter so the
        // buffering cost is bounded either way.
        match self.cfg.body_access {
            BodyAccessMode::ReadOnly => BodyAccess::ReadOnly,
            BodyAccessMode::ReadWrite => BodyAccess::ReadWrite,
        }
    }

    fn request_body_mode(&self) -> BodyMode {
        // In ReadWrite mode we MUST buffer the whole body before the
        // filter runs — otherwise Praxis would stream chunks upstream
        // as they arrive, and a body rewrite at end-of-stream would
        // race against an already-finished upstream write. StreamBuffer
        // accumulates chunks, calls our filter exactly once at EOS with
        // the full body, and forwards whatever we put back into `body`.
        // ReadOnly inherits the default `Stream`: we don't need to
        // mutate, so streaming chunk-by-chunk is fine.
        match self.cfg.body_access {
            BodyAccessMode::ReadOnly => BodyMode::Stream,
            BodyAccessMode::ReadWrite => BodyMode::StreamBuffer { max_bytes: None },
        }
    }

    fn response_body_access(&self) -> BodyAccess {
        // Mirror of `request_body_access` — needed so APL `result:`
        // pipelines (post-phase) can rewrite the upstream's response
        // body before it flows back to the client. A route's
        // `result: { ssn: "redact(!perm.view_ssn)" }` only takes
        // effect when this is at least ReadOnly; ReadWrite enables
        // the actual re-serialization step.
        match self.cfg.body_access {
            BodyAccessMode::ReadOnly => BodyAccess::ReadOnly,
            BodyAccessMode::ReadWrite => BodyAccess::ReadWrite,
        }
    }

    fn response_body_mode(&self) -> BodyMode {
        // Same rationale as `request_body_mode`: in ReadWrite mode we
        // need the full response body assembled before we run the
        // post-phase hook so any field rewrites land before Pingora
        // writes the bytes downstream.
        match self.cfg.body_access {
            BodyAccessMode::ReadOnly => BodyMode::Stream,
            BodyAccessMode::ReadWrite => BodyMode::StreamBuffer { max_bytes: None },
        }
    }

    async fn on_request(
        &self,
        ctx: &mut HttpFilterContext<'_>,
    ) -> Result<FilterAction, FilterError> {
        // Early identity gate. Saves the per-request body-buffer cost
        // on un-auth'd traffic — if there's no valid token, we never
        // reach `on_request_body` and the body never gets buffered.
        let (result, _bg) = self
            .mgr
            .invoke_named::<IdentityHook>(
                HOOK_IDENTITY_RESOLVE,
                self.identity_payload(ctx),
                Extensions::default(),
                None,
            )
            .await;

        if !result.continue_processing {
            let rej = auth_rejection(result.violation.as_ref());
            tracing::debug!(target: "cpex.filter", "identity deny (on_request)");
            return Ok(FilterAction::Reject(rej));
        }

        tracing::trace!(target: "cpex.filter", "identity allow (on_request)");
        Ok(FilterAction::Continue)
    }

    async fn on_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        // CMF dispatch only fires once the full body has been seen
        // (so Praxis's `mcp` filter has finished parsing and writing
        // its metadata). For streaming chunks we just pass.
        if !end_of_stream {
            return Ok(FilterAction::Continue);
        }

        // Pull MCP-derived entity coords from durable filter_metadata.
        // If the operator hasn't wired `mcp` upstream of us, or the
        // request isn't an entity-bearing MCP method, we have nothing
        // to dispatch and just allow.
        let method = match ctx.get_metadata("mcp.method") {
            Some(m) => m.to_string(),
            None => {
                tracing::trace!(target: "cpex.filter", "no mcp.method in metadata; no CMF dispatch");
                return Ok(FilterAction::BodyDone);
            }
        };
        let Some((entity_type, hook_name)) = entity_for_mcp_method(&method) else {
            tracing::trace!(
                target: "cpex.filter",
                mcp_method = %method,
                "MCP method has no entity binding; no CMF dispatch",
            );
            return Ok(FilterAction::BodyDone);
        };
        let entity_name = match ctx.get_metadata("mcp.name") {
            Some(n) => n.to_string(),
            None => {
                // The mcp filter rejects selector-bearing methods
                // without a name when configured to do so; if we get
                // here, it means mcp.on_invalid was set to Continue.
                // Without an entity name, route resolution can't pick
                // a route — skip CMF and let the request flow.
                tracing::debug!(
                    target: "cpex.filter",
                    mcp_method = %method,
                    "MCP method missing mcp.name metadata; skipping CMF dispatch",
                );
                return Ok(FilterAction::BodyDone);
            }
        };

        // Build Extensions with re-resolved identity + entity coords.
        let extensions = match self.build_cmf_extensions(ctx, entity_type, &entity_name).await {
            Ok(ext) => ext,
            Err(rej) => return Ok(FilterAction::Reject(rej)),
        };

        // Parse the JSON-RPC body to build the typed CMF content
        // part. Yes, Praxis's `mcp` filter already parsed once — but
        // it only stashes method/name in `filter_metadata`, not the
        // `params.arguments` object that APL `args.*` predicates need
        // to evaluate against. We re-parse here to fill the message
        // properly. The body is already in memory; the duplicate
        // parse is microseconds.
        let body_bytes = body.as_ref().cloned().unwrap_or_else(Bytes::new);
        let id = json_rpc_id(&body_bytes);
        let content = build_content_for_method(&method, &entity_name, &id, &body_bytes);

        // Dispatch the appropriate CMF hook. The route annotation
        // (installed by the APL visitor at config-load time) drives
        // the actual policy evaluation; if no APL route matches, the
        // hook is a no-op.
        let payload = MessagePayload {
            // `Message::with_content` sets the schema version
            // internally from cpex-core's `SCHEMA_VERSION` const, so
            // the integration never hardcodes a wire-format version.
            message: Message::with_content(Role::User, content),
        };
        let (cmf_result, _bg) = self
            .mgr
            .invoke_named::<CmfHook>(hook_name, payload, extensions, None)
            .await;

        if !cmf_result.continue_processing {
            let request_id = json_rpc_id_value(&body_bytes);
            let rej = mcp_error_rejection(cmf_result.violation.as_ref(), request_id);
            tracing::debug!(
                target: "cpex.filter",
                hook = %hook_name,
                entity = %entity_name,
                "CMF deny",
            );
            return Ok(FilterAction::Reject(rej));
        }

        // Allow path. If APL `delegate(...)` steps minted any outbound
        // tokens, the delegators wrote them into
        // `modified_extensions.raw_credentials.delegated_tokens`.
        // Attach each one to the upstream request as the configured
        // header so downstream services see "fresh" credentials.
        let attached = attach_delegated_tokens(ctx, cmf_result.modified_extensions.as_ref());
        if attached > 0 {
            tracing::debug!(
                target: "cpex.filter",
                count = attached,
                "attached delegated tokens to upstream request",
            );
        }

        // If body_access is ReadWrite AND APL mutated the payload
        // (a `redact(args.X)` / `assign(args.X, ...)` step fired),
        // re-serialize the mutated MessagePayload back into the
        // JSON-RPC body so the upstream service receives the
        // rewritten args. In ReadOnly mode this is a no-op — the
        // executor already discarded the mutation at its merge
        // boundary, so there's nothing here to rewrite anyway.
        if matches!(self.cfg.body_access, BodyAccessMode::ReadWrite) {
            if let Some(mp) = cmf_result.modified_payload.as_ref() {
                if let Some(updated) = mp.as_any().downcast_ref::<MessagePayload>() {
                    let original = body.as_ref().cloned().unwrap_or_else(Bytes::new);
                    if let Some(new_bytes) =
                        reserialize_json_rpc_body(&original, &method, &updated.message)
                    {
                        // Praxis exposes header mutations only from the
                        // request phase, and Transfer-Encoding is stripped
                        // as hop-by-hop on the upstream hop. That means
                        // the inbound `Content-Length` is what governs
                        // upstream body length — if the rewrite shrinks
                        // the body, pad with trailing ASCII spaces
                        // (which every JSON parser ignores) so the wire
                        // length still matches Content-Length. Rewrites
                        // that grow the body are not supported in this
                        // mode; the cmf executor's mutators (`redact()`)
                        // either shrink or are length-neutral today.
                        let final_bytes = match new_bytes.len().cmp(&original.len()) {
                            std::cmp::Ordering::Less => {
                                let mut padded =
                                    Vec::with_capacity(original.len());
                                padded.extend_from_slice(&new_bytes);
                                padded.resize(original.len(), b' ');
                                Bytes::from(padded)
                            }
                            std::cmp::Ordering::Equal => new_bytes,
                            std::cmp::Ordering::Greater => {
                                tracing::warn!(
                                    target: "cpex.filter",
                                    method = %method,
                                    new_len = new_bytes.len(),
                                    original_len = original.len(),
                                    "rewritten body is larger than original; sending without pad — upstream may see truncation",
                                );
                                new_bytes
                            }
                        };
                        tracing::debug!(
                            target: "cpex.filter",
                            method = %method,
                            new_len = final_bytes.len(),
                            original_len = original.len(),
                            "rewriting upstream body from mutated MessagePayload",
                        );
                        *body = Some(final_bytes);
                    }
                }
            }
        }

        tracing::trace!(
            target: "cpex.filter",
            hook = %hook_name,
            entity = %entity_name,
            "CMF allow",
        );
        Ok(FilterAction::BodyDone)
    }

    fn on_response_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        // Wait for the full upstream response — `response_body_mode =
        // StreamBuffer` guarantees we'll see it materialized here.
        if !end_of_stream {
            return Ok(FilterAction::Continue);
        }
        // No point doing anything if the operator hasn't opted into
        // response rewriting. (In ReadOnly mode we still get called,
        // but every mutation would be discarded by Praxis anyway.)
        if !matches!(self.cfg.body_access, BodyAccessMode::ReadWrite) {
            return Ok(FilterAction::Continue);
        }

        // The mcp filter stashes method/name during the request phase
        // and praxis preserves filter_metadata across phases, so we
        // can route the post-phase hook without re-parsing the body.
        let method = match ctx.get_metadata("mcp.method") {
            Some(m) => m.to_string(),
            None => return Ok(FilterAction::Continue),
        };
        let Some((entity_type, hook_name)) = entity_for_mcp_method_post(&method) else {
            return Ok(FilterAction::Continue);
        };
        let entity_name = match ctx.get_metadata("mcp.name") {
            Some(n) => n.to_string(),
            None => return Ok(FilterAction::Continue),
        };

        // praxis's filter trait makes `on_response_body` sync — Pingora's
        // response_body callback can't be awaited. We're on a tokio
        // worker (Pingora is multi-thread), so `block_in_place` lets
        // us drive the async CMF dispatch without stalling other tasks.
        let mgr = Arc::clone(&self.mgr);
        let cfg_body_access = self.cfg.body_access;
        let body_bytes = body.as_ref().cloned().unwrap_or_else(Bytes::new);
        let id_str = json_rpc_id(&body_bytes);

        // Re-resolve identity from the still-present request headers
        // so the post-phase pipeline sees the same `subject.*` /
        // `role.*` / `perm.*` shape the pre-phase did.
        let extensions = match tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.build_cmf_extensions(ctx, entity_type, &entity_name)
                    .await
            })
        }) {
            Ok(e) => e,
            Err(_rej) => {
                tracing::debug!(
                    target: "cpex.filter",
                    "post-phase identity rebuild failed; skipping response rewrite",
                );
                return Ok(FilterAction::Continue);
            }
        };

        let content =
            build_response_content_for_method(&method, &entity_name, &id_str, &body_bytes);
        if content.is_empty() {
            return Ok(FilterAction::Continue);
        }
        let payload = MessagePayload {
            message: Message::with_content(Role::Assistant, content),
        };

        let cmf_result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let (r, _bg) = mgr
                    .invoke_named::<CmfHook>(hook_name, payload, extensions, None)
                    .await;
                r
            })
        });

        // A post-phase deny is unusual but plausible (an operator may
        // want to refuse a response on principle — e.g. "the upstream
        // returned PII that's still labelled internal"). For v0 we log
        // it; replacing the response stream with a synthetic error
        // envelope here would require rewriting the upstream's headers
        // too, which praxis doesn't expose from `on_response_body`.
        if !cmf_result.continue_processing {
            tracing::warn!(
                target: "cpex.filter",
                method = %method,
                entity = %entity_name,
                violation = ?cmf_result.violation,
                "post-phase deny — surfaced as a log; the response body still flows downstream",
            );
            return Ok(FilterAction::Continue);
        }

        if let Some(mp) = cmf_result.modified_payload.as_ref() {
            if let Some(updated) = mp.as_any().downcast_ref::<MessagePayload>() {
                let original = body.as_ref().cloned().unwrap_or_else(Bytes::new);
                if let Some(new_bytes) =
                    reserialize_json_rpc_response_body(&original, &method, &updated.message)
                {
                    // Same pad-with-spaces workaround as the request
                    // body — praxis won't let us update Content-Length
                    // from the body phase. JSON parsers ignore trailing
                    // whitespace, so the response stays well-formed
                    // even with the trailing pad.
                    let final_bytes = match new_bytes.len().cmp(&original.len()) {
                        std::cmp::Ordering::Less => {
                            let mut padded = Vec::with_capacity(original.len());
                            padded.extend_from_slice(&new_bytes);
                            padded.resize(original.len(), b' ');
                            Bytes::from(padded)
                        }
                        std::cmp::Ordering::Equal => new_bytes,
                        std::cmp::Ordering::Greater => {
                            tracing::warn!(
                                target: "cpex.filter",
                                method = %method,
                                new_len = new_bytes.len(),
                                original_len = original.len(),
                                "rewritten response body is larger than original; sending without pad — client may see truncation",
                            );
                            new_bytes
                        }
                    };
                    tracing::debug!(
                        target: "cpex.filter",
                        method = %method,
                        new_len = final_bytes.len(),
                        original_len = original.len(),
                        "rewriting downstream response body from mutated MessagePayload",
                    );
                    *body = Some(final_bytes);
                }
            }
        }
        // Suppress the unused-binding warning for ReadOnly mode where
        // the body_access check above short-circuits before we get here.
        let _ = cfg_body_access;
        Ok(FilterAction::Continue)
    }
}

/// Walk the minted delegated tokens on the resolved Extensions and
/// push them as upstream request headers. Returns the count attached
/// (0 when no delegation ran or no extensions were returned). Each
/// token's `outbound_header` field decides where it goes; the value
/// is `Bearer <token>` (RFC 6750 wire format — what every audience
/// expects). Uses `request_headers_to_set` rather than
/// `extra_request_headers` because authorization tokens are
/// overwrites, not appends.
fn attach_delegated_tokens(
    ctx: &mut HttpFilterContext<'_>,
    extensions: Option<&Extensions>,
) -> usize {
    let Some(ext) = extensions else { return 0; };
    let Some(raw) = ext.raw_credentials.as_ref() else { return 0; };

    // Pass 1: attach each minted token to its configured outbound
    // header. The delegator's plugin config (`default_outbound_header`)
    // sets this; per-token routing is preserved on `outbound_header`
    // so different delegators can target different downstream headers.
    let mut attached_outbound: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    let mut count = 0;
    for tok in raw.delegated_tokens.values() {
        let name = match http::header::HeaderName::try_from(tok.outbound_header.as_str()) {
            Ok(n) => n,
            Err(_) => {
                tracing::warn!(
                    target: "cpex.filter",
                    header = %tok.outbound_header,
                    "delegated token outbound_header is not a valid HTTP header name; skipping"
                );
                continue;
            }
        };
        let value = match http::header::HeaderValue::try_from(
            format!("Bearer {}", tok.token.as_str()),
        ) {
            Ok(v) => v,
            Err(_) => {
                tracing::warn!(
                    target: "cpex.filter",
                    audience = %tok.audience,
                    "minted token bytes are not a valid HTTP header value; skipping"
                );
                continue;
            }
        };
        attached_outbound.insert(tok.outbound_header.to_ascii_lowercase());
        ctx.request_headers_to_set.push((name, value));
        count += 1;
    }

    // Pass 2: strip the inbound credential headers — but only when
    // we actually attached delegated tokens, and only headers that
    // are NOT also being set by an outbound (collision case —
    // `request_headers_to_set` overwrites, no remove needed).
    //
    // Rationale: each identity resolver records its `source_header`
    // on `RawInboundToken.source_header` so forwarding plugins can
    // make informed decisions. When delegation is in play the
    // operator's intent is "rewrite credentials for the downstream"
    // — leaving the inbound JWT in the upstream request would leak
    // the user's IdP token alongside the audience-scoped token we
    // just minted. When no delegation ran, we leave the inbound
    // untouched (pass-through proxy mode — operator can compose
    // Praxis's stock filters if they want explicit stripping).
    if count > 0 {
        for inbound in raw.inbound_tokens.values() {
            let normalized = inbound.source_header.to_ascii_lowercase();
            if attached_outbound.contains(&normalized) {
                // Outbound at the same header name → set overwrites.
                continue;
            }
            match http::header::HeaderName::try_from(inbound.source_header.as_str()) {
                Ok(n) => ctx.request_headers_to_remove.push(n),
                Err(_) => tracing::warn!(
                    target: "cpex.filter",
                    header = %inbound.source_header,
                    "inbound source_header is not a valid HTTP header name; cannot strip"
                ),
            }
        }
    }

    count
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// JSON-RPC error code for gateway-side denials. Lives in the
/// implementation-defined `-32000` to `-32099` range carved out by the
/// JSON-RPC 2.0 spec for server errors. One code covers all of
/// `apl.policy`, `cedar.*`, `pii.*`, `delegation.*`, etc. — the
/// specific violation goes in `data.violation` so MCP clients can
/// switch on a single code while still seeing the underlying reason.
const MCP_GATEWAY_DENIED_CODE: i64 = -32001;

/// Build an HTTP 401 rejection for transport-level auth failures
/// (missing / invalid / wrong-audience JWT). Per MCP's Authorization
/// spec, these MUST be HTTP 401 + `WWW-Authenticate`. The body is a
/// short human-readable string — MCP clients are expected to react to
/// the status + header, not parse the body.
///
/// TODO: once the gateway exposes its own OAuth Protected Resource
/// Metadata document, the `WWW-Authenticate` value should point to it
/// per RFC 9728 (`Bearer resource_metadata="..."`). Today we send the
/// minimum-compliant header.
fn auth_rejection(violation: Option<&cpex_core::error::PluginViolation>) -> Rejection {
    let (code, reason) = match violation {
        Some(v) => (v.code.clone(), v.reason.clone()),
        None => (
            "auth.unknown".to_string(),
            "authentication required".to_string(),
        ),
    };
    let body = format!("{code}: {reason}");
    Rejection::status(401)
        .with_header("WWW-Authenticate", "Bearer")
        .with_header("X-Cpex-Violation", code)
        .with_body(body.into_bytes())
}

/// Build an MCP-compliant JSON-RPC error envelope for application-level
/// denials (policy / PDP / PII / delegation failure / internal errors)
/// that the gateway catches BEFORE the upstream tool runs.
///
/// Per MCP's Tools spec ("Error Handling"), these are *protocol errors*
/// reported via JSON-RPC error envelopes inside an HTTP 200 response,
/// not HTTP 4xx, so that MCP clients can correlate the failure to the
/// original request `id` and surface the violation through their
/// normal error UI.
///
/// Shape (matches the JSON-RPC 2.0 schema referenced by MCP):
///
/// ```json
/// {
///   "jsonrpc": "2.0",
///   "id": <request id, preserving original type>,
///   "error": {
///     "code": -32001,
///     "message": "<human reason from the violation>",
///     "data": { "violation": "<violation code>" }
///   }
/// }
/// ```
fn mcp_error_rejection(
    violation: Option<&cpex_core::error::PluginViolation>,
    request_id: serde_json::Value,
) -> Rejection {
    let (violation_code, reason) = match violation {
        Some(v) => (v.code.clone(), v.reason.clone()),
        None => (
            "gateway.unknown".to_string(),
            "denied by gateway".to_string(),
        ),
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": MCP_GATEWAY_DENIED_CODE,
            "message": reason,
            "data": { "violation": violation_code },
        }
    });
    let bytes = serde_json::to_vec(&body).unwrap_or_default();
    Rejection::status(200)
        .with_header("Content-Type", "application/json")
        .with_header("X-Cpex-Violation", violation_code)
        .with_body(bytes)
}

/// Register the plugin factories this integration ships with:
///
///   * `identity/jwt`      — apl-identity-jwt (JWT identity resolver)
///   * `delegator/oauth`   — apl-delegator-oauth (RFC 8693 token exchange)
///   * `validator/pii-scan` — apl-pii-scanner (regex-based PII detection)
///   * `audit/logger`      — apl-audit-logger (structured audit emission)
///
/// PDP factories (cedar-direct) wire via `AplOptions.pdp_factories` in
/// `CpexFilter::new` rather than this function — different registration
/// surface (PdpFactory vs PluginFactory).
fn register_builtin_factories(mgr: &Arc<PluginManager>) {
    mgr.register_factory(JWT_KIND, Box::new(JwtIdentityFactory));
    mgr.register_factory(OAUTH_DELEGATOR_KIND, Box::new(OAuthDelegatorFactory));
    mgr.register_factory(PII_SCANNER_KIND, Box::new(PiiScannerFactory));
    mgr.register_factory(AUDIT_LOGGER_KIND, Box::new(AuditLoggerFactory));
}

// -----------------------------------------------------------------------------
// JSON-RPC body parsing
// -----------------------------------------------------------------------------

/// Read the JSON-RPC `id` field as a string for use as a CMF
/// correlation ID. JSON-RPC permits string or numeric ids; we
/// stringify either to a single canonical key. Returns an empty
/// string when the body is missing or malformed — the correlation
/// ID isn't load-bearing for policy, only for audit linkage.
fn json_rpc_id(body: &Bytes) -> String {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("id").cloned())
        .map(|id| match id {
            serde_json::Value::String(s) => s,
            other => other.to_string(),
        })
        .unwrap_or_default()
}

/// Typed companion to `json_rpc_id`. Returns the raw `id` JSON value
/// from the request body — preserves the original shape (string or
/// number) so an MCP error envelope echoes back exactly what the
/// client sent. Returns `Value::Null` when the body is missing or
/// malformed; per JSON-RPC 2.0, an error response MAY use `null` when
/// the original id could not be determined.
fn json_rpc_id_value(body: &Bytes) -> serde_json::Value {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("id").cloned())
        .unwrap_or(serde_json::Value::Null)
}

/// Re-serialize a JSON-RPC request body, replacing only the fields
/// APL mutated in the typed `MessagePayload`. Returns `Some(new_bytes)`
/// when the body changed, `None` when nothing needed rewriting (no
/// matching content part, malformed original, etc.).
///
/// Touched fields by MCP method:
///   * `tools/call`     → `params.arguments` (from the first
///                        `ContentPart::ToolCall.arguments`)
///   * `prompts/get`    → `params.arguments` (from the first
///                        `ContentPart::PromptRequest.arguments`)
///   * `resources/read` → `params.uri` (from
///                        `ContentPart::ResourceRef.uri`)
///
/// All other JSON-RPC envelope fields (`jsonrpc`, `id`, `method`,
/// `params.name`) pass through unchanged. This minimizes the
/// blast radius of the rewrite — operators relying on a byte-stable
/// envelope (signature validation, content-hash matching) only see
/// changes when APL actually mutated.
fn reserialize_json_rpc_body(
    original: &Bytes,
    method: &str,
    message: &Message,
) -> Option<Bytes> {
    let mut envelope: serde_json::Value = serde_json::from_slice(original).ok()?;
    let params = envelope.get_mut("params")?;
    let params_obj = params.as_object_mut()?;

    match method {
        "tools/call" | "prompts/get" => {
            // Find the first ToolCall / PromptRequest in the message
            // and lift its `arguments` back into `params.arguments`.
            for part in &message.content {
                let new_args = match part {
                    ContentPart::ToolCall { content } if method == "tools/call" => {
                        Some(&content.arguments)
                    }
                    ContentPart::PromptRequest { content } if method == "prompts/get" => {
                        Some(&content.arguments)
                    }
                    _ => None,
                };
                if let Some(args) = new_args {
                    let new_args_value: serde_json::Value = args
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect::<serde_json::Map<_, _>>()
                        .into();
                    params_obj.insert("arguments".to_string(), new_args_value);
                    return Some(Bytes::from(serde_json::to_vec(&envelope).ok()?));
                }
            }
            None
        }
        "resources/read" => {
            for part in &message.content {
                if let ContentPart::ResourceRef { content } = part {
                    params_obj.insert(
                        "uri".to_string(),
                        serde_json::Value::String(content.uri.clone()),
                    );
                    return Some(Bytes::from(serde_json::to_vec(&envelope).ok()?));
                }
            }
            None
        }
        _ => None,
    }
}

/// Build the typed CMF `ContentPart` list for an MCP method. Parses
/// `params` out of the JSON-RPC body so APL `args.*` / `prompt.args.*`
/// / `resource.*` predicates have something to evaluate against. On
/// malformed or absent body we fall back to an empty content list —
/// the caller can still dispatch CMF (entity coords drive routing),
/// just without typed args available to predicates.
fn build_content_for_method(
    method: &str,
    entity_name: &str,
    correlation_id: &str,
    body: &Bytes,
) -> Vec<ContentPart> {
    let params: serde_json::Value = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("params").cloned())
        .unwrap_or(serde_json::Value::Null);

    match method {
        "tools/call" => {
            let arguments = params
                .get("arguments")
                .and_then(|v| v.as_object())
                .map(|m| {
                    m.iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect()
                })
                .unwrap_or_default();
            vec![ContentPart::ToolCall {
                content: ToolCall {
                    tool_call_id: correlation_id.to_string(),
                    name: entity_name.to_string(),
                    arguments,
                    namespace: None,
                },
            }]
        }
        "prompts/get" => {
            let arguments = params
                .get("arguments")
                .and_then(|v| v.as_object())
                .map(|m| {
                    m.iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect()
                })
                .unwrap_or_default();
            vec![ContentPart::PromptRequest {
                content: PromptRequest {
                    prompt_request_id: correlation_id.to_string(),
                    name: entity_name.to_string(),
                    arguments,
                    server_id: None,
                },
            }]
        }
        "resources/read" => {
            // For resources/read, `params.uri` is the resource
            // identifier; `mcp.name` in metadata is set to the same
            // URI by Praxis's mcp filter (it treats `uri` as the
            // "selector"). Carry it through as the ResourceReference.
            let uri = params
                .get("uri")
                .and_then(|v| v.as_str())
                .unwrap_or(entity_name)
                .to_string();
            vec![ContentPart::ResourceRef {
                content: ResourceReference {
                    resource_request_id: correlation_id.to_string(),
                    uri,
                    name: None,
                    resource_type: ResourceType::Uri,
                    range_start: None,
                    range_end: None,
                    selector: None,
                },
            }]
        }
        _ => Vec::new(),
    }
}

/// Build the typed CMF `ContentPart` list from a JSON-RPC *response*
/// body — the post-phase mirror of [`build_content_for_method`]. Today
/// only `tools/call` produces a structured ToolResult; prompts/get
/// and resources/read return TBD shapes the filter can extend later.
///
/// The actual tool data lives in MCP's `result.content[].text` (a
/// JSON-stringified payload, per the MCP Tools spec) and/or
/// `result.structuredContent` (newer 2025-06-18 shape). We try
/// `structuredContent` first; on miss, parse the first text block's
/// contents as JSON; on parse-miss, wrap the raw text as
/// `{ "text": "<raw>" }` so APL `result.text` predicates still resolve.
fn build_response_content_for_method(
    method: &str,
    entity_name: &str,
    correlation_id: &str,
    body: &Bytes,
) -> Vec<ContentPart> {
    if method != "tools/call" {
        return Vec::new();
    }
    let envelope: serde_json::Value =
        match serde_json::from_slice::<serde_json::Value>(body) {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };
    let result = match envelope.get("result") {
        Some(r) => r,
        None => return Vec::new(),
    };
    let is_error = result
        .get("isError")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Prefer structuredContent (MCP 2025-06-18 typed-result path).
    let content_value = if let Some(structured) = result.get("structuredContent") {
        structured.clone()
    } else {
        // Fall back to result.content[0].text and parse it as JSON.
        result
            .get("content")
            .and_then(|c| c.as_array())
            .and_then(|arr| arr.iter().find(|b| {
                b.get("type").and_then(|t| t.as_str()) == Some("text")
            }))
            .and_then(|block| block.get("text").and_then(|t| t.as_str()))
            .map(|s| {
                serde_json::from_str::<serde_json::Value>(s)
                    .unwrap_or_else(|_| serde_json::json!({ "text": s }))
            })
            .unwrap_or(serde_json::Value::Null)
    };

    vec![ContentPart::ToolResult {
        content: ToolResult {
            tool_call_id: correlation_id.to_string(),
            tool_name: entity_name.to_string(),
            content: content_value,
            is_error,
        },
    }]
}

/// Re-serialize a JSON-RPC response body, replacing only the fields
/// the post-phase APL pipeline mutated. Mirror of
/// [`reserialize_json_rpc_body`] for the response side.
///
/// Writes the mutated `ContentPart::ToolResult.content` back into BOTH
/// `result.content[0].text` (as a JSON-stringified payload — the legacy
/// MCP shape every client supports) AND `result.structuredContent`
/// (the typed shape; only set if the original response had it). This
/// keeps unstructured + structured consumers in sync.
fn reserialize_json_rpc_response_body(
    original: &Bytes,
    method: &str,
    message: &Message,
) -> Option<Bytes> {
    if method != "tools/call" {
        return None;
    }
    let mut envelope: serde_json::Value = serde_json::from_slice(original).ok()?;
    let result = envelope.get_mut("result")?;
    let result_obj = result.as_object_mut()?;

    let new_content = message.content.iter().find_map(|part| match part {
        ContentPart::ToolResult { content } => Some(content.content.clone()),
        _ => None,
    })?;

    // Always rewrite the text block. This is the load-bearing path
    // for every MCP client we see today.
    if let Some(content_arr) = result_obj
        .get_mut("content")
        .and_then(|c| c.as_array_mut())
    {
        for block in content_arr.iter_mut() {
            if block.get("type").and_then(|t| t.as_str()) == Some("text") {
                if let Some(obj) = block.as_object_mut() {
                    let serialized = serde_json::to_string_pretty(&new_content)
                        .unwrap_or_else(|_| new_content.to_string());
                    obj.insert(
                        "text".to_string(),
                        serde_json::Value::String(serialized),
                    );
                    break;
                }
            }
        }
    }
    // Also update structuredContent if it was there to begin with —
    // don't introduce it on a response that didn't have it (would
    // surprise clients sniffing for the new shape).
    if result_obj.contains_key("structuredContent") {
        result_obj.insert("structuredContent".to_string(), new_content);
    }

    Some(Bytes::from(serde_json::to_vec(&envelope).ok()?))
}

#[cfg(test)]
mod content_tests {
    use super::*;

    #[test]
    fn tools_call_carries_args_through() {
        let body = Bytes::from_static(
            br#"{"jsonrpc":"2.0","id":"42","method":"tools/call",
                 "params":{"name":"get_compensation","arguments":{"employee_id":"E001"}}}"#,
        );
        let id = json_rpc_id(&body);
        assert_eq!(id, "42");
        let parts = build_content_for_method("tools/call", "get_compensation", &id, &body);
        assert_eq!(parts.len(), 1);
        match &parts[0] {
            ContentPart::ToolCall { content } => {
                assert_eq!(content.name, "get_compensation");
                assert_eq!(content.tool_call_id, "42");
                assert_eq!(
                    content.arguments.get("employee_id").unwrap(),
                    &serde_json::Value::String("E001".to_string())
                );
            }
            other => panic!("expected ToolCall, got {other:?}"),
        }
    }

    #[test]
    fn prompts_get_carries_args() {
        let body = Bytes::from_static(
            br#"{"jsonrpc":"2.0","id":1,"method":"prompts/get",
                 "params":{"name":"weather-report","arguments":{"city":"SF"}}}"#,
        );
        let id = json_rpc_id(&body);
        let parts = build_content_for_method("prompts/get", "weather-report", &id, &body);
        match &parts[0] {
            ContentPart::PromptRequest { content } => {
                assert_eq!(content.name, "weather-report");
                assert_eq!(
                    content.arguments.get("city").unwrap(),
                    &serde_json::Value::String("SF".to_string())
                );
            }
            other => panic!("expected PromptRequest, got {other:?}"),
        }
    }

    #[test]
    fn resources_read_carries_uri() {
        let body = Bytes::from_static(
            br#"{"jsonrpc":"2.0","id":1,"method":"resources/read",
                 "params":{"uri":"file:///etc/hosts"}}"#,
        );
        let id = json_rpc_id(&body);
        let parts = build_content_for_method("resources/read", "file:///etc/hosts", &id, &body);
        match &parts[0] {
            ContentPart::ResourceRef { content } => {
                assert_eq!(content.uri, "file:///etc/hosts");
            }
            other => panic!("expected ResourceRef, got {other:?}"),
        }
    }

    #[test]
    fn malformed_body_yields_empty_content() {
        let body = Bytes::from_static(b"not json");
        let id = json_rpc_id(&body);
        let parts = build_content_for_method("tools/call", "x", &id, &body);
        // Malformed body → arguments default to empty map; ToolCall
        // still constructed so route resolution works.
        match &parts[0] {
            ContentPart::ToolCall { content } => {
                assert!(content.arguments.is_empty());
            }
            other => panic!("expected ToolCall, got {other:?}"),
        }
    }
}
