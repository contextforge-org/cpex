// Location: ./examples/tutorial/src/mediate.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// `mediate()`, the tutorial's one-call wrapper around the enforcement
// loop a CPEX host owns.
//
// ┌──────────────────────────────────────────────────────────────────┐
// │ NO MAGIC. This is HARNESS code, not a CPEX API.                    │
// │                                                                    │
// │ CPEX deliberately has no "mediate this tool call for me" function: │
// │ CPEX is a library you embed at an enforcement point (a gateway, an │
// │ MCP server, an agent framework), and *your host* owns the loop of  │
// │ resolving identity, running policy, calling the backend, and       │
// │ running policy again on the result. This file is that loop, ~1     │
// │ screen of code, written once so the tutorial modules can focus on  │
// │ POLICY instead of re-typing it every time.                         │
// │                                                                    │
// │ Module 9 re-derives this loop hook-by-hook when we teach the       │
// │ dispatch API directly. Until then, read `mediate` below once and   │
// │ trust it.                                                          │
// └──────────────────────────────────────────────────────────────────┘
//
// The real dispatch surface it wraps:
//   1. `invoke_named::<IdentityHook>("identity.resolve", ...)` resolves a
//      token into a subject (id, roles, permissions). Skipped when the
//      caller is anonymous.
//   2. `invoke_named::<CmfHook>("cmf.tool_pre_invoke", ...)` runs the APL
//      Pre phase: `args` validation + `authorization.pre_invocation`.
//   3. the host calls the backend itself.
//   4. `invoke_named::<CmfHook>("cmf.tool_post_invoke", ...)` runs the APL
//      Post phase: the `result:` field pipeline (redact/mask) +
//      `authorization.post_invocation`.

use std::sync::Arc;

use serde_json::{Map, Value};

use cpex::PluginManager;
use cpex_core::cmf::content::{ToolCall, ToolResult};
use cpex_core::cmf::enums::Role;
use cpex_core::cmf::{CmfHook, ContentPart, Message, MessagePayload};
use cpex_core::executor::PipelineResult;
use cpex_core::extensions::{AgentExtension, Extensions, HttpExtension, MetaExtension};
use cpex_core::identity::{IdentityHook, IdentityPayload, TokenSource, HOOK_IDENTITY_RESOLVE};

/// Request header an agent echoes to resume a suspended elicitation. Its
/// value is the `elicitation_id` from a prior pending outcome.
const ELICITATION_ID_HEADER: &str = "X-Policy-Elicitation-Id";

/// Who is making the call. Built with [`Caller::anonymous`] (modules 0–1,
/// no IdP) or [`Caller::with_token`] (modules 2+, a Keycloak-minted JWT).
/// A `session_id` opts the call into cross-request session state, the
/// tainting module (7) relies on two calls sharing one session id.
#[derive(Debug, Clone, Default)]
pub struct Caller {
    /// Bearer token (a JWT from the tutorial IdP). `None` = anonymous.
    pub token: Option<String>,
    /// Session id for cross-request information flow. Session state only
    /// keys off this when the caller is also authenticated (has a subject).
    pub session_id: Option<String>,
    /// Elicitation id being resumed. Set on a retry after a prior call
    /// returned [`Outcome::Pending`]; it is sent as the resume header so
    /// policy checks the existing approval instead of opening a new one.
    pub elicitation_id: Option<String>,
}

impl Caller {
    /// An unauthenticated caller, no token. Used by module 1, where the
    /// policy gates on structural predicates only.
    pub fn anonymous() -> Self {
        Self::default()
    }

    /// A caller presenting a bearer token (a JWT). The identity plugin
    /// validates it and resolves the subject before policy runs.
    pub fn with_token(token: impl Into<String>) -> Self {
        Self {
            token: Some(token.into()),
            session_id: None,
            elicitation_id: None,
        }
    }

    /// Attach a session id so this call shares information-flow state with
    /// other calls using the same id (module 7).
    pub fn in_session(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Resume a suspended operation by echoing the elicitation id from a
    /// prior [`Outcome::Pending`] (module 8).
    pub fn resuming(mut self, elicitation_id: impl Into<String>) -> Self {
        self.elicitation_id = Some(elicitation_id.into());
        self
    }
}

/// The result of mediating one operation.
#[derive(Debug, Clone)]
pub enum Outcome {
    /// Policy allowed the call. `result` is the backend's response *after*
    /// any `result:` pipeline transformations (redaction/masking) ran.
    Allowed { result: Value },
    /// Policy denied the call, the backend never ran. `code` is the APL
    /// reason code (e.g. `policy.deny`, `auth.token_expired`); `reason` is
    /// the human-readable message.
    Denied { code: String, reason: String },
    /// Policy suspended the call awaiting a human. The operation did not
    /// run. Resume by approving out of band, then call again with
    /// `Caller::resuming(elicitation_id)` (module 8).
    Pending {
        elicitation_id: String,
        approver: String,
    },
}

impl Outcome {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Outcome::Allowed { .. })
    }

    pub fn is_pending(&self) -> bool {
        matches!(self, Outcome::Pending { .. })
    }
}

/// Mediate one tool call end-to-end through CPEX policy.
///
/// `backend` is the function CPEX brackets: it runs only if the Pre phase
/// allows, and its output is fed through the Post phase before returning.
/// This mirrors a real host, where CPEX sits in front of the actual tool
/// and never calls it directly.
pub async fn mediate<F>(
    mgr: &Arc<PluginManager>,
    caller: &Caller,
    tool: &str,
    args: Value,
    backend: F,
) -> Outcome
where
    F: FnOnce(&Value) -> Value,
{
    // --- Base extensions: which entity is this, and (optionally) which
    //     session does it belong to. Meta drives APL route matching. ---
    let mut ext = Extensions {
        meta: Some(Arc::new(MetaExtension {
            entity_type: Some("tool".into()),
            entity_name: Some(tool.into()),
            ..Default::default()
        })),
        ..Default::default()
    };
    if let Some(sid) = &caller.session_id {
        ext.agent = Some(Arc::new(AgentExtension {
            session_id: Some(sid.clone()),
            ..Default::default()
        }));
    }
    // Resuming a suspended elicitation: echo its id in the resume header so
    // policy checks the existing approval instead of opening a new one.
    if let Some(eid) = &caller.elicitation_id {
        let mut http = HttpExtension::default();
        http.set_request_header(ELICITATION_ID_HEADER, eid);
        ext.http = Some(Arc::new(http));
    }

    // --- Step 1: resolve identity (skipped for anonymous callers). The
    //     JWT plugin validates the token and returns a subject; we fold
    //     that subject into the extensions the policy phases will read. ---
    if let Some(token) = &caller.token {
        let (id_result, id_bg) = mgr
            .invoke_named::<IdentityHook>(
                HOOK_IDENTITY_RESOLVE,
                IdentityPayload::new(token.clone(), TokenSource::Bearer),
                ext.clone(),
                None,
            )
            .await;
        id_bg.wait_for_background_tasks().await;
        if !id_result.continue_processing {
            return denied(&id_result);
        }
        if let Some(identity) = IdentityPayload::from_pipeline_result(&id_result) {
            ext = identity.apply_to_extensions(ext);
        }
    }

    // --- Step 2: Pre phase, args validation + authorization.pre_invocation. ---
    let pre_payload = MessagePayload {
        message: tool_call_message(tool, &args),
    };
    let (pre_result, pre_bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", pre_payload, ext.clone(), None)
        .await;
    pre_bg.wait_for_background_tasks().await;
    if !pre_result.continue_processing {
        // A suspended elicitation surfaces as a distinguished violation
        // carrying the elicitation id, not an ordinary denial.
        if let Some(v) = &pre_result.violation {
            if v.code == "elicitation.pending" {
                let id = v
                    .details
                    .get("elicitation_id")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string();
                let approver = v
                    .details
                    .get("approver")
                    .and_then(|x| x.as_str())
                    .unwrap_or("the approver")
                    .to_string();
                return Outcome::Pending {
                    elicitation_id: id,
                    approver,
                };
            }
        }
        return denied(&pre_result);
    }
    // Carry any extension changes the Pre phase made (e.g. a delegated
    // token, or session labels) into the Post phase.
    let post_ext = pre_result.modified_extensions.clone().unwrap_or(ext);

    // --- Step 3: the host calls the backend. In production this is the
    //     real tool/service; here it is a fake in `backends.rs`. ---
    let raw_result = backend(&args);

    // --- Step 4: Post phase, the `result:` pipeline (redact/mask) +
    //     authorization.post_invocation. The returned payload carries the
    //     transformed result, which is what the caller actually sees. ---
    let post_payload = MessagePayload {
        message: tool_result_message(tool, &raw_result),
    };
    let (post_result, post_bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_post_invoke", post_payload, post_ext, None)
        .await;
    post_bg.wait_for_background_tasks().await;
    if !post_result.continue_processing {
        return denied(&post_result);
    }

    // The Post phase may have rewritten the result (redaction). If it did,
    // `modified_payload` holds the transformed message; otherwise the
    // backend's original result stands.
    let result = post_result
        .modified_payload
        .as_ref()
        .and_then(|p| p.as_any().downcast_ref::<MessagePayload>())
        .and_then(|mp| mp.message.get_tool_results().into_iter().next())
        .map(|tr| tr.content.clone())
        .unwrap_or(raw_result);

    Outcome::Allowed { result }
}

/// Turn a denied pipeline result into an [`Outcome::Denied`], pulling the
/// APL reason code and message out of the violation (with sane fallbacks
/// for the rare case where a phase halts without one).
fn denied(result: &PipelineResult) -> Outcome {
    match &result.violation {
        Some(v) => Outcome::Denied {
            code: v.code.clone(),
            reason: v.reason.clone(),
        },
        None => Outcome::Denied {
            code: "policy.deny".into(),
            reason: "denied without a violation".into(),
        },
    }
}

/// Build a CMF message carrying a tool call (the Pre-phase payload).
fn tool_call_message(tool: &str, args: &Value) -> Message {
    Message::with_content(
        Role::User,
        vec![ContentPart::ToolCall {
            content: ToolCall {
                tool_call_id: "tutorial-call".into(),
                name: tool.into(),
                arguments: json_to_map(args),
                namespace: None,
            },
        }],
    )
}

/// Build a CMF message carrying a tool result (the Post-phase payload).
fn tool_result_message(tool: &str, result: &Value) -> Message {
    Message::with_content(
        Role::Tool,
        vec![ContentPart::ToolResult {
            content: ToolResult {
                tool_call_id: "tutorial-call".into(),
                tool_name: tool.into(),
                content: result.clone(),
                is_error: false,
            },
        }],
    )
}

/// Flatten a JSON object into the `HashMap` shape `ToolCall.arguments`
/// wants. A non-object value is wrapped under a `"value"` key so callers
/// can pass a bare scalar without ceremony.
fn json_to_map(args: &Value) -> std::collections::HashMap<String, Value> {
    match args {
        Value::Object(map) => map.clone().into_iter().collect(),
        other => {
            let mut m = Map::new();
            m.insert("value".into(), other.clone());
            m.into_iter().collect()
        },
    }
}
