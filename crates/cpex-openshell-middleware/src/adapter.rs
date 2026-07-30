// Location: ./crates/cpex-openshell-middleware/src/adapter.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Xiaokui Shu
//
// Adapter from an OpenShell `EvaluateHttpRequest` view to a CPEX CMF tool
// operation.
//
// The reusable `cpex::embed` API is hook-agnostic; this adapter is the
// OpenShell-specific choice to map an egress operation onto the CMF *tool*
// entity (`cmf.tool_pre_invoke`), so a bundle's `require` / `taint` steps run
// and the demo can reuse the Praxis capstone `tool:` routes. Because this rides
// OpenShell's request-only middleware contract, only the pre-invocation hook is
// used: there is no response phase (redaction), no credential-write channel
// (delegation), and no suspend outcome (elicitation). Those require an
// in-process integration.
//
// The tool name comes from the MCP `tools/call` name when the body is JSON-RPC,
// otherwise from a closed operator-supplied `(host, method, path) -> tool` map.
// Identity is read only from a dedicated identity header (never a credential
// header); OpenShell already strips credential/hop-by-hop headers before the
// call, so `Authorization` is not even visible here.

use std::collections::HashMap;

use cpex::cpex_core::cmf::content::ToolCall;
use cpex::cpex_core::cmf::enums::Role;
use cpex::cpex_core::cmf::{ContentPart, Message, MessagePayload};
use cpex::cpex_core::extensions::{AgentExtension, Extensions, MetaExtension};
use cpex::cpex_core::hooks::payload::PluginPayload;
use std::sync::Arc;

use crate::config::RestToolMap;
use crate::proto::HttpRequestEvaluation;

/// Dedicated header carrying the verified-identity JWT. Distinct from any
/// credential-carrying header (never `Authorization`): a bearer the proxy would
/// inject for upstream auth must never be misread as the caller's identity.
/// Lowercased because OpenShell delivers header names lowercased.
pub const IDENTITY_HEADER: &str = "x-cpex-identity";

/// The resolved CMF operation for one egress request: the tool entity that
/// drives route matching plus the payload the pre-invoke hook evaluates.
pub struct MappedOperation {
    pub tool: String,
    pub payload: Box<dyn PluginPayload>,
    pub extensions: Extensions,
}

/// Extract the verified-identity JWT from the evaluation's headers, matching the
/// dedicated identity header case-insensitively. `None` when absent. Never falls
/// back to `Authorization` (which OpenShell strips before the call anyway).
pub fn identity_token(eval: &HttpRequestEvaluation) -> Option<String> {
    eval.headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(IDENTITY_HEADER))
        .map(|h| h.value.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Resolve the egress request to a CMF tool operation, or `None` when it maps to
/// no tool. An unmapped operation must fail closed at the caller (no unevaluated
/// bytes): the service never forwards a request CPEX did not evaluate.
pub fn map_operation(eval: &HttpRequestEvaluation, rest_map: &RestToolMap) -> Option<MappedOperation> {
    let (tool, arguments) = resolve_tool_and_args(eval, rest_map)?;

    let extensions = Extensions {
        // The tool entity drives route matching against the bundle's `tool:`
        // routes.
        meta: Some(Arc::new(MetaExtension {
            entity_type: Some("tool".into()),
            entity_name: Some(tool.clone()),
            ..Default::default()
        })),
        // The session id is bound to the trusted sandbox identity (never an
        // agent-controllable value), so a taint label cannot be shed by
        // rotating it. The cross-call taint block keys on this.
        agent: Some(Arc::new(AgentExtension {
            session_id: Some(sandbox_session_id(eval)),
            ..Default::default()
        })),
        ..Default::default()
    };

    let payload = Box::new(MessagePayload {
        message: Message::with_content(
            Role::User,
            vec![ContentPart::ToolCall {
                content: ToolCall {
                    tool_call_id: "openshell-egress".into(),
                    name: tool.clone(),
                    arguments,
                    namespace: None,
                },
            }],
        ),
    });

    Some(MappedOperation {
        tool,
        payload,
        extensions,
    })
}

/// Derive the tool name and CMF `args` for one egress request.
///
/// - JSON-RPC MCP body: the `tools/call` `params.name` is the tool, and
///   `params.arguments` are the args (over MCP the args map for free).
/// - REST: a closed `(host, method, path) -> tool` map names the tool, and the
///   declared query/body field projections fill the args, so args-reading
///   policies (`args.visibility`, …) work identically to the MCP leg.
fn resolve_tool_and_args(
    eval: &HttpRequestEvaluation,
    rest_map: &RestToolMap,
) -> Option<(String, HashMap<String, serde_json::Value>)> {
    if let Some((tool, args)) = mcp_tool_and_args(&eval.body) {
        return Some((tool, args));
    }
    let target = eval.target.as_ref()?;
    rest_map.resolve(&target.host, &target.method, &target.path, &target.query, &eval.body)
}

/// Parse a JSON-RPC 2.0 `tools/call` body into (tool name, arguments). Returns
/// `None` for non-JSON or non-`tools/call` bodies so the caller falls through to
/// the REST map.
fn mcp_tool_and_args(body: &[u8]) -> Option<(String, HashMap<String, serde_json::Value>)> {
    let json: serde_json::Value = serde_json::from_slice(body).ok()?;
    if json.get("method")?.as_str()? != "tools/call" {
        return None;
    }
    let params = json.get("params")?;
    let name = params.get("name")?.as_str()?.to_string();
    let mut args = HashMap::new();
    if let Some(obj) = params.get("arguments").and_then(serde_json::Value::as_object) {
        for (k, v) in obj {
            args.insert(k.clone(), v.clone());
        }
    }
    Some((name, args))
}

/// A stable session id bound to the trusted sandbox identity from the request
/// context, never an agent-supplied value. Falls back to the request id only if
/// no sandbox id is present (keeps distinct sandboxes from colliding).
fn sandbox_session_id(eval: &HttpRequestEvaluation) -> String {
    match &eval.context {
        Some(ctx) if !ctx.sandbox_id.is_empty() => format!("sandbox:{}", ctx.sandbox_id),
        Some(ctx) => format!("request:{}", ctx.request_id),
        None => "sandbox:unknown".to_string(),
    }
}
