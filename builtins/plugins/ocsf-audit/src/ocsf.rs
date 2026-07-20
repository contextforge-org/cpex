// Location: ./builtins/plugins/ocsf-audit/src/ocsf.rs
// Copyright 2026 AI Identity
// SPDX-License-Identifier: Apache-2.0
//
// CMF -> OCSF mapping. This is the running-code form of
// the CMF→OCSF field map (shared review doc). Each block below
// cites the field-map row it implements.
//
// Design choices:
//   * We build a serde_json::Value rather than hand-rolling fully
//     typed OCSF structs — OCSF object shapes still move release to
//     release, and a Value keeps the scaffold honest about what's
//     proposed vs merged.
//   * Fields with no native OCSF home yet (the five gaps) go under
//     `unmapped` when cfg.include_gap_fields is set. That is correct
//     OCSF practice AND it makes the gaps self-documenting in the
//     emitted evidence.
//
// OCSF MODELING NOTE: `ai_operation` is a PROFILE, not a class. PR #1641
// (merged 2026-06-29, "Add ai_agent object and extend ai_operation profile
// coverage") makes it contribute `ai_agent` / `ai_model` / `message_context`
// to existing base classes — all in the Application category (6). The host
// class is **API Activity (6003)** — agreed with the CPEX team 2026-07-17/18
// (matches AOS's host-class choice and AI Identity's production gateway).
// Activity ids follow API Activity's real enum (CRUD + 99 Other), NOT a
// bespoke enum: per the OCSF enum contract, a known id carries the
// normalized caption as activity_name; source-defined names ride with 99.

use serde_json::{json, Map, Value};

use cpex_core::cmf::{ContentPart, MessagePayload};
use cpex_core::hooks::payload::Extensions;

use crate::config::OcsfAuditConfig;

// --- OCSF identifiers ---
const SCHEMA_VERSION: &str = "1.9.0-dev";
const CATEGORY_UID_APPLICATION: u32 = 6;
/// API Activity — the concrete Application-category class hosting the
/// ai_operation profile (P0 decision, 2026-07-18 thread).
const CLASS_UID_API_ACTIVITY: u32 = 6003;
const SEVERITY_INFORMATIONAL: u32 = 1;

/// OCSF activity on API Activity (6003): 0 Unknown · 1 Create · 2 Read ·
/// 3 Update · 4 Delete · 99 Other.
///
/// Mapping convention (2026-07-18 thread):
///   * Read Resource / Invoke Prompt        -> 2 (Read)
///   * Invoke Tool with readOnlyHint: true  -> 2 (Read)
///   * Invoke Tool otherwise                -> 99 + activity_name "Invoke Tool"
///     (we can't honestly claim Create/Update/Delete without knowing the
///     operation; destructiveHint stays context, not a Delete mapping)
///   * Completion                           -> 99 + activity_name "Completion"
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Activity {
    Unknown,
    Read,
    /// 99 (Other) with a source-defined activity_name, per the OCSF
    /// enum contract.
    Other(&'static str),
}

impl Activity {
    fn id(self) -> u32 {
        match self {
            Activity::Unknown => 0,
            Activity::Read => 2,
            Activity::Other(_) => 99,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Activity::Unknown => "Unknown",
            // Known id -> normalized enum caption, never a source-defined
            // string (the AOS pin-1-vary-name practice violates this).
            Activity::Read => "Read",
            Activity::Other(n) => n,
        }
    }
}

/// True when the MCP tool metadata for this invocation carries
/// `readOnlyHint: true`. When the content part names the tool, the hint
/// only applies if the MCP slot describes that same tool.
fn tool_read_only_hint(ext: &Extensions, call_name: Option<&str>) -> bool {
    let Some(mcp) = ext.mcp.as_ref() else {
        return false;
    };
    let Some(tool) = mcp.tool.as_ref() else {
        return false;
    };
    if let Some(name) = call_name {
        if tool.name != name {
            return false;
        }
    }
    matches!(
        tool.annotations.get("readOnlyHint"),
        Some(Value::Bool(true))
    )
}

/// Infer the OCSF activity from the message content parts (the typed
/// handler does not receive the hook name, so we classify from content —
/// which is more robust anyway) plus the MCP tool annotations.
pub fn activity_of(payload: &MessagePayload, ext: &Extensions) -> Activity {
    for part in &payload.message.content {
        match part {
            // ContentPart variant shapes confirmed against cpex@feat/hil_apl ad666ba (2026-07-06).
            ContentPart::ToolCall { content } => {
                return if tool_read_only_hint(ext, Some(&content.name)) {
                    Activity::Read
                } else {
                    Activity::Other("Invoke Tool")
                }
            },
            ContentPart::ToolResult { .. } => {
                // Result side of the same invocation; the result part
                // carries no tool name, so the MCP slot speaks for it.
                return if tool_read_only_hint(ext, None) {
                    Activity::Read
                } else {
                    Activity::Other("Invoke Tool")
                };
            },
            ContentPart::PromptRequest { .. }
            | ContentPart::PromptResult { .. }
            | ContentPart::Resource { .. }
            | ContentPart::ResourceRef { .. } => return Activity::Read,
            _ => {},
        }
    }
    // Plain assistant text / thinking with completion metadata = LLM output.
    if payload
        .message
        .content
        .iter()
        .any(|p| matches!(p, ContentPart::Text { .. } | ContentPart::Thinking { .. }))
    {
        return Activity::Other("Completion");
    }
    Activity::Unknown
}

/// Build the OCSF AI Operation event (the inner event, pre-attestation).
/// `now_rfc3339` is injected so the caller controls the clock (testable).
pub fn build_ai_operation(
    payload: &MessagePayload,
    ext: &Extensions,
    cfg: &OcsfAuditConfig,
    now_rfc3339: &str,
) -> Value {
    let activity = activity_of(payload, ext);

    let mut ev = Map::new();

    // --- base event ---------------------------------------------------
    ev.insert("activity_id".into(), json!(activity.id()));
    ev.insert("activity_name".into(), json!(activity.name()));
    ev.insert("category_uid".into(), json!(CATEGORY_UID_APPLICATION));
    ev.insert("class_uid".into(), json!(CLASS_UID_API_ACTIVITY));
    ev.insert(
        "type_uid".into(),
        json!(CLASS_UID_API_ACTIVITY * 100 + activity.id()),
    );
    ev.insert("severity_id".into(), json!(SEVERITY_INFORMATIONAL));
    ev.insert("time".into(), json!(now_rfc3339));

    // security_control profile: this passive post-hook stream is
    // action_id 3 (Observed) / disposition_id 17 (Logged). The deny and
    // modify mappings (action_id 2 / 4) arrive with the cpex-core
    // decision event (WS-A / P1) — the plugin structurally cannot see a
    // denial from a post hook.
    ev.insert("action_id".into(), json!(3));
    ev.insert("action".into(), json!("Observed"));
    ev.insert("disposition_id".into(), json!(17));
    ev.insert("disposition".into(), json!("Logged"));

    // metadata + product (field map: `meta`/`request` -> base metadata)
    let mut profiles = vec!["ai_operation", "security_control"];
    if cfg.chain {
        // The attestation wrapper (entry_hash chain) is the
        // record_integrity shape from PR #1661 / OCSF 1.9.
        profiles.push("record_integrity");
    }
    ev.insert(
        "metadata".into(),
        json!({
            "version": SCHEMA_VERSION,
            "profiles": profiles,
            "product": { "name": cfg.product_name, "vendor_name": cfg.vendor_name },
        }),
    );

    // correlation (field map: AgentExtension.conversation_id -> base
    // correlation_uid). Review C1: the correlation key must be stable
    // across every event of one run — conversation_id IS the run.
    // Per-event ids (request_id, tool_call_id) correlate nothing;
    // tool_call_id rides at api.request.uid instead (see
    // attach_capability_coords).
    if let Some(cid) = correlation_uid(ext) {
        ev.insert("correlation_uid".into(), json!(cid));
    }

    // status (field map: ToolResult.is_error -> status)
    if let Some(is_err) = first_tool_error(payload) {
        ev.insert("status_id".into(), json!(if is_err { 2 } else { 1 })); // 1=Success 2=Failure
    }

    // --- actor / user (field map: SecurityExtension.SubjectExtension) -
    if let Some(sec) = ext.security.as_ref() {
        if let Some(s) = &sec.subject {
            // roles/teams are HashSets — sort so the emitted event is
            // canonical and entry_hash is reproducible (review C2).
            let mut groups: Vec<&String> = s.teams.iter().collect();
            groups.sort_unstable();
            let mut roles: Vec<&String> = s.roles.iter().collect();
            roles.sort_unstable();
            ev.insert(
                "actor".into(),
                json!({
                    "user": {
                        "uid": s.id,
                        "groups": groups,
                    },
                    // roles/permissions ride along as enrichment.
                    "roles": roles,
                }),
            );
        }
    }

    // --- ai_agent (field map: AgentExtension; PR #1641) ---------------
    if let Some(ag) = ext.agent.as_ref() {
        ev.insert(
            "ai_agent".into(),
            json!({
                "uid": ag.agent_id,
                "instance_uid": ag.session_id,
                // multi-agent lineage
                "parent_uid": ag.parent_agent_id,
                "conversation_uid": ag.conversation_id,
                "turn": ag.turn,
            }),
        );
    }

    // --- ai_model + message_context (field map: LLMExtension /
    //     CompletionExtension; mostly merged) -------------------------
    if let Some(comp) = ext.completion.as_ref() {
        let mut mctx = Map::new();
        if let Some(tok) = &comp.tokens {
            mctx.insert("prompt_tokens".into(), json!(tok.input_tokens));
            mctx.insert("completion_tokens".into(), json!(tok.output_tokens));
            mctx.insert("total_tokens".into(), json!(tok.total_tokens));
        }
        if !mctx.is_empty() {
            ev.insert("message_context".into(), Value::Object(mctx));
        }
        if let Some(model) = &comp.model {
            ev.insert("ai_model".into(), json!({ "name": model }));
        }
        if let Some(ms) = comp.latency_ms {
            ev.insert("duration".into(), json!(ms)); // base `duration` (ms)
        }
    }

    // --- delegation (field map: DelegationExtension; upcoming/Ania) ---
    if let Some(del) = ext.delegation.as_ref() {
        if del.delegated || !del.chain.is_empty() {
            let chain: Vec<Value> = del
                .chain
                .iter()
                .map(|hop| {
                    json!({
                        "subject_uid": hop.subject_id,
                        "audience": hop.audience,
                        "scopes_granted": hop.scopes_granted,
                        "ttl_seconds": hop.ttl_seconds,
                        "timestamp": hop.timestamp.to_rfc3339(),
                    })
                })
                .collect();
            ev.insert(
                "delegation".into(),
                json!({
                    "depth": del.depth,
                    "origin_subject_uid": del.origin_subject_id,
                    "actor_subject_uid": del.actor_subject_id,
                    "chain": chain,
                }),
            );
        }
    }

    // --- tool/prompt/resource coordinates from content ----------------
    attach_capability_coords(&mut ev, payload);

    // --- the five gaps -> unmapped (field map §5) ---------------------
    if cfg.include_gap_fields {
        let unmapped = build_unmapped_gaps(payload, ext);
        if let Value::Object(m) = &unmapped {
            if !m.is_empty() {
                ev.insert("unmapped".into(), unmapped);
            }
        }
    }

    Value::Object(ev)
}

/// Gap fields with no native OCSF home yet. Emitting them under
/// `unmapped` keeps the evidence complete and documents the gaps.
fn build_unmapped_gaps(payload: &MessagePayload, ext: &Extensions) -> Value {
    let mut g = Map::new();

    // gap 3: completion.stop_reason
    if let Some(comp) = ext.completion.as_ref() {
        if let Some(sr) = &comp.stop_reason {
            g.insert(
                "cmf.completion.stop_reason".into(),
                json!(format!("{sr:?}")),
            );
        }
    }

    // gap 1: mcp tool/resource/prompt metadata
    if let Some(mcp) = ext.mcp.as_ref() {
        // MCPExtension = { tool, resource, prompt } (confirmed cpex@feat/hil_apl ad666ba (2026-07-06)).
        // Serialized whole; each sub-object carries server_id/namespace/schemas.
        g.insert("cmf.mcp".into(), json!(mcp));
    }

    // gap 2: framework context
    if let Some(fw) = ext.framework.as_ref() {
        g.insert(
            "cmf.framework".into(),
            json!({
                "framework": fw.framework,
                "framework_version": fw.framework_version,
                "node_id": fw.node_id,
                "graph_id": fw.graph_id,
            }),
        );
    }

    // gap 4: monotonic security labels (taint set)
    if let Some(sec) = ext.security.as_ref() {
        // SecurityExtension.labels: MonotonicSet<String> (add-only taint),
        // iterated via .iter() (confirmed cpex@feat/hil_apl ad666ba (2026-07-06)).
        let labels = security_labels(sec);
        if !labels.is_empty() {
            g.insert("cmf.security.labels".into(), json!(labels));
        }
    }

    // gap 5: workload attestation (SPIFFE) — partial OCSF home
    if let Some(wl) = caller_workload(ext) {
        g.insert("cmf.workload_identity".into(), wl);
    }

    // multimodal content kinds present (lightweight provenance of shape)
    let _ = payload;

    Value::Object(g)
}

// ---------------------------------------------------------------------
// Helpers — small, content-shape-dependent extractors. CMF accessor and
// variant shapes confirmed against cpex@feat/hil_apl ad666ba (2026-07-06).
// ---------------------------------------------------------------------

fn correlation_uid(ext: &Extensions) -> Option<String> {
    // Review C1: correlation_uid must be multi-event-stable, so it
    // mirrors the run id (AgentExtension.conversation_id) — NOT
    // request_id or tool_call_id, which are per-event unique and
    // correlate nothing. Session-grain grouping stays a join on
    // ai_agent.instance_uid (session_id); the run is the primary
    // forensic grain a SIEM keys on.
    ext.agent.as_ref()?.conversation_id.clone()
}

fn first_tool_error(payload: &MessagePayload) -> Option<bool> {
    for part in &payload.message.content {
        if let ContentPart::ToolResult { content } = part {
            return Some(content.is_error);
        }
    }
    None
}

fn attach_capability_coords(ev: &mut Map<String, Value>, payload: &MessagePayload) {
    for part in &payload.message.content {
        match part {
            ContentPart::ToolCall { content } => {
                ev.insert(
                    "tool".into(),
                    json!({
                        "name": content.name,
                        "uid": content.tool_call_id,
                        "namespace": content.namespace,
                    }),
                );
                // Review C1: the per-call id's home is api.request.uid
                // (one request = one tool call), not correlation_uid.
                ev.insert(
                    "api".into(),
                    json!({ "request": { "uid": content.tool_call_id } }),
                );
                return;
            },
            ContentPart::Resource { content } => {
                ev.insert(
                    "resource".into(),
                    json!({ "uri": content.uri, "type": format!("{:?}", content.resource_type) }),
                );
                return;
            },
            _ => {},
        }
    }
}

// The following two isolate the less-obvious accessor paths to one place
// each (both confirmed against cpex@feat/hil_apl ad666ba (2026-07-06)).

fn security_labels(sec: &cpex_core::extensions::SecurityExtension) -> Vec<String> {
    // MonotonicSet<String>::iter() -> impl Iterator<Item = &String>.
    // The backing HashSet iterates in randomized, seed-dependent order;
    // sort so the emitted array is canonical and the entry_hash an
    // independent verifier recomputes matches ours (review C2).
    let mut labels: Vec<String> = sec.labels.iter().cloned().collect();
    labels.sort_unstable();
    labels
}

fn caller_workload(ext: &Extensions) -> Option<Value> {
    // Confirmed cpex@feat/hil_apl ad666ba (2026-07-06): the resolved inbound workload identity
    // is reachable at Extensions.security.caller_workload (the executor
    // applies IdentityPayload.caller_workload onto the security ext).
    // `this_workload` (the gateway's OWN attested id) is the signer
    // identity and is handled in sign.rs, not here.
    let sec = ext.security.as_ref()?;
    let wl = sec.caller_workload.as_ref()?;
    Some(json!({
        "spiffe_id": wl.spiffe_id,
        "trust_domain": wl.trust_domain,
        "attestor": wl.attestor,        // e.g. gke-workload-identity, spire-agent, mtls
        "attested_at": wl.attested_at,  // for stale-evidence rejection
    }))
}
