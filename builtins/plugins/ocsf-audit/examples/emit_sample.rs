// Location: ./builtins/plugins/ocsf-audit/examples/emit_sample.rs
// Copyright 2026 AI Identity
// SPDX-License-Identifier: Apache-2.0
//
// Demo: build two realistic CMF turns (a tool invocation, then an LLM
// completion), run them through the OCSF audit emitter with attestation
// chaining on, and pretty-print the resulting OCSF events.
//
// Purpose: show what the plugin emits — including every gap field
// (stop_reason, mcp, framework, monotonic labels, workload identity)
// and the tamper-evident hash chain linking the two events — WITHOUT
// standing up a full CPEX gateway.
//
//   cargo run --example emit_sample
//
// The timestamps are fixed so the output is deterministic (and so the
// entry_hash chain is reproducible across runs).

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::json;

use cpex_plugin_ocsf_audit::OcsfAuditEmitter;

use cpex_core::cmf::{ContentPart, Message, MessagePayload, Role, ToolCall};
use cpex_core::extensions::{
    AgentExtension, CompletionExtension, DelegationExtension, DelegationHop, Extensions,
    FrameworkExtension, MCPExtension, SecurityExtension, StopReason, SubjectExtension, TokenUsage,
    ToolMetadata, WorkloadIdentity,
};
use cpex_core::plugin::{OnError, PluginConfig, PluginMode};

fn emitter() -> OcsfAuditEmitter {
    let config = PluginConfig {
        name: "ocsf-audit-demo".into(),
        kind: "audit/ocsf".into(),
        hooks: vec!["cmf.tool_post_invoke".into(), "cmf.llm_output".into()],
        mode: PluginMode::Sequential,
        priority: 50,
        on_error: OnError::Fail,
        config: Some(json!({
            "chain": true,
            "signing": "none",
            "chain_uid": "demo-chain-org-f3576cf6",
            "product_name": "AI Identity OCSF Audit",
            "vendor_name": "AI Identity",
        })),
        ..Default::default()
    };
    OcsfAuditEmitter::new(config).expect("valid demo config")
}

/// Turn 1 — an agent invokes the `get_compensation` HR tool. Carries
/// identity, delegation, MCP tool metadata, framework context, taint
/// labels, and an attested workload identity.
fn tool_turn() -> (MessagePayload, Extensions) {
    let payload = MessagePayload {
        message: Message::with_content(
            Role::Tool,
            vec![ContentPart::ToolCall {
                content: ToolCall {
                    tool_call_id: "call-001".into(),
                    name: "get_compensation".into(),
                    arguments: HashMap::from([("employee_id".to_string(), json!("EMP-001234"))]),
                    namespace: Some("hr".into()),
                },
            }],
        ),
    };

    let mut sec = SecurityExtension::default();
    let mut subj = SubjectExtension::default();
    subj.id = Some("alice@corp.com".into());
    subj.roles.insert("hr".into());
    subj.teams.insert("people-ops".into());
    sec.subject = Some(subj);
    sec.labels.insert("PII".into());
    sec.labels.insert("secret".into());
    sec.caller_workload = Some(WorkloadIdentity {
        spiffe_id: Some("spiffe://corp/agent/hr-bot".into()),
        trust_domain: Some("corp".into()),
        attestor: Some("gke-workload-identity".into()),
        ..Default::default()
    });

    let agent = AgentExtension {
        agent_id: Some("agent-7".into()),
        parent_agent_id: Some("orchestrator-1".into()),
        session_id: Some("sess-42".into()),
        conversation_id: Some("conv-9".into()),
        turn: Some(3),
        ..Default::default()
    };

    let delegation = DelegationExtension {
        delegated: true,
        depth: 1,
        origin_subject_id: Some("alice@corp.com".into()),
        actor_subject_id: Some("agent-7".into()),
        chain: vec![DelegationHop {
            subject_id: "agent-7".into(),
            audience: Some("workday-api".into()),
            scopes_granted: vec!["read_compensation".into()],
            ttl_seconds: Some(300),
            ..Default::default()
        }],
        ..Default::default()
    };

    let mcp = MCPExtension {
        tool: Some(ToolMetadata {
            name: "get_compensation".into(),
            server_id: Some("hr-mcp".into()),
            namespace: Some("hr".into()),
            ..Default::default()
        }),
        ..Default::default()
    };

    let framework = FrameworkExtension {
        framework: Some("langgraph".into()),
        node_id: Some("node-compensation".into()),
        graph_id: Some("graph-hr".into()),
        ..Default::default()
    };

    let ext = Extensions {
        security: Some(Arc::new(sec)),
        agent: Some(Arc::new(agent)),
        delegation: Some(Arc::new(delegation)),
        mcp: Some(Arc::new(mcp)),
        framework: Some(Arc::new(framework)),
        ..Default::default()
    };

    (payload, ext)
}

/// Turn 2 — the model produces output. Carries completion metadata:
/// stop reason (a gap), token usage, model, latency.
fn completion_turn() -> (MessagePayload, Extensions) {
    let payload = MessagePayload {
        message: Message::with_content(
            Role::Assistant,
            vec![ContentPart::Text {
                text: "Alice's current base compensation is redacted per policy.".into(),
            }],
        ),
    };

    let completion = CompletionExtension {
        stop_reason: Some(StopReason::End),
        tokens: Some(TokenUsage {
            input_tokens: 120,
            output_tokens: 28,
            total_tokens: 148,
        }),
        model: Some("claude-opus-4-8".into()),
        latency_ms: Some(842),
        ..Default::default()
    };

    let agent = AgentExtension {
        agent_id: Some("agent-7".into()),
        session_id: Some("sess-42".into()),
        // Same run as turn 1 — so both events carry
        // correlation_uid = "conv-9" and are joinable (review C1).
        conversation_id: Some("conv-9".into()),
        turn: Some(4),
        ..Default::default()
    };

    let ext = Extensions {
        completion: Some(Arc::new(completion)),
        agent: Some(Arc::new(agent)),
        ..Default::default()
    };

    (payload, ext)
}

fn main() {
    let e = emitter();

    let (p1, x1) = tool_turn();
    let ev1 = e.build(&p1, &x1, "2026-06-30T12:00:00.000Z");

    let (p2, x2) = completion_turn();
    let ev2 = e.build(&p2, &x2, "2026-06-30T12:00:01.000Z");

    println!("// ===== OCSF event 1 — Invoke Tool (get_compensation) =====");
    println!("{}", serde_json::to_string_pretty(&ev1).unwrap());
    println!();
    println!("// ===== OCSF event 2 — Completion (chained to event 1) =====");
    println!("{}", serde_json::to_string_pretty(&ev2).unwrap());
    println!();

    // Demonstrate the tamper-evident chain: event 2's prev_entry_hash
    // equals event 1's entry_hash.
    let h1 = ev1["attestation"]["entry_hash"].as_str().unwrap_or("");
    let prev2 = ev2["attestation"]["prev_entry_hash"].as_str().unwrap_or("");
    println!(
        "// chain check: event2.prev_entry_hash == event1.entry_hash -> {}",
        h1 == prev2
    );
}
