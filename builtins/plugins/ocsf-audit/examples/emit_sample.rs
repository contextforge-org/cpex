// Location: ./builtins/plugins/ocsf-audit/examples/emit_sample.rs
// Copyright 2026 AI Identity
// SPDX-License-Identifier: Apache-2.0
// Authors: Jeff Leva
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
// fingerprint chain is reproducible across runs).

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

/// Demo signing key, generated at runtime from a fixed scalar so the
/// sample output is byte-identical across runs (RFC 6979 deterministic
/// ECDSA) WITHOUT any key material living in the repo. Demo only — a
/// real deployment points signing_key_pem_path at a provisioned key and
/// publishes the public half (JWKS) under the authority named by
/// authority_uid.
fn demo_key_pem() -> String {
    use p256::pkcs8::EncodePrivateKey;
    p256::ecdsa::SigningKey::from_slice(&[0x42u8; 32])
        .expect("valid P-256 scalar")
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .expect("pem")
        .to_string()
}

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
            "signing": "dsse",
            "signing_key_pem": demo_key_pem(),
            "signing_key_id": "demo-key-2026-07",
            "authority_uid": "org-f3576cf6",
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

    // Demonstrate the tamper-evident chain: event 2's
    // prev_event.fingerprint equals event 1's fingerprint.
    let fp1 = &ev1["attestation_list"][0]["fingerprint"];
    let prev2 = &ev2["attestation_list"][0]["prev_event"]["fingerprint"];
    println!(
        "// chain check: event2.prev_event.fingerprint == event1.fingerprint -> {}",
        fp1 == prev2
    );
    // And the retrieval coordinates the merged shape adds: prev_event
    // names the record it points at, so a consumer can go fetch it.
    println!(
        "// chain check: event2.prev_event.uid == event1.metadata.uid   -> {}",
        ev2["attestation_list"][0]["prev_event"]["uid"] == ev1["metadata"]["uid"]
    );

    // The independent-verifier loop, from nothing but the emitted JSON
    // and the public key: reconstruct the signed bytes, recompute the
    // fingerprint, verify the DSSE signature over the PAE.
    {
        use base64::Engine;
        use cpex_plugin_ocsf_audit::sign::{dsse_pae, fingerprint_value, signing_input};
        use p256::ecdsa::signature::Verifier;

        let vk = *p256::ecdsa::SigningKey::from_slice(&[0x42u8; 32])
            .unwrap()
            .verifying_key();
        for (label, ev) in [("event1", &ev1), ("event2", &ev2)] {
            let bytes = signing_input(ev);
            let fp_ok = fingerprint_value(&bytes)
                == ev["attestation_list"][0]["fingerprint"]["value"]
                    .as_str()
                    .unwrap();
            let der = base64::engine::general_purpose::STANDARD
                .decode(ev["unmapped"]["signature_b64"].as_str().unwrap())
                .unwrap();
            let sig_ok = p256::ecdsa::Signature::from_der(&der)
                .map(|sig| vk.verify(&dsse_pae(&bytes), &sig).is_ok())
                .unwrap_or(false);
            println!(
                "// verify {label}: fingerprint recomputed -> {fp_ok} · DSSE signature -> {sig_ok}"
            );
        }
    }
}
