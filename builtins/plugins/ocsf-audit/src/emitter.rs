// Location: ./builtins/plugins/ocsf-audit/src/emitter.rs
// Copyright 2026 AI Identity
// SPDX-License-Identifier: Apache-2.0
//
// The plugin proper. Mirrors audit-logger::AuditLogger: holds config,
// implements Plugin + HookHandler<CmfHook>, builds a record, emits,
// and returns allow() (observation-only, never blocks).
//
// Added over audit-logger:
//   * OCSF mapping (ocsf::build_ai_operation)
//   * optional attestation wrapper with a tamper-evident hash chain
//     (entry_hash -> prev_entry_hash) threaded across calls
//   * a pluggable signer (sign::OcsfSigner)

use std::sync::Mutex;

use async_trait::async_trait;
use serde_json::{json, Value};

use cpex_core::cmf::{CmfHook, MessagePayload};
use cpex_core::context::PluginContext;
use cpex_core::error::PluginError;
use cpex_core::hooks::payload::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::plugin::{Plugin, PluginConfig};

use crate::config::{OcsfAuditConfig, OcsfDestination, SigningMode};
use crate::ocsf;
use crate::sign::{canonical_bytes, entry_hash, DsseSigner, NoopSigner, OcsfSigner};

pub struct OcsfAuditEmitter {
    cfg: PluginConfig,
    typed: OcsfAuditConfig,
    chain_uid: String,
    signer: Box<dyn OcsfSigner>,
    /// Last entry_hash, threaded into the next record's prev_entry_hash.
    prev_entry_hash: Mutex<Option<String>>,
}

impl std::fmt::Debug for OcsfAuditEmitter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OcsfAuditEmitter")
            .field("name", &self.cfg.name)
            .field("chain_uid", &self.chain_uid)
            .finish()
    }
}

impl OcsfAuditEmitter {
    pub fn new(cfg: PluginConfig) -> Result<Self, Box<PluginError>> {
        let typed: OcsfAuditConfig = match cfg.config.as_ref() {
            Some(raw) => serde_json::from_value(raw.clone()).map_err(|e| {
                Box::new(PluginError::Config {
                    message: format!(
                        "plugin '{}' (cpex-plugin-ocsf-audit) config parse failed: {e}",
                        cfg.name
                    ),
                })
            })?,
            None => OcsfAuditConfig::default(),
        };

        let chain_uid = typed
            .chain_uid
            .clone()
            // Process-lifetime fallback uid. Not random across restarts —
            // operators who need a stable chain set chain_uid explicitly.
            .unwrap_or_else(|| format!("ocsf-chain-{}", cfg.name));

        let signer: Box<dyn OcsfSigner> = match typed.signing {
            SigningMode::None => Box::new(NoopSigner),
            SigningMode::Dsse => Box::new(DsseSigner::new()),
        };

        Ok(Self {
            cfg,
            typed,
            chain_uid,
            signer,
            prev_entry_hash: Mutex::new(None),
        })
    }

    /// Build the OCSF event and, if chaining is on, wrap it in an
    /// attestation. `now_rfc3339` injected for testability and for
    /// deterministic example/demo output. Public so `examples/` and
    /// downstream tooling can obtain the event without going through
    /// the stderr/tracing emit path.
    pub fn build(&self, payload: &MessagePayload, ext: &Extensions, now_rfc3339: &str) -> Value {
        let event = ocsf::build_ai_operation(payload, ext, &self.typed, now_rfc3339);

        if !self.typed.chain {
            return event;
        }

        // Predecessor binding (review §4-B, fixed 2026-07-20): the hash
        // commits to (chain_uid, event, prev_entry_hash) — prev is part
        // of the HASHED INPUT, not a back-pointer riding beside it, so
        // the chain order is cryptographically bound, and committing
        // chain_uid prevents splicing a record into a different chain.
        // An independent verifier recomputes, per record:
        //   entry_hash = sha256(canonical_bytes(
        //       {"chain_uid": c, "event": e, "prev_entry_hash": p}))
        // where e = the emitted event minus its `attestation` member,
        // and c / p come from that attestation. Canonical bytes are
        // JCS-style (review C2): key-sorted, compact, set-derived
        // arrays already sorted at build time (ocsf.rs).
        let binding = |prev: &Option<String>| {
            json!({
                "chain_uid": self.chain_uid,
                "event": event,
                "prev_entry_hash": prev,
            })
        };

        let (this_hash, prev, bytes) = {
            let mut guard = self.prev_entry_hash.lock().unwrap();
            let prev = guard.clone();
            let bytes = canonical_bytes(&binding(&prev));
            let this_hash = entry_hash(&bytes);
            *guard = Some(this_hash.clone());
            (this_hash, prev, bytes)
        };

        let mut attestation = json!({
            "chain_uid": self.chain_uid,
            "entry_hash": this_hash,
            "prev_entry_hash": prev,
        });

        if let Some(signed) = self.signer.sign(&bytes) {
            attestation["signature"] = json!(signed.signature);
            attestation["digital_signature"] = signed.digital_signature;
        } else {
            attestation["digital_signature"] =
                json!({ "serialization_id": self.signer.serialization_id(), "signed": false });
        }

        // Attach the attestation to the event (OCSF `attestation` object).
        let mut out = event;
        if let Value::Object(m) = &mut out {
            m.insert("attestation".into(), attestation);
        }
        out
    }

    fn emit(&self, event: &Value) {
        match self.typed.destination {
            OcsfDestination::Stderr => eprintln!("{event}"),
            OcsfDestination::Tracing => {
                tracing::info!(target: "ocsf.audit", event = %event, "ocsf");
            },
        }
    }
}

#[async_trait]
impl Plugin for OcsfAuditEmitter {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for OcsfAuditEmitter {
    async fn handle(
        &self,
        payload: &MessagePayload,
        ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let event = self.build(payload, ext, &now);
        self.emit(&event);
        // Observation-only: never block the request.
        PluginResult::allow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cpex_core::cmf::{ContentPart, Message, Role, ToolCall};
    use cpex_core::extensions::{SecurityExtension, SubjectExtension};
    use cpex_core::plugin::{OnError, PluginConfig, PluginMode};
    use std::collections::HashMap;
    use std::sync::Arc;

    fn cfg(extra: serde_json::Value) -> PluginConfig {
        PluginConfig {
            name: "ocsf-audit".into(),
            kind: super::super::factory::KIND.into(),
            hooks: vec!["cmf.tool_post_invoke".into()],
            mode: PluginMode::Sequential,
            priority: 50,
            on_error: OnError::Fail,
            config: Some(extra),
            ..Default::default()
        }
    }

    fn tool_payload() -> MessagePayload {
        MessagePayload {
            message: Message::with_content(
                Role::Tool,
                vec![ContentPart::ToolCall {
                    content: ToolCall {
                        tool_call_id: "call-1".into(),
                        name: "get_compensation".into(),
                        arguments: HashMap::new(),
                        namespace: Some("hr".into()),
                    },
                }],
            ),
        }
    }

    fn subject_ext() -> Extensions {
        let mut sec = SecurityExtension::default();
        sec.subject = Some(SubjectExtension {
            id: Some("alice@corp.com".into()),
            ..Default::default()
        });
        Extensions {
            security: Some(Arc::new(sec)),
            ..Default::default()
        }
    }

    #[test]
    fn maps_tool_call_to_ocsf_ai_operation() {
        let e = OcsfAuditEmitter::new(cfg(json!({ "chain": false }))).unwrap();
        let ev = e.build(&tool_payload(), &subject_ext(), "2026-06-30T12:00:00.000Z");

        // Host class: API Activity (P0, 2026-07-18 thread).
        assert_eq!(ev["class_uid"], 6003);
        // No readOnlyHint on this tool -> honest 99 (Other) with a
        // source-defined name, per the OCSF enum contract.
        assert_eq!(ev["activity_id"], 99);
        assert_eq!(ev["activity_name"], "Invoke Tool");
        assert_eq!(ev["type_uid"], 600399);
        // Passive post-hook stream = security_control Observed/Logged.
        assert_eq!(ev["action_id"], 3);
        assert_eq!(ev["disposition_id"], 17);
        // Review C1: the per-call id lands at api.request.uid, NOT
        // correlation_uid (which mirrors the run id and is absent here
        // because this payload carries no AgentExtension).
        assert_eq!(ev["api"]["request"]["uid"], "call-1");
        assert!(ev["correlation_uid"].is_null());
        assert_eq!(ev["tool"]["name"], "get_compensation");
        assert_eq!(ev["tool"]["namespace"], "hr");
        assert_eq!(ev["actor"]["user"]["uid"], "alice@corp.com");
        assert_eq!(ev["metadata"]["product"]["vendor_name"], "AI Identity");
    }

    #[test]
    fn chains_entry_hashes_across_calls() {
        let e = OcsfAuditEmitter::new(cfg(json!({ "chain": true }))).unwrap();

        let ev1 = e.build(&tool_payload(), &subject_ext(), "2026-06-30T12:00:00.000Z");
        let ev2 = e.build(&tool_payload(), &subject_ext(), "2026-06-30T12:00:01.000Z");

        // First record has no predecessor.
        assert!(ev1["attestation"]["prev_entry_hash"].is_null());
        // Second record's prev_entry_hash == first record's entry_hash.
        assert_eq!(
            ev2["attestation"]["prev_entry_hash"],
            ev1["attestation"]["entry_hash"]
        );
        // Unsigned-but-chained in the default (None) signing mode.
        assert_eq!(ev1["attestation"]["digital_signature"]["signed"], false);
    }

    #[test]
    fn read_only_hint_maps_tool_call_to_read() {
        use cpex_core::extensions::{MCPExtension, ToolMetadata};

        let mut ext = subject_ext();
        ext.mcp = Some(Arc::new(MCPExtension {
            tool: Some(ToolMetadata {
                name: "get_compensation".into(),
                annotations: HashMap::from([("readOnlyHint".to_string(), json!(true))]),
                ..Default::default()
            }),
            ..Default::default()
        }));

        let e = OcsfAuditEmitter::new(cfg(json!({ "chain": false }))).unwrap();
        let ev = e.build(&tool_payload(), &ext, "2026-07-20T12:00:00.000Z");

        // readOnlyHint: true -> known id 2 with the normalized caption.
        assert_eq!(ev["activity_id"], 2);
        assert_eq!(ev["activity_name"], "Read");
        assert_eq!(ev["type_uid"], 600302);
    }

    #[test]
    fn read_only_hint_for_different_tool_is_ignored() {
        use cpex_core::extensions::{MCPExtension, ToolMetadata};

        let mut ext = subject_ext();
        ext.mcp = Some(Arc::new(MCPExtension {
            tool: Some(ToolMetadata {
                name: "some_other_tool".into(),
                annotations: HashMap::from([("readOnlyHint".to_string(), json!(true))]),
                ..Default::default()
            }),
            ..Default::default()
        }));

        let e = OcsfAuditEmitter::new(cfg(json!({ "chain": false }))).unwrap();
        let ev = e.build(&tool_payload(), &ext, "2026-07-20T12:00:00.000Z");

        // The hint describes a different tool than the one invoked.
        assert_eq!(ev["activity_id"], 99);
        assert_eq!(ev["activity_name"], "Invoke Tool");
    }

    #[test]
    fn profiles_reflect_chain_config() {
        let chained = OcsfAuditEmitter::new(cfg(json!({ "chain": true })))
            .unwrap()
            .build(&tool_payload(), &subject_ext(), "2026-07-20T12:00:00.000Z");
        assert_eq!(
            chained["metadata"]["profiles"],
            json!(["ai_operation", "security_control", "record_integrity"])
        );

        let unchained = OcsfAuditEmitter::new(cfg(json!({ "chain": false })))
            .unwrap()
            .build(&tool_payload(), &subject_ext(), "2026-07-20T12:00:00.000Z");
        assert_eq!(
            unchained["metadata"]["profiles"],
            json!(["ai_operation", "security_control"])
        );
    }

    /// Review §4-B (fixed 2026-07-20): prev_entry_hash is folded into
    /// the hashed input. Two byte-identical events at different chain
    /// positions must produce different entry_hashes — under the old
    /// back-pointer design they collided, so reordering or splicing
    /// records between positions (or chains) was undetectable from the
    /// hashes alone.
    #[test]
    fn entry_hash_binds_predecessor_into_hashed_input() {
        let e = OcsfAuditEmitter::new(cfg(json!({ "chain": true }))).unwrap();
        let t = "2026-07-20T12:00:00.000Z";
        let ev1 = e.build(&tool_payload(), &subject_ext(), t);
        let ev2 = e.build(&tool_payload(), &subject_ext(), t);

        // Identical event content (attestation aside)...
        let strip = |v: &Value| {
            let mut v = v.clone();
            v.as_object_mut().unwrap().remove("attestation");
            v
        };
        assert_eq!(strip(&ev1), strip(&ev2));

        // ...but a different chain position -> a different entry_hash,
        // while linkage still holds.
        assert_ne!(
            ev1["attestation"]["entry_hash"],
            ev2["attestation"]["entry_hash"]
        );
        assert_eq!(
            ev2["attestation"]["prev_entry_hash"],
            ev1["attestation"]["entry_hash"]
        );
    }

    #[tokio::test]
    async fn handler_is_observation_only() {
        let e = OcsfAuditEmitter::new(cfg(json!({}))).unwrap();
        let mut ctx = PluginContext::default();
        let r = e.handle(&tool_payload(), &subject_ext(), &mut ctx).await;
        assert!(r.continue_processing);
        assert!(r.violation.is_none());
    }

    // --- gap-branch coverage --------------------------------------------
    // The happy-path test above only exercises a tool call + subject. These
    // build a fully-populated Extensions set and assert every gap field
    // lands where CMF-OCSF-FIELD-MAP.md says it should.

    use cpex_core::extensions::{
        AgentExtension, CompletionExtension, DelegationExtension, DelegationHop,
        FrameworkExtension, MCPExtension, StopReason, TokenUsage, ToolMetadata, WorkloadIdentity,
    };

    /// Extensions with every audit-relevant branch populated.
    fn full_ext() -> Extensions {
        let mut sec = SecurityExtension::default();
        let mut subj = SubjectExtension::default();
        subj.id = Some("alice@corp.com".into());
        subj.roles.insert("hr".into());
        subj.teams.insert("people-ops".into());
        sec.subject = Some(subj);
        // monotonic taint labels (gap 4)
        sec.labels.insert("PII".into());
        sec.labels.insert("secret".into());
        // workload attestation (gap 5)
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

        let completion = CompletionExtension {
            stop_reason: Some(StopReason::MaxTokens), // gap 3
            tokens: Some(TokenUsage {
                input_tokens: 120,
                output_tokens: 30,
                total_tokens: 150,
            }),
            model: Some("claude-opus-4-8".into()),
            latency_ms: Some(842),
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

        Extensions {
            security: Some(Arc::new(sec)),
            agent: Some(Arc::new(agent)),
            completion: Some(Arc::new(completion)),
            delegation: Some(Arc::new(delegation)),
            mcp: Some(Arc::new(mcp)),
            framework: Some(Arc::new(framework)),
            ..Default::default()
        }
    }

    #[test]
    fn gap_fields_land_in_unmapped() {
        let e = OcsfAuditEmitter::new(cfg(json!({ "chain": false }))).unwrap();
        let ev = e.build(&tool_payload(), &full_ext(), "2026-06-30T12:00:00.000Z");

        let un = &ev["unmapped"];
        assert_eq!(un["cmf.completion.stop_reason"], "MaxTokens");
        assert_eq!(un["cmf.framework"]["framework"], "langgraph");
        assert_eq!(un["cmf.framework"]["graph_id"], "graph-hr");
        assert_eq!(un["cmf.mcp"]["tool"]["server_id"], "hr-mcp");
        assert_eq!(
            un["cmf.workload_identity"]["spiffe_id"],
            "spiffe://corp/agent/hr-bot"
        );
        assert_eq!(
            un["cmf.workload_identity"]["attestor"],
            "gke-workload-identity"
        );
        // monotonic labels — order-independent membership check
        let labels = un["cmf.security.labels"].as_array().expect("labels array");
        assert!(labels.iter().any(|v| v == "PII"));
        assert!(labels.iter().any(|v| v == "secret"));
    }

    #[test]
    fn mapped_objects_populate_from_extensions() {
        let e = OcsfAuditEmitter::new(cfg(json!({ "chain": false }))).unwrap();
        let ev = e.build(&tool_payload(), &full_ext(), "2026-06-30T12:00:00.000Z");

        // ai_agent + lineage (PR #1641)
        assert_eq!(ev["ai_agent"]["uid"], "agent-7");
        assert_eq!(ev["ai_agent"]["parent_uid"], "orchestrator-1");
        // Review C1: correlation_uid mirrors the run id
        // (AgentExtension.conversation_id) so every event of one run
        // carries the same value — a per-event id correlates nothing.
        assert_eq!(ev["correlation_uid"], "conv-9");
        assert_eq!(ev["api"]["request"]["uid"], "call-1");
        // message_context tokens (merged)
        assert_eq!(ev["message_context"]["total_tokens"], 150);
        assert_eq!(ev["ai_model"]["name"], "claude-opus-4-8");
        assert_eq!(ev["duration"], 842);
        // delegation object (upcoming/Ania)
        assert_eq!(ev["delegation"]["depth"], 1);
        assert_eq!(ev["delegation"]["chain"][0]["audience"], "workday-api");
        assert_eq!(
            ev["delegation"]["chain"][0]["scopes_granted"][0],
            "read_compensation"
        );
    }

    /// Review C2: HashSet/MonotonicSet iteration order is randomized per
    /// instance, so the builder must sort set-derived arrays — otherwise
    /// the same logical event canonicalizes to different bytes across
    /// process runs and an independent verifier can't recompute
    /// entry_hash.
    #[test]
    fn set_derived_arrays_are_sorted_for_canonical_hashing() {
        let mut sec = SecurityExtension::default();
        let mut subj = SubjectExtension::default();
        subj.id = Some("alice@corp.com".into());
        for r in ["zeta", "alpha", "mid"] {
            subj.roles.insert(r.into());
        }
        for t in ["t2", "t1", "t3"] {
            subj.teams.insert(t.into());
        }
        sec.subject = Some(subj);
        for l in ["secret", "PII", "internal", "export-controlled"] {
            sec.labels.insert(l.into());
        }
        let ext = Extensions {
            security: Some(Arc::new(sec)),
            ..Default::default()
        };

        let e = OcsfAuditEmitter::new(cfg(json!({ "chain": true }))).unwrap();
        let ev = e.build(&tool_payload(), &ext, "2026-07-06T12:00:00.000Z");

        assert_eq!(
            ev["unmapped"]["cmf.security.labels"],
            json!(["PII", "export-controlled", "internal", "secret"])
        );
        assert_eq!(ev["actor"]["roles"], json!(["alpha", "mid", "zeta"]));
        assert_eq!(ev["actor"]["user"]["groups"], json!(["t1", "t2", "t3"]));
    }

    /// Structural OCSF conformance — NOT full schema validation (that needs
    /// the published schema + a validator; see README). Asserts the base
    /// event has the required, correctly-typed fields every OCSF consumer
    /// relies on to route a record.
    #[test]
    fn emits_required_ocsf_base_fields() {
        let e = OcsfAuditEmitter::new(cfg(json!({ "chain": false }))).unwrap();
        let ev = e.build(&tool_payload(), &full_ext(), "2026-06-30T12:00:00.000Z");

        for key in [
            "activity_id",
            "category_uid",
            "class_uid",
            "type_uid",
            "severity_id",
        ] {
            assert!(ev[key].is_u64(), "{key} must be an integer");
        }
        assert!(ev["time"].is_string(), "time must be present");
        assert!(ev["metadata"]["version"].is_string());
        assert!(ev["metadata"]["product"]["name"].is_string());
        // type_uid convention: class_uid * 100 + activity_id
        assert_eq!(
            ev["type_uid"].as_u64().unwrap(),
            ev["class_uid"].as_u64().unwrap() * 100 + ev["activity_id"].as_u64().unwrap()
        );
    }
}
