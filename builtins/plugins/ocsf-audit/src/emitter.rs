// Location: ./builtins/plugins/ocsf-audit/src/emitter.rs
// Copyright 2026 AI Identity
// SPDX-License-Identifier: Apache-2.0
// Authors: Jeff Leva
//
// The plugin proper. Mirrors audit-logger::AuditLogger: holds config,
// implements Plugin + HookHandler<CmfHook>, builds a record, emits,
// and returns allow() (observation-only, never blocks).
//
// Added over audit-logger:
//   * OCSF mapping (ocsf::build_ai_operation)
//   * optional attestation with a tamper-evident hash chain
//     (fingerprint -> prev_event.fingerprint) threaded across calls
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
use crate::sign::{canonical_bytes, fingerprint_value, DsseSigner, NoopSigner, OcsfSigner};

/// Back-reference to the preceding record in the chain, i.e. everything
/// the merged `prev_event` object needs: the predecessor's
/// `metadata.uid` (schema-required), its `type_uid` (which tells a
/// consumer the class, and therefore the store, to retrieve it from),
/// and its fingerprint value (what actually binds the link to content).
#[derive(Clone)]
struct PrevRef {
    uid: String,
    type_uid: i64,
    fingerprint: String,
}

#[derive(Default)]
struct ChainState {
    /// Monotonic per-emitter counter. Drives deterministic record and
    /// attestation uids so example/demo output stays reproducible.
    seq: u64,
    prev: Option<PrevRef>,
}

pub struct OcsfAuditEmitter {
    cfg: PluginConfig,
    typed: OcsfAuditConfig,
    chain_uid: String,
    signer: Box<dyn OcsfSigner>,
    chain: Mutex<ChainState>,
}

/// Build a merged-shape `fingerprint` object around a hex digest.
///
/// `algorithm_id` 3 = SHA-256, `encoding_id` 1 = Hex, `serialization_id`
/// 2 = JCS — the last being how a verifier knows which bytes were
/// hashed (our JCS-style canonicalizer, see sign.rs).
fn fingerprint_obj(value: &str) -> Value {
    json!({
        "algorithm_id": 3,
        "algorithm": "SHA-256",
        "encoding_id": 1,
        "encoding": "Hex",
        "serialization_id": 2,
        "serialization": "JCS",
        "value": value,
    })
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
            SigningMode::Dsse => {
                // A missing/unreadable/invalid key fails construction
                // loudly. The alternative — falling back to unsigned —
                // would emit records that LOOK like the operator's
                // signing policy while silently lacking the signatures
                // it promised.
                let config_err = |message: String| Box::new(PluginError::Config { message });
                let pem = match (&typed.signing_key_pem, &typed.signing_key_pem_path) {
                    (Some(inline), None) => inline.clone(),
                    (None, Some(path)) => std::fs::read_to_string(path).map_err(|e| {
                        config_err(format!(
                            "plugin '{}' (cpex-plugin-ocsf-audit): signing=dsse could not \
                             read signing_key_pem_path '{path}': {e}",
                            cfg.name
                        ))
                    })?,
                    (Some(_), Some(_)) => {
                        return Err(config_err(format!(
                            "plugin '{}' (cpex-plugin-ocsf-audit): set exactly one of \
                             signing_key_pem / signing_key_pem_path, not both",
                            cfg.name
                        )))
                    },
                    (None, None) => {
                        return Err(config_err(format!(
                            "plugin '{}' (cpex-plugin-ocsf-audit): signing=dsse requires a \
                             key — set signing_key_pem (inline PKCS#8 PEM) or \
                             signing_key_pem_path",
                            cfg.name
                        )))
                    },
                };
                Box::new(
                    DsseSigner::from_pem(&pem, typed.signing_key_id.clone()).map_err(|e| {
                        config_err(format!(
                            "plugin '{}' (cpex-plugin-ocsf-audit): {e}",
                            cfg.name
                        ))
                    })?,
                )
            },
        };

        Ok(Self {
            cfg,
            typed,
            chain_uid,
            signer,
            chain: Mutex::new(ChainState::default()),
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

        // Predecessor binding, merged-#1661 semantics: the fingerprint
        // is computed over the canonical serialization of the WHOLE
        // EVENT, including this attestation's own `uid`, `chain_uid`,
        // `authority_uid` and `prev_event`, and excluding only
        // `fingerprint` and `signatures`. So the record's chain position
        // is inside the hashed input — deleting, reordering or splicing
        // a record changes its own fingerprint, and every later link
        // with it.
        //
        // This replaces the pre-merge construction, which hashed a
        // synthetic wrapper `{chain_uid, event, prev_entry_hash}`. That
        // form preserved the same property but was only reproducible by
        // a verifier who knew our wrapper convention; the merged form is
        // reproducible by anyone following the schema.
        //
        // Canonical bytes are JCS-style (review C2): key-sorted,
        // compact, set-derived arrays already sorted at build time
        // (ocsf.rs).
        let mut out = event;

        // Held across the whole build: seq allocation, predecessor read
        // and chain advance must be one atomic step, or two concurrent
        // invocations can mint the same uid and fork the chain off the
        // same predecessor. `build` is sync, so there is no await under
        // the guard.
        let mut guard = self.chain.lock().unwrap();
        let record_uid = format!("{}-{:06}", self.chain_uid, guard.seq);
        let att_uid = format!("{}-att-{:06}", self.chain_uid, guard.seq);
        let prev = guard.prev.clone();

        // `metadata.uid` identifies this record; the NEXT record's
        // `prev_event.uid` points at it, so it must exist before we hash.
        let type_uid = out.get("type_uid").and_then(Value::as_i64).unwrap_or(0);
        if let Some(m) = out.get_mut("metadata").and_then(Value::as_object_mut) {
            m.insert("uid".into(), json!(record_uid));
        }

        // Attestation minus fingerprint/signatures — the hashed form.
        let mut attestation = json!({
            "uid": att_uid,
            "chain_uid": self.chain_uid,
        });
        // authority_uid is part of the hashed serialization (merged
        // #1661 semantics list it alongside chain_uid / prev_event), so
        // the claimed authority cannot be swapped post-hoc without
        // breaking the fingerprint — and every signature over it.
        if let Some(authority) = &self.typed.authority_uid {
            attestation["authority_uid"] = json!(authority);
        }
        if let Some(p) = &prev {
            attestation["prev_event"] = json!({
                "uid": p.uid,
                "type_uid": p.type_uid,
                "fingerprint": fingerprint_obj(&p.fingerprint),
            });
        }
        if let Value::Object(m) = &mut out {
            m.insert("attestation_list".into(), json!([attestation]));
        }

        let bytes = canonical_bytes(&out);
        let this_fp = fingerprint_value(&bytes);

        // Now fill in the two excluded members.
        out["attestation_list"][0]["fingerprint"] = fingerprint_obj(&this_fp);
        if let Some(signed) = self.signer.sign(&bytes) {
            out["attestation_list"][0]["signatures"] = json!([signed.digital_signature]);
            // The signature bytes (and the JWKS kid that resolves the
            // public key) have no home on `digital_signature` yet — that
            // gap is filed as ocsf-schema#1709. Until it lands they ride
            // in `unmapped`, matching the production reference bundle.
            // MERGE into any existing `unmapped` — the gap fields from
            // ocsf.rs already live there, and those are inside the
            // hashed bytes; only these two post-hash keys are excluded
            // by a verifier (see sign::signing_input).
            if let Value::Object(m) = &mut out {
                let un = m
                    .entry("unmapped")
                    .or_insert_with(|| Value::Object(Default::default()));
                if let Some(un) = un.as_object_mut() {
                    un.insert("signature_b64".into(), json!(signed.signature));
                    if let Some(kid) = &signed.key_id {
                        un.insert("signature_key_id".into(), json!(kid));
                    }
                }
            }
        }

        guard.prev = Some(PrevRef {
            uid: record_uid,
            type_uid,
            fingerprint: this_fp,
        });
        guard.seq += 1;
        drop(guard);

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
        assert!(ev["metadata"]["correlation_uid"].is_null());
        assert_eq!(ev["tool"]["name"], "get_compensation");
        assert_eq!(ev["tool"]["namespace"], "hr");
        assert_eq!(ev["actor"]["user"]["uid"], "alice@corp.com");
        assert_eq!(ev["metadata"]["product"]["vendor_name"], "AI Identity");
    }

    #[test]
    fn chains_fingerprints_across_calls() {
        let e = OcsfAuditEmitter::new(cfg(json!({ "chain": true }))).unwrap();

        let ev1 = e.build(&tool_payload(), &subject_ext(), "2026-06-30T12:00:00.000Z");
        let ev2 = e.build(&tool_payload(), &subject_ext(), "2026-06-30T12:00:01.000Z");

        let (a1, a2) = (&ev1["attestation_list"][0], &ev2["attestation_list"][0]);

        // Genesis record carries no prev_event at all (the merged shape
        // omits it rather than emitting an explicit null).
        assert!(a1.get("prev_event").is_none());

        // Second record's prev_event binds the first: fingerprint by
        // content, uid + type_uid for retrieval.
        assert_eq!(a2["prev_event"]["fingerprint"], a1["fingerprint"]);
        assert_eq!(a2["prev_event"]["uid"], ev1["metadata"]["uid"]);
        assert_eq!(a2["prev_event"]["type_uid"], ev1["type_uid"]);

        // Fingerprint is a merged-shape object, bare-hex valued.
        assert_eq!(a1["fingerprint"]["algorithm_id"], 3);
        assert_eq!(a1["fingerprint"]["encoding_id"], 1);
        assert_eq!(a1["fingerprint"]["serialization_id"], 2);
        assert_eq!(a1["fingerprint"]["value"].as_str().unwrap().len(), 64);

        // Unsigned-but-chained in the default (None) signing mode: the
        // at_least_one(fingerprint, signatures) constraint is satisfied
        // by the fingerprint, and no empty signatures array is emitted.
        assert!(a1.get("signatures").is_none());
        assert!(ev1.get("unmapped").is_none());
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

    /// Review §4-B (fixed 2026-07-20; carried into the merged shape
    /// 2026-07-31): the predecessor is folded into the hashed input,
    /// now by `prev_event` living inside the serialized event rather
    /// than via a synthetic wrapper. Two byte-identical events at
    /// different chain positions must produce different fingerprints —
    /// under a plain back-pointer design they collide, so reordering or
    /// splicing records between positions (or chains) is undetectable
    /// from the hashes alone.
    #[test]
    fn fingerprint_binds_predecessor_into_hashed_input() {
        let e = OcsfAuditEmitter::new(cfg(json!({ "chain": true }))).unwrap();
        let t = "2026-07-20T12:00:00.000Z";
        let ev1 = e.build(&tool_payload(), &subject_ext(), t);
        let ev2 = e.build(&tool_payload(), &subject_ext(), t);

        // Identical event content (attestation and record uid aside)...
        let strip = |v: &Value| {
            let mut v = v.clone();
            let m = v.as_object_mut().unwrap();
            m.remove("attestation_list");
            m.get_mut("metadata")
                .and_then(Value::as_object_mut)
                .map(|md| md.remove("uid"));
            v
        };
        assert_eq!(strip(&ev1), strip(&ev2));

        // ...but a different chain position -> a different fingerprint,
        // while linkage still holds.
        let (a1, a2) = (&ev1["attestation_list"][0], &ev2["attestation_list"][0]);
        assert_ne!(a1["fingerprint"]["value"], a2["fingerprint"]["value"]);
        assert_eq!(a2["prev_event"]["fingerprint"], a1["fingerprint"]);
    }

    // --- signing (DSSE) --------------------------------------------------

    /// Deterministic test key (RFC 6979 makes ECDSA deterministic per
    /// key+message, so signed sample output stays reproducible). PEM is
    /// generated at runtime — no key material lives in the repo.
    fn test_key_pem() -> String {
        use p256::pkcs8::EncodePrivateKey;
        p256::ecdsa::SigningKey::from_slice(&[0x11u8; 32])
            .unwrap()
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .unwrap()
            .to_string()
    }

    fn signed_cfg() -> PluginConfig {
        cfg(json!({
            "chain": true,
            "signing": "dsse",
            "signing_key_pem": test_key_pem(),
            "signing_key_id": "test-key-1",
            "authority_uid": "org-test-authority",
        }))
    }

    /// The full independent-verifier loop, from nothing but the emitted
    /// JSON and the public key: reconstruct the signed bytes
    /// (sign::signing_input), recompute the fingerprint, verify the
    /// DSSE signature over the PAE.
    #[test]
    fn signed_event_verifies_offline() {
        use crate::sign::{dsse_pae, signing_input};
        use base64::Engine;
        use p256::ecdsa::signature::Verifier;

        let e = OcsfAuditEmitter::new(signed_cfg()).unwrap();
        let ev = e.build(&tool_payload(), &full_ext(), "2026-07-31T12:00:00.000Z");

        let att = &ev["attestation_list"][0];
        // #2: authority_uid emitted, and it names the configured party.
        assert_eq!(att["authority_uid"], "org-test-authority");
        // Descriptor carries the verified enum ids: ECDSA (3) / DSSE (5),
        // with normalized captions.
        assert_eq!(att["signatures"][0]["algorithm_id"], 3);
        assert_eq!(att["signatures"][0]["algorithm"], "ECDSA");
        assert_eq!(att["signatures"][0]["serialization_id"], 5);
        assert_eq!(att["signatures"][0]["serialization"], "DSSE");
        // kid rides beside the bytes so a verifier can resolve the key.
        assert_eq!(ev["unmapped"]["signature_key_id"], "test-key-1");

        // Independent reconstruction: fingerprint matches...
        let bytes = signing_input(&ev);
        assert_eq!(
            crate::sign::fingerprint_value(&bytes),
            att["fingerprint"]["value"].as_str().unwrap()
        );
        // ...and the signature verifies over the PAE of the same bytes.
        let der = base64::engine::general_purpose::STANDARD
            .decode(ev["unmapped"]["signature_b64"].as_str().unwrap())
            .unwrap();
        let sig = p256::ecdsa::Signature::from_der(&der).unwrap();
        let vk = *p256::ecdsa::SigningKey::from_slice(&[0x11u8; 32])
            .unwrap()
            .verifying_key();
        vk.verify(&dsse_pae(&bytes), &sig)
            .expect("emitted signature must verify offline");
    }

    /// Regression: signing must MERGE into `unmapped`, not replace it —
    /// the gap fields (stop_reason, mcp, framework, labels, workload)
    /// live there and are part of the hashed evidence.
    #[test]
    fn signing_preserves_gap_fields_in_unmapped() {
        let e = OcsfAuditEmitter::new(signed_cfg()).unwrap();
        let ev = e.build(&tool_payload(), &full_ext(), "2026-07-31T12:00:00.000Z");

        let un = ev["unmapped"].as_object().unwrap();
        assert!(un.contains_key("signature_b64"));
        assert!(un.contains_key("cmf.completion.stop_reason"));
        assert!(un.contains_key("cmf.mcp"));
        assert!(un.contains_key("cmf.security.labels"));
    }

    /// authority_uid sits INSIDE the hashed serialization: two otherwise
    /// identical records claiming different authorities must fingerprint
    /// differently — the claimed authority can't be swapped post-hoc.
    #[test]
    fn authority_uid_is_bound_into_the_fingerprint() {
        let build = |authority: &str| {
            OcsfAuditEmitter::new(cfg(json!({
                "chain": true,
                "authority_uid": authority,
            })))
            .unwrap()
            .build(&tool_payload(), &subject_ext(), "2026-07-31T12:00:00.000Z")
        };
        let a = build("org-alpha");
        let b = build("org-beta");
        assert_ne!(
            a["attestation_list"][0]["fingerprint"]["value"],
            b["attestation_list"][0]["fingerprint"]["value"]
        );
    }

    /// signing=dsse with no key must fail construction loudly — never
    /// fall back to silently-unsigned records.
    #[test]
    fn dsse_without_key_fails_construction() {
        let err = OcsfAuditEmitter::new(cfg(json!({ "signing": "dsse" }))).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("requires a key"), "unexpected error: {msg}");
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
        // It lives on `metadata`, which is where OCSF defines it.
        assert_eq!(ev["metadata"]["correlation_uid"], "conv-9");
        assert!(ev.get("correlation_uid").is_none());
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
    /// the fingerprint.
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
