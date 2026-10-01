# Sample output — `cargo run --example emit_sample`

Real OCSF events produced by the mapping in [`src/ocsf.rs`](src/ocsf.rs) from the two
demo turns in [`examples/emit_sample.rs`](examples/emit_sample.rs). Regenerated 2026-07-31
for the **merged #1661 shape** (PR merged upstream 2026-07-17, `2a244bc9`) — the
attestation carrier changed, so the hashes changed with it. Notes on fidelity:

- **Host class is API Activity (6003)** with its real activity enum: a tool call without
  `readOnlyHint` is the honest `activity_id: 99` + source-defined `activity_name`
  ("Invoke Tool" / "Completion"); reads (resources, prompts, read-only-hinted tools) are
  `2 (Read)` with the normalized caption. `metadata.profiles` declares `ai_operation` +
  `security_control` (+ `record_integrity` when chained), and the passive stream carries
  `action_id: 3 (Observed)` / `disposition_id: 17 (Logged)` — deny/modify records arrive
  with the cpex-core decision event (WS-A / P1).
- **Merged attestation shape.** Records carry `attestation_list[]`, each entry holding a
  `fingerprint` object (`algorithm_id` 3 = SHA-256, `encoding_id` 1 = Hex,
  `serialization_id` 2 = JCS, bare-hex `value`), a `chain_uid`, an attestation `uid`, and —
  from the second record on — a `prev_event` naming its predecessor by `uid` + `type_uid`
  and binding it by `fingerprint`. The pre-merge draft form (string `entry_hash` /
  `prev_entry_hash`, singular `signature`) no longer exists in the schema.
- **The fingerprint commits to the record's chain position** (review §4-B, carried into the
  merged shape): it is computed over the JCS-style canonical bytes of the **whole event**
  with `attestation_list[0]` present and carrying `uid` / `chain_uid` / `authority_uid` /
  `prev_event`, and only `fingerprint` / `signatures` excluded (plus the two post-hash
  signature extras under `unmapped` — the rule is running code, `sign::signing_input`).
  So a verifier does not need to know anything about this crate: strip those members,
  canonicalize per RFC 8785, recompute. That is a change from the pre-merge construction,
  which hashed a private wrapper object.
- **Signed, and independently verifiable.** `signing: dsse` produces ECDSA-P256-SHA256
  over the DSSE PAE of the same canonical bytes the fingerprint covers (deterministic per
  RFC 6979, which is why this output is byte-identical across runs). `signatures[]`
  carries the `digital_signature` descriptor — `algorithm_id` 3 = ECDSA,
  `serialization_id` 5 = DSSE, enum ids verified against ocsf-schema main 2026-07-31 —
  and the raw bytes + JWKS `kid` ride in `unmapped.signature_b64` /
  `unmapped.signature_key_id` pending
  [ocsf-schema#1709](https://github.com/ocsf/ocsf-schema/pull/1709). The demo key is
  generated at runtime from a fixed scalar (no key material in the repo); the `// verify`
  lines at the bottom are the example itself re-deriving everything from the emitted JSON
  and the public key alone.
- **`attestation.authority_uid` names the party the signing credential belongs to**
  (`org-f3576cf6`, matching the production reference bundle's demo org). It sits inside
  the hashed bytes, so the claimed authority cannot be swapped after the fact without
  breaking the fingerprint — and keys rotate, so this is the stable identifier a verifier
  checks the resolved JWKS key against.
- **`metadata.correlation_uid` is the run id** (`AgentExtension.conversation_id`; review
  C1): both events of this run carry `"conv-9"`, so a SIEM can join them. It sits on
  `metadata`, which is where OCSF defines it — it was previously emitted at the event root.
  The per-call `tool_call_id` rides at `api.request.uid`. `metadata.uid` identifies the
  record itself, and is what the next record's `prev_event.uid` points at.
- **Key ordering is alphabetical** because `serde_json::Map` is backed by a `BTreeMap` by
  default in Rust (the canonical hash bytes sort keys explicitly and do not rely on this).

```jsonc
// ===== OCSF event 1 — Invoke Tool (get_compensation) =====
{
  "action": "Observed",
  "action_id": 3,
  "activity_id": 99,
  "activity_name": "Invoke Tool",
  "actor": {
    "roles": [
      "hr"
    ],
    "user": {
      "groups": [
        "people-ops"
      ],
      "uid": "alice@corp.com"
    }
  },
  "ai_agent": {
    "conversation_uid": "conv-9",
    "instance_uid": "sess-42",
    "parent_uid": "orchestrator-1",
    "turn": 3,
    "uid": "agent-7"
  },
  "api": {
    "request": {
      "uid": "call-001"
    }
  },
  "attestation_list": [
    {
      "authority_uid": "org-f3576cf6",
      "chain_uid": "demo-chain-org-f3576cf6",
      "fingerprint": {
        "algorithm": "SHA-256",
        "algorithm_id": 3,
        "encoding": "Hex",
        "encoding_id": 1,
        "serialization": "JCS",
        "serialization_id": 2,
        "value": "25ed739d1fea4a60e64b2b61aacdc59b14a24b89e46ecedab2314917dce74d12"
      },
      "signatures": [
        {
          "algorithm": "ECDSA",
          "algorithm_id": 3,
          "serialization": "DSSE",
          "serialization_id": 5
        }
      ],
      "uid": "demo-chain-org-f3576cf6-att-000000"
    }
  ],
  "category_uid": 6,
  "class_uid": 6003,
  "delegation": {
    "actor_subject_uid": "agent-7",
    "chain": [
      {
        "audience": "workday-api",
        "scopes_granted": [
          "read_compensation"
        ],
        "subject_uid": "agent-7",
        "timestamp": "1970-01-01T00:00:00+00:00",
        "ttl_seconds": 300
      }
    ],
    "depth": 1,
    "origin_subject_uid": "alice@corp.com"
  },
  "disposition": "Logged",
  "disposition_id": 17,
  "metadata": {
    "correlation_uid": "conv-9",
    "product": {
      "name": "AI Identity OCSF Audit",
      "vendor_name": "AI Identity"
    },
    "profiles": [
      "ai_operation",
      "security_control",
      "record_integrity"
    ],
    "uid": "demo-chain-org-f3576cf6-000000",
    "version": "1.9.0-dev"
  },
  "severity_id": 1,
  "time": "2026-06-30T12:00:00.000Z",
  "tool": {
    "name": "get_compensation",
    "namespace": "hr",
    "uid": "call-001"
  },
  "type_uid": 600399,
  "unmapped": {
    "cmf.framework": {
      "framework": "langgraph",
      "framework_version": null,
      "graph_id": "graph-hr",
      "node_id": "node-compensation"
    },
    "cmf.mcp": {
      "tool": {
        "annotations": {},
        "name": "get_compensation",
        "namespace": "hr",
        "server_id": "hr-mcp"
      }
    },
    "cmf.security.labels": [
      "PII",
      "secret"
    ],
    "cmf.workload_identity": {
      "attested_at": null,
      "attestor": "gke-workload-identity",
      "spiffe_id": "spiffe://corp/agent/hr-bot",
      "trust_domain": "corp"
    },
    "signature_b64": "MEUCIQD89xutRcH/wFhwiRIIEV8mpyy3qzhPSwc4atxzSfJPYgIgD3JDploPrXZPxGGSeIF5LS5C860rccDCIMgXWtS1Vrs=",
    "signature_key_id": "demo-key-2026-07"
  }
}

// ===== OCSF event 2 — Completion (chained to event 1) =====
{
  "action": "Observed",
  "action_id": 3,
  "activity_id": 99,
  "activity_name": "Completion",
  "ai_agent": {
    "conversation_uid": "conv-9",
    "instance_uid": "sess-42",
    "parent_uid": null,
    "turn": 4,
    "uid": "agent-7"
  },
  "ai_model": {
    "name": "claude-opus-4-8"
  },
  "attestation_list": [
    {
      "authority_uid": "org-f3576cf6",
      "chain_uid": "demo-chain-org-f3576cf6",
      "fingerprint": {
        "algorithm": "SHA-256",
        "algorithm_id": 3,
        "encoding": "Hex",
        "encoding_id": 1,
        "serialization": "JCS",
        "serialization_id": 2,
        "value": "88376850d7518d2b8a2536e5e135b5e4f0235c15d1c70cb3ab8af9ba426260ca"
      },
      "prev_event": {
        "fingerprint": {
          "algorithm": "SHA-256",
          "algorithm_id": 3,
          "encoding": "Hex",
          "encoding_id": 1,
          "serialization": "JCS",
          "serialization_id": 2,
          "value": "25ed739d1fea4a60e64b2b61aacdc59b14a24b89e46ecedab2314917dce74d12"
        },
        "type_uid": 600399,
        "uid": "demo-chain-org-f3576cf6-000000"
      },
      "signatures": [
        {
          "algorithm": "ECDSA",
          "algorithm_id": 3,
          "serialization": "DSSE",
          "serialization_id": 5
        }
      ],
      "uid": "demo-chain-org-f3576cf6-att-000001"
    }
  ],
  "category_uid": 6,
  "class_uid": 6003,
  "disposition": "Logged",
  "disposition_id": 17,
  "duration": 842,
  "message_context": {
    "completion_tokens": 28,
    "prompt_tokens": 120,
    "total_tokens": 148
  },
  "metadata": {
    "correlation_uid": "conv-9",
    "product": {
      "name": "AI Identity OCSF Audit",
      "vendor_name": "AI Identity"
    },
    "profiles": [
      "ai_operation",
      "security_control",
      "record_integrity"
    ],
    "uid": "demo-chain-org-f3576cf6-000001",
    "version": "1.9.0-dev"
  },
  "severity_id": 1,
  "time": "2026-06-30T12:00:01.000Z",
  "type_uid": 600399,
  "unmapped": {
    "cmf.completion.stop_reason": "End",
    "signature_b64": "MEUCIQCsNtZsEFzBcAEmp+Vkg+y4bVLTaUqCyQiR27qPHrk1GwIgcGuddgH+Z34kMcqnQMHsqS5xTi/gqx0Eyx+Yrb349wY=",
    "signature_key_id": "demo-key-2026-07"
  }
}

// chain check: event2.prev_event.fingerprint == event1.fingerprint -> true
// chain check: event2.prev_event.uid == event1.metadata.uid   -> true
// verify event1: fingerprint recomputed -> true · DSSE signature -> true
// verify event2: fingerprint recomputed -> true · DSSE signature -> true
```
