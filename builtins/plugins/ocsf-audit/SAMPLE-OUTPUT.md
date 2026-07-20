# Sample output — `cargo run --example emit_sample`

Real OCSF events produced by the mapping in [`src/ocsf.rs`](src/ocsf.rs) from the two
demo turns in [`examples/emit_sample.rs`](examples/emit_sample.rs). Regenerated 2026-07-20
after the P0 / review-§4-B revision (production-readiness plan, 2026-07-17/18) — the
hashes changed accordingly. Notes on fidelity:

- **Host class is API Activity (6003)** with its real activity enum: a tool call without
  `readOnlyHint` is the honest `activity_id: 99` + source-defined `activity_name`
  ("Invoke Tool" / "Completion"); reads (resources, prompts, read-only-hinted tools) are
  `2 (Read)` with the normalized caption. `metadata.profiles` declares `ai_operation` +
  `security_control` (+ `record_integrity` when chained), and the passive stream carries
  `action_id: 3 (Observed)` / `disposition_id: 17 (Logged)` — deny/modify records arrive
  with the cpex-core decision event (WS-A / P1).
- **`entry_hash` commits to the record's chain position** (review §4-B): SHA-256 over the
  JCS-style canonical bytes of `{"chain_uid", "event", "prev_entry_hash"}` — the
  predecessor hash is part of the hashed input, not a back-pointer. An independent
  verifier strips `attestation` from an emitted event, rebuilds that binding object from
  the attestation's `chain_uid`/`prev_entry_hash`, canonicalizes
  (`sign::canonical_bytes` — sorted keys, compact, set-derived arrays sorted at build
  time; review C2), and recomputes. Output below — hashes included — is byte-identical
  across process runs.
- **`correlation_uid` is the run id** (`AgentExtension.conversation_id`; review C1): both
  events of this run carry `"conv-9"`, so a SIEM can join them on the standard base field.
  The per-call `tool_call_id` rides at `api.request.uid`.
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
  "attestation": {
    "chain_uid": "demo-chain-org-f3576cf6",
    "digital_signature": {
      "serialization_id": "NONE",
      "signed": false
    },
    "entry_hash": "sha256:3512c3592465569f02b2d69323bddf96ea1c992c0f72254573fdcb352cbabd39",
    "prev_entry_hash": null
  },
  "category_uid": 6,
  "class_uid": 6003,
  "correlation_uid": "conv-9",
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
    "product": {
      "name": "AI Identity OCSF Audit",
      "vendor_name": "AI Identity"
    },
    "profiles": [
      "ai_operation",
      "security_control",
      "record_integrity"
    ],
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
    }
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
  "attestation": {
    "chain_uid": "demo-chain-org-f3576cf6",
    "digital_signature": {
      "serialization_id": "NONE",
      "signed": false
    },
    "entry_hash": "sha256:7d99ca0c534a0ed5c9ca3d7fb3d3881c16d04e5345ed323ae43f00ea6b73e11a",
    "prev_entry_hash": "sha256:3512c3592465569f02b2d69323bddf96ea1c992c0f72254573fdcb352cbabd39"
  },
  "category_uid": 6,
  "class_uid": 6003,
  "correlation_uid": "conv-9",
  "disposition": "Logged",
  "disposition_id": 17,
  "duration": 842,
  "message_context": {
    "completion_tokens": 28,
    "prompt_tokens": 120,
    "total_tokens": 148
  },
  "metadata": {
    "product": {
      "name": "AI Identity OCSF Audit",
      "vendor_name": "AI Identity"
    },
    "profiles": [
      "ai_operation",
      "security_control",
      "record_integrity"
    ],
    "version": "1.9.0-dev"
  },
  "severity_id": 1,
  "time": "2026-06-30T12:00:01.000Z",
  "type_uid": 600399,
  "unmapped": {
    "cmf.completion.stop_reason": "End"
  }
}

// chain check: event2.prev_entry_hash == event1.entry_hash -> true
```
