# cpex-plugin-ocsf-audit

A CMF plugin that emits each dispatched request as an **OCSF API Activity event**
(class 6003, `ai_operation` + `security_control` profiles) — optionally wrapped in a
tamper-evident **attestation chain** (`record_integrity` profile shape) that an
independent party can verify offline.

It is a near-twin of the [`audit-logger`](../audit-logger) builtin — same
observation-only, always-allow contract, same factory + hook wiring. The difference is
the record shape:

| | `audit-logger` | `ocsf-audit` (this crate) |
|---|---|---|
| Output | free-form JSON line | OCSF API Activity event |
| Verifiability | none | hash chain with predecessor binding, DSSE-ready |
| Schema | ad hoc | OCSF — interoperable across tools |

CPEX produces the enforcement record; this plugin makes it portable (OCSF) and
independently verifiable (attestation chain) without CPEX having to own a schema.

## Wiring (APL)

```yaml
plugins:
  - name: ocsf-audit
    kind: audit/ocsf
    hooks:                       # POST hooks: result/taint/delegation resolved
      - cmf.tool_post_invoke
      - cmf.llm_output
      - cmf.resource_post_fetch
      - cmf.prompt_post_invoke   # NOT cmf.prompt_post_fetch — see note below
    config:
      destination: stderr        # or: tracing
      chain: true                # tamper-evident entry_hash chain
      signing: none              # or: dsse (stub until a signer is provisioned)
      chain_uid: "org-example"   # stable chain id across the deployment
```

> **Prompt hook name.** `cpex-core` ships two prompt-hook vocabularies:
> `hooks/types.rs` has `cmf.prompt_pre/post_fetch`, but the Rust CMF/APL runtime
> dispatches the `cmf/constants.rs` names `cmf.prompt_pre/post_invoke`. A Rust CMF
> plugin must register on the `_invoke` names or prompt events silently never fire.
> (The resource hook names agree across both files — only prompt diverges.)

## Record shape

- **Host class:** API Activity (`class_uid: 6003`, `category_uid: 6`), carrying the
  `ai_operation` profile objects (`ai_agent`, `ai_model`, `message_context`) plus
  `delegation`, actor/user, and tool/resource coordinates.
- **Activity ids** follow API Activity's real enum. Resources, prompts, and tools
  annotated `readOnlyHint: true` map to `2 (Read)`; other tool invocations are the
  honest `99 (Other)` + `activity_name: "Invoke Tool"` (no Create/Update/Delete claim
  without knowing the operation); completions are `99` + `"Completion"`.
- **security_control:** this passive post-hook stream is `action_id: 3 (Observed)` /
  `disposition_id: 17 (Logged)`. Deny/modify records (`action_id` 2/4) require the
  framework to surface its decision to a plugin — planned, not in this crate yet.
- **Gap fields** with no OCSF home yet (`completion.stop_reason`, `mcp.*`,
  `framework.*`, monotonic security labels, workload identity) are emitted under
  OCSF `unmapped` (config `include_gap_fields`, default on), which preserves the
  evidence and makes the open schema gaps self-documenting. Upstream OCSF issues for
  these gaps are being filed.

## The attestation chain

With `chain: true`, every event is wrapped in an attestation with **predecessor
binding**: the entry hash commits to the record's position in its chain, not just its
content.

```
entry_hash = sha256( canonical_bytes( {
    "chain_uid":       <configured chain id>,
    "event":           <the emitted event, minus its `attestation` member>,
    "prev_entry_hash": <previous entry_hash, or null for the first record>
} ) )
```

`canonical_bytes` is a JCS-style (RFC 8785) canonical serialization (sorted keys,
compact output; set-derived arrays are sorted at build time), so an independent
verifier can recompute the chain from the emitted JSON alone — no access to this
process, no shared secret. Tampering with any record, reordering records, or splicing
a record into a different chain breaks recomputation at that entry.

Signing is a seam (`sign::OcsfSigner`): `signing: none` emits chained-but-unsigned
records; the `dsse` mode is a stub pending signer provisioning (detached DSSE over the
same canonical binding bytes, so a signature commits to chain position). A provisioned
signer that fails must mark the record loudly (`signed: false` + reason), never
silently unsigned.

Known limitation (tracked for productionization): the chain head lives in process
memory — one chain per plugin instance, reset on restart. Durable / replica-safe
chaining and checkpoint signing are part of the production-readiness plan.

## Building and testing

```bash
cargo build -p cpex-plugin-ocsf-audit
cargo test  -p cpex-plugin-ocsf-audit
cargo run   -p cpex-plugin-ocsf-audit --example emit_sample
```

`SAMPLE-OUTPUT.md` holds the deterministic output of the example — two chained events
with reproducible hashes.
