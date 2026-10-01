# cpex-plugin-ocsf-audit

A CMF plugin that emits each dispatched request as an **OCSF API Activity event**
(class 6003, `ai_operation` + `security_control` profiles) — optionally wrapped in a
tamper-evident **attestation chain** (`record_integrity` profile) that an
independent party can verify offline.

It is a near-twin of the [`audit-logger`](../audit-logger) builtin — same
observation-only, always-allow contract, same factory + hook wiring. The difference is
the record shape:

| | `audit-logger` | `ocsf-audit` (this crate) |
|---|---|---|
| Output | free-form JSON line | OCSF API Activity event |
| Verifiability | none | hash chain (`fingerprint` → `prev_event`), DSSE-signed (ECDSA P-256) |
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
      chain: true                # tamper-evident fingerprint chain
      signing: dsse              # or: none (chained-but-unsigned)
      signing_key_pem_path: /etc/cpex/keys/ocsf-signing.pem  # PKCS#8 P-256
      signing_key_id: "prod-2026-07"   # JWKS kid -> unmapped.signature_key_id
      authority_uid: "org-example"     # the party the signing key belongs to
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
  framework to surface its decision to a plugin — the AuditHook design
  (2026-07-31) is that seam; not in this crate yet.
- **Gap fields** with no OCSF home yet (`completion.stop_reason`, `mcp.*`,
  `framework.*`, monotonic security labels, workload identity) are emitted under
  OCSF `unmapped` (config `include_gap_fields`, default on), which preserves the
  evidence and makes the open schema gaps self-documenting. Upstream OCSF issues for
  these gaps are being filed.

## The attestation chain

With `chain: true`, every event carries an `attestation_list[]` entry in the merged
OCSF 1.9 `record_integrity` shape (`fingerprint` / `prev_event` / `signatures`
objects), with **predecessor binding**: the fingerprint commits to the record's
position in its chain, not just its content.

```
fingerprint.value = sha256( canonical_bytes( event ) )
  where `event` includes the attestation's own chain_uid and prev_event,
  and excludes only the fingerprint and signatures members
```

`canonical_bytes` is a JCS-style (RFC 8785) canonical serialization (sorted keys,
compact output; set-derived arrays are sorted at build time), so a verifier following
the OCSF schema can recompute the chain from the emitted JSON alone — no access to
this process, no shared secret, no knowledge of this crate's conventions. Tampering
with any record, reordering records, or splicing a record into a different chain
breaks recomputation at that entry.

**Signing** (`signing: dsse`) produces ECDSA-P256-SHA256 over the DSSE PAE of the
same canonical bytes the fingerprint covers, so a signature commits to the record's
chain position. Signing is deterministic (RFC 6979), which keeps `SAMPLE-OUTPUT.md`
byte-identical across runs. The key is an operator-provided PKCS#8 PEM
(`signing_key_pem` / `signing_key_pem_path`) — a key handle, not a key service:
custody (HSM/KMS residency, rotation, key publication) belongs to the authority named
by `attestation.authority_uid`, which sits inside the hashed bytes so the claimed
authority cannot be swapped post-hoc. Signature bytes + key id ride `unmapped`
(`signature_b64`, `signature_key_id`) pending a schema home via
[ocsf-schema#1709](https://github.com/ocsf/ocsf-schema/pull/1709). A configured
signer that fails to construct is a loud startup error — never silently-unsigned
records. The verifier rule ships as running code: `sign::signing_input` +
`sign::dsse_pae`, exercised end-to-end by the `signed_event_verifies_offline` test
and printed as the `// verify` lines of the example.

Known limitation (tracked for productionization): the chain head lives in process
memory — one chain per plugin instance, reset on restart. A durable-append sink with
WAL replay (per the 2026-07-31 audit design, §6) retires this: recover the last
fingerprint on restart and continue the chain.

## Building and testing

```bash
cargo build -p cpex-plugin-ocsf-audit
cargo test  -p cpex-plugin-ocsf-audit
cargo run   -p cpex-plugin-ocsf-audit --example emit_sample
```

`SAMPLE-OUTPUT.md` holds the deterministic output of the example — two chained,
signed events with reproducible hashes and signatures.
