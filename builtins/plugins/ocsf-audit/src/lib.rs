// Location: ./builtins/plugins/ocsf-audit/src/lib.rs
// Copyright 2026 AI Identity
// SPDX-License-Identifier: Apache-2.0
// Authors: Jeff Leva
//
// cpex-plugin-ocsf-audit — CMF plugin that emits one OCSF AI Operation
// event per dispatched request, off the CPEX `run(audit-log)` seam.
//
// It is a near-twin of the upstream `audit-logger` builtin (same
// observation-only, always-allow contract, same factory + hook wiring).
// The difference is the record shape: instead of a free-form JSON line,
// it serializes the CMF `Message` + `Extensions` into an OCSF event,
// following docs/cosai-ws4-ocsf-mapping/CMF-OCSF-FIELD-MAP.md, then
// (optionally) attaches a tamper-evident attestation chain
// (fingerprint → prev_event.fingerprint) and signs it.
//
// Why this exists: it makes CPEX's enforcement record interoperable
// (OCSF) and independently verifiable (signed attestation chain),
// without CPEX having to own a schema. CPEX produces the event; this
// plugin makes it portable and verifiable offline.
//
// CMF = ContextForge Message Format (per cpex-core/src/cmf/mod.rs).
//
// Status: builds green against cpex@feat/hil_apl `ad666ba` (cargo build
// + cargo test; Teryl's review baseline, 2026-07-06). The Extension
// field reads and ContentPart variant shapes are confirmed against that
// commit. Review corrections applied 2026-07-06 (see
// docs/cosai-ws4-ocsf-mapping/cmf-ocsf-mapping-review.md): prompt hooks
// register on cmf.prompt_*_invoke (C6 — the _fetch names silently never
// fire), correlation_uid mirrors the run id (C1), and events are
// JCS-style canonically serialized so the fingerprint chain verifies
// independently (C2 caveat).
//
// Revision 2026-07-20 (P0 + review §4-B, per the production-readiness
// plan agreed 2026-07-17/18): host class is now API Activity (6003) with
// its real activity enum (CRUD via readOnlyHint, else 99 + source name);
// metadata.profiles declares ai_operation + security_control (+
// record_integrity when chained) and the passive stream carries
// action_id 3 (Observed) / disposition_id 17 (Logged); and the hash
// commits to the record's chain position — predecessor binding, not a
// back-pointer. Remaining by design: deny/modify records (action_id
// 2/4) wait on the cpex-core decision event (WS-A / P1).
//
// Revision 2026-07-31 — MERGED #1661 SHAPE. PR #1661 merged upstream
// 2026-07-17 (`2a244bc9`), and the emitted attestation now matches it:
// `attestation_list[]` carrying `fingerprint` / `prev_event` /
// `signatures` objects, replacing the draft `attestation` member with
// string `entry_hash` / `prev_entry_hash` / singular `signature`. The
// fingerprint is computed per the merged semantics — over the whole
// event including the attestation's own uid/chain_uid/prev_event and
// excluding only fingerprint/signatures — so a verifier following the
// schema can reproduce it without knowing anything about this crate.
// `metadata.uid` is now emitted (prev_event references point at it) and
// `correlation_uid` moved to `metadata`, which is where OCSF defines
// it. Signature bytes ride in `unmapped.signature_b64` pending
// ocsf-schema#1709.
//
// Revision 2026-07-31 (same day, later) — SIGNER WIRED + authority_uid.
// `sign::DsseSigner` is real: ECDSA-P256-SHA256 over the DSSE PAE of
// the fingerprint's canonical bytes (RFC 6979 deterministic), key
// operator-provided as PKCS#8 PEM, loud config failure when missing.
// `attestation.authority_uid` (recommended in the merged schema) names
// the party the signing credential belongs to and sits INSIDE the
// hashed bytes. Verifier rule is running code: `sign::signing_input` +
// `sign::dsse_pae`. Key custody (HSM/KMS, rotation epochs, JWKS
// publication) is deliberately out of plugin scope — it belongs to the
// operating authority.

pub mod config;
pub mod emitter;
pub mod factory;
pub mod ocsf;
pub mod sign;

pub use config::{OcsfAuditConfig, OcsfDestination, SigningMode};
pub use emitter::OcsfAuditEmitter;
pub use factory::{OcsfAuditFactory, KIND};
