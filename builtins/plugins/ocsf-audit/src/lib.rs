// Location: ./builtins/plugins/ocsf-audit/src/lib.rs
// Copyright 2026 AI Identity
// SPDX-License-Identifier: Apache-2.0
//
// cpex-plugin-ocsf-audit — CMF plugin that emits one OCSF AI Operation
// event per dispatched request, off the CPEX `run(audit-log)` seam.
//
// It is a near-twin of the upstream `audit-logger` builtin (same
// observation-only, always-allow contract, same factory + hook wiring).
// The difference is the record shape: instead of a free-form JSON line,
// it serializes the CMF `Message` + `Extensions` into an OCSF event,
// following the CMF→OCSF field map (shared review doc), then
// (optionally) wraps it in a tamper-evident attestation chain
// (entry_hash → prev_entry_hash) and signs it.
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
// the CMF↔OCSF mapping review): prompt hooks
// register on cmf.prompt_*_invoke (C6 — the _fetch names silently never
// fire), correlation_uid mirrors the run id (C1), and events are
// JCS-style canonically serialized so the entry_hash chain verifies
// independently (C2 caveat).
//
// Revision 2026-07-20 (P0 + review §4-B, per the production-readiness
// plan agreed 2026-07-17/18): host class is now API Activity (6003) with
// its real activity enum (CRUD via readOnlyHint, else 99 + source name);
// metadata.profiles declares ai_operation + security_control (+
// record_integrity when chained) and the passive stream carries
// action_id 3 (Observed) / disposition_id 17 (Logged); and entry_hash
// now commits to (chain_uid, event, prev_entry_hash) — predecessor
// binding, not a back-pointer. Remaining by design: the DSSE signer is
// a stub (the hash chain works unsigned), and deny/modify records
// (action_id 2/4) wait on the cpex-core decision event (WS-A / P1).

pub mod config;
pub mod emitter;
pub mod factory;
pub mod ocsf;
pub mod sign;

pub use config::{OcsfAuditConfig, OcsfDestination, SigningMode};
pub use emitter::OcsfAuditEmitter;
pub use factory::{OcsfAuditFactory, KIND};
