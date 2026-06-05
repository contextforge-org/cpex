// Location: ./crates/apl-audit-logger/src/lib.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// apl-audit-logger — CMF plugin that emits one structured JSON
// audit record per dispatched request. The record captures:
//
//   * timestamp + correlation id
//   * subject (id, roles, teams) and client (client_id, name)
//   * entity (type + name) and tool args summary
//   * delegation outcomes (which audiences got tokens, which
//     scopes were granted)
//
// Mode: always allow — the plugin is observation-only. Operators
// who want to halt on audit failure would compose this with a
// downstream policy step.
//
// Output:
//
//   * `destination: stderr` (default) — one JSON line per call,
//     handy for the demo's `docker compose logs -f` flow.
//   * `destination: tracing` — emit as a structured `tracing::info!`
//     so it lands in whatever the host's subscriber routes to.
//
// Capabilities the plugin declares (operator wires them in YAML
// under `capabilities:`):
//
//   * `read_subject`           — for sub / roles / teams / claims
//   * `read_client`            — for client_id / client_name
//   * `read_meta`              — for entity_type / entity_name
//   * `read_delegated_tokens`  — to surface what got minted

pub mod config;
pub mod factory;
pub mod logger;

pub use config::{AuditDestination, AuditLoggerConfig};
pub use factory::{AuditLoggerFactory, KIND};
pub use logger::AuditLogger;
