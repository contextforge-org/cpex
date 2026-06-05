// Location: ./crates/apl-audit-logger/src/config.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditLoggerConfig {
    /// Where audit records go. Stderr is the default — convenient
    /// for the demo (`docker compose logs -f`) and for k8s sidecar
    /// log forwarding. Tracing routes through whatever subscriber
    /// the host installed.
    #[serde(default)]
    pub destination: AuditDestination,

    /// Optional sink name — surfaces in every record so a single
    /// audit collector can distinguish multiple deployments. Free-
    /// form string.
    #[serde(default)]
    pub source: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditDestination {
    /// Write one JSON line per call to stderr.
    #[default]
    Stderr,
    /// Emit via `tracing::info!` at target `apl.audit`. Routed by
    /// the host's subscriber to wherever traces normally go.
    Tracing,
}
