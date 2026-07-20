// Location: ./builtins/plugins/ocsf-audit/src/config.rs
// Copyright 2026 AI Identity
// SPDX-License-Identifier: Apache-2.0
//
// Operator-facing config for the OCSF audit plugin. Mirrors the
// upstream audit-logger's config style (serde, snake_case enums,
// stderr default) and adds OCSF/attestation knobs.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OcsfAuditConfig {
    /// Where OCSF events go. Stderr default keeps the demo flow
    /// (`docker compose logs -f | jq`) identical to audit-logger.
    #[serde(default)]
    pub destination: OcsfDestination,

    /// Populates OCSF `metadata.product` so a single collector can
    /// attribute events to a deployment.
    #[serde(default = "default_product_name")]
    pub product_name: String,

    /// Populates OCSF `metadata.product.vendor_name`.
    #[serde(default = "default_vendor_name")]
    pub vendor_name: String,

    /// When true, wrap every event in an attestation: compute an
    /// `entry_hash` over the canonical event and thread the previous
    /// event's hash into `prev_entry_hash`, forming a tamper-evident
    /// chain. This is the integrity seam from the field map.
    #[serde(default = "default_true")]
    pub chain: bool,

    /// Stable identifier for this attestation chain (OCSF
    /// `attestation.chain_uid`). If absent, a process-lifetime random
    /// uid is generated at startup.
    #[serde(default)]
    pub chain_uid: Option<String>,

    /// Signing mode for the attestation. `none` produces an unsigned
    /// (but still hash-chained) record; `dsse` is the production mode
    /// and declares `digital_signature.serialization_id = DSSE`.
    #[serde(default)]
    pub signing: SigningMode,

    /// When true (default), gap fields that have no native OCSF home
    /// yet — `completion.stop_reason`, `mcp.*`, `framework.*`,
    /// monotonic security labels — are emitted under OCSF `unmapped`
    /// rather than dropped. This is deliberate: it preserves evidence
    /// AND surfaces exactly which WS4/OCSF gaps the plugin had to work
    /// around. See CMF-OCSF-FIELD-MAP.md §5.
    #[serde(default = "default_true")]
    pub include_gap_fields: bool,
}

fn default_product_name() -> String {
    "AI Identity OCSF Audit".to_string()
}
fn default_vendor_name() -> String {
    "AI Identity".to_string()
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OcsfDestination {
    /// One OCSF JSON object per line to stderr.
    #[default]
    Stderr,
    /// Emit via `tracing::info!` at target `ocsf.audit`.
    Tracing,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningMode {
    /// Hash-chained but unsigned. Useful for the demo and for
    /// environments where the signing key isn't provisioned yet.
    #[default]
    None,
    /// DSSE-signed (merged in OCSF #1662 via
    /// `digital_signature.serialization_id`). Requires a key — see
    /// sign.rs. Currently a stub.
    Dsse,
}
