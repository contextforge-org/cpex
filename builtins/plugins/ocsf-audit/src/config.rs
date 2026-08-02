// Location: ./builtins/plugins/ocsf-audit/src/config.rs
// Copyright 2026 AI Identity
// SPDX-License-Identifier: Apache-2.0
// Authors: Jeff Leva
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

    /// When true, attach an attestation to every event: compute a
    /// `fingerprint` over the canonical event and reference the previous
    /// event through `prev_event` (its uid, type_uid and fingerprint),
    /// forming a tamper-evident chain. This is the integrity seam from
    /// the field map, and it declares the `record_integrity` profile.
    #[serde(default = "default_true")]
    pub chain: bool,

    /// Stable identifier for this attestation chain (OCSF
    /// `attestation.chain_uid`). If absent, a process-lifetime random
    /// uid is generated at startup.
    #[serde(default)]
    pub chain_uid: Option<String>,

    /// Signing mode for the attestation. `none` produces an unsigned
    /// (but still hash-chained) record — valid under the merged shape,
    /// whose `at_least_one(fingerprint, signatures)` constraint the
    /// fingerprint alone satisfies. `dsse` is the production mode and
    /// declares `signatures[0].serialization_id = DSSE`; it REQUIRES a
    /// key via exactly one of `signing_key_pem` /
    /// `signing_key_pem_path` — a missing key fails construction loudly
    /// rather than silently emitting unsigned records.
    #[serde(default)]
    pub signing: SigningMode,

    /// Inline PKCS#8 P-256 private key PEM for `signing: dsse`.
    /// Mutually exclusive with `signing_key_pem_path`. Inline is for
    /// tests/demos and secret-manager injection; operators with a key
    /// file should prefer the path form.
    #[serde(default)]
    pub signing_key_pem: Option<String>,

    /// Path to a PKCS#8 P-256 private key PEM for `signing: dsse`.
    /// Mutually exclusive with `signing_key_pem`.
    #[serde(default)]
    pub signing_key_pem_path: Option<String>,

    /// Key identifier (JWKS `kid`) stamped at
    /// `unmapped.signature_key_id`, so a verifier can resolve the
    /// public key from the authority's published key set. Rides in
    /// `unmapped` (outside the hashed bytes, like the signature itself)
    /// until ocsf-schema#1709 gives signature material a schema home.
    #[serde(default)]
    pub signing_key_id: Option<String>,

    /// OCSF `attestation.authority_uid` — identifies the authority the
    /// signing credential belongs to. Signing keys rotate and expire;
    /// this is the stable party identifier a verifier checks the
    /// resolved key AGAINST, which is what defeats an
    /// otherwise-valid-credential substitution. Part of the hashed
    /// canonical serialization (merged #1661 semantics), so it cannot
    /// be swapped after the fact without breaking the fingerprint.
    /// `recommended` in the schema; set it whenever signing is on.
    #[serde(default)]
    pub authority_uid: Option<String>,

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
    /// `digital_signature.serialization_id`; DSSE = 5, verified against
    /// ocsf-schema main 2026-07-31). ECDSA-P256-SHA256 over the PAE of
    /// the event's canonical bytes — see sign.rs. Requires a key.
    Dsse,
}
