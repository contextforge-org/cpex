// Location: ./crates/apl-pii-scanner/src/config.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor

use serde::{Deserialize, Serialize};

/// Plugin config — what operators write under
/// `plugins[<name>].config:` in unified-config YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiScannerConfig {
    /// Which patterns to detect. Defaults to `[ssn, credit_card]`
    /// which covers the common high-signal cases.
    #[serde(default = "default_detect")]
    pub detect: Vec<PiiPattern>,

    /// What to do when a match is found.
    #[serde(default)]
    pub mode: PiiScanMode,
}

fn default_detect() -> Vec<PiiPattern> {
    vec![PiiPattern::Ssn, PiiPattern::CreditCard]
}

/// Built-in PII pattern catalog. Patterns chosen for high signal-to-
/// noise on the kinds of values that flow through agent tool calls.
/// Operators can supply a custom regex via `PiiPattern::Custom`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PiiPattern {
    /// US Social Security Number: `NNN-NN-NNNN`.
    Ssn,
    /// Credit-card-like sequences (13-19 digits, optional separators).
    /// Note: does NOT Luhn-check — for v0 the regex match is enough
    /// to flag. Luhn validation is a future refinement.
    CreditCard,
    /// Email address. Surprisingly common false-positive risk —
    /// operators turn this off if their tools legitimately deal in
    /// email addresses (HR directory, contact lists).
    Email,
    /// Operator-supplied regex. Useful for company-specific IDs
    /// (employee IDs that aren't already public, internal account
    /// numbers, etc.).
    Custom { name: String, regex: String },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PiiScanMode {
    /// Return `pii.detected` violation — gateway translates to 403.
    /// The strictest mode; the request never reaches downstream.
    #[default]
    Deny,
    /// Replace each matching value with `[PII]` in the outbound
    /// payload. Lets the request through but with secrets neutered.
    Redact,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn defaults() {
        let cfg: PiiScannerConfig = serde_json::from_value(json!({})).unwrap();
        assert_eq!(cfg.detect.len(), 2);
        assert!(matches!(cfg.mode, PiiScanMode::Deny));
    }

    #[test]
    fn parse_full_config() {
        let raw = json!({
            "detect": [
                { "kind": "ssn" },
                { "kind": "custom", "name": "internal_id", "regex": "^INT-[A-Z0-9]{10}$" }
            ],
            "mode": "redact",
        });
        let cfg: PiiScannerConfig = serde_json::from_value(raw).unwrap();
        assert_eq!(cfg.detect.len(), 2);
        assert!(matches!(cfg.mode, PiiScanMode::Redact));
    }
}
