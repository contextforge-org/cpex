// Location: ./builtins/plugins/delegator-biscuit/src/config.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Typed configuration for `BiscuitDelegator`.

use std::path::PathBuf;

use biscuit_auth::PublicKey;
use serde::{Deserialize, Serialize};

/// Plugin config — what operators write under
/// `plugins[<name>].config:` in unified-config YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiscuitDelegatorConfig {
    /// The root public key the inbound biscuit was signed against.
    /// Verification fails if the inbound's authority-block signature
    /// doesn't validate under this key.
    pub root_public_key: PublicKeySource,

    /// Header name the forwarding plugin should attach the minted
    /// token under. Most downstream services expect
    /// `Authorization` or a custom `X-AIP-Token`-style header.
    #[serde(default = "default_outbound_header")]
    pub default_outbound_header: String,

    /// Default TTL for the appended delegation block, in seconds.
    /// Per-call overrides come from `AttenuationConfig.ttl_seconds`
    /// on the `DelegationPayload`.
    #[serde(default = "default_ttl_seconds")]
    pub default_ttl_seconds: u64,
}

/// Where the root public key is loaded from. Three modes:
///
///   * **`hex`** — 32-byte Ed25519 public key encoded as 64 hex
///     characters. Convenient for testing and dev configs.
///   * **`file`** — path to a file containing the raw 32-byte key
///     (binary) or its hex encoding (with optional newline). The
///     resolver auto-detects which.
///   * **`bytes`** — inline 32-byte raw key. Rarely used directly
///     in YAML (operators prefer hex or file) but available for
///     programmatic construction.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PublicKeySource {
    Hex { hex: String },
    File { path: PathBuf },
    Bytes { bytes: Vec<u8> },
}

fn default_outbound_header() -> String {
    "Authorization".to_string()
}

fn default_ttl_seconds() -> u64 {
    300
}

impl PublicKeySource {
    /// Turn the serializable source into a runtime `PublicKey`.
    /// Returns a string error so the caller wraps in
    /// `PluginError::Config` with context.
    pub fn resolve(&self) -> Result<PublicKey, String> {
        match self {
            Self::Hex { hex } => {
                let bytes = hex::decode(hex.trim())
                    .map_err(|e| format!("public_key.hex isn't valid hex: {e}"))?;
                Self::bytes_to_public_key(&bytes)
            },
            Self::Bytes { bytes } => Self::bytes_to_public_key(bytes),
            Self::File { path } => {
                let raw = std::fs::read(path)
                    .map_err(|e| format!("public_key file '{}' unreadable: {e}", path.display()))?;
                // File might be raw 32 bytes OR a hex string (with
                // optional whitespace). Try raw first; fall back to
                // hex if the length doesn't match.
                if raw.len() == 32 {
                    Self::bytes_to_public_key(&raw)
                } else {
                    // Treat as hex with possible whitespace.
                    let as_str = std::str::from_utf8(&raw).map_err(|e| {
                        format!(
                            "public_key file '{}' isn't 32 raw bytes or valid \
                             UTF-8 hex: {e}",
                            path.display()
                        )
                    })?;
                    let trimmed = as_str.trim();
                    let bytes = hex::decode(trimmed).map_err(|e| {
                        format!("public_key file '{}' isn't valid hex: {e}", path.display())
                    })?;
                    Self::bytes_to_public_key(&bytes)
                }
            },
        }
    }

    fn bytes_to_public_key(bytes: &[u8]) -> Result<PublicKey, String> {
        if bytes.len() != 32 {
            return Err(format!(
                "Ed25519 public key must be 32 bytes; got {}",
                bytes.len()
            ));
        }
        PublicKey::from_bytes(bytes, biscuit_auth::Algorithm::Ed25519)
            .map_err(|e| format!("public key bytes not a valid Ed25519 key: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use biscuit_auth::KeyPair;

    #[test]
    fn hex_source_resolves() {
        let kp = KeyPair::new();
        let pub_hex = hex::encode(kp.public().to_bytes());
        let src = PublicKeySource::Hex { hex: pub_hex };
        assert!(src.resolve().is_ok());
    }

    #[test]
    fn hex_source_rejects_wrong_length() {
        let src = PublicKeySource::Hex {
            hex: "deadbeef".into(), // 4 bytes — wrong length
        };
        let err = src.resolve().unwrap_err();
        assert!(err.contains("32 bytes"));
    }

    #[test]
    fn hex_source_rejects_garbage() {
        let src = PublicKeySource::Hex {
            hex: "not hex".into(),
        };
        let err = src.resolve().unwrap_err();
        assert!(err.contains("hex"));
    }

    #[test]
    fn config_deserializes() {
        let kp = KeyPair::new();
        let pub_hex = hex::encode(kp.public().to_bytes());
        let raw = serde_json::json!({
            "root_public_key": { "kind": "hex", "hex": pub_hex },
            "default_outbound_header": "X-AIP-Token",
            "default_ttl_seconds": 60,
        });
        let cfg: BiscuitDelegatorConfig = serde_json::from_value(raw).unwrap();
        assert_eq!(cfg.default_outbound_header, "X-AIP-Token");
        assert_eq!(cfg.default_ttl_seconds, 60);
        assert!(cfg.root_public_key.resolve().is_ok());
    }
}
