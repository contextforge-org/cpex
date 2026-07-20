// Location: ./builtins/plugins/ocsf-audit/src/sign.rs
// Copyright 2026 AI Identity
// SPDX-License-Identifier: Apache-2.0
//
// Signing seam for the attestation. The hash chain (entry_hash /
// prev_entry_hash) works with no signer at all; a signer adds the
// `signature` + `digital_signature` that make the record verifiable
// against an identity, offline.
//
// OCSF #1662 merged `digital_signature.serialization_id`, which is how
// a record declares its canonicalization (JCS / JWS / COSE / DSSE).
// We target DSSE.

use serde_json::Value;
use sha2::{Digest, Sha256};

/// JCS-style (RFC 8785) canonical serialization of an event.
///
/// This is what `entry_hash` and the signer consume, so an independent
/// verifier can recompute the hash from the emitted JSON without
/// depending on our serializer's internals (review C2). Guarantees:
///   * object keys sorted, compact output (no insignificant whitespace)
///     — explicitly, not via serde_json's default BTreeMap-backed Map
///     (a downstream workspace enabling serde_json's `preserve_order`
///     feature would silently switch that to insertion order);
///   * arrays serialized in the order given. Array order is semantic
///     in JSON (delegation chain, profiles), so the canonicalizer must
///     NOT sort them — instead, set-derived arrays (security labels,
///     roles, teams — HashSet/MonotonicSet, randomized iteration) are
///     sorted at build time in ocsf.rs, making the emitted event itself
///     canonical.
///
/// Caveats vs full RFC 8785: keys are sorted by Rust byte order, which
/// equals the mandated UTF-16 code-unit order for the ASCII key names
/// we emit; all numbers we emit are integers, where serde_json's
/// formatting matches the mandated ES6 form. Revisit both if non-ASCII
/// keys or floats ever enter the event shape.
pub fn canonical_bytes(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_canonical(v, &mut out);
    out
}

fn write_canonical(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Object(m) => {
            out.push(b'{');
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_unstable();
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                // serde_json string form = RFC 8785 escaping (two-char
                // escapes for control chars where defined, \u00XX else).
                out.extend_from_slice(
                    serde_json::to_string(k.as_str())
                        .expect("string")
                        .as_bytes(),
                );
                out.push(b':');
                write_canonical(&m[k.as_str()], out);
            }
            out.push(b'}');
        },
        Value::Array(a) => {
            out.push(b'[');
            for (i, el) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(el, out);
            }
            out.push(b']');
        },
        leaf => out.extend_from_slice(serde_json::to_string(leaf).expect("leaf").as_bytes()),
    }
}

/// Compute the entry hash over canonical bytes (callers obtain them via
/// `canonical_bytes`). Since the §4-B fix (2026-07-20) the emitter
/// passes the canonical bytes of the chain-binding object
/// `{chain_uid, event, prev_entry_hash}` — not the bare event — so the
/// hash commits to the record's position in its chain; the signer
/// consumes the same bytes.
pub fn entry_hash(canonical_bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(canonical_bytes);
    format!("sha256:{:x}", h.finalize())
}

/// Result of signing: the detached signature and the OCSF
/// `digital_signature` descriptor to embed alongside it.
pub struct Signed {
    pub signature: String,
    pub digital_signature: serde_json::Value,
}

pub trait OcsfSigner: Send + Sync {
    fn sign(&self, canonical_bytes: &[u8]) -> Option<Signed>;
    /// Value for `attestation.digital_signature.serialization_id`.
    fn serialization_id(&self) -> &'static str;
}

/// No-op: hash-chained but unsigned. Default for demo / unprovisioned.
pub struct NoopSigner;

impl OcsfSigner for NoopSigner {
    fn sign(&self, _canonical_bytes: &[u8]) -> Option<Signed> {
        None
    }
    fn serialization_id(&self) -> &'static str {
        "NONE"
    }
}

/// DSSE signer — STUB. Wire to AI Identity's existing DSSE/key
/// machinery (the same path the gateway uses to sign OCSF
/// attestations today). Until then it behaves like NoopSigner so the
/// plugin still runs.
pub struct DsseSigner {
    // TODO: key handle / signer client.
}

impl DsseSigner {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for DsseSigner {
    fn default() -> Self {
        Self::new()
    }
}

impl OcsfSigner for DsseSigner {
    fn sign(&self, _canonical_bytes: &[u8]) -> Option<Signed> {
        // TODO: produce a DSSE envelope over canonical_bytes and return
        // the signature + a digital_signature descriptor with
        // serialization_id = "DSSE". Returning None keeps the chain
        // intact-but-unsigned until the key is wired.
        None
    }
    fn serialization_id(&self) -> &'static str {
        "DSSE"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_form_is_sorted_and_compact() {
        // Build with unsorted key insertion; canonical output must be
        // key-sorted, compact, and nest-stable.
        let v = json!({
            "z": [3, 1, 2],                    // array order preserved
            "a": { "y": "b", "x": true },      // nested keys sorted
            "m": null,
        });
        assert_eq!(
            String::from_utf8(canonical_bytes(&v)).unwrap(),
            r#"{"a":{"x":true,"y":"b"},"m":null,"z":[3,1,2]}"#
        );
    }

    #[test]
    fn entry_hash_is_reproducible_from_canonical_bytes() {
        let v = json!({ "b": 1, "a": ["PII", "secret"] });
        let h1 = entry_hash(&canonical_bytes(&v));
        let h2 = entry_hash(&canonical_bytes(&v.clone()));
        assert_eq!(h1, h2);
        assert!(h1.starts_with("sha256:"));
    }
}
