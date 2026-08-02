// Location: ./builtins/plugins/ocsf-audit/src/sign.rs
// Copyright 2026 AI Identity
// SPDX-License-Identifier: Apache-2.0
// Authors: Jeff Leva
//
// Signing seam for the attestation. The hash chain (fingerprint /
// prev_event) works with no signer at all; a signer adds the
// `signatures` entry that makes the record verifiable against an
// identity, offline.
//
// OCSF #1662 merged `digital_signature.serialization_id`, which is how
// a record declares its signing envelope. Enum ids verified against
// ocsf-schema main 2026-07-31: 1 Flat · 2 JCS · 3 JWS · 4 COSE ·
// 5 DSSE; and `digital_signature.algorithm_id` 3 = ECDSA (a different
// enum than `fingerprint.algorithm_id`, where 3 = SHA-256 — same
// number, different meaning; don't conflate them).
//
// We emit DSSE (serialization_id 5): the signature is ECDSA-P256-SHA256
// over the DSSE PAE of the event's canonical bytes — the SAME bytes the
// fingerprint covers (event with the attestation's uid / chain_uid /
// authority_uid / prev_event present, fingerprint / signatures absent).
// So the signature commits to the record's chain position, and a
// verifier needs exactly three things: the emitted JSON, the public
// key, and this file's documented PAE rule.
//
// Shape note (2026-07-31): this targets the MERGED #1661 shape —
// `attestation_list[]` carrying `fingerprint` / `prev_event` /
// `signatures` objects. The pre-merge draft shape (string `entry_hash`,
// `prev_entry_hash`, singular `signature`) is gone from the schema.

use base64::Engine;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::SigningKey;
use p256::pkcs8::DecodePrivateKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// JCS-style (RFC 8785) canonical serialization of an event.
///
/// This is what the fingerprint and the signer consume, so an independent
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
                // We emit `fingerprint.serialization_id = 2` (JCS), which
                // tells a verifier to reproduce these bytes with a real
                // RFC 8785 library. That claim holds only for the value
                // space documented on `canonical_bytes` — ASCII keys
                // (byte order == UTF-16 code-unit order) and integer
                // numbers. Assert it rather than leave it a convention,
                // so the claim cannot go quietly false if the event
                // shape grows a non-ASCII key.
                debug_assert!(
                    k.is_ascii(),
                    "non-ASCII key {k:?} breaks the JCS (serialization_id 2) claim — \
                     sort by UTF-16 code units or drop to 99/Other"
                );
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
        // Same reasoning as the key assertion above: serde_json's integer
        // formatting matches RFC 8785, its float formatting does not.
        Value::Number(n) => {
            debug_assert!(
                n.is_i64() || n.is_u64(),
                "non-integer number {n} breaks the JCS (serialization_id 2) claim — \
                 RFC 8785 mandates the ES6 float form"
            );
            out.extend_from_slice(serde_json::to_string(n).expect("number").as_bytes());
        },
        leaf => out.extend_from_slice(serde_json::to_string(leaf).expect("leaf").as_bytes()),
    }
}

/// Compute the fingerprint value over canonical bytes (callers obtain
/// them via `canonical_bytes`).
///
/// Returns bare lowercase hex — no `sha256:` prefix. The algorithm is
/// declared by the sibling `fingerprint.algorithm_id` (3 = SHA-256) and
/// the representation by `fingerprint.encoding_id` (1 = Hex), so a
/// prefix inside `value` would both duplicate that and break a verifier
/// decoding `value` per `encoding_id`.
///
/// Per the merged `attestation` semantics, the emitter passes the
/// canonical bytes of the WHOLE EVENT with its `attestation_list[0]`
/// present and carrying `uid` / `chain_uid` / `authority_uid` /
/// `prev_event`, but with `fingerprint` and `signatures` absent. So the
/// record's position in its chain is inside the hashed input (a spliced
/// or reordered record changes its own fingerprint), and the signer
/// consumes the same bytes.
pub fn fingerprint_value(canonical_bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(canonical_bytes);
    format!("{:x}", h.finalize())
}

/// Reconstruct, from an EMITTED event, the exact bytes its fingerprint
/// and signature were computed over. This is the verifier rule as
/// running code:
///
///   1. remove `attestation_list[0].fingerprint` and `.signatures`
///      (the schema's own exclusions);
///   2. remove `unmapped.signature_b64` / `unmapped.signature_key_id` —
///      the signature bytes have no `digital_signature` home until
///      ocsf-schema#1709 lands, so they ride in `unmapped`, and being
///      derived FROM the hash they cannot be inside it (dropping
///      `unmapped` entirely if that leaves it empty, since an empty
///      object was never emitted pre-signing);
///   3. canonicalize (JCS).
///
/// Then `fingerprint_value(bytes)` must equal the attestation's
/// `fingerprint.value`, and the DSSE signature verifies over
/// `dsse_pae(bytes)`.
pub fn signing_input(event: &Value) -> Vec<u8> {
    let mut ev = event.clone();
    if let Some(att) = ev
        .get_mut("attestation_list")
        .and_then(|l| l.get_mut(0))
        .and_then(Value::as_object_mut)
    {
        att.remove("fingerprint");
        att.remove("signatures");
    }
    let mut drop_unmapped = false;
    if let Some(un) = ev.get_mut("unmapped").and_then(Value::as_object_mut) {
        un.remove("signature_b64");
        un.remove("signature_key_id");
        drop_unmapped = un.is_empty();
    }
    if drop_unmapped {
        if let Some(m) = ev.as_object_mut() {
            m.remove("unmapped");
        }
    }
    canonical_bytes(&ev)
}

/// DSSE payload type for an OCSF event's canonical bytes.
pub const DSSE_PAYLOAD_TYPE: &str = "application/vnd.ocsf.event+json";

/// DSSE Pre-Authentication Encoding over `DSSE_PAYLOAD_TYPE`:
/// `"DSSEv1" SP LEN(type) SP type SP LEN(payload) SP payload`.
/// The signature is computed over these bytes, never the raw payload —
/// that's what makes the envelope resistant to cross-protocol reuse of
/// the same key.
pub fn dsse_pae(payload: &[u8]) -> Vec<u8> {
    let t = DSSE_PAYLOAD_TYPE.as_bytes();
    let mut out = Vec::with_capacity(payload.len() + t.len() + 32);
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(t.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(t);
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

/// Result of signing: the detached signature bytes (base64 DER) and the
/// OCSF `digital_signature` descriptor to embed in
/// `attestation.signatures`. `key_id` (the JWKS `kid`) rides beside the
/// bytes at `unmapped.signature_key_id`, matching the production
/// reference bundle, until #1709 gives both a schema home.
pub struct Signed {
    pub signature: String,
    pub key_id: Option<String>,
    pub digital_signature: serde_json::Value,
}

pub trait OcsfSigner: Send + Sync {
    fn sign(&self, canonical_bytes: &[u8]) -> Option<Signed>;
}

/// No-op: hash-chained but unsigned. Default for demo / unprovisioned.
pub struct NoopSigner;

impl OcsfSigner for NoopSigner {
    fn sign(&self, _canonical_bytes: &[u8]) -> Option<Signed> {
        None
    }
}

/// DSSE signer — ECDSA-P256-SHA256 over the PAE of the event's
/// canonical bytes, deterministic per RFC 6979.
///
/// The key is operator-provided (config: `signing_key_pem` inline or
/// `signing_key_pem_path`) — this crate holds a key handle, not a key
/// service. Custody — HSM/KMS residency, rotation epochs, JWKS
/// publication and its never-unpublish guarantee — is deliberately NOT
/// plugin scope; it belongs to whoever operates the signing authority
/// named by `attestation.authority_uid`.
pub struct DsseSigner {
    key: SigningKey,
    key_id: Option<String>,
}

impl DsseSigner {
    /// Build from a PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`). SEC1
    /// (`BEGIN EC PRIVATE KEY`) is deliberately not parsed — convert
    /// once with `openssl pkcs8 -topk8 -nocrypt` rather than making the
    /// plugin guess at formats.
    pub fn from_pem(pem: &str, key_id: Option<String>) -> Result<Self, String> {
        let key = SigningKey::from_pkcs8_pem(pem).map_err(|e| {
            format!(
                "signing=dsse requires a PKCS#8 P-256 private key PEM \
                 (-----BEGIN PRIVATE KEY-----); parse failed: {e}. \
                 A SEC1 'BEGIN EC PRIVATE KEY' file converts with: \
                 openssl pkcs8 -topk8 -nocrypt -in key.pem"
            )
        })?;
        Ok(Self { key, key_id })
    }

    /// The corresponding public key — what an operator publishes (JWKS)
    /// and a verifier fetches. Exposed for tests, the example, and
    /// downstream verification tooling.
    pub fn verifying_key(&self) -> p256::ecdsa::VerifyingKey {
        *self.key.verifying_key()
    }
}

impl OcsfSigner for DsseSigner {
    fn sign(&self, canonical_bytes: &[u8]) -> Option<Signed> {
        let sig: p256::ecdsa::Signature = self.key.sign(&dsse_pae(canonical_bytes));
        Some(Signed {
            signature: base64::engine::general_purpose::STANDARD.encode(sig.to_der().as_bytes()),
            key_id: self.key_id.clone(),
            // Descriptor only — enum ids verified against ocsf-schema
            // main 2026-07-31. `algorithm` / `serialization` carry the
            // normalized captions (the production bundle's
            // "ECDSA-P256-SHA256" string predates this and is not the
            // schema caption; curve + hash resolve via the JWKS kid).
            digital_signature: json!({
                "algorithm_id": 3,
                "algorithm": "ECDSA",
                "serialization_id": 5,
                "serialization": "DSSE",
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;
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

    /// The emitted `fingerprint.serialization_id = 2` (JCS) is a promise
    /// that a verifier can reproduce our bytes with an off-the-shelf
    /// RFC 8785 implementation. That promise is true for the value space
    /// we actually emit — ASCII keys, integer numbers — and this pins
    /// the two properties a real 8785 library would exercise: keys in
    /// code-unit order, integers in ES6 form. Floats or non-ASCII keys
    /// trip the debug assertions in `write_canonical`; if the event
    /// shape ever needs them, the honest move is `serialization_id` 99
    /// with `serialization` naming the scheme.
    #[test]
    fn canonical_form_matches_jcs_for_the_value_space_we_emit() {
        let v = json!({
            "b": 10,
            "a": -1,
            "A": 0,          // uppercase sorts before lowercase in both orders
            "nested": { "z": [1, 2], "y": "s" },
        });
        assert_eq!(
            String::from_utf8(canonical_bytes(&v)).unwrap(),
            r#"{"A":0,"a":-1,"b":10,"nested":{"y":"s","z":[1,2]}}"#
        );
    }

    #[test]
    fn fingerprint_is_reproducible_from_canonical_bytes() {
        let v = json!({ "b": 1, "a": ["PII", "secret"] });
        let h1 = fingerprint_value(&canonical_bytes(&v));
        let h2 = fingerprint_value(&canonical_bytes(&v.clone()));
        assert_eq!(h1, h2);
        // Bare lowercase hex — algorithm/encoding are declared by the
        // sibling fingerprint fields, not smuggled into `value`.
        assert_eq!(h1.len(), 64);
        assert!(h1
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
    }

    #[test]
    fn dsse_pae_matches_the_spec_form() {
        // PAE("application/vnd.ocsf.event+json", "hello"):
        // the payload type is 31 bytes, the payload 5.
        assert_eq!(
            dsse_pae(b"hello"),
            b"DSSEv1 31 application/vnd.ocsf.event+json 5 hello".to_vec()
        );
    }

    fn test_key() -> SigningKey {
        // Fixed scalar (well below the P-256 group order) so signature
        // output is deterministic across runs — RFC 6979 makes ECDSA
        // deterministic per (key, message). Test/demo key only; never a
        // production pattern.
        SigningKey::from_slice(&[0x11u8; 32]).expect("valid P-256 scalar")
    }

    #[test]
    fn dsse_signature_is_deterministic_and_verifies() {
        let pem = {
            use p256::pkcs8::EncodePrivateKey;
            test_key()
                .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
                .unwrap()
                .to_string()
        };
        let signer = DsseSigner::from_pem(&pem, Some("test-key-1".into())).unwrap();

        let payload = canonical_bytes(&json!({ "class_uid": 6003, "activity_id": 99 }));
        let s1 = signer.sign(&payload).unwrap();
        let s2 = signer.sign(&payload).unwrap();
        // RFC 6979: same key + same message -> same signature.
        assert_eq!(s1.signature, s2.signature);
        assert_eq!(s1.key_id.as_deref(), Some("test-key-1"));
        assert_eq!(s1.digital_signature["algorithm_id"], 3);
        assert_eq!(s1.digital_signature["serialization_id"], 5);

        // Round-trip verify with nothing but the public key and the
        // documented PAE rule.
        let der = base64::engine::general_purpose::STANDARD
            .decode(&s1.signature)
            .unwrap();
        let sig = p256::ecdsa::Signature::from_der(&der).unwrap();
        signer
            .verifying_key()
            .verify(&dsse_pae(&payload), &sig)
            .expect("signature must verify over the PAE bytes");
    }

    #[test]
    fn from_pem_rejects_garbage_loudly() {
        let err = match DsseSigner::from_pem("not a pem", None) {
            Ok(_) => panic!("garbage PEM must not parse"),
            Err(e) => e,
        };
        assert!(
            err.contains("PKCS#8"),
            "error must name the expected format: {err}"
        );
    }
}
