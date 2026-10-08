// Location: ./tests/parity/harness/src/keys.rs
// SPDX-License-Identifier: Apache-2.0
//
// TEST-ONLY signing keys and JWT minting.
//
// Each key is an Ed25519 keypair whose seed is SHA-256 of a fixed, public
// label. Anyone can rederive the private half, which is the point: the keys
// exist only so parity runs mint identical tokens on every machine. They
// must never sign anything outside this harness.

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::spec::TokenSpec;

/// Key published in the mock JWKS.
pub const PRIMARY: &str = "primary";
/// Key the mock JWKS does not publish (forged-signature cases).
pub const ROGUE: &str = "rogue";

pub struct TestKey {
    pub kid: String,
    pair: Ed25519KeyPair,
}

impl TestKey {
    fn derive(name: &str) -> Self {
        let label = format!("cpex parity harness TEST-ONLY ed25519 key: {name}");
        let seed = Sha256::digest(label.as_bytes());
        let pair = Ed25519KeyPair::from_seed_unchecked(&seed).expect("32-byte seed");
        Self {
            kid: format!("parity-{name}"),
            pair,
        }
    }

    fn public_bytes(&self) -> &[u8] {
        self.pair.public_key().as_ref()
    }

    /// Public half as a JWK (`kty: OKP`, `crv: Ed25519`).
    pub fn jwk(&self) -> Value {
        json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "use": "sig",
            "kid": self.kid,
            "x": URL_SAFE_NO_PAD.encode(self.public_bytes()),
        })
    }
}

pub struct KeyRing {
    primary: TestKey,
    rogue: TestKey,
}

impl Default for KeyRing {
    fn default() -> Self {
        Self {
            primary: TestKey::derive(PRIMARY),
            rogue: TestKey::derive(ROGUE),
        }
    }
}

impl KeyRing {
    fn key(&self, name: &str) -> Result<&TestKey, String> {
        match name {
            PRIMARY => Ok(&self.primary),
            ROGUE => Ok(&self.rogue),
            other => Err(format!("unknown test key '{other}'")),
        }
    }

    /// The JWKS document the mock IdP serves: the primary key only.
    pub fn jwks(&self) -> Value {
        json!({ "keys": [self.primary.jwk()] })
    }

    /// Sign `spec.claims` as a compact EdDSA JWT. Deterministic: Ed25519
    /// signatures carry no randomness, and claims come verbatim from data.
    pub fn mint(&self, spec: &TokenSpec) -> Result<String, String> {
        let key = self.key(&spec.key)?;
        let kid = spec.kid.clone().unwrap_or_else(|| key.kid.clone());
        let header = json!({ "alg": "EdDSA", "typ": "JWT", "kid": kid });
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).map_err(|e| e.to_string())?),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&spec.claims).map_err(|e| e.to_string())?),
        );
        let sig = key.pair.sign(signing_input.as_bytes());
        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(sig.as_ref())
        ))
    }
}
