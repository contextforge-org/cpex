// Location: ./crates/apl-session-valkey/src/config.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// Parses and validates the `global.apl.session_store` block for the
// Valkey backend. Deliberately minimal (R11): a single endpoint, TLS,
// auth, key prefix, optional sliding TTL, and fail-closed timeout/retry
// knobs with committed safe defaults. Sentinel/Cluster fields are NOT
// present — they are out of scope and would be dead config surface.

use serde::Deserialize;

use crate::error::BuildError;

/// Default key prefix/namespace for the label keyspace. The `v1` segment
/// lets a future value-schema change bump the namespace cleanly.
fn default_key_prefix() -> String {
    "taint:v1".to_string()
}

// Committed fail-closed defaults (see plan Key Technical Decisions). They
// ship in code so behavior and tests are deterministic; operators tune
// from this baseline.
fn default_connect_timeout_ms() -> u64 {
    250
}
fn default_command_timeout_ms() -> u64 {
    500
}
fn default_max_retries() -> u32 {
    1
}

/// Parsed `global.apl.session_store` config for `kind: valkey`.
///
/// Unknown keys (including `kind`, consumed by the factory dispatch) are
/// ignored so the same block can carry the discriminator.
#[derive(Debug, Clone, Deserialize)]
pub struct ValkeyConfig {
    /// Endpoint: a `redis://` / `rediss://` URL or a bare `host:port`.
    pub endpoint: String,

    /// Whether to use TLS. Implied `true` for a `rediss://` endpoint.
    /// Required for any non-localhost endpoint (validated).
    #[serde(default)]
    pub tls: bool,

    /// Optional ACL username (Valkey 6+ ACLs). Paired with `password`.
    #[serde(default)]
    pub username: Option<String>,

    /// Optional auth password / ACL secret. Sourced from config/env by
    /// the operator; never hard-coded.
    #[serde(default)]
    pub password: Option<String>,

    /// Key prefix/namespace for label keys (R9).
    #[serde(default = "default_key_prefix")]
    pub key_prefix: String,

    /// Sliding TTL in seconds, refreshed on load and append. `None`
    /// (default) means no expiry (R7).
    #[serde(default)]
    pub ttl_seconds: Option<u64>,

    /// Declared maximum session-identity lifetime, used only to emit the
    /// TTL-soundness warning (R17) when `ttl_seconds` is shorter.
    #[serde(default)]
    pub max_session_lifetime_seconds: Option<u64>,

    /// Connection acquisition timeout (ms).
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,

    /// Per-command response timeout (ms) — the fail-closed hot-path knob.
    #[serde(default = "default_command_timeout_ms")]
    pub command_timeout_ms: u64,

    /// Max retries for a transient command failure (≤1 recommended).
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
}

impl ValkeyConfig {
    /// Parse from the YAML config block, then validate.
    pub fn from_value(value: &serde_yaml::Value) -> Result<Self, BuildError> {
        let cfg: ValkeyConfig =
            serde_yaml::from_value(value.clone()).map_err(|e| BuildError::Config(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Enforce the non-negotiable invariants. TLS is mandatory off
    /// localhost (R10); the TTL-soundness warning (R17) is emitted here.
    fn validate(&self) -> Result<(), BuildError> {
        let tls = self.tls_enabled();
        if !tls && !endpoint_is_localhost(&self.endpoint) {
            return Err(BuildError::TlsRequired(self.endpoint.clone()));
        }
        if let (Some(ttl), Some(life)) = (self.ttl_seconds, self.max_session_lifetime_seconds) {
            if ttl < life {
                tracing::warn!(
                    alarm = "session_store_ttl_unsound",
                    ttl_seconds = ttl,
                    max_session_lifetime_seconds = life,
                    "valkey session_store TTL is shorter than the declared max session lifetime; \
                     accumulated taint can silently expire (downgrade-by-waiting) — see R8"
                );
            }
        }
        Ok(())
    }

    /// TLS is on when explicitly set or implied by a `rediss://` scheme.
    pub fn tls_enabled(&self) -> bool {
        self.tls || self.endpoint.starts_with("rediss://")
    }

    /// Build the `redis`/`rediss` connection URL deadpool consumes,
    /// folding in scheme (from TLS) and any ACL credentials.
    pub fn connection_url(&self) -> String {
        // Already a fully-formed URL → trust it as-is.
        if self.endpoint.starts_with("redis://") || self.endpoint.starts_with("rediss://") {
            return self.endpoint.clone();
        }
        let scheme = if self.tls_enabled() {
            "rediss"
        } else {
            "redis"
        };
        let auth = match (&self.username, &self.password) {
            (Some(u), Some(p)) => format!("{u}:{p}@"),
            (None, Some(p)) => format!(":{p}@"),
            _ => String::new(),
        };
        format!("{scheme}://{auth}{}", self.endpoint)
    }
}

/// Best-effort localhost check for the TLS-required rule. Strips scheme,
/// credentials, and port, then matches the common loopback hosts.
fn endpoint_is_localhost(endpoint: &str) -> bool {
    let no_scheme = endpoint
        .strip_prefix("rediss://")
        .or_else(|| endpoint.strip_prefix("redis://"))
        .unwrap_or(endpoint);
    // Drop any credentials before the host.
    let host_port = no_scheme.rsplit('@').next().unwrap_or(no_scheme);
    // Bracketed IPv6 loopback, e.g. [::1]:6379.
    if host_port.starts_with("[::1]") {
        return true;
    }
    let host = host_port.split(':').next().unwrap_or(host_port);
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> Result<ValkeyConfig, BuildError> {
        let v: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        ValkeyConfig::from_value(&v)
    }

    #[test]
    fn localhost_without_tls_is_allowed() {
        let cfg = parse("kind: valkey\nendpoint: localhost:6379\n").unwrap();
        assert_eq!(cfg.key_prefix, "taint:v1");
        assert_eq!(cfg.connect_timeout_ms, 250);
        assert_eq!(cfg.command_timeout_ms, 500);
        assert_eq!(cfg.max_retries, 1);
        assert_eq!(cfg.connection_url(), "redis://localhost:6379");
    }

    #[test]
    fn non_localhost_without_tls_is_rejected() {
        let err = parse("kind: valkey\nendpoint: valkey.prod.internal:6379\n").unwrap_err();
        assert!(matches!(err, BuildError::TlsRequired(_)), "got {err:?}");
    }

    #[test]
    fn non_localhost_with_tls_is_allowed() {
        let cfg = parse("kind: valkey\nendpoint: valkey.prod.internal:6379\ntls: true\n").unwrap();
        assert!(cfg.tls_enabled());
        assert_eq!(cfg.connection_url(), "rediss://valkey.prod.internal:6379");
    }

    #[test]
    fn rediss_scheme_implies_tls() {
        let cfg = parse("kind: valkey\nendpoint: rediss://valkey.prod.internal:6379\n").unwrap();
        assert!(cfg.tls_enabled());
        // A fully-formed URL is trusted as-is.
        assert_eq!(cfg.connection_url(), "rediss://valkey.prod.internal:6379");
    }

    #[test]
    fn credentials_fold_into_url() {
        let cfg = parse(
            "kind: valkey\nendpoint: valkey.prod.internal:6379\ntls: true\nusername: gw\npassword: secret\n",
        )
        .unwrap();
        assert_eq!(
            cfg.connection_url(),
            "rediss://gw:secret@valkey.prod.internal:6379"
        );
    }

    #[test]
    fn missing_endpoint_is_config_error() {
        let err = parse("kind: valkey\n").unwrap_err();
        assert!(matches!(err, BuildError::Config(_)), "got {err:?}");
    }

    #[test]
    fn ipv6_loopback_without_tls_is_allowed() {
        let cfg = parse("kind: valkey\nendpoint: \"[::1]:6379\"\n").unwrap();
        assert!(!cfg.tls_enabled());
    }
}
