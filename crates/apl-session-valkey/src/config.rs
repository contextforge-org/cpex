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
    // NOTE: bounded retry + circuit-breaker are deliberately NOT implemented
    // in v0 (deferred follow-up). The store fails closed on the first
    // backend error, which is safe — it just fails faster. A `max_retries`
    // knob is intentionally absent rather than present-but-dead, so config
    // never advertises behavior the code doesn't have.
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
    /// localhost (R10); a `tls: true` + plaintext `redis://` scheme is a
    /// contradiction (would connect in cleartext); the connection URL
    /// must build; the TTL-soundness warning (R17) is emitted here.
    ///
    /// All error text routes the endpoint through [`redact_endpoint`] so
    /// embedded credentials never leak into errors or logs.
    fn validate(&self) -> Result<(), BuildError> {
        // A fully-formed plaintext `redis://` endpoint with `tls: true`
        // is contradictory: tls_enabled() would say "secure" while the
        // explicit scheme forces cleartext. Reject rather than silently
        // connecting in the clear.
        if self.tls && self.endpoint.starts_with("redis://") {
            return Err(BuildError::Config(format!(
                "`tls: true` conflicts with the plaintext `redis://` scheme in endpoint '{}'; \
                 use a `rediss://` URL or a bare host:port",
                redact_endpoint(&self.endpoint)
            )));
        }

        if !self.tls_enabled() && !endpoint_is_localhost(&self.endpoint) {
            return Err(BuildError::TlsRequired(redact_endpoint(&self.endpoint)));
        }

        // Build the URL now so a malformed endpoint / unencodable
        // credential fails at config-load, not on first request.
        self.connection_url()?;

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

    /// Build the `redis`/`rediss` connection URL deadpool consumes.
    ///
    /// Credentials are percent-encoded via the `url` crate (never naive
    /// string interpolation), and the wire scheme always reflects
    /// [`Self::tls_enabled`] so it cannot disagree with the validated TLS
    /// intent. A fully-formed endpoint URL is parsed (and trusted for its
    /// own embedded credentials); a bare `host:port` is assembled with
    /// the configured scheme and any separate `username`/`password`.
    pub fn connection_url(&self) -> Result<String, BuildError> {
        if self.endpoint.starts_with("redis://") || self.endpoint.starts_with("rediss://") {
            // Validate it parses; trust the operator's embedded scheme +
            // credentials. (validate() has already rejected the
            // tls:true + redis:// contradiction.)
            let url = url::Url::parse(&self.endpoint).map_err(|e| {
                BuildError::Config(format!(
                    "invalid endpoint URL '{}': {e}",
                    redact_endpoint(&self.endpoint)
                ))
            })?;
            return Ok(url.to_string());
        }

        let scheme = if self.tls_enabled() {
            "rediss"
        } else {
            "redis"
        };
        let mut url = url::Url::parse(&format!("{scheme}://{}", self.endpoint)).map_err(|e| {
            BuildError::Config(format!(
                "invalid endpoint '{}': {e}",
                redact_endpoint(&self.endpoint)
            ))
        })?;
        if let Some(password) = &self.password {
            // set_username/set_password percent-encode and reject hosts
            // that cannot carry userinfo (e.g. cannot-be-a-base URLs).
            url.set_username(self.username.as_deref().unwrap_or(""))
                .map_err(|_| BuildError::Config("endpoint cannot carry credentials".to_string()))?;
            url.set_password(Some(password))
                .map_err(|_| BuildError::Config("endpoint cannot carry credentials".to_string()))?;
        }
        Ok(url.to_string())
    }
}

/// Strip any `userinfo` (`user:pass@`) from an endpoint before it appears
/// in an error message or log line, so credentials are never disclosed.
fn redact_endpoint(endpoint: &str) -> String {
    if let Some(scheme_end) = endpoint.find("://") {
        let (scheme, after) = (&endpoint[..scheme_end], &endpoint[scheme_end + 3..]);
        if let Some(at) = after.rfind('@') {
            return format!("{scheme}://***@{}", &after[at + 1..]);
        }
        return endpoint.to_string();
    }
    // Bare host:port may still carry userinfo if misconfigured.
    if let Some(at) = endpoint.rfind('@') {
        return format!("***@{}", &endpoint[at + 1..]);
    }
    endpoint.to_string()
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
        assert!(cfg
            .connection_url()
            .unwrap()
            .starts_with("redis://localhost:6379"));
    }

    #[test]
    fn non_localhost_without_tls_is_rejected() {
        let err = parse("kind: valkey\nendpoint: valkey.prod.internal:6379\n").unwrap_err();
        assert!(matches!(err, BuildError::TlsRequired(_)), "got {err:?}");
    }

    #[test]
    fn non_localhost_with_tls_uses_rediss_scheme() {
        let cfg = parse("kind: valkey\nendpoint: valkey.prod.internal:6379\ntls: true\n").unwrap();
        assert!(cfg.tls_enabled());
        assert!(cfg
            .connection_url()
            .unwrap()
            .starts_with("rediss://valkey.prod.internal:6379"));
    }

    #[test]
    fn rediss_scheme_implies_tls() {
        let cfg = parse("kind: valkey\nendpoint: rediss://valkey.prod.internal:6379\n").unwrap();
        assert!(cfg.tls_enabled());
        assert!(cfg.connection_url().unwrap().starts_with("rediss://"));
    }

    /// Regression for the TLS-bypass finding: `tls: true` with an explicit
    /// plaintext `redis://` scheme must be rejected, not silently connect
    /// in the clear.
    #[test]
    fn tls_true_with_plaintext_scheme_is_rejected() {
        let err = parse("kind: valkey\nendpoint: redis://valkey.prod.internal:6379\ntls: true\n")
            .unwrap_err();
        assert!(matches!(err, BuildError::Config(_)), "got {err:?}");
    }

    #[test]
    fn credentials_are_percent_encoded_in_url() {
        // A password with URL-significant characters must be encoded, not
        // interpolated raw (which would corrupt the URL).
        let cfg = parse(
            "kind: valkey\nendpoint: valkey.prod.internal:6379\ntls: true\nusername: gw\npassword: \"p@ss:w/rd\"\n",
        )
        .unwrap();
        let url = cfg.connection_url().unwrap();
        assert!(url.starts_with("rediss://gw:"), "url: {url}");
        assert!(url.contains("@valkey.prod.internal:6379"), "url: {url}");
        // The raw special chars must NOT appear unencoded in the userinfo.
        assert!(
            url.contains("p%40ss"),
            "password '@' must be encoded: {url}"
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

    #[test]
    fn redact_endpoint_strips_userinfo() {
        assert_eq!(
            redact_endpoint("rediss://user:secret@host:6379"),
            "rediss://***@host:6379"
        );
        assert_eq!(redact_endpoint("host:6379"), "host:6379");
    }

    /// Credentials must never leak into the TLS-required error.
    #[test]
    fn tls_required_error_redacts_credentials() {
        // rediss-less, non-localhost, with embedded creds, tls off → error.
        let err =
            parse("kind: valkey\nendpoint: redis://user:topsecret@prod.host:6379\n").unwrap_err();
        let msg = format!("{err}");
        assert!(
            !msg.contains("topsecret"),
            "error leaked credentials: {msg}"
        );
    }
}
