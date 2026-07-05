// Location: ./builtins/session/valkey/src/error.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// Construction-time errors for the Valkey session-store backend. These
// surface when the `global.apl.session_store` config block is malformed
// or the connection pool cannot be built — i.e. at `load_config_yaml`
// time, NOT on the request hot path. Request-time failures flow through
// `apl_cpex::SessionStoreError` (the trait's return type) so callers can
// fail closed.

/// Error returned while building a `ValkeySessionStore` from config.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    /// The config block was structurally invalid (missing/!typed fields).
    #[error("invalid valkey session_store config: {0}")]
    Config(String),

    /// TLS is mandatory for any non-localhost endpoint: session
    /// security labels must not transit a network segment in plaintext.
    #[error(
        "valkey session_store requires TLS for non-localhost endpoint '{0}' \
         — set `tls: true` or use a `rediss://` URL"
    )]
    TlsRequired(String),

    /// The connection pool could not be constructed (bad URL, etc.).
    #[error("failed to build valkey connection pool: {0}")]
    Pool(String),
}
