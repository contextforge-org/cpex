// Location: ./crates/apl-session-valkey/src/store.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// `ValkeySessionStore` — the Valkey-backed `SessionStore`. Labels live in
// a Redis SET per session so `append_labels` is a single atomic
// server-side union (`SADD`), never a client-side read-modify-write that
// would lose labels under concurrent cross-node appends (R16).
//
// # Fail-closed mapping (R5/R15)
//
//   - `SMEMBERS` on a missing key returns an empty set → `Ok(empty)`
//     (unknown session, R15). It is NOT an error.
//   - connection/timeout/protocol/decode failures → `Err(Backend)` so the
//     caller fails the request closed.
//
// # Sliding TTL (R7)
//
// `append_labels` issues `SADD` + `EXPIRE` in one atomic pipeline.
// `load_labels` refreshes the TTL fail-open: the read already succeeded,
// so a refresh failure is alarmed but the labels are still returned.

use std::fmt::Write as _;
use std::time::Duration;

use apl_cpex::{SessionStore, SessionStoreError};
use async_trait::async_trait;
use deadpool_redis::{Connection, Pool};
use redis::AsyncCommands;
use sha2::{Digest, Sha256};

use crate::config::ValkeyConfig;
use crate::connection::build_pool;
use crate::error::BuildError;

/// Valkey-backed session label store.
pub struct ValkeySessionStore {
    pool: Pool,
    key_prefix: String,
    ttl_seconds: Option<u64>,
    command_timeout: Duration,
}

impl ValkeySessionStore {
    /// Build from validated config. The pool is created lazily, so this
    /// does not dial Valkey — connection failures surface on first use
    /// and correctly fail the request closed.
    pub fn from_config(cfg: &ValkeyConfig) -> Result<Self, BuildError> {
        Ok(Self {
            pool: build_pool(cfg)?,
            key_prefix: cfg.key_prefix.clone(),
            ttl_seconds: cfg.ttl_seconds,
            command_timeout: Duration::from_millis(cfg.command_timeout_ms),
        })
    }

    /// Key schema: `<prefix>:<hex(sha256(session_id))>`. The full-width
    /// digest keeps the Valkey keyspace collision-free and removes raw
    /// session ids from it.
    fn key(&self, session_id: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(session_id.as_bytes());
        let digest = hasher.finalize();
        let mut hex = String::with_capacity(digest.len() * 2);
        for byte in digest {
            let _ = write!(hex, "{byte:02x}");
        }
        format!("{}:{}", self.key_prefix, hex)
    }

    /// Acquire a pooled connection, bounded by the command timeout.
    async fn conn(&self) -> Result<Connection, SessionStoreError> {
        match tokio::time::timeout(self.command_timeout, self.pool.get()).await {
            Ok(Ok(conn)) => Ok(conn),
            Ok(Err(e)) => Err(backend(e)),
            Err(_) => Err(SessionStoreError::Backend(
                "valkey connection acquire timed out".to_string(),
            )),
        }
    }
}

/// Map any backend failure to the fail-closed `SessionStoreError`.
fn backend(e: impl std::fmt::Display) -> SessionStoreError {
    SessionStoreError::Backend(e.to_string())
}

#[async_trait]
impl SessionStore for ValkeySessionStore {
    async fn load_labels(&self, session_id: &str) -> Result<Vec<String>, SessionStoreError> {
        let key = self.key(session_id);
        let mut conn = self.conn().await?;

        // SMEMBERS on a missing key returns an empty set (Ok), so an
        // unknown session naturally maps to Ok(empty) (R15). Only a real
        // backend failure becomes Err (R5).
        let labels: Vec<String> =
            match tokio::time::timeout(self.command_timeout, conn.smembers(&key)).await {
                Ok(res) => res.map_err(backend)?,
                Err(_) => {
                    return Err(SessionStoreError::Backend(
                        "valkey SMEMBERS timed out".to_string(),
                    ))
                }
            };

        // Sliding-TTL refresh is fail-open for the read: the labels were
        // read successfully, so a refresh failure is alarmed, not failed
        // closed (R7). A persistently-failing refresh risks silent key
        // expiry across requests — see the operator runbook.
        if let Some(ttl) = self.ttl_seconds {
            let refresh: Result<bool, _> =
                match tokio::time::timeout(self.command_timeout, conn.expire(&key, ttl as i64))
                    .await
                {
                    Ok(res) => res,
                    Err(_) => Ok(false), // treat timeout as a failed refresh
                };
            if let Err(e) = refresh {
                tracing::warn!(
                    alarm = "session_store_ttl_refresh_failed",
                    error = %e,
                    "valkey TTL refresh on load failed; returning read labels (fail-open)"
                );
            }
        }

        Ok(labels)
    }

    async fn append_labels(
        &self,
        session_id: &str,
        labels: &[String],
    ) -> Result<(), SessionStoreError> {
        if labels.is_empty() {
            return Ok(());
        }
        let key = self.key(session_id);
        let mut conn = self.conn().await?;

        // Atomic server-side union + optional TTL refresh in one round
        // trip (MULTI/EXEC). SADD is a commutative merge, so concurrent
        // cross-node appends never lose labels (R16).
        let mut pipe = redis::pipe();
        pipe.atomic();
        pipe.sadd(&key, labels).ignore();
        if let Some(ttl) = self.ttl_seconds {
            pipe.expire(&key, ttl as i64).ignore();
        }

        match tokio::time::timeout(self.command_timeout, pipe.query_async::<()>(&mut conn)).await {
            Ok(res) => res.map_err(backend)?,
            Err(_) => {
                return Err(SessionStoreError::Backend(
                    "valkey append (SADD+EXPIRE) timed out".to_string(),
                ))
            }
        }
        Ok(())
    }
}
