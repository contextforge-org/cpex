// Location: ./builtins/session/valkey/src/connection.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// Internal connection layer (R14): builds and holds the deadpool-redis
// pool for the Valkey backend. Kept private to this crate — it is NOT a
// public reusable API. When a second consumer (the planned OAuth token
// cache) is actually scheduled, extract a shared layer then
// (refactor-then-reuse), shaped by two real consumers.

use deadpool_redis::{Config as PoolConfig, Pool, Runtime};

use crate::config::ValkeyConfig;
use crate::error::BuildError;

/// Build the connection pool from validated config. The pool is created
/// lazily — `create_pool` does not dial Valkey, so a bad endpoint surfaces
/// on first use (where it correctly fails the request closed) rather than
/// blocking `load_config_yaml`.
pub(crate) fn build_pool(cfg: &ValkeyConfig) -> Result<Pool, BuildError> {
    let url = cfg.connection_url()?;
    let pool_cfg = PoolConfig::from_url(url);
    // Note: the pool-create error is intentionally not interpolated with
    // the URL — that string carries credentials. `connection_url()` has
    // already validated the URL parses, so failures here are rare.
    pool_cfg
        .create_pool(Some(Runtime::Tokio1))
        .map_err(|e| BuildError::Pool(e.to_string()))
}
