// Location: ./crates/cpex-openshell-middleware/src/runtime.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Xiaokui Shu
//
// The process-lifetime CPEX runtime, built once from a bundle file at service
// startup and shared by reference for every request. The session store is
// process-lifetime and in-memory, so cross-call taint labels outlive
// individual requests; a restart clears them (acceptable for the single-node
// proof-of-feasibility). There is no live bundle hot-reload: swapping the PDP
// (Cedar ↔ CEL) is a restart with a different bundle path.

use std::sync::Arc;

use cpex::embed::{CpexAuthorizer, EmbedError};
use cpex::MemorySessionStore;

/// Build the CPEX runtime from a bundle YAML file. The bundle names the
/// identity/JWT plugin (Keycloak issuer/JWKS), the PDP (`cedar` or `cel`), and
/// the `tool:` routes' `require`/`taint` steps. Construction failure is fatal:
/// the service must not start without a coherent policy (fail closed).
pub async fn build(bundle_path: &str) -> Result<Arc<CpexAuthorizer>, EmbedError> {
    let yaml = std::fs::read_to_string(bundle_path)
        .map_err(|e| EmbedError::Config(format!("failed to read bundle {bundle_path}: {e}")))?;
    // Process-lifetime in-memory session store: taint labels persist for the
    // process and are shared across requests; a restart clears them.
    let store = Arc::new(MemorySessionStore::new());
    let authorizer = CpexAuthorizer::from_bundle_yaml(&yaml, store).await?;
    Ok(Arc::new(authorizer))
}
