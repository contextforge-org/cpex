// Location: ./crates/apl-cedarling/src/error.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Build-time errors for constructing Cedarling-backed resolvers and
// handlers. Runtime errors flow through `PluginViolation` (for
// hook handlers) or `PdpError::Dispatch` (for the PDP path) — same
// pattern as `apl-pdp-cedar-direct`.

use thiserror::Error;

/// Errors that can occur while constructing a Cedarling-backed
/// resolver or handler from config.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum CedarlingPluginError {
    /// The policy store file/URL couldn't be loaded.
    #[error("failed to load policy store: {0}")]
    PolicyStoreLoad(String),

    /// The bootstrap config was malformed or missing required fields.
    #[error("invalid Cedarling bootstrap config: {0}")]
    BootstrapConfig(String),

    /// Cedarling itself failed to initialize (JWKS unreachable,
    /// schema validation failed, etc.).
    #[error("Cedarling initialization failed: {0}")]
    Init(String),
}
