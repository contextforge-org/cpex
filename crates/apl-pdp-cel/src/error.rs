// Location: ./crates/apl-pdp-cel/src/error.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Build-time errors for `CelResolver`. These fire at construction
// (parsing the unified-config block); never at request time.
//
// Request-time problems (a bad `expr`, an undeclared variable, a
// non-boolean result) flow through `apl_core::PdpError` / a fail-closed
// `PdpDecision::Deny` because that's the trait's return surface —
// deliberately separate from build errors, which are config faults the
// operator fixes once.
//
// `BuildError` implements `std::error::Error` (via thiserror), so it
// boxes cleanly into `apl_cpex::visitor::VisitorError` when the
// AplConfigVisitor builds a resolver from a unified-config block. The
// visitor wraps that into `cpex_core::PluginError::Config` on its way out
// of `load_config_yaml`.

use thiserror::Error;

/// Error returned at resolver construction (`CelResolver::from_config`).
#[derive(Debug, Error)]
pub enum BuildError {
    /// Config block wasn't a mapping, or a field had the wrong shape /
    /// an unrecognized value (e.g. `on_error: maybe`).
    #[error("invalid CEL PDP config: {0}")]
    ConfigShape(String),

    /// An optional default `expr` was supplied in the config block but
    /// didn't parse as CEL. Per-step expressions are validated lazily at
    /// request time (their text isn't known until a route calls), but a
    /// config-level default is checked eagerly so the operator learns of
    /// the typo at load.
    #[error("failed to compile CEL expression: {0}")]
    ExprCompile(String),
}
