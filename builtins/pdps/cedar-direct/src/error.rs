// Location: ./builtins/pdps/cedar-direct/src/error.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Build-time errors for `CedarDirectResolver`. All variants fire at
// construction (parse, validate, load); never at request time.
//
// Request-time errors flow through `apl_core::PdpError` because that's
// the trait's return type. The two error stories are deliberately
// separate — build errors are config faults the operator fixes once;
// request errors are per-evaluation issues the host has to handle
// continuously.
//
// `BuildError` implements `std::error::Error` (via thiserror), so it
// boxes cleanly into `apl_cpex::visitor::VisitorError` when the
// AplConfigVisitor builds a resolver from a unified-config block. The
// visitor then wraps that into `cpex_core::PluginError::Config` on its
// way out of `load_config_yaml`. Each layer wraps the layer below using
// its own native error type — no dep inversion required to make the
// error flow work.

use thiserror::Error;

/// Error returned at resolver construction.
#[derive(Debug, Error)]
pub enum BuildError {
    /// The policy text didn't parse as Cedar. Carries the underlying
    /// parser message verbatim so operators can see exactly which
    /// `permit`/`forbid` line broke.
    #[error("failed to parse Cedar policy set: {0}")]
    PolicyParse(String),

    /// Cedar accepted the policy text but the schema (if supplied)
    /// rejected one or more policies as invalid against the declared
    /// entity / action shape.
    #[error("policy set failed schema validation: {0}")]
    PolicyValidation(String),

    /// I/O failure reading a policy file from disk. Distinct variant
    /// from `PolicyParse` so operators can tell "file not found" from
    /// "file found but unparseable" without grepping the message.
    #[error("failed to read Cedar policy file '{path}': {source}")]
    PolicyFile {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// Schema text didn't parse as Cedar schema.
    #[error("failed to parse Cedar schema: {0}")]
    SchemaParse(String),

    /// I/O failure reading a schema file from disk.
    #[error("failed to read Cedar schema file '{path}': {source}")]
    SchemaFile {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// Config block missing required fields, or fields had the wrong
    /// shape. Fired by `from_config(&serde_yaml::Value)` when the
    /// operator's YAML doesn't match the expected layout.
    #[error("invalid Cedar PDP config: {0}")]
    ConfigShape(String),
}
