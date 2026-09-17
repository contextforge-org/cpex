// Location: ./crates/cpex-core/src/extensions/framework.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// FrameworkExtension — agentic framework context.
// Mirrors cpex/framework/extensions/framework.py.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Agentic framework context.
///
/// Carries framework identity and graph/workflow metadata.
/// Immutable — set by the host.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FrameworkExtension {
    /// Framework name (e.g., "langchain", "crewai", "autogen").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framework: Option<String>,

    /// Framework version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framework_version: Option<String>,

    /// Node ID in an agent graph/workflow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,

    /// Graph/workflow ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graph_id: Option<String>,

    /// Framework-specific metadata.
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}
