// Location: ./crates/cpex-core/src/extensions/tiers.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Mutability tiers and capability definitions.
//
// Each extension slot has a mutability tier that controls how plugins
// can interact with it. Capabilities gate per-plugin access.
//
// Mirrors cpex/framework/extensions/tiers.py.

use serde::{Deserialize, Serialize};

/// Mutability tier for an extension slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutabilityTier {
    /// Cannot be modified after creation.
    Immutable,
    /// Can only grow (add-only sets, append-only chains).
    Monotonic,
    /// Can be freely modified by plugins with write capability.
    Mutable,
}

/// Declared permission that controls extension access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Read the authenticated subject identity.
    ReadSubject,
    /// Read subject roles.
    ReadRoles,
    /// Read subject team memberships.
    ReadTeams,
    /// Read subject claims (e.g., JWT claims).
    ReadClaims,
    /// Read subject permissions.
    ReadPermissions,
    /// Read the agent execution context.
    ReadAgent,
    /// Read HTTP headers.
    ReadHeaders,
    /// Write (modify) HTTP headers.
    WriteHeaders,
    /// Read security labels.
    ReadLabels,
    /// Append security labels (monotonic add-only).
    AppendLabels,
    /// Read the delegation chain.
    ReadDelegation,
    /// Append to the delegation chain (monotonic).
    AppendDelegation,
}

/// Access policy for an extension slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessPolicy {
    /// All plugins can access.
    Unrestricted,
    /// Only plugins with the declared capability can access.
    CapabilityGated,
}

/// Policy for a single extension slot.
///
/// Declares the mutability tier, access policy, and required
/// capabilities for reading and writing.
#[derive(Debug, Clone)]
pub struct SlotPolicy {
    /// How the slot can be modified.
    pub tier: MutabilityTier,
    /// Whether access requires a capability.
    pub access: AccessPolicy,
    /// Capability required for reading (if capability-gated).
    pub read_cap: Option<Capability>,
    /// Capability required for writing (if capability-gated).
    pub write_cap: Option<Capability>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier_serde() {
        let tier = MutabilityTier::Monotonic;
        let json = serde_json::to_string(&tier).unwrap();
        assert_eq!(json, "\"monotonic\"");
    }

    #[test]
    fn test_capability_serde() {
        let cap = Capability::AppendLabels;
        let json = serde_json::to_string(&cap).unwrap();
        assert_eq!(json, "\"append_labels\"");
    }
}
