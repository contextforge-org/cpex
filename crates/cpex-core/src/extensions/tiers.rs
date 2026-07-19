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
///
/// # Why no `Write*` for identity slots
///
/// The IdentityResolve and TokenDelegate hook families return result
/// payloads that the framework consumes to mutate `Extensions`. Plugins
/// never write to `security.subject` / `security.client` /
/// `security.*_workload` / `raw_credentials.*` directly — those slots
/// are owned by the framework on behalf of return-based handlers. The
/// matching write capabilities are therefore absent from this enum
/// until a use case appears for plugin-driven mutation of these slots
/// outside the resolve/delegate hooks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    ReadSubject,
    /// Read subject roles (`security.subject.roles`).
    ReadRoles,
    /// Read subject team memberships (`security.subject.teams`).
    ReadTeams,
    /// Read subject claims (`security.subject.claims`).
    ReadClaims,
    /// Read subject permissions (`security.subject.permissions`).
    ReadPermissions,

    ReadClient,

    ReadWorkload,

    ReadAgent,

    ReadHeaders,
    /// Write (modify) HTTP headers.
    WriteHeaders,

    ReadLabels,
    /// Append security labels (monotonic add-only).
    AppendLabels,

    ReadDelegation,
    /// Append to the delegation chain (monotonic).
    AppendDelegation,

    ReadInboundCredentials,
    /// Read minted outbound delegated tokens
    /// (`raw_credentials.delegated_tokens`) — the credentials a
    /// TokenDelegate handler produced for an upstream call. Held by
    /// forwarding / proxy plugins that re-attach them on the outbound
    /// request. Same out-of-process caveat as
    /// `read_inbound_credentials`.
    ReadDelegatedTokens,
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
