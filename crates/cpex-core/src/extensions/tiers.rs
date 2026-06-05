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
    // ----- Subject (user identity) -----
    /// Read the authenticated subject identity (`security.subject`).
    /// Unlocks the slot but not its sub-fields — roles / teams /
    /// claims / permissions each have their own cap below.
    ReadSubject,
    /// Read subject roles (`security.subject.roles`).
    ReadRoles,
    /// Read subject team memberships (`security.subject.teams`).
    ReadTeams,
    /// Read subject claims (`security.subject.claims`).
    ReadClaims,
    /// Read subject permissions (`security.subject.permissions`).
    ReadPermissions,

    // ----- Client (OAuth application identity) -----
    /// Read the OAuth client / gateway-access identity
    /// (`security.client`). Distinct from the user identity
    /// (`subject`) — a single user can connect through different
    /// clients (first-party browser, third-party agent) and policies
    /// sometimes want to gate on the client.
    ReadClient,

    // ----- Workload (attested SPIFFE / mTLS identity) -----
    /// Read either workload-identity slot — both
    /// `security.caller_workload` (the inbound attested peer) and
    /// `security.this_workload` (our own outbound identity). One
    /// capability covers both: a plugin either has access to
    /// attested-workload identity or it doesn't. Distinct from
    /// `read_agent` which governs session / conversation context,
    /// **NOT** identity.
    ReadWorkload,

    // ----- Agent execution context (session / conversation) -----
    /// Read the agent execution context (`AgentExtension`).
    /// **NOT a credential** — this carries session / conversation /
    /// lineage state, not identity. Identity reads use
    /// `read_subject` / `read_client` / `read_workload`.
    ReadAgent,

    // ----- HTTP wire layer -----
    /// Read HTTP headers.
    ReadHeaders,
    /// Write (modify) HTTP headers.
    WriteHeaders,

    // ----- Security labels (taint flow) -----
    /// Read security labels.
    ReadLabels,
    /// Append security labels (monotonic add-only).
    AppendLabels,

    // ----- Delegation chain (validated) -----
    /// Read the delegation chain.
    ReadDelegation,
    /// Append to the delegation chain (monotonic).
    AppendDelegation,

    // ----- Raw credentials (Layer 3) -----
    /// Read raw inbound tokens
    /// (`raw_credentials.inbound_tokens`) — the bearer-token
    /// strings captured at the wire layer before validation.
    /// Narrowly scoped: only IdentityResolve handlers, forwarding
    /// plugins, and a small set of audit plugins should declare it.
    /// Out-of-process plugins can't see these tokens regardless of
    /// capability — token fields are `#[serde(skip)]`.
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
