# -*- coding: utf-8 -*-
"""Location: ./cpex/framework/extensions/tiers.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Teryl Taylor

Extension mutability tiers and capability-gated access.

Defines the three mutability tiers (immutable, monotonic, mutable),
the capability enum for gating extension visibility and writability,
and the slot registry that maps each extension slot to its policy.

Provides filter_extensions() for pre-hook capability filtering and
validate_tier_constraints() for post-hook tier enforcement.
"""

# Standard
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping

from cpex.framework.extensions.constants import (
    FIELD_AGENT,
    FIELD_CLAIMS,
    FIELD_CLASSIFICATION,
    FIELD_COMPLETION,
    FIELD_CUSTOM,
    FIELD_DATA,
    FIELD_DELEGATION,
    FIELD_FRAMEWORK,
    FIELD_HTTP,
    FIELD_LABELS,
    FIELD_LLM,
    FIELD_MCP,
    FIELD_META,
    FIELD_OBJECTS,
    FIELD_PERMISSIONS,
    FIELD_PROVENANCE,
    FIELD_REQUEST,
    FIELD_ROLES,
    FIELD_SECURITY,
    FIELD_SUBJECT,
    FIELD_TEAMS,
    SlotName,
)
from cpex.framework.extensions.extensions import Extensions
from cpex.framework.extensions.security import SecurityExtension, SubjectExtension


class MutabilityTier(str, Enum):
    """Mutability tier for an extension slot.

    Attributes:
        IMMUTABLE: Set once, never changed. Pipeline rejects any delta.
        MONOTONIC: Can only grow (add elements). Pipeline validates
            before <= after.
        MUTABLE: Freely modifiable through COW.
    """

    IMMUTABLE = "immutable"
    MONOTONIC = "monotonic"
    MUTABLE = "mutable"


class Capability(str, Enum):
    """Declared capabilities that a plugin can request.

    Controls visibility (read) and writability (write/append) of
    extension slots. Write/append capabilities imply their
    corresponding read capability.

    Attributes:
        READ_SUBJECT: Access to subject.id and subject.type.
        READ_ROLES: Access to subject.roles.
        READ_TEAMS: Access to subject.teams.
        READ_CLAIMS: Access to subject.claims.
        READ_PERMISSIONS: Access to subject.permissions.
        READ_AGENT: Access to AgentExtension.
        READ_HEADERS: Read access to HTTP headers.
        WRITE_HEADERS: Read + write access to HTTP headers.
        READ_LABELS: Read access to security labels.
        APPEND_LABELS: Read + append-only access to security labels.
        READ_LABELS: Read access to security labels.
        APPEND_LABELS: Read + append-only access to security labels.
        READ_DELEGATION: Read access to DelegationExtension (chain, depth, origin, actor).
        APPEND_DELEGATION: Read + append-only access to the delegation chain.
    """

    READ_SUBJECT = "read_subject"
    READ_ROLES = "read_roles"
    READ_TEAMS = "read_teams"
    READ_CLAIMS = "read_claims"
    READ_PERMISSIONS = "read_permissions"
    READ_AGENT = "read_agent"
    READ_HEADERS = "read_headers"
    WRITE_HEADERS = "write_headers"
    READ_LABELS = "read_labels"
    APPEND_LABELS = "append_labels"
    READ_DELEGATION = "read_delegation"
    APPEND_DELEGATION = "append_delegation"


# Write/append capabilities that imply their read counterpart.
_WRITE_IMPLIES_READ: dict[Capability, Capability] = {
    Capability.WRITE_HEADERS: Capability.READ_HEADERS,
    Capability.APPEND_LABELS: Capability.READ_LABELS,
    Capability.APPEND_DELEGATION: Capability.READ_DELEGATION,
}

# Subject sub-field capabilities that imply read_subject.
_SUBJECT_IMPLIES_READ: frozenset[Capability] = frozenset(
    {
        Capability.READ_ROLES,
        Capability.READ_TEAMS,
        Capability.READ_CLAIMS,
        Capability.READ_PERMISSIONS,
    }
)


class AccessPolicy(str, Enum):
    """Declares whether an extension slot requires capabilities for visibility.

    Attributes:
        UNRESTRICTED: Visible to all plugins regardless of capabilities.
        CAPABILITY_GATED: Requires a declared capability for visibility.
    """

    UNRESTRICTED = "unrestricted"
    CAPABILITY_GATED = "capability_gated"


@dataclass(frozen=True)
class SlotPolicy:
    """Policy for a single extension slot or sub-field.

    Attributes:
        tier: The mutability tier.
        access: Whether the slot is unrestricted or capability-gated.
        read_cap: Capability required to see this slot (when capability-gated).
        write_cap: Capability required to modify this slot.
            None means no mutation path exists.
    """

    tier: MutabilityTier
    access: AccessPolicy = AccessPolicy.UNRESTRICTED
    read_cap: Capability | None = None
    write_cap: Capability | None = None


# ---------------------------------------------------------------------------
# Slot Registry — single source of truth (internal only)
# ---------------------------------------------------------------------------

_SLOT_REGISTRY: dict[str, SlotPolicy] = {
    # Unrestricted — always visible, always immutable
    SlotName.REQUEST: SlotPolicy(MutabilityTier.IMMUTABLE),
    SlotName.PROVENANCE: SlotPolicy(MutabilityTier.IMMUTABLE),
    SlotName.COMPLETION: SlotPolicy(MutabilityTier.IMMUTABLE),
    SlotName.LLM: SlotPolicy(MutabilityTier.IMMUTABLE),
    SlotName.FRAMEWORK: SlotPolicy(MutabilityTier.IMMUTABLE),
    SlotName.MCP: SlotPolicy(MutabilityTier.IMMUTABLE),
    SlotName.META: SlotPolicy(MutabilityTier.IMMUTABLE),
    # Capability-gated, immutable
    SlotName.AGENT: SlotPolicy(
        MutabilityTier.IMMUTABLE,
        access=AccessPolicy.CAPABILITY_GATED,
        read_cap=Capability.READ_AGENT,
    ),
    # Subject — granular sub-field gating
    SlotName.SECURITY_SUBJECT: SlotPolicy(
        MutabilityTier.IMMUTABLE,
        access=AccessPolicy.CAPABILITY_GATED,
        read_cap=Capability.READ_SUBJECT,
    ),
    SlotName.SECURITY_SUBJECT_ROLES: SlotPolicy(
        MutabilityTier.IMMUTABLE,
        access=AccessPolicy.CAPABILITY_GATED,
        read_cap=Capability.READ_ROLES,
    ),
    SlotName.SECURITY_SUBJECT_TEAMS: SlotPolicy(
        MutabilityTier.IMMUTABLE,
        access=AccessPolicy.CAPABILITY_GATED,
        read_cap=Capability.READ_TEAMS,
    ),
    SlotName.SECURITY_SUBJECT_CLAIMS: SlotPolicy(
        MutabilityTier.IMMUTABLE,
        access=AccessPolicy.CAPABILITY_GATED,
        read_cap=Capability.READ_CLAIMS,
    ),
    SlotName.SECURITY_SUBJECT_PERMISSIONS: SlotPolicy(
        MutabilityTier.IMMUTABLE,
        access=AccessPolicy.CAPABILITY_GATED,
        read_cap=Capability.READ_PERMISSIONS,
    ),
    # Unrestricted — always visible sub-fields
    SlotName.SECURITY_OBJECTS: SlotPolicy(MutabilityTier.IMMUTABLE),
    SlotName.SECURITY_DATA: SlotPolicy(MutabilityTier.IMMUTABLE),
    # Security labels — monotonic, capability-gated
    SlotName.SECURITY_LABELS: SlotPolicy(
        MutabilityTier.MONOTONIC,
        access=AccessPolicy.CAPABILITY_GATED,
        read_cap=Capability.READ_LABELS,
        write_cap=Capability.APPEND_LABELS,
    ),
    # HTTP — capability-gated, writable with write cap
    SlotName.HTTP: SlotPolicy(
        MutabilityTier.IMMUTABLE,
        access=AccessPolicy.CAPABILITY_GATED,
        read_cap=Capability.READ_HEADERS,
        write_cap=Capability.WRITE_HEADERS,
    ),
    # Delegation — monotonic (chain grows, never shrinks), capability-gated.
    # Contains identity-adjacent information (subject IDs, audiences, scopes).
    # Framework controls chain growth via with_new_hop(); merge validates
    # monotonic growth (new chain must be superset of original).
    SlotName.DELEGATION: SlotPolicy(
        MutabilityTier.MONOTONIC,
        access=AccessPolicy.CAPABILITY_GATED,
        read_cap=Capability.READ_DELEGATION,
        write_cap=Capability.APPEND_DELEGATION,
    ),
    # Unrestricted, mutable — no capability gate
    SlotName.CUSTOM: SlotPolicy(MutabilityTier.MUTABLE),
}

# Read-only view — prevents mutation even if imported directly
_slot_registry: Mapping[str, SlotPolicy] = MappingProxyType(_SLOT_REGISTRY)


def _has_read_access(policy: SlotPolicy, capabilities: frozenset[str]) -> bool:
    """Check if a plugin has read access to a slot.

    A plugin has read access if:
    - The slot has no read_cap (base tier, always visible), OR
    - The plugin holds the read_cap, OR
    - The plugin holds a write_cap that implies the read_cap, OR
    - For subject sub-fields: any subject sub-field cap implies
      read_subject.
    """
    if policy.access == AccessPolicy.UNRESTRICTED:
        return True
    if policy.read_cap.value in capabilities:
        return True
    # Check if any held write cap implies this read cap
    for write_cap, implied_read in _WRITE_IMPLIES_READ.items():
        if implied_read == policy.read_cap and write_cap.value in capabilities:
            return True
    # Check if any subject sub-field cap implies read_subject
    if policy.read_cap == Capability.READ_SUBJECT:
        for sub_cap in _SUBJECT_IMPLIES_READ:
            if sub_cap.value in capabilities:
                return True
    return False


def _has_subject_access(capabilities: frozenset[str]) -> bool:
    """Check if a plugin has any subject-related capability."""
    if Capability.READ_SUBJECT.value in capabilities:
        return True
    for sub_cap in _SUBJECT_IMPLIES_READ:
        if sub_cap.value in capabilities:
            return True
    return False


# ---------------------------------------------------------------------------
# Extension Filtering
# ---------------------------------------------------------------------------


def _build_filtered_subject(
    subject: SubjectExtension,
    capabilities: frozenset[str],
) -> SubjectExtension:
    """Build a filtered SubjectExtension containing only accessible fields.

    Always includes id and type (base subject access). Individual
    sub-fields (roles, teams, claims, permissions) are only populated
    if the plugin holds the corresponding capability.
    """
    return subject.model_copy(
        update={
            FIELD_ROLES: subject.roles if Capability.READ_ROLES.value in capabilities else frozenset(),
            FIELD_TEAMS: subject.teams if Capability.READ_TEAMS.value in capabilities else frozenset(),
            FIELD_CLAIMS: subject.claims if Capability.READ_CLAIMS.value in capabilities else {},
            FIELD_PERMISSIONS: (
                subject.permissions if Capability.READ_PERMISSIONS.value in capabilities else frozenset()
            ),
        }
    )


def _build_filtered_security(
    sec: SecurityExtension,
    capabilities: frozenset[str],
) -> SecurityExtension:
    """Build a filtered SecurityExtension containing only accessible fields.

    Unrestricted sub-fields (objects, data, classification) are always
    included. Capability-gated sub-fields (labels, subject) are only
    populated if the plugin holds the required capability.
    """
    fields: dict[str, Any] = {
        # Unrestricted — always included
        FIELD_OBJECTS: sec.objects,
        FIELD_DATA: sec.data,
        FIELD_CLASSIFICATION: sec.classification,
    }

    # Labels — capability-gated
    if _has_read_access(_slot_registry[SlotName.SECURITY_LABELS], capabilities):
        fields[FIELD_LABELS] = sec.labels
    else:
        fields[FIELD_LABELS] = frozenset()

    # Subject — granular capability-gated
    if sec.subject is not None and _has_subject_access(capabilities):
        fields[FIELD_SUBJECT] = _build_filtered_subject(sec.subject, capabilities)
    else:
        fields[FIELD_SUBJECT] = None

    return sec.model_copy(update=fields)


def filter_extensions(
    extensions: Extensions | None,
    capabilities: frozenset[str],
) -> Extensions | None:
    """Build a new Extensions containing only slots the plugin can access.

    Starts from an empty Extensions and copies in only the slots the
    plugin has read access to. Slots not explicitly included are left
    as None (the default). This is secure by default — if a new slot
    is added to Extensions but not registered here, it remains hidden.

    For the security extension, filtering is granular: unrestricted
    sub-fields (objects, data) are always included, while labels and
    subject sub-fields are gated by their respective capabilities.

    Args:
        extensions: The source Extensions model instance (or None).
        capabilities: Plugin's declared capability strings.

    Returns:
        A new frozen Extensions with only accessible slots populated,
        or None if input was None.
    """
    if extensions is None:
        return None

    fields: dict[str, Any] = {}

    # Unrestricted top-level slots — always included when present
    if extensions.request is not None:
        fields[FIELD_REQUEST] = extensions.request
    if extensions.provenance is not None:
        fields[FIELD_PROVENANCE] = extensions.provenance
    if extensions.completion is not None:
        fields[FIELD_COMPLETION] = extensions.completion
    if extensions.llm is not None:
        fields[FIELD_LLM] = extensions.llm
    if extensions.framework is not None:
        fields[FIELD_FRAMEWORK] = extensions.framework
    if extensions.mcp is not None:
        fields[FIELD_MCP] = extensions.mcp
    if extensions.meta is not None:
        fields[FIELD_META] = extensions.meta
    # Capability-gated: delegation
    if extensions.delegation is not None:
        if _has_read_access(_slot_registry[SlotName.DELEGATION], capabilities):
            fields[FIELD_DELEGATION] = extensions.delegation
    if extensions.custom is not None:
        fields[FIELD_CUSTOM] = extensions.custom

    # Capability-gated top-level slots — included only with access
    if extensions.agent is not None:
        if _has_read_access(_slot_registry[SlotName.AGENT], capabilities):
            fields[FIELD_AGENT] = extensions.agent

    if extensions.http is not None:
        if _has_read_access(_slot_registry[SlotName.HTTP], capabilities):
            fields[FIELD_HTTP] = extensions.http

    # Security — granular sub-field filtering
    if extensions.security is not None:
        fields[FIELD_SECURITY] = _build_filtered_security(extensions.security, capabilities)

    return Extensions(**fields)


# ---------------------------------------------------------------------------
# Tier Validation
# ---------------------------------------------------------------------------


class TierViolationError(Exception):
    """Raised when a plugin violates a mutability tier constraint.

    Attributes:
        plugin_name: Name of the offending plugin.
        slot: The extension slot that was violated.
        tier: The mutability tier of the slot.
        detail: Description of the violation.
    """

    def __init__(
        self,
        plugin_name: str,
        slot: str,
        tier: MutabilityTier,
        detail: str,
    ) -> None:
        """Initialise a tier violation error.

        Args:
            plugin_name: Name of the offending plugin.
            slot: The extension slot that was violated.
            tier: The mutability tier of the slot.
            detail: Description of the violation.
        """
        self.plugin_name = plugin_name
        self.slot = slot
        self.tier = tier
        self.detail = detail
        super().__init__(f"Plugin '{plugin_name}' violated {tier.value} tier on '{slot}': {detail}")


def _resolve_slot(ext: Extensions | None, dot_path: str) -> Any:
    """Resolve a dot-notation slot path to its value."""
    if ext is None:
        return None
    obj: Any = ext
    for part in dot_path.split("."):
        if obj is None:
            return None
        obj = getattr(obj, part, None)
    return obj


def _is_monotonic_superset(before: Any, after: Any) -> bool:
    """Check that after is a superset of before for monotonic validation."""
    if before is None or (isinstance(before, frozenset) and len(before) == 0):
        return True
    if after is None:
        return isinstance(before, frozenset) and len(before) == 0
    if isinstance(before, frozenset) and isinstance(after, frozenset):
        return before <= after
    return before == after


def validate_tier_constraints(
    before: Extensions | None,
    after: Extensions | None,
    capabilities: frozenset[str],
    plugin_name: str,
) -> None:
    """Validate that tier constraints were respected after a plugin transform.

    Compares the original (unfiltered) extensions against the modified
    extensions. Raises TierViolationError on any violation.

    Args:
        before: Original Extensions before plugin execution.
        after: Extensions after plugin execution.
        capabilities: Plugin's declared capability strings.
        plugin_name: Name of the plugin (for error messages).

    Raises:
        TierViolationError: If a tier constraint was violated.
    """
    if before is None and after is None:
        return

    for slot_name, policy in _slot_registry.items():
        before_val = _resolve_slot(before, slot_name)
        after_val = _resolve_slot(after, slot_name)

        # No change — always fine
        if before_val == after_val:
            continue

        # Mutable tier with no write_cap — freely modifiable
        if policy.tier == MutabilityTier.MUTABLE and policy.write_cap is None:
            continue

        # Something changed — check if mutation is allowed
        if policy.write_cap is None:
            raise TierViolationError(
                plugin_name,
                slot_name,
                policy.tier,
                "slot has no write capability and cannot be modified",
            )

        if policy.write_cap.value not in capabilities:
            raise TierViolationError(
                plugin_name,
                slot_name,
                policy.tier,
                f"plugin lacks '{policy.write_cap.value}' capability",
            )

        # Plugin has write capability — check tier-specific constraints
        if policy.tier == MutabilityTier.MONOTONIC:
            if not _is_monotonic_superset(before_val, after_val):
                raise TierViolationError(
                    plugin_name,
                    slot_name,
                    policy.tier,
                    "monotonic slot had elements removed",
                )


# ---------------------------------------------------------------------------
# Selective Merge
# ---------------------------------------------------------------------------


def _merge_security(
    original: SecurityExtension,
    plugin_sec: SecurityExtension | None,
    capabilities: frozenset[str],
    plugin_name: str,
) -> SecurityExtension | None:
    """Accept writable security changes back into the original.

    - subject, objects, data, classification: immutable — ignored.
    - labels: monotonic — accepted only if the plugin holds
      append_labels and the result is a superset of the original.

    Returns None if nothing changed (caller should skip the update).
    """
    if plugin_sec is None:
        return None

    # Labels — monotonic, capability-gated
    if Capability.APPEND_LABELS.value in capabilities and plugin_sec.labels != original.labels:
        if not _is_monotonic_superset(original.labels, plugin_sec.labels):
            raise TierViolationError(
                plugin_name,
                SlotName.SECURITY_LABELS,
                MutabilityTier.MONOTONIC,
                "monotonic slot had elements removed",
            )
        return original.model_copy(update={FIELD_LABELS: plugin_sec.labels})

    return None


def merge_extensions(
    original: Extensions | None,
    plugin_output: Extensions | None,
    capabilities: frozenset[str],
    plugin_name: str,
) -> Extensions | None:
    """Merge accepted plugin changes back into the original Extensions.

    Only writable slots are read from the plugin's output:

    - **Immutable** slots (request, provenance, agent, etc.) are
      ignored — the original values are preserved.
    - **Monotonic** slots (security.labels) are accepted only when
      the plugin holds the write capability and the result is a
      superset of the original.
    - **Mutable** slots (custom) are accepted unconditionally.
    - **Guarded-writable** slots (http) are accepted only when the
      plugin holds the write capability.

    If nothing changed, the original object is returned as-is.

    This is the complement of ``filter_extensions`` (which controls
    what a plugin *sees*).  ``merge_extensions`` controls what the
    manager *accepts back*.

    Args:
        original: The authoritative Extensions before plugin execution.
        plugin_output: The Extensions returned by the plugin.
        capabilities: Plugin's declared capability strings.
        plugin_name: Name of the plugin (for error messages).

    Returns:
        The original Extensions with accepted changes applied via
        model_copy, or the original unchanged if nothing was accepted.

    Raises:
        TierViolationError: If a monotonic slot had elements removed.
    """
    if original is None:
        return None
    if plugin_output is None:
        return original

    updates: dict[str, Any] = {}

    # HTTP — writable only with write_headers capability
    if (
        Capability.WRITE_HEADERS.value in capabilities
        and plugin_output.http is not None
        and plugin_output.http != original.http
    ):
        updates[FIELD_HTTP] = plugin_output.http

    # Security — mixed tiers, delegate to helper
    if original.security is not None:
        merged_sec = _merge_security(original.security, plugin_output.security, capabilities, plugin_name)
        if merged_sec is not None:
            updates[FIELD_SECURITY] = merged_sec

    # Delegation — monotonic (chain must grow, never shrink), requires append_delegation
    if (
        Capability.APPEND_DELEGATION.value in capabilities
        and plugin_output.delegation is not None
        and original.delegation is not None
        and plugin_output.delegation != original.delegation
    ):
        # Validate monotonic: new chain must be a superset (longer or equal, same prefix)
        orig_chain = original.delegation.chain
        new_chain = plugin_output.delegation.chain
        if len(new_chain) < len(orig_chain):
            raise TierViolationError(
                plugin_name,
                FIELD_DELEGATION,
                MutabilityTier.MONOTONIC,
                f"shrank delegation chain (was {len(orig_chain)} hops, now {len(new_chain)})",
            )
        if new_chain[: len(orig_chain)] != orig_chain:
            raise TierViolationError(
                plugin_name,
                FIELD_DELEGATION,
                MutabilityTier.MONOTONIC,
                "modified existing delegation chain hops",
            )
        updates[FIELD_DELEGATION] = plugin_output.delegation
    elif (
        Capability.APPEND_DELEGATION.value in capabilities
        and plugin_output.delegation is not None
        and original.delegation is None
    ):
        # First delegation — accept (requires append_delegation capability)
        updates[FIELD_DELEGATION] = plugin_output.delegation

    # Custom — mutable, no capability gate
    if plugin_output.custom != original.custom:
        updates[FIELD_CUSTOM] = plugin_output.custom

    if not updates:
        return original

    return original.model_copy(update=updates)
