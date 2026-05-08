# -*- coding: utf-8 -*-
"""Location: ./cpex/framework/extensions/security.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Teryl Taylor

Security extension models.
Carries data classification, security labels, authenticated identity,
access control profiles, and data governance policies.

The SecurityExtension itself is monotonic tier — labels can only be
added, never removed, during normal message flow. Its nested fields
(subject, objects, data) are immutable tier.
"""

# Standard
from enum import Enum

# Third-Party
from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Subject
# ---------------------------------------------------------------------------


class SubjectType(str, Enum):
    """Closed-set enumeration of subject types.

    Attributes:
        USER: Human user.
        AGENT: Autonomous agent.
        SERVICE: Backend service.
        SYSTEM: System-level principal.

    Examples:
        >>> SubjectType.USER
        <SubjectType.USER: 'user'>
        >>> SubjectType("agent")
        <SubjectType.AGENT: 'agent'>
    """

    USER = "user"
    AGENT = "agent"
    SERVICE = "service"
    SYSTEM = "system"


class SubjectExtension(BaseModel):
    """Authenticated entity making the request.

    Access to individual fields is controlled by declared capabilities
    on the MessageView. Immutable — the processing pipeline rejects
    any modifications.

    Attributes:
        id: Unique subject identifier.
        type: Subject kind.
        roles: Assigned roles (developer, admin, viewer, etc.).
        permissions: Granted permissions (tools.execute, db.read, etc.).
        teams: Team memberships (for multi-tenant scoping).
        claims: Raw identity claims (JWT, SAML).

    Examples:
        >>> subject = SubjectExtension(
        ...     id="user-alice",
        ...     type=SubjectType.USER,
        ...     roles={"admin", "developer"},
        ...     permissions={"tools.execute", "db.read"},
        ... )
        >>> subject.id
        'user-alice'
        >>> "admin" in subject.roles
        True
        >>> "db.read" in subject.permissions
        True
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(description="Unique subject identifier.")
    type: SubjectType = Field(description="Subject kind.")
    roles: frozenset[str] = Field(default_factory=frozenset, description="Assigned roles.")
    permissions: frozenset[str] = Field(default_factory=frozenset, description="Granted permissions.")
    teams: frozenset[str] = Field(default_factory=frozenset, description="Team memberships.")
    claims: dict[str, str] = Field(default_factory=dict, description="Raw identity claims (JWT, SAML).")


# ---------------------------------------------------------------------------
# Object Security Profile
# ---------------------------------------------------------------------------


class ObjectSecurityProfile(BaseModel):
    """Access control contract declared by or for an object.

    Lives on extensions.security.objects, keyed by entity name/URI.
    Evaluated on pre-hook views (tool_call, resource request, prompt
    request). Immutable — the processing pipeline rejects any
    modifications.

    Attributes:
        managed_by: Who enforces access control: host, tool, or both.
        permissions: Required permissions to invoke.
        trust_domain: Trust domain: internal, external, or privileged.
        data_scope: Field names this entity accesses/returns.

    Examples:
        >>> profile = ObjectSecurityProfile(
        ...     managed_by="tool",
        ...     permissions=["read:compensation"],
        ...     trust_domain="internal",
        ...     data_scope=["salary", "bonus"],
        ... )
        >>> profile.managed_by
        'tool'
        >>> "read:compensation" in profile.permissions
        True
    """

    model_config = ConfigDict(frozen=True)

    managed_by: str = Field(default="host", description="Who enforces access control: host, tool, or both.")
    permissions: list[str] = Field(default_factory=list, description="Required permissions to invoke.")
    trust_domain: str | None = Field(default=None, description="Trust domain: internal, external, or privileged.")
    data_scope: list[str] = Field(default_factory=list, description="Field names this entity accesses/returns.")


# ---------------------------------------------------------------------------
# Data Policy
# ---------------------------------------------------------------------------


class RetentionPolicy(BaseModel):
    """Data retention constraints.

    Attributes:
        max_age_seconds: Maximum retention duration in seconds.
        policy: Retention class: session, transient, persistent, or none.
        delete_after: ISO timestamp after which data must be deleted.

    Examples:
        >>> ret = RetentionPolicy(policy="session", max_age_seconds=3600)
        >>> ret.policy
        'session'
        >>> ret.max_age_seconds
        3600
    """

    model_config = ConfigDict(frozen=True)

    max_age_seconds: int | None = Field(default=None, description="Maximum retention duration in seconds.")
    policy: str = Field(default="persistent", description="Retention class: session, transient, persistent, none.")
    delete_after: str | None = Field(default=None, description="ISO timestamp after which data must be deleted.")


class DataPolicy(BaseModel):
    """Data governance policy for data returned by an entity.

    Lives on extensions.security.data, keyed by entity name/URI.
    Enforced on post-hook views (tool_result, resource response,
    prompt result). Always enforced by the gateway — the tool
    declares, the framework enforces. Immutable — the processing
    pipeline rejects any modifications.

    Attributes:
        apply_labels: Labels to stamp on output (PII, financial, etc.).
        allowed_actions: What downstream can do. None means unrestricted.
        denied_actions: What downstream cannot do (export, forward, log_raw).
        retention: How long data can be kept.

    Examples:
        >>> policy = DataPolicy(
        ...     apply_labels=["PII", "financial"],
        ...     denied_actions=["export", "forward", "log_raw"],
        ...     retention=RetentionPolicy(policy="session", max_age_seconds=7200),
        ... )
        >>> "PII" in policy.apply_labels
        True
        >>> policy.retention.policy
        'session'
    """

    model_config = ConfigDict(frozen=True)

    apply_labels: list[str] = Field(default_factory=list, description="Labels to stamp on output.")
    allowed_actions: list[str] | None = Field(
        default=None, description="What downstream can do. None means unrestricted."
    )
    denied_actions: list[str] = Field(default_factory=list, description="What downstream cannot do.")
    retention: RetentionPolicy | None = Field(default=None, description="How long data can be kept.")


# ---------------------------------------------------------------------------
# SecurityExtension
# ---------------------------------------------------------------------------


class SecurityExtension(BaseModel):
    """Data classification, security labels, and security-relevant context.

    Monotonic tier for labels — labels can only be added, never removed,
    during normal message flow. Removal requires a privileged
    declassification operation that is audited separately. The nested
    fields (subject, objects, data) are immutable.

    Attributes:
        labels: Security/data labels (PII, CONFIDENTIAL, SECRET, etc.).
        classification: Data classification level.
        subject: Authenticated identity.
        objects: Access control profiles, keyed by entity identifier.
        data: Data governance policies, keyed by entity identifier.

    Examples:
        >>> ext = SecurityExtension(
        ...     labels=frozenset({"PII", "CONFIDENTIAL"}),
        ...     classification="confidential",
        ...     subject=SubjectExtension(
        ...         id="user-alice",
        ...         type=SubjectType.USER,
        ...         roles=frozenset({"admin"}),
        ...     ),
        ... )
        >>> "PII" in ext.labels
        True
        >>> ext.subject.id
        'user-alice'

        >>> # Monotonic label addition via model_copy
        >>> updated = ext.model_copy(update={"labels": ext.labels | frozenset({"financial"})})
        >>> "financial" in updated.labels
        True
        >>> "PII" in updated.labels
        True
    """

    model_config = ConfigDict(frozen=True)

    labels: frozenset[str] = Field(default_factory=frozenset, description="Security/data labels.")
    classification: str | None = Field(default=None, description="Data classification level.")
    subject: SubjectExtension | None = Field(default=None, description="Authenticated identity.")
    objects: dict[str, ObjectSecurityProfile] = Field(
        default_factory=dict, description="Access control profiles, keyed by entity identifier."
    )
    data: dict[str, DataPolicy] = Field(
        default_factory=dict, description="Data governance policies, keyed by entity identifier."
    )
