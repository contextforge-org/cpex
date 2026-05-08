# -*- coding: utf-8 -*-
"""Location: ./cpex/framework/hooks/identity.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Teryl Taylor

Hook definitions for identity resolution and token delegation.

Two hooks, two phases:
- IdentityResolve: inbound — decode token, verify, map to SubjectExtension
- TokenDelegate: outbound — exchange token for downstream tool credential

See: docs/delegation-hooks-design.md

These hooks produce CMF types (SubjectExtension, DelegationExtension)
and complement the legacy HTTP auth hooks in http.py which operate
on flat strings and dicts.
"""

# Standard
from enum import Enum
from typing import Any

# Third-Party
from pydantic import BaseModel, ConfigDict, Field, SecretStr

# First-Party
from cpex.framework.extensions.delegation import DelegationExtension
from cpex.framework.extensions.security import SubjectExtension
from cpex.framework.models import PluginPayload, PluginResult

# ---------------------------------------------------------------------------
# Hook Types
# ---------------------------------------------------------------------------


class IdentityHookType(str, Enum):
    """Identity and delegation hook points.

    Attributes:
        IDENTITY_RESOLVE: Inbound — decode and validate token,
            produce SubjectExtension.
        TOKEN_DELEGATE: Outbound — exchange/mint token for
            downstream tool invocation.

    Examples:
        >>> IdentityHookType.IDENTITY_RESOLVE
        <IdentityHookType.IDENTITY_RESOLVE: 'identity_resolve'>
        >>> IdentityHookType.TOKEN_DELEGATE.value
        'token_delegate'
    """

    IDENTITY_RESOLVE = "identity_resolve"
    TOKEN_DELEGATE = "token_delegate"


# ---------------------------------------------------------------------------
# IdentityResolve — Inbound
# ---------------------------------------------------------------------------


class IdentityPayload(PluginPayload):
    """Payload for the identity resolution hook.

    Carries the raw credential extracted from the inbound request.
    The hook implementation decodes, validates, and maps it to a
    SubjectExtension.

    Attributes:
        raw_token: The raw token string (JWT, opaque, API key, etc.).
        source: How the credential was extracted.
        headers: Full HTTP headers for custom auth extraction.
        client_host: Client IP address (if available).
        client_port: Client port (if available).

    Examples:
        >>> payload = IdentityPayload(
        ...     raw_token="eyJhbGciOi...",
        ...     source="bearer",
        ...     headers={"authorization": "Bearer eyJhbGciOi..."},
        ... )
        >>> payload.source
        'bearer'
        >>> str(payload.raw_token)
        '**********'
        >>> payload.raw_token.get_secret_value()
        'eyJhbGciOi...'
    """

    raw_token: SecretStr = Field(description="Raw credential string. Redacted on serialization.")
    source: str = Field(
        default="bearer",
        description="Credential source: bearer, mtls, api_key, custom.",
    )
    headers: dict[str, str] = Field(
        default_factory=dict,
        description="Full HTTP headers for custom auth extraction.",
    )
    client_host: str | None = Field(default=None, description="Client IP address.")
    client_port: int | None = Field(default=None, description="Client port.")


class IdentityResult(PluginPayload):
    """Result of identity resolution — returned as modified_payload.

    Either provides a resolved SubjectExtension, or rejects with
    a status code and reason. The framework validates the result
    and seals the SubjectExtension as immutable.

    Extends PluginPayload so it can be carried as the modified_payload
    in PluginResult[IdentityResult]. This follows the same pattern as
    HttpAuthCheckPermissionResultPayload.

    Attributes:
        subject: The resolved identity. None if rejected.
        delegation: Initial delegation state from act claims.
        rejected: Whether the identity was rejected.
        reject_status: HTTP status code for rejection (401 or 403).
        reject_reason: Human-readable rejection reason.
        raw_claims: Full decoded claims for audit/policy (optional).

    Examples:
        >>> result = IdentityResult(
        ...     subject=SubjectExtension(id="alice@corp.com", type="user"),
        ... )
        >>> result.rejected
        False

        >>> rejected = IdentityResult(
        ...     rejected=True,
        ...     reject_status=401,
        ...     reject_reason="Token expired",
        ... )
    """

    subject: SubjectExtension | None = Field(default=None, description="Resolved identity.")
    delegation: DelegationExtension | None = Field(
        default=None,
        description="Initial delegation state (from act claims in JWT).",
    )
    rejected: bool = Field(default=False, description="Whether the identity was rejected.")
    reject_status: int = Field(default=401, description="HTTP status code for rejection.")
    reject_reason: str = Field(default="", description="Rejection reason.")
    raw_claims: dict[str, Any] = Field(
        default_factory=dict,
        description="Full decoded token claims (for audit/policy).",
    )


IdentityResolveResult = PluginResult[IdentityResult]


# ---------------------------------------------------------------------------
# TokenDelegate — Outbound
# ---------------------------------------------------------------------------


class AttenuationConfig(BaseModel):
    """Configuration for token scope attenuation from DSL route config.

    Attributes:
        capabilities: Specific capabilities to grant.
        resource_template: URI template with argument substitution.
        actions: Allowed actions on the resource.
        ttl_seconds: Token lifetime override.

    Examples:
        >>> config = AttenuationConfig(
        ...     capabilities=["read:compensation"],
        ...     resource_template="hr://employees/{{ args.employee_id }}",
        ...     actions=["read"],
        ...     ttl_seconds=60,
        ... )
    """

    model_config = ConfigDict(frozen=True)

    capabilities: list[str] = Field(default_factory=list)
    resource_template: str | None = None
    actions: list[str] = Field(default_factory=list)
    ttl_seconds: int | None = None


class DelegationPayload(PluginPayload):
    """Payload for the token delegation hook.

    Carries the target tool information and security profile.
    The hook implementation exchanges/mints a token for the target.
    Subject and existing delegation chain are read from the CMF
    message extensions (not duplicated here).

    Attributes:
        target_name: Tool, agent, or resource being called.
        target_type: Entity type: tool, agent, resource, service.
        target_audience: Audience URI for the target (from config).
        required_permissions: From ObjectSecurityProfile.permissions.
        trust_domain: From ObjectSecurityProfile.trust_domain.
        auth_enforced_by: Who enforces auth: caller, target, or both.
        route_attenuation: Scope attenuation config from DSL route.
        bearer_token: The caller's current bearer token (for exchange).

    Examples:
        >>> payload = DelegationPayload(
        ...     target_name="get_compensation",
        ...     target_type="tool",
        ...     required_permissions=["read:compensation"],
        ...     auth_enforced_by="target",
        ...     bearer_token="eyJhbGciOi...",
        ... )
    """

    target_name: str = Field(description="Tool/agent/resource being called.")
    target_type: str = Field(default="tool", description="Entity type.")
    target_audience: str | None = Field(default=None, description="Audience URI.")
    required_permissions: list[str] = Field(default_factory=list, description="Required permissions.")
    trust_domain: str | None = Field(default=None, description="Trust domain.")
    auth_enforced_by: str = Field(default="caller", description="Auth enforcement: caller, target, both.")
    route_attenuation: AttenuationConfig | None = Field(default=None, description="Scope attenuation config.")
    bearer_token: SecretStr | None = Field(
        default=None, description="Caller's current bearer token. Redacted on serialization."
    )


class DelegationResult(PluginPayload):
    """Result of token delegation — returned as modified_payload.

    The delegated token is returned separately (never stored in
    Extensions). The delegation_update is merged into Extensions
    by the framework.

    Extends PluginPayload so it can be carried as the modified_payload
    in PluginResult[DelegationResult].

    Attributes:
        delegated_token: The credential for the downstream target.
        delegation_update: Updated DelegationExtension (merged by framework).
        forwarded_headers: Additional headers for the downstream request.
        cache_key: Token cache key (for reuse).
        cache_ttl: Seconds to cache the token.

    Examples:
        >>> result = DelegationResult(
        ...     delegated_token="eyJhbGciOi...",
        ...     forwarded_headers={"Authorization": "Bearer eyJhbGciOi..."},
        ... )
    """

    delegated_token: str | None = Field(default=None, description="Credential for downstream.")
    delegation_update: DelegationExtension = Field(
        default_factory=DelegationExtension,
        description="Updated delegation chain.",
    )
    forwarded_headers: dict[str, str] = Field(
        default_factory=dict,
        description="Additional headers for downstream.",
    )
    cache_key: str | None = Field(default=None, description="Token cache key.")
    cache_ttl: int | None = Field(default=None, description="Cache TTL in seconds.")


TokenDelegateResult = PluginResult[DelegationResult]


# ---------------------------------------------------------------------------
# Hook Registration
# ---------------------------------------------------------------------------


def _register_identity_hooks() -> None:
    """Register identity hooks in the global registry.

    Called at module load time. Idempotent.
    """
    from cpex.framework.hooks.registry import get_hook_registry

    registry = get_hook_registry()

    if not registry.is_registered(IdentityHookType.IDENTITY_RESOLVE):
        registry.register_hook(
            IdentityHookType.IDENTITY_RESOLVE,
            IdentityPayload,
            IdentityResolveResult,
        )

    if not registry.is_registered(IdentityHookType.TOKEN_DELEGATE):
        registry.register_hook(
            IdentityHookType.TOKEN_DELEGATE,
            DelegationPayload,
            TokenDelegateResult,
        )


_register_identity_hooks()
