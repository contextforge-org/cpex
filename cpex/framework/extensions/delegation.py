# -*- coding: utf-8 -*-
"""Location: ./cpex/framework/extensions/delegation.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Teryl Taylor

Delegation extension models.
Carries the delegation chain state through the CMF message for policy
evaluation. The chain grows monotonically — each hop appends, never
removes. Scope narrowing is enforced at the framework level.

See: docs/delegation-hooks-design.md
"""

# Standard
from datetime import UTC, datetime

# Third-Party
from pydantic import BaseModel, ConfigDict, Field


class DelegationHop(BaseModel):
    """One hop in the delegation chain.

    Each hop represents one step: "entity X delegated to entity Y
    for audience Z with these scopes." Immutable once created.

    Attributes:
        subject_id: Who is acting at this hop.
        subject_type: Entity kind (user, agent, service).
        audience: Target audience for this hop's token.
        scopes_granted: What this hop's token can do.
        timestamp: When this hop was created.
        ttl_seconds: Token lifetime for this hop.
        strategy: How the token was obtained (token_exchange, ucan, etc.).
        from_cache: Whether the token came from cache.

    Examples:
        >>> hop = DelegationHop(
        ...     subject_id="alice@corp.com",
        ...     subject_type="user",
        ...     scopes_granted=("read:compensation",),
        ...     timestamp=datetime(2025, 1, 1),
        ...     strategy="token_exchange",
        ... )
        >>> hop.subject_id
        'alice@corp.com'
    """

    model_config = ConfigDict(frozen=True)

    subject_id: str = Field(description="Who is acting at this hop.")
    subject_type: str = Field(description="Entity kind: user, agent, service, system.")
    audience: str | None = Field(default=None, description="Target audience for this hop's token.")
    scopes_granted: tuple[str, ...] = Field(default=(), description="Scopes this hop's token grants.")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC), description="When this hop was created.")
    ttl_seconds: int | None = Field(default=None, description="Token lifetime in seconds.")
    strategy: str | None = Field(default=None, description="Token strategy: token_exchange, ucan, passthrough, etc.")
    from_cache: bool = Field(default=False, description="Whether the token came from cache.")


class DelegationExtension(BaseModel):
    """Delegation chain state carried in the CMF message.

    Mutability tiers:
    - chain: monotonic (grows with each hop, never shrinks)
    - origin_subject_id, delegated: immutable (set at first delegation)
    - actor_subject_id: updates per hop (current actor changes)

    The chain is available to the DSL via the delegation.* namespace:
        delegation.origin, delegation.actor, delegation.depth,
        delegation.age, delegated

    Attributes:
        chain: Ordered list of delegation hops (monotonic growth).
        depth: Number of hops in the chain.
        origin_subject_id: Original caller (immutable once set).
        actor_subject_id: Current actor (latest hop's subject).
        delegated: Whether this request is delegated.
        age_seconds: Seconds since the original delegation.

    Examples:
        >>> ext = DelegationExtension()
        >>> ext.delegated
        False
        >>> ext.depth
        0
    """

    model_config = ConfigDict(frozen=True)

    chain: tuple[DelegationHop, ...] = Field(default=(), description="Ordered delegation hops.")
    depth: int = Field(default=0, description="Number of hops.")
    origin_subject_id: str | None = Field(default=None, description="Original caller.")
    actor_subject_id: str | None = Field(default=None, description="Current actor.")
    delegated: bool = Field(default=False, description="Whether this is a delegated request.")
    age_seconds: float = Field(default=0.0, description="Seconds since original delegation.")

    def with_new_hop(self, hop: DelegationHop) -> "DelegationExtension":
        """Create a new DelegationExtension with an appended hop.

        Returns a new instance — the original is unchanged (immutable).
        The framework enforces scope narrowing before calling this.

        Args:
            hop: The new delegation hop to append.

        Returns:
            New DelegationExtension with the hop appended.
        """
        new_chain = self.chain + (hop,)
        origin = self.origin_subject_id or hop.subject_id
        age = (datetime.now(UTC) - self.chain[0].timestamp).total_seconds() if self.chain else 0.0
        return DelegationExtension(
            chain=new_chain,
            depth=len(new_chain),
            origin_subject_id=origin,
            actor_subject_id=hop.subject_id,
            delegated=True,
            age_seconds=age,
        )
