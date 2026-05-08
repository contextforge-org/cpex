# -*- coding: utf-8 -*-
"""Base classes for PDP resolvers.

Defines the interface that all PDP resolvers implement, and the result
type returned by PDP calls. These mirror the Rust PdpResolver trait
and ExternalPdpResult struct in apl_core.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PdpResult:
    """Result of an external PDP evaluation.

    Maps to apl_core::ExternalPdpResult on the Rust side.
    """

    allowed: bool
    """Whether the PDP allowed the request."""

    reason: str | None = None
    """Human-readable reason for the decision."""

    context: dict[str, Any] = field(default_factory=dict)
    """Additional context from the PDP (obligations, advice, etc.)."""

    from_cache: bool = False
    """Whether this result was served from cache."""

    latency_ms: float = 0.0
    """Round-trip latency of the PDP call in milliseconds."""


class PdpResolver(ABC):
    """Abstract base for external PDP resolvers.

    Implementations handle the transport (HTTP, gRPC, in-process) and
    protocol (AuthZen, OPA, Cedar) specifics. The APL pipeline calls
    `resolve()` with the input built from the AttributeBag and
    ContentSurface, and uses the returned PdpResult to allow/deny.

    Resolvers are expected to be reusable across requests — create
    once at gateway startup, call `resolve()` per-request, call
    `close()` at shutdown.
    """

    @abstractmethod
    async def resolve(self, input_data: dict[str, Any]) -> PdpResult:
        """Evaluate a policy decision against the external PDP.

        Args:
            input_data: Context extracted from the APL pipeline.
                Keys depend on the configured input_namespaces:
                - "subject": identity attributes
                - "authorization_details": RFC 9396 RAR details
                - "delegation": delegation chain attributes
                - "session": session state (labels, tool_calls, cost)
                - "args": tool call arguments (from ContentSurface)
                - "tool": tool name (from static_context)
                - "action": route action (from static_context)

        Returns:
            PdpResult with the PDP's decision.

        Raises:
            PdpError: If the PDP call fails and cannot be handled
                by the resolver's retry/fallback logic.
        """
        ...

    async def close(self) -> None:
        """Clean up resources (HTTP clients, connections).

        Called at gateway shutdown. Override if the resolver holds
        persistent connections.
        """
        pass


class PdpError(Exception):
    """Raised when a PDP call fails irrecoverably."""

    def __init__(self, message: str, endpoint: str, cause: Exception | None = None):
        """Initialize a PDP error.

        Args:
            message: Human-readable error description.
            endpoint: The PDP endpoint that failed.
            cause: The underlying exception, if any.
        """
        super().__init__(message)
        self.endpoint = endpoint
        self.cause = cause
