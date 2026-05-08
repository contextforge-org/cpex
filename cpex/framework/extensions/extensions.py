# -*- coding: utf-8 -*-
"""Location: ./cpex/framework/extensions/extensions.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Teryl Taylor

Extensions container model.
Aggregates all typed extension models into a single container that
attaches to a Message. Each extension slot corresponds to a specific
mutability tier enforced by the processing pipeline.
"""

# Standard
from typing import Any

# Third-Party
from pydantic import BaseModel, ConfigDict, Field

# First-Party
from cpex.framework.extensions.agent import AgentExtension
from cpex.framework.extensions.completion import CompletionExtension
from cpex.framework.extensions.delegation import DelegationExtension
from cpex.framework.extensions.framework import FrameworkExtension
from cpex.framework.extensions.http import HttpExtension
from cpex.framework.extensions.llm import LLMExtension
from cpex.framework.extensions.mcp import MCPExtension
from cpex.framework.extensions.meta import MetaExtension
from cpex.framework.extensions.provenance import ProvenanceExtension
from cpex.framework.extensions.request import RequestExtension
from cpex.framework.extensions.security import SecurityExtension


class Extensions(BaseModel):
    """Container for all typed message extensions.

    Each extension slot carries contextual metadata with an explicit
    mutability tier enforced by the processing pipeline during
    copy-on-write operations.

    Frozen by design — consumers must use model_copy(update={...})
    to create modified copies.

    Attributes:
        request: Execution environment, request ID, timestamp, tracing (immutable).
        agent: Session tracking, multi-agent lineage, user intent (immutable).
        http: HTTP headers with capability-gated access (guarded).
        security: Labels, classification, identity, access control, data policy (monotonic/immutable).
        mcp: Tool, resource, or prompt metadata (immutable).
        completion: Stop reason, token usage, model, latency (immutable).
        provenance: Source, message ID, parent ID (immutable).
        llm: Model identity and capabilities (immutable).
        framework: Agentic framework context (immutable).
        meta: Host-provided operational metadata — tags, scope, properties (immutable).
        custom: Custom extensions (mutable).

    Examples:
        >>> ext = Extensions(
        ...     request=RequestExtension(
        ...         environment="production",
        ...         request_id="req-001",
        ...     ),
        ...     llm=LLMExtension(
        ...         model_id="gpt-4o",
        ...         provider="openai",
        ...     ),
        ... )
        >>> ext.request.environment
        'production'
        >>> ext.llm.provider
        'openai'
        >>> ext.security is None
        True

        >>> # Frozen: modifications require model_copy
        >>> updated = ext.model_copy(update={"custom": {"trace": True}})
        >>> updated.custom
        {'trace': True}
        >>> ext.custom is None
        True
    """

    model_config = ConfigDict(frozen=True)

    request: RequestExtension | None = Field(default=None, description="Execution environment and tracing.")
    agent: AgentExtension | None = Field(default=None, description="Agent execution context.")
    http: HttpExtension | None = Field(default=None, description="HTTP request context.")
    security: SecurityExtension | None = Field(default=None, description="Security labels and identity.")
    delegation: DelegationExtension | None = Field(default=None, description="Delegation chain state.")
    mcp: MCPExtension | None = Field(default=None, description="MCP entity metadata.")
    completion: CompletionExtension | None = Field(default=None, description="LLM completion information.")
    provenance: ProvenanceExtension | None = Field(default=None, description="Origin and threading.")
    llm: LLMExtension | None = Field(default=None, description="Model identity and capabilities.")
    framework: FrameworkExtension | None = Field(default=None, description="Agentic framework context.")
    meta: MetaExtension | None = Field(default=None, description="Host-provided operational metadata.")
    custom: dict[str, Any] | None = Field(default=None, description="Custom extensions (mutable).")
