# -*- coding: utf-8 -*-
"""Location: ./cpex/framework/extensions/__init__.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Teryl Taylor

Extensions Package.
Provides structured, typed extension models for identity, security,
governance, and execution context metadata. Extensions are designed
to be reusable across different payload types.
"""

# First-Party
from cpex.framework.extensions.agent import AgentExtension, ConversationContext
from cpex.framework.extensions.completion import CompletionExtension, StopReason, TokenUsage
from cpex.framework.extensions.constants import SlotName
from cpex.framework.extensions.delegation import DelegationExtension, DelegationHop
from cpex.framework.extensions.extensions import Extensions
from cpex.framework.extensions.framework import FrameworkExtension
from cpex.framework.extensions.http import HttpExtension
from cpex.framework.extensions.llm import LLMExtension
from cpex.framework.extensions.mcp import (
    MCPExtension,
    PromptMetadata,
    ResourceMetadata,
    ToolMetadata,
)
from cpex.framework.extensions.meta import MetaExtension
from cpex.framework.extensions.provenance import ProvenanceExtension
from cpex.framework.extensions.request import RequestExtension
from cpex.framework.extensions.security import (
    DataPolicy,
    ObjectSecurityProfile,
    RetentionPolicy,
    SecurityExtension,
    SubjectExtension,
    SubjectType,
)
from cpex.framework.extensions.tiers import (
    AccessPolicy,
    Capability,
    MutabilityTier,
    TierViolationError,
)

__all__ = [
    "AccessPolicy",
    "SlotName",
    "AgentExtension",
    "Capability",
    "CompletionExtension",
    "ConversationContext",
    "DataPolicy",
    "DelegationExtension",
    "DelegationHop",
    "Extensions",
    "FrameworkExtension",
    "HttpExtension",
    "LLMExtension",
    "MCPExtension",
    "MetaExtension",
    "MutabilityTier",
    "ObjectSecurityProfile",
    "PromptMetadata",
    "ProvenanceExtension",
    "RequestExtension",
    "ResourceMetadata",
    "RetentionPolicy",
    "SecurityExtension",
    "StopReason",
    "SubjectExtension",
    "SubjectType",
    "TierViolationError",
    "TokenUsage",
    "ToolMetadata",
]
