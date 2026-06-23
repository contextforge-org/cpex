# Location: ./bindings/python/python/cpex/__init__.py
# Copyright 2025
# SPDX-License-Identifier: Apache-2.0
# Authors: Ted Habeck
#
# Rust-backed cpex package — re-exports from the native extension module.
#
# Import from here, not from cpex._lib directly.
# No import-time side effects beyond loading the native extension (R4, #7).
from cpex._lib import (
    # Core runtime.
    PipelineResult,
    PluginManager,
    # CMF message + content parts.
    AudioSource,
    ContentPart,
    DocumentSource,
    ImageSource,
    Message,
    PromptRequest,
    PromptResult,
    Resource,
    ResourceReference,
    ToolCall,
    ToolResult,
    VideoSource,
    # Extensions container + slots.
    AgentExtension,
    ClientExtension,
    CompletionExtension,
    DelegationExtension,
    DelegationHop,
    Extensions,
    FrameworkExtension,
    HttpExtension,
    LLMExtension,
    MCPExtension,
    MetaExtension,
    ProvenanceExtension,
    RequestExtension,
    SecurityExtension,
    SubjectExtension,
    WorkloadIdentity,
    # Identity + Delegation payloads.
    DelegationPayload,
    IdentityPayload,
    # Nested sub-objects (returned as handles).
    AuthorizationDetail,
    ConversationContext,
    PromptMetadata,
    ResourceMetadata,
    TokenUsage,
    ToolMetadata,
)

__all__ = [
    "PluginManager",
    "PipelineResult",
    # CMF.
    "Message",
    "ContentPart",
    "ToolCall",
    "ToolResult",
    "Resource",
    "ResourceReference",
    "PromptRequest",
    "PromptResult",
    "ImageSource",
    "VideoSource",
    "AudioSource",
    "DocumentSource",
    # Extensions.
    "Extensions",
    "SecurityExtension",
    "SubjectExtension",
    "ClientExtension",
    "WorkloadIdentity",
    "RequestExtension",
    "AgentExtension",
    "HttpExtension",
    "MCPExtension",
    "CompletionExtension",
    "ProvenanceExtension",
    "LLMExtension",
    "FrameworkExtension",
    "MetaExtension",
    "DelegationExtension",
    "DelegationHop",
    # Payloads.
    "IdentityPayload",
    "DelegationPayload",
    # Nested sub-objects.
    "ConversationContext",
    "ToolMetadata",
    "ResourceMetadata",
    "PromptMetadata",
    "TokenUsage",
    "AuthorizationDetail",
]
