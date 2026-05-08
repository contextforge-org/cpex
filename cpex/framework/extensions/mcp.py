# -*- coding: utf-8 -*-
"""Location: ./cpex/framework/extensions/mcp.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Teryl Taylor

MCP extension models.
Carries typed metadata about MCP entities (tools, resources, prompts)
being processed. Gives consumers access to schemas and annotations.
Immutable tier — shared reference, no modifications allowed.
"""

# Standard
from typing import Any

# Third-Party
from pydantic import BaseModel, ConfigDict, Field


class ToolMetadata(BaseModel):
    """Typed metadata for an MCP tool.

    Attributes:
        name: Unique tool identifier.
        title: Human-readable display name.
        description: Description of tool functionality.
        input_schema: JSON Schema defining expected parameters.
        output_schema: JSON Schema for structured output.
        server_id: ID of the server providing this tool.
        namespace: Tool namespace (server/origin).
        annotations: MCP annotations (e.g., readOnlyHint, destructiveHint).

    Examples:
        >>> meta = ToolMetadata(
        ...     name="get_user",
        ...     description="Retrieve user by ID",
        ...     input_schema={"type": "object", "properties": {"id": {"type": "string"}}},
        ...     server_id="user-service",
        ... )
        >>> meta.name
        'get_user'
        >>> meta.server_id
        'user-service'
    """

    model_config = ConfigDict(frozen=True)

    name: str = Field(description="Unique tool identifier.")
    title: str | None = Field(default=None, description="Human-readable display name.")
    description: str | None = Field(default=None, description="Description of tool functionality.")
    input_schema: dict[str, Any] | None = Field(default=None, description="JSON Schema defining expected parameters.")
    output_schema: dict[str, Any] | None = Field(default=None, description="JSON Schema for structured output.")
    server_id: str | None = Field(default=None, description="ID of the server providing this tool.")
    namespace: str | None = Field(default=None, description="Tool namespace (server/origin).")
    annotations: dict[str, Any] = Field(default_factory=dict, description="MCP annotations.")


class ResourceMetadata(BaseModel):
    """Typed metadata for an MCP resource.

    Attributes:
        uri: Resource URI.
        name: Resource name.
        description: Resource description.
        mime_type: MIME type (text/csv, application/json, etc.).
        server_id: ID of the server providing this resource.
        annotations: MCP annotations (classification, retention, access hints).

    Examples:
        >>> meta = ResourceMetadata(
        ...     uri="file:///data/report.csv",
        ...     name="Quarterly Report",
        ...     mime_type="text/csv",
        ... )
        >>> meta.uri
        'file:///data/report.csv'
    """

    model_config = ConfigDict(frozen=True)

    uri: str = Field(description="Resource URI.")
    name: str | None = Field(default=None, description="Resource name.")
    description: str | None = Field(default=None, description="Resource description.")
    mime_type: str | None = Field(default=None, description="MIME type.")
    server_id: str | None = Field(default=None, description="ID of the server providing this resource.")
    annotations: dict[str, Any] = Field(default_factory=dict, description="MCP annotations.")


class PromptMetadata(BaseModel):
    """Typed metadata for an MCP prompt template.

    Prompts use an argument list rather than JSON Schema for input
    definition, following the MCP prompt specification. There is no
    output schema — prompt output is always rendered messages.

    Attributes:
        name: Prompt template name.
        description: Prompt description.
        arguments: Argument definitions (each has name, description, required).
        server_id: ID of the server providing this prompt.
        annotations: MCP annotations.

    Examples:
        >>> meta = PromptMetadata(
        ...     name="summarize",
        ...     description="Summarize a document",
        ...     arguments=[
        ...         {"name": "text", "description": "Text to summarize", "required": True},
        ...     ],
        ... )
        >>> meta.name
        'summarize'
        >>> meta.arguments[0]["name"]
        'text'
    """

    model_config = ConfigDict(frozen=True)

    name: str = Field(description="Prompt template name.")
    description: str | None = Field(default=None, description="Prompt description.")
    arguments: list[dict[str, Any]] | None = Field(default=None, description="Argument definitions.")
    server_id: str | None = Field(default=None, description="ID of the server providing this prompt.")
    annotations: dict[str, Any] = Field(default_factory=dict, description="MCP annotations.")


class MCPExtension(BaseModel):
    """Typed metadata about the MCP entity being processed.

    Exactly one of tool, resource, or prompt is populated per message,
    depending on the content type. Immutable — the processing pipeline
    rejects any modifications.

    Attributes:
        tool: Tool metadata (populated for tool_call / tool_result content).
        resource: Resource metadata (populated for resource / resource_ref content).
        prompt: Prompt metadata (populated for prompt_request / prompt_result content).

    Examples:
        >>> ext = MCPExtension(
        ...     tool=ToolMetadata(name="get_user", description="Retrieve user by ID"),
        ... )
        >>> ext.tool.name
        'get_user'
        >>> ext.resource is None
        True
    """

    model_config = ConfigDict(frozen=True)

    tool: ToolMetadata | None = Field(default=None, description="Tool metadata.")
    resource: ResourceMetadata | None = Field(default=None, description="Resource metadata.")
    prompt: PromptMetadata | None = Field(default=None, description="Prompt metadata.")
