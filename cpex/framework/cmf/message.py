# -*- coding: utf-8 -*-
"""Location: ./cpex/framework/cmf/message.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Teryl Taylor

Common Message Format (CMF) message models.
This module implements the canonical message representation for interactions
between users, agents, tools, and language models. All models are frozen
(immutable) and require model_copy() for modification, supporting the CMF's
copy-on-write semantics and mutability tier enforcement.

Domain objects (ToolCall, ImageSource, etc.) are standalone frozen models
reusable across contexts. ContentPart wrappers (ToolCallContentPart, etc.)
compose them into the typed content-part hierarchy for message serialization.
"""

# Standard
from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING, Annotated, Any, Iterator, Literal, Union

# Third-Party
from pydantic import BaseModel, ConfigDict, Discriminator, Field, Tag, model_validator

# First-Party
from cpex.framework.extensions.extensions import Extensions

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Role(str, Enum):
    """Closed-set enumeration of message roles.

    Identifies WHO is speaking in a conversation turn.

    Attributes:
        SYSTEM: System-level instructions.
        DEVELOPER: Developer-provided instructions.
        USER: Human user input.
        ASSISTANT: LLM/agent response.
        TOOL: Tool execution result.

    Examples:
        >>> Role.USER
        <Role.USER: 'user'>
        >>> Role.USER.value
        'user'
        >>> Role("assistant")
        <Role.ASSISTANT: 'assistant'>
    """

    SYSTEM = "system"
    DEVELOPER = "developer"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class Channel(str, Enum):
    """Closed-set enumeration of output channel types.

    Classifies the kind of output a message represents, allowing
    pipelines to route or filter messages by output type without
    inspecting content.

    Attributes:
        ANALYSIS: Intermediate analytical output not intended as final response.
        COMMENTARY: Meta-level observations about the task or process.
        FINAL: Terminal response intended for delivery to the end consumer.

    Examples:
        >>> Channel.FINAL
        <Channel.FINAL: 'final'>
        >>> Channel("analysis")
        <Channel.ANALYSIS: 'analysis'>
    """

    ANALYSIS = "analysis"
    COMMENTARY = "commentary"
    FINAL = "final"


class ContentType(str, Enum):
    """Closed-set enumeration of content part types.

    Discriminator for the typed ContentPart hierarchy, identifying
    the kind of content carried by each part of a multimodal message.

    Attributes:
        TEXT: Plain text content.
        THINKING: Chain-of-thought reasoning.
        TOOL_CALL: Tool/function invocation request.
        TOOL_RESULT: Result from tool execution.
        RESOURCE: Embedded resource with content (MCP).
        RESOURCE_REF: Lightweight resource reference without embedded content.
        PROMPT_REQUEST: Prompt template invocation request (MCP).
        PROMPT_RESULT: Rendered prompt template result.
        IMAGE: Image content (URL or base64).
        VIDEO: Video content (URL or base64).
        AUDIO: Audio content (URL or base64).
        DOCUMENT: Document content (PDF, Word, etc.).

    Examples:
        >>> ContentType.TOOL_CALL
        <ContentType.TOOL_CALL: 'tool_call'>
        >>> ContentType("text")
        <ContentType.TEXT: 'text'>
    """

    TEXT = "text"
    THINKING = "thinking"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    RESOURCE = "resource"
    RESOURCE_REF = "resource_ref"
    PROMPT_REQUEST = "prompt_request"
    PROMPT_RESULT = "prompt_result"
    IMAGE = "image"
    VIDEO = "video"
    AUDIO = "audio"
    DOCUMENT = "document"


class ResourceType(str, Enum):
    """Closed-set enumeration of resource types.

    Attributes:
        FILE: File-system resource.
        BLOB: Binary large object.
        URI: Generic URI-addressable resource.
        DATABASE: Database entity.
        API: API endpoint.
        MEMORY: In-memory or ephemeral resource.
        ARTIFACT: Produced artifact (generated output, build result).

    Examples:
        >>> ResourceType.FILE
        <ResourceType.FILE: 'file'>
        >>> ResourceType("database")
        <ResourceType.DATABASE: 'database'>
    """

    FILE = "file"
    BLOB = "blob"
    URI = "uri"
    DATABASE = "database"
    API = "api"
    MEMORY = "memory"
    ARTIFACT = "artifact"


# ---------------------------------------------------------------------------
# Domain Objects (standalone, reusable across contexts)
# ---------------------------------------------------------------------------


class ToolCall(BaseModel):
    """Normalized tool/function invocation request.

    Standalone domain object reusable outside of message content parts.

    Attributes:
        tool_call_id: Unique request correlation ID.
        name: Tool name.
        arguments: Arguments as a JSON-serializable dict.
        namespace: Optional namespace for namespaced tools.

    Examples:
        >>> call = ToolCall(
        ...     tool_call_id="tc_001",
        ...     name="get_user",
        ...     arguments={"user_id": "123"},
        ... )
        >>> call.name
        'get_user'
        >>> call.arguments
        {'user_id': '123'}
    """

    model_config = ConfigDict(frozen=True)

    tool_call_id: str = Field(description="Unique request correlation ID.")
    name: str = Field(description="Tool name.")
    arguments: dict[str, Any] = Field(default_factory=dict, description="Arguments as a JSON-serializable dict.")
    namespace: str | None = Field(default=None, description="Namespace for namespaced tools.")


class ToolResult(BaseModel):
    """Result from tool execution.

    Standalone domain object reusable outside of message content parts.

    Attributes:
        tool_call_id: Correlation ID linking to the corresponding tool call.
        tool_name: Name of the tool that was executed.
        content: Result content, any JSON-serializable value.
        is_error: Whether the result represents an error.

    Examples:
        >>> result = ToolResult(
        ...     tool_call_id="tc_001",
        ...     tool_name="get_user",
        ...     content={"name": "Alice"},
        ... )
        >>> result.is_error
        False
        >>> result.tool_name
        'get_user'
    """

    model_config = ConfigDict(frozen=True)

    tool_call_id: str = Field(description="Correlation ID linking to the corresponding tool call.")
    tool_name: str = Field(description="Name of the tool that was executed.")
    content: Any = Field(default=None, description="Result content, any JSON-serializable value.")
    is_error: bool = Field(default=False, description="Whether the result represents an error.")


class Resource(BaseModel):
    """Embedded resource with content (MCP).

    Standalone domain object reusable outside of message content parts.

    Attributes:
        resource_request_id: Unique request correlation ID.
        uri: Unique identifier in URI format.
        name: Human-readable name.
        description: What this resource contains.
        resource_type: The kind of resource.
        content: Text content if embedded.
        blob: Binary content if embedded.
        mime_type: MIME type of content.
        size_bytes: Size information.
        annotations: Metadata (classification, retention, etc.).
        version: Version tracking.

    Examples:
        >>> res = Resource(
        ...     resource_request_id="rr_001",
        ...     uri="file:///data/report.csv",
        ...     name="Q4 Report",
        ...     resource_type=ResourceType.FILE,
        ...     content="col1,col2\\n1,2",
        ...     mime_type="text/csv",
        ... )
        >>> res.uri
        'file:///data/report.csv'
    """

    model_config = ConfigDict(frozen=True)

    resource_request_id: str = Field(description="Unique request correlation ID.")
    uri: str = Field(description="Unique identifier in URI format.")
    name: str | None = Field(default=None, description="Human-readable name.")
    description: str | None = Field(default=None, description="What this resource contains.")
    resource_type: ResourceType = Field(description="The kind of resource.")
    content: str | None = Field(default=None, description="Text content if embedded.")
    blob: bytes | None = Field(default=None, description="Binary content if embedded.")

    @model_validator(mode="after")
    def _check_content_blob_exclusion(self) -> Resource:
        """Ensure content and blob are mutually exclusive.

        Returns:
            The validated Resource instance.

        Raises:
            ValueError: If both content and blob are set.
        """
        if self.content is not None and self.blob is not None:
            raise ValueError("Resource cannot have both 'content' and 'blob' set")
        return self

    mime_type: str | None = Field(default=None, description="MIME type of content.")
    size_bytes: int | None = Field(default=None, description="Size information.")
    annotations: dict[str, Any] = Field(default_factory=dict, description="Metadata (classification, retention, etc.).")
    version: str | None = Field(default=None, description="Version tracking.")


class ResourceReference(BaseModel):
    """Lightweight resource reference without embedded content.

    Standalone domain object reusable outside of message content parts.

    Attributes:
        resource_request_id: Correlation ID linking to the originating resource request.
        uri: Resource URI.
        name: Human-readable name.
        resource_type: Type of resource.
        range_start: Line number or byte offset for partial references.
        range_end: End of range.
        selector: CSS/XPath/JSONPath selector.

    Examples:
        >>> ref = ResourceReference(
        ...     resource_request_id="rr_002",
        ...     uri="db://users/42",
        ...     resource_type=ResourceType.DATABASE,
        ... )
        >>> ref.uri
        'db://users/42'
    """

    model_config = ConfigDict(frozen=True)

    resource_request_id: str = Field(description="Correlation ID linking to the originating resource request.")
    uri: str = Field(description="Resource URI.")
    name: str | None = Field(default=None, description="Human-readable name.")
    resource_type: ResourceType = Field(description="Type of resource.")
    range_start: int | None = Field(default=None, description="Line number or byte offset for partial references.")
    range_end: int | None = Field(default=None, description="End of range.")
    selector: str | None = Field(default=None, description="CSS/XPath/JSONPath selector.")

    @model_validator(mode="after")
    def _check_range_consistency(self) -> ResourceReference:
        """Ensure range_end is not less than range_start.

        Returns:
            The validated ResourceReference instance.

        Raises:
            ValueError: If range_end < range_start.
        """
        if self.range_start is not None and self.range_end is not None:
            if self.range_end < self.range_start:
                raise ValueError(f"range_end ({self.range_end}) must be >= range_start ({self.range_start})")
        return self


class PromptRequest(BaseModel):
    """Prompt template invocation request (MCP).

    Standalone domain object reusable outside of message content parts.

    Attributes:
        prompt_request_id: Request ID for correlation.
        name: Prompt template name.
        arguments: Arguments to pass to the template.
        server_id: Source server for multi-server scenarios.

    Examples:
        >>> req = PromptRequest(
        ...     prompt_request_id="pr_001",
        ...     name="summarize",
        ...     arguments={"text": "Long document..."},
        ... )
        >>> req.name
        'summarize'
    """

    model_config = ConfigDict(frozen=True)

    prompt_request_id: str = Field(description="Request ID for correlation.")
    name: str = Field(description="Prompt template name.")
    arguments: dict[str, Any] = Field(default_factory=dict, description="Arguments to pass to the template.")
    server_id: str | None = Field(default=None, description="Source server for multi-server scenarios.")


class PromptResult(BaseModel):
    """Rendered prompt template result.

    Standalone domain object reusable outside of message content parts.

    Attributes:
        prompt_request_id: ID of the corresponding prompt request.
        prompt_name: Name of the prompt that was rendered.
        messages: Rendered messages (prompts produce messages).
        content: Single text result for simple prompts.
        is_error: Whether rendering failed.
        error_message: Error details if rendering failed.

    Examples:
        >>> result = PromptResult(
        ...     prompt_request_id="pr_001",
        ...     prompt_name="summarize",
        ...     content="This document discusses...",
        ... )
        >>> result.is_error
        False
    """

    model_config = ConfigDict(frozen=True)

    prompt_request_id: str = Field(description="ID of the corresponding prompt request.")
    prompt_name: str = Field(description="Name of the prompt that was rendered.")
    messages: list[Message] = Field(
        default_factory=list,
        description="Rendered messages (prompts produce messages).",
    )
    content: str | None = Field(default=None, description="Single text result for simple prompts.")
    is_error: bool = Field(default=False, description="Whether rendering failed.")
    error_message: str | None = Field(default=None, description="Error details if rendering failed.")


class ImageSource(BaseModel):
    """Image source data.

    Standalone domain object reusable outside of message content parts.

    Attributes:
        type: Source type, either URL or base64-encoded.
        data: URL or base64-encoded string.
        media_type: MIME type (e.g., image/jpeg).

    Examples:
        >>> img = ImageSource(type="url", data="https://example.com/photo.jpg")
        >>> img.type
        'url'
    """

    model_config = ConfigDict(frozen=True)

    type: Literal["url", "base64"] = Field(description="Source type: 'url' or 'base64'.")
    data: str = Field(description="URL or base64-encoded string.")
    media_type: str | None = Field(default=None, description="MIME type (e.g., image/jpeg).")


class VideoSource(BaseModel):
    """Video source data.

    Standalone domain object reusable outside of message content parts.

    Attributes:
        type: Source type, either URL or base64-encoded.
        data: URL or base64-encoded string.
        media_type: MIME type (e.g., video/mp4).
        duration_ms: Duration in milliseconds.

    Examples:
        >>> vid = VideoSource(type="url", data="https://example.com/clip.mp4")
        >>> vid.type
        'url'
    """

    model_config = ConfigDict(frozen=True)

    type: Literal["url", "base64"] = Field(description="Source type: 'url' or 'base64'.")
    data: str = Field(description="URL or base64-encoded string.")
    media_type: str | None = Field(default=None, description="MIME type (e.g., video/mp4).")
    duration_ms: int | None = Field(default=None, description="Duration in milliseconds.")


class AudioSource(BaseModel):
    """Audio source data.

    Standalone domain object reusable outside of message content parts.

    Attributes:
        type: Source type, either URL or base64-encoded.
        data: URL or base64-encoded string.
        media_type: MIME type (e.g., audio/mp3).
        duration_ms: Duration in milliseconds.

    Examples:
        >>> aud = AudioSource(type="url", data="https://example.com/track.mp3")
        >>> aud.type
        'url'
    """

    model_config = ConfigDict(frozen=True)

    type: Literal["url", "base64"] = Field(description="Source type: 'url' or 'base64'.")
    data: str = Field(description="URL or base64-encoded string.")
    media_type: str | None = Field(default=None, description="MIME type (e.g., audio/mp3).")
    duration_ms: int | None = Field(default=None, description="Duration in milliseconds.")


class DocumentSource(BaseModel):
    """Document source data (PDF, Word, etc.).

    Standalone domain object reusable outside of message content parts.

    Attributes:
        type: Source type, either URL or base64-encoded.
        data: URL or base64-encoded string.
        media_type: MIME type (e.g., application/pdf).
        title: Document title.

    Examples:
        >>> doc = DocumentSource(
        ...     type="base64",
        ...     data="JVBERi0xLjQ...",
        ...     media_type="application/pdf",
        ...     title="Annual Report",
        ... )
        >>> doc.title
        'Annual Report'
    """

    model_config = ConfigDict(frozen=True)

    type: Literal["url", "base64"] = Field(description="Source type: 'url' or 'base64'.")
    data: str = Field(description="URL or base64-encoded string.")
    media_type: str | None = Field(default=None, description="MIME type (e.g., application/pdf).")
    title: str | None = Field(default=None, description="Document title.")


# ---------------------------------------------------------------------------
# Content Parts (ContentPart base + wrappers)
# ---------------------------------------------------------------------------


class ContentPart(BaseModel):
    """Base class for all content parts in a CMF message.

    Frozen by design — subclasses inherit immutability. Consumers must
    use model_copy(update={...}) to create modified copies.

    Attributes:
        content_type: Discriminator identifying the concrete content type.

    Examples:
        >>> part = TextContent(text="hello")
        >>> isinstance(part, ContentPart)
        True
        >>> part.content_type
        <ContentType.TEXT: 'text'>
    """

    model_config = ConfigDict(frozen=True)

    content_type: ContentType = Field(description="Content type discriminator.")


class TextContent(ContentPart):
    """Plain text content part.

    Attributes:
        content_type: Discriminator, always ContentType.TEXT.
        text: The text content.

    Examples:
        >>> part = TextContent(text="Hello, world!")
        >>> part.content_type
        <ContentType.TEXT: 'text'>
        >>> part.text
        'Hello, world!'
        >>> modified = part.model_copy(update={"text": "Updated"})
        >>> (part.text, modified.text)
        ('Hello, world!', 'Updated')
    """

    content_type: Literal[ContentType.TEXT] = Field(default=ContentType.TEXT, description="Content type discriminator.")
    text: str = Field(description="The text content.")


class ThinkingContent(ContentPart):
    """Chain-of-thought reasoning content part.

    Attributes:
        content_type: Discriminator, always ContentType.THINKING.
        text: The reasoning text.

    Examples:
        >>> part = ThinkingContent(text="Let me analyze this...")
        >>> part.content_type
        <ContentType.THINKING: 'thinking'>
    """

    content_type: Literal[ContentType.THINKING] = Field(
        default=ContentType.THINKING, description="Content type discriminator."
    )
    text: str = Field(description="The reasoning text.")


class ToolCallContentPart(ContentPart):
    """Content part wrapping a ToolCall domain object.

    Attributes:
        content_type: Discriminator, always ContentType.TOOL_CALL.
        content: The wrapped ToolCall.

    Examples:
        >>> part = ToolCallContentPart(
        ...     content=ToolCall(tool_call_id="tc_001", name="search", arguments={"q": "test"}),
        ... )
        >>> part.content.name
        'search'
    """

    content_type: Literal[ContentType.TOOL_CALL] = Field(
        default=ContentType.TOOL_CALL, description="Content type discriminator."
    )
    content: ToolCall = Field(description="The wrapped ToolCall.")


class ToolResultContentPart(ContentPart):
    """Content part wrapping a ToolResult domain object.

    Attributes:
        content_type: Discriminator, always ContentType.TOOL_RESULT.
        content: The wrapped ToolResult.

    Examples:
        >>> part = ToolResultContentPart(
        ...     content=ToolResult(tool_call_id="tc_001", tool_name="search", content="Found 10 results"),
        ... )
        >>> part.content.tool_name
        'search'
    """

    content_type: Literal[ContentType.TOOL_RESULT] = Field(
        default=ContentType.TOOL_RESULT, description="Content type discriminator."
    )
    content: ToolResult = Field(description="The wrapped ToolResult.")


class ResourceContentPart(ContentPart):
    """Content part wrapping a Resource domain object.

    Attributes:
        content_type: Discriminator, always ContentType.RESOURCE.
        content: The wrapped Resource.

    Examples:
        >>> part = ResourceContentPart(
        ...     content=Resource(resource_request_id="rr_001", uri="file:///data.txt", resource_type=ResourceType.FILE),
        ... )
        >>> part.content.uri
        'file:///data.txt'
    """

    content_type: Literal[ContentType.RESOURCE] = Field(
        default=ContentType.RESOURCE, description="Content type discriminator."
    )
    content: Resource = Field(description="The wrapped Resource.")


class ResourceRefContentPart(ContentPart):
    """Content part wrapping a ResourceReference domain object.

    Attributes:
        content_type: Discriminator, always ContentType.RESOURCE_REF.
        content: The wrapped ResourceReference.

    Examples:
        >>> part = ResourceRefContentPart(
        ...     content=ResourceReference(resource_request_id="rr_002", uri="db://users/42", resource_type=ResourceType.DATABASE),
        ... )
        >>> part.content.uri
        'db://users/42'
    """

    content_type: Literal[ContentType.RESOURCE_REF] = Field(
        default=ContentType.RESOURCE_REF, description="Content type discriminator."
    )
    content: ResourceReference = Field(description="The wrapped ResourceReference.")


class PromptRequestContentPart(ContentPart):
    """Content part wrapping a PromptRequest domain object.

    Attributes:
        content_type: Discriminator, always ContentType.PROMPT_REQUEST.
        content: The wrapped PromptRequest.

    Examples:
        >>> part = PromptRequestContentPart(
        ...     content=PromptRequest(prompt_request_id="pr_001", name="summarize"),
        ... )
        >>> part.content.name
        'summarize'
    """

    content_type: Literal[ContentType.PROMPT_REQUEST] = Field(
        default=ContentType.PROMPT_REQUEST, description="Content type discriminator."
    )
    content: PromptRequest = Field(description="The wrapped PromptRequest.")


class PromptResultContentPart(ContentPart):
    """Content part wrapping a PromptResult domain object.

    Attributes:
        content_type: Discriminator, always ContentType.PROMPT_RESULT.
        content: The wrapped PromptResult.

    Examples:
        >>> part = PromptResultContentPart(
        ...     content=PromptResult(prompt_request_id="pr_001", prompt_name="summarize"),
        ... )
        >>> part.content.prompt_name
        'summarize'
    """

    content_type: Literal[ContentType.PROMPT_RESULT] = Field(
        default=ContentType.PROMPT_RESULT, description="Content type discriminator."
    )
    content: PromptResult = Field(description="The wrapped PromptResult.")


class ImageContentPart(ContentPart):
    """Content part wrapping an ImageSource domain object.

    Attributes:
        content_type: Discriminator, always ContentType.IMAGE.
        content: The wrapped ImageSource.

    Examples:
        >>> part = ImageContentPart(
        ...     content=ImageSource(type="url", data="https://example.com/photo.jpg"),
        ... )
        >>> part.content.type
        'url'
    """

    content_type: Literal[ContentType.IMAGE] = Field(
        default=ContentType.IMAGE, description="Content type discriminator."
    )
    content: ImageSource = Field(description="The wrapped ImageSource.")


class VideoContentPart(ContentPart):
    """Content part wrapping a VideoSource domain object.

    Attributes:
        content_type: Discriminator, always ContentType.VIDEO.
        content: The wrapped VideoSource.

    Examples:
        >>> part = VideoContentPart(
        ...     content=VideoSource(type="url", data="https://example.com/clip.mp4"),
        ... )
        >>> part.content.type
        'url'
    """

    content_type: Literal[ContentType.VIDEO] = Field(
        default=ContentType.VIDEO, description="Content type discriminator."
    )
    content: VideoSource = Field(description="The wrapped VideoSource.")


class AudioContentPart(ContentPart):
    """Content part wrapping an AudioSource domain object.

    Attributes:
        content_type: Discriminator, always ContentType.AUDIO.
        content: The wrapped AudioSource.

    Examples:
        >>> part = AudioContentPart(
        ...     content=AudioSource(type="url", data="https://example.com/track.mp3"),
        ... )
        >>> part.content.type
        'url'
    """

    content_type: Literal[ContentType.AUDIO] = Field(
        default=ContentType.AUDIO, description="Content type discriminator."
    )
    content: AudioSource = Field(description="The wrapped AudioSource.")


class DocumentContentPart(ContentPart):
    """Content part wrapping a DocumentSource domain object.

    Attributes:
        content_type: Discriminator, always ContentType.DOCUMENT.
        content: The wrapped DocumentSource.

    Examples:
        >>> part = DocumentContentPart(
        ...     content=DocumentSource(type="base64", data="JVBERi0xLjQ...", media_type="application/pdf"),
        ... )
        >>> part.content.media_type
        'application/pdf'
    """

    content_type: Literal[ContentType.DOCUMENT] = Field(
        default=ContentType.DOCUMENT, description="Content type discriminator."
    )
    content: DocumentSource = Field(description="The wrapped DocumentSource.")


# ---------------------------------------------------------------------------
# ContentPart Discriminated Union
# ---------------------------------------------------------------------------


def _content_type_discriminator(v: Any) -> str:
    """Extract the content_type discriminator value from a content part.

    Supports both dict (during deserialization) and model instance access.

    Args:
        v: A content part as a dict or model instance.

    Returns:
        The content_type string value for discriminator routing.
    """
    if isinstance(v, dict):
        ct = v.get("content_type")
        if ct is None:
            raise ValueError("Missing 'content_type' discriminator in content part dict")
        return ct
    if not hasattr(v, "content_type"):
        raise ValueError(f"Content part {type(v).__name__} missing 'content_type' attribute")
    return v.content_type.value


ContentPartUnion = Annotated[
    Union[
        Annotated[TextContent, Tag("text")],
        Annotated[ThinkingContent, Tag("thinking")],
        Annotated[ToolCallContentPart, Tag("tool_call")],
        Annotated[ToolResultContentPart, Tag("tool_result")],
        Annotated[ResourceContentPart, Tag("resource")],
        Annotated[ResourceRefContentPart, Tag("resource_ref")],
        Annotated[PromptRequestContentPart, Tag("prompt_request")],
        Annotated[PromptResultContentPart, Tag("prompt_result")],
        Annotated[ImageContentPart, Tag("image")],
        Annotated[VideoContentPart, Tag("video")],
        Annotated[AudioContentPart, Tag("audio")],
        Annotated[DocumentContentPart, Tag("document")],
    ],
    Discriminator(_content_type_discriminator),
]
"""Discriminated union of all content part types.

Pydantic uses the content_type field to resolve the correct subclass
during validation and deserialization.
"""


# ---------------------------------------------------------------------------
# Message
# ---------------------------------------------------------------------------


class Message(BaseModel):
    """Canonical CMF message representing a single turn in a conversation.

    A Message is the storage and wire format. It preserves the structure
    exactly as the LLM or framework sent it. For policy evaluation and
    inspection, use MessageView (via iter_views()) which decomposes the
    message into individually addressable, uniformly accessible parts.

    All Message instances are frozen. To create a modified copy, use
    model_copy(update={...}).

    Attributes:
        schema_version: Message schema version.
        role: Who is speaking.
        content: List of typed content parts (multimodal).
        channel: Optional output classification.
        extensions: Optional contextual metadata (identity, security, governance).

    Examples:
        >>> msg = Message(
        ...     role=Role.USER,
        ...     content=[TextContent(text="What is the weather?")],
        ... )
        >>> msg.role
        <Role.USER: 'user'>
        >>> msg.content[0].text
        'What is the weather?'
        >>> msg.schema_version
        '2.0'

        >>> # Frozen: modifications require model_copy
        >>> updated = msg.model_copy(update={"channel": Channel.FINAL})
        >>> updated.channel
        <Channel.FINAL: 'final'>
        >>> msg.channel is None
        True

        >>> # Multi-part assistant message
        >>> assistant_msg = Message(
        ...     role=Role.ASSISTANT,
        ...     content=[
        ...         ThinkingContent(text="I should check the weather API."),
        ...         TextContent(text="Let me look that up."),
        ...         ToolCallContentPart(
        ...             content=ToolCall(
        ...                 tool_call_id="tc_001",
        ...                 name="get_weather",
        ...                 arguments={"city": "London"},
        ...             ),
        ...         ),
        ...     ],
        ... )
        >>> len(assistant_msg.content)
        3
        >>> assistant_msg.content[2].content.name
        'get_weather'
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = Field(default="2.0", description="Message schema version.")
    role: Role = Field(description="Who is speaking.")
    content: list[ContentPartUnion] = Field(default_factory=list, description="List of typed content parts.")
    channel: Channel | None = Field(default=None, description="Optional output classification.")

    def iter_views(self, hook: str | None = None, extensions: Extensions | None = None) -> Iterator[MessageView]:
        """Decompose this message into individually addressable MessageViews.

        Yields one MessageView per content part. Each view provides a
        uniform interface for policy evaluation regardless of content type.

        Args:
            hook: Optional hook location string (e.g., "llm_input",
                "tool_post_invoke") to attach to each view.

        Returns:
            An iterator of MessageView objects.

        Examples:
            >>> msg = Message(
            ...     role=Role.ASSISTANT,
            ...     content=[
            ...         TextContent(text="Let me check."),
            ...         ToolCallContentPart(
            ...             content=ToolCall(
            ...                 tool_call_id="tc_001",
            ...                 name="get_weather",
            ...                 arguments={"city": "London"},
            ...             ),
            ...         ),
            ...     ],
            ... )
            >>> views = list(msg.iter_views())
            >>> len(views)
            2
            >>> views[0].kind.value
            'text'
            >>> views[1].name
            'get_weather'
        """
        from cpex.framework.cmf.view import iter_views  # pylint: disable=import-outside-toplevel

        return iter_views(self, hook=hook, extensions=extensions)


if TYPE_CHECKING:
    from cpex.framework.cmf.view import MessageView
