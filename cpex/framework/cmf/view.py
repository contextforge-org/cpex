# -*- coding: utf-8 -*-
"""Location: ./cpex/framework/cmf/view.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Teryl Taylor

MessageView — read-only projection for policy evaluation.

Decomposes a Message into individually addressable views with a
uniform interface regardless of content type. Zero-copy design —
properties are computed on-demand by accessing the underlying
content part and message extensions directly.
"""

# Standard
import json
import logging
import re
from enum import Enum
from types import MappingProxyType
from typing import Any, Iterator, Mapping

# First-Party
from cpex.framework.cmf.message import (
    ContentPart,
    ContentType,
    Message,
    Resource,
    Role,
)
from cpex.framework.extensions.security import (
    DataPolicy,
    ObjectSecurityProfile,
    SubjectExtension,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ViewKind(str, Enum):
    """Closed-set enumeration of message view kinds.

    Maps one-to-one with ContentType, identifying the kind of
    content that a view represents.

    Attributes:
        TEXT: Plain text content.
        THINKING: Reasoning/chain-of-thought content.
        TOOL_CALL: Tool/function invocation.
        TOOL_RESULT: Result from tool execution.
        RESOURCE: Embedded resource with content.
        RESOURCE_REF: Reference to a resource (URI only).
        PROMPT_REQUEST: Prompt template request.
        PROMPT_RESULT: Rendered prompt result.
        IMAGE: Image content.
        VIDEO: Video content.
        AUDIO: Audio content.
        DOCUMENT: Document content.

    Examples:
        >>> ViewKind.TOOL_CALL
        <ViewKind.TOOL_CALL: 'tool_call'>
        >>> ViewKind.TOOL_CALL.value
        'tool_call'
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


class ViewAction(str, Enum):
    """Closed-set enumeration of semantic actions.

    Attributes:
        READ: Reading/accessing data.
        WRITE: Writing/modifying data.
        EXECUTE: Executing a tool or command.
        INVOKE: Invoking a prompt template.
        SEND: Sending content outbound.
        RECEIVE: Receiving content inbound.
        GENERATE: Generating content (LLM output).

    Examples:
        >>> ViewAction.EXECUTE
        <ViewAction.EXECUTE: 'execute'>
    """

    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    INVOKE = "invoke"
    SEND = "send"
    RECEIVE = "receive"
    GENERATE = "generate"


# ---------------------------------------------------------------------------
# ContentType -> ViewKind mapping
# ---------------------------------------------------------------------------

_CONTENT_TYPE_TO_VIEW_KIND: dict[ContentType, ViewKind] = {
    ContentType.TEXT: ViewKind.TEXT,
    ContentType.THINKING: ViewKind.THINKING,
    ContentType.TOOL_CALL: ViewKind.TOOL_CALL,
    ContentType.TOOL_RESULT: ViewKind.TOOL_RESULT,
    ContentType.RESOURCE: ViewKind.RESOURCE,
    ContentType.RESOURCE_REF: ViewKind.RESOURCE_REF,
    ContentType.PROMPT_REQUEST: ViewKind.PROMPT_REQUEST,
    ContentType.PROMPT_RESULT: ViewKind.PROMPT_RESULT,
    ContentType.IMAGE: ViewKind.IMAGE,
    ContentType.VIDEO: ViewKind.VIDEO,
    ContentType.AUDIO: ViewKind.AUDIO,
    ContentType.DOCUMENT: ViewKind.DOCUMENT,
}

_ACTION_MAP: dict[ViewKind, ViewAction] = {
    ViewKind.TOOL_CALL: ViewAction.EXECUTE,
    ViewKind.TOOL_RESULT: ViewAction.RECEIVE,
    ViewKind.RESOURCE: ViewAction.READ,
    ViewKind.RESOURCE_REF: ViewAction.READ,
    ViewKind.PROMPT_REQUEST: ViewAction.INVOKE,
    ViewKind.PROMPT_RESULT: ViewAction.RECEIVE,
}

# Kinds whose action depends on message direction (role)
_DIRECTION_DEPENDENT_KINDS = frozenset(
    {
        ViewKind.TEXT,
        ViewKind.THINKING,
        ViewKind.IMAGE,
        ViewKind.VIDEO,
        ViewKind.AUDIO,
        ViewKind.DOCUMENT,
    }
)

# Sensitive headers stripped during serialization
_SENSITIVE_HEADERS = frozenset({"authorization", "cookie", "x-api-key"})


# ---------------------------------------------------------------------------
# MessageView
# ---------------------------------------------------------------------------


class MessageView:
    """Read-only, zero-copy view over a single content part for policy evaluation.

    A MessageView provides a uniform interface for inspecting any content
    part of a message — regardless of whether it's text, a tool call, a
    resource, or media. Properties are computed on-demand from the
    underlying content part and message extensions without copying data.

    For wrapped content parts (tool calls, resources, media, etc.), the
    domain object is accessed via the wrapper's .content field. The _inner
    property provides convenient access to the wrapped domain object.

    MessageViews are produced by Message.iter_views() or the standalone
    iter_views() function. A single Message with multiple content parts
    yields one view per part.

    Attributes:
        kind: The type of content this view represents.
        role: The role of the parent message.
        raw: Direct access to the underlying content part.

    Examples:
        >>> from cpex.framework.cmf.message import (
        ...     Message, Role, TextContent, ToolCall, ToolCallContentPart,
        ... )
        >>> msg = Message(
        ...     role=Role.ASSISTANT,
        ...     content=[
        ...         TextContent(text="Let me look that up."),
        ...         ToolCallContentPart(
        ...             content=ToolCall(
        ...                 tool_call_id="tc_001",
        ...                 name="get_user",
        ...                 arguments={"id": "123"},
        ...             ),
        ...         ),
        ...     ],
        ... )
        >>> views = list(iter_views(msg))
        >>> len(views)
        2
        >>> views[0].kind
        <ViewKind.TEXT: 'text'>
        >>> views[1].kind
        <ViewKind.TOOL_CALL: 'tool_call'>
        >>> views[1].name
        'get_user'
        >>> views[1].uri
        'tool://_/get_user'
        >>> views[1].is_pre
        True
    """

    __slots__ = ("_part", "_kind", "_message", "_extensions", "_hook")

    def __init__(
        self,
        part: ContentPart,
        kind: ViewKind,
        message: Message,
        hook: str | None = None,
        extensions: Any = None,
    ) -> None:
        """Initialize a MessageView.

        Args:
            part: The underlying content part.
            kind: The kind of content.
            message: The parent message (for role access).
            hook: The hook location where this view is being evaluated
                (e.g., "llm_input", "tool_post_invoke"). None if unset.
            extensions: The Extensions object, passed separately from the
                message for capability-gated filtering.
        """
        self._part = part
        self._kind = kind
        self._message = message
        self._extensions = extensions
        self._hook = hook

    # =========================================================================
    # Internal Helpers
    # =========================================================================

    @property
    def _inner(self) -> Any:
        """Get the wrapped domain object for composite content parts.

        For TextContent/ThinkingContent (which have no wrapper), returns
        the part itself. For all other types, returns the .content field
        which holds the domain object (ToolCall, Resource, etc.).

        Returns:
            The domain object for this content part.
        """
        if self._kind in (ViewKind.TEXT, ViewKind.THINKING):
            return self._part
        return self._part.content  # type: ignore[union-attr]

    # =========================================================================
    # Core Properties
    # =========================================================================

    @property
    def kind(self) -> ViewKind:
        """The type of content this view represents.

        Returns:
            The ViewKind for this view.
        """
        return self._kind

    @property
    def role(self) -> Role:
        """The role of the parent message.

        Returns:
            The Role (user, assistant, system, developer, tool).
        """
        return self._message.role

    @property
    def hook(self) -> str | None:
        """The hook location where this view is being evaluated.

        Indicates where in the pipeline the evaluation is occurring
        (e.g., "llm_input", "llm_output", "tool_pre_invoke",
        "tool_post_invoke"). None if not set.

        Returns:
            Hook location string or None.
        """
        return self._hook

    @property
    def raw(self) -> ContentPart:
        """Direct access to the underlying content part.

        Returns:
            The underlying ContentPart subclass instance.
        """
        return self._part

    @property
    def content(self) -> str | None:
        """Scannable text content.

        For text/thinking: the text itself. For tool calls and prompt
        requests: JSON-serialized arguments. For tool results:
        JSON-serialized content. For resources: embedded content string.

        Returns:
            Scannable text or None if no text content is available.
        """
        inner = self._inner

        if self._kind in (ViewKind.TEXT, ViewKind.THINKING):
            return inner.text

        if self._kind == ViewKind.RESOURCE:
            return inner.content

        if self._kind == ViewKind.TOOL_CALL:
            try:
                return json.dumps(inner.arguments)
            except (TypeError, ValueError):
                return str(inner.arguments)

        if self._kind == ViewKind.TOOL_RESULT:
            result_content = inner.content
            if result_content is None:
                return None
            if isinstance(result_content, str):
                return result_content
            try:
                return json.dumps(result_content)
            except (TypeError, ValueError):
                return str(result_content)

        if self._kind == ViewKind.PROMPT_REQUEST:
            try:
                return json.dumps(inner.arguments)
            except (TypeError, ValueError):
                return str(inner.arguments)

        if self._kind == ViewKind.PROMPT_RESULT:
            return inner.content

        return None

    @property
    def uri(self) -> str | None:
        """Synthetic identity URI.

        Tools: tool://namespace/name. Tool results: tool_result://name.
        Prompts: prompt://server/name. Prompt results: prompt_result://name.
        Resources: the resource's own URI.

        Returns:
            URI string or None if not applicable.
        """
        inner = self._inner

        if self._kind in (ViewKind.RESOURCE, ViewKind.RESOURCE_REF):
            return inner.uri

        if self._kind == ViewKind.TOOL_CALL:
            ns = inner.namespace or "_"
            return f"tool://{ns}/{inner.name}"

        if self._kind == ViewKind.TOOL_RESULT:
            return f"tool_result://{inner.tool_name}"

        if self._kind == ViewKind.PROMPT_REQUEST:
            server = inner.server_id or "_"
            return f"prompt://{server}/{inner.name}"

        if self._kind == ViewKind.PROMPT_RESULT:
            return f"prompt_result://{inner.prompt_name}"

        return None

    @property
    def name(self) -> str | None:
        """Human-readable name (tool name, resource name, prompt name).

        Returns:
            Name string or None if not applicable.
        """
        inner = self._inner

        if self._kind in (ViewKind.TOOL_CALL, ViewKind.PROMPT_REQUEST):
            return inner.name

        if self._kind in (ViewKind.RESOURCE, ViewKind.RESOURCE_REF):
            return inner.name

        if self._kind == ViewKind.TOOL_RESULT:
            return inner.tool_name

        if self._kind == ViewKind.PROMPT_RESULT:
            return inner.prompt_name

        return None

    @property
    def action(self) -> ViewAction:
        """The semantic action this view represents.

        For content kinds like text and media, the action depends on
        the message role: SEND for user/system/developer input,
        GENERATE for assistant output, RECEIVE for tool output.

        Returns:
            A ViewAction value.
        """
        fixed = _ACTION_MAP.get(self._kind)
        if fixed is not None:
            return fixed
        role = self._message.role
        if role == Role.ASSISTANT:
            return ViewAction.GENERATE
        if role == Role.TOOL:
            return ViewAction.RECEIVE
        return ViewAction.SEND

    @property
    def args(self) -> dict[str, Any] | None:
        """Arguments dict for tool calls and prompt requests.

        Returns:
            Arguments dict or None for other content types.
        """
        inner = self._inner
        if self._kind == ViewKind.TOOL_CALL:
            return inner.arguments
        if self._kind == ViewKind.PROMPT_REQUEST:
            return inner.arguments
        return None

    @property
    def mime_type(self) -> str | None:
        """MIME type if applicable.

        Returns:
            MIME type string or None.
        """
        inner = self._inner
        if self._kind == ViewKind.RESOURCE:
            return inner.mime_type
        if self._kind in (ViewKind.IMAGE, ViewKind.VIDEO, ViewKind.AUDIO, ViewKind.DOCUMENT):
            return inner.media_type
        return None

    @property
    def size_bytes(self) -> int | None:
        """Content size in bytes (computed from content).

        Returns:
            Size in bytes or None.
        """
        if self._kind == ViewKind.RESOURCE:
            res: Resource = self._inner
            if res.size_bytes is not None:
                return res.size_bytes
            if res.content:
                return len(res.content.encode("utf-8"))
            if res.blob:
                return len(res.blob)
            return None

        text = self.content
        if text is not None:
            return len(text.encode("utf-8"))
        return None

    @property
    def properties(self) -> dict[str, Any]:
        """Type-specific properties as a dict.

        For single property access, prefer get_property() which
        avoids allocating a dict.

        Returns:
            Dict of property name to value for this view's kind.
        """
        props: dict[str, Any] = {}
        inner = self._inner

        if self._kind == ViewKind.RESOURCE:
            props["resource_type"] = inner.resource_type.value
            props["version"] = inner.version
            props["annotations"] = inner.annotations

        elif self._kind == ViewKind.TOOL_CALL:
            props["namespace"] = inner.namespace
            props["tool_id"] = inner.tool_call_id

        elif self._kind == ViewKind.TOOL_RESULT:
            props["is_error"] = inner.is_error
            props["tool_name"] = inner.tool_name

        elif self._kind == ViewKind.PROMPT_REQUEST:
            props["server_id"] = inner.server_id

        elif self._kind == ViewKind.PROMPT_RESULT:
            props["is_error"] = inner.is_error
            props["message_count"] = len(inner.messages) if inner.messages else 0

        return props

    def get_property(self, name: str, default: Any = None) -> Any:
        """Get a single type-specific property without allocating a dict.

        Args:
            name: Property name to retrieve.
            default: Value to return if property doesn't exist.

        Returns:
            The property value or default.
        """
        inner = self._inner

        if self._kind == ViewKind.RESOURCE:
            if name == "resource_type":
                return inner.resource_type.value
            if name == "version":
                return inner.version
            if name == "annotations":
                return inner.annotations

        elif self._kind == ViewKind.TOOL_CALL:
            if name == "namespace":
                return inner.namespace
            if name == "tool_id":
                return inner.tool_call_id

        elif self._kind == ViewKind.TOOL_RESULT:
            if name == "is_error":
                return inner.is_error
            if name == "tool_name":
                return inner.tool_name

        elif self._kind == ViewKind.PROMPT_REQUEST:
            if name == "server_id":
                return inner.server_id

        elif self._kind == ViewKind.PROMPT_RESULT:
            if name == "is_error":
                return inner.is_error
            if name == "message_count":
                return len(inner.messages) if inner.messages else 0

        return default

    # =========================================================================
    # Direction
    # =========================================================================

    @property
    def is_pre(self) -> bool:
        """True if this represents input/request content (before processing).

        Determined by ViewKind for requests/responses, and by Role
        for text, thinking, and media content.

        Returns:
            True if this is pre-processing content.
        """
        if self._kind in (ViewKind.TOOL_CALL, ViewKind.PROMPT_REQUEST, ViewKind.RESOURCE_REF):
            return True
        if self._kind in (ViewKind.TOOL_RESULT, ViewKind.PROMPT_RESULT, ViewKind.RESOURCE):
            return False
        return self._message.role in (Role.USER, Role.SYSTEM, Role.DEVELOPER)

    @property
    def is_post(self) -> bool:
        """True if this represents output/response content (after processing).

        Returns:
            True if this is post-processing content.
        """
        if self._kind in (ViewKind.TOOL_RESULT, ViewKind.PROMPT_RESULT, ViewKind.RESOURCE):
            return True
        if self._kind in (ViewKind.TOOL_CALL, ViewKind.PROMPT_REQUEST, ViewKind.RESOURCE_REF):
            return False
        return self._message.role in (Role.ASSISTANT, Role.TOOL)

    @property
    def is_tool(self) -> bool:
        """True if tool_call or tool_result.

        Returns:
            True if this is a tool-related view.
        """
        return self._kind in (ViewKind.TOOL_CALL, ViewKind.TOOL_RESULT)

    @property
    def is_prompt(self) -> bool:
        """True if prompt_request or prompt_result.

        Returns:
            True if this is a prompt-related view.
        """
        return self._kind in (ViewKind.PROMPT_REQUEST, ViewKind.PROMPT_RESULT)

    @property
    def is_resource(self) -> bool:
        """True if resource or resource_ref.

        Returns:
            True if this is a resource-related view.
        """
        return self._kind in (ViewKind.RESOURCE, ViewKind.RESOURCE_REF)

    @property
    def is_text(self) -> bool:
        """True if text or thinking.

        Returns:
            True if this is text-based content.
        """
        return self._kind in (ViewKind.TEXT, ViewKind.THINKING)

    @property
    def is_media(self) -> bool:
        """True if image, video, audio, or document.

        Returns:
            True if this is media content.
        """
        return self._kind in (ViewKind.IMAGE, ViewKind.VIDEO, ViewKind.AUDIO, ViewKind.DOCUMENT)

    # =========================================================================
    # Flat Accessors (capability-gated in the spec)
    # =========================================================================

    def _ext(self) -> Any:
        """Get the extensions, or None."""
        return self._extensions

    # --- Base tier (no capability required) ---

    @property
    def environment(self) -> str | None:
        """Execution environment (production, staging, dev).

        Capability: base (no requirement).

        Returns:
            Environment string or None.
        """
        ext = self._ext()
        if ext and ext.request:
            return ext.request.environment
        return None

    @property
    def request_id(self) -> str | None:
        """Request correlation ID.

        Capability: base (no requirement).

        Returns:
            Request ID string or None.
        """
        ext = self._ext()
        if ext and ext.request:
            return ext.request.request_id
        return None

    # --- read_subject ---

    @property
    def subject(self) -> SubjectExtension | None:
        """The authenticated entity making the request.

        Capability: read_subject.

        Returns:
            SubjectExtension or None.
        """
        ext = self._ext()
        if ext and ext.security:
            return ext.security.subject
        return None

    # --- read_roles ---

    @property
    def roles(self) -> frozenset[str]:
        """Subject's assigned roles.

        Capability: read_roles.

        Returns:
            Frozenset of role strings.
        """
        s = self.subject
        return s.roles if s else frozenset()

    # --- read_permissions ---

    @property
    def permissions(self) -> frozenset[str]:
        """Subject's granted permissions.

        Capability: read_permissions.

        Returns:
            Frozenset of permission strings.
        """
        s = self.subject
        return s.permissions if s else frozenset()

    # --- read_teams ---

    @property
    def teams(self) -> frozenset[str]:
        """Subject's team memberships.

        Capability: read_teams.

        Returns:
            Frozenset of team strings.
        """
        s = self.subject
        return s.teams if s else frozenset()

    # --- read_headers ---

    @property
    def headers(self) -> Mapping[str, str]:
        """HTTP headers associated with the request.

        Capability: read_headers.

        .. note::
           This returns raw headers including sensitive values
           (Authorization, Cookie, X-API-Key). This is by design —
           plugins with ``read_headers`` capability are trusted to
           see them. Sensitive headers are only stripped in
           ``to_dict()`` serialization, not in direct property access.

        Returns:
            Read-only mapping of header name to value.
        """
        ext = self._ext()
        if ext and ext.http:
            return MappingProxyType(ext.http.headers)
        return MappingProxyType({})

    # --- read_labels ---

    @property
    def labels(self) -> frozenset[str]:
        """Security/data labels on this message.

        Capability: read_labels.

        Returns:
            Frozenset of label strings.
        """
        ext = self._ext()
        if ext and ext.security:
            return ext.security.labels
        return frozenset()

    # --- read_agent ---

    @property
    def agent_input(self) -> str | None:
        """Original user intent that triggered this action.

        Capability: read_agent.

        Returns:
            Input string or None.
        """
        ext = self._ext()
        if ext and ext.agent:
            return ext.agent.input
        return None

    @property
    def session_id(self) -> str | None:
        """Broad session identifier.

        Capability: read_agent.

        Returns:
            Session ID string or None.
        """
        ext = self._ext()
        if ext and ext.agent:
            return ext.agent.session_id
        return None

    @property
    def conversation_id(self) -> str | None:
        """Specific dialogue/task within a session.

        Capability: read_agent.

        Returns:
            Conversation ID string or None.
        """
        ext = self._ext()
        if ext and ext.agent:
            return ext.agent.conversation_id
        return None

    @property
    def turn(self) -> int | None:
        """Position in conversation (0-indexed).

        Capability: read_agent.

        Returns:
            Turn number or None.
        """
        ext = self._ext()
        if ext and ext.agent:
            return ext.agent.turn
        return None

    @property
    def agent_id(self) -> str | None:
        """Identifier of the producing agent.

        Capability: read_agent.

        Returns:
            Agent ID string or None.
        """
        ext = self._ext()
        if ext and ext.agent:
            return ext.agent.agent_id
        return None

    @property
    def parent_agent_id(self) -> str | None:
        """Spawning agent's ID (multi-agent lineage).

        Capability: read_agent.

        Returns:
            Parent agent ID string or None.
        """
        ext = self._ext()
        if ext and ext.agent:
            return ext.agent.parent_agent_id
        return None

    # --- read_objects ---

    @property
    def object(self) -> ObjectSecurityProfile | None:
        """Access control profile for this view's entity.

        Resolved by view.name from extensions.security.objects.

        Capability: read_objects.

        Returns:
            ObjectSecurityProfile or None.
        """
        ext = self._ext()
        view_name = self.name
        if ext and ext.security and view_name:
            return ext.security.objects.get(view_name)
        return None

    # --- read_data ---

    @property
    def data_policy(self) -> DataPolicy | None:
        """Data governance policy for this view's entity.

        Resolved by view.name from extensions.security.data.

        Capability: read_data.

        Returns:
            DataPolicy or None.
        """
        ext = self._ext()
        view_name = self.name
        if ext and ext.security and view_name:
            return ext.security.data.get(view_name)
        return None

    # =========================================================================
    # Helper Methods
    # =========================================================================

    def has_role(self, role: str) -> bool:
        """Check if subject has a specific role.

        Args:
            role: The role to check for.

        Returns:
            True if the subject has the role.
        """
        return role in self.roles

    def has_permission(self, perm: str) -> bool:
        """Check if subject has a specific permission.

        Args:
            perm: The permission to check for.

        Returns:
            True if the subject has the permission.
        """
        return perm in self.permissions

    def has_label(self, label: str) -> bool:
        """Check if a security label is present.

        Args:
            label: Label to check for (e.g., "PII", "SECRET").

        Returns:
            True if the label is present.
        """
        return label in self.labels

    def has_header(self, name: str) -> bool:
        """Check if an HTTP header exists (case-insensitive).

        Args:
            name: Header name to check.

        Returns:
            True if header exists.
        """
        return self.get_header(name) is not None

    def get_header(self, name: str, default: str | None = None) -> str | None:
        """Get an HTTP header value (case-insensitive).

        Args:
            name: Header name.
            default: Default value if header not found.

        Returns:
            Header value or default.
        """
        lower_name = name.lower()
        for key, value in self.headers.items():
            if key.lower() == lower_name:
                return value
        return default

    def get_arg(self, name: str, default: Any = None) -> Any:
        """Get a single argument value.

        Args:
            name: Argument name.
            default: Value if argument doesn't exist.

        Returns:
            Argument value or default.
        """
        args = self.args
        if args is None:
            return default
        return args.get(name, default)

    def has_arg(self, name: str) -> bool:
        """Check if an argument exists.

        Args:
            name: Argument name to check.

        Returns:
            True if argument exists.
        """
        args = self.args
        return args is not None and name in args

    def matches_uri_pattern(self, pattern: str) -> bool:
        """Check if URI matches a glob-style pattern.

        Supports * (single segment) and ** (any number of segments)
        wildcards.

        Args:
            pattern: Glob pattern to match against.

        Returns:
            True if URI matches the pattern.
        """
        view_uri = self.uri
        if not view_uri:
            return False
        # Split on ** first, then * within each segment, escaping literals
        parts = pattern.split("**")
        regex_parts = []
        for part in parts:
            sub_parts = part.split("*")
            regex_parts.append("[^/]*".join(re.escape(s) for s in sub_parts))
        regex = f"^{'.*'.join(regex_parts)}$"
        return bool(re.match(regex, view_uri))

    def has_content(self) -> bool:
        """True if scannable text content is available.

        Returns:
            True if content is not None.
        """
        return self.content is not None

    # =========================================================================
    # Serialization
    # =========================================================================

    def to_dict(self, include_content: bool = True, include_context: bool = True) -> dict[str, Any]:
        """Serialize the view to a JSON-compatible dictionary.

        Sensitive headers (Authorization, Cookie, X-API-Key) are
        automatically stripped from the serialized output.

        Args:
            include_content: Include text content (may be large).
            include_context: Include extensions context.

        Returns:
            JSON-serializable dictionary with view properties.
        """
        result: dict[str, Any] = {
            "kind": self._kind.value,
            "role": self._message.role.value,
            "is_pre": self.is_pre,
            "is_post": self.is_post,
            "action": self.action.value,
        }

        if self._hook is not None:
            result["hook"] = self._hook

        if self.uri:
            result["uri"] = self.uri
        if self.name:
            result["name"] = self.name

        if include_content:
            text = self.content
            if text is not None:
                result["content"] = text
                result["size_bytes"] = len(text.encode("utf-8"))
            else:
                size = self.size_bytes
                if size is not None:
                    result["size_bytes"] = size

        if self.mime_type:
            result["mime_type"] = self.mime_type

        args = self.args
        if args is not None:
            result["arguments"] = args

        props = self.properties
        if props:
            result["properties"] = props

        if include_context:
            extensions: dict[str, Any] = {}

            # Subject
            s = self.subject
            if s:
                extensions["subject"] = {
                    "id": s.id,
                    "type": s.type.value,
                    "roles": sorted(s.roles),
                    "permissions": sorted(s.permissions),
                    "teams": sorted(s.teams),
                }

            # Environment
            env = self.environment
            if env:
                extensions["environment"] = env

            # Labels
            lbls = self.labels
            if lbls:
                extensions["labels"] = sorted(lbls)

            # Headers (strip sensitive)
            hdrs = self.headers
            if hdrs:
                safe = {k: v for k, v in hdrs.items() if k.lower() not in _SENSITIVE_HEADERS}
                if safe:
                    extensions["headers"] = safe

            # Object profile (for pre views)
            obj = self.object
            if obj:
                extensions["object"] = {
                    "managed_by": obj.managed_by,
                    "permissions": obj.permissions,
                    "trust_domain": obj.trust_domain,
                    "data_scope": obj.data_scope,
                }

            # Data policy (for post views)
            dp = self.data_policy
            if dp:
                dp_dict: dict[str, Any] = {
                    "apply_labels": dp.apply_labels,
                    "denied_actions": dp.denied_actions,
                }
                if dp.allowed_actions is not None:
                    dp_dict["allowed_actions"] = dp.allowed_actions
                if dp.retention:
                    dp_dict["retention"] = {
                        "max_age_seconds": dp.retention.max_age_seconds,
                        "policy": dp.retention.policy,
                        "delete_after": dp.retention.delete_after,
                    }
                extensions["data"] = dp_dict

            # Agent context
            ext = self._ext()
            if ext and ext.agent:
                agent_dict: dict[str, Any] = {}
                if ext.agent.input:
                    agent_dict["input"] = ext.agent.input
                if ext.agent.session_id:
                    agent_dict["session_id"] = ext.agent.session_id
                if ext.agent.conversation_id:
                    agent_dict["conversation_id"] = ext.agent.conversation_id
                if ext.agent.turn is not None:
                    agent_dict["turn"] = ext.agent.turn
                if ext.agent.agent_id:
                    agent_dict["agent_id"] = ext.agent.agent_id
                if ext.agent.parent_agent_id:
                    agent_dict["parent_agent_id"] = ext.agent.parent_agent_id
                if agent_dict:
                    extensions["agent"] = agent_dict

            if extensions:
                result["extensions"] = extensions

        return result

    def to_opa_input(self, include_content: bool = True) -> dict[str, Any]:
        """Serialize to OPA-compatible input format.

        Wraps the view in the standard OPA input envelope:
        {"input": {...view data...}}.

        Args:
            include_content: Include text content in the input.

        Returns:
            Dict in OPA input format.
        """
        return {"input": self.to_dict(include_content=include_content)}

    def __repr__(self) -> str:
        """String representation of the view.

        Returns:
            Human-readable representation.
        """
        role_part = f", role={self._message.role.value}"
        uri_part = f", uri={self.uri}" if self.uri else ""
        hook_part = f", hook={self._hook}" if self._hook else ""
        direction = "pre" if self.is_pre else "post" if self.is_post else "?"
        return f"MessageView(kind={self._kind.value}{role_part}, {direction}{uri_part}{hook_part})"


# ---------------------------------------------------------------------------
# View Iterator (standalone)
# ---------------------------------------------------------------------------


def iter_views(message: Message, hook: str | None = None, extensions: Any = None) -> Iterator[MessageView]:
    """Iterate over a message yielding one MessageView per content part.

    Memory-efficient: views are yielded one at a time and hold only
    references to the underlying message and content part.

    This is the standalone version. Message.iter_views() delegates
    to this function.

    Args:
        message: The message to decompose into views.
        hook: Optional hook location string (e.g., "llm_input",
            "tool_post_invoke") to attach to each view.

    Yields:
        A MessageView for each content part in the message.

    Examples:
        >>> from cpex.framework.cmf.message import (
        ...     Message, Role, TextContent, ToolCall, ToolCallContentPart,
        ...     ThinkingContent,
        ... )
        >>> msg = Message(
        ...     role=Role.ASSISTANT,
        ...     content=[
        ...         ThinkingContent(text="User wants admin users."),
        ...         TextContent(text="Let me look that up."),
        ...         ToolCallContentPart(
        ...             content=ToolCall(
        ...                 tool_call_id="tc_001",
        ...                 name="execute_sql",
        ...                 arguments={"query": "SELECT * FROM users"},
        ...             ),
        ...         ),
        ...     ],
        ... )
        >>> views = list(iter_views(msg))
        >>> len(views)
        3
        >>> [(v.kind.value, v.is_pre) for v in views]
        [('thinking', False), ('text', False), ('tool_call', True)]
    """
    for part in message.content:
        kind = _CONTENT_TYPE_TO_VIEW_KIND.get(part.content_type)
        if kind is None:
            logger.warning("Unknown content type %r in iter_views", part.content_type)
            raise ValueError(f"Unknown content type: {part.content_type!r}")
        yield MessageView(part, kind, message, hook=hook, extensions=extensions)
