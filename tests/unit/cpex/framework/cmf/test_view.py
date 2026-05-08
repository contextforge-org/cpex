# -*- coding: utf-8 -*-
"""Location: ./tests/unit/cpex/framework/cmf/test_view.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Teryl Taylor

Unit tests for MessageView.
"""

# Standard

# Third-Party
import pytest

# First-Party
from cpex.framework.cmf.message import (
    AudioContentPart,
    AudioSource,
    DocumentContentPart,
    DocumentSource,
    ImageContentPart,
    ImageSource,
    Message,
    PromptRequest,
    PromptRequestContentPart,
    PromptResult,
    PromptResultContentPart,
    Resource,
    ResourceContentPart,
    ResourceRefContentPart,
    ResourceReference,
    ResourceType,
    Role,
    TextContent,
    ThinkingContent,
    ToolCall,
    ToolCallContentPart,
    ToolResult,
    ToolResultContentPart,
    VideoContentPart,
    VideoSource,
)
from cpex.framework.cmf.view import (
    ViewAction,
    ViewKind,
    iter_views,
)
from cpex.framework.extensions.agent import AgentExtension
from cpex.framework.extensions.extensions import Extensions
from cpex.framework.extensions.http import HttpExtension
from cpex.framework.extensions.request import RequestExtension
from cpex.framework.extensions.security import (
    DataPolicy,
    ObjectSecurityProfile,
    RetentionPolicy,
    SecurityExtension,
    SubjectExtension,
    SubjectType,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def simple_assistant_msg():
    """An assistant message with text, thinking, and a tool call."""
    return Message(
        role=Role.ASSISTANT,
        content=[
            ThinkingContent(text="User wants admin users."),
            TextContent(text="Let me look that up."),
            ToolCallContentPart(
                content=ToolCall(
                    tool_call_id="tc_001",
                    name="execute_sql",
                    arguments={"query": "SELECT * FROM users WHERE role='admin'"},
                ),
            ),
        ],
    )


@pytest.fixture
def full_msg():
    """A message and extensions (separated per CMF design)."""
    msg = Message(
        role=Role.ASSISTANT,
        content=[
            ToolCallContentPart(
                content=ToolCall(
                    tool_call_id="tc_001",
                    name="get_compensation",
                    namespace="hr-server",
                    arguments={"employee_id": "emp-42"},
                ),
            ),
        ],
    )
    ext = Extensions(
        request=RequestExtension(
            environment="production",
            request_id="req-001",
        ),
        agent=AgentExtension(
            input="Show me Alice's compensation",
            session_id="sess-001",
            conversation_id="conv-001",
            turn=2,
            agent_id="main-agent",
            parent_agent_id="orchestrator",
        ),
        http=HttpExtension(
            headers={
                "Authorization": "Bearer secret-token",
                "Cookie": "session=abc",
                "X-Request-ID": "req-001",
                "Content-Type": "application/json",
            },
        ),
        security=SecurityExtension(
            labels=frozenset({"CONFIDENTIAL"}),
            classification="confidential",
            subject=SubjectExtension(
                id="user-alice",
                type=SubjectType.USER,
                roles=frozenset({"admin", "hr-manager"}),
                permissions=frozenset({"read:compensation", "tools.execute"}),
                teams=frozenset({"hr-team"}),
            ),
            objects={
                "get_compensation": ObjectSecurityProfile(
                    managed_by="tool",
                    permissions=["read:compensation"],
                    trust_domain="internal",
                    data_scope=["salary", "bonus"],
                ),
            },
            data={
                "get_compensation": DataPolicy(
                    apply_labels=["PII", "financial"],
                    denied_actions=["export", "forward", "log_raw"],
                    retention=RetentionPolicy(
                        policy="session",
                        max_age_seconds=3600,
                    ),
                ),
            },
        ),
    )
    return msg, ext


# ---------------------------------------------------------------------------
# Enum Tests
# ---------------------------------------------------------------------------


class TestViewKind:
    """Tests for ViewKind enum."""

    def test_member_count(self):
        assert len(ViewKind) == 12

    def test_values_match_content_type(self):
        from cpex.framework.cmf.message import ContentType

        for ct in ContentType:
            assert ct.value in [vk.value for vk in ViewKind]


class TestViewAction:
    """Tests for ViewAction enum."""

    def test_member_count(self):
        assert len(ViewAction) == 7

    def test_values(self):
        expected = {"read", "write", "execute", "invoke", "send", "receive", "generate"}
        assert {va.value for va in ViewAction} == expected


# ---------------------------------------------------------------------------
# View Iteration
# ---------------------------------------------------------------------------


class TestIterViews:
    """Tests for iter_views() and Message.iter_views()."""

    def test_standalone_and_method_match(self, simple_assistant_msg):
        standalone = list(iter_views(simple_assistant_msg))
        method = list(simple_assistant_msg.iter_views())
        assert len(standalone) == len(method) == 3

    def test_view_count(self, simple_assistant_msg):
        views = list(iter_views(simple_assistant_msg))
        assert len(views) == 3

    def test_view_kinds(self, simple_assistant_msg):
        views = list(iter_views(simple_assistant_msg))
        assert views[0].kind == ViewKind.THINKING
        assert views[1].kind == ViewKind.TEXT
        assert views[2].kind == ViewKind.TOOL_CALL

    def test_empty_message(self):
        msg = Message(role=Role.USER)
        views = list(iter_views(msg))
        assert len(views) == 0

    def test_single_content_part(self):
        msg = Message(role=Role.USER, content=[TextContent(text="Hi")])
        views = list(iter_views(msg))
        assert len(views) == 1
        assert views[0].kind == ViewKind.TEXT

    def test_all_content_types(self):
        msg = Message(
            role=Role.ASSISTANT,
            content=[
                TextContent(text="hi"),
                ThinkingContent(text="hmm"),
                ToolCallContentPart(content=ToolCall(tool_call_id="t1", name="x", arguments={})),
                ToolResultContentPart(content=ToolResult(tool_call_id="t1", tool_name="x", content="ok")),
                ResourceContentPart(
                    content=Resource(
                        resource_request_id="r1", uri="file:///a", resource_type=ResourceType.FILE, content="data"
                    )
                ),
                ResourceRefContentPart(
                    content=ResourceReference(
                        resource_request_id="r2", uri="db://b", resource_type=ResourceType.DATABASE
                    )
                ),
                PromptRequestContentPart(content=PromptRequest(prompt_request_id="p1", name="summarize")),
                PromptResultContentPart(
                    content=PromptResult(prompt_request_id="p1", prompt_name="summarize", content="summary")
                ),
                ImageContentPart(content=ImageSource(type="url", data="http://img")),
                VideoContentPart(content=VideoSource(type="url", data="http://vid")),
                AudioContentPart(content=AudioSource(type="url", data="http://aud")),
                DocumentContentPart(content=DocumentSource(type="url", data="http://doc")),
            ],
        )
        views = list(iter_views(msg))
        assert len(views) == 12
        expected_kinds = [
            ViewKind.TEXT,
            ViewKind.THINKING,
            ViewKind.TOOL_CALL,
            ViewKind.TOOL_RESULT,
            ViewKind.RESOURCE,
            ViewKind.RESOURCE_REF,
            ViewKind.PROMPT_REQUEST,
            ViewKind.PROMPT_RESULT,
            ViewKind.IMAGE,
            ViewKind.VIDEO,
            ViewKind.AUDIO,
            ViewKind.DOCUMENT,
        ]
        for view, expected in zip(views, expected_kinds):
            assert view.kind == expected


# ---------------------------------------------------------------------------
# Core Properties
# ---------------------------------------------------------------------------


class TestCoreProperties:
    """Tests for MessageView core properties."""

    def test_role(self, simple_assistant_msg):
        view = list(iter_views(simple_assistant_msg))[0]
        assert view.role == Role.ASSISTANT

    def test_raw_access(self, simple_assistant_msg):
        views = list(iter_views(simple_assistant_msg))
        assert isinstance(views[0].raw, ThinkingContent)
        assert isinstance(views[2].raw, ToolCallContentPart)

    def test_content_text(self):
        msg = Message(role=Role.USER, content=[TextContent(text="Hello")])
        view = list(iter_views(msg))[0]
        assert view.content == "Hello"

    def test_content_thinking(self):
        msg = Message(role=Role.ASSISTANT, content=[ThinkingContent(text="Reasoning...")])
        view = list(iter_views(msg))[0]
        assert view.content == "Reasoning..."

    def test_content_tool_call(self):
        msg = Message(
            role=Role.ASSISTANT,
            content=[
                ToolCallContentPart(content=ToolCall(tool_call_id="tc1", name="test", arguments={"key": "value"}))
            ],
        )
        view = list(iter_views(msg))[0]
        assert view.content == '{"key": "value"}'

    def test_content_tool_result(self):
        msg = Message(
            role=Role.TOOL,
            content=[
                ToolResultContentPart(content=ToolResult(tool_call_id="tc1", tool_name="test", content={"result": 42}))
            ],
        )
        view = list(iter_views(msg))[0]
        assert view.content == '{"result": 42}'

    def test_content_tool_result_string(self):
        msg = Message(
            role=Role.TOOL,
            content=[
                ToolResultContentPart(content=ToolResult(tool_call_id="tc1", tool_name="test", content="plain text"))
            ],
        )
        view = list(iter_views(msg))[0]
        assert view.content == "plain text"

    def test_content_tool_result_none(self):
        msg = Message(
            role=Role.TOOL,
            content=[ToolResultContentPart(content=ToolResult(tool_call_id="tc1", tool_name="test"))],
        )
        view = list(iter_views(msg))[0]
        assert view.content is None

    def test_content_resource(self):
        msg = Message(
            role=Role.TOOL,
            content=[
                ResourceContentPart(
                    content=Resource(
                        resource_request_id="r1",
                        uri="file:///a",
                        resource_type=ResourceType.FILE,
                        content="file data",
                    )
                )
            ],
        )
        view = list(iter_views(msg))[0]
        assert view.content == "file data"

    def test_content_prompt_request(self):
        msg = Message(
            role=Role.ASSISTANT,
            content=[
                PromptRequestContentPart(
                    content=PromptRequest(prompt_request_id="p1", name="s", arguments={"text": "hi"})
                )
            ],
        )
        view = list(iter_views(msg))[0]
        assert view.content == '{"text": "hi"}'

    def test_content_prompt_result(self):
        msg = Message(
            role=Role.TOOL,
            content=[
                PromptResultContentPart(
                    content=PromptResult(prompt_request_id="p1", prompt_name="s", content="rendered")
                )
            ],
        )
        view = list(iter_views(msg))[0]
        assert view.content == "rendered"

    def test_content_media_none(self):
        msg = Message(
            role=Role.USER,
            content=[ImageContentPart(content=ImageSource(type="url", data="http://img"))],
        )
        view = list(iter_views(msg))[0]
        assert view.content is None


# ---------------------------------------------------------------------------
# URI
# ---------------------------------------------------------------------------


class TestURI:
    """Tests for synthetic URI generation."""

    def test_tool_call_uri(self):
        msg = Message(
            role=Role.ASSISTANT,
            content=[ToolCallContentPart(content=ToolCall(tool_call_id="tc1", name="get_user", arguments={}))],
        )
        view = list(iter_views(msg))[0]
        assert view.uri == "tool://_/get_user"

    def test_tool_call_uri_with_namespace(self):
        msg = Message(
            role=Role.ASSISTANT,
            content=[
                ToolCallContentPart(
                    content=ToolCall(tool_call_id="tc1", name="get_user", namespace="user-svc", arguments={})
                )
            ],
        )
        view = list(iter_views(msg))[0]
        assert view.uri == "tool://user-svc/get_user"

    def test_tool_result_uri(self):
        msg = Message(
            role=Role.TOOL,
            content=[ToolResultContentPart(content=ToolResult(tool_call_id="tc1", tool_name="get_user"))],
        )
        view = list(iter_views(msg))[0]
        assert view.uri == "tool_result://get_user"

    def test_resource_uri(self):
        msg = Message(
            role=Role.TOOL,
            content=[
                ResourceContentPart(
                    content=Resource(
                        resource_request_id="r1",
                        uri="file:///data/report.csv",
                        resource_type=ResourceType.FILE,
                    )
                )
            ],
        )
        view = list(iter_views(msg))[0]
        assert view.uri == "file:///data/report.csv"

    def test_resource_ref_uri(self):
        msg = Message(
            role=Role.ASSISTANT,
            content=[
                ResourceRefContentPart(
                    content=ResourceReference(
                        resource_request_id="r1",
                        uri="db://users/42",
                        resource_type=ResourceType.DATABASE,
                    )
                )
            ],
        )
        view = list(iter_views(msg))[0]
        assert view.uri == "db://users/42"

    def test_prompt_request_uri(self):
        msg = Message(
            role=Role.ASSISTANT,
            content=[
                PromptRequestContentPart(
                    content=PromptRequest(prompt_request_id="p1", name="summarize", server_id="prompt-svc")
                )
            ],
        )
        view = list(iter_views(msg))[0]
        assert view.uri == "prompt://prompt-svc/summarize"

    def test_prompt_result_uri(self):
        msg = Message(
            role=Role.TOOL,
            content=[PromptResultContentPart(content=PromptResult(prompt_request_id="p1", prompt_name="summarize"))],
        )
        view = list(iter_views(msg))[0]
        assert view.uri == "prompt_result://summarize"

    def test_text_uri_is_none(self):
        msg = Message(role=Role.USER, content=[TextContent(text="hi")])
        view = list(iter_views(msg))[0]
        assert view.uri is None


# ---------------------------------------------------------------------------
# Name
# ---------------------------------------------------------------------------


class TestName:
    """Tests for the name property."""

    def test_tool_call_name(self):
        msg = Message(
            role=Role.ASSISTANT,
            content=[ToolCallContentPart(content=ToolCall(tool_call_id="tc1", name="get_user", arguments={}))],
        )
        assert list(iter_views(msg))[0].name == "get_user"

    def test_tool_result_name(self):
        msg = Message(
            role=Role.TOOL,
            content=[ToolResultContentPart(content=ToolResult(tool_call_id="tc1", tool_name="get_user"))],
        )
        assert list(iter_views(msg))[0].name == "get_user"

    def test_prompt_request_name(self):
        msg = Message(
            role=Role.ASSISTANT,
            content=[PromptRequestContentPart(content=PromptRequest(prompt_request_id="p1", name="summarize"))],
        )
        assert list(iter_views(msg))[0].name == "summarize"

    def test_prompt_result_name(self):
        msg = Message(
            role=Role.TOOL,
            content=[PromptResultContentPart(content=PromptResult(prompt_request_id="p1", prompt_name="summarize"))],
        )
        assert list(iter_views(msg))[0].name == "summarize"

    def test_text_name_is_none(self):
        msg = Message(role=Role.USER, content=[TextContent(text="hi")])
        assert list(iter_views(msg))[0].name is None


# ---------------------------------------------------------------------------
# Action
# ---------------------------------------------------------------------------


class TestAction:
    """Tests for the action property."""

    def test_action_mapping(self):
        pairs = [
            (TextContent(text="hi"), Role.USER, ViewAction.SEND),
            (ThinkingContent(text="hmm"), Role.ASSISTANT, ViewAction.GENERATE),
            (
                ToolCallContentPart(content=ToolCall(tool_call_id="t", name="x", arguments={})),
                Role.ASSISTANT,
                ViewAction.EXECUTE,
            ),
            (ToolResultContentPart(content=ToolResult(tool_call_id="t", tool_name="x")), Role.TOOL, ViewAction.RECEIVE),
            (
                ResourceContentPart(
                    content=Resource(resource_request_id="r", uri="f:///a", resource_type=ResourceType.FILE)
                ),
                Role.TOOL,
                ViewAction.READ,
            ),
            (
                ResourceRefContentPart(
                    content=ResourceReference(resource_request_id="r", uri="f:///a", resource_type=ResourceType.FILE)
                ),
                Role.ASSISTANT,
                ViewAction.READ,
            ),
            (
                PromptRequestContentPart(content=PromptRequest(prompt_request_id="p", name="s")),
                Role.ASSISTANT,
                ViewAction.INVOKE,
            ),
            (
                PromptResultContentPart(content=PromptResult(prompt_request_id="p", prompt_name="s")),
                Role.TOOL,
                ViewAction.RECEIVE,
            ),
            (ImageContentPart(content=ImageSource(type="url", data="http://img")), Role.USER, ViewAction.SEND),
        ]
        for part, role, expected_action in pairs:
            msg = Message(role=role, content=[part])
            view = list(iter_views(msg))[0]
            assert view.action == expected_action, f"Expected {expected_action} for {part.content_type}"


# ---------------------------------------------------------------------------
# Direction
# ---------------------------------------------------------------------------


class TestDirection:
    """Tests for is_pre / is_post direction logic."""

    def test_tool_call_is_pre(self):
        msg = Message(
            role=Role.ASSISTANT,
            content=[ToolCallContentPart(content=ToolCall(tool_call_id="t", name="x", arguments={}))],
        )
        view = list(iter_views(msg))[0]
        assert view.is_pre is True
        assert view.is_post is False

    def test_tool_result_is_post(self):
        msg = Message(
            role=Role.TOOL, content=[ToolResultContentPart(content=ToolResult(tool_call_id="t", tool_name="x"))]
        )
        view = list(iter_views(msg))[0]
        assert view.is_pre is False
        assert view.is_post is True

    def test_prompt_request_is_pre(self):
        msg = Message(
            role=Role.ASSISTANT,
            content=[PromptRequestContentPart(content=PromptRequest(prompt_request_id="p", name="s"))],
        )
        view = list(iter_views(msg))[0]
        assert view.is_pre is True

    def test_prompt_result_is_post(self):
        msg = Message(
            role=Role.TOOL,
            content=[PromptResultContentPart(content=PromptResult(prompt_request_id="p", prompt_name="s"))],
        )
        view = list(iter_views(msg))[0]
        assert view.is_post is True

    def test_resource_ref_is_pre(self):
        msg = Message(
            role=Role.ASSISTANT,
            content=[
                ResourceRefContentPart(
                    content=ResourceReference(resource_request_id="r", uri="f:///a", resource_type=ResourceType.FILE)
                ),
            ],
        )
        view = list(iter_views(msg))[0]
        assert view.is_pre is True

    def test_resource_is_post(self):
        msg = Message(
            role=Role.TOOL,
            content=[
                ResourceContentPart(
                    content=Resource(resource_request_id="r", uri="f:///a", resource_type=ResourceType.FILE)
                ),
            ],
        )
        view = list(iter_views(msg))[0]
        assert view.is_post is True

    def test_user_text_is_pre(self):
        msg = Message(role=Role.USER, content=[TextContent(text="hi")])
        view = list(iter_views(msg))[0]
        assert view.is_pre is True
        assert view.is_post is False

    def test_assistant_text_is_post(self):
        msg = Message(role=Role.ASSISTANT, content=[TextContent(text="hello")])
        view = list(iter_views(msg))[0]
        assert view.is_pre is False
        assert view.is_post is True

    def test_system_text_is_pre(self):
        msg = Message(role=Role.SYSTEM, content=[TextContent(text="instructions")])
        view = list(iter_views(msg))[0]
        assert view.is_pre is True

    def test_developer_text_is_pre(self):
        msg = Message(role=Role.DEVELOPER, content=[TextContent(text="hints")])
        view = list(iter_views(msg))[0]
        assert view.is_pre is True

    def test_tool_text_is_post(self):
        msg = Message(role=Role.TOOL, content=[TextContent(text="result text")])
        view = list(iter_views(msg))[0]
        assert view.is_pre is False
        assert view.is_post is True


# ---------------------------------------------------------------------------
# Entity Type Helpers
# ---------------------------------------------------------------------------


class TestEntityTypeHelpers:
    """Tests for is_tool, is_prompt, is_resource, is_text, is_media."""

    def test_is_tool(self):
        msg = Message(
            role=Role.ASSISTANT,
            content=[ToolCallContentPart(content=ToolCall(tool_call_id="t", name="x", arguments={}))],
        )
        assert list(iter_views(msg))[0].is_tool is True

    def test_is_tool_result(self):
        msg = Message(
            role=Role.TOOL, content=[ToolResultContentPart(content=ToolResult(tool_call_id="t", tool_name="x"))]
        )
        assert list(iter_views(msg))[0].is_tool is True

    def test_is_prompt(self):
        msg = Message(
            role=Role.ASSISTANT,
            content=[PromptRequestContentPart(content=PromptRequest(prompt_request_id="p", name="s"))],
        )
        assert list(iter_views(msg))[0].is_prompt is True

    def test_is_resource(self):
        msg = Message(
            role=Role.TOOL,
            content=[
                ResourceContentPart(
                    content=Resource(resource_request_id="r", uri="f:///a", resource_type=ResourceType.FILE)
                ),
            ],
        )
        assert list(iter_views(msg))[0].is_resource is True

    def test_is_text(self):
        msg = Message(role=Role.USER, content=[TextContent(text="hi")])
        assert list(iter_views(msg))[0].is_text is True

    def test_is_text_thinking(self):
        msg = Message(role=Role.ASSISTANT, content=[ThinkingContent(text="hmm")])
        assert list(iter_views(msg))[0].is_text is True

    def test_is_media(self):
        for part in [
            ImageContentPart(content=ImageSource(type="url", data="http://img")),
            VideoContentPart(content=VideoSource(type="url", data="http://vid")),
            AudioContentPart(content=AudioSource(type="url", data="http://aud")),
            DocumentContentPart(content=DocumentSource(type="url", data="http://doc")),
        ]:
            msg = Message(role=Role.USER, content=[part])
            assert list(iter_views(msg))[0].is_media is True

    def test_text_is_not_media(self):
        msg = Message(role=Role.USER, content=[TextContent(text="hi")])
        assert list(iter_views(msg))[0].is_media is False


# ---------------------------------------------------------------------------
# Flat Accessors
# ---------------------------------------------------------------------------


class TestFlatAccessors:
    """Tests for capability-gated flat accessors."""

    def test_base_tier(self, full_msg):
        view = list(iter_views(full_msg[0], extensions=full_msg[1]))[0]
        assert view.environment == "production"
        assert view.request_id == "req-001"

    def test_subject(self, full_msg):
        view = list(iter_views(full_msg[0], extensions=full_msg[1]))[0]
        assert view.subject.id == "user-alice"
        assert view.subject.type == SubjectType.USER

    def test_roles(self, full_msg):
        view = list(iter_views(full_msg[0], extensions=full_msg[1]))[0]
        assert "admin" in view.roles
        assert "hr-manager" in view.roles

    def test_permissions(self, full_msg):
        view = list(iter_views(full_msg[0], extensions=full_msg[1]))[0]
        assert "read:compensation" in view.permissions

    def test_teams(self, full_msg):
        view = list(iter_views(full_msg[0], extensions=full_msg[1]))[0]
        assert "hr-team" in view.teams

    def test_headers(self, full_msg):
        view = list(iter_views(full_msg[0], extensions=full_msg[1]))[0]
        assert view.headers["Content-Type"] == "application/json"

    def test_labels(self, full_msg):
        view = list(iter_views(full_msg[0], extensions=full_msg[1]))[0]
        assert "CONFIDENTIAL" in view.labels

    def test_agent_accessors(self, full_msg):
        view = list(iter_views(full_msg[0], extensions=full_msg[1]))[0]
        assert view.agent_input == "Show me Alice's compensation"
        assert view.session_id == "sess-001"
        assert view.conversation_id == "conv-001"
        assert view.turn == 2
        assert view.agent_id == "main-agent"
        assert view.parent_agent_id == "orchestrator"

    def test_object_profile(self, full_msg):
        view = list(iter_views(full_msg[0], extensions=full_msg[1]))[0]
        assert view.object is not None
        assert view.object.managed_by == "tool"
        assert view.object.permissions == ["read:compensation"]
        assert view.object.trust_domain == "internal"
        assert view.object.data_scope == ["salary", "bonus"]

    def test_data_policy(self, full_msg):
        view = list(iter_views(full_msg[0], extensions=full_msg[1]))[0]
        assert view.data_policy is not None
        assert "PII" in view.data_policy.apply_labels
        assert "export" in view.data_policy.denied_actions
        assert view.data_policy.retention.policy == "session"

    def test_no_extensions(self):
        msg = Message(role=Role.USER, content=[TextContent(text="hi")])
        view = list(iter_views(msg))[0]
        assert view.environment is None
        assert view.request_id is None
        assert view.subject is None
        assert view.roles == frozenset()
        assert view.permissions == frozenset()
        assert view.teams == frozenset()
        assert view.headers == {}
        assert view.labels == frozenset()
        assert view.agent_input is None
        assert view.session_id is None
        assert view.conversation_id is None
        assert view.turn is None
        assert view.agent_id is None
        assert view.parent_agent_id is None
        assert view.object is None
        assert view.data_policy is None

    def test_object_resolves_by_name(self):
        msg = Message(
            role=Role.ASSISTANT,
            content=[
                ToolCallContentPart(content=ToolCall(tool_call_id="tc1", name="tool_a", arguments={})),
                ToolCallContentPart(content=ToolCall(tool_call_id="tc2", name="tool_b", arguments={})),
            ],
        )
        ext = Extensions(
            security=SecurityExtension(
                objects={"tool_a": ObjectSecurityProfile(managed_by="host")},
            ),
        )
        views = list(iter_views(msg, extensions=ext))
        assert views[0].object is not None
        assert views[0].object.managed_by == "host"
        assert views[1].object is None


# ---------------------------------------------------------------------------
# Helper Methods
# ---------------------------------------------------------------------------


class TestHelperMethods:
    """Tests for helper methods on MessageView."""

    def test_has_role(self, full_msg):
        view = list(iter_views(full_msg[0], extensions=full_msg[1]))[0]
        assert view.has_role("admin") is True
        assert view.has_role("viewer") is False

    def test_has_permission(self, full_msg):
        view = list(iter_views(full_msg[0], extensions=full_msg[1]))[0]
        assert view.has_permission("read:compensation") is True
        assert view.has_permission("write:users") is False

    def test_has_label(self, full_msg):
        view = list(iter_views(full_msg[0], extensions=full_msg[1]))[0]
        assert view.has_label("CONFIDENTIAL") is True
        assert view.has_label("SECRET") is False

    def test_has_header(self, full_msg):
        view = list(iter_views(full_msg[0], extensions=full_msg[1]))[0]
        assert view.has_header("Content-Type") is True
        assert view.has_header("content-type") is True
        assert view.has_header("X-Missing") is False

    def test_get_header_case_insensitive(self, full_msg):
        view = list(iter_views(full_msg[0], extensions=full_msg[1]))[0]
        assert view.get_header("content-type") == "application/json"
        assert view.get_header("CONTENT-TYPE") == "application/json"

    def test_get_header_default(self, full_msg):
        view = list(iter_views(full_msg[0], extensions=full_msg[1]))[0]
        assert view.get_header("X-Missing") is None
        assert view.get_header("X-Missing", "fallback") == "fallback"

    def test_get_arg(self, full_msg):
        view = list(iter_views(full_msg[0], extensions=full_msg[1]))[0]
        assert view.get_arg("employee_id") == "emp-42"
        assert view.get_arg("missing") is None
        assert view.get_arg("missing", "default") == "default"

    def test_has_arg(self, full_msg):
        view = list(iter_views(full_msg[0], extensions=full_msg[1]))[0]
        assert view.has_arg("employee_id") is True
        assert view.has_arg("missing") is False

    def test_has_arg_text_view(self):
        msg = Message(role=Role.USER, content=[TextContent(text="hi")])
        view = list(iter_views(msg))[0]
        assert view.has_arg("anything") is False

    def test_matches_uri_pattern(self, full_msg):
        view = list(iter_views(full_msg[0], extensions=full_msg[1]))[0]
        assert view.matches_uri_pattern("tool://hr-server/*") is True
        assert view.matches_uri_pattern("tool://hr-server/get_*") is True
        assert view.matches_uri_pattern("tool://other/*") is False
        assert view.matches_uri_pattern("tool://**") is True

    def test_matches_uri_pattern_no_uri(self):
        msg = Message(role=Role.USER, content=[TextContent(text="hi")])
        view = list(iter_views(msg))[0]
        assert view.matches_uri_pattern("*") is False

    def test_has_content(self, simple_assistant_msg):
        views = list(iter_views(simple_assistant_msg))
        assert views[0].has_content() is True
        assert views[1].has_content() is True
        assert views[2].has_content() is True


# ---------------------------------------------------------------------------
# Type-Specific Properties
# ---------------------------------------------------------------------------


class TestProperties:
    """Tests for type-specific properties."""

    def test_tool_call_properties(self):
        msg = Message(
            role=Role.ASSISTANT,
            content=[
                ToolCallContentPart(content=ToolCall(tool_call_id="tc1", name="test", namespace="ns", arguments={}))
            ],
        )
        view = list(iter_views(msg))[0]
        assert view.get_property("namespace") == "ns"
        assert view.get_property("tool_id") == "tc1"
        props = view.properties
        assert props["namespace"] == "ns"
        assert props["tool_id"] == "tc1"

    def test_tool_result_properties(self):
        msg = Message(
            role=Role.TOOL,
            content=[ToolResultContentPart(content=ToolResult(tool_call_id="tc1", tool_name="test", is_error=True))],
        )
        view = list(iter_views(msg))[0]
        assert view.get_property("is_error") is True
        assert view.get_property("tool_name") == "test"

    def test_resource_properties(self):
        msg = Message(
            role=Role.TOOL,
            content=[
                ResourceContentPart(
                    content=Resource(
                        resource_request_id="r1",
                        uri="f:///a",
                        resource_type=ResourceType.FILE,
                        version="v2",
                        annotations={"key": "val"},
                    )
                )
            ],
        )
        view = list(iter_views(msg))[0]
        assert view.get_property("resource_type") == "file"
        assert view.get_property("version") == "v2"
        assert view.get_property("annotations") == {"key": "val"}

    def test_prompt_result_properties(self):
        msg = Message(
            role=Role.TOOL,
            content=[
                PromptResultContentPart(
                    content=PromptResult(
                        prompt_request_id="p1",
                        prompt_name="s",
                        messages=[
                            Message(role=Role.USER, content=[TextContent(text="m1")]),
                            Message(role=Role.ASSISTANT, content=[TextContent(text="m2")]),
                        ],
                        is_error=False,
                    )
                )
            ],
        )
        view = list(iter_views(msg))[0]
        assert view.get_property("is_error") is False
        assert view.get_property("message_count") == 2

    def test_get_property_default(self):
        msg = Message(role=Role.USER, content=[TextContent(text="hi")])
        view = list(iter_views(msg))[0]
        assert view.get_property("anything") is None
        assert view.get_property("anything", "fallback") == "fallback"

    def test_empty_properties_for_text(self):
        msg = Message(role=Role.USER, content=[TextContent(text="hi")])
        view = list(iter_views(msg))[0]
        assert view.properties == {}


# ---------------------------------------------------------------------------
# Misc Properties
# ---------------------------------------------------------------------------


class TestMiscProperties:
    """Tests for mime_type, size_bytes, args."""

    def test_mime_type_resource(self):
        msg = Message(
            role=Role.TOOL,
            content=[
                ResourceContentPart(
                    content=Resource(
                        resource_request_id="r1",
                        uri="f:///a",
                        resource_type=ResourceType.FILE,
                        mime_type="text/csv",
                    )
                )
            ],
        )
        assert list(iter_views(msg))[0].mime_type == "text/csv"

    def test_mime_type_image(self):
        msg = Message(
            role=Role.USER,
            content=[
                ImageContentPart(content=ImageSource(type="url", data="http://img", media_type="image/png")),
            ],
        )
        assert list(iter_views(msg))[0].mime_type == "image/png"

    def test_mime_type_text_none(self):
        msg = Message(role=Role.USER, content=[TextContent(text="hi")])
        assert list(iter_views(msg))[0].mime_type is None

    def test_size_bytes_text(self):
        msg = Message(role=Role.USER, content=[TextContent(text="hello")])
        assert list(iter_views(msg))[0].size_bytes == 5

    def test_size_bytes_resource_explicit(self):
        msg = Message(
            role=Role.TOOL,
            content=[
                ResourceContentPart(
                    content=Resource(
                        resource_request_id="r1",
                        uri="f:///a",
                        resource_type=ResourceType.FILE,
                        size_bytes=1024,
                    )
                )
            ],
        )
        assert list(iter_views(msg))[0].size_bytes == 1024

    def test_size_bytes_resource_from_content(self):
        msg = Message(
            role=Role.TOOL,
            content=[
                ResourceContentPart(
                    content=Resource(
                        resource_request_id="r1",
                        uri="f:///a",
                        resource_type=ResourceType.FILE,
                        content="hello",
                    )
                )
            ],
        )
        assert list(iter_views(msg))[0].size_bytes == 5

    def test_args_tool_call(self):
        msg = Message(
            role=Role.ASSISTANT,
            content=[ToolCallContentPart(content=ToolCall(tool_call_id="tc1", name="x", arguments={"a": 1, "b": 2}))],
        )
        view = list(iter_views(msg))[0]
        assert view.args == {"a": 1, "b": 2}

    def test_args_text_none(self):
        msg = Message(role=Role.USER, content=[TextContent(text="hi")])
        assert list(iter_views(msg))[0].args is None


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


class TestSerialization:
    """Tests for to_dict() and to_opa_input()."""

    def test_to_dict_basic(self, simple_assistant_msg):
        view = list(iter_views(simple_assistant_msg))[2]
        d = view.to_dict()
        assert d["kind"] == "tool_call"
        assert d["role"] == "assistant"
        assert d["is_pre"] is True
        assert d["is_post"] is False
        assert d["action"] == "execute"
        assert d["name"] == "execute_sql"
        assert d["uri"] == "tool://_/execute_sql"

    def test_to_dict_strips_sensitive_headers(self, full_msg):
        view = list(iter_views(full_msg[0], extensions=full_msg[1]))[0]
        d = view.to_dict()
        headers = d["extensions"].get("headers", {})
        assert "Authorization" not in headers
        assert "Cookie" not in headers
        assert "Content-Type" in headers

    def test_to_dict_includes_extensions(self, full_msg):
        view = list(iter_views(full_msg[0], extensions=full_msg[1]))[0]
        d = view.to_dict()
        ext = d["extensions"]
        assert ext["environment"] == "production"
        assert ext["subject"]["id"] == "user-alice"
        assert "CONFIDENTIAL" in ext["labels"]
        assert ext["object"]["managed_by"] == "tool"
        assert "PII" in ext["data"]["apply_labels"]
        assert ext["agent"]["input"] == "Show me Alice's compensation"

    def test_to_dict_exclude_content(self, simple_assistant_msg):
        view = list(iter_views(simple_assistant_msg))[0]
        d = view.to_dict(include_content=False)
        assert "content" not in d
        assert "size_bytes" not in d

    def test_to_dict_exclude_context(self, full_msg):
        view = list(iter_views(full_msg[0], extensions=full_msg[1]))[0]
        d = view.to_dict(include_context=False)
        assert "extensions" not in d

    def test_to_opa_input(self, simple_assistant_msg):
        view = list(iter_views(simple_assistant_msg))[2]
        opa = view.to_opa_input()
        assert "input" in opa
        assert opa["input"]["kind"] == "tool_call"

    def test_to_dict_no_extensions(self):
        msg = Message(role=Role.USER, content=[TextContent(text="hi")])
        view = list(iter_views(msg))[0]
        d = view.to_dict()
        assert "extensions" not in d


# ---------------------------------------------------------------------------
# Repr
# ---------------------------------------------------------------------------


class TestRepr:
    """Tests for __repr__."""

    def test_repr_text(self):
        msg = Message(role=Role.USER, content=[TextContent(text="hi")])
        view = list(iter_views(msg))[0]
        r = repr(view)
        assert "kind=text" in r
        assert "role=user" in r
        assert "pre" in r

    def test_repr_tool_call(self):
        msg = Message(
            role=Role.ASSISTANT,
            content=[ToolCallContentPart(content=ToolCall(tool_call_id="tc1", name="test", arguments={}))],
        )
        view = list(iter_views(msg))[0]
        r = repr(view)
        assert "tool_call" in r
        assert "tool://_/test" in r


# ---------------------------------------------------------------------------
# Hook property
# ---------------------------------------------------------------------------


class TestHookProperty:
    """Tests for the hook property on MessageView."""

    def test_hook_none_by_default(self):
        msg = Message(role=Role.USER, content=[TextContent(text="hi")])
        view = list(iter_views(msg))[0]
        assert view.hook is None

    def test_hook_passed_through(self):
        msg = Message(role=Role.USER, content=[TextContent(text="hi")])
        view = list(iter_views(msg, hook="llm_input"))[0]
        assert view.hook == "llm_input"

    def test_hook_in_to_dict(self):
        msg = Message(role=Role.USER, content=[TextContent(text="hi")])
        view = list(iter_views(msg, hook="tool_pre_invoke"))[0]
        d = view.to_dict()
        assert d["hook"] == "tool_pre_invoke"

    def test_hook_absent_from_to_dict_when_none(self):
        msg = Message(role=Role.USER, content=[TextContent(text="hi")])
        view = list(iter_views(msg))[0]
        d = view.to_dict()
        assert "hook" not in d


# ---------------------------------------------------------------------------
# Content edge cases
# ---------------------------------------------------------------------------


class TestContentEdgeCases:
    """Tests for content property edge cases (json fallbacks)."""

    def test_tool_call_non_serializable_args(self):
        """Tool call with non-JSON-serializable arguments falls back to str()."""
        tc = ToolCall(tool_call_id="tc1", name="test", arguments={"key": "val"})
        msg = Message(role=Role.ASSISTANT, content=[ToolCallContentPart(content=tc)])
        view = list(iter_views(msg))[0]
        assert view.content is not None

    def test_prompt_request_content(self):
        pr = PromptRequest(
            prompt_request_id="pr1",
            name="test",
            arguments={"key": "val"},
        )
        msg = Message(role=Role.USER, content=[PromptRequestContentPart(content=pr)])
        view = list(iter_views(msg))[0]
        assert '"key"' in view.content

    def test_prompt_result_content(self):
        pr = PromptResult(
            prompt_request_id="pr1",
            prompt_name="test",
            content="rendered text",
        )
        msg = Message(role=Role.TOOL, content=[PromptResultContentPart(content=pr)])
        view = list(iter_views(msg))[0]
        assert view.content == "rendered text"

    def test_resource_blob_size(self):
        """Resource with blob but no content still reports size_bytes."""
        res = Resource(
            resource_request_id="r1",
            uri="file:///a.bin",
            resource_type=ResourceType.FILE,
            blob=b"\x00\x01\x02",
        )
        msg = Message(role=Role.TOOL, content=[ResourceContentPart(content=res)])
        view = list(iter_views(msg))[0]
        assert view.content is None
        assert view.size_bytes == 3

    def test_resource_explicit_size(self):
        """Resource with explicit size_bytes uses that value."""
        res = Resource(
            resource_request_id="r1",
            uri="file:///a.txt",
            resource_type=ResourceType.FILE,
            content="hello",
            size_bytes=999,
        )
        msg = Message(role=Role.TOOL, content=[ResourceContentPart(content=res)])
        view = list(iter_views(msg))[0]
        assert view.size_bytes == 999

    def test_to_dict_no_content_with_blob_size(self):
        """to_dict includes size_bytes even when content is None (blob path)."""
        res = Resource(
            resource_request_id="r1",
            uri="file:///a.bin",
            resource_type=ResourceType.FILE,
            blob=b"\x00\x01",
        )
        msg = Message(role=Role.TOOL, content=[ResourceContentPart(content=res)])
        view = list(iter_views(msg))[0]
        d = view.to_dict()
        assert "content" not in d
        assert d["size_bytes"] == 2


# ---------------------------------------------------------------------------
# Properties edge cases
# ---------------------------------------------------------------------------


class TestPropertiesEdgeCases:
    """Tests for properties on various view kinds."""

    def test_resource_properties(self):
        res = Resource(
            resource_request_id="r1",
            uri="file:///a.txt",
            resource_type=ResourceType.FILE,
            content="hi",
            version="v1",
            annotations={"label": "pii"},
        )
        msg = Message(role=Role.TOOL, content=[ResourceContentPart(content=res)])
        view = list(iter_views(msg))[0]
        props = view.properties
        assert props["resource_type"] == "file"
        assert props["version"] == "v1"
        assert props["annotations"] == {"label": "pii"}

    def test_tool_call_properties(self):
        tc = ToolCall(
            tool_call_id="tc1",
            name="test",
            namespace="ns",
            arguments={},
        )
        msg = Message(role=Role.ASSISTANT, content=[ToolCallContentPart(content=tc)])
        view = list(iter_views(msg))[0]
        props = view.properties
        assert props["namespace"] == "ns"
        assert props["tool_id"] == "tc1"

    def test_tool_result_properties(self):
        tr = ToolResult(
            tool_call_id="tc1",
            tool_name="test",
            content="result",
            is_error=True,
        )
        msg = Message(role=Role.TOOL, content=[ToolResultContentPart(content=tr)])
        view = list(iter_views(msg))[0]
        props = view.properties
        assert props["is_error"] is True
        assert props["tool_name"] == "test"

    def test_prompt_request_properties(self):
        pr = PromptRequest(
            prompt_request_id="pr1",
            name="test",
            server_id="srv1",
        )
        msg = Message(role=Role.USER, content=[PromptRequestContentPart(content=pr)])
        view = list(iter_views(msg))[0]
        props = view.properties
        assert props["server_id"] == "srv1"


# ---------------------------------------------------------------------------
# Headers immutability
# ---------------------------------------------------------------------------


class TestHeadersImmutability:
    """Tests that headers returns a read-only mapping."""

    def test_headers_not_mutable(self):
        ext = Extensions(http=HttpExtension(headers={"Authorization": "Bearer tok"}))
        msg = Message(
            role=Role.USER,
            content=[TextContent(text="hi")],
        )
        view = list(iter_views(msg, extensions=ext))[0]
        with pytest.raises(TypeError):
            view.headers["new_key"] = "val"


# ---------------------------------------------------------------------------
# get_arg / has_arg
# ---------------------------------------------------------------------------


class TestArgHelpers:
    """Tests for get_arg and has_arg."""

    def test_get_arg_on_non_tool(self):
        msg = Message(role=Role.USER, content=[TextContent(text="hi")])
        view = list(iter_views(msg))[0]
        assert view.get_arg("anything") is None
        assert view.get_arg("anything", "fallback") == "fallback"
