# -*- coding: utf-8 -*-
"""Location: ./tests/unit/cpex/framework/extensions/test_extensions.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Teryl Taylor

Unit tests for extension models.
"""

# Standard

# Third-Party
import pytest

# First-Party
from cpex.framework.extensions.agent import AgentExtension, ConversationContext
from cpex.framework.extensions.completion import (
    CompletionExtension,
    StopReason,
    TokenUsage,
)
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

# ---------------------------------------------------------------------------
# RequestExtension
# ---------------------------------------------------------------------------


class TestRequestExtension:
    """Tests for RequestExtension."""

    def test_creation(self):
        ext = RequestExtension(
            environment="production",
            request_id="req-001",
            timestamp="2025-01-15T10:30:00Z",
        )
        assert ext.environment == "production"
        assert ext.request_id == "req-001"
        assert ext.timestamp == "2025-01-15T10:30:00Z"

    def test_defaults(self):
        ext = RequestExtension()
        assert ext.environment is None
        assert ext.request_id is None
        assert ext.timestamp is None
        assert ext.trace_id is None
        assert ext.span_id is None

    def test_frozen(self):
        ext = RequestExtension(environment="dev")
        with pytest.raises(Exception):
            ext.environment = "production"

    def test_model_copy(self):
        ext = RequestExtension(environment="dev")
        updated = ext.model_copy(update={"environment": "production"})
        assert ext.environment == "dev"
        assert updated.environment == "production"

    def test_tracing_fields(self):
        ext = RequestExtension(
            trace_id="trace-abc",
            span_id="span-123",
        )
        assert ext.trace_id == "trace-abc"
        assert ext.span_id == "span-123"


# ---------------------------------------------------------------------------
# AgentExtension
# ---------------------------------------------------------------------------


class TestConversationContext:
    """Tests for ConversationContext."""

    def test_creation(self):
        ctx = ConversationContext(
            summary="User asked about revenue.",
            topics=["revenue", "Q4"],
        )
        assert ctx.summary == "User asked about revenue."
        assert ctx.topics == ["revenue", "Q4"]

    def test_defaults(self):
        ctx = ConversationContext()
        assert ctx.history == []
        assert ctx.summary is None
        assert ctx.topics == []

    def test_frozen(self):
        ctx = ConversationContext(summary="test")
        with pytest.raises(Exception):
            ctx.summary = "modified"


class TestAgentExtension:
    """Tests for AgentExtension."""

    def test_creation(self):
        ext = AgentExtension(
            input="What is the weather?",
            session_id="sess-001",
            conversation_id="conv-042",
            turn=3,
            agent_id="weather-agent",
        )
        assert ext.input == "What is the weather?"
        assert ext.session_id == "sess-001"
        assert ext.turn == 3

    def test_defaults(self):
        ext = AgentExtension()
        assert ext.input is None
        assert ext.session_id is None
        assert ext.conversation_id is None
        assert ext.turn is None
        assert ext.agent_id is None
        assert ext.parent_agent_id is None
        assert ext.conversation is None

    def test_multi_agent_lineage(self):
        ext = AgentExtension(
            agent_id="sub-agent-01",
            parent_agent_id="main-agent",
        )
        assert ext.parent_agent_id == "main-agent"

    def test_with_conversation(self):
        conv = ConversationContext(summary="Prior context", topics=["weather"])
        ext = AgentExtension(conversation=conv)
        assert ext.conversation.summary == "Prior context"


# ---------------------------------------------------------------------------
# HttpExtension
# ---------------------------------------------------------------------------


class TestHttpExtension:
    """Tests for HttpExtension."""

    def test_creation(self):
        ext = HttpExtension(
            headers={"Content-Type": "application/json", "X-Request-ID": "req-001"},
        )
        assert ext.headers["Content-Type"] == "application/json"

    def test_defaults(self):
        ext = HttpExtension()
        assert ext.headers == {}

    def test_frozen(self):
        ext = HttpExtension(headers={"X-Test": "value"})
        with pytest.raises(Exception):
            ext.headers = {}

    def test_model_copy_add_header(self):
        ext = HttpExtension(headers={"X-Test": "value"})
        updated = ext.model_copy(
            update={"headers": {**ext.headers, "X-New": "added"}},
        )
        assert "X-New" in updated.headers
        assert "X-New" not in ext.headers


# ---------------------------------------------------------------------------
# SecurityExtension
# ---------------------------------------------------------------------------


class TestSubjectType:
    """Tests for SubjectType enum."""

    def test_values(self):
        assert SubjectType.USER.value == "user"
        assert SubjectType.AGENT.value == "agent"
        assert SubjectType.SERVICE.value == "service"
        assert SubjectType.SYSTEM.value == "system"

    def test_member_count(self):
        assert len(SubjectType) == 4


class TestSubjectExtension:
    """Tests for SubjectExtension."""

    def test_creation(self):
        subject = SubjectExtension(
            id="user-alice",
            type=SubjectType.USER,
            roles=frozenset({"admin", "developer"}),
            permissions=frozenset({"db.read", "tools.execute"}),
        )
        assert subject.id == "user-alice"
        assert subject.type == SubjectType.USER
        assert "admin" in subject.roles
        assert "db.read" in subject.permissions

    def test_defaults(self):
        subject = SubjectExtension(id="svc-1", type=SubjectType.SERVICE)
        assert subject.roles == frozenset()
        assert subject.permissions == frozenset()
        assert subject.teams == frozenset()
        assert subject.claims == {}

    def test_frozen_sets(self):
        subject = SubjectExtension(
            id="test",
            type=SubjectType.USER,
            roles=frozenset({"admin"}),
        )
        assert isinstance(subject.roles, frozenset)
        assert isinstance(subject.permissions, frozenset)
        assert isinstance(subject.teams, frozenset)


class TestObjectSecurityProfile:
    """Tests for ObjectSecurityProfile."""

    def test_creation(self):
        profile = ObjectSecurityProfile(
            managed_by="tool",
            permissions=["read:compensation"],
            trust_domain="internal",
            data_scope=["salary", "bonus"],
        )
        assert profile.managed_by == "tool"
        assert "read:compensation" in profile.permissions
        assert profile.trust_domain == "internal"

    def test_defaults(self):
        profile = ObjectSecurityProfile()
        assert profile.managed_by == "host"
        assert profile.permissions == []
        assert profile.trust_domain is None
        assert profile.data_scope == []


class TestRetentionPolicy:
    """Tests for RetentionPolicy."""

    def test_creation(self):
        ret = RetentionPolicy(
            max_age_seconds=3600,
            policy="session",
        )
        assert ret.max_age_seconds == 3600
        assert ret.policy == "session"

    def test_defaults(self):
        ret = RetentionPolicy()
        assert ret.max_age_seconds is None
        assert ret.policy == "persistent"
        assert ret.delete_after is None


class TestDataPolicy:
    """Tests for DataPolicy."""

    def test_creation(self):
        policy = DataPolicy(
            apply_labels=["PII", "financial"],
            denied_actions=["export", "forward"],
            retention=RetentionPolicy(policy="session", max_age_seconds=7200),
        )
        assert "PII" in policy.apply_labels
        assert "export" in policy.denied_actions
        assert policy.retention.policy == "session"

    def test_defaults(self):
        policy = DataPolicy()
        assert policy.apply_labels == []
        assert policy.allowed_actions is None
        assert policy.denied_actions == []
        assert policy.retention is None

    def test_unrestricted_vs_restricted(self):
        unrestricted = DataPolicy()
        restricted = DataPolicy(allowed_actions=["view", "summarize"])
        assert unrestricted.allowed_actions is None
        assert restricted.allowed_actions == ["view", "summarize"]


class TestSecurityExtension:
    """Tests for SecurityExtension."""

    def test_creation(self):
        ext = SecurityExtension(
            labels=frozenset({"PII", "CONFIDENTIAL"}),
            classification="confidential",
            subject=SubjectExtension(id="user-1", type=SubjectType.USER),
        )
        assert "PII" in ext.labels
        assert ext.classification == "confidential"
        assert ext.subject.id == "user-1"

    def test_defaults(self):
        ext = SecurityExtension()
        assert ext.labels == frozenset()
        assert ext.classification is None
        assert ext.subject is None
        assert ext.objects == {}
        assert ext.data == {}

    def test_monotonic_label_addition(self):
        ext = SecurityExtension(labels=frozenset({"PII"}))
        updated = ext.model_copy(
            update={"labels": ext.labels | frozenset({"CONFIDENTIAL"})},
        )
        assert "PII" in updated.labels
        assert "CONFIDENTIAL" in updated.labels
        assert ext.labels == frozenset({"PII"})

    def test_labels_are_frozenset(self):
        ext = SecurityExtension(labels=frozenset({"PII"}))
        assert isinstance(ext.labels, frozenset)

    def test_with_objects_and_data(self):
        ext = SecurityExtension(
            objects={
                "get_user": ObjectSecurityProfile(
                    managed_by="host",
                    permissions=["users.read"],
                ),
            },
            data={
                "get_user": DataPolicy(
                    apply_labels=["PII"],
                    denied_actions=["export"],
                ),
            },
        )
        assert ext.objects["get_user"].permissions == ["users.read"]
        assert ext.data["get_user"].apply_labels == ["PII"]


# ---------------------------------------------------------------------------
# MCPExtension
# ---------------------------------------------------------------------------


class TestToolMetadata:
    """Tests for ToolMetadata."""

    def test_creation(self):
        meta = ToolMetadata(
            name="get_user",
            description="Retrieve user by ID",
            input_schema={"type": "object", "properties": {"id": {"type": "string"}}},
        )
        assert meta.name == "get_user"
        assert meta.input_schema is not None

    def test_defaults(self):
        meta = ToolMetadata(name="test")
        assert meta.title is None
        assert meta.description is None
        assert meta.input_schema is None
        assert meta.output_schema is None
        assert meta.server_id is None
        assert meta.namespace is None
        assert meta.annotations == {}


class TestResourceMetadata:
    """Tests for ResourceMetadata."""

    def test_creation(self):
        meta = ResourceMetadata(
            uri="file:///data/report.csv",
            name="Quarterly Report",
            mime_type="text/csv",
        )
        assert meta.uri == "file:///data/report.csv"


class TestPromptMetadata:
    """Tests for PromptMetadata."""

    def test_creation(self):
        meta = PromptMetadata(
            name="summarize",
            arguments=[{"name": "text", "description": "Text to summarize", "required": True}],
        )
        assert meta.name == "summarize"
        assert meta.arguments[0]["name"] == "text"


class TestMCPExtension:
    """Tests for MCPExtension."""

    def test_with_tool(self):
        ext = MCPExtension(tool=ToolMetadata(name="get_user"))
        assert ext.tool.name == "get_user"
        assert ext.resource is None
        assert ext.prompt is None

    def test_with_resource(self):
        ext = MCPExtension(resource=ResourceMetadata(uri="file:///test"))
        assert ext.resource.uri == "file:///test"
        assert ext.tool is None

    def test_with_prompt(self):
        ext = MCPExtension(prompt=PromptMetadata(name="summarize"))
        assert ext.prompt.name == "summarize"

    def test_defaults(self):
        ext = MCPExtension()
        assert ext.tool is None
        assert ext.resource is None
        assert ext.prompt is None


# ---------------------------------------------------------------------------
# CompletionExtension
# ---------------------------------------------------------------------------


class TestStopReason:
    """Tests for StopReason enum."""

    def test_values(self):
        assert StopReason.END.value == "end"
        assert StopReason.MAX_TOKENS.value == "max_tokens"

    def test_member_count(self):
        assert len(StopReason) == 5


class TestTokenUsage:
    """Tests for TokenUsage."""

    def test_creation(self):
        usage = TokenUsage(input_tokens=100, output_tokens=50, total_tokens=150)
        assert usage.total_tokens == 150


class TestCompletionExtension:
    """Tests for CompletionExtension."""

    def test_creation(self):
        ext = CompletionExtension(
            stop_reason=StopReason.END,
            tokens=TokenUsage(input_tokens=100, output_tokens=50, total_tokens=150),
            model="gpt-4o",
            latency_ms=1200,
        )
        assert ext.stop_reason == StopReason.END
        assert ext.tokens.total_tokens == 150
        assert ext.model == "gpt-4o"
        assert ext.latency_ms == 1200

    def test_defaults(self):
        ext = CompletionExtension()
        assert ext.stop_reason is None
        assert ext.tokens is None
        assert ext.model is None
        assert ext.raw_format is None
        assert ext.created_at is None
        assert ext.latency_ms is None


# ---------------------------------------------------------------------------
# ProvenanceExtension
# ---------------------------------------------------------------------------


class TestProvenanceExtension:
    """Tests for ProvenanceExtension."""

    def test_creation(self):
        ext = ProvenanceExtension(
            source="agent:weather-bot",
            message_id="msg-001",
            parent_id="msg-000",
        )
        assert ext.source == "agent:weather-bot"
        assert ext.message_id == "msg-001"

    def test_defaults(self):
        ext = ProvenanceExtension()
        assert ext.source is None
        assert ext.message_id is None
        assert ext.parent_id is None


# ---------------------------------------------------------------------------
# LLMExtension
# ---------------------------------------------------------------------------


class TestLLMExtension:
    """Tests for LLMExtension."""

    def test_creation(self):
        ext = LLMExtension(
            model_id="claude-sonnet-4-20250514",
            provider="anthropic",
            capabilities=["vision", "tool_use"],
        )
        assert ext.provider == "anthropic"
        assert "tool_use" in ext.capabilities

    def test_defaults(self):
        ext = LLMExtension()
        assert ext.model_id is None
        assert ext.provider is None
        assert ext.capabilities == []


# ---------------------------------------------------------------------------
# FrameworkExtension
# ---------------------------------------------------------------------------


class TestFrameworkExtension:
    """Tests for FrameworkExtension."""

    def test_creation(self):
        ext = FrameworkExtension(
            framework="langgraph",
            framework_version="0.2.0",
            node_id="weather_node",
            graph_id="travel_planner",
        )
        assert ext.framework == "langgraph"
        assert ext.node_id == "weather_node"

    def test_defaults(self):
        ext = FrameworkExtension()
        assert ext.framework is None
        assert ext.framework_version is None
        assert ext.node_id is None
        assert ext.graph_id is None
        assert ext.metadata == {}


# ---------------------------------------------------------------------------
# Extensions Container
# ---------------------------------------------------------------------------


class TestExtensions:
    """Tests for the Extensions container."""

    def test_all_none_by_default(self):
        ext = Extensions()
        assert ext.request is None
        assert ext.agent is None
        assert ext.http is None
        assert ext.security is None
        assert ext.mcp is None
        assert ext.completion is None
        assert ext.provenance is None
        assert ext.llm is None
        assert ext.framework is None
        assert ext.custom is None

    def test_frozen(self):
        ext = Extensions()
        with pytest.raises(Exception):
            ext.request = RequestExtension()

    def test_model_copy(self):
        ext = Extensions(
            request=RequestExtension(environment="dev"),
        )
        updated = ext.model_copy(
            update={"request": RequestExtension(environment="production")},
        )
        assert ext.request.environment == "dev"
        assert updated.request.environment == "production"

    def test_full_construction(self):
        ext = Extensions(
            request=RequestExtension(environment="production", request_id="req-001"),
            agent=AgentExtension(input="Hello", session_id="sess-001"),
            http=HttpExtension(headers={"X-Test": "value"}),
            security=SecurityExtension(labels=frozenset({"PII"})),
            mcp=MCPExtension(tool=ToolMetadata(name="get_user")),
            completion=CompletionExtension(stop_reason=StopReason.END),
            provenance=ProvenanceExtension(source="user"),
            llm=LLMExtension(model_id="gpt-4o", provider="openai"),
            framework=FrameworkExtension(framework="langgraph"),
            custom={"debug": True},
        )
        assert ext.request.environment == "production"
        assert ext.agent.input == "Hello"
        assert ext.http.headers["X-Test"] == "value"
        assert "PII" in ext.security.labels
        assert ext.mcp.tool.name == "get_user"
        assert ext.completion.stop_reason == StopReason.END
        assert ext.provenance.source == "user"
        assert ext.llm.provider == "openai"
        assert ext.framework.framework == "langgraph"
        assert ext.custom["debug"] is True

    def test_custom_extension(self):
        ext = Extensions(custom={"key": "value", "nested": {"a": 1}})
        assert ext.custom["key"] == "value"
        assert ext.custom["nested"]["a"] == 1
