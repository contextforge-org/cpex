# -*- coding: utf-8 -*-
"""Location: ./tests/unit/cpex/framework/cmf/test_message.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Teryl Taylor

Unit tests for CMF message models.
"""

# Standard

# Third-Party
import pytest

# First-Party
from cpex.framework.cmf.message import (
    AudioContentPart,
    AudioSource,
    Channel,
    ContentPart,
    ContentType,
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

# ---------------------------------------------------------------------------
# Enum Tests
# ---------------------------------------------------------------------------


class TestRole:
    """Tests for the Role enum."""

    def test_values(self):
        assert Role.SYSTEM.value == "system"
        assert Role.DEVELOPER.value == "developer"
        assert Role.USER.value == "user"
        assert Role.ASSISTANT.value == "assistant"
        assert Role.TOOL.value == "tool"

    def test_from_string(self):
        assert Role("user") == Role.USER
        assert Role("assistant") == Role.ASSISTANT

    def test_invalid_value(self):
        with pytest.raises(ValueError):
            Role("invalid")

    def test_member_count(self):
        assert len(Role) == 5


class TestChannel:
    """Tests for the Channel enum."""

    def test_values(self):
        assert Channel.ANALYSIS.value == "analysis"
        assert Channel.COMMENTARY.value == "commentary"
        assert Channel.FINAL.value == "final"

    def test_from_string(self):
        assert Channel("final") == Channel.FINAL

    def test_member_count(self):
        assert len(Channel) == 3


class TestContentType:
    """Tests for the ContentType enum."""

    def test_all_types_present(self):
        expected = {
            "text",
            "thinking",
            "tool_call",
            "tool_result",
            "resource",
            "resource_ref",
            "prompt_request",
            "prompt_result",
            "image",
            "video",
            "audio",
            "document",
        }
        assert {ct.value for ct in ContentType} == expected

    def test_member_count(self):
        assert len(ContentType) == 12


class TestResourceType:
    """Tests for the ResourceType enum."""

    def test_all_types_present(self):
        expected = {"file", "blob", "uri", "database", "api", "memory", "artifact"}
        assert {rt.value for rt in ResourceType} == expected

    def test_member_count(self):
        assert len(ResourceType) == 7


# ---------------------------------------------------------------------------
# ContentPart Base Class Tests
# ---------------------------------------------------------------------------


class TestContentPart:
    """Tests for the ContentPart base class."""

    def test_subclass_relationship(self):
        part = TextContent(text="hello")
        assert isinstance(part, ContentPart)

    def test_wrapper_subclass_relationship(self):
        part = ToolCallContentPart(
            content=ToolCall(tool_call_id="tc1", name="test"),
        )
        assert isinstance(part, ContentPart)

    def test_frozen(self):
        part = TextContent(text="hello")
        with pytest.raises(Exception):
            part.text = "world"


# ---------------------------------------------------------------------------
# Domain Object Tests
# ---------------------------------------------------------------------------


class TestToolCallDomain:
    """Tests for the ToolCall domain object."""

    def test_creation(self):
        call = ToolCall(
            tool_call_id="tc_001",
            name="get_user",
            arguments={"user_id": "123"},
        )
        assert call.tool_call_id == "tc_001"
        assert call.name == "get_user"
        assert call.arguments == {"user_id": "123"}

    def test_default_arguments(self):
        call = ToolCall(tool_call_id="tc_002", name="list_users")
        assert call.arguments == {}

    def test_default_namespace(self):
        call = ToolCall(tool_call_id="tc_003", name="test")
        assert call.namespace is None

    def test_with_namespace(self):
        call = ToolCall(
            tool_call_id="tc_004",
            name="get_user",
            namespace="user-service",
        )
        assert call.namespace == "user-service"

    def test_frozen(self):
        call = ToolCall(tool_call_id="tc_005", name="test")
        with pytest.raises(Exception):
            call.name = "other"


class TestToolResultDomain:
    """Tests for the ToolResult domain object."""

    def test_creation(self):
        result = ToolResult(
            tool_call_id="tc_001",
            tool_name="get_user",
            content={"name": "Alice"},
        )
        assert result.tool_call_id == "tc_001"
        assert result.tool_name == "get_user"
        assert result.content == {"name": "Alice"}
        assert result.is_error is False

    def test_error_result(self):
        result = ToolResult(
            tool_call_id="tc_002",
            tool_name="fail_tool",
            content="Something went wrong",
            is_error=True,
        )
        assert result.is_error is True

    def test_default_content(self):
        result = ToolResult(tool_call_id="tc_003", tool_name="test")
        assert result.content is None
        assert result.is_error is False


class TestImageSourceDomain:
    """Tests for the ImageSource domain object."""

    def test_url_image(self):
        img = ImageSource(type="url", data="https://example.com/photo.jpg")
        assert img.type == "url"
        assert img.media_type is None

    def test_base64_image(self):
        img = ImageSource(
            type="base64",
            data="iVBORw0KGgo...",
            media_type="image/png",
        )
        assert img.type == "base64"
        assert img.media_type == "image/png"


class TestVideoSourceDomain:
    """Tests for the VideoSource domain object."""

    def test_creation(self):
        vid = VideoSource(type="url", data="https://example.com/clip.mp4")
        assert vid.duration_ms is None

    def test_with_duration(self):
        vid = VideoSource(
            type="url",
            data="https://example.com/clip.mp4",
            duration_ms=30000,
        )
        assert vid.duration_ms == 30000


class TestAudioSourceDomain:
    """Tests for the AudioSource domain object."""

    def test_creation(self):
        aud = AudioSource(type="url", data="https://example.com/track.mp3")
        assert aud.type == "url"


class TestDocumentSourceDomain:
    """Tests for the DocumentSource domain object."""

    def test_creation(self):
        doc = DocumentSource(
            type="base64",
            data="JVBERi0xLjQ...",
            media_type="application/pdf",
            title="Annual Report",
        )
        assert doc.title == "Annual Report"


class TestResourceDomain:
    """Tests for the Resource domain object."""

    def test_creation(self):
        res = Resource(
            resource_request_id="rr_001",
            uri="file:///data/report.csv",
            name="Q4 Report",
            resource_type=ResourceType.FILE,
            content="col1,col2\n1,2",
            mime_type="text/csv",
        )
        assert res.uri == "file:///data/report.csv"
        assert res.resource_type == ResourceType.FILE

    def test_minimal_creation(self):
        res = Resource(
            resource_request_id="rr_002",
            uri="db://users/42",
            resource_type=ResourceType.DATABASE,
        )
        assert res.name is None
        assert res.content is None
        assert res.blob is None

    def test_blob_resource(self):
        res = Resource(
            resource_request_id="rr_003",
            uri="blob://data",
            resource_type=ResourceType.BLOB,
            blob=b"\x00\x01\x02",
        )
        assert res.blob == b"\x00\x01\x02"


class TestResourceReferenceDomain:
    """Tests for the ResourceReference domain object."""

    def test_creation(self):
        ref = ResourceReference(
            resource_request_id="rr_004",
            uri="file:///path/to/file.txt",
            resource_type=ResourceType.FILE,
        )
        assert ref.uri == "file:///path/to/file.txt"

    def test_with_range(self):
        ref = ResourceReference(
            resource_request_id="rr_005",
            uri="file:///code.py",
            resource_type=ResourceType.FILE,
            range_start=10,
            range_end=50,
        )
        assert ref.range_start == 10
        assert ref.range_end == 50

    def test_with_selector(self):
        ref = ResourceReference(
            resource_request_id="rr_006",
            uri="api://data",
            resource_type=ResourceType.API,
            selector="$.results[0]",
        )
        assert ref.selector == "$.results[0]"


class TestPromptRequestDomain:
    """Tests for the PromptRequest domain object."""

    def test_creation(self):
        req = PromptRequest(
            prompt_request_id="pr_001",
            name="summarize",
            arguments={"text": "Long document..."},
        )
        assert req.name == "summarize"
        assert req.arguments == {"text": "Long document..."}

    def test_defaults(self):
        req = PromptRequest(prompt_request_id="pr_002", name="test")
        assert req.arguments == {}
        assert req.server_id is None


class TestPromptResultDomain:
    """Tests for the PromptResult domain object."""

    def test_creation(self):
        result = PromptResult(
            prompt_request_id="pr_001",
            prompt_name="summarize",
            content="This document discusses...",
        )
        assert result.prompt_name == "summarize"
        assert result.is_error is False

    def test_error_result(self):
        result = PromptResult(
            prompt_request_id="pr_002",
            prompt_name="fail_prompt",
            is_error=True,
            error_message="Template not found",
        )
        assert result.is_error is True
        assert result.error_message == "Template not found"

    def test_defaults(self):
        result = PromptResult(prompt_request_id="pr_003", prompt_name="test")
        assert result.messages == []
        assert result.content is None


# ---------------------------------------------------------------------------
# ContentPart Wrapper Tests
# ---------------------------------------------------------------------------


class TestTextContent:
    """Tests for TextContent."""

    def test_creation(self):
        part = TextContent(text="Hello, world!")
        assert part.content_type == ContentType.TEXT
        assert part.text == "Hello, world!"

    def test_frozen(self):
        part = TextContent(text="original")
        with pytest.raises(Exception):
            part.text = "modified"

    def test_model_copy(self):
        part = TextContent(text="original")
        modified = part.model_copy(update={"text": "updated"})
        assert part.text == "original"
        assert modified.text == "updated"


class TestThinkingContent:
    """Tests for ThinkingContent."""

    def test_creation(self):
        part = ThinkingContent(text="Let me analyze this...")
        assert part.content_type == ContentType.THINKING
        assert part.text == "Let me analyze this..."


class TestToolCallContentPart:
    """Tests for ToolCallContentPart wrapper."""

    def test_creation(self):
        call = ToolCall(tool_call_id="tc_001", name="get_user", arguments={"user_id": "123"})
        part = ToolCallContentPart(content=call)
        assert part.content_type == ContentType.TOOL_CALL
        assert part.content.name == "get_user"
        assert part.content.arguments == {"user_id": "123"}

    def test_frozen(self):
        part = ToolCallContentPart(content=ToolCall(tool_call_id="tc1", name="test"))
        with pytest.raises(Exception):
            part.content = ToolCall(tool_call_id="tc2", name="other")


class TestToolResultContentPart:
    """Tests for ToolResultContentPart wrapper."""

    def test_creation(self):
        result = ToolResult(tool_call_id="tc_001", tool_name="get_user", content={"name": "Alice"})
        part = ToolResultContentPart(content=result)
        assert part.content_type == ContentType.TOOL_RESULT
        assert part.content.tool_name == "get_user"
        assert part.content.is_error is False


class TestResourceContentPart:
    """Tests for ResourceContentPart wrapper."""

    def test_creation(self):
        res = Resource(
            resource_request_id="rr_001",
            uri="file:///data/report.csv",
            resource_type=ResourceType.FILE,
        )
        part = ResourceContentPart(content=res)
        assert part.content_type == ContentType.RESOURCE
        assert part.content.uri == "file:///data/report.csv"


class TestImageContentPart:
    """Tests for ImageContentPart wrapper."""

    def test_creation(self):
        img = ImageSource(type="url", data="https://example.com/photo.jpg")
        part = ImageContentPart(content=img)
        assert part.content_type == ContentType.IMAGE
        assert part.content.type == "url"


class TestDocumentContentPart:
    """Tests for DocumentContentPart wrapper."""

    def test_creation(self):
        doc = DocumentSource(
            type="base64",
            data="JVBERi0xLjQ...",
            media_type="application/pdf",
            title="Annual Report",
        )
        part = DocumentContentPart(content=doc)
        assert part.content_type == ContentType.DOCUMENT
        assert part.content.title == "Annual Report"


# ---------------------------------------------------------------------------
# Message Tests
# ---------------------------------------------------------------------------


class TestMessage:
    """Tests for the Message model."""

    def test_simple_message(self):
        msg = Message(
            role=Role.USER,
            content=[TextContent(text="Hello")],
        )
        assert msg.role == Role.USER
        assert msg.schema_version == "2.0"
        assert msg.channel is None
        assert len(msg.content) == 1

    def test_empty_content(self):
        msg = Message(role=Role.SYSTEM)
        assert msg.content == []

    def test_multi_part_message(self):
        msg = Message(
            role=Role.ASSISTANT,
            content=[
                ThinkingContent(text="Reasoning..."),
                TextContent(text="Here is the answer."),
                ToolCallContentPart(
                    content=ToolCall(tool_call_id="tc_001", name="search", arguments={"q": "test"}),
                ),
            ],
        )
        assert len(msg.content) == 3
        assert msg.content[0].content_type == ContentType.THINKING
        assert msg.content[1].content_type == ContentType.TEXT
        assert msg.content[2].content_type == ContentType.TOOL_CALL

    def test_with_channel(self):
        msg = Message(
            role=Role.ASSISTANT,
            content=[TextContent(text="Final answer.")],
            channel=Channel.FINAL,
        )
        assert msg.channel == Channel.FINAL

    def test_frozen(self):
        msg = Message(role=Role.USER, content=[TextContent(text="Hi")])
        with pytest.raises(Exception):
            msg.role = Role.ASSISTANT

    def test_model_copy(self):
        msg = Message(role=Role.USER, content=[TextContent(text="Hi")])
        updated = msg.model_copy(update={"channel": Channel.FINAL})
        assert msg.channel is None
        assert updated.channel == Channel.FINAL
        assert updated.role == Role.USER

    def test_deserialization_from_dict(self):
        msg = Message.model_validate(
            {
                "role": "user",
                "content": [
                    {"content_type": "text", "text": "Hello"},
                    {"content_type": "tool_call", "content": {"tool_call_id": "tc1", "name": "foo", "arguments": {}}},
                ],
            }
        )
        assert msg.role == Role.USER
        assert len(msg.content) == 2
        assert isinstance(msg.content[0], TextContent)
        assert isinstance(msg.content[1], ToolCallContentPart)

    def test_deserialization_all_content_types(self):
        msg = Message.model_validate(
            {
                "role": "assistant",
                "content": [
                    {"content_type": "text", "text": "hi"},
                    {"content_type": "thinking", "text": "hmm"},
                    {"content_type": "tool_call", "content": {"tool_call_id": "t1", "name": "x", "arguments": {}}},
                    {"content_type": "tool_result", "content": {"tool_call_id": "t1", "tool_name": "x"}},
                    {
                        "content_type": "resource",
                        "content": {"resource_request_id": "r1", "uri": "file:///a", "resource_type": "file"},
                    },
                    {
                        "content_type": "resource_ref",
                        "content": {"resource_request_id": "r2", "uri": "db://b", "resource_type": "database"},
                    },
                    {"content_type": "prompt_request", "content": {"prompt_request_id": "p1", "name": "s"}},
                    {"content_type": "prompt_result", "content": {"prompt_request_id": "p1", "prompt_name": "s"}},
                    {"content_type": "image", "content": {"type": "url", "data": "http://img"}},
                    {"content_type": "video", "content": {"type": "url", "data": "http://vid"}},
                    {"content_type": "audio", "content": {"type": "url", "data": "http://aud"}},
                    {"content_type": "document", "content": {"type": "url", "data": "http://doc"}},
                ],
            }
        )
        assert len(msg.content) == 12
        expected_types = [
            TextContent,
            ThinkingContent,
            ToolCallContentPart,
            ToolResultContentPart,
            ResourceContentPart,
            ResourceRefContentPart,
            PromptRequestContentPart,
            PromptResultContentPart,
            ImageContentPart,
            VideoContentPart,
            AudioContentPart,
            DocumentContentPart,
        ]
        for part, expected in zip(msg.content, expected_types):
            assert isinstance(part, expected), f"Expected {expected.__name__}, got {type(part).__name__}"

    def test_serialization_roundtrip(self):
        msg = Message(
            role=Role.ASSISTANT,
            content=[
                TextContent(text="hello"),
                ToolCallContentPart(
                    content=ToolCall(tool_call_id="tc1", name="test", arguments={"a": 1}),
                ),
            ],
        )
        data = msg.model_dump()
        restored = Message.model_validate(data)
        assert restored.role == msg.role
        assert len(restored.content) == 2
        assert restored.content[0].text == "hello"
        assert restored.content[1].content.name == "test"

    def test_iter_views(self):
        msg = Message(
            role=Role.ASSISTANT,
            content=[
                TextContent(text="hello"),
                ToolCallContentPart(
                    content=ToolCall(tool_call_id="tc1", name="test", arguments={}),
                ),
            ],
        )
        views = list(msg.iter_views())
        assert len(views) == 2


# ---------------------------------------------------------------------------
# Validation Tests
# ---------------------------------------------------------------------------


class TestResourceValidation:
    """Tests for Resource model validators."""

    def test_content_only(self):
        res = Resource(
            resource_request_id="r1",
            uri="file:///a.txt",
            resource_type=ResourceType.FILE,
            content="hello",
        )
        assert res.content == "hello"
        assert res.blob is None

    def test_blob_only(self):
        res = Resource(
            resource_request_id="r1",
            uri="file:///a.bin",
            resource_type=ResourceType.FILE,
            blob=b"\x00\x01",
        )
        assert res.blob == b"\x00\x01"
        assert res.content is None

    def test_neither_content_nor_blob(self):
        res = Resource(
            resource_request_id="r1",
            uri="file:///a.txt",
            resource_type=ResourceType.FILE,
        )
        assert res.content is None
        assert res.blob is None

    def test_content_and_blob_raises(self):
        with pytest.raises(ValueError, match="cannot have both"):
            Resource(
                resource_request_id="r1",
                uri="file:///a.txt",
                resource_type=ResourceType.FILE,
                content="hello",
                blob=b"\x00",
            )


class TestResourceReferenceValidation:
    """Tests for ResourceReference range validators."""

    def test_valid_range(self):
        ref = ResourceReference(
            resource_request_id="r1",
            uri="file:///a.txt",
            resource_type=ResourceType.FILE,
            range_start=10,
            range_end=20,
        )
        assert ref.range_start == 10
        assert ref.range_end == 20

    def test_equal_range(self):
        ref = ResourceReference(
            resource_request_id="r1",
            uri="file:///a.txt",
            resource_type=ResourceType.FILE,
            range_start=5,
            range_end=5,
        )
        assert ref.range_start == ref.range_end

    def test_invalid_range_raises(self):
        with pytest.raises(ValueError, match="range_end.*must be >= range_start"):
            ResourceReference(
                resource_request_id="r1",
                uri="file:///a.txt",
                resource_type=ResourceType.FILE,
                range_start=20,
                range_end=10,
            )

    def test_start_only(self):
        ref = ResourceReference(
            resource_request_id="r1",
            uri="file:///a.txt",
            resource_type=ResourceType.FILE,
            range_start=5,
        )
        assert ref.range_start == 5
        assert ref.range_end is None

    def test_end_only(self):
        ref = ResourceReference(
            resource_request_id="r1",
            uri="file:///a.txt",
            resource_type=ResourceType.FILE,
            range_end=10,
        )
        assert ref.range_start is None
        assert ref.range_end == 10


class TestDiscriminator:
    """Tests for content_type discriminator function."""

    def test_missing_content_type_in_dict_raises(self):
        with pytest.raises(Exception):
            Message(role=Role.USER, content=[{"text": "hello"}])

    def test_invalid_content_type_in_dict_raises(self):
        with pytest.raises(Exception):
            Message(role=Role.USER, content=[{"content_type": "bogus", "text": "hello"}])


class TestMediaSourceLiteral:
    """Tests that media source type fields enforce Literal['url', 'base64']."""

    def test_image_source_valid_types(self):
        assert ImageSource(type="url", data="https://x.com/a.jpg").type == "url"
        assert ImageSource(type="base64", data="abc").type == "base64"

    def test_image_source_invalid_type(self):
        with pytest.raises(Exception):
            ImageSource(type="ftp", data="abc")

    def test_video_source_invalid_type(self):
        with pytest.raises(Exception):
            VideoSource(type="file", data="abc")

    def test_audio_source_invalid_type(self):
        with pytest.raises(Exception):
            AudioSource(type="stream", data="abc")

    def test_document_source_invalid_type(self):
        with pytest.raises(Exception):
            DocumentSource(type="unknown", data="abc")
