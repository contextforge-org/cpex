# Location: ./tests/unit/cpex/framework/test_pyo3_payload.py
# Copyright 2025
# SPDX-License-Identifier: Apache-2.0
# Authors: Teryl Taylor
#
# Unit tests for PyO3 MessagePayload bindings.

import pytest

# Skip all tests if native backend not available
pytest.importorskip("cpex_native")

from cpex_native import MessagePayload


class TestMessagePayload:
    """Test PyO3 MessagePayload wrapper."""

    def test_create_text_message(self):
        """Test creating a simple text message."""
        message_dict = {
            "schema_version": "1.0",
            "role": "user",
            "content": [{"content_type": "text", "text": "Hello, world!"}],
            "channel": None,
        }

        payload = MessagePayload(message_dict)
        assert payload is not None

    def test_to_dict_roundtrip(self):
        """Test converting message to dict and back."""
        original = {
            "schema_version": "1.0",
            "role": "user",
            "content": [{"content_type": "text", "text": "Test message"}],
        }

        payload = MessagePayload(original)
        result = payload.to_dict()

        assert result["schema_version"] == "1.0"
        assert result["role"] == "user"
        assert len(result["content"]) == 1
        assert result["content"][0]["content_type"] == "text"
        assert result["content"][0]["text"] == "Test message"

    def test_model_copy(self):
        """Test copy-on-write semantics."""
        message_dict = {
            "schema_version": "1.0",
            "role": "user",
            "content": [{"content_type": "text", "text": "Original"}],
        }

        original = MessagePayload(message_dict)
        copied = original.model_copy()

        # Both should have same content
        assert original.get_text_content() == copied.get_text_content()

        # But be different objects
        assert original is not copied

    def test_get_text_content(self):
        """Test extracting text content."""
        message_dict = {
            "schema_version": "1.0",
            "role": "user",
            "content": [
                {"content_type": "text", "text": "Hello "},
                {"content_type": "text", "text": "world!"},
            ],
        }

        payload = MessagePayload(message_dict)
        text = payload.get_text_content()

        assert text == "Hello world!"

    def test_get_text_content_empty(self):
        """Test extracting text from message with no text parts."""
        message_dict = {
            "schema_version": "1.0",
            "role": "assistant",
            "content": [
                {
                    "content_type": "tool_call",
                    "content": {
                        "tool_call_id": "call_123",
                        "name": "get_weather",
                        "arguments": {"city": "SF"},
                    },
                }
            ],
        }

        payload = MessagePayload(message_dict)
        text = payload.get_text_content()

        assert text == ""

    def test_is_tool_call_true(self):
        """Test detecting tool call messages."""
        message_dict = {
            "schema_version": "1.0",
            "role": "assistant",
            "content": [
                {
                    "content_type": "tool_call",
                    "content": {
                        "tool_call_id": "call_123",
                        "name": "get_weather",
                        "arguments": {"city": "San Francisco"},
                    },
                }
            ],
        }

        payload = MessagePayload(message_dict)
        assert payload.is_tool_call() is True

    def test_is_tool_call_false(self):
        """Test detecting non-tool-call messages."""
        message_dict = {
            "schema_version": "1.0",
            "role": "user",
            "content": [{"content_type": "text", "text": "Hello"}],
        }

        payload = MessagePayload(message_dict)
        assert payload.is_tool_call() is False

    def test_get_role(self):
        """Test getting message role."""
        message_dict = {
            "schema_version": "1.0",
            "role": "assistant",
            "content": [{"content_type": "text", "text": "Response"}],
        }

        payload = MessagePayload(message_dict)
        assert payload.role == "assistant"

    def test_get_schema_version(self):
        """Test getting schema version."""
        message_dict = {
            "schema_version": "1.0",
            "role": "user",
            "content": [{"content_type": "text", "text": "Test"}],
        }

        payload = MessagePayload(message_dict)
        assert payload.schema_version == "1.0"

    def test_get_channel_none(self):
        """Test getting channel when None."""
        message_dict = {
            "schema_version": "1.0",
            "role": "user",
            "content": [{"content_type": "text", "text": "Test"}],
        }

        payload = MessagePayload(message_dict)
        assert payload.channel is None

    def test_get_channel_some(self):
        """Test getting channel when set."""
        message_dict = {
            "schema_version": "1.0",
            "role": "user",
            "content": [{"content_type": "text", "text": "Test"}],
            "channel": "analysis",
        }

        payload = MessagePayload(message_dict)
        assert payload.channel == "analysis"

    def test_multimodal_content(self):
        """Test message with multiple content types."""
        message_dict = {
            "schema_version": "1.0",
            "role": "user",
            "content": [
                {"content_type": "text", "text": "Look at this image: "},
                {
                    "content_type": "image",
                    "content": {
                        "type": "url",
                        "data": "https://example.com/image.jpg",
                        "media_type": "image/jpeg",
                    },
                },
            ],
        }

        payload = MessagePayload(message_dict)
        result = payload.to_dict()

        assert len(result["content"]) == 2
        assert result["content"][0]["content_type"] == "text"
        assert result["content"][1]["content_type"] == "image"

    def test_tool_result_content(self):
        """Test message with tool result."""
        message_dict = {
            "schema_version": "1.0",
            "role": "tool",
            "content": [
                {
                    "content_type": "tool_result",
                    "content": {
                        "tool_call_id": "call_123",
                        "tool_name": "get_weather",
                        "content": {"temperature": 72, "condition": "sunny"},
                        "is_error": False,
                    },
                }
            ],
        }

        payload = MessagePayload(message_dict)
        result = payload.to_dict()

        assert result["content"][0]["content_type"] == "tool_result"
        assert result["content"][0]["content"]["tool_call_id"] == "call_123"
        assert result["content"][0]["content"]["is_error"] is False

    def test_thinking_content(self):
        """Test message with thinking/reasoning content."""
        message_dict = {
            "schema_version": "1.0",
            "role": "assistant",
            "content": [
                {
                    "content_type": "thinking",
                    "text": "Let me think about this step by step...",
                }
            ],
            "channel": "analysis",
        }

        payload = MessagePayload(message_dict)
        result = payload.to_dict()

        assert result["content"][0]["content_type"] == "thinking"
        assert result["channel"] == "analysis"

    def test_invalid_message_structure(self):
        """Test error handling for invalid message structure."""
        invalid_dict = {
            "schema_version": "1.0",
            # Missing required 'role' field
            "content": [{"content_type": "text", "text": "Test"}],
        }

        with pytest.raises(ValueError, match="Failed to deserialize message"):
            MessagePayload(invalid_dict)

    def test_invalid_content_part(self):
        """Test error handling for invalid content part."""
        invalid_dict = {
            "schema_version": "1.0",
            "role": "user",
            "content": [
                {
                    # Missing 'content_type' discriminator
                    "text": "Test"
                }
            ],
        }

        with pytest.raises(ValueError, match="Failed to deserialize message"):
            MessagePayload(invalid_dict)

# Made with Bob
