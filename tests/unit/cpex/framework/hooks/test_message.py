# -*- coding: utf-8 -*-
"""Location: ./tests/unit/cpex/framework/hooks/test_message.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Teryl Taylor

Unit tests for message evaluation hook definitions.
"""

# Third-Party
import pytest

# First-Party
from cpex.framework.cmf.message import Message, Role, TextContent
from cpex.framework.hooks.message import (
    MessageHookType,
    MessagePayload,
    MessageResult,
)
from cpex.framework.hooks.registry import get_hook_registry
from cpex.framework.models import PluginPayload, PluginResult

# ---------------------------------------------------------------------------
# MessageHookType Tests
# ---------------------------------------------------------------------------


class TestMessageHookType:
    """Tests for the MessageHookType enum."""

    def test_evaluate_value(self):
        assert MessageHookType.EVALUATE.value == "evaluate"

    def test_from_string(self):
        assert MessageHookType("evaluate") == MessageHookType.EVALUATE

    def test_invalid_value(self):
        with pytest.raises(ValueError):
            MessageHookType("invalid")

    def test_member_count(self):
        assert len(MessageHookType) == 9

    def test_is_str_enum(self):
        assert isinstance(MessageHookType.EVALUATE, str)
        assert MessageHookType.EVALUATE == "evaluate"


# ---------------------------------------------------------------------------
# MessagePayload Tests
# ---------------------------------------------------------------------------


class TestMessagePayload:
    """Tests for the MessagePayload model."""

    def test_subclass_of_plugin_payload(self):
        assert issubclass(MessagePayload, PluginPayload)

    def test_creation(self):
        msg = Message(
            role=Role.USER,
            content=[TextContent(text="Hello")],
        )
        payload = MessagePayload(message=msg)
        assert payload.message is msg
        assert payload.message.role == Role.USER
        assert payload.message.content[0].text == "Hello"

    def test_message_field_required(self):
        with pytest.raises(Exception):
            MessagePayload()

    def test_with_multi_part_message(self):
        msg = Message(
            role=Role.ASSISTANT,
            content=[
                TextContent(text="Part one"),
                TextContent(text="Part two"),
            ],
        )
        payload = MessagePayload(message=msg)
        assert len(payload.message.content) == 2

    def test_iter_views_through_payload(self):
        msg = Message(
            role=Role.USER,
            content=[
                TextContent(text="First"),
                TextContent(text="Second"),
            ],
        )
        payload = MessagePayload(message=msg)
        views = list(payload.message.iter_views())
        assert len(views) == 2


# ---------------------------------------------------------------------------
# MessageResult Tests
# ---------------------------------------------------------------------------


class TestMessageResult:
    """Tests for the MessageResult type alias."""

    def test_is_plugin_result_subclass(self):
        assert issubclass(MessageResult, PluginResult)


# ---------------------------------------------------------------------------
# Hook Registration Tests
# ---------------------------------------------------------------------------


class TestMessageHookRegistration:
    """Tests for message hook registration in the global registry."""

    def test_evaluate_hook_registered(self):
        registry = get_hook_registry()
        assert registry.is_registered(MessageHookType.EVALUATE)

    def test_payload_type(self):
        registry = get_hook_registry()
        assert registry.get_payload_type(MessageHookType.EVALUATE) is MessagePayload

    def test_result_type(self):
        registry = get_hook_registry()
        assert registry.get_result_type(MessageHookType.EVALUATE) is MessageResult

    def test_idempotent_registration(self):
        """Re-importing or re-calling _register should not raise."""
        # First-Party
        from cpex.framework.hooks.message import _register_message_hooks

        _register_message_hooks()
        registry = get_hook_registry()
        assert registry.is_registered(MessageHookType.EVALUATE)
