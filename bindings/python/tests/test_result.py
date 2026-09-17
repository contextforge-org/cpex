# Location: ./bindings/python/tests/test_result.py
# Copyright 2025
# SPDX-License-Identifier: Apache-2.0
# Authors: Ted Habeck
#
# Tests for PyPipelineResult field access and repr (U5).

import re

import pytest
from cpex import PluginManager, PipelineResult


# ---------------------------------------------------------------------------
# Happy path field access
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_all_fields_accessible(manager: PluginManager):
    """All seven PipelineResult fields are accessible after a real invoke."""
    payload = {
        "message": {
            "role": "user",
            "content": [{"content_type": "text", "text": "Hello"}],
        }
    }
    result = await manager.invoke_hook("cmf.tool_pre_invoke", payload)
    assert isinstance(result, PipelineResult)

    # continue_processing
    assert isinstance(result.continue_processing, bool)
    # violation — None for an allowed result
    assert result.violation is None
    # errors — list (may be empty)
    assert isinstance(result.errors, list)
    # metadata — may be None
    assert result.metadata is None or isinstance(result.metadata, dict)
    # context_table — always a dict
    assert isinstance(result.context_table, dict)


# ---------------------------------------------------------------------------
# Deny result — violation dict shape
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_deny_result_violation_fields(pii_deny_config_path: str):
    """A denied result exposes violation dict with expected keys."""
    mgr = PluginManager(pii_deny_config_path)
    await mgr.initialize()

    payload = {
        "message": {
            "role": "assistant",
            "content": [
                {
                    "content_type": "tool_call",
                    "content": {
                        "tool_call_id": "tc_x",
                        "name": "submit_form",
                        "arguments": {"ssn": "987-65-4321"},
                    },
                }
            ],
        }
    }
    result = await mgr.invoke_hook("cmf.tool_pre_invoke", payload)

    assert result.continue_processing is False
    assert result.violation is not None
    assert isinstance(result.violation, dict)
    # Standard violation keys
    assert "reason" in result.violation

    await mgr.shutdown()


# ---------------------------------------------------------------------------
# repr safety — no pointer leakage (R3)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_repr_no_pointers(manager: PluginManager):
    """__repr__ must not contain hex pointer substrings (R3)."""
    payload = {
        "message": {
            "role": "user",
            "content": [{"content_type": "text", "text": "hi"}],
        }
    }
    result = await manager.invoke_hook("cmf.tool_pre_invoke", payload)
    r = repr(result)
    # Hex-pointer pattern: 0x followed by hex digits
    assert not re.search(r"0x[0-9a-fA-F]+", r), f"repr contains pointer: {r!r}"
