# Location: ./bindings/python/tests/test_result.py
# Copyright 2025
# SPDX-License-Identifier: Apache-2.0
# Authors: Ted Habeck
#
# Tests for PipelineResult field access and repr.

import re

import pytest
from cpex import PipelineResult, PolicyEngine

from _support import text_message, tool_call, tool_route


# ---------------------------------------------------------------------------
# Happy path field access
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_all_fields_accessible(engine: PolicyEngine):
    """All PipelineResult fields are accessible after a real invoke."""
    result = await engine.invoke_hook(
        "cmf.tool_pre_invoke",
        tool_call("lookup_person", {"name": "Alice"}),
        tool_route("lookup_person"),
    )
    assert isinstance(result, PipelineResult)

    # continue_processing
    assert isinstance(result.continue_processing, bool)
    # violation: None for an allowed result
    assert result.violation is None
    # errors: list (may be empty)
    assert isinstance(result.errors, list)
    # metadata: may be None
    assert result.metadata is None or isinstance(result.metadata, dict)
    # context_table: always a dict
    assert isinstance(result.context_table, dict)


# ---------------------------------------------------------------------------
# Deny result: violation dict shape
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_deny_result_violation_fields(pii_deny_config_path: str):
    """A denied result exposes violation dict with expected keys."""
    eng = PolicyEngine(pii_deny_config_path)
    await eng.initialize()

    result = await eng.invoke_hook(
        "cmf.tool_pre_invoke",
        tool_call("lookup_person", {"ssn": "987-65-4321"}, call_id="tc_x"),
        tool_route("lookup_person"),
    )

    assert result.continue_processing is False
    assert result.violation is not None
    assert isinstance(result.violation, dict)
    # Standard violation keys
    assert "reason" in result.violation
    assert "code" in result.violation

    await eng.shutdown()


# ---------------------------------------------------------------------------
# repr safety: no pointer leakage
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_repr_no_pointers(engine: PolicyEngine):
    """__repr__ must not contain hex pointer substrings."""
    result = await engine.invoke_hook("cmf.tool_pre_invoke", text_message("hi"))
    r = repr(result)
    # Hex-pointer pattern: 0x followed by hex digits
    assert not re.search(r"0x[0-9a-fA-F]+", r), f"repr contains pointer: {r!r}"
