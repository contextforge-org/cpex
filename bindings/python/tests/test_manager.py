# Location: ./bindings/python/tests/test_manager.py
# Copyright 2025
# SPDX-License-Identifier: Apache-2.0
# Authors: Ted Habeck
#
# Integration tests for the PolicyEngine lifecycle.

import pytest
from cpex import PipelineResult, PluginManager, PolicyEngine

from _support import tool_call, tool_route


# ---------------------------------------------------------------------------
# Import surface
# ---------------------------------------------------------------------------


def test_cpex_lib_importable():
    """cpex._lib must be importable and resolve to the native extension."""
    import cpex
    import cpex._lib  # noqa: F401

    assert hasattr(cpex._lib, "PolicyEngine"), "cpex._lib must expose PolicyEngine"
    assert hasattr(cpex._lib, "PipelineResult"), "cpex._lib must expose PipelineResult"
    assert set(cpex.__all__) == {"PolicyEngine", "PluginManager", "PipelineResult"}


def test_plugin_manager_is_an_alias_of_policy_engine():
    """The pre-0.3 name and the new name are the same class."""
    assert PluginManager is PolicyEngine
    assert PolicyEngine.__name__ == "PolicyEngine"


@pytest.mark.asyncio
@pytest.mark.parametrize("cls", [PolicyEngine, PluginManager], ids=["PolicyEngine", "PluginManager"])
async def test_both_names_load_and_run_a_migrated_config(cls, pii_deny_config_path: str):
    """Either name loads a PPE-format config and enforces it."""
    eng = cls(pii_deny_config_path)
    assert isinstance(eng, PolicyEngine)
    await eng.initialize()

    denied = await eng.invoke_hook(
        "cmf.tool_pre_invoke",
        tool_call("lookup_person", {"ssn": "123-45-6789"}),
        tool_route("lookup_person"),
    )
    allowed = await eng.invoke_hook(
        "cmf.tool_pre_invoke",
        tool_call("lookup_person", {"name": "Alice"}),
        tool_route("lookup_person"),
    )
    await eng.shutdown()

    assert denied.continue_processing is False
    assert denied.violation["code"] == "pii.ssn_detected"
    assert allowed.continue_processing is True


# ---------------------------------------------------------------------------
# Happy path lifecycle
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_lifecycle_construct_initialize_shutdown(pii_deny_config_path: str):
    """Construct, initialize and shut down without error."""
    eng = PolicyEngine(pii_deny_config_path)
    await eng.initialize()
    await eng.shutdown()


@pytest.mark.asyncio
async def test_invoke_returns_pipeline_result(engine: PolicyEngine):
    """A non-triggering invoke returns a PipelineResult with continue_processing=True."""
    result = await engine.invoke_hook(
        "cmf.tool_pre_invoke",
        tool_call("lookup_person", {"name": "Alice"}),
        tool_route("lookup_person"),
    )
    assert isinstance(result, PipelineResult)
    assert result.continue_processing is True


# ---------------------------------------------------------------------------
# Deny
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pii_deny_returns_violation(engine: PolicyEngine):
    """A tool call with an SSN argument halts the pipeline with a violation."""
    result = await engine.invoke_hook(
        "cmf.tool_pre_invoke",
        tool_call("lookup_person", {"ssn": "123-45-6789"}),
        tool_route("lookup_person"),
    )

    assert result.continue_processing is False, "the SSN check should halt the pipeline"
    assert result.violation is not None, "violation dict must be populated"
    assert result.violation["code"] == "pii.ssn_detected"
    assert result.violation["reason"] == "ssn found in tool arguments"


@pytest.mark.asyncio
async def test_route_is_selected_by_meta(engine: PolicyEngine):
    """Under policy dispatch the route comes from meta, not the payload.

    A request with no meta cannot be matched to a route, so it is refused
    rather than let through unchecked. A request naming a tool with no
    route has no policy to apply and is allowed.
    """
    payload = tool_call("lookup_person", {"ssn": "123-45-6789"})
    unidentified = await engine.invoke_hook("cmf.tool_pre_invoke", payload)
    other_tool = await engine.invoke_hook(
        "cmf.tool_pre_invoke", payload, tool_route("other_tool")
    )
    assert unidentified.continue_processing is False
    assert unidentified.violation["code"] == "unidentified_request"
    assert other_tool.continue_processing is True


@pytest.mark.asyncio
async def test_generic_hook_does_not_raise(engine: PolicyEngine):
    """A non-CMF hook routes through GenericPayload and returns a result."""
    result = await engine.invoke_hook(
        "custom.arbitrary.hook", {"data": "value"}, tool_route("lookup_person")
    )
    assert isinstance(result, PipelineResult)
    assert result.continue_processing is True


# ---------------------------------------------------------------------------
# Modified-payload round-trip
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pii_redact_returns_modified_payload(pii_redact_config_path: str):
    """Redaction rewrites the payload, and the change round-trips through PyO3.

    Asserts:
    - continue_processing is True (redaction allows, unlike deny)
    - payload_modified is True and modified_payload is set
    - the SSN argument value is replaced with [REDACTED]
    - an unrelated argument field is preserved verbatim
    """
    eng = PolicyEngine(pii_redact_config_path)
    await eng.initialize()

    result = await eng.invoke_hook(
        "cmf.tool_pre_invoke",
        tool_call("lookup_person", {"ssn": "123-45-6789", "name": "Alice"}),
        tool_route("lookup_person"),
    )

    assert result.continue_processing is True, "redaction should allow processing"
    assert result.payload_modified is True
    assert result.modified_payload is not None, "redaction must set modified_payload"

    args = result.modified_payload["message"]["content"][0]["content"]["arguments"]
    assert args["ssn"] == "[REDACTED]", f"SSN should be redacted, got: {args['ssn']!r}"
    assert args["name"] == "Alice", "unrelated field must be preserved"

    await eng.shutdown()


# ---------------------------------------------------------------------------
# After shutdown
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_invoke_after_shutdown_raises(pii_deny_config_path: str):
    """Shutdown is terminal: later calls raise RuntimeError, not a crash."""
    eng = PolicyEngine(pii_deny_config_path)
    await eng.initialize()
    await eng.shutdown()

    with pytest.raises(RuntimeError, match="after shutdown"):
        await eng.invoke_hook(
            "cmf.tool_pre_invoke",
            tool_call("lookup_person", {"ssn": "123-45-6789"}),
            tool_route("lookup_person"),
        )
    with pytest.raises(RuntimeError, match="after shutdown"):
        await eng.initialize()
    with pytest.raises(RuntimeError, match="after shutdown"):
        await eng.refresh_secrets()

    # A second shutdown is a no-op.
    await eng.shutdown()
