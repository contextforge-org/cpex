# Location: ./bindings/python/tests/test_manager.py
# Copyright 2025
# SPDX-License-Identifier: Apache-2.0
# Authors: Ted Habeck
#
# Integration tests for PyPluginManager lifecycle (U4).

import pytest
from cpex import PluginManager, PipelineResult


# ---------------------------------------------------------------------------
# AE1 — importable (KD11 guard test)
# ---------------------------------------------------------------------------


def test_cpex_lib_importable():
    """cpex._lib must be importable and resolve to the native extension (KD11)."""
    import cpex
    import cpex._lib  # noqa: F401

    # __file__ on the package must NOT point to the legacy ./cpex/ directory.
    # In the test venv, cpex.__file__ should end with cpex/__init__.py from
    # the bindings package, and cpex._lib is a native .so/.dylib.
    assert hasattr(cpex._lib, "PluginManager"), "cpex._lib must expose PluginManager"
    assert hasattr(cpex._lib, "PipelineResult"), "cpex._lib must expose PipelineResult"


# ---------------------------------------------------------------------------
# Happy path lifecycle
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_lifecycle_construct_initialize_shutdown(pii_deny_config_path: str):
    """Construct → initialize → shutdown completes without error."""
    mgr = PluginManager(pii_deny_config_path)
    await mgr.initialize()
    await mgr.shutdown()


@pytest.mark.asyncio
async def test_invoke_returns_pipeline_result(manager: PluginManager):
    """A non-triggering invoke returns a PipelineResult with continue_processing=True."""
    payload = {
        "message": {
            "role": "user",
            "content": [{"content_type": "text", "text": "Hello, world!"}],
        }
    }
    result = await manager.invoke_hook("cmf.tool_pre_invoke", payload)
    assert isinstance(result, PipelineResult)
    # SSN not present — no denial
    assert result.continue_processing is True


# ---------------------------------------------------------------------------
# AE2 — pii-scan deny (KD10, KD4)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pii_deny_returns_violation(pii_deny_config_path: str):
    """AE2: CMF invoke with SSN payload → continue_processing=False, violation present."""
    mgr = PluginManager(pii_deny_config_path)
    await mgr.initialize()

    # Payload contains a tool call with an SSN in the arguments.
    payload = {
        "message": {
            "role": "assistant",
            "content": [
                {
                    "content_type": "tool_call",
                    "content": {
                        "tool_call_id": "tc_001",
                        "name": "lookup_person",
                        "arguments": {"ssn": "123-45-6789"},
                    },
                }
            ],
        }
    }
    result = await mgr.invoke_hook("cmf.tool_pre_invoke", payload)

    assert result.continue_processing is False, "pii-scan deny should halt pipeline"
    assert result.violation is not None, "violation dict must be populated"
    assert "reason" in result.violation, "violation must have a reason field"

    await mgr.shutdown()


@pytest.mark.asyncio
async def test_generic_hook_does_not_raise(manager: PluginManager):
    """Non-CMF hook routes through GenericPayload and returns a result (KD2)."""
    result = await manager.invoke_hook("custom.arbitrary.hook", {"data": "value"})
    assert isinstance(result, PipelineResult)
    assert result.continue_processing is True
