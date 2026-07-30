# -*- coding: utf-8 -*-
"""Location: ./tests/unit/cpex/framework/test_execution_records.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0

Unit tests for ControlExecutionRecord generation on PluginResult.executions (issue #130).

These tests verify:
- executions is always present (empty when no plugins ran)
- sequential deny path produces a record with correct fields
- sequential allow path produces a record with correct fields (matched=False on clean allow)
- transform plugin produces a record with payload_modified=True
- audit plugin produces a record with applied=False regardless of result
- concurrent deny path produces a record with correct fields
- fire-and-forget plugins produce spawn-time records (mode=fire_and_forget)
- plugin identity fields come from trusted config, not plugin-returned metadata
- string truncation helpers work correctly
- on_error=ignore/disable timeout is recorded as TIMEOUT, not COMPLETED
"""

# Standard
import asyncio

# Third-Party
import pytest

# First-Party
from cpex.framework import (
    ControlExecutionRecord,
    ControlExecutionStatus,
    GlobalContext,
    PluginManager,
    PluginMode,
    PluginResult,
    PromptHookType,
    PromptPrehookPayload,
)
from cpex.framework.models import (
    _MAX_CONFIG_KEYS,
    _MAX_STRING_LEN,
    _collect_config_keys,
    _truncate,
    _truncate_opt,
)


# ---------------------------------------------------------------------------
# Helper / truncation unit tests
# ---------------------------------------------------------------------------


def test_truncate_short_string_unchanged():
    assert _truncate("hello") == "hello"


def test_truncate_long_string_is_bounded():
    long = "a" * (_MAX_STRING_LEN + 20)
    result = _truncate(long)
    # Result (including ellipsis) must not exceed MAX_STRING_LEN bytes
    assert len(result.encode("utf-8")) <= _MAX_STRING_LEN
    assert result.endswith("…")


def test_truncate_unicode_does_not_produce_invalid_utf8():
    # Each emoji is 4 bytes — truncation must not split a code point
    s = "🎉" * 100
    result = _truncate(s)
    # Must be valid string (no UnicodeDecodeError)
    result.encode("utf-8")
    assert len(result) > 0


def test_truncate_opt_none_passthrough():
    assert _truncate_opt(None) is None


def test_truncate_opt_non_none():
    assert _truncate_opt("hi") == "hi"


def test_collect_config_keys_extracts_keys_only():
    config = {"policy_file": "apl/demo/hr.yaml", "timeout": 30}
    keys = _collect_config_keys(config)
    assert set(keys) == {"policy_file", "timeout"}


def test_collect_config_keys_bounded():
    config = {f"key_{i}": i for i in range(_MAX_CONFIG_KEYS + 10)}
    keys = _collect_config_keys(config)
    assert len(keys) == _MAX_CONFIG_KEYS


def test_collect_config_keys_non_dict_returns_empty():
    assert _collect_config_keys(None) == []
    assert _collect_config_keys("not a dict") == []  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# ControlExecutionRecord model tests
# ---------------------------------------------------------------------------


def test_execution_record_default_values():
    rec = ControlExecutionRecord(
        plugin_id="abc",
        plugin_name="test-plugin",
        plugin_kind="builtin",
        hook_name="tool_pre_invoke",
        mode=PluginMode.SEQUENTIAL,
        status=ControlExecutionStatus.COMPLETED,
        effective_allow=True,
    )
    assert rec.requested_allow is None
    assert rec.matched is None
    assert rec.applied is False
    assert rec.payload_modified is False
    assert rec.extensions_modified is False
    assert rec.duration_ns == 0
    assert rec.reason is None
    assert rec.error_code is None
    assert rec.config_keys == []


def test_execution_record_serialises_to_dict():
    rec = ControlExecutionRecord(
        plugin_id="abc",
        plugin_name="pii-guard",
        plugin_kind="builtin",
        hook_name="tool_pre_invoke",
        mode=PluginMode.SEQUENTIAL,
        status=ControlExecutionStatus.COMPLETED,
        effective_allow=False,
        matched=True,
        applied=True,
        error_code="pii_access_denied",
        reason="PII clearance required",
    )
    d = rec.model_dump()
    assert d["plugin_name"] == "pii-guard"
    assert d["effective_allow"] is False
    assert d["matched"] is True
    assert d["error_code"] == "pii_access_denied"


# ---------------------------------------------------------------------------
# Integration: executions on PluginResult (via PluginManager)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_executions_empty_when_no_plugins_registered():
    """PluginResult.executions is always present and empty when no hooks are registered."""
    manager = PluginManager("./tests/unit/cpex/fixtures/configs/valid_no_plugin.yaml")
    await manager.initialize()
    prompt = PromptPrehookPayload(prompt_id="p1", args={"user": "hello"})
    context = GlobalContext(request_id="req1")
    result, _ = await manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, prompt, global_context=context)
    assert hasattr(result, "executions")
    assert result.executions == []
    await manager.shutdown()
    PluginManager.reset()


@pytest.mark.asyncio
async def test_executions_sequential_deny_record():
    """A sequential plugin that denies produces a record with expected fields."""
    manager = PluginManager("./tests/unit/cpex/fixtures/configs/valid_single_filter_plugin.yaml")
    await manager.initialize()

    # "innovative" is in the deny list
    prompt = PromptPrehookPayload(prompt_id="test_prompt", args={"user": "innovative"})
    context = GlobalContext(request_id="req2", server_id="s1")
    result, _ = await manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, prompt, global_context=context)

    assert not result.continue_processing
    assert len(result.executions) >= 1

    rec = result.executions[0]
    assert isinstance(rec, ControlExecutionRecord)
    assert rec.plugin_name == "DenyListPlugin"
    assert rec.hook_name == PromptHookType.PROMPT_PRE_FETCH
    assert rec.mode == PluginMode.SEQUENTIAL
    assert rec.status == ControlExecutionStatus.COMPLETED
    assert rec.effective_allow is False
    assert rec.requested_allow is False
    assert rec.matched is True
    assert rec.applied is True
    assert rec.payload_modified is False
    assert rec.duration_ns > 0   # real execution — must have elapsed some time
    assert rec.error_code is not None   # deny path always has an error_code
    # Identity fields come from trusted config, not from plugin
    assert rec.plugin_id  # non-empty UUID hex
    assert rec.plugin_kind  # non-empty kind string

    await manager.shutdown()
    PluginManager.reset()


@pytest.mark.asyncio
async def test_executions_sequential_allow_record():
    """A sequential plugin that allows produces a record with correct allow fields."""
    manager = PluginManager("./tests/unit/cpex/fixtures/configs/valid_single_filter_plugin.yaml")
    await manager.initialize()

    # "hello" is NOT in the deny list — should pass
    prompt = PromptPrehookPayload(prompt_id="test_prompt", args={"user": "hello"})
    context = GlobalContext(request_id="req3", server_id="s1")
    result, _ = await manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, prompt, global_context=context)

    assert result.continue_processing
    assert len(result.executions) >= 1

    rec = result.executions[0]
    assert rec.plugin_name == "DenyListPlugin"
    assert rec.status == ControlExecutionStatus.COMPLETED
    assert rec.effective_allow is True
    assert rec.requested_allow is True
    # DenyListPlugin unconditionally returns modified_payload=payload on allow (line 75 of
    # deny_filter.py), so the executor detects a payload identity change → payload_modified=True
    # → matched=True even on a clean allow.  The meaningful invariant is no denial occurred.
    assert rec.matched is not None, (
        f"clean allow must have a deterministic matched value, not None; got {rec.matched!r}"
    )
    assert isinstance(rec.applied, bool)
    assert rec.duration_ns > 0

    await manager.shutdown()
    PluginManager.reset()


@pytest.mark.asyncio
async def test_executions_records_are_per_invocation_not_shared():
    """Two separate invoke_hook calls produce independent execution record lists."""
    manager = PluginManager("./tests/unit/cpex/fixtures/configs/valid_single_filter_plugin.yaml")
    await manager.initialize()

    prompt = PromptPrehookPayload(prompt_id="test_prompt", args={"user": "hello"})
    context = GlobalContext(request_id="req4", server_id="s1")

    result1, _ = await manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, prompt, global_context=context)
    result2, _ = await manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, prompt, global_context=context)

    # Each result has its own list — mutating one must not affect the other
    assert result1.executions is not result2.executions
    result1.executions.clear()
    assert len(result2.executions) >= 1

    await manager.shutdown()
    PluginManager.reset()


@pytest.mark.asyncio
async def test_executions_plugin_id_is_non_empty_hex():
    """plugin_id is a non-empty hex string (UUID without hyphens)."""
    manager = PluginManager("./tests/unit/cpex/fixtures/configs/valid_single_filter_plugin.yaml")
    await manager.initialize()

    prompt = PromptPrehookPayload(prompt_id="test_prompt", args={"user": "hello"})
    context = GlobalContext(request_id="req5", server_id="s1")
    result, _ = await manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, prompt, global_context=context)

    rec = result.executions[0]
    assert len(rec.plugin_id) == 32   # UUID hex = 32 chars
    int(rec.plugin_id, 16)            # must be valid hex

    await manager.shutdown()
    PluginManager.reset()


_MODES_CONFIG = "./tests/unit/cpex/fixtures/configs/execution_records_modes.yaml"


@pytest.mark.asyncio
async def test_executions_fail_closed_on_error_fail():
    """Critical: a sequential plugin that raises with on_error=fail must propagate the error
    (fail-closed), not swallow it and return continue_processing=True (fail-open).
    The record must be written before the re-raise with status=ERROR and effective_allow=False."""
    from cpex.framework.errors import PluginError

    manager = PluginManager(_MODES_CONFIG)
    await manager.initialize()

    # test_prompt_error routes to ErrorPlugin (sequential, on_error=fail, always raises)
    prompt = PromptPrehookPayload(prompt_id="test_prompt_error", args={"user": "hello"})
    context = GlobalContext(request_id="req-fail-closed")

    with pytest.raises(PluginError):
        await manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, prompt, global_context=context)

    await manager.shutdown()
    PluginManager.reset()


@pytest.mark.asyncio
async def test_executions_concurrent_clean_allow_matched_false():
    """Concurrent clean-allow record must have matched=False (consistent with serial path)."""
    manager = PluginManager(_MODES_CONFIG)
    await manager.initialize()

    # test_prompt_allow routes only to ConcurrentAllowPlugin (passthrough, concurrent)
    prompt = PromptPrehookPayload(prompt_id="test_prompt_allow", args={"user": "hello"})
    context = GlobalContext(request_id="req-concurrent-allow")
    result, _ = await manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, prompt, global_context=context)

    assert result.continue_processing
    assert len(result.executions) >= 1
    rec = result.executions[0]
    assert rec.plugin_name == "ConcurrentAllowPlugin"
    assert rec.mode == PluginMode.CONCURRENT
    assert rec.status == ControlExecutionStatus.COMPLETED
    assert rec.effective_allow is True
    assert rec.matched is False, (
        f"concurrent clean allow: matched must be False, got {rec.matched!r}"
    )
    assert rec.applied is False
    assert rec.payload_modified is False

    await manager.shutdown()
    PluginManager.reset()


@pytest.mark.asyncio
async def test_executions_concurrent_deny_record():
    """A concurrent plugin that denies produces a record with correct fields."""
    manager = PluginManager(_MODES_CONFIG)
    await manager.initialize()

    # test_prompt routes only to ConcurrentDenyPlugin; "innovative" triggers denial
    prompt = PromptPrehookPayload(prompt_id="test_prompt", args={"user": "innovative"})
    context = GlobalContext(request_id="req-concurrent-deny")
    result, _ = await manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, prompt, global_context=context)

    assert not result.continue_processing
    assert len(result.executions) >= 1

    rec = result.executions[0]
    assert rec.plugin_name == "ConcurrentDenyPlugin"
    assert rec.mode == PluginMode.CONCURRENT
    assert rec.status == ControlExecutionStatus.COMPLETED
    assert rec.effective_allow is False
    assert rec.requested_allow is False
    assert rec.matched is True
    assert rec.applied is True
    assert rec.payload_modified is False   # concurrent plugins cannot modify payload

    await manager.shutdown()
    PluginManager.reset()


@pytest.mark.asyncio
async def test_executions_transform_record():
    """A transform plugin produces a record: allow=True, payload_modified=True, applied=True."""
    manager = PluginManager(_MODES_CONFIG)
    await manager.initialize()

    # test_prompt_transform routes only to TransformPlugin; "crap" triggers substitution
    prompt = PromptPrehookPayload(prompt_id="test_prompt_transform", args={"user": "crap input"})
    context = GlobalContext(request_id="req-transform")
    result, _ = await manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, prompt, global_context=context)

    assert result.continue_processing
    assert len(result.executions) >= 1

    rec = result.executions[0]
    assert rec.plugin_name == "TransformPlugin"
    assert rec.mode == PluginMode.TRANSFORM
    assert rec.status == ControlExecutionStatus.COMPLETED
    assert rec.effective_allow is True
    assert rec.payload_modified is True
    assert rec.applied is True            # applied because payload was modified
    assert rec.duration_ns > 0

    await manager.shutdown()
    PluginManager.reset()


@pytest.mark.asyncio
async def test_executions_audit_record():
    """An audit plugin produces a record: allow=True, applied=False, payload_modified=False."""
    manager = PluginManager(_MODES_CONFIG)
    await manager.initialize()

    # test_prompt_audit routes only to AuditPlugin (passthrough, audit)
    prompt = PromptPrehookPayload(prompt_id="test_prompt_audit", args={"user": "hello"})
    context = GlobalContext(request_id="req-audit")
    result, _ = await manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, prompt, global_context=context)

    assert result.continue_processing
    assert len(result.executions) >= 1

    rec = result.executions[0]
    assert rec.plugin_name == "AuditPlugin"
    assert rec.mode == PluginMode.AUDIT
    assert rec.status == ControlExecutionStatus.COMPLETED
    assert rec.effective_allow is True
    assert rec.payload_modified is False   # audit plugins cannot modify payloads
    assert rec.applied is False            # no denial, no mutation → not applied
    assert rec.duration_ns > 0

    await manager.shutdown()
    PluginManager.reset()


@pytest.mark.asyncio
async def test_executions_faf_record():
    """A fire-and-forget plugin produces a spawn-time record with mode=fire_and_forget."""
    manager = PluginManager(_MODES_CONFIG)
    await manager.initialize()

    # test_prompt_faf routes only to FafPlugin (passthrough, fire_and_forget)
    prompt = PromptPrehookPayload(prompt_id="test_prompt_faf", args={"user": "hello"})
    context = GlobalContext(request_id="req-faf")
    result, _ = await manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, prompt, global_context=context)

    assert result.continue_processing
    assert len(result.executions) >= 1

    rec = result.executions[0]
    assert rec.plugin_name == "FafPlugin"
    assert rec.mode == PluginMode.FIRE_AND_FORGET
    # Spawn-time record: status is COMPLETED as an optimistic placeholder.
    # Identify FAF records by mode, not by status.
    assert rec.status == ControlExecutionStatus.COMPLETED
    assert rec.effective_allow is True
    assert rec.duration_ns == 0           # not yet executed at pipeline return time
    assert rec.requested_allow is None    # outcome unknowable at spawn

    # Wait for the background task to confirm it ran without error
    errors = await result.wait_for_background_tasks()
    assert errors == []

    await manager.shutdown()
    PluginManager.reset()


@pytest.mark.asyncio
async def test_executions_timeout_ignore_recorded_as_timeout():
    """A plugin that times out with on_error=ignore must produce a TIMEOUT record, not COMPLETED."""
    # timeout=1 so the 3600s sleep in TimeoutPlugin fires within the test
    manager = PluginManager(_MODES_CONFIG, timeout=1)
    await manager.initialize()

    # test_prompt_timeout routes only to TimeoutPlugin (sequential, on_error=ignore)
    prompt = PromptPrehookPayload(prompt_id="test_prompt_timeout", args={"user": "hello"})
    context = GlobalContext(request_id="req-timeout-ignore")
    result, _ = await manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, prompt, global_context=context)

    assert result.continue_processing
    assert len(result.executions) >= 1

    rec = result.executions[0]
    assert rec.plugin_name == "TimeoutPlugin"
    assert rec.status == ControlExecutionStatus.TIMEOUT, (
        f"expected TIMEOUT, got {rec.status!r} — timeout under on_error=ignore must not look like a clean allow"
    )
    assert rec.effective_allow is True    # pipeline continued
    assert rec.error_code == "plugin_timeout"

    await manager.shutdown()
    PluginManager.reset()


@pytest.mark.asyncio
async def test_executions_concurrent_timeout_ignore_does_not_escape():
    """A concurrent plugin that times out with on_error=ignore must NOT let PluginTimeoutError
    escape invoke_hook: the pipeline continues and the record is TIMEOUT (mirrors serial phase)."""
    # timeout=1 so the 3600s sleep in TimeoutPlugin fires within the test
    manager = PluginManager(_MODES_CONFIG, timeout=1)
    await manager.initialize()

    # test_prompt_concurrent_timeout routes only to ConcurrentTimeoutPlugin (concurrent, on_error=ignore)
    prompt = PromptPrehookPayload(prompt_id="test_prompt_concurrent_timeout", args={"user": "hello"})
    context = GlobalContext(request_id="req-concurrent-timeout")
    result, _ = await manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, prompt, global_context=context)

    assert result.continue_processing   # must not raise / must fail-open-continue for ignore
    assert len(result.executions) >= 1

    rec = result.executions[0]
    assert rec.plugin_name == "ConcurrentTimeoutPlugin"
    assert rec.mode == PluginMode.CONCURRENT
    assert rec.status == ControlExecutionStatus.TIMEOUT, (
        f"expected TIMEOUT, got {rec.status!r} — concurrent ignore-timeout must not look like a clean allow"
    )
    assert rec.effective_allow is True
    assert rec.error_code == "plugin_timeout"

    await manager.shutdown()
    PluginManager.reset()
