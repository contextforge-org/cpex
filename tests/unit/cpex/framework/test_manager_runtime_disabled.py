# -*- coding: utf-8 -*-
"""Location: ./tests/unit/cpex/framework/test_manager_runtime_disabled.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0

Tests for PluginExecutor._runtime_disabled:
  - persistent-per-executor lifetime across multiple execute() calls
  - asyncio.Lock guards mutations under concurrent failures
  - reset_runtime_disabled() clears the set under the same lock
"""

# Standard
import asyncio
from unittest.mock import patch

# Third-Party
import pytest

from cpex.framework import (
    GlobalContext,
    OnError,
    Plugin,
    PluginConfig,
    PluginManager,
    PluginMode,
    PluginResult,
    PromptHookType,
    PromptPrehookPayload,
)

# First-Party
from cpex.framework.base import HookRef
from cpex.framework.registry import PluginRef


def _cfg(name: str, on_error: OnError = OnError.DISABLE) -> PluginConfig:
    return PluginConfig(
        name=name,
        description="test",
        author="test",
        version="1.0",
        kind="test.Plugin",
        mode=PluginMode.CONCURRENT,
        on_error=on_error,
        hooks=["prompt_pre_fetch"],
        tags=[],
        priority=100,
    )


async def _make_manager() -> PluginManager:
    manager = PluginManager("./tests/unit/cpex/fixtures/configs/valid_no_plugin.yaml")
    await manager.initialize()
    return manager


@pytest.mark.asyncio
async def test_runtime_disabled_persists_across_execute_calls():
    """OnError.DISABLE is a persistent decision: a disabled plugin stays disabled
    across subsequent execute() calls on the same executor."""

    call_count = 0

    class FailingPlugin(Plugin):
        async def prompt_pre_fetch(self, payload, context):
            nonlocal call_count
            call_count += 1
            raise RuntimeError("boom")

    manager = await _make_manager()
    plugin = FailingPlugin(_cfg("Persistent"))
    hook_ref = HookRef(PromptHookType.PROMPT_PRE_FETCH, PluginRef(plugin))

    with patch.object(manager._registry, "get_hook_refs_for_hook") as mock_get:
        mock_get.return_value = [hook_ref]
        payload = PromptPrehookPayload(prompt_id="t", args={})
        ctx = GlobalContext(request_id="1")

        for _ in range(5):
            await manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, payload, ctx)

    assert call_count == 1
    assert "Persistent" in manager._executor._runtime_disabled

    await manager.shutdown()


@pytest.mark.asyncio
async def test_runtime_disabled_concurrent_failures_dont_corrupt_set():
    """Concurrent OnError.DISABLE failures across multiple plugins all land in the
    set. With the asyncio.Lock guarding mutations, no plugin name is dropped."""

    plugin_names = [f"P{i}" for i in range(20)]

    class FailingPlugin(Plugin):
        async def prompt_pre_fetch(self, payload, context):
            raise RuntimeError("boom")

    manager = await _make_manager()
    plugins = [FailingPlugin(_cfg(n)) for n in plugin_names]
    hook_refs = [HookRef(PromptHookType.PROMPT_PRE_FETCH, PluginRef(p)) for p in plugins]

    async def trip(hook_ref: HookRef) -> None:
        with patch.object(manager._registry, "get_hook_refs_for_hook") as mock_get:
            mock_get.return_value = [hook_ref]
            await manager.invoke_hook(
                PromptHookType.PROMPT_PRE_FETCH,
                PromptPrehookPayload(prompt_id="t", args={}),
                GlobalContext(request_id="x"),
            )

    await asyncio.gather(*(trip(hr) for hr in hook_refs))

    assert manager._executor._runtime_disabled == set(plugin_names)

    await manager.shutdown()


@pytest.mark.asyncio
async def test_reset_runtime_disabled_clears_and_reenables():
    """reset_runtime_disabled() empties the set; subsequent invocations re-run the plugin."""

    call_count = 0

    class FlakyPlugin(Plugin):
        async def prompt_pre_fetch(self, payload, context):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("first call fails")
            return PluginResult(continue_processing=True)

    manager = await _make_manager()
    plugin = FlakyPlugin(_cfg("Flaky"))
    hook_ref = HookRef(PromptHookType.PROMPT_PRE_FETCH, PluginRef(plugin))

    with patch.object(manager._registry, "get_hook_refs_for_hook") as mock_get:
        mock_get.return_value = [hook_ref]
        payload = PromptPrehookPayload(prompt_id="t", args={})
        ctx = GlobalContext(request_id="r")

        await manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, payload, ctx)
        assert "Flaky" in manager._executor._runtime_disabled
        # Skipped while disabled
        await manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, payload, ctx)
        assert call_count == 1

        await manager._executor.reset_runtime_disabled()
        assert manager._executor._runtime_disabled == set()

        # Now runs again, succeeds this time
        await manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, payload, ctx)
        assert call_count == 2
        assert "Flaky" not in manager._executor._runtime_disabled

    await manager.shutdown()
