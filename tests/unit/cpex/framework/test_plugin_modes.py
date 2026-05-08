# -*- coding: utf-8 -*-
"""Location: ./tests/unit/cpex/framework/test_plugin_modes.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0

Tests for PluginMode / OnError refactor:
  - FIRE_AND_FORGET fire-and-forget semantics
  - OnError.IGNORE / DISABLE / FAIL behaviors
  - CONCURRENT parallel execution (can block, cannot modify)
  - SEQUENTIAL chained execution (can block + modify)
  - TRANSFORM chained execution (can modify, cannot block)
  - AUDIT sequential execution (observe-only: cannot halt or modify)
  - Phase ordering: SEQUENTIAL → TRANSFORM → AUDIT → CONCURRENT → FIRE_AND_FORGET
  - execution_pool semaphore for FIRE_AND_FORGET tasks
  - Backward-compat migration: enforce / enforce_ignore_error → SEQUENTIAL, permissive → TRANSFORM
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
    PluginError,
    PluginManager,
    PluginMode,
    PluginResult,
    PromptHookType,
    PromptPrehookPayload,
)

# First-Party
from cpex.framework.base import HookRef
from cpex.framework.registry import PluginRef

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_plugin_config(
    name: str, mode: PluginMode, on_error: OnError = OnError.FAIL, priority: int = 100
) -> PluginConfig:
    return PluginConfig(
        name=name,
        description="test",
        author="test",
        version="1.0",
        kind="test.Plugin",
        mode=mode,
        on_error=on_error,
        hooks=["prompt_pre_fetch"],
        tags=[],
        priority=priority,
    )


async def _make_manager() -> PluginManager:
    manager = PluginManager("./tests/unit/cpex/fixtures/configs/valid_no_plugin.yaml")
    await manager.initialize()
    return manager


# ---------------------------------------------------------------------------
# FIRE_AND_FORGET mode
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fire_and_forget_mode_fires_background_task():
    """Pipeline continues immediately without waiting for a FIRE_AND_FORGET plugin."""

    started = asyncio.Event()
    finished = asyncio.Event()

    class SlowFireAndForgetPlugin(Plugin):
        async def prompt_pre_fetch(self, payload, context):
            started.set()
            await asyncio.sleep(0.05)
            finished.set()
            return PluginResult(continue_processing=True)

    manager = await _make_manager()
    cfg = make_plugin_config("SlowFireAndForget", PluginMode.FIRE_AND_FORGET)
    plugin = SlowFireAndForgetPlugin(cfg)

    with patch.object(manager._registry, "get_hook_refs_for_hook") as mock_get:
        mock_get.return_value = [HookRef(PromptHookType.PROMPT_PRE_FETCH, PluginRef(plugin))]
        payload = PromptPrehookPayload(prompt_id="test", args={})
        global_context = GlobalContext(request_id="1")

        result, _ = await manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, payload, global_context)

    # Pipeline result is returned immediately; FIRE_AND_FORGET task hasn't finished yet
    assert result.continue_processing
    assert not finished.is_set()

    # Wait deterministically for the background task to complete
    await result.wait_for_background_tasks()
    assert finished.is_set()

    await manager.shutdown()


@pytest.mark.asyncio
async def test_fire_and_forget_mode_error_does_not_block():
    """A FIRE_AND_FORGET plugin that errors must not halt or affect the pipeline."""

    class BrokenFireAndForgetPlugin(Plugin):
        async def prompt_pre_fetch(self, payload, context):
            raise RuntimeError("fire_and_forget error")

    manager = await _make_manager()
    cfg = make_plugin_config("BrokenFireAndForget", PluginMode.FIRE_AND_FORGET)
    plugin = BrokenFireAndForgetPlugin(cfg)

    with patch.object(manager._registry, "get_hook_refs_for_hook") as mock_get:
        mock_get.return_value = [HookRef(PromptHookType.PROMPT_PRE_FETCH, PluginRef(plugin))]
        payload = PromptPrehookPayload(prompt_id="test", args={})
        global_context = GlobalContext(request_id="2")

        result, _ = await manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, payload, global_context)

    assert result.continue_processing

    # Wait for the background task; errors are returned, not raised
    await result.wait_for_background_tasks()

    await manager.shutdown()


@pytest.mark.asyncio
async def test_wait_for_background_tasks_returns_errors():
    """wait_for_background_tasks() returns a PluginErrorModel for each failed task."""

    class BrokenPlugin(Plugin):
        async def prompt_pre_fetch(self, payload, context):
            raise RuntimeError("boom")

    manager = await _make_manager()
    cfg = make_plugin_config("BrokenFnF", PluginMode.FIRE_AND_FORGET)
    plugin = BrokenPlugin(cfg)

    with patch.object(manager._registry, "get_hook_refs_for_hook") as mock_get:
        mock_get.return_value = [HookRef(PromptHookType.PROMPT_PRE_FETCH, PluginRef(plugin))]
        payload = PromptPrehookPayload(prompt_id="test", args={})
        global_context = GlobalContext(request_id="wait_errors")

        result, _ = await manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, payload, global_context)

    errors = await result.wait_for_background_tasks()
    assert len(errors) == 1
    assert errors[0].plugin_name == "BrokenFnF"
    assert "RuntimeError" in errors[0].message

    await manager.shutdown()


# ---------------------------------------------------------------------------
# OnError behaviors (CONCURRENT mode)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_on_error_ignore_continues_pipeline():
    """CONCURRENT + on_error=IGNORE: error is logged, pipeline continues."""

    class FailPlugin(Plugin):
        async def prompt_pre_fetch(self, payload, context):
            raise RuntimeError("intentional error")

    manager = await _make_manager()
    cfg = make_plugin_config("IgnorePlugin", PluginMode.CONCURRENT, on_error=OnError.IGNORE)
    plugin = FailPlugin(cfg)

    with patch.object(manager._registry, "get_hook_refs_for_hook") as mock_get:
        mock_get.return_value = [HookRef(PromptHookType.PROMPT_PRE_FETCH, PluginRef(plugin))]
        payload = PromptPrehookPayload(prompt_id="test", args={})
        global_context = GlobalContext(request_id="3")

        result, _ = await manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, payload, global_context)

    assert result.continue_processing
    assert result.violation is None

    await manager.shutdown()


@pytest.mark.asyncio
async def test_on_error_disable_disables_plugin():
    """CONCURRENT + on_error=DISABLE: plugin is runtime-disabled after first error."""

    call_count = 0

    class DisablePlugin(Plugin):
        async def prompt_pre_fetch(self, payload, context):
            nonlocal call_count
            call_count += 1
            raise RuntimeError("first call fails")

    manager = await _make_manager()
    cfg = make_plugin_config("DisablePlugin", PluginMode.CONCURRENT, on_error=OnError.DISABLE)
    plugin = DisablePlugin(cfg)
    hook_ref = HookRef(PromptHookType.PROMPT_PRE_FETCH, PluginRef(plugin))

    with patch.object(manager._registry, "get_hook_refs_for_hook") as mock_get:
        mock_get.return_value = [hook_ref]
        payload = PromptPrehookPayload(prompt_id="test", args={})
        global_context = GlobalContext(request_id="4")

        # First call: error is caught, plugin gets disabled
        result1, _ = await manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, payload, global_context)
        assert result1.continue_processing

        # Second call: plugin is in _runtime_disabled, should be skipped
        result2, _ = await manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, payload, global_context)
        assert result2.continue_processing

    # Plugin ran exactly once (skipped on second call)
    assert call_count == 1
    assert "DisablePlugin" in manager._executor._runtime_disabled

    await manager.shutdown()


@pytest.mark.asyncio
async def test_on_error_fail_raises():
    """CONCURRENT + on_error=FAIL (default): error propagates as PluginError."""

    class FailPlugin(Plugin):
        async def prompt_pre_fetch(self, payload, context):
            raise RuntimeError("fail!")

    manager = await _make_manager()
    cfg = make_plugin_config("FailPlugin", PluginMode.CONCURRENT, on_error=OnError.FAIL)
    plugin = FailPlugin(cfg)

    with patch.object(manager._registry, "get_hook_refs_for_hook") as mock_get:
        mock_get.return_value = [HookRef(PromptHookType.PROMPT_PRE_FETCH, PluginRef(plugin))]
        payload = PromptPrehookPayload(prompt_id="test", args={})
        global_context = GlobalContext(request_id="5")

        with pytest.raises(PluginError):
            await manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, payload, global_context)

    await manager.shutdown()


# ---------------------------------------------------------------------------
# CONCURRENT parallel execution
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_parallel_execution():
    """Multiple CONCURRENT plugins should run concurrently."""

    results_order: list[str] = []
    start_barrier = asyncio.Event()

    class SlowPlugin(Plugin):
        async def prompt_pre_fetch(self, payload, context):
            results_order.append(f"start:{self.name}")
            await start_barrier.wait()
            await asyncio.sleep(0.01)
            results_order.append(f"end:{self.name}")
            return PluginResult(continue_processing=True)

    manager = await _make_manager()
    cfg1 = make_plugin_config("ConcP1", PluginMode.CONCURRENT, priority=1)
    cfg2 = make_plugin_config("ConcP2", PluginMode.CONCURRENT, priority=2)
    plugin1 = SlowPlugin(cfg1)
    plugin2 = SlowPlugin(cfg2)

    ref1 = HookRef(PromptHookType.PROMPT_PRE_FETCH, PluginRef(plugin1))
    ref2 = HookRef(PromptHookType.PROMPT_PRE_FETCH, PluginRef(plugin2))

    with patch.object(manager._registry, "get_hook_refs_for_hook") as mock_get:
        mock_get.return_value = [ref1, ref2]
        payload = PromptPrehookPayload(prompt_id="test", args={})
        global_context = GlobalContext(request_id="6")

        # Let the invoke run while releasing the barrier concurrently
        async def release_and_invoke():
            task = asyncio.create_task(manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, payload, global_context))
            await asyncio.sleep(0.005)  # Let both plugins reach the barrier
            start_barrier.set()
            return await task

        result, _ = await release_and_invoke()

    assert result.continue_processing
    # Both plugins started before either finished (parallel execution)
    assert results_order[:2] == ["start:ConcP1", "start:ConcP2"]

    await manager.shutdown()


# ---------------------------------------------------------------------------
# AUDIT sequential execution
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_sequential_execution():
    """AUDIT plugins execute in priority order sequentially."""

    call_order: list[str] = []

    class SequentialPlugin(Plugin):
        async def prompt_pre_fetch(self, payload, context):
            call_order.append(self.name)
            return PluginResult(continue_processing=True)

    manager = await _make_manager()
    cfg1 = make_plugin_config("PermP1", PluginMode.AUDIT, priority=1)
    cfg2 = make_plugin_config("PermP2", PluginMode.AUDIT, priority=2)
    plugin1 = SequentialPlugin(cfg1)
    plugin2 = SequentialPlugin(cfg2)

    ref1 = HookRef(PromptHookType.PROMPT_PRE_FETCH, PluginRef(plugin1))
    ref2 = HookRef(PromptHookType.PROMPT_PRE_FETCH, PluginRef(plugin2))

    with patch.object(manager._registry, "get_hook_refs_for_hook") as mock_get:
        mock_get.return_value = [ref1, ref2]
        payload = PromptPrehookPayload(prompt_id="test", args={})
        global_context = GlobalContext(request_id="7")

        result, _ = await manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, payload, global_context)

    assert result.continue_processing
    assert call_order == ["PermP1", "PermP2"]

    await manager.shutdown()


# ---------------------------------------------------------------------------
# execution_pool semaphore
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_execution_pool_semaphore():
    """With execution_pool=1, FIRE_AND_FORGET tasks are serialized."""

    concurrency_high_water = 0
    current_concurrent = 0

    class ConcurrencyProbePlugin(Plugin):
        async def prompt_pre_fetch(self, payload, context):
            nonlocal concurrency_high_water, current_concurrent
            current_concurrent += 1
            concurrency_high_water = max(concurrency_high_water, current_concurrent)
            await asyncio.sleep(0.02)
            current_concurrent -= 1
            return PluginResult(continue_processing=True)

    manager = await _make_manager()

    cfg1 = make_plugin_config("ObsPool1", PluginMode.FIRE_AND_FORGET, priority=1)
    cfg2 = make_plugin_config("ObsPool2", PluginMode.FIRE_AND_FORGET, priority=2)
    plugin1 = ConcurrencyProbePlugin(cfg1)
    plugin2 = ConcurrencyProbePlugin(cfg2)

    ref1 = HookRef(PromptHookType.PROMPT_PRE_FETCH, PluginRef(plugin1))
    ref2 = HookRef(PromptHookType.PROMPT_PRE_FETCH, PluginRef(plugin2))

    with patch.object(manager._registry, "get_hook_refs_for_hook") as mock_get:
        mock_get.return_value = [ref1, ref2]
        payload = PromptPrehookPayload(prompt_id="test", args={})
        global_context = GlobalContext(request_id="8")

        # Patch execution_pool=1 via the settings layer
        with patch("cpex.framework.manager.settings") as mock_settings:
            mock_settings.execution_pool = 1
            result, _ = await manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, payload, global_context)

    assert result.continue_processing

    # Wait deterministically for all background FIRE_AND_FORGET tasks to complete
    await result.wait_for_background_tasks()

    # With pool=1, max concurrency should be 1
    assert concurrency_high_water <= 1

    await manager.shutdown()


# ---------------------------------------------------------------------------
# Backward compatibility: YAML migration
# ---------------------------------------------------------------------------


def test_plugin_config_migration_enforce_ignore_error():
    """Legacy 'enforce_ignore_error' mode migrates to SEQUENTIAL + on_error=ignore."""
    cfg = PluginConfig.model_validate(
        {
            "name": "legacy",
            "kind": "test.Plugin",
            "mode": "enforce_ignore_error",
        }
    )
    assert cfg.mode == PluginMode.SEQUENTIAL
    assert cfg.on_error == OnError.IGNORE


def test_plugin_config_migration_preserves_explicit_on_error():
    """Migration does not override an explicitly provided on_error value."""
    cfg = PluginConfig.model_validate(
        {
            "name": "legacy2",
            "kind": "test.Plugin",
            "mode": "enforce_ignore_error",
            "on_error": "disable",
        }
    )
    assert cfg.mode == PluginMode.SEQUENTIAL
    assert cfg.on_error == OnError.DISABLE


def test_plugin_config_migration_enforce_to_sequential():
    """Legacy 'enforce' mode migrates to SEQUENTIAL."""
    cfg = PluginConfig.model_validate(
        {
            "name": "legacy_enforce",
            "kind": "test.Plugin",
            "mode": "enforce",
        }
    )
    assert cfg.mode == PluginMode.SEQUENTIAL


def test_plugin_config_migration_permissive_to_transform():
    """Legacy 'permissive' mode migrates to TRANSFORM."""
    cfg = PluginConfig.model_validate(
        {
            "name": "legacy_permissive",
            "kind": "test.Plugin",
            "mode": "permissive",
        }
    )
    assert cfg.mode == PluginMode.TRANSFORM


# ---------------------------------------------------------------------------
# SEQUENTIAL mode tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sequential_chains_payload():
    """Each SEQUENTIAL plugin receives the output payload of the previous plugin."""

    received_payloads: list = []

    class ChainPlugin(Plugin):
        async def prompt_pre_fetch(self, payload, context):
            step = int(payload.args.get("step", "0"))
            received_payloads.append(step)
            new_payload = PromptPrehookPayload(prompt_id=payload.prompt_id, args={"step": str(step + 1)})
            return PluginResult(continue_processing=True, modified_payload=new_payload)

    manager = await _make_manager()
    cfg1 = make_plugin_config("SeqChain1", PluginMode.SEQUENTIAL, priority=1)
    cfg2 = make_plugin_config("SeqChain2", PluginMode.SEQUENTIAL, priority=2)
    plugin1 = ChainPlugin(cfg1)
    plugin2 = ChainPlugin(cfg2)

    ref1 = HookRef(PromptHookType.PROMPT_PRE_FETCH, PluginRef(plugin1))
    ref2 = HookRef(PromptHookType.PROMPT_PRE_FETCH, PluginRef(plugin2))

    with patch.object(manager._registry, "get_hook_refs_for_hook") as mock_get:
        mock_get.return_value = [ref1, ref2]
        payload = PromptPrehookPayload(prompt_id="test", args={"step": "0"})
        global_context = GlobalContext(request_id="seq1")

        with patch("cpex.framework.manager.settings") as mock_settings:
            mock_settings.execution_pool = None
            mock_settings.default_hook_policy = "allow"
            result, _ = await manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, payload, global_context)

    # First plugin saw step=0, second saw step=1 (chained)
    assert received_payloads[0] == 0
    assert received_payloads[1] == 1
    # Final payload has step=2
    assert result.modified_payload is not None
    assert result.modified_payload.args["step"] == "2"

    await manager.shutdown()


@pytest.mark.asyncio
async def test_sequential_can_halt_pipeline():
    """A SEQUENTIAL plugin that returns continue_processing=False halts the pipeline."""

    call_order: list[str] = []

    class HaltPlugin(Plugin):
        async def prompt_pre_fetch(self, payload, context):
            call_order.append(self.name)
            return PluginResult(continue_processing=False)

    class NeverReachedPlugin(Plugin):
        async def prompt_pre_fetch(self, payload, context):
            call_order.append(self.name)
            return PluginResult(continue_processing=True)

    manager = await _make_manager()
    cfg_halt = make_plugin_config("SeqHalt", PluginMode.SEQUENTIAL, priority=1)
    cfg_after = make_plugin_config("SeqAfter", PluginMode.SEQUENTIAL, priority=2)
    plugin_halt = HaltPlugin(cfg_halt)
    plugin_after = NeverReachedPlugin(cfg_after)

    ref_halt = HookRef(PromptHookType.PROMPT_PRE_FETCH, PluginRef(plugin_halt))
    ref_after = HookRef(PromptHookType.PROMPT_PRE_FETCH, PluginRef(plugin_after))

    with patch.object(manager._registry, "get_hook_refs_for_hook") as mock_get:
        mock_get.return_value = [ref_halt, ref_after]
        payload = PromptPrehookPayload(prompt_id="test", args={})
        global_context = GlobalContext(request_id="seq2")

        result, _ = await manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, payload, global_context)

    assert not result.continue_processing
    assert call_order == ["SeqHalt"]  # second plugin never ran

    await manager.shutdown()


@pytest.mark.asyncio
async def test_sequential_executes_before_transform():
    """SEQUENTIAL plugins run before TRANSFORM plugins regardless of priority."""

    call_order: list[str] = []

    class OrderPlugin(Plugin):
        async def prompt_pre_fetch(self, payload, context):
            call_order.append(self.name)
            return PluginResult(continue_processing=True)

    manager = await _make_manager()
    cfg_seq = make_plugin_config("SeqFirst", PluginMode.SEQUENTIAL, priority=10)
    cfg_xform = make_plugin_config("XformSecond", PluginMode.TRANSFORM, priority=1)  # lower priority number
    plugin_seq = OrderPlugin(cfg_seq)
    plugin_xform = OrderPlugin(cfg_xform)

    ref_seq = HookRef(PromptHookType.PROMPT_PRE_FETCH, PluginRef(plugin_seq))
    ref_xform = HookRef(PromptHookType.PROMPT_PRE_FETCH, PluginRef(plugin_xform))

    with patch.object(manager._registry, "get_hook_refs_for_hook") as mock_get:
        mock_get.return_value = [ref_seq, ref_xform]
        payload = PromptPrehookPayload(prompt_id="test", args={})
        global_context = GlobalContext(request_id="seq3")

        with patch("cpex.framework.manager.settings") as mock_settings:
            mock_settings.execution_pool = None
            mock_settings.default_hook_policy = "allow"
            result, _ = await manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, payload, global_context)

    assert result.continue_processing
    assert call_order == ["SeqFirst", "XformSecond"]

    await manager.shutdown()


@pytest.mark.asyncio
async def test_sequential_executes_before_concurrent():
    """SEQUENTIAL plugins run before CONCURRENT plugins."""

    call_order: list[str] = []

    class OrderPlugin(Plugin):
        async def prompt_pre_fetch(self, payload, context):
            call_order.append(self.name)
            return PluginResult(continue_processing=True)

    manager = await _make_manager()
    cfg_seq = make_plugin_config("SeqFirst2", PluginMode.SEQUENTIAL, priority=10)
    cfg_conc = make_plugin_config("ConcSecond", PluginMode.CONCURRENT, priority=1)
    plugin_seq = OrderPlugin(cfg_seq)
    plugin_conc = OrderPlugin(cfg_conc)

    ref_seq = HookRef(PromptHookType.PROMPT_PRE_FETCH, PluginRef(plugin_seq))
    ref_conc = HookRef(PromptHookType.PROMPT_PRE_FETCH, PluginRef(plugin_conc))

    with patch.object(manager._registry, "get_hook_refs_for_hook") as mock_get:
        mock_get.return_value = [ref_seq, ref_conc]
        payload = PromptPrehookPayload(prompt_id="test", args={})
        global_context = GlobalContext(request_id="seq4")

        result, _ = await manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, payload, global_context)

    assert result.continue_processing
    assert call_order == ["SeqFirst2", "ConcSecond"]

    await manager.shutdown()


# ---------------------------------------------------------------------------
# Phase ordering tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_phase_order_all_five_modes():
    """All five phases execute in the correct order: SEQ → TRANSFORM → AUDIT → CONC → F&F."""

    phase_log: list[str] = []
    fnf_event = asyncio.Event()

    class LogPlugin(Plugin):
        async def prompt_pre_fetch(self, payload, context):
            phase_log.append(self.name)
            if self.name == "fnf":
                fnf_event.set()
            return PluginResult(continue_processing=True)

    manager = await _make_manager()
    modes = [
        ("seq", PluginMode.SEQUENTIAL),
        ("xform", PluginMode.TRANSFORM),
        ("audit", PluginMode.AUDIT),
        ("conc", PluginMode.CONCURRENT),
        ("fnf", PluginMode.FIRE_AND_FORGET),
    ]
    refs = []
    for name, mode in modes:
        cfg = make_plugin_config(name, mode, priority=1)
        plugin = LogPlugin(cfg)
        refs.append(HookRef(PromptHookType.PROMPT_PRE_FETCH, PluginRef(plugin)))

    with patch.object(manager._registry, "get_hook_refs_for_hook") as mock_get:
        mock_get.return_value = refs
        payload = PromptPrehookPayload(prompt_id="test", args={})
        global_context = GlobalContext(request_id="phase_all")

        with patch("cpex.framework.manager.settings") as mock_settings:
            mock_settings.execution_pool = None
            mock_settings.default_hook_policy = "allow"
            result, _ = await manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, payload, global_context)

    assert result.continue_processing
    # F&F is async — wait for it deterministically
    await result.wait_for_background_tasks()

    assert phase_log == ["seq", "xform", "audit", "conc", "fnf"]

    await manager.shutdown()


@pytest.mark.asyncio
async def test_fire_and_forget_fires_after_all_phases():
    """FIRE_AND_FORGET tasks are scheduled after SEQUENTIAL and CONCURRENT phases complete."""

    phase_log: list[str] = []
    fire_and_forget_started = asyncio.Event()

    class SeqPlugin(Plugin):
        async def prompt_pre_fetch(self, payload, context):
            phase_log.append("sequential")
            return PluginResult(continue_processing=True)

    class FnfPlugin(Plugin):
        async def prompt_pre_fetch(self, payload, context):
            fire_and_forget_started.set()
            phase_log.append("fire_and_forget")
            return PluginResult(continue_processing=True)

    manager = await _make_manager()
    cfg_seq = make_plugin_config("FnfSeq", PluginMode.SEQUENTIAL, priority=1)
    cfg_fnf = make_plugin_config("FnfFnf", PluginMode.FIRE_AND_FORGET, priority=1)
    plugin_seq = SeqPlugin(cfg_seq)
    plugin_fnf = FnfPlugin(cfg_fnf)

    ref_seq = HookRef(PromptHookType.PROMPT_PRE_FETCH, PluginRef(plugin_seq))
    ref_fnf = HookRef(PromptHookType.PROMPT_PRE_FETCH, PluginRef(plugin_fnf))

    with patch.object(manager._registry, "get_hook_refs_for_hook") as mock_get:
        mock_get.return_value = [ref_seq, ref_fnf]
        payload = PromptPrehookPayload(prompt_id="test", args={})
        global_context = GlobalContext(request_id="obs_order")

        result, _ = await manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, payload, global_context)

    # Pipeline has returned; sequential ran synchronously
    assert "sequential" in phase_log
    # FIRE_AND_FORGET has not yet completed (fire-and-forget)
    assert not fire_and_forget_started.is_set()

    await result.wait_for_background_tasks()
    assert "fire_and_forget" in phase_log
    # FIRE_AND_FORGET always comes after sequential in the log
    assert phase_log.index("sequential") < phase_log.index("fire_and_forget")

    await manager.shutdown()


# ---------------------------------------------------------------------------
# TRANSFORM mode tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_transform_chains_payload():
    """Each TRANSFORM plugin receives the chained output of the previous plugin."""

    received_payloads: list = []

    class ChainPlugin(Plugin):
        async def prompt_pre_fetch(self, payload, context):
            step = int(payload.args.get("step", "0"))
            received_payloads.append(step)
            new_payload = PromptPrehookPayload(prompt_id=payload.prompt_id, args={"step": str(step + 1)})
            return PluginResult(continue_processing=True, modified_payload=new_payload)

    manager = await _make_manager()
    cfg1 = make_plugin_config("XformChain1", PluginMode.TRANSFORM, priority=1)
    cfg2 = make_plugin_config("XformChain2", PluginMode.TRANSFORM, priority=2)
    plugin1 = ChainPlugin(cfg1)
    plugin2 = ChainPlugin(cfg2)

    ref1 = HookRef(PromptHookType.PROMPT_PRE_FETCH, PluginRef(plugin1))
    ref2 = HookRef(PromptHookType.PROMPT_PRE_FETCH, PluginRef(plugin2))

    with patch.object(manager._registry, "get_hook_refs_for_hook") as mock_get:
        mock_get.return_value = [ref1, ref2]
        payload = PromptPrehookPayload(prompt_id="test", args={"step": "0"})
        global_context = GlobalContext(request_id="xform1")

        with patch("cpex.framework.manager.settings") as mock_settings:
            mock_settings.execution_pool = None
            mock_settings.default_hook_policy = "allow"
            result, _ = await manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, payload, global_context)

    assert received_payloads == [0, 1]
    assert result.modified_payload is not None
    assert result.modified_payload.args["step"] == "2"

    await manager.shutdown()


@pytest.mark.asyncio
async def test_transform_cannot_halt_pipeline():
    """A TRANSFORM plugin returning continue_processing=False is suppressed."""

    call_order: list[str] = []

    class BlockingTransform(Plugin):
        async def prompt_pre_fetch(self, payload, context):
            call_order.append("blocker")
            return PluginResult(continue_processing=False)

    class AfterTransform(Plugin):
        async def prompt_pre_fetch(self, payload, context):
            call_order.append("after")
            return PluginResult(continue_processing=True)

    manager = await _make_manager()
    cfg1 = make_plugin_config("XformBlock", PluginMode.TRANSFORM, priority=1)
    cfg2 = make_plugin_config("XformAfter", PluginMode.TRANSFORM, priority=2)
    plugin1 = BlockingTransform(cfg1)
    plugin2 = AfterTransform(cfg2)

    ref1 = HookRef(PromptHookType.PROMPT_PRE_FETCH, PluginRef(plugin1))
    ref2 = HookRef(PromptHookType.PROMPT_PRE_FETCH, PluginRef(plugin2))

    with patch.object(manager._registry, "get_hook_refs_for_hook") as mock_get:
        mock_get.return_value = [ref1, ref2]
        payload = PromptPrehookPayload(prompt_id="test", args={})
        global_context = GlobalContext(request_id="xform2")

        result, _ = await manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, payload, global_context)

    # Pipeline was NOT halted — both plugins ran
    assert result.continue_processing
    assert call_order == ["blocker", "after"]

    await manager.shutdown()


@pytest.mark.asyncio
async def test_transform_executes_after_sequential_before_audit():
    """TRANSFORM phase runs between SEQUENTIAL and AUDIT."""

    call_order: list[str] = []

    class OrderPlugin(Plugin):
        async def prompt_pre_fetch(self, payload, context):
            call_order.append(self.name)
            return PluginResult(continue_processing=True)

    manager = await _make_manager()
    configs = [
        ("AuditP", PluginMode.AUDIT, 1),
        ("XformP", PluginMode.TRANSFORM, 1),
        ("SeqP", PluginMode.SEQUENTIAL, 1),
    ]
    refs = []
    for name, mode, prio in configs:
        cfg = make_plugin_config(name, mode, priority=prio)
        plugin = OrderPlugin(cfg)
        refs.append(HookRef(PromptHookType.PROMPT_PRE_FETCH, PluginRef(plugin)))

    with patch.object(manager._registry, "get_hook_refs_for_hook") as mock_get:
        mock_get.return_value = refs
        payload = PromptPrehookPayload(prompt_id="test", args={})
        global_context = GlobalContext(request_id="xform3")

        with patch("cpex.framework.manager.settings") as mock_settings:
            mock_settings.execution_pool = None
            mock_settings.default_hook_policy = "allow"
            result, _ = await manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, payload, global_context)

    assert call_order == ["SeqP", "XformP", "AuditP"]

    await manager.shutdown()


# ---------------------------------------------------------------------------
# Modification discard regression tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_modification_discarded():
    """AUDIT plugins that return modified_payload have their changes silently discarded."""

    class AuditModifier(Plugin):
        async def prompt_pre_fetch(self, payload, context):
            new_payload = PromptPrehookPayload(prompt_id=payload.prompt_id, args={"injected": "yes"})
            return PluginResult(continue_processing=True, modified_payload=new_payload)

    manager = await _make_manager()
    cfg = make_plugin_config("AuditMod", PluginMode.AUDIT, priority=1)
    plugin = AuditModifier(cfg)

    ref = HookRef(PromptHookType.PROMPT_PRE_FETCH, PluginRef(plugin))

    with patch.object(manager._registry, "get_hook_refs_for_hook") as mock_get:
        mock_get.return_value = [ref]
        payload = PromptPrehookPayload(prompt_id="test", args={"original": "yes"})
        global_context = GlobalContext(request_id="audit_mod")

        with patch("cpex.framework.manager.settings") as mock_settings:
            mock_settings.execution_pool = None
            mock_settings.default_hook_policy = "allow"
            result, _ = await manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, payload, global_context)

    # Payload should be unchanged — AUDIT cannot modify
    assert result.modified_payload is None

    await manager.shutdown()


@pytest.mark.asyncio
async def test_concurrent_modification_discarded():
    """CONCURRENT plugins that return modified_payload have their changes silently discarded."""

    class ConcModifier(Plugin):
        async def prompt_pre_fetch(self, payload, context):
            new_payload = PromptPrehookPayload(prompt_id=payload.prompt_id, args={"injected": "yes"})
            return PluginResult(continue_processing=True, modified_payload=new_payload)

    manager = await _make_manager()
    cfg = make_plugin_config("ConcMod", PluginMode.CONCURRENT, priority=1)
    plugin = ConcModifier(cfg)

    ref = HookRef(PromptHookType.PROMPT_PRE_FETCH, PluginRef(plugin))

    with patch.object(manager._registry, "get_hook_refs_for_hook") as mock_get:
        mock_get.return_value = [ref]
        payload = PromptPrehookPayload(prompt_id="test", args={"original": "yes"})
        global_context = GlobalContext(request_id="conc_mod")

        with patch("cpex.framework.manager.settings") as mock_settings:
            mock_settings.execution_pool = None
            mock_settings.default_hook_policy = "allow"
            result, _ = await manager.invoke_hook(PromptHookType.PROMPT_PRE_FETCH, payload, global_context)

    # Payload should be unchanged — CONCURRENT cannot modify
    assert result.modified_payload is None

    await manager.shutdown()
