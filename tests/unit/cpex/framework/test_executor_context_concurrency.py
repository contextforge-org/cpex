# -*- coding: utf-8 -*-
"""Location: ./tests/unit/cpex/framework/test_executor_context_concurrency.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0

Concurrency cross-talk tests for the per-call ExecutionContext refactor.

The PluginExecutor used to keep per-request scratch state on instance attributes
(_max_retry_delay_ms, _hook_chain_executed/skipped/stopped_by/span_id). Because
the executor is held by a Borg-singleton PluginManager and shared across
concurrent dispatches, that state was racy: a second execute() would clobber a
first execute()'s counters and span id. After the refactor, all per-call state
lives on a stack-local ExecutionContext threaded through the call stack, so
concurrent invocations cannot cross-contaminate.
"""

# Standard
import asyncio
import itertools
import uuid
from typing import Any, Dict, List, Optional, Tuple
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
    PluginViolation,
    PromptHookType,
    PromptPrehookPayload,
)

# First-Party
from cpex.framework.base import HookRef
from cpex.framework.observability import current_trace_id
from cpex.framework.registry import PluginRef


def _cfg(name: str, mode: PluginMode = PluginMode.SEQUENTIAL) -> PluginConfig:
    return PluginConfig(
        name=name,
        description="test",
        author="test",
        version="1.0",
        kind="test.Plugin",
        mode=mode,
        on_error=OnError.FAIL,
        hooks=["prompt_pre_fetch"],
        tags=[],
        priority=100,
    )


async def _make_manager() -> PluginManager:
    manager = PluginManager("./tests/unit/cpex/fixtures/configs/valid_no_plugin.yaml")
    await manager.initialize()
    return manager


class _RecordingObservability:
    """Captures (start_span, end_span) calls keyed by the span_id we mint."""

    def __init__(self) -> None:
        self._counter = itertools.count()
        self.starts: Dict[str, Dict[str, Any]] = {}
        self.ends: Dict[str, Tuple[str, Dict[str, Any]]] = {}

    def start_span(
        self,
        trace_id: str,
        name: str,
        kind: str = "internal",
        resource_type: Optional[str] = None,
        resource_name: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        span_id = f"span-{next(self._counter)}"
        self.starts[span_id] = {
            "trace_id": trace_id,
            "name": name,
            "attributes": dict(attributes or {}),
        }
        return span_id

    def end_span(
        self,
        span_id: Optional[str],
        status: str = "ok",
        attributes: Optional[Dict[str, Any]] = None,
    ) -> None:
        if span_id is None:
            return
        self.ends[span_id] = (status, dict(attributes or {}))


@pytest.mark.asyncio
async def test_concurrent_executes_have_isolated_retry_delay():
    """Two concurrent invokes must each return their own plugin's retry_delay_ms.

    Before the refactor, both calls shared self._max_retry_delay_ms; under
    interleaving the second call's reset (= 0) or max() update could leak into
    the first call's return value. With ExecutionContext per call this is safe.
    """

    barrier = asyncio.Event()

    class DelayPlugin(Plugin):
        def __init__(self, cfg: PluginConfig, delay_ms: int) -> None:
            super().__init__(cfg)
            self._delay = delay_ms

        async def prompt_pre_fetch(self, payload, context):
            # Force interleaving: every plugin parks at the barrier before returning
            await barrier.wait()
            return PluginResult(continue_processing=True, retry_delay_ms=self._delay)

    manager = await _make_manager()
    delays = [50, 200, 400, 800, 1600]
    plugins = [DelayPlugin(_cfg(f"D{i}"), d) for i, d in enumerate(delays)]
    hook_refs = [HookRef(PromptHookType.PROMPT_PRE_FETCH, PluginRef(p)) for p in plugins]

    async def run_one(hook_ref: HookRef) -> int:
        with patch.object(manager._registry, "get_hook_refs_for_hook", return_value=[hook_ref]):
            result, _ = await manager.invoke_hook(
                PromptHookType.PROMPT_PRE_FETCH,
                PromptPrehookPayload(prompt_id="p", args={}),
                GlobalContext(request_id=str(uuid.uuid4())),
            )
            return result.retry_delay_ms

    # Schedule all five executes; release them all at once so they interleave.
    tasks = [asyncio.create_task(run_one(hr)) for hr in hook_refs]
    await asyncio.sleep(0)  # let tasks reach the barrier
    barrier.set()
    returned = await asyncio.gather(*tasks)

    # Each call must report its own delay, in input order.
    assert returned == delays

    await manager.shutdown()


@pytest.mark.asyncio
async def test_concurrent_executes_have_isolated_hook_chain_spans():
    """Each concurrent execute() must produce its own span with counters that
    reflect only its own plugins, not the union of overlapping calls."""

    obs = _RecordingObservability()
    manager = await _make_manager()
    manager.observability = obs

    barrier = asyncio.Event()

    class StopPlugin(Plugin):
        async def prompt_pre_fetch(self, payload, context):
            await barrier.wait()
            return PluginResult(
                continue_processing=False,
                violation=PluginViolation(reason="halt", description="halt", code="HALT", details={}),
            )

    class PassPlugin(Plugin):
        async def prompt_pre_fetch(self, payload, context):
            await barrier.wait()
            return PluginResult(continue_processing=True)

    halting = StopPlugin(_cfg("Stopper"))
    passing = PassPlugin(_cfg("Passer"))
    hr_halt = HookRef(PromptHookType.PROMPT_PRE_FETCH, PluginRef(halting))
    hr_pass = HookRef(PromptHookType.PROMPT_PRE_FETCH, PluginRef(passing))

    async def run_with_trace(hook_ref: HookRef, trace: str) -> None:
        token = current_trace_id.set(trace)
        try:
            with patch.object(manager._registry, "get_hook_refs_for_hook", return_value=[hook_ref]):
                await manager.invoke_hook(
                    PromptHookType.PROMPT_PRE_FETCH,
                    PromptPrehookPayload(prompt_id="p", args={}),
                    GlobalContext(request_id="r"),
                )
        finally:
            current_trace_id.reset(token)

    tasks = [
        asyncio.create_task(run_with_trace(hr_halt, "trace-halt")),
        asyncio.create_task(run_with_trace(hr_pass, "trace-pass")),
    ]
    await asyncio.sleep(0)
    barrier.set()
    await asyncio.gather(*tasks)

    # Each invoke produced its own span. Find them by trace_id.
    halt_span = next(sid for sid, info in obs.starts.items() if info["trace_id"] == "trace-halt")
    pass_span = next(sid for sid, info in obs.starts.items() if info["trace_id"] == "trace-pass")
    assert halt_span != pass_span

    # The halting span attributes attribute the stop to "Stopper" only.
    _, halt_attrs = obs.ends[halt_span]
    assert halt_attrs["plugin.chain.stopped"] is True
    assert halt_attrs["plugin.chain.stopped_by"] == "Stopper"
    assert halt_attrs["plugin.executed_count"] == 1

    # The passing span attributes do NOT carry "Stopper" — it never ran in that chain.
    _, pass_attrs = obs.ends[pass_span]
    assert pass_attrs["plugin.chain.stopped"] is False
    assert pass_attrs["plugin.chain.stopped_by"] == ""
    assert pass_attrs["plugin.executed_count"] == 1

    await manager.shutdown()


@pytest.mark.asyncio
async def test_many_concurrent_executes_independent_counts():
    """Soak: 50 concurrent invokes, each with two plugins. Every span must
    report executed_count=2 — no double-counting, no lost increments."""

    obs = _RecordingObservability()
    manager = await _make_manager()
    manager.observability = obs

    class Pass(Plugin):
        async def prompt_pre_fetch(self, payload, context):
            # tiny await to encourage interleaving across event loop
            await asyncio.sleep(0)
            return PluginResult(continue_processing=True)

    async def one_invoke(idx: int) -> None:
        a = Pass(_cfg(f"A{idx}"))
        b = Pass(_cfg(f"B{idx}"))
        refs: List[HookRef] = [
            HookRef(PromptHookType.PROMPT_PRE_FETCH, PluginRef(a)),
            HookRef(PromptHookType.PROMPT_PRE_FETCH, PluginRef(b)),
        ]
        token = current_trace_id.set(f"trace-{idx}")
        try:
            with patch.object(manager._registry, "get_hook_refs_for_hook", return_value=refs):
                await manager.invoke_hook(
                    PromptHookType.PROMPT_PRE_FETCH,
                    PromptPrehookPayload(prompt_id="p", args={}),
                    GlobalContext(request_id=f"r{idx}"),
                )
        finally:
            current_trace_id.reset(token)

    await asyncio.gather(*(one_invoke(i) for i in range(50)))

    # Filter to hook-chain spans only (per-plugin spans are also recorded but irrelevant here).
    chain_span_ids = {sid for sid, info in obs.starts.items() if info["name"] == "plugin.hook.invoke"}
    assert len(chain_span_ids) == 50
    for sid in chain_span_ids:
        _status, attrs = obs.ends[sid]
        assert attrs["plugin.executed_count"] == 2
        assert attrs["plugin.chain.stopped"] is False
        assert attrs["plugin.chain.stopped_by"] == ""

    await manager.shutdown()
