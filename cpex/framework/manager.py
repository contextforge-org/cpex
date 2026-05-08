# -*- coding: utf-8 -*-
"""Location: ./cpex/framework/manager.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Teryl Taylor, Mihai Criveti, Fred Araujo

Plugin manager.
Module that manages and calls plugins at hookpoints throughout the gateway.

This module provides the core plugin management functionality including:
- Plugin lifecycle management (initialization, execution, shutdown)
- Timeout protection for plugin execution
- Context management with automatic cleanup
- Priority-based plugin ordering
- Conditional plugin execution based on prompts/servers/tenants

Examples:
    >>> # Initialize plugin manager with configuration
    >>> manager = PluginManager("plugins/config.yaml")
    >>> # await manager.initialize()  # Called in async context

    >>> # Create test payload and context
    >>> from cpex.framework.models import GlobalContext
    >>> from cpex.framework.hooks.prompts import PromptPrehookPayload
    >>> payload = PromptPrehookPayload(prompt_id="123", name="test", args={"user": "input"})
    >>> context = GlobalContext(request_id="123")
    >>> # result, contexts = await manager.prompt_pre_fetch(payload, context)  # Called in async context
"""

# Standard
import asyncio
import logging
import threading
from dataclasses import dataclass
from typing import Any, Literal, Optional, Union

# Third-Party
from pydantic import BaseModel, RootModel

# First-Party
from cpex.framework.base import HookRef, Plugin
from cpex.framework.constants import EXTERNAL_PLUGIN_TYPE
from cpex.framework.errors import PluginError, PluginViolationError, convert_exception_to_error
from cpex.framework.extensions.extensions import Extensions
from cpex.framework.extensions.tiers import filter_extensions
from cpex.framework.hooks.policies import DefaultHookPolicy, HookPayloadPolicy, apply_policy
from cpex.framework.loader.config import ConfigLoader
from cpex.framework.loader.plugin import PluginLoader
from cpex.framework.memory import _safe_deepcopy, copyonwrite, wrap_payload_for_isolation
from cpex.framework.models import (
    Config,
    GlobalContext,
    OnError,
    PluginContext,
    PluginContextTable,
    PluginErrorModel,
    PluginMode,
    PluginPayload,
    PluginResult,
)
from cpex.framework.observability import ObservabilityProvider, current_trace_id
from cpex.framework.registry import PluginInstanceRegistry
from cpex.framework.settings import settings
from cpex.framework.utils import payload_matches

# Use standard logging to avoid circular imports (plugins -> services -> plugins)
logger = logging.getLogger(__name__)

# Configuration constants
DEFAULT_PLUGIN_TIMEOUT = 30  # seconds
MAX_PAYLOAD_SIZE = 1_000_000  # 1MB
CONTEXT_CLEANUP_INTERVAL = 300  # 5 minutes
CONTEXT_MAX_AGE = 3600  # 1 hour
HTTP_AUTH_CHECK_PERMISSION_HOOK = "http_auth_check_permission"

# Metadata constants
DECISION_PLUGIN_METADATA_KEY = "_decision_plugin"
RESERVED_INTERNAL_METADATA_KEYS = frozenset({DECISION_PLUGIN_METADATA_KEY})


@dataclass
class ExecutionContext:
    """Per-call mutable state for one PluginExecutor.execute() invocation.

    Attributes:
        max_retry_delay_ms: Largest retry delay requested by any plugin in the
            chain. Returned to the caller via PluginResult.retry_delay_ms.
        hook_chain_executed: Count of plugins that ran (used for observability).
        hook_chain_skipped: Count of plugins that were skipped (statically
            disabled, runtime-disabled, or conditions unmet).
        hook_chain_stopped_by: Name of the plugin that halted the pipeline,
            or None if the chain ran to completion.
        hook_chain_span_id: Observability span id for the hook-chain span,
            or None if observability is unavailable.
    """

    max_retry_delay_ms: int = 0
    hook_chain_executed: int = 0
    hook_chain_skipped: int = 0
    hook_chain_stopped_by: Optional[str] = None
    hook_chain_span_id: Optional[str] = None


@dataclass
class PhaseState:
    """State accumulated during a serial execution phase.

    Replaces the nested tuple return type from _run_serial_phase,
    improving readability and self-documentation.

    Attributes:
        payload: The current effective payload (may be modified by plugins).
        decision_plugin: Name of the last plugin that modified the payload.
        extensions: The current extensions (may be modified by plugins).
    """

    payload: Optional[PluginPayload] = None
    decision_plugin: Optional[str] = None
    extensions: Optional[Extensions] = None


class PluginTimeoutError(Exception):
    """Raised when a plugin execution exceeds the timeout limit."""


class PayloadSizeError(ValueError):
    """Raised when a payload exceeds the maximum allowed size."""


class PluginExecutor:
    """Executes a list of plugins with timeout protection and error handling.

    This class manages the execution of plugins in priority order, handling:
    - Timeout protection for each plugin
    - Context management between plugins
    - Error isolation to prevent plugin failures from affecting the gateway
    - Metadata aggregation from multiple plugins

    Examples:
        >>> executor = PluginExecutor()
        >>> # In async context:
        >>> # result, contexts = await executor.execute(
        >>> #     plugins=[plugin1, plugin2],
        >>> #     payload=payload,
        >>> #     global_context=context,
        >>> #     plugin_run=pre_prompt_fetch,
        >>> #     compare=pre_prompt_matches
        >>> # )
    """

    def __init__(
        self,
        config: Optional[Config] = None,
        timeout: int = DEFAULT_PLUGIN_TIMEOUT,
        observability: Optional[ObservabilityProvider] = None,
        hook_policies: Optional[dict[str, HookPayloadPolicy]] = None,
        default_hook_policy: Optional[Literal["allow", "deny"]] = None,
    ):
        """Initialize the plugin executor.

        Args:
            config: the plugin manager configuration.
            timeout: Maximum execution time per plugin in seconds.
            observability: Optional observability provider implementing ObservabilityProvider protocol.
            hook_policies: Per-hook-type payload modification policies.
            default_hook_policy: Fallback hook policy ("allow", "denied") when a policy is not specified
                for a hook type (overrides `settings.default_hook_policy`).
        """
        self.timeout = timeout
        self.config = config
        self.observability = observability
        self.hook_policies: dict[str, HookPayloadPolicy] = hook_policies or {}
        self.default_hook_policy = DefaultHookPolicy(
            default_hook_policy if default_hook_policy else settings.default_hook_policy
        )
        # Persistent-per-executor: plugins that hit OnError.DISABLE stay out of rotation
        # for the lifetime of this executor. Multi-tenant isolation is provided by
        # TenantPluginManager (each tenant owns its own executor). Mutations are guarded
        # by _runtime_disabled_lock; the membership read in _group_by_mode is unguarded
        # because set.__contains__ is atomic under the GIL.
        self._runtime_disabled: set[str] = set()
        self._runtime_disabled_lock = asyncio.Lock()

    async def execute(
        self,
        hook_refs: list[HookRef],
        payload: PluginPayload,
        global_context: GlobalContext,
        hook_type: str,
        local_contexts: Optional[PluginContextTable] = None,
        violations_as_exceptions: bool = False,
        extensions: Optional[Extensions] = None,
    ) -> tuple[PluginResult, PluginContextTable | None]:
        """Execute plugins in priority order with timeout protection.

        Args:
            hook_refs: List of hook references to execute, sorted by priority.
            payload: The payload to be processed by plugins.
            global_context: Shared context for all plugins containing request metadata.
            hook_type: The hook type identifier (e.g., "tool_pre_invoke").
            local_contexts: Optional existing contexts from previous hook executions.
            violations_as_exceptions: Raise violations as exceptions rather than as returns.
            extensions: Optional extensions to filter and pass to plugins that accept them.

        Returns:
            A tuple containing:
            - PluginResult with processing status, modified payload, and metadata
            - PluginContextTable with updated local contexts for each plugin

        Raises:
            PayloadSizeError: If the payload exceeds MAX_PAYLOAD_SIZE.
            PluginError: If there is an error inside a plugin.
            PluginViolationError: If a violation occurs and violation_as_exceptions is set.

        Examples:
            >>> # Execute plugins with timeout protection
            >>> from cpex.framework.hooks.prompts import PromptHookType
            >>> executor = PluginExecutor(timeout=30)
            >>> # Assuming you have a registry instance:
            >>> # plugins = registry.get_plugins_for_hook(PromptHookType.PROMPT_PRE_FETCH)
            >>> # In async context:
            >>> # result, contexts = await executor.execute(
            >>> #     plugins=plugins,
            >>> #     payload=PromptPrehookPayload(prompt_id="123", name="test", args={}),
            >>> #     global_context=GlobalContext(request_id="123"),
            >>> #     plugin_run=pre_prompt_fetch,
            >>> #     compare=pre_prompt_matches
            >>> # )
        """
        if not hook_refs:
            return (PluginResult(modified_payload=None), None)

        # Validate payload size
        self._validate_payload_size(payload)

        # Look up the policy for this hook type (may be None)
        policy = self.hook_policies.get(hook_type)

        res_local_contexts = {}
        combined_metadata: dict[str, Any] = {}
        current_payload: PluginPayload | None = None
        current_extensions: Extensions | None = None
        decision_plugin_name: Optional[str] = None
        ctx = ExecutionContext()

        # Start hook-chain observability span
        trace_id = current_trace_id.get()
        if trace_id and self.observability:
            try:
                ctx.hook_chain_span_id = self.observability.start_span(
                    trace_id=trace_id,
                    name="plugin.hook.invoke",
                    kind="internal",
                    attributes={
                        "plugin.hook.type": hook_type,
                        "plugin.chain.length": len(hook_refs),
                    },
                )
            except Exception as e:
                logger.debug("Hook-chain observability start_span failed: %s", e)

        sequential_refs, transform_refs, audit_refs, concurrent_refs, fire_and_forget_refs = self._group_by_mode(
            hook_refs, payload, hook_type, global_context, ctx
        )

        # Independent semaphores prevent one mode from starving the other
        pool = int(settings.execution_pool) if settings.execution_pool else None
        fire_and_forget_semaphore = asyncio.Semaphore(pool) if pool else None
        concurrent_semaphore = asyncio.Semaphore(pool) if pool else None

        # SEQUENTIAL: sequential, chained execution — can halt pipeline
        halt_result, phase = await self._run_serial_phase(
            hook_refs=sequential_refs,
            mode_label="SEQUENTIAL",
            payload=payload,
            policy=policy,
            hook_type=hook_type,
            global_context=global_context,
            local_contexts=local_contexts,
            res_local_contexts=res_local_contexts,
            violations_as_exceptions=violations_as_exceptions,
            combined_metadata=combined_metadata,
            current_payload=current_payload,
            decision_plugin_name=decision_plugin_name,
            apply_modifications=True,
            allow_blocking=True,
            ctx=ctx,
            current_extensions=current_extensions,
            fire_and_forget_refs=fire_and_forget_refs,
            fire_and_forget_semaphore=fire_and_forget_semaphore,
            extensions=extensions,
        )
        current_payload = phase.payload
        decision_plugin_name = phase.decision_plugin
        current_extensions = phase.extensions
        if halt_result is not None:
            self._end_hook_chain_span(ctx, status="ok")
            return halt_result

        # TRANSFORM: serial, chained execution — can modify payloads but cannot halt pipeline
        _, phase = await self._run_serial_phase(
            hook_refs=transform_refs,
            mode_label="TRANSFORM",
            payload=payload,
            policy=policy,
            hook_type=hook_type,
            global_context=global_context,
            local_contexts=local_contexts,
            res_local_contexts=res_local_contexts,
            violations_as_exceptions=violations_as_exceptions,
            combined_metadata=combined_metadata,
            current_payload=current_payload,
            decision_plugin_name=decision_plugin_name,
            apply_modifications=True,
            allow_blocking=False,
            ctx=ctx,
            current_extensions=current_extensions,
            extensions=extensions,
        )
        current_payload = phase.payload
        decision_plugin_name = phase.decision_plugin
        current_extensions = phase.extensions

        # AUDIT: serial execution — observe-only (no modifications, no blocking)
        _, phase = await self._run_serial_phase(
            hook_refs=audit_refs,
            mode_label="AUDIT",
            payload=payload,
            policy=policy,
            hook_type=hook_type,
            global_context=global_context,
            local_contexts=local_contexts,
            res_local_contexts=res_local_contexts,
            violations_as_exceptions=violations_as_exceptions,
            combined_metadata=combined_metadata,
            current_payload=current_payload,
            decision_plugin_name=decision_plugin_name,
            apply_modifications=False,
            allow_blocking=False,
            ctx=ctx,
            current_extensions=current_extensions,
            extensions=extensions,
        )

        # CONCURRENT: parallel execution with fail-fast on first blocking result
        if concurrent_refs:
            concurrent_ctx_list: list[tuple[HookRef, PluginContext, PluginPayload]] = []
            concurrent_tasks: list[asyncio.Task] = []
            effective_payload = current_payload if current_payload is not None else payload
            for ref in concurrent_refs:
                plugin_input = self._isolate_payload(effective_payload, policy)
                local_context = self._prepare_plugin_context(ref, global_context, local_contexts, res_local_contexts)
                idx = len(concurrent_ctx_list)
                concurrent_ctx_list.append((ref, local_context, effective_payload))
                coro = self.execute_plugin(
                    ref,
                    plugin_input,
                    local_context,
                    violations_as_exceptions,
                    global_context,
                    combined_metadata,
                    extensions=extensions,
                )
                if concurrent_semaphore:
                    coro = self._with_semaphore(concurrent_semaphore, coro)
                concurrent_tasks.append(asyncio.create_task(self._tagged(coro, idx)))

            for completed_coro in asyncio.as_completed(concurrent_tasks):
                result, idx = await completed_coro
                ref, _, _ = concurrent_ctx_list[idx]
                ctx.hook_chain_executed += 1
                # Propagate retry signal from concurrent plugins
                ctx.max_retry_delay_ms = max(ctx.max_retry_delay_ms, result.retry_delay_ms)
                if result.modified_payload is not None:
                    logger.debug(
                        "CONCURRENT plugin %s returned modified_payload on hook %s; "
                        "discarding (concurrent plugins cannot modify payloads)",
                        ref.plugin_ref.name,
                        hook_type,
                    )
                if not result.continue_processing:
                    pending = sum(1 for t in concurrent_tasks if not t.done())
                    violation_detail = (
                        f": [{result.violation.code}] {result.violation.reason}" if result.violation else ""
                    )
                    logger.warning(
                        "Pipeline halted by CONCURRENT plugin %s on hook %s%s; cancelling %d pending task(s)",
                        ref.plugin_ref.name,
                        hook_type,
                        violation_detail,
                        pending,
                    )
                    for task in concurrent_tasks:
                        if not task.done():
                            task.cancel()
                    await asyncio.gather(*concurrent_tasks, return_exceptions=True)
                    ctx.hook_chain_stopped_by = ref.plugin_ref.name
                    halt = self._build_halt_result(
                        current_payload,
                        result.violation,
                        combined_metadata,
                        fire_and_forget_refs,
                        payload,
                        global_context,
                        res_local_contexts,
                        fire_and_forget_semaphore,
                        hook_type,
                        decision_plugin_name,
                        extensions=extensions,
                    )
                    self._end_hook_chain_span(ctx, status="ok")
                    return halt

        # FIRE_AND_FORGET: fire-and-forget background tasks (fires last with final payload snapshot)
        bg_tasks = self._fire_and_forget_tasks(
            fire_and_forget_refs,
            payload,
            global_context,
            res_local_contexts,
            fire_and_forget_semaphore,
            extensions=extensions,
        )

        if hook_type == HTTP_AUTH_CHECK_PERMISSION_HOOK and decision_plugin_name:
            combined_metadata[DECISION_PLUGIN_METADATA_KEY] = decision_plugin_name

        self._end_hook_chain_span(ctx, status="ok")

        return (
            PluginResult(
                continue_processing=True,
                modified_payload=current_payload,
                modified_extensions=current_extensions,
                violation=None,
                metadata=combined_metadata,
                background_tasks=bg_tasks,
                retry_delay_ms=ctx.max_retry_delay_ms,
            ),
            res_local_contexts,
        )

    def _group_by_mode(
        self,
        hook_refs: list[HookRef],
        payload: PluginPayload,
        hook_type: str,
        global_context: GlobalContext,
        ctx: ExecutionContext,
    ) -> tuple[list[HookRef], list[HookRef], list[HookRef], list[HookRef], list[HookRef]]:
        """Group hook references by mode, filtering disabled and condition-unmatched plugins.

        Args:
            hook_refs: All hook references to evaluate.
            payload: The current payload (used for condition matching).
            hook_type: The hook type identifier.
            global_context: Shared context for condition evaluation.
            ctx: Per-call execution context; skip count is accumulated here.

        Returns:
            A tuple of (sequential_refs, transform_refs, audit_refs, concurrent_refs,
            fire_and_forget_refs), each sorted by priority.
        """
        sequential_refs: list[HookRef] = []
        transform_refs: list[HookRef] = []
        audit_refs: list[HookRef] = []
        concurrent_refs: list[HookRef] = []
        fire_and_forget_refs: list[HookRef] = []

        for ref in hook_refs:
            # Skip statically disabled plugins
            if ref.plugin_ref.mode == PluginMode.DISABLED:
                logger.debug("Skipping plugin %s — statically disabled", ref.plugin_ref.name)
                ctx.hook_chain_skipped += 1
                continue
            # Skip runtime-disabled plugins
            if ref.plugin_ref.name in self._runtime_disabled:
                logger.debug("Skipping plugin %s — runtime-disabled after previous error", ref.plugin_ref.name)
                ctx.hook_chain_skipped += 1
                continue
            # Check conditions
            if ref.plugin_ref.conditions and not payload_matches(
                payload, hook_type, ref.plugin_ref.conditions, global_context
            ):
                logger.debug("Skipping plugin %s - conditions not met", ref.plugin_ref.name)
                ctx.hook_chain_skipped += 1
                continue
            # Bucket by mode
            if ref.plugin_ref.mode == PluginMode.SEQUENTIAL:
                sequential_refs.append(ref)
            elif ref.plugin_ref.mode == PluginMode.TRANSFORM:
                transform_refs.append(ref)
            elif ref.plugin_ref.mode == PluginMode.AUDIT:
                audit_refs.append(ref)
            elif ref.plugin_ref.mode == PluginMode.CONCURRENT:
                concurrent_refs.append(ref)
            elif ref.plugin_ref.mode == PluginMode.FIRE_AND_FORGET:
                fire_and_forget_refs.append(ref)

        sequential_refs.sort(key=lambda r: r.plugin_ref.priority)
        transform_refs.sort(key=lambda r: r.plugin_ref.priority)
        audit_refs.sort(key=lambda r: r.plugin_ref.priority)
        concurrent_refs.sort(key=lambda r: r.plugin_ref.priority)
        fire_and_forget_refs.sort(key=lambda r: r.plugin_ref.priority)

        return sequential_refs, transform_refs, audit_refs, concurrent_refs, fire_and_forget_refs

    def _end_hook_chain_span(self, ctx: ExecutionContext, status: str = "ok") -> None:
        """End the hook-chain observability span with accumulated counters."""
        if ctx.hook_chain_span_id is not None and self.observability:
            try:
                self.observability.end_span(
                    span_id=ctx.hook_chain_span_id,
                    status=status,
                    attributes={
                        "plugin.executed_count": ctx.hook_chain_executed,
                        "plugin.skipped_count": ctx.hook_chain_skipped,
                        "plugin.chain.stopped": ctx.hook_chain_stopped_by is not None,
                        "plugin.chain.stopped_by": ctx.hook_chain_stopped_by or "",
                    },
                )
            except Exception as e:
                logger.debug("Hook-chain observability end_span failed: %s", e)
            ctx.hook_chain_span_id = None

    async def _run_serial_phase(
        self,
        hook_refs: list[HookRef],
        mode_label: str,
        payload: PluginPayload,
        policy: Any,
        hook_type: str,
        global_context: GlobalContext,
        local_contexts: Optional[PluginContextTable],
        res_local_contexts: dict,
        violations_as_exceptions: bool,
        combined_metadata: dict[str, Any],
        current_payload: Optional[PluginPayload],
        decision_plugin_name: Optional[str],
        apply_modifications: bool,
        allow_blocking: bool,
        ctx: ExecutionContext,
        current_extensions: Optional[Extensions] = None,
        fire_and_forget_refs: Optional[list[HookRef]] = None,
        fire_and_forget_semaphore: Optional[asyncio.Semaphore] = None,
        extensions: Optional[Extensions] = None,
    ) -> tuple[
        Optional[tuple[PluginResult, PluginContextTable | None]],
        PhaseState,
    ]:
        """Run a serial execution phase (SEQUENTIAL, TRANSFORM, or AUDIT).

        Args:
            hook_refs: Hook references to execute in priority order.
            mode_label: Human-readable mode name for log messages.
            payload: The original (unmodified) payload.
            policy: Hook payload policy for field filtering.
            hook_type: The hook type identifier.
            global_context: Shared context for all plugins.
            local_contexts: Existing contexts from previous hook executions.
            res_local_contexts: Accumulator for local contexts produced in this execution.
            violations_as_exceptions: Whether to raise violations as exceptions.
            combined_metadata: Accumulator for plugin metadata.
            current_payload: The current effective payload (may be None).
            decision_plugin_name: Name of the plugin that last modified the payload.
            apply_modifications: Whether to apply payload modifications from plugins.
            allow_blocking: Whether plugins can halt the pipeline.
            ctx: Per-call execution context; counters and stop reason accumulate here.
            fire_and_forget_refs: Fire-and-forget refs to schedule on halt (only used when allow_blocking=True).
            fire_and_forget_semaphore: Semaphore for fire-and-forget tasks (only used when allow_blocking=True).

        Returns:
            A tuple of (halt_result, phase_state). halt_result is None if pipeline continues.
        """
        for hook_ref in hook_refs:
            local_context = self._prepare_plugin_context(hook_ref, global_context, local_contexts, res_local_contexts)
            effective_payload = current_payload if current_payload is not None else payload
            plugin_input = self._isolate_payload(effective_payload, policy)

            result = await self.execute_plugin(
                hook_ref,
                plugin_input,
                local_context,
                violations_as_exceptions,
                global_context,
                combined_metadata,
                extensions=extensions,
            )
            ctx.hook_chain_executed += 1

            # Propagate retry signal — take the largest delay requested by any plugin
            ctx.max_retry_delay_ms = max(ctx.max_retry_delay_ms, result.retry_delay_ms)

            if result.modified_payload is not None:
                if apply_modifications:
                    current_payload, decision_plugin_name = self._apply_payload_modification(
                        hook_ref,
                        result,
                        plugin_input,
                        policy,
                        hook_type,
                        current_payload,
                        decision_plugin_name,
                        apply_to=effective_payload,
                    )
                else:
                    logger.debug(
                        "%s plugin %s returned modified_payload on hook %s; discarding (%s is observe-only)",
                        mode_label,
                        hook_ref.plugin_ref.name,
                        hook_type,
                        mode_label.lower(),
                    )

            # Accumulate modified_extensions (last writer wins)
            if result.modified_extensions is not None:
                current_extensions = result.modified_extensions

            if not result.continue_processing:
                violation_detail = f": [{result.violation.code}] {result.violation.reason}" if result.violation else ""
                if allow_blocking:
                    logger.warning(
                        "Pipeline halted by %s plugin %s on hook %s%s; scheduling fire-and-forget tasks",
                        mode_label,
                        hook_ref.plugin_ref.name,
                        hook_type,
                        violation_detail,
                    )
                    ctx.hook_chain_stopped_by = hook_ref.plugin_ref.name
                    state = PhaseState(
                        payload=current_payload, decision_plugin=decision_plugin_name, extensions=current_extensions
                    )
                    halt = self._build_halt_result(
                        current_payload,
                        result.violation,
                        combined_metadata,
                        fire_and_forget_refs or [],
                        payload,
                        global_context,
                        res_local_contexts,
                        fire_and_forget_semaphore,
                        hook_type,
                        decision_plugin_name,
                        extensions=extensions,
                    )
                    return halt, state
                else:
                    logger.warning(
                        "%s plugin %s returned continue_processing=False on hook %s%s; "
                        "pipeline continues (blocking suppressed)",
                        mode_label,
                        hook_ref.plugin_ref.name,
                        hook_type,
                        violation_detail,
                    )

        return None, PhaseState(
            payload=current_payload, decision_plugin=decision_plugin_name, extensions=current_extensions
        )

    def _apply_payload_modification(
        self,
        hook_ref: HookRef,
        result: PluginResult,
        effective_payload: PluginPayload,
        policy: Any,
        hook_type: str,
        current_payload: Optional[PluginPayload],
        decision_plugin_name: Optional[str],
        *,
        apply_to: Optional[PluginPayload] = None,
    ) -> tuple[Optional[PluginPayload], Optional[str]]:
        """Apply a plugin's payload modification, respecting the hook policy.

        Args:
            effective_payload: The baseline payload the plugin received (may be
                an isolated/CoW copy).  Used for diffing to detect changes.
            apply_to: The canonical pipeline payload to merge accepted changes
                into.  When ``None``, changes are applied to *effective_payload*.

        Returns:
            Updated (current_payload, decision_plugin_name) tuple.
        """
        if policy:
            if isinstance(result.modified_payload, type(effective_payload)) and isinstance(
                effective_payload, BaseModel
            ):
                # Same-type BaseModel payload — apply field-level policy filtering
                filtered = apply_policy(effective_payload, result.modified_payload, policy, apply_to=apply_to)
                if filtered is not None:
                    return filtered, hook_ref.plugin_ref.name
            else:
                # Cross-type payload — guard: only accept PluginPayload subtypes or dict
                if isinstance(result.modified_payload, (PluginPayload, dict)):
                    logger.debug(
                        "Plugin %s returned cross-type payload (%s -> %s) on hook %s; accepting without field filtering",
                        hook_ref.plugin_ref.name,
                        type(effective_payload).__name__,
                        type(result.modified_payload).__name__,
                        hook_type,
                    )
                    return result.modified_payload, hook_ref.plugin_ref.name
                else:
                    logger.warning(
                        "Plugin %s returned unexpected type %s on hook %s; ignoring modification",
                        hook_ref.plugin_ref.name,
                        type(result.modified_payload).__name__,
                        hook_type,
                    )
        elif self.default_hook_policy == DefaultHookPolicy.ALLOW:
            # No explicit policy + default=allow -- accept all modifications
            return result.modified_payload, hook_ref.plugin_ref.name
        else:
            # No explicit policy + default=deny -- reject all modifications
            logger.warning(
                "Plugin %s attempted payload modification on hook %s but no policy is defined and default is deny",
                hook_ref.plugin_ref.name,
                hook_type,
            )
        return current_payload, decision_plugin_name

    def _prepare_plugin_context(
        self,
        hook_ref: HookRef,
        global_context: GlobalContext,
        local_contexts: Optional[PluginContextTable],
        res_local_contexts: dict,
    ) -> PluginContext:
        """Create an isolated GlobalContext copy and resolve or create the PluginContext.

        The resolved context is stored in *res_local_contexts* as a side effect.
        """
        local_context_key = global_context.request_id + hook_ref.plugin_ref.uuid
        tmp_gc = GlobalContext(
            request_id=global_context.request_id,
            user=global_context.user,
            user_context=global_context.user_context,
            tenant_id=global_context.tenant_id,
            server_id=global_context.server_id,
            content_type=global_context.content_type,
            state={} if not global_context.state else copyonwrite(global_context.state),
            metadata={} if not global_context.metadata else copyonwrite(global_context.metadata),
        )
        if local_contexts and local_context_key in local_contexts:
            local_context = local_contexts[local_context_key]
            local_context.global_context = tmp_gc
        else:
            local_context = PluginContext(global_context=tmp_gc)
        res_local_contexts[local_context_key] = local_context
        return local_context

    def _isolate_payload(
        self,
        effective_payload: PluginPayload,
        policy: Any,
    ) -> PluginPayload:
        """Return an isolated copy of the payload when policy or defaults demand it.

        Copy-on-write wrapping is used for BaseModel payloads; other types are deep-copied.
        When no isolation is required the original payload is returned as-is.
        """
        needs_isolation = (
            policy or self.default_hook_policy == DefaultHookPolicy.DENY or isinstance(effective_payload, RootModel)
        )
        if not needs_isolation:
            return effective_payload
        if isinstance(effective_payload, BaseModel):
            return wrap_payload_for_isolation(effective_payload)
        return _safe_deepcopy(effective_payload)

    def _build_halt_result(
        self,
        current_payload: Optional[PluginPayload],
        violation: Any,
        combined_metadata: dict[str, Any],
        fire_and_forget_refs: list[HookRef],
        payload: PluginPayload,
        global_context: GlobalContext,
        res_local_contexts: dict,
        fire_and_forget_semaphore: Optional[asyncio.Semaphore],
        hook_type: str,
        decision_plugin_name: Optional[str],
        extensions: Optional[Extensions] = None,
    ) -> tuple[PluginResult, dict]:
        """Schedule fire-and-forget tasks and build a pipeline-halting result."""
        bg_tasks = self._fire_and_forget_tasks(
            fire_and_forget_refs,
            payload,
            global_context,
            res_local_contexts,
            fire_and_forget_semaphore,
            extensions=extensions,
        )
        if hook_type == HTTP_AUTH_CHECK_PERMISSION_HOOK and decision_plugin_name:
            combined_metadata[DECISION_PLUGIN_METADATA_KEY] = decision_plugin_name
        return (
            PluginResult(
                continue_processing=False,
                modified_payload=current_payload,
                violation=violation,
                metadata=combined_metadata,
                background_tasks=bg_tasks,
            ),
            res_local_contexts,
        )

    @staticmethod
    async def _with_semaphore(semaphore: asyncio.Semaphore, coro: Any) -> Any:
        """Await *coro* while holding *semaphore*, bounding concurrent CONCURRENT tasks."""
        async with semaphore:
            return await coro

    @staticmethod
    async def _tagged(coro: Any, tag: Any) -> tuple[Any, Any]:
        """Await *coro* and pair the result with *tag* for use with as_completed."""
        result = await coro
        return result, tag

    def _fire_and_forget_tasks(
        self,
        fire_and_forget_refs: list[HookRef],
        payload: PluginPayload,
        global_context: GlobalContext,
        res_local_contexts: dict,
        semaphore: Optional[asyncio.Semaphore],
        extensions: Optional[Extensions] = None,
    ) -> list[asyncio.Task]:
        """Schedule all FIRE_AND_FORGET plugins as fire-and-forget background tasks.

        May be called from an early-exit path or from the normal completion path.
        Each FIRE_AND_FORGET plugin receives an isolated snapshot of the payload at call time.
        Returns the list of asyncio.Task handles for all newly scheduled tasks.
        """
        tasks: list[asyncio.Task] = []
        for ref in fire_and_forget_refs:
            local_context_key = global_context.request_id + ref.plugin_ref.uuid
            if local_context_key in res_local_contexts:
                # Already scheduled — skip to avoid double-scheduling
                continue
            task_input = (
                wrap_payload_for_isolation(payload) if isinstance(payload, BaseModel) else _safe_deepcopy(payload)
            )
            tmp_gc = GlobalContext(
                request_id=global_context.request_id,
                user=global_context.user,
                user_context=global_context.user_context,
                tenant_id=global_context.tenant_id,
                server_id=global_context.server_id,
                content_type=global_context.content_type,
                state={} if not global_context.state else copyonwrite(global_context.state),
                metadata={} if not global_context.metadata else copyonwrite(global_context.metadata),
            )
            local_context = PluginContext(global_context=tmp_gc)
            res_local_contexts[local_context_key] = local_context
            task = asyncio.create_task(
                self._run_fire_and_forget_task(ref, task_input, local_context, semaphore, extensions=extensions)
            )
            tasks.append(task)
        return tasks

    async def _run_fire_and_forget_task(
        self,
        hook_ref: HookRef,
        payload: PluginPayload,
        local_context: PluginContext,
        semaphore: Optional[asyncio.Semaphore],
        extensions: Optional[Extensions] = None,
    ) -> Optional[PluginErrorModel]:
        """Execute a plugin as a fire-and-forget background task.

        Returns None on success, or a PluginErrorModel if the plugin raised.
        Errors are logged but never propagated — background tasks cannot halt the pipeline.
        If on_error=DISABLE, the plugin is added to the runtime-disabled set.
        """
        try:
            if semaphore:
                async with semaphore:
                    await self._execute_with_timeout(hook_ref, payload, local_context, extensions=extensions)
            else:
                await self._execute_with_timeout(hook_ref, payload, local_context, extensions=extensions)
            return None
        except Exception as exc:
            logger.error("Plugin %s failed in fire-and-forget mode (ignored)", hook_ref.plugin_ref.name)
            if hook_ref.plugin_ref.on_error == OnError.DISABLE:
                async with self._runtime_disabled_lock:
                    self._runtime_disabled.add(hook_ref.plugin_ref.name)
            # FAIL and IGNORE both just log for FIRE_AND_FORGET mode (background can't halt pipeline)
            return PluginErrorModel(message=repr(exc), plugin_name=hook_ref.plugin_ref.name)

    async def execute_plugin(
        self,
        hook_ref: HookRef,
        payload: PluginPayload,
        local_context: PluginContext,
        violations_as_exceptions: bool,
        global_context: Optional[GlobalContext] = None,
        combined_metadata: Optional[dict[str, Any]] = None,
        extensions: Optional[Extensions] = None,
    ) -> PluginResult:
        """Execute a single plugin with timeout protection.

        Args:
            hook_ref: Hooking structure that contains the plugin and hook.
            payload: The payload to be processed by plugins.
            local_context: local context.
            violations_as_exceptions: Raise violations as exceptions rather than as returns.
            global_context: Shared context for all plugins containing request metadata.
            combined_metadata: combination of the metadata of all plugins.
            extensions: Optional extensions to filter and pass to plugins that accept them.

        Returns:
            A tuple containing:
            - PluginResult with processing status, modified payload, and metadata
            - PluginContextTable with updated local contexts for each plugin

        Raises:
            PayloadSizeError: If the payload exceeds MAX_PAYLOAD_SIZE.
            PluginError: If there is an error inside a plugin.
            PluginViolationError: If a violation occurs and violation_as_exceptions is set.
        """
        try:
            # Execute plugin with timeout protection
            result = await self._execute_with_timeout(hook_ref, payload, local_context, extensions=extensions)
            # Merge global state for modes that participate in the pipeline chain.
            # AUDIT and FIRE_AND_FORGET operate on isolated snapshots and should not
            # mutate shared state.
            if (
                local_context.global_context
                and global_context
                and hook_ref.plugin_ref.mode
                in (
                    PluginMode.SEQUENTIAL,
                    PluginMode.TRANSFORM,
                    PluginMode.CONCURRENT,
                )
            ):
                global_context.state.update(local_context.global_context.state)
                global_context.metadata.update(local_context.global_context.metadata)
            # Aggregate metadata from all plugins
            if result.metadata and combined_metadata is not None:
                combined_metadata.update(
                    {k: v for k, v in result.metadata.items() if k not in RESERVED_INTERNAL_METADATA_KEYS}
                )

            # Set plugin name in violation if present
            if result.violation:
                result.violation.plugin_name = hook_ref.plugin_ref.plugin.name

            # Handle plugin blocking the request
            if not result.continue_processing:
                if hook_ref.plugin_ref.mode in (PluginMode.CONCURRENT, PluginMode.SEQUENTIAL):
                    mode = hook_ref.plugin_ref.mode.value
                    if result.violation:
                        logger.warning(
                            "Plugin %s blocked request in %s mode — violation [%s] %s: %s",
                            hook_ref.plugin_ref.plugin.name,
                            mode,
                            result.violation.code,
                            result.violation.reason,
                            result.violation.description,
                        )
                    else:
                        logger.warning(
                            "Plugin %s blocked request in %s mode (no violation details)",
                            hook_ref.plugin_ref.plugin.name,
                            mode,
                        )
                    if violations_as_exceptions:
                        if result.violation:
                            plugin_name = result.violation.plugin_name
                            violation_reason = result.violation.reason
                            violation_desc = result.violation.description
                            violation_code = result.violation.code
                            raise PluginViolationError(
                                f"{hook_ref.name} blocked by plugin {plugin_name}: {violation_code} - {violation_reason} ({violation_desc})",
                                violation=result.violation,
                            )
                        raise PluginViolationError(f"{hook_ref.name} blocked by plugin")
                    return PluginResult(
                        continue_processing=False,
                        modified_payload=None,
                        violation=result.violation,
                        metadata=combined_metadata,
                    )
                if hook_ref.plugin_ref.mode in (PluginMode.AUDIT, PluginMode.TRANSFORM):
                    mode_label = hook_ref.plugin_ref.mode.value
                    if result.violation:
                        logger.warning(
                            "Plugin %s (%s) raised violation — pipeline continues: [%s] %s — %s",
                            hook_ref.plugin_ref.plugin.name,
                            mode_label,
                            result.violation.code,
                            result.violation.reason,
                            result.violation.description,
                        )
                    else:
                        logger.warning(
                            "Plugin %s (%s) returned continue_processing=False without a violation "
                            "— pipeline continues",
                            hook_ref.plugin_ref.plugin.name,
                            mode_label,
                        )
                    # Violations are logged but not propagated; AUDIT and TRANSFORM
                    # plugins cannot halt the pipeline.  TRANSFORM may still carry a
                    # modified_payload (applied by the caller); AUDIT never does.
                    forwarded_payload = (
                        result.modified_payload if hook_ref.plugin_ref.mode == PluginMode.TRANSFORM else None
                    )
                    return PluginResult(
                        continue_processing=True,
                        modified_payload=forwarded_payload,
                        violation=None,
                        metadata=combined_metadata,
                    )
            return result
        except asyncio.TimeoutError as exc:
            on_error = hook_ref.plugin_ref.on_error
            logger.error("Plugin %s timed out after %ds", hook_ref.plugin_ref.name, self.timeout)
            if on_error == OnError.FAIL:
                raise PluginError(
                    error=PluginErrorModel(
                        message=f"Plugin {hook_ref.plugin_ref.name} exceeded {self.timeout}s timeout",
                        plugin_name=hook_ref.plugin_ref.name,
                    )
                ) from exc
            if on_error == OnError.DISABLE:
                async with self._runtime_disabled_lock:
                    self._runtime_disabled.add(hook_ref.plugin_ref.name)
        except PluginViolationError:
            raise
        except PluginError as pe:
            on_error = hook_ref.plugin_ref.on_error
            logger.error("Plugin %s failed with error: %s", hook_ref.plugin_ref.name, str(pe))
            if on_error == OnError.FAIL:
                raise
            if on_error == OnError.DISABLE:
                async with self._runtime_disabled_lock:
                    self._runtime_disabled.add(hook_ref.plugin_ref.name)
        except Exception as e:
            on_error = hook_ref.plugin_ref.on_error
            logger.error("Plugin %s failed with error: %s", hook_ref.plugin_ref.name, str(e))
            if on_error == OnError.FAIL:
                raise PluginError(error=convert_exception_to_error(e, hook_ref.plugin_ref.name)) from e
            if on_error == OnError.DISABLE:
                async with self._runtime_disabled_lock:
                    self._runtime_disabled.add(hook_ref.plugin_ref.name)
        # Return a result indicating processing should continue despite the error
        return PluginResult(continue_processing=True)

    async def reset_runtime_disabled(self) -> None:
        """Clear the runtime-disabled plugin set.

        Intended for tests and operational reset (e.g., after the underlying error
        condition has been addressed and previously-disabled plugins should be
        re-enabled without restarting the process). Acquires the same lock used
        by the disable path, so it is safe to call concurrently with hook dispatch.
        """
        async with self._runtime_disabled_lock:
            self._runtime_disabled.clear()

    async def _execute_with_timeout(
        self,
        hook_ref: HookRef,
        payload: PluginPayload,
        context: PluginContext,
        extensions: Optional[Extensions] = None,
    ) -> PluginResult:
        """Execute a plugin with timeout protection.

        Args:
            hook_ref: Reference to the hook and plugin to execute.
            payload: Payload to process.
            context: Plugin execution context.
            extensions: Optional extensions to filter and pass if the plugin accepts them.

        Returns:
            Result from plugin execution.

        Raises:
            asyncio.TimeoutError: If plugin exceeds timeout.
            asyncio.CancelledError: If plugin execution is cancelled.
            Exception: Re-raised from plugin hook execution failures.
        """
        # Start observability span if tracing is active
        trace_id = current_trace_id.get()
        span_id = None

        if trace_id and self.observability:
            try:
                span_id = self.observability.start_span(
                    trace_id=trace_id,
                    name=f"plugin.execute.{hook_ref.plugin_ref.name}",
                    kind="internal",
                    resource_type="plugin",
                    resource_name=hook_ref.plugin_ref.name,
                    attributes={
                        "plugin.name": hook_ref.plugin_ref.name,
                        "plugin.uuid": hook_ref.plugin_ref.uuid,
                        "plugin.mode": (
                            hook_ref.plugin_ref.mode.value
                            if hasattr(hook_ref.plugin_ref.mode, "value")
                            else str(hook_ref.plugin_ref.mode)
                        ),
                        "plugin.priority": hook_ref.plugin_ref.priority,
                        "plugin.timeout": self.timeout,
                    },
                )
            except Exception as e:
                logger.debug("Plugin observability start_span failed: %s", e)

        # Execute plugin
        try:
            if hook_ref.accepts_extensions:
                filtered = filter_extensions(extensions, hook_ref.plugin_ref.capabilities)
                result = await asyncio.wait_for(hook_ref.hook(payload, context, filtered), timeout=self.timeout)
            else:
                result = await asyncio.wait_for(hook_ref.hook(payload, context), timeout=self.timeout)
        except Exception:
            if span_id is not None:
                try:
                    self.observability.end_span(span_id=span_id, status="error")
                except Exception:  # nosec B110
                    pass
            raise

        # End span with success
        if span_id is not None:
            try:
                self.observability.end_span(
                    span_id=span_id,
                    status="ok",
                    attributes={
                        "plugin.had_violation": result.violation is not None,
                        "plugin.modified_payload": result.modified_payload is not None,
                    },
                )
            except Exception as e:
                logger.debug("Plugin observability end_span failed: %s", e)

        return result

    def _validate_payload_size(self, payload: Any) -> None:
        """Validate that payload doesn't exceed size limits.

        Args:
            payload: The payload to validate.

        Raises:
            PayloadSizeError: If payload exceeds MAX_PAYLOAD_SIZE.
        """
        # For PromptPrehookPayload, check args size
        if hasattr(payload, "args") and payload.args:
            total_size = sum(len(str(v)) for v in payload.args.values())
            if total_size > MAX_PAYLOAD_SIZE:
                raise PayloadSizeError(f"Payload size {total_size} exceeds limit of {MAX_PAYLOAD_SIZE} bytes")
        # For PromptPosthookPayload, check result size
        elif hasattr(payload, "result") and payload.result:
            # Estimate size of result messages
            total_size = len(str(payload.result))
            if total_size > MAX_PAYLOAD_SIZE:
                raise PayloadSizeError(f"Result size {total_size} exceeds limit of {MAX_PAYLOAD_SIZE} bytes")


class PluginManager:
    """Plugin manager for managing the plugin lifecycle.

    This class implements a thread-safe Borg singleton pattern to ensure consistent
    plugin management across the application. It handles:
    - Plugin discovery and loading from configuration
    - Plugin lifecycle management (initialization, execution, shutdown)
    - Context management with automatic cleanup
    - Hook execution orchestration

    Thread Safety:
        Uses double-checked locking to prevent race conditions when multiple threads
        create PluginManager instances simultaneously. The first instance to acquire
        the lock loads the configuration; subsequent instances reuse the shared state.

    Attributes:
        config: The loaded plugin configuration.
        plugin_count: Number of currently loaded plugins.
        initialized: Whether the manager has been initialized.

    Examples:
        >>> # Initialize plugin manager
        >>> manager = PluginManager("plugins/config.yaml")
        >>> # In async context:
        >>> # await manager.initialize()
        >>> # print(f"Loaded {manager.plugin_count} plugins")
        >>>
        >>> # Execute prompt hooks
        >>> from cpex.framework.models import GlobalContext
        >>> from cpex.framework.hooks.prompts import PromptPrehookPayload
        >>> payload = PromptPrehookPayload(prompt_id="123", name="test", args={})
        >>> context = GlobalContext(request_id="req-123")
        >>> # In async context:
        >>> # result, contexts = await manager.prompt_pre_fetch(payload, context)
        >>>
        >>> # Shutdown when done
        >>> # await manager.shutdown()
    """

    __shared_state: dict[Any, Any] = {}
    __lock: threading.Lock = threading.Lock()  # Thread safety for synchronous init
    _async_lock: asyncio.Lock | None = None  # Async lock for initialize/shutdown
    _loader: PluginLoader = PluginLoader()
    _initialized: bool = False
    _registry: PluginInstanceRegistry = PluginInstanceRegistry()
    _config: Config | None = None
    _config_path: str | None = None
    _executor: PluginExecutor | None = None

    def __init__(
        self,
        config: str = "",
        timeout: int = DEFAULT_PLUGIN_TIMEOUT,
        observability: Optional[ObservabilityProvider] = None,
        hook_policies: Optional[dict[str, HookPayloadPolicy]] = None,
        default_hook_policy: Optional[Literal["allow", "deny"]] = None,
    ):
        """Initialize plugin manager.

        PluginManager implements a thread-safe Borg singleton:
            - Shared state is initialized only once across all instances.
            - Subsequent instantiations reuse same state and skip config reload.
            - Uses double-checked locking to prevent race conditions in multi-threaded environments.

        Thread Safety:
            The initialization uses a double-checked locking pattern to ensure that
            config loading only happens once, even when multiple threads create
            PluginManager instances simultaneously.

        Args:
            config: Path to plugin configuration file (YAML).
            timeout: Maximum execution time per plugin in seconds.
            observability: Optional observability provider implementing ObservabilityProvider protocol.
            hook_policies: Per-hook-type payload modification policies (injected by gateway).
            default_hook_policy: Fallback hook policy ("allow", "deny") when a policy is not specified
                for a hook type (if set, takes precedence over `settings.default_hook_policy`).

        Examples:
            >>> # Initialize with configuration file
            >>> manager = PluginManager("plugins/config.yaml")

            >>> # Initialize with custom timeout
            >>> manager = PluginManager("plugins/config.yaml", timeout=60)
        """
        self.__dict__ = self.__shared_state

        # Only initialize once (first instance when shared state is empty)
        # Use lock to prevent race condition in multi-threaded environments
        if not self.__shared_state:
            with self.__lock:
                # Double-check after acquiring lock (another thread may have initialized)
                if not self.__shared_state:
                    if config:
                        self._config = ConfigLoader.load_config(config)
                        self._config_path = config

                    # Update executor with timeout, observability, and policies
                    self._executor = PluginExecutor(
                        config=self._config,
                        timeout=timeout,
                        observability=observability,
                        hook_policies=hook_policies,
                        default_hook_policy=default_hook_policy,
                    )
        elif hook_policies or default_hook_policy or observability:
            # Allow optional arguments to be injected after initial Borg creation.
            with self.__lock:
                executor = self._get_executor()
                # Only update timeout if caller provided a non-default value
                if timeout != DEFAULT_PLUGIN_TIMEOUT:
                    executor.timeout = timeout
                if not executor.hook_policies:
                    executor.hook_policies = hook_policies
                elif executor.hook_policies != hook_policies:
                    logger.warning(
                        "PluginManager: hook_policies already set; ignoring new policies (call reset() first to replace them)"
                    )
                if default_hook_policy:
                    executor.default_hook_policy = DefaultHookPolicy(default_hook_policy)
                if observability and not executor.observability:
                    executor.observability = observability

    def _get_executor(self) -> PluginExecutor:
        """Get plugin executor, creating it lazily if necessary.

        Returns:
            PluginExecutor: The plugin executor instance.
        """
        if self._executor is None:
            self._executor = PluginExecutor(config=self._config)
        return self._executor

    @property
    def executor(self) -> PluginExecutor:
        """Expose executor for tests and internal callers.

        Returns:
            PluginExecutor: The plugin executor instance.
        """
        return self._get_executor()

    @executor.setter
    def executor(self, value: PluginExecutor) -> None:
        """Set the plugin executor instance.

        Args:
            value: The plugin executor to assign.
        """
        self._executor = value

    @classmethod
    def reset(cls) -> None:
        """Reset the Borg pattern shared state.

        This method clears all shared state, allowing a fresh PluginManager
        instance to be created with new configuration. Primarily used for testing.

        Thread-safe: Uses lock to ensure atomic reset operation.

        Examples:
            >>> # Between tests, reset shared state
            >>> PluginManager.reset()
            >>> manager = PluginManager("new_config.yaml")
        """
        with cls.__lock:
            cls.__shared_state.clear()
            cls._initialized = False
            cls._config = None
            cls._config_path = None
            cls._async_lock = None
            cls._registry = PluginInstanceRegistry()
            cls._executor = None
            cls._loader = PluginLoader()

    @property
    def config(self) -> Config | None:
        """Plugin manager configuration.

        Returns:
            The plugin configuration object or None if not configured.
        """
        return self._config

    @property
    def plugin_count(self) -> int:
        """Number of plugins loaded.

        Returns:
            The number of currently loaded plugins.
        """
        return self._registry.plugin_count

    @property
    def initialized(self) -> bool:
        """Plugin manager initialization status.

        Returns:
            True if the plugin manager has been initialized.
        """
        return self._initialized

    @property
    def observability(self) -> Optional[ObservabilityProvider]:
        """Current observability provider.

        Returns:
            The observability provider or None if not configured.
        """
        return self._executor.observability

    @observability.setter
    def observability(self, provider: Optional[ObservabilityProvider]) -> None:
        """Set the observability provider.

        Thread-safe: uses lock to prevent races with concurrent readers.

        Args:
            provider: ObservabilityProvider to inject into the executor.
        """
        with self.__lock:
            self._executor.observability = provider

    def get_plugin(self, name: str) -> Optional[Plugin]:
        """Get a plugin by name.

        Args:
            name: the name of the plugin to return.

        Returns:
            A plugin.
        """
        plugin_ref = self._registry.get_plugin(name)
        return plugin_ref.plugin if plugin_ref else None

    def has_hooks_for(self, hook_type: str) -> bool:
        """Check if there are any hooks registered for a specific hook type.

        Args:
            hook_type: The type of hook to check for.

        Returns:
            True if there are hooks registered for the specified type, False otherwise.
        """
        return self._registry.has_hooks_for(hook_type)

    async def initialize(self) -> None:
        """Initialize the plugin manager and load all configured plugins.

        This method:
        1. Loads plugin configurations from the config file
        2. Instantiates each enabled plugin
        3. Registers plugins with the registry
        4. Validates plugin initialization

        Thread Safety:
            Uses asyncio.Lock to prevent concurrent initialization from multiple
            coroutines or async tasks. Combined with threading.Lock in __init__
            for full multi-threaded safety.

        Raises:
            RuntimeError: If plugin initialization fails with an exception.
            ValueError: If a plugin cannot be initialized or registered.

        Examples:
            >>> manager = PluginManager("plugins/config.yaml")
            >>> # In async context:
            >>> # await manager.initialize()
            >>> # Manager is now ready to execute plugins
        """
        # Initialize async lock lazily (can't create asyncio.Lock in class definition)
        with self.__lock:
            if self._async_lock is None:
                self._async_lock = asyncio.Lock()

        async with self._async_lock:
            # Double-check after acquiring lock
            if self._initialized:
                logger.debug("Plugin manager already initialized")
                return

            # Defensive cleanup: registry should be empty when not initialized
            if self._registry.plugin_count:
                logger.debug("Plugin registry not empty before initialize; clearing stale plugins")
                await self._registry.shutdown()

            # Configure search path based on safe plugin_dirs
            plugin_dirs = self._config.plugin_dirs if self._config and self._config.plugin_dirs else []
            self._loader.append_to_search_path(plugin_dirs)

            plugins = self._config.plugins if self._config and self._config.plugins else []

            loaded_count = 0

            for plugin_config in plugins:
                try:
                    # For disabled plugins, create a stub plugin without full instantiation
                    if plugin_config.mode != PluginMode.DISABLED:
                        # Fully instantiate enabled plugins
                        plugin = await self._loader.load_and_instantiate_plugin(plugin_config)
                        if plugin:
                            # For external plugins, initialize() merges the remote
                            # config (mode, hooks, etc.) so the post-init config is
                            # authoritative.  For internal plugins the original YAML
                            # config is already complete.
                            if plugin_config.kind == EXTERNAL_PLUGIN_TYPE:
                                trusted = plugin.config.model_copy()
                            else:
                                trusted = plugin_config
                            self._registry.register(plugin, trusted_config=trusted)
                            loaded_count += 1
                            logger.info("Loaded plugin: %s (mode: %s)", plugin_config.name, plugin_config.mode)
                        else:
                            raise ValueError(f"Unable to instantiate plugin: {plugin_config.name}")
                    else:
                        logger.info("Plugin: %s is disabled. Ignoring.", plugin_config.name)

                except Exception as e:
                    # Clean error message without stack trace spam
                    logger.error("Failed to load plugin %s: {%s}", plugin_config.name, str(e))
                    if not settings.fail_on_plugin_error:
                        logger.warning(
                            "Skipping plugin %s because fail_on_plugin_error is disabled", plugin_config.name
                        )
                        continue
                    # Let it crash gracefully with a clean error
                    raise RuntimeError(f"Plugin initialization failed: {plugin_config.name} - {str(e)}") from e

            self._initialized = True
            logger.info("Plugin manager initialized with %s plugins", loaded_count)

    async def shutdown(self) -> None:
        """Shutdown all plugins and cleanup resources.

        This method:
        1. Shuts down all registered plugins
        2. Clears the plugin registry
        3. Cleans up stored contexts
        4. Resets initialization state

        Thread Safety:
            Uses asyncio.Lock to prevent concurrent shutdown with initialization
            or with another shutdown call.

        Note: The config is preserved to allow modifying settings and re-initializing.
        To fully reset for a new config, create a new PluginManager instance.

        Examples:
            >>> manager = PluginManager("plugins/config.yaml")
            >>> # In async context:
            >>> # await manager.initialize()
            >>> # ... use the manager ...
            >>> # await manager.shutdown()
        """
        # Initialize async lock lazily if needed
        with self.__lock:
            if self._async_lock is None:
                self._async_lock = asyncio.Lock()

        async with self._async_lock:
            if not self._initialized:
                logger.debug("Plugin manager not initialized, nothing to shutdown")
                return

            logger.info("Shutting down plugin manager")

            # Shutdown all plugins
            await self._registry.shutdown()

            # Reset state to allow re-initialization
            self._initialized = False

            logger.info("Plugin manager shutdown complete")

    async def invoke_hook(
        self,
        hook_type: str,
        payload: PluginPayload,
        global_context: GlobalContext,
        local_contexts: Optional[PluginContextTable] = None,
        violations_as_exceptions: bool = False,
        extensions: Optional[Extensions] = None,
    ) -> tuple[PluginResult, PluginContextTable | None]:
        """Invoke a set of plugins configured for the hook point in priority order.

        Args:
            hook_type: The type of hook to execute.
            payload: The plugin payload for which the plugins will analyze and modify.
            global_context: Shared context for all plugins with request metadata.
            local_contexts: Optional existing contexts from previous hook executions.
            violations_as_exceptions: Raise violations as exceptions rather than as returns.
            extensions: Optional extensions to filter and pass to plugins that accept them.

        Returns:
            A tuple containing:
            - PluginResult with processing status and modified payload
            - PluginContextTable with plugin contexts for state management

        Examples:
            >>> manager = PluginManager("plugins/config.yaml")
            >>> # In async context:
            >>> # await manager.initialize()
            >>> # payload = ResourcePreFetchPayload("file:///data.txt")
            >>> # context = GlobalContext(request_id="123", server_id="srv1")
            >>> # result, contexts = await manager.resource_pre_fetch(payload, context)
            >>> # if result.continue_processing:
            >>> #     # Use modified payload
            >>> #     uri = result.modified_payload.uri
        """
        # Get plugins configured for this hook
        hook_refs = self._registry.get_hook_refs_for_hook(hook_type=hook_type)

        # Execute plugins
        result = await self._get_executor().execute(
            hook_refs,
            payload,
            global_context,
            hook_type,
            local_contexts,
            violations_as_exceptions,
            extensions=extensions,
        )

        return result

    async def invoke_hook_for_plugin(
        self,
        name: str,
        hook_type: str,
        payload: Union[PluginPayload, dict[str, Any], str],
        context: Union[PluginContext, GlobalContext],
        violations_as_exceptions: bool = False,
        payload_as_json: bool = False,
    ) -> PluginResult:
        """Invoke a specific hook for a single named plugin.

        This method allows direct invocation of a particular plugin's hook by name,
        bypassing the normal priority-ordered execution. Useful for testing individual
        plugins or when specific plugin behavior needs to be triggered independently.

        Args:
            name: The name of the plugin to invoke.
            hook_type: The type of hook to execute (e.g., "prompt_pre_fetch").
            payload: The plugin payload to be processed by the hook.
            context: Plugin execution context (PluginContext) or GlobalContext (will be wrapped).
            violations_as_exceptions: Raise violations as exceptions rather than returns.
            payload_as_json: payload passed in as json rather than pydantic.

        Returns:
            PluginResult with processing status, modified payload, and metadata.

        Raises:
            PluginError: If the plugin or hook type cannot be found in the registry.
            ValueError: If payload type does not match payload_as_json setting.

        Examples:
            >>> manager = PluginManager("plugins/config.yaml")
            >>> # In async context:
            >>> # await manager.initialize()
            >>> # payload = PromptPrehookPayload(name="test", args={})
            >>> # context = PluginContext(global_context=GlobalContext(request_id="123"))
            >>> # result = await manager.invoke_hook_for_plugin(
            >>> #     name="auth_plugin",
            >>> #     hook_type="prompt_pre_fetch",
            >>> #     payload=payload,
            >>> #     context=context
            >>> # )
        """
        # Auto-wrap GlobalContext in PluginContext for convenience
        if isinstance(context, GlobalContext):
            context = PluginContext(global_context=context)

        hook_ref = self._registry.get_plugin_hook_by_name(name, hook_type)
        if not hook_ref:
            raise PluginError(
                error=PluginErrorModel(
                    message=f"Unable to find {hook_type} for plugin {name}.  Make sure the plugin is registered.",
                    plugin_name=name,
                )
            )
        if payload_as_json:
            plugin = hook_ref.plugin_ref.plugin
            # When payload_as_json=True, payload should be str or dict
            if isinstance(payload, (str, dict)):
                pydantic_payload = plugin.json_to_payload(hook_type, payload)
                return await self._get_executor().execute_plugin(
                    hook_ref, pydantic_payload, context, violations_as_exceptions
                )
            raise ValueError(f"When payload_as_json=True, payload must be str or dict, got {type(payload)}")
        # When payload_as_json=False, payload should already be a PluginPayload
        if not isinstance(payload, PluginPayload):
            raise ValueError(f"When payload_as_json=False, payload must be a PluginPayload, got {type(payload)}")
        return await self._get_executor().execute_plugin(hook_ref, payload, context, violations_as_exceptions)


class TenantPluginManager(PluginManager):
    """PluginManager with per-context configuration overrides.

    Each instance has independent state (Borg pattern is disabled).
    Fully compatible with PluginManager API.

    Examples:
        >>> from cpex.framework.models import Config
        >>> config = Config(plugins=[])
        >>> tpm = TenantPluginManager(config=config)
        >>> tpm.initialized
        False
    """

    def __init__(  # pylint: disable=super-init-not-called
        self,
        config: Union[str, Config],
        timeout: int = DEFAULT_PLUGIN_TIMEOUT,
        observability: Optional[ObservabilityProvider] = None,
        hook_policies: Optional[dict[str, HookPayloadPolicy]] = None,
        default_hook_policy: Optional[str] = None,
    ):
        """Initialize a TenantPluginManager with independent state.

        Bypasses PluginManager.__init__ entirely — Borg logic doesn't apply here.
        Each TenantPluginManager is fully independent.

        Args:
            config: Plugin configuration (path or Config object).
            timeout: Per-plugin call timeout in seconds.
            observability: Optional observability provider.
            hook_policies: Optional hook payload policy map.
            default_hook_policy: Fallback hook policy when not specified for a hook type.
        """
        if isinstance(config, Config):
            self._config_path = None
            self._config = config
        else:
            self._config_path = config
            self._config = ConfigLoader.load_config(config)

        self._executor = PluginExecutor(
            config=self._config,
            timeout=timeout,
            observability=observability,
            hook_policies=hook_policies,
            default_hook_policy=default_hook_policy,
        )
        self._initialized = False
        self._registry = PluginInstanceRegistry()
        self._loader = PluginLoader()
        self._async_lock: asyncio.Lock | None = None
