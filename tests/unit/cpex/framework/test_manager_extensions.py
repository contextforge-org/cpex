# -*- coding: utf-8 -*-
"""Tests for PluginManager with extensions-aware plugins.

Covers:
- _execute_with_timeout with accepts_extensions=True
- Plugin receives capability-filtered extensions
- Extensions passed through invoke_hook reach the plugin
"""

import pytest

from cpex.framework import (
    GlobalContext,
    PluginManager,
    ToolHookType,
    ToolPreInvokePayload,
)
from cpex.framework.extensions.extensions import Extensions
from cpex.framework.extensions.security import (
    SecurityExtension,
    SubjectExtension,
    SubjectType,
)


@pytest.mark.asyncio
async def test_manager_extensions_aware_plugin_receives_extensions():
    """An extensions-aware plugin (3-param hook) receives filtered extensions."""
    manager = PluginManager("./tests/unit/cpex/fixtures/configs/extensions_aware_plugin.yaml")
    await manager.initialize()

    extensions = Extensions(
        security=SecurityExtension(
            labels=frozenset({"internal"}),
            subject=SubjectExtension(
                id="alice@corp.com",
                type=SubjectType.USER,
                roles=frozenset({"required_role", "engineer"}),
                permissions=frozenset({"tool_execute"}),
            ),
        ),
    )

    payload = ToolPreInvokePayload(name="test_tool", args={"key": "value"})
    context = GlobalContext(request_id="req-1")

    result, contexts = await manager.invoke_hook(
        ToolHookType.TOOL_PRE_INVOKE,
        payload,
        global_context=context,
        extensions=extensions,
    )

    assert result.continue_processing is True
    await manager.shutdown()


@pytest.mark.asyncio
async def test_manager_extensions_aware_plugin_without_extensions():
    """An extensions-aware plugin works when no extensions are passed."""
    manager = PluginManager("./tests/unit/cpex/fixtures/configs/extensions_aware_plugin.yaml")
    await manager.initialize()

    payload = ToolPreInvokePayload(name="test_tool", args={"key": "value"})
    context = GlobalContext(request_id="req-1")

    # No extensions passed — plugin should still work (backward compat)
    result, contexts = await manager.invoke_hook(
        ToolHookType.TOOL_PRE_INVOKE,
        payload,
        global_context=context,
    )

    assert result.continue_processing is True
    await manager.shutdown()


@pytest.mark.asyncio
async def test_manager_extensions_capability_filtering():
    """Extensions are filtered by the plugin's declared capabilities."""
    manager = PluginManager("./tests/unit/cpex/fixtures/configs/extensions_aware_plugin.yaml")
    await manager.initialize()

    # Create extensions with HTTP headers — plugin doesn't have read_headers capability
    from cpex.framework.extensions.http import HttpExtension

    extensions = Extensions(
        security=SecurityExtension(
            labels=frozenset({"PII"}),
            subject=SubjectExtension(
                id="alice@corp.com",
                type=SubjectType.USER,
                roles=frozenset({"engineer"}),
            ),
        ),
        http=HttpExtension(headers={"authorization": "Bearer secret"}),
    )

    payload = ToolPreInvokePayload(name="test_tool", args={"key": "value"})
    context = GlobalContext(request_id="req-1")

    result, contexts = await manager.invoke_hook(
        ToolHookType.TOOL_PRE_INVOKE,
        payload,
        global_context=context,
        extensions=extensions,
    )

    # Plugin should execute successfully — it has read_subject and read_labels
    # but NOT read_headers, so HTTP headers should be filtered out by the framework
    assert result.continue_processing is True
    await manager.shutdown()


@pytest.mark.asyncio
async def test_manager_plugin_adds_label_and_manager_merges():
    """Plugin adds a label to extensions; manager merges it back in the result."""
    manager = PluginManager("./tests/unit/cpex/fixtures/configs/extensions_label_plugin.yaml")
    await manager.initialize()

    extensions = Extensions(
        security=SecurityExtension(
            labels=frozenset({"internal"}),
        ),
    )

    payload = ToolPreInvokePayload(name="test_tool", args={"key": "value"})
    context = GlobalContext(request_id="req-1")

    result, contexts = await manager.invoke_hook(
        ToolHookType.TOOL_PRE_INVOKE,
        payload,
        global_context=context,
        extensions=extensions,
    )

    assert result.continue_processing is True

    # The plugin should have added 'PLUGIN_TOUCHED' label via modified_extensions
    assert result.modified_extensions is not None
    assert "PLUGIN_TOUCHED" in result.modified_extensions.security.labels
    # Original label should still be present (monotonic — only growth)
    assert "internal" in result.modified_extensions.security.labels
    await manager.shutdown()


@pytest.mark.asyncio
async def test_manager_plugin_writes_custom_extensions():
    """Plugin reads labels and writes observation to custom extensions."""
    manager = PluginManager("./tests/unit/cpex/fixtures/configs/extensions_custom_plugin.yaml")
    await manager.initialize()

    extensions = Extensions(
        security=SecurityExtension(
            labels=frozenset({"PII", "financial"}),
        ),
    )

    payload = ToolPreInvokePayload(name="test_tool", args={"key": "value"})
    context = GlobalContext(request_id="req-1")

    result, contexts = await manager.invoke_hook(
        ToolHookType.TOOL_PRE_INVOKE,
        payload,
        global_context=context,
        extensions=extensions,
    )

    assert result.continue_processing is True
    # Plugin should have written pii_detected=True to custom extensions
    assert result.modified_extensions is not None
    assert result.modified_extensions.custom["pii_detected"] is True
    await manager.shutdown()


@pytest.mark.asyncio
async def test_manager_plugin_custom_no_pii():
    """Plugin reads labels — no PII label means pii_detected=False."""
    manager = PluginManager("./tests/unit/cpex/fixtures/configs/extensions_custom_plugin.yaml")
    await manager.initialize()

    extensions = Extensions(
        security=SecurityExtension(
            labels=frozenset({"internal"}),
        ),
    )

    payload = ToolPreInvokePayload(name="test_tool", args={"key": "value"})
    context = GlobalContext(request_id="req-1")

    result, contexts = await manager.invoke_hook(
        ToolHookType.TOOL_PRE_INVOKE,
        payload,
        global_context=context,
        extensions=extensions,
    )

    assert result.continue_processing is True
    assert result.modified_extensions is not None
    assert result.modified_extensions.custom["pii_detected"] is False
    await manager.shutdown()
