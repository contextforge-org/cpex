# -*- coding: utf-8 -*-
"""Host-side integration test for samplewasmplugin.

Runs the built .wasm artifact through cpex's PluginManager exactly the
way production would. If this test passes, the plugin satisfies the
contextforge:cpex@0.1.0 contract end to end.

Run with:  make test   (from the plugin root)
"""

from pathlib import Path

import pytest

from cpex.framework import (
    GlobalContext,
    PluginConfig,
    PluginContext,
    ToolPostInvokePayload,
    ToolPreInvokePayload,
)
from cpex.framework.wasm import WasmPlugin


PLUGIN_ROOT = Path(__file__).parent.parent
MANIFEST = PLUGIN_ROOT / "plugin-manifest.yaml"


def _make_plugin(extra_config: dict | None = None) -> WasmPlugin:
    config = PluginConfig(
        name="samplewasmplugin",
        kind="wasm",
        version="0.1.0",
        hooks=["tool_pre_invoke", "tool_post_invoke"],
        mode="sequential",
        priority=150,
        config={
            "manifest_path": str(MANIFEST),
            "blocked_tools": ["rm", "sudo"],
            **(extra_config or {}),
        },
    )
    return WasmPlugin(config)


@pytest.fixture
def context() -> PluginContext:
    return PluginContext(global_context=GlobalContext(request_id="test-1"))


@pytest.mark.asyncio
async def test_manifest_loads_and_artifact_verifies():
    """Smoke: manifest parses, sha256 of the built wasm matches."""
    plugin = _make_plugin()
    await plugin.initialize()
    try:
        assert plugin._manifest is not None
        assert plugin._manifest.name == "samplewasmplugin"
        assert "tool_pre_invoke" in plugin._manifest.hooks
    finally:
        await plugin.cleanup()


@pytest.mark.asyncio
async def test_blocks_listed_tool(context):
    plugin = _make_plugin()
    await plugin.initialize()
    try:
        payload = ToolPreInvokePayload(name="rm", args={"path": "/tmp/x"})
        result = await plugin.invoke_hook("tool_pre_invoke", payload, context)
        assert result.continue_processing is False
        assert result.violation is not None
        assert result.violation.code == "TOOL_BLOCKED"
    finally:
        await plugin.cleanup()


@pytest.mark.asyncio
async def test_allows_unlisted_tool(context):
    plugin = _make_plugin()
    await plugin.initialize()
    try:
        payload = ToolPreInvokePayload(name="search", args={"query": "weather"})
        result = await plugin.invoke_hook("tool_pre_invoke", payload, context)
        assert result.continue_processing is True
        assert result.violation is None
    finally:
        await plugin.cleanup()


@pytest.mark.asyncio
async def test_post_invoke_is_passthrough(context):
    plugin = _make_plugin()
    await plugin.initialize()
    try:
        payload = ToolPostInvokePayload(name="search", result={"hits": []})
        result = await plugin.invoke_hook("tool_post_invoke", payload, context)
        assert result.continue_processing is True
    finally:
        await plugin.cleanup()


@pytest.mark.asyncio
async def test_unknown_hook_returns_plugin_error(context):
    plugin = _make_plugin()
    await plugin.initialize()
    try:
        payload = ToolPreInvokePayload(name="x")
        with pytest.raises(Exception) as ei:
            await plugin.invoke_hook(
                "agent_pre_invoke",  # not in our manifest
                payload,
                context,
            )
        # cpex wraps as PluginError; the inner message should mention the hook
        assert "agent_pre_invoke" in str(ei.value) or "UNKNOWN" in str(ei.value).upper()
    finally:
        await plugin.cleanup()
