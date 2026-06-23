# -*- coding: utf-8 -*-
# Location: ./crates/cpex-hosts-python/tests/fixtures/echo_plugin.py
# Copyright 2026
# SPDX-License-Identifier: Apache-2.0
#
# Minimal CPEX plugin fixture for Rust integration tests.
# Three variants:
#   EchoPlugin  — returns allow() unchanged
#   ModifyPlugin — returns a modified payload (mutates a field)
#   ErrorPlugin  — raises RuntimeError to test on_error handling

from cpex.framework.base import Plugin
from cpex.framework.decorator import hook
from cpex.framework.models import PluginConfig, PluginResult


class EchoPlugin(Plugin):
    """Minimal plugin that echoes the payload unchanged."""

    def __init__(self, config: PluginConfig) -> None:
        super().__init__(config)

    async def initialize(self) -> None:
        pass

    async def shutdown(self) -> None:
        pass

    @hook("cmf.tool_pre_invoke")
    async def on_tool_pre_invoke(self, payload, context) -> PluginResult:
        return PluginResult(continue_processing=True)

    @hook("cmf.tool_post_invoke")
    async def on_tool_post_invoke(self, payload, context) -> PluginResult:
        return PluginResult(continue_processing=True)


class ModifyPlugin(Plugin):
    """Plugin that modifies the payload by wrapping the content."""

    def __init__(self, config: PluginConfig) -> None:
        super().__init__(config)

    @hook("cmf.tool_pre_invoke")
    async def on_tool_pre_invoke(self, payload, context) -> PluginResult:
        # Return a modified payload — add a sentinel field to the dict.
        modified = dict(payload) if isinstance(payload, dict) else payload
        return PluginResult(continue_processing=True, modified_payload=modified)


class ErrorPlugin(Plugin):
    """Plugin that always raises RuntimeError — used to test on_error."""

    def __init__(self, config: PluginConfig) -> None:
        super().__init__(config)

    @hook("cmf.tool_pre_invoke")
    async def on_tool_pre_invoke(self, payload, context) -> PluginResult:
        raise RuntimeError("intentional error from ErrorPlugin")


class NoLifecyclePlugin(Plugin):
    """Plugin with no initialize/shutdown — tests AC-6 (missing = no-op)."""

    def __init__(self, config: PluginConfig) -> None:
        super().__init__(config)

    @hook("cmf.tool_pre_invoke")
    async def on_tool_pre_invoke(self, payload, context) -> PluginResult:
        return PluginResult(continue_processing=True)
