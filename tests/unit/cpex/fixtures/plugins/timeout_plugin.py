# -*- coding: utf-8 -*-
"""Location: ./tests/unit/cpex/fixtures/plugins/timeout_plugin.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0

Timeout plugin — sleeps indefinitely to trigger asyncio.wait_for timeout.
Used to test on_error=ignore/disable timeout recording behaviour.
"""

# Standard
import asyncio

# First-Party
from cpex.framework import (
    Plugin,
    PluginContext,
    PromptPrehookPayload,
    PromptPrehookResult,
)


class TimeoutPlugin(Plugin):
    """A plugin that always times out (sleeps indefinitely)."""

    async def prompt_pre_fetch(self, payload: PromptPrehookPayload, context: PluginContext) -> PromptPrehookResult:
        """Sleep indefinitely — always triggers the executor timeout."""
        await asyncio.sleep(3600)
        return PromptPrehookResult(continue_processing=True)  # never reached
