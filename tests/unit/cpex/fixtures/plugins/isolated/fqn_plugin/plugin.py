"""A synthetic bare-FQN plugin fixture (no requirements.txt).

Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: habeck

Used by U7 acceptance tests: a plugin whose manifest declares ``kind`` as a
class path rather than a known kind, exercising the installer's FQN
auto-conversion to isolated_venv.
"""

import logging

from cpex.framework import (
    Plugin,
    PluginConfig,
    PluginContext,
    ToolPreInvokePayload,
    ToolPreInvokeResult,
)

logger = logging.getLogger(__name__)


class FqnPlugin(Plugin):
    """A minimal plugin referenced by its fully-qualified class path."""

    def __init__(self, config: PluginConfig):
        """Entry init block for the plugin."""
        super().__init__(config)

    async def tool_pre_invoke(self, payload: ToolPreInvokePayload, context: PluginContext) -> ToolPreInvokeResult:
        """Allow the tool invocation to proceed."""
        logger.info("FqnPlugin: tool_pre_invoke")
        return ToolPreInvokeResult(continue_processing=True)
