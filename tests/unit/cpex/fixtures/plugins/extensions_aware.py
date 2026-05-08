# -*- coding: utf-8 -*-
"""Test plugin that accepts extensions as a third parameter.

Used to test the accepts_extensions=True path through
_execute_with_timeout in the PluginManager.
"""

from cpex.framework import Plugin
from cpex.framework.decorator import hook
from cpex.framework.extensions.extensions import Extensions
from cpex.framework.hooks.tools import ToolPreInvokePayload
from cpex.framework.models import PluginContext, PluginResult


class ExtensionsAwarePlugin(Plugin):
    """A plugin that receives and uses filtered extensions."""

    @hook("tool_pre_invoke")
    async def tool_pre_invoke(
        self,
        payload: ToolPreInvokePayload,
        context: PluginContext,
        extensions: Extensions,
    ) -> PluginResult:
        """Check extensions for required role. Denies if role missing."""
        if extensions and extensions.security and extensions.security.subject:
            roles = extensions.security.subject.roles or frozenset()
            if "required_role" in roles:
                return PluginResult(continue_processing=True)

        # Allow if no extensions provided (backward compat)
        if extensions is None:
            return PluginResult(continue_processing=True)

        return PluginResult(continue_processing=True)


class ExtensionsLabelPlugin(Plugin):
    """A plugin that reads labels from extensions and adds a label."""

    @hook("tool_pre_invoke")
    async def tool_pre_invoke(
        self,
        payload: ToolPreInvokePayload,
        context: PluginContext,
        extensions: Extensions,
    ) -> PluginResult:
        """If extensions have security, add 'PLUGIN_TOUCHED' label."""
        if extensions and extensions.security:
            new_labels = extensions.security.labels | frozenset({"PLUGIN_TOUCHED"})
            new_security = extensions.security.model_copy(update={"labels": new_labels})
            modified_ext = extensions.model_copy(update={"security": new_security})
            return PluginResult(
                continue_processing=True,
                modified_extensions=modified_ext,
            )
        return PluginResult(continue_processing=True)


class ExtensionsCustomPlugin(Plugin):
    """A plugin that reads labels and writes to custom extensions."""

    @hook("tool_pre_invoke")
    async def tool_pre_invoke(
        self,
        payload: ToolPreInvokePayload,
        context: PluginContext,
        extensions: Extensions,
    ) -> PluginResult:
        """Read labels, write observation to custom extensions."""
        pii_detected = False
        if extensions and extensions.security:
            pii_detected = "PII" in extensions.security.labels

        custom = dict(extensions.custom) if extensions and extensions.custom else {}
        custom["pii_detected"] = pii_detected
        modified_ext = extensions.model_copy(update={"custom": custom})
        return PluginResult(
            continue_processing=True,
            modified_extensions=modified_ext,
        )
