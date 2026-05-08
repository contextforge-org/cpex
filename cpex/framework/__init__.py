# -*- coding: utf-8 -*-
"""Location: ./cpex/framework/__init__.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Fred Araujo

Plugin Framework Package.
Exposes core ContextForge plugin components:
- Context
- Manager
- Payloads
- Models
- ExternalPluginServer
"""

# Standard
from typing import Optional

# First-Party
from cpex.framework.base import Plugin
from cpex.framework.decorator import hook
from cpex.framework.errors import PluginError, PluginViolationError
from cpex.framework.external.mcp.server import ExternalPluginServer
from cpex.framework.hooks.agents import (
    AgentHookType,
    AgentPostInvokePayload,
    AgentPostInvokeResult,
    AgentPreInvokePayload,
    AgentPreInvokeResult,
)
from cpex.framework.hooks.http import (
    HttpAuthCheckPermissionPayload,
    HttpAuthCheckPermissionResult,
    HttpAuthCheckPermissionResultPayload,
    HttpAuthResolveUserPayload,
    HttpAuthResolveUserResult,
    HttpHeaderPayload,
    HttpHookType,
    HttpPostRequestPayload,
    HttpPostRequestResult,
    HttpPreRequestPayload,
    HttpPreRequestResult,
)
from cpex.framework.hooks.policies import HookPayloadPolicy
from cpex.framework.hooks.prompts import (
    PromptHookType,
    PromptPosthookPayload,
    PromptPosthookResult,
    PromptPrehookPayload,
    PromptPrehookResult,
)
from cpex.framework.hooks.registry import HookRegistry, get_hook_registry
from cpex.framework.hooks.resources import (
    ResourceHookType,
    ResourcePostFetchPayload,
    ResourcePostFetchResult,
    ResourcePreFetchPayload,
    ResourcePreFetchResult,
)
from cpex.framework.hooks.tools import (
    ToolHookType,
    ToolPostInvokePayload,
    ToolPostInvokeResult,
    ToolPreInvokePayload,
    ToolPreInvokeResult,
)
from cpex.framework.loader.config import ConfigLoader
from cpex.framework.loader.plugin import PluginLoader
from cpex.framework.manager import PluginManager, TenantPluginManager
from cpex.framework.models import (
    GlobalContext,
    MCPClientConfig,
    MCPServerConfig,
    OnError,
    PluginCondition,
    PluginConfig,
    PluginContext,
    PluginContextTable,
    PluginErrorModel,
    PluginMode,
    PluginPayload,
    PluginResult,
    PluginViolation,
    TransportType,
    UserContext,
)
from cpex.framework.observability import ObservabilityProvider
from cpex.framework.utils import get_attr

# Plugin manager singleton (lazy initialization)
_plugin_manager: Optional[PluginManager] = None


def get_plugin_manager(
    observability: Optional[ObservabilityProvider] = None, hook_policies: Optional[dict[str, HookPayloadPolicy]] = None
) -> Optional[PluginManager]:
    """Get or initialize the plugin manager singleton.

    This is the public API for accessing the plugin manager from anywhere in the application.
    The plugin manager is lazily initialized on first access if plugins are enabled.

    Args:
        observability: Optional observability provider implementing ObservabilityProvider protocol.
        hook_policies: Per-hook-type payload modification policies.

    Returns:
        PluginManager instance if plugins are enabled, None otherwise.

    Examples:
        >>> from cpex.framework import get_plugin_manager
        >>> pm = get_plugin_manager()
        >>> # Returns PluginManager if plugins are enabled, None otherwise
        >>> pm is None or isinstance(pm, PluginManager)
        True
    """
    global _plugin_manager  # pylint: disable=global-statement
    if _plugin_manager is None:
        # Use plugin framework's settings
        from cpex.framework.settings import settings  # pylint: disable=import-outside-toplevel

        if settings.enabled:
            _plugin_manager = PluginManager(
                settings.config_file,
                timeout=settings.plugin_timeout,
                observability=observability,
                hook_policies=hook_policies,
            )
    return _plugin_manager


__all__ = [
    "AgentHookType",
    "AgentPostInvokePayload",
    "AgentPostInvokeResult",
    "AgentPreInvokePayload",
    "AgentPreInvokeResult",
    "ConfigLoader",
    "ExternalPluginServer",
    "get_attr",
    "get_hook_registry",
    "get_plugin_manager",
    "GlobalContext",
    "hook",
    "HookRegistry",
    "HttpAuthCheckPermissionPayload",
    "HttpAuthCheckPermissionResult",
    "HttpAuthCheckPermissionResultPayload",
    "HttpAuthResolveUserPayload",
    "HttpAuthResolveUserResult",
    "HttpHeaderPayload",
    "HttpHookType",
    "HttpPostRequestPayload",
    "HttpPostRequestResult",
    "HttpPreRequestPayload",
    "HttpPreRequestResult",
    "MCPClientConfig",
    "MCPServerConfig",
    "ObservabilityProvider",
    "OnError",
    "Plugin",
    "PluginCondition",
    "PluginConfig",
    "PluginContext",
    "PluginContextTable",
    "PluginError",
    "PluginErrorModel",
    "PluginLoader",
    "PluginManager",
    "PluginMode",
    "PluginPayload",
    "PluginResult",
    "PluginViolation",
    "PluginViolationError",
    "PromptHookType",
    "PromptPosthookPayload",
    "PromptPosthookResult",
    "PromptPrehookPayload",
    "PromptPrehookResult",
    "ResourceHookType",
    "ResourcePostFetchPayload",
    "ResourcePostFetchResult",
    "ResourcePreFetchPayload",
    "ResourcePreFetchResult",
    "ToolHookType",
    "ToolPostInvokePayload",
    "ToolPostInvokeResult",
    "ToolPreInvokeResult",
    "TenantPluginManager",
    "ToolPreInvokePayload",
    "TransportType",
    "UserContext",
]
