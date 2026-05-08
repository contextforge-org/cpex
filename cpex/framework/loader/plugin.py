# -*- coding: utf-8 -*-
"""Location: ./cpex/framework/loader/plugin.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Teryl Taylor, Mihai Criveti

Plugin loader implementation.
This module implements the plugin loader.
"""

# Standard
import logging
import os
import sys
from pathlib import Path
from typing import Type, cast

# First-Party
from cpex.framework.base import Plugin
from cpex.framework.constants import EXTERNAL_PLUGIN_TYPE, ISOLATED_VENV_PLUGIN_TYPE
from cpex.framework.external.mcp.client import ExternalPlugin
from cpex.framework.models import PluginConfig
from cpex.framework.utils import import_module, parse_class_name

# Use standard logging to avoid circular imports (plugins -> services -> plugins)
logger = logging.getLogger(__name__)

# Allowed plugin dirs to use as plugin search paths
ALLOWED_PLUGIN_DIRS = {
    os.path.abspath("/var/lib/cpex/plugins"),
    os.path.abspath("/private/var/lib/cpex/plugins"),
    os.getcwd(),
}


class PluginLoader:
    """A plugin loader object for loading and instantiating plugins.

    Examples:
        >>> loader = PluginLoader()
        >>> isinstance(loader._plugin_types, dict)
        True
        >>> len(loader._plugin_types)
        0
    """

    def __init__(self) -> None:
        """Initialize the plugin loader.

        Examples:
            >>> loader = PluginLoader()
            >>> loader._plugin_types
            {}
        """
        self._plugin_types: dict[str, Type[Plugin]] = {}
        self.plugin_dirs: list[str] = []

    def __get_plugin_type(self, kind: str) -> Type[Plugin]:
        """Import a plugin type from a python module.

        Args:
            kind: The fully-qualified type of the plugin to be registered.

        Raises:
            Exception: if unable to import a module.

        Returns:
            A plugin type.
        """
        try:
            mod_name, cls_name = parse_class_name(kind)
            module = import_module(mod_name)
            class_ = getattr(module, cls_name)
            return cast(Type[Plugin], class_)
        except Exception:
            logger.exception("Unable to import plugin type '%s'", kind)
            raise

    def __register_plugin_type(self, kind: str) -> None:
        """Register a plugin type.

        Args:
            kind: The fully-qualified type of the plugin to be registered.
        """
        if kind not in self._plugin_types:
            plugin_type: Type[Plugin]
            if kind == EXTERNAL_PLUGIN_TYPE:
                plugin_type = ExternalPlugin
            else:
                plugin_type = self.__get_plugin_type(kind)
            self._plugin_types[kind] = plugin_type

    async def load_and_instantiate_plugin(self, config: PluginConfig) -> Plugin | None:
        """Load and instantiate a plugin, given a configuration.

        The plugin receives a defensive copy of the config so it cannot
        modify the authoritative config retained by the Manager/PluginRef.

        For external plugins, the transport type is determined by the presence
        of 'mcp', 'grpc', or 'unix_socket' configuration:
        - If 'grpc' is set, uses GrpcExternalPlugin for gRPC transport
        - If 'mcp' is set, uses ExternalPlugin for MCP transport
        - If 'unix_socket' is set, uses UnixSocketExternalPlugin for raw Unix socket transport

        Args:
            config: A plugin configuration.

        Returns:
            A plugin instance.

        Raises:
            ValueError: If an external plugin has no transport configured.
        """
        # Defensive copy — the plugin never sees the authoritative config
        plugin_config = config.model_copy()

        # Handle external plugins with transport selection
        if config.kind == EXTERNAL_PLUGIN_TYPE:
            plugin: Plugin
            if config.grpc:
                # Use gRPC transport
                # Import here to avoid circular dependency and to make grpc optional
                # First-Party
                from cpex.framework.external.grpc.client import (
                    GrpcExternalPlugin,
                )  # pylint: disable=import-outside-toplevel

                plugin = GrpcExternalPlugin(plugin_config)
                logger.info("Loading external plugin '%s' with gRPC transport", config.name)
            elif config.unix_socket:
                # Use raw Unix socket transport (high-performance local IPC)
                # First-Party
                from cpex.framework.external.unix.client import (
                    UnixSocketExternalPlugin,
                )  # pylint: disable=import-outside-toplevel

                plugin = UnixSocketExternalPlugin(plugin_config)
                logger.info("Loading external plugin '%s' with Unix socket transport", config.name)
            elif config.mcp:
                # Use MCP transport
                plugin = ExternalPlugin(plugin_config)
                logger.info("Loading external plugin '%s' with MCP transport", config.name)
            else:
                # Defensive fallback: PluginConfig validation should prevent this path.
                raise ValueError(
                    f"External plugin '{config.name}' must have 'mcp', 'grpc', or 'unix_socket' configuration"
                )  # pragma: no cover

            await plugin.initialize()
            return plugin

        if config.kind == ISOLATED_VENV_PLUGIN_TYPE:
            from cpex.framework.isolated.client import IsolatedVenvPlugin  # pylint: disable=import-outside-toplevel

            plugin: Plugin = IsolatedVenvPlugin(config, plugin_dirs=self.plugin_dirs.copy())
            await plugin.initialize()
            return plugin

        # Handle other plugin types
        if config.kind not in self._plugin_types:
            self.__register_plugin_type(config.kind)
        plugin_type = self._plugin_types[config.kind]
        if plugin_type:
            plugin = plugin_type(plugin_config)
            await plugin.initialize()
            return plugin
        return None

    def append_to_search_path(self, plugin_dirs: list[str]) -> None:
        """Safe append plugin dir paths to search path.

        Args:
            plugin_dirs: paths to append to search path
        """
        for plugin_dir in plugin_dirs:
            resolved = str(Path(plugin_dir).resolve())
            if resolved.startswith(tuple(ALLOWED_PLUGIN_DIRS)):
                self.plugin_dirs.append(plugin_dir)
                if resolved not in sys.path:
                    sys.path.append(resolved)

    async def shutdown(self) -> None:
        """Shutdown and cleanup plugin loader.

        Examples:
           >>> import asyncio
           >>> loader = PluginLoader()
           >>> asyncio.run(loader.shutdown())
           >>> loader._plugin_types
           {}
        """
        if self._plugin_types:
            self._plugin_types.clear()
