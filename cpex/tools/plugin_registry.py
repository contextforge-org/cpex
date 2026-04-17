# -*- coding: utf-8 -*-
"""Location: ./cpex/tools/plugin_registry.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Ted Habeck

This module implements the plugin registry object.
"""

import datetime
import json
import os
from pathlib import Path

from cpex.framework.models import InstalledPluginInfo, InstalledPluginRegistry, PluginInstallationType, PluginManifest
from cpex.tools.catalog import PluginCatalog


class PluginRegistry:
    """Plugin registry.
    Plugin registry is responsible for storing information about installed plugins.
    """

    registry: InstalledPluginRegistry = InstalledPluginRegistry()

    def __init__(self, *args, **kwargs):
        """Initialize the plugin registry."""
        super().__init__(*args, **kwargs)
        DEFAULT_PLUGIN_REGISTRY_FOLDER = Path(os.environ.get("PLUGIN_REGISTRY_FILE", "data"))
        os.makedirs(DEFAULT_PLUGIN_REGISTRY_FOLDER, exist_ok=True)
        DEFAULT_PLUGIN_REGISTRY_FILE = "installed-plugins.json"
        ipr_file = DEFAULT_PLUGIN_REGISTRY_FOLDER / DEFAULT_PLUGIN_REGISTRY_FILE
        if ipr_file.exists():
            with open(ipr_file, "r", encoding="utf-8") as ipr:
                self.registry = InstalledPluginRegistry(**json.load(ipr))
        else:
            self.registry = InstalledPluginRegistry()

    def update(
        self, manifest: PluginManifest, installation_type: str, catalog: PluginCatalog, git_user_name: str
    ) -> None:
        """
        Given a plugin manifest, register it in the plugin registry.

        Args:
        manifest: PluginManifest: The manifest of the plugin to be registered.
        installation_type: str: The type of installation (e.g., "local", "global").
        catalog: PluginCatalog: The catalog containing the plugin.
        git_user_name: str: The name of the user who installed the plugin.

        Raises:
        RuntimeError: If the plugin manifest is invalid or the installation type is not recognized.
        """
        package_source = ""
        if installation_type == "monorepo":
            if manifest.monorepo is None:
                raise RuntimeError("PluginManifest.monorepo can not be None.")
            package_source = manifest.monorepo.package_source
        elif installation_type == "pypi":
            if manifest.package_info is None:
                raise RuntimeError("PluginManifest.package_info can not be None.")
            package_source = manifest.package_info.pypi_package
        else:
            raise ValueError(f"Invalid installation type: {installation_type}")

        installation_path = catalog.find_package_path(manifest.name)

        ipi: InstalledPluginInfo = InstalledPluginInfo(
            name=manifest.name,
            kind=manifest.kind,
            version=manifest.version,
            installation_type=PluginInstallationType(installation_type),
            installation_path=str(installation_path.resolve()),
            installed_at=datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z",
            installed_by=git_user_name,
            package_source=package_source,
            editable=False,
        )
        # add the newly downloaded plugin to the registry
        self.registry.register_plugin(ipi)

    def has(self, plugin_name: str) -> bool:
        """
        Check if a plugin is installed.
        Args:
            plugin_name: The name of the plugin to check.
        Returns:
            True if the plugin is installed, False otherwise.
        """
        for plugin in self.registry.plugins:
            if plugin.name == plugin_name:
                return True
        return False

    def remove(self, plugin_name: str) -> bool:
        """
        Remove a plugin from the registry.

        Args:
            plugin_name: The name of the plugin to remove.

        Returns:
            True if the plugin was found and removed, False otherwise.
        """
        return self.registry.unregister_plugin(plugin_name)
