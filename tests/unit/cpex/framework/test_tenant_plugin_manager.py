# -*- coding: utf-8 -*-
"""Location: ./tests/unit/cpex/framework/test_tenant_plugin_manager.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0

Tests for TenantPluginManager.
"""

# Third-Party
import pytest

# First-Party
from cpex.framework.loader.config import ConfigLoader
from cpex.framework.manager import TenantPluginManager

FIXTURE_NO_PLUGIN = "./tests/unit/cpex/fixtures/configs/valid_no_plugin.yaml"


@pytest.mark.asyncio
async def test_tenant_plugin_manager_with_config_object():
    """Test TenantPluginManager initialization with Config object."""
    config = ConfigLoader.load_config(FIXTURE_NO_PLUGIN)
    manager = TenantPluginManager(config=config)
    try:
        await manager.initialize()
        assert manager.initialized
        assert manager._config_path is None
        assert manager._config is config
    finally:
        await manager.shutdown()


@pytest.mark.asyncio
async def test_tenant_plugin_manager_with_string_path():
    """Test TenantPluginManager initialization with string path."""
    manager = TenantPluginManager(config=FIXTURE_NO_PLUGIN)
    try:
        await manager.initialize()
        assert manager.initialized
        assert manager._config_path == FIXTURE_NO_PLUGIN
        assert manager._config is not None
    finally:
        await manager.shutdown()
