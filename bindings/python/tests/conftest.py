# Location: ./bindings/python/tests/conftest.py
# Copyright 2025
# SPDX-License-Identifier: Apache-2.0
# Authors: Ted Habeck
#
# Pytest fixtures for cpex-python binding tests.
#
# No module-level os.environ mutation — env changes are scoped to the
# test function that needs them (mirrors tests/unit/cpex/conftest.py style).

import os
from pathlib import Path

import pytest
from cpex import PluginManager

FIXTURES_DIR = Path(__file__).parent / "fixtures"
PII_DENY_CONFIG = str(FIXTURES_DIR / "pii_deny.yaml")


@pytest.fixture
async def manager():
    """Create, initialize, and yield a PluginManager backed by pii_deny.yaml.

    Shuts down after the test so fire-and-forget tasks are drained (KD4).
    """
    mgr = PluginManager(PII_DENY_CONFIG)
    await mgr.initialize()
    yield mgr
    await mgr.shutdown()


@pytest.fixture
def pii_deny_config_path() -> str:
    """Return the absolute path to the pii_deny fixture config."""
    return PII_DENY_CONFIG
