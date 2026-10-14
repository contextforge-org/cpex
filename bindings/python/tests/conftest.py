# Location: ./bindings/python/tests/conftest.py
# Copyright 2025
# SPDX-License-Identifier: Apache-2.0
# Authors: Ted Habeck
#
# Pytest fixtures for cpex-python binding tests.
#
# No module-level os.environ mutation: env changes are scoped to the
# test function that needs them.

import pytest
from cpex import PolicyEngine

from _support import PASSTHROUGH_CONFIG, PII_DENY_CONFIG, PII_REDACT_CONFIG


@pytest.fixture
async def engine():
    """Create, initialize, and yield a PolicyEngine backed by pii_deny.yaml.

    Shuts down after the test so fire-and-forget tasks are drained.
    """
    eng = PolicyEngine(PII_DENY_CONFIG)
    await eng.initialize()
    yield eng
    await eng.shutdown()


@pytest.fixture
async def passthrough_engine():
    """Create, initialize, and yield a PolicyEngine with nothing to enforce."""
    eng = PolicyEngine(PASSTHROUGH_CONFIG)
    await eng.initialize()
    yield eng
    await eng.shutdown()


@pytest.fixture
def pii_deny_config_path() -> str:
    """Return the absolute path to the pii_deny fixture config."""
    return PII_DENY_CONFIG


@pytest.fixture
def pii_redact_config_path() -> str:
    """Return the absolute path to the pii_redact fixture config."""
    return PII_REDACT_CONFIG
