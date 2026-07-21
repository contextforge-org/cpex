# Location: ./bindings/python/tests/test_errors.py
# Copyright 2025
# SPDX-License-Identifier: Apache-2.0
# Authors: Ted Habeck
#
# Error-path tests for cpex-python (U2, U7, KD2, KD7).

import pytest
from cpex import PluginManager


# ---------------------------------------------------------------------------
# Config errors
# ---------------------------------------------------------------------------


def test_missing_config_file_raises_value_error():
    """Missing config file → ValueError (R2)."""
    with pytest.raises(ValueError, match="cannot read config file"):
        PluginManager("/nonexistent/path/config.yaml")


def test_malformed_yaml_raises_value_error(tmp_path):
    """Malformed YAML → ValueError (R2)."""
    bad_config = tmp_path / "bad.yaml"
    bad_config.write_text("plugins: [\n  - name: broken\n    : : bad_yaml")
    with pytest.raises(ValueError):
        PluginManager(str(bad_config))


def test_valid_empty_config_constructs_ok(tmp_path):
    """A valid minimal config (no plugins) constructs without error."""
    empty_config = tmp_path / "empty.yaml"
    empty_config.write_text("plugins: []\n")
    mgr = PluginManager(str(empty_config))
    assert mgr is not None


# ---------------------------------------------------------------------------
# Conversion failure (KD2)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unconvertible_payload_raises_value_error(manager: PluginManager):
    """An unconvertible Python type in the payload raises ValueError (KD2, R2)."""
    with pytest.raises(ValueError):
        await manager.invoke_hook("custom.hook", {"bad": object()})


@pytest.mark.asyncio
async def test_invalid_cmf_payload_raises_value_error(manager: PluginManager):
    """A cmf.* hook with a dict missing the `message` field raises ValueError."""
    # MessagePayload requires a `message:` field with a Message struct.
    # An empty dict (or a dict without `message`) fails serde deserialization.
    with pytest.raises(ValueError, match="not a valid MessagePayload"):
        await manager.invoke_hook("cmf.tool_pre_invoke", {})
