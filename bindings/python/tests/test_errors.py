# Location: ./bindings/python/tests/test_errors.py
# Copyright 2025
# SPDX-License-Identifier: Apache-2.0
# Authors: Ted Habeck
#
# Error-path tests for cpex-python.

import pytest
from cpex import PolicyEngine


# ---------------------------------------------------------------------------
# Config errors
# ---------------------------------------------------------------------------


def test_missing_config_file_raises_value_error():
    """Missing config file raises ValueError."""
    with pytest.raises(ValueError, match="cannot read config file"):
        PolicyEngine("/nonexistent/path/config.yaml")


def test_malformed_yaml_raises_value_error(tmp_path):
    """Malformed YAML raises ValueError."""
    bad_config = tmp_path / "bad.yaml"
    bad_config.write_text("plugins: [\n  - name: broken\n    : : bad_yaml")
    with pytest.raises(ValueError):
        PolicyEngine(str(bad_config))


def test_valid_empty_config_constructs_ok(tmp_path):
    """A valid minimal config (no plugins) constructs without error."""
    empty_config = tmp_path / "empty.yaml"
    empty_config.write_text("plugins: []\n")
    eng = PolicyEngine(str(empty_config))
    assert eng is not None


# ---------------------------------------------------------------------------
# Conversion failure
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unconvertible_payload_raises_value_error(passthrough_engine: PolicyEngine):
    """An unconvertible Python type in the payload raises ValueError."""
    with pytest.raises(ValueError):
        await passthrough_engine.invoke_hook("custom.hook", {"bad": object()})


@pytest.mark.asyncio
async def test_invalid_cmf_payload_raises_value_error(passthrough_engine: PolicyEngine):
    """A cmf.* hook with a dict missing the `message` field raises ValueError."""
    # MessagePayload requires a `message:` field with a Message struct.
    # An empty dict (or a dict without `message`) fails serde deserialization.
    with pytest.raises(ValueError, match="not a valid MessagePayload"):
        await passthrough_engine.invoke_hook("cmf.tool_pre_invoke", {})
