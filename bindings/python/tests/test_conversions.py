# Location: ./bindings/python/tests/test_conversions.py
# Copyright 2025
# SPDX-License-Identifier: Apache-2.0
# Authors: Ted Habeck
#
# Tests for PyObject ↔ JSON value conversion behaviour (U3).
# These are exercised through the Python API (invoke_hook with
# various payload shapes) — the Rust internals are not callable directly.

import pytest
from cpex import PluginManager


def _build_generic_payload(value: dict) -> dict:
    """Wrap a dict as a generic (non-cmf) hook payload."""
    return value


# ---------------------------------------------------------------------------
# Round-trip happy paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_flat_dict_round_trip(manager: PluginManager):
    """A flat dict passes through a non-cmf hook unchanged."""
    payload = {"key": "value", "num": 42, "flag": True}
    result = await manager.invoke_hook("custom.hook", payload)
    assert result.continue_processing is True


@pytest.mark.asyncio
async def test_nested_dict_round_trip(manager: PluginManager):
    """A nested dict/list passes through without ValueError."""
    payload = {"outer": {"inner": [1, 2, 3]}, "text": "hello"}
    result = await manager.invoke_hook("custom.hook", payload)
    assert result.continue_processing is True


@pytest.mark.asyncio
async def test_mixed_scalar_types(manager: PluginManager):
    """bool, int, float, str, None all accepted."""
    payload = {"b": True, "i": 7, "f": 3.14, "s": "text", "n": None}
    result = await manager.invoke_hook("custom.hook", payload)
    assert result.continue_processing is True


@pytest.mark.asyncio
async def test_empty_dict(manager: PluginManager):
    result = await manager.invoke_hook("custom.hook", {})
    assert result.continue_processing is True


@pytest.mark.asyncio
async def test_empty_list_in_payload(manager: PluginManager):
    result = await manager.invoke_hook("custom.hook", {"items": []})
    assert result.continue_processing is True


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_nesting_at_128_levels_succeeds(manager: PluginManager):
    """Exactly 128 levels deep (depth arg == 128) must succeed — depth > 128 is the guard."""
    payload: dict = {}
    current = payload
    for _ in range(128):  # root is depth=0; 128 children → deepest call is depth=128
        current["child"] = {}
        current = current["child"]
    result = await manager.invoke_hook("custom.hook", payload)
    assert result.continue_processing is True


@pytest.mark.asyncio
async def test_nesting_at_129_levels_raises(manager: PluginManager):
    """129 levels deep (depth arg == 129 > 128) raises ValueError (R3)."""
    payload: dict = {}
    current = payload
    for _ in range(129):  # root is depth=0; 129 children → deepest call depth=129 > 128
        current["child"] = {}
        current = current["child"]
    with pytest.raises(ValueError, match="nesting exceeds maximum depth"):
        await manager.invoke_hook("custom.hook", payload)


@pytest.mark.asyncio
async def test_non_string_key_raises(manager: PluginManager):
    """A dict with a non-string key must raise ValueError."""
    # Cannot construct {1: "v"} as a typed dict but we can via **kwargs trick.
    bad_payload = {1: "value"}  # type: ignore[dict-item]
    with pytest.raises((ValueError, TypeError)):
        await manager.invoke_hook("custom.hook", bad_payload)


@pytest.mark.asyncio
async def test_unconvertible_type_raises(manager: PluginManager):
    """An unconvertible Python type (set) in the payload raises ValueError."""
    bad_payload = {"items": {1, 2, 3}}  # type: ignore[dict-item]
    with pytest.raises(ValueError, match="cannot convert Python object"):
        await manager.invoke_hook("custom.hook", bad_payload)
