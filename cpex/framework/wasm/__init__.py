# -*- coding: utf-8 -*-
"""Location: ./cpex/framework/wasm/__init__.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0

CPEX WASM plugin support.

Exposes:
- WasmPlugin: host-side wrapper for Component Model wasm plugin artifacts
- WasmManifest: parsed, validated YAML manifest
- CAPABILITY_NAMES: the canonical capability registry
- WASM_API_VERSION: the WIT package version this host supports
"""

from cpex.framework.wasm.capabilities import CAPABILITY_NAMES
from cpex.framework.wasm.client import WasmPlugin
from cpex.framework.wasm.manifest import WasmManifest

WASM_API_VERSION = "cpex.plugin/v1"

__all__ = [
    "CAPABILITY_NAMES",
    "WASM_API_VERSION",
    "WasmManifest",
    "WasmPlugin",
]
