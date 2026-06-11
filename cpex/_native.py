# Location: ./cpex/_native.py
# Copyright (c) 2024-2026
# SPDX-License-Identifier: Apache-2.0
# Authors: Bob (AI Assistant)

"""
Python wrapper for the Rust-based native plugin manager.

This module re-exports the Rust extension module classes with Python-friendly names.
"""

from cpex_native import Extensions as PyExtensions
from cpex_native import MessagePayload as PyMessagePayload
from cpex_native import OnError as PyOnError
from cpex_native import PluginConfig as PyPluginConfig
from cpex_native import PluginContext as PyPluginContext
from cpex_native import PluginContextTable as PyPluginContextTable
from cpex_native import PluginManager as PyPluginManager
from cpex_native import PluginMode as PyPluginMode
from cpex_native import PluginResult as PyPluginResult

__all__ = [
    "PyPluginManager",
    "PyPluginMode",
    "PyOnError",
    "PyPluginConfig",
    "PyPluginResult",
    "PyPluginContext",
    "PyPluginContextTable",
    "PyExtensions",
    "PyMessagePayload",
]

# Made with Bob
