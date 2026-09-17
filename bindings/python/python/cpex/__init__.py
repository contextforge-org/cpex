# Location: ./bindings/python/python/cpex/__init__.py
# Copyright 2025
# SPDX-License-Identifier: Apache-2.0
# Authors: Ted Habeck
#
# Rust-backed cpex package — re-exports from the native extension module.
#
# Import from here, not from cpex._lib directly.
# No import-time side effects beyond loading the native extension (R4, #7).
from cpex._lib import PipelineResult, PluginManager

__all__ = ["PluginManager", "PipelineResult"]
