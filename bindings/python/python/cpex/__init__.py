# Location: ./bindings/python/python/cpex/__init__.py
# Copyright 2025
# SPDX-License-Identifier: Apache-2.0
# Authors: Ted Habeck
#
# Rust-backed cpex package: re-exports from the native extension module.
#
# Import from here, not from cpex._lib directly.
# No import-time side effects beyond loading the native extension.
#
# `PluginManager` is the pre-0.3 name of `PolicyEngine`, kept as an alias
# so existing callers keep working. Both names are the same class.
from cpex._lib import PipelineResult, PolicyEngine

PluginManager = PolicyEngine

__all__ = ["PolicyEngine", "PluginManager", "PipelineResult"]
