# -*- coding: utf-8 -*-
"""Location: ./cpex/__init__.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Fred Araujo

ContextForge Plugin Framework and Utilities Package.

This module provides the main entry point for the CPEX plugin framework,
with automatic backend selection between pure Python and Rust implementations.
"""

import os
from typing import Literal

# Backend selection logic
# Priority:
# 1. CPEX_BACKEND environment variable ("rust" or "python")
# 2. Availability of Rust backend (cpex_native module)
# 3. Fallback to pure Python backend

BACKEND: Literal["rust", "python"] = "python"  # Default
_RUST_AVAILABLE = False

# Check if Rust backend is available
try:
    from cpex._native import (
        PyExtensions,
        PyMessagePayload,
        PyOnError,
        PyPluginConfig,
        PyPluginContext,
        PyPluginContextTable,
        PyPluginMode,
        PyPluginResult,
    )
    from cpex._native import (
        PyPluginManager as RustPluginManager,
    )

    _RUST_AVAILABLE = True
except ImportError:
    _RUST_AVAILABLE = False
    RustPluginManager = None  # type: ignore

# Determine backend from environment or availability
_backend_env = os.environ.get("CPEX_BACKEND", "").lower()
if _backend_env == "rust":
    if not _RUST_AVAILABLE:
        raise ImportError(
            "CPEX_BACKEND=rust specified but Rust backend (cpex_native) is not available. "
            "Build the Rust extension with: maturin develop --manifest-path crates/cpex-python/Cargo.toml"
        )
    BACKEND = "rust"
elif _backend_env == "python":
    BACKEND = "python"
elif _RUST_AVAILABLE:
    # Auto-select Rust if available and no explicit preference
    BACKEND = "rust"
else:
    BACKEND = "python"

# Import the appropriate backend
if BACKEND == "rust":
    # Rust backend - use PyO3 bindings
    # Note: Currently supports Rust plugins only
    # Python plugin support will be added in a future phase
    PluginManager = RustPluginManager

    # Export Rust types
    __all__ = [
        "PluginManager",
        "RustPluginManager",
        "BACKEND",
        "PyPluginMode",
        "PyOnError",
        "PyPluginConfig",
        "PyPluginResult",
        "PyPluginContext",
        "PyPluginContextTable",
        "PyExtensions",
        "PyMessagePayload",
    ]
else:
    # Pure Python backend - import from framework
    try:
        from cpex.framework.manager import PluginManager as PythonPluginManager

        PluginManager = PythonPluginManager

        __all__ = [
            "PluginManager",
            "PythonPluginManager",
            "BACKEND",
        ]
    except ImportError as e:
        raise ImportError(f"Failed to import Python backend: {e}. Ensure cpex.framework is properly installed.") from e

# Version info
__version__ = "0.1.0"
__author__ = "ContextForge Team"
__license__ = "Apache-2.0"


# Provide backend information
def get_backend_info() -> dict:
    """Get information about the current backend.

    Returns:
        dict: Backend information including:
            - backend: "rust" or "python"
            - rust_available: bool
            - version: str
    """
    return {
        "backend": BACKEND,
        "rust_available": _RUST_AVAILABLE,
        "version": __version__,
    }


# Made with Bob
