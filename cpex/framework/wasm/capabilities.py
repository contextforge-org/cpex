# -*- coding: utf-8 -*-
"""Location: ./cpex/framework/wasm/capabilities.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0

Capability registry for CPEX WASM plugins.

Capabilities are the security primitive: they determine which host imports
get linked into a wasm instance. A capability NOT listed in the manifest
is NOT linked, and the wasm runtime refuses to instantiate a component
that tries to import an unlinked function. This is structural sandboxing.

Each capability is either:
    - a bare token like "log", "kv:read"
    - a parameterized form like "http:fetch:api.example.com:443"
      or "filesystem:read:/etc/cpex"
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

# Bare-token capabilities. Order is canonical and used for sorted listings.
CAPABILITY_NAMES: tuple[str, ...] = (
    "log",
    "clock",
    "random",
    "kv:read",
    "kv:write",
)

# Parameterized capabilities. Each entry is (prefix, allowed_pattern).
# The pattern matches the WHOLE capability string.
_PARAMETERIZED: tuple[tuple[str, re.Pattern[str]], ...] = (
    # http:fetch                        — unrestricted (discouraged)
    # http:fetch:host                   — any port on host
    # http:fetch:host:port              — specific host+port
    ("http:fetch", re.compile(r"^http:fetch(?::[^:\s]+(?::\d{1,5})?)?$")),
    # filesystem:{read|write}:/abs/path
    ("filesystem", re.compile(r"^filesystem:(read|write):/[^\s]+$")),
)


@dataclass(frozen=True)
class ParsedCapability:
    """Structured form of a capability string."""

    raw: str
    kind: str          # "log", "http:fetch", "filesystem:read", ...
    scope: Optional[str] = None   # "api.example.com:443" or "/etc/cpex" or None


def validate_capability_string(cap: str) -> None:
    """Raise ValueError if `cap` is not a known capability.

    Examples:
        >>> validate_capability_string("log")
        >>> validate_capability_string("http:fetch:api.example.com:443")
        >>> validate_capability_string("filesystem:read:/etc/cpex")
        >>> validate_capability_string("network")          # raises
        Traceback (most recent call last):
            ...
        ValueError: ...
    """
    if cap in CAPABILITY_NAMES:
        return
    for prefix, pattern in _PARAMETERIZED:
        if cap == prefix or cap.startswith(prefix + ":"):
            if pattern.fullmatch(cap):
                return
            raise ValueError(
                f"Capability {cap!r} has prefix {prefix!r} but invalid form. "
                f"Expected: {pattern.pattern}"
            )
    raise ValueError(
        f"Unknown capability: {cap!r}. "
        f"Known bare capabilities: {sorted(CAPABILITY_NAMES)}; "
        f"parameterized prefixes: {[p for p, _ in _PARAMETERIZED]}"
    )


def parse_capability(cap: str) -> ParsedCapability:
    """Parse a capability string into (kind, optional scope).

    For bare tokens, scope is None. For parameterized capabilities, the
    scope is everything after the kind prefix.
    """
    validate_capability_string(cap)
    if cap in CAPABILITY_NAMES:
        return ParsedCapability(raw=cap, kind=cap, scope=None)
    for prefix, _ in _PARAMETERIZED:
        if cap == prefix:
            return ParsedCapability(raw=cap, kind=prefix, scope=None)
        if cap.startswith(prefix + ":"):
            # e.g. http:fetch + : + api.example.com:443
            # We need to be careful: prefix may itself contain ':'.
            rest = cap[len(prefix) + 1 :]
            # For filesystem we treat the next token as part of the kind.
            if prefix == "filesystem":
                mode, _, path = rest.partition(":")
                return ParsedCapability(
                    raw=cap, kind=f"filesystem:{mode}", scope=path
                )
            return ParsedCapability(raw=cap, kind=prefix, scope=rest)
    raise AssertionError("unreachable")  # validate_capability_string filtered


def check_capabilities_subset(
    required: list[str], granted: list[str]
) -> None:
    """Verify that the wasm-declared required capabilities are a subset of
    what the YAML manifest grants.

    Used during the manifest cross-check: the component MUST NOT need more
    than the deployer gave it.
    """
    granted_set = set(granted)
    missing = [c for c in required if c not in granted_set]
    if missing:
        raise ValueError(
            f"Component requires capabilities not granted by manifest: {missing}. "
            f"Granted: {sorted(granted_set)}"
        )
