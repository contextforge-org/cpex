# -*- coding: utf-8 -*-
"""External Policy Decision Point (PDP) resolvers.

This module provides clients for delegating policy decisions to external
PDPs (OPA, Cedar, AuthZen, or custom) from within the APL pipeline.

The APL pipeline (Rust) defines the PdpResolver trait. These Python
classes implement that interface, handling the HTTP calls while the
Rust core stays synchronous and transport-agnostic.

Usage in YAML policy:
    policy:
      - authzen("https://pdp.corp.com/access/v1/evaluation"):
          timeout_ms: 500
          on_error: deny

Usage from Python (gateway integration):
    from cpex.framework.pdp import AuthZenResolver, OpaResolver

    resolver = AuthZenResolver("https://pdp.corp.com/access/v1/evaluation")
    # Pass to pipeline executor as the PDP callback
"""

from cpex.framework.pdp.authzen import AuthZenResolver
from cpex.framework.pdp.base import PdpResolver, PdpResult
from cpex.framework.pdp.opa import OpaResolver

__all__ = [
    "AuthZenResolver",
    "OpaResolver",
    "PdpResolver",
    "PdpResult",
]
