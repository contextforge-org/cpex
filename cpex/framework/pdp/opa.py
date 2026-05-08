# -*- coding: utf-8 -*-
"""OPA PDP resolver — Open Policy Agent Data API.

OPA's Data API evaluates a Rego policy against an input document:

    POST /v1/data/{policy_path}
    { "input": { ... } }
    → { "result": true }

Unlike AuthZen, OPA's input is free-form — whatever the Rego policy
expects. We pass the CPEX pipeline context as-is under the "input" key,
so Rego policies can reference it directly:

    package cpex.authz

    default allow = false

    allow {
        some detail in input.authorization_details.types
        detail == "tool_invocation"
        "read" in input.authorization_details.actions
        input.delegation.depth <= 3
    }

    deny[msg] {
        input.session.labels[_] == "PII"
        input.action == "forward"
        msg := "Cannot forward PII-tainted data"
    }

References:
    - OPA REST API: https://www.openpolicyagent.org/docs/latest/rest-api/
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from cpex.framework.pdp.base import PdpError, PdpResolver, PdpResult

logger = logging.getLogger(__name__)


class OpaResolver(PdpResolver):
    """Open Policy Agent Data API client.

    Sends CPEX pipeline context as OPA input and reads the decision
    from the result.

    Args:
        endpoint: OPA policy data endpoint. Supports {placeholder} templates
            that are interpolated from the input_data at request time.
            Static:   "http://opa:8181/v1/data/cpex/authz/allow"
            Template: "http://opa:8181/v1/data/cpex/tools/{tool}/allow"
        timeout_ms: HTTP timeout in milliseconds. Default 500.
        headers: Additional HTTP headers.
        fail_open: If True, allow on OPA errors. If False, raise PdpError.

    Usage:
        # Static endpoint — same OPA package for all tools
        resolver = OpaResolver("http://opa:8181/v1/data/cpex/authz/allow")

        # Template endpoint — per-tool OPA packages
        resolver = OpaResolver("http://opa:8181/v1/data/cpex/tools/{tool}/allow")

        result = await resolver.resolve({
            "tool": "get_compensation",
            "action": "read",
            ...
        })
        # With template: hits /v1/data/cpex/tools/get_compensation/allow
    """

    def __init__(
        self,
        endpoint: str,
        timeout_ms: int = 500,
        headers: dict[str, str] | None = None,
        fail_open: bool = False,
    ):
        """Initialize the OPA resolver.

        Args:
            endpoint: OPA policy data endpoint URL. Supports {placeholder} templates.
            timeout_ms: HTTP timeout in milliseconds. Default 500.
            headers: Additional HTTP headers.
            fail_open: If True, allow on OPA errors. If False, raise PdpError.
        """
        self._endpoint_template = endpoint
        self.fail_open = fail_open
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_ms / 1000.0),
            headers=headers or {},
        )

    def _resolve_endpoint(self, input_data: dict[str, Any]) -> str:
        """Resolve the endpoint URL, interpolating any {placeholders}."""
        if "{" not in self._endpoint_template:
            return self._endpoint_template
        # Flatten input_data to string values for interpolation
        flat = {k: str(v) for k, v in input_data.items() if isinstance(v, str)}
        try:
            return self._endpoint_template.format(**flat)
        except KeyError:
            # Missing placeholder — use template as-is
            logger.warning(
                "OPA endpoint template has unresolved placeholders: %s",
                self._endpoint_template,
            )
            return self._endpoint_template

    async def resolve(self, input_data: dict[str, Any]) -> PdpResult:
        """Evaluate a policy decision via OPA.

        The input_data is passed directly as OPA's `input` document.
        Rego policies reference fields as `input.delegation.depth`, etc.
        If the endpoint is a template, placeholders are resolved from input_data.
        """
        endpoint = self._resolve_endpoint(input_data)
        request_body = {"input": input_data}

        start = time.monotonic()
        try:
            response = await self._client.post(
                endpoint,
                json=request_body,
            )
            latency_ms = (time.monotonic() - start) * 1000
            response.raise_for_status()
            return self._parse_response(response.json(), latency_ms)

        except httpx.TimeoutException as e:
            latency_ms = (time.monotonic() - start) * 1000
            logger.warning("OPA timeout after %.1fms: %s", latency_ms, endpoint)
            if self.fail_open:
                return PdpResult(
                    allowed=True,
                    reason="OPA timeout, fail-open",
                    latency_ms=latency_ms,
                )
            raise PdpError(
                f"OPA timeout after {latency_ms:.0f}ms",
                endpoint=endpoint,
                cause=e,
            )

        except httpx.HTTPStatusError as e:
            latency_ms = (time.monotonic() - start) * 1000
            logger.error("OPA HTTP %d from %s", e.response.status_code, endpoint)
            if self.fail_open:
                return PdpResult(
                    allowed=True,
                    reason=f"OPA HTTP {e.response.status_code}, fail-open",
                    latency_ms=latency_ms,
                )
            raise PdpError(
                f"OPA HTTP {e.response.status_code}",
                endpoint=endpoint,
                cause=e,
            )

        except httpx.HTTPError as e:
            latency_ms = (time.monotonic() - start) * 1000
            logger.error("OPA connection error: %s", e)
            if self.fail_open:
                return PdpResult(
                    allowed=True,
                    reason="OPA unreachable, fail-open",
                    latency_ms=latency_ms,
                )
            raise PdpError(
                f"OPA connection error: {e}",
                endpoint=endpoint,
                cause=e,
            )

    def _parse_response(self, body: dict[str, Any], latency_ms: float) -> PdpResult:
        """Parse OPA Data API response.

        OPA returns different shapes depending on the policy:
            { "result": true }                          — boolean policy
            { "result": { "allow": true } }             — structured policy
            { "result": { "allow": true, "deny": [] } } — allow + deny reasons
        """
        result = body.get("result")

        if isinstance(result, bool):
            return PdpResult(allowed=result, latency_ms=latency_ms)

        if isinstance(result, dict):
            allowed = result.get("allow", False)
            reason = None

            # Extract deny reasons if present
            deny_reasons = result.get("deny", [])
            if deny_reasons:
                if isinstance(deny_reasons, list) and deny_reasons:
                    reason = deny_reasons[0] if isinstance(deny_reasons[0], str) else str(deny_reasons[0])
                elif isinstance(deny_reasons, str):
                    reason = deny_reasons

            return PdpResult(
                allowed=bool(allowed),
                reason=reason,
                context=result,
                latency_ms=latency_ms,
            )

        # Unexpected format — log and use fail mode
        logger.warning("Unexpected OPA response format: %s", body)
        return PdpResult(
            allowed=self.fail_open,
            reason=f"Unexpected OPA response: {type(result).__name__}",
            latency_ms=latency_ms,
        )

    async def close(self) -> None:
        """Shut down the HTTP client."""
        await self._client.aclose()
