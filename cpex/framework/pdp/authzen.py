# -*- coding: utf-8 -*-
"""AuthZen PDP resolver — OpenID AuthZen Access Evaluation API.

AuthZen defines a standard interface for policy evaluation that is
PDP-agnostic: the same API works whether the backend is OPA, Cedar,
Topaz, Cerbos, OSO, or any other engine implementing the spec.

AuthZen API (single evaluation):
    POST /access/v1/evaluation
    {
      "subject": { "type": "user", "id": "alice@corp.com", "properties": {...} },
      "action":  { "name": "read" },
      "resource": { "type": "tool", "id": "get_compensation", "properties": {...} },
      "context": { ... }
    }
    → { "decision": true }

AuthZen API (batch evaluation):
    POST /access/v1/evaluations
    {
      "evaluations": [
        { "subject": ..., "action": ..., "resource": ..., "context": ... },
        ...
      ]
    }
    → { "evaluations": [{ "decision": true }, { "decision": false }] }

Mapping from CPEX/APL types to AuthZen:
    SubjectExtension  → subject  (type, id, properties: roles/permissions/teams)
    route action      → action   (name)
    tool/resource     → resource (type, id, properties)
    everything else   → context  (delegation, session, authorization_details, args)

References:
    - OpenID AuthZen: https://openid.net/specs/openid-authzen-authorization-api-1_0.html
    - AuthZen interop: https://authzen.org
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from cpex.framework.pdp.base import PdpError, PdpResolver, PdpResult

logger = logging.getLogger(__name__)


class AuthZenResolver(PdpResolver):
    """AuthZen Access Evaluation API client.

    Translates CPEX pipeline context into AuthZen's subject/action/resource/context
    tuple and calls the evaluation endpoint.

    Args:
        endpoint: AuthZen evaluation endpoint URL. Supports {placeholder}
            templates interpolated from input_data at request time.
            Static:   "https://pdp.corp.com/access/v1/evaluation"
            Template: "https://pdp.corp.com/access/v1/{tool}/evaluation"
        timeout_ms: HTTP timeout in milliseconds. Default 500.
        headers: Additional HTTP headers (e.g., API keys, bearer tokens).
        fail_open: If True, allow on PDP errors. If False, raise PdpError.

    Usage:
        # Static endpoint
        resolver = AuthZenResolver("https://pdp.corp.com/access/v1/evaluation")

        # Template endpoint — per-tool policy sets
        resolver = AuthZenResolver("https://pdp.corp.com/access/v1/{tool}/evaluation")

        result = await resolver.resolve({
            "tool": "get_compensation",
            "action": "read",
            ...
        })
    """

    def __init__(
        self,
        endpoint: str,
        timeout_ms: int = 500,
        headers: dict[str, str] | None = None,
        fail_open: bool = False,
    ):
        """Initialize the AuthZen resolver.

        Args:
            endpoint: AuthZen evaluation endpoint URL. Supports {placeholder} templates.
            timeout_ms: HTTP timeout in milliseconds. Default 500.
            headers: Additional HTTP headers (e.g., API keys, bearer tokens).
            fail_open: If True, allow on PDP errors. If False, raise PdpError.
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
        flat = {k: str(v) for k, v in input_data.items() if isinstance(v, str)}
        try:
            return self._endpoint_template.format(**flat)
        except KeyError:
            logger.warning(
                "AuthZen endpoint template has unresolved placeholders: %s",
                self._endpoint_template,
            )
            return self._endpoint_template

    async def resolve(self, input_data: dict[str, Any]) -> PdpResult:
        """Evaluate a policy decision via AuthZen.

        Transforms the flat input_data (from APL's build_pdp_input) into
        the AuthZen subject/action/resource/context structure.
        If the endpoint is a template, placeholders are resolved from input_data.
        """
        endpoint = self._resolve_endpoint(input_data)
        request_body = self._build_request(input_data)

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
            logger.warning("AuthZen timeout after %.1fms: %s", latency_ms, endpoint)
            if self.fail_open:
                return PdpResult(
                    allowed=True,
                    reason="AuthZen timeout, fail-open",
                    latency_ms=latency_ms,
                )
            raise PdpError(
                f"AuthZen timeout after {latency_ms:.0f}ms",
                endpoint=endpoint,
                cause=e,
            )

        except httpx.HTTPStatusError as e:
            latency_ms = (time.monotonic() - start) * 1000
            logger.error(
                "AuthZen HTTP %d from %s: %s",
                e.response.status_code,
                endpoint,
                e.response.text[:200],
            )
            if self.fail_open:
                return PdpResult(
                    allowed=True,
                    reason=f"AuthZen HTTP {e.response.status_code}, fail-open",
                    latency_ms=latency_ms,
                )
            raise PdpError(
                f"AuthZen HTTP {e.response.status_code}",
                endpoint=endpoint,
                cause=e,
            )

        except httpx.HTTPError as e:
            latency_ms = (time.monotonic() - start) * 1000
            logger.error("AuthZen connection error: %s", e)
            if self.fail_open:
                return PdpResult(
                    allowed=True,
                    reason="AuthZen unreachable, fail-open",
                    latency_ms=latency_ms,
                )
            raise PdpError(
                f"AuthZen connection error: {e}",
                endpoint=endpoint,
                cause=e,
            )

    def _build_request(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Map CPEX pipeline context → AuthZen evaluation request.

        AuthZen expects:
            subject:  { type, id, properties }
            action:   { name, properties }
            resource: { type, id, properties }
            context:  { ... everything else ... }

        The input_data comes from APL's build_pdp_input() which extracts
        namespaces from the AttributeBag and ContentSurface.
        """
        # --- Subject ---
        subject_data = input_data.get("subject", {})
        subject = {
            "type": subject_data.get("type", "unknown"),
            "id": subject_data.get("id", "unknown"),
        }
        # Everything else in subject_data goes into properties
        subject_props = {k: v for k, v in subject_data.items() if k not in ("type", "id")}
        if subject_props:
            subject["properties"] = subject_props

        # --- Action ---
        action_name = input_data.get("action", "unknown")
        if isinstance(action_name, dict):
            action = action_name
        else:
            action = {"name": str(action_name)}

        # --- Resource ---
        resource_type = "tool"  # default for CPEX
        resource_id = input_data.get("tool", "unknown")
        if isinstance(resource_id, dict):
            resource = resource_id
        else:
            resource = {"type": resource_type, "id": str(resource_id)}

        # --- Context ---
        # Everything that isn't subject/action/tool goes into context
        context_keys = {"delegation", "session", "authorization_details", "args"}
        context = {}
        for key in context_keys:
            if key in input_data:
                context[key] = input_data[key]

        # Include any other keys that aren't part of the standard mapping
        standard_keys = {"subject", "action", "tool"} | context_keys
        for key, value in input_data.items():
            if key not in standard_keys:
                context[key] = value

        request: dict[str, Any] = {
            "subject": subject,
            "action": action,
            "resource": resource,
        }
        if context:
            request["context"] = context

        return request

    def _parse_response(self, body: dict[str, Any], latency_ms: float) -> PdpResult:
        """Parse AuthZen evaluation response.

        AuthZen response format:
            { "decision": true }
        or with context:
            { "decision": true, "context": { "reason": { ... } } }
        """
        decision = body.get("decision", False)

        # Extract reason from context if present
        reason = None
        resp_context = body.get("context", {})
        if isinstance(resp_context, dict):
            reason_obj = resp_context.get("reason", {})
            if isinstance(reason_obj, str):
                reason = reason_obj
            elif isinstance(reason_obj, dict):
                reason = reason_obj.get("message") or reason_obj.get("detail")

        return PdpResult(
            allowed=bool(decision),
            reason=reason,
            context=resp_context if isinstance(resp_context, dict) else {},
            latency_ms=latency_ms,
        )

    async def close(self) -> None:
        """Shut down the HTTP client."""
        await self._client.aclose()
