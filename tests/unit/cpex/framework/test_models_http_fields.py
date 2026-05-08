# -*- coding: utf-8 -*-
"""Location: ./tests/unit/cpex/framework/test_models_http_fields.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0

Tests for HTTP-transport fields backported from ContextForge main:
  - PluginViolation.http_status_code
  - PluginViolation.http_headers
  - PluginResult.http_headers
"""

from cpex.framework.models import PluginResult, PluginViolation


def test_plugin_violation_http_fields_default_none():
    violation = PluginViolation(reason="r", description="d", code="C", details={})
    assert violation.http_status_code is None
    assert violation.http_headers is None


def test_plugin_violation_http_fields_set():
    violation = PluginViolation(
        reason="rate-limited",
        description="too many requests",
        code="RATE_LIMITED",
        details={},
        http_status_code=429,
        http_headers={"Retry-After": "30"},
    )
    assert violation.http_status_code == 429
    assert violation.http_headers == {"Retry-After": "30"}


def test_plugin_violation_http_fields_serialization_roundtrip():
    original = PluginViolation(
        reason="r",
        description="d",
        code="C",
        details={},
        http_status_code=422,
        http_headers={"X-Trace-Id": "abc"},
    )
    restored = PluginViolation.model_validate(original.model_dump())
    assert restored.http_status_code == 422
    assert restored.http_headers == {"X-Trace-Id": "abc"}


def test_plugin_result_http_headers_default_none():
    result = PluginResult()
    assert result.http_headers is None


def test_plugin_result_http_headers_set_and_roundtrip():
    result = PluginResult(http_headers={"X-RateLimit-Remaining": "0"})
    assert result.http_headers == {"X-RateLimit-Remaining": "0"}
    restored = PluginResult.model_validate(result.model_dump())
    assert restored.http_headers == {"X-RateLimit-Remaining": "0"}
