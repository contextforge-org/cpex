# -*- coding: utf-8 -*-
"""Tests for identity resolution and token delegation hook payloads.

Covers:
- IdentityPayload construction and SecretStr redaction
- DelegationPayload construction and SecretStr redaction
- AttenuationConfig construction
- IdentityResult construction
- Serialization safety (tokens redacted in JSON output)
"""

import pytest
from pydantic import SecretStr

from cpex.framework.extensions.security import SubjectExtension, SubjectType
from cpex.framework.hooks.identity import (
    AttenuationConfig,
    DelegationPayload,
    IdentityPayload,
    IdentityResult,
)


class TestIdentityPayload:
    """Tests for IdentityPayload."""

    def test_basic_construction(self):
        payload = IdentityPayload(
            raw_token="eyJhbGciOi...",
            source="bearer",
        )
        assert payload.source == "bearer"
        assert isinstance(payload.raw_token, SecretStr)

    def test_raw_token_is_secret(self):
        payload = IdentityPayload(raw_token="secret-jwt", source="bearer")
        # str() should redact
        assert "secret-jwt" not in str(payload.raw_token)
        # get_secret_value() reveals it
        assert payload.raw_token.get_secret_value() == "secret-jwt"

    def test_serialization_redacts_token(self):
        payload = IdentityPayload(raw_token="secret-jwt", source="bearer")
        dumped = payload.model_dump()
        # The serialized value should not contain the actual token
        assert dumped["raw_token"] != "secret-jwt"

    def test_with_headers(self):
        payload = IdentityPayload(
            raw_token="tok",
            source="bearer",
            headers={"authorization": "Bearer tok"},
            client_host="10.0.0.1",
            client_port=443,
        )
        assert payload.headers["authorization"] == "Bearer tok"
        assert payload.client_host == "10.0.0.1"

    def test_default_source(self):
        payload = IdentityPayload(raw_token="tok")
        assert payload.source == "bearer"


class TestDelegationPayload:
    """Tests for DelegationPayload."""

    def test_basic_construction(self):
        payload = DelegationPayload(
            target_name="get_compensation",
            target_type="tool",
            required_permissions=["read:compensation"],
        )
        assert payload.target_name == "get_compensation"
        assert payload.target_type == "tool"
        assert payload.bearer_token is None

    def test_bearer_token_is_secret(self):
        payload = DelegationPayload(
            target_name="get_compensation",
            bearer_token="my-bearer-token",
        )
        assert isinstance(payload.bearer_token, SecretStr)
        assert "my-bearer-token" not in str(payload.bearer_token)
        assert payload.bearer_token.get_secret_value() == "my-bearer-token"

    def test_serialization_redacts_bearer(self):
        payload = DelegationPayload(
            target_name="tool",
            bearer_token="secret-bearer",
        )
        dumped = payload.model_dump()
        assert dumped["bearer_token"] != "secret-bearer"

    def test_with_attenuation(self):
        attenuation = AttenuationConfig(
            capabilities=["read:compensation"],
            resource_template="hr://employees/{{ args.employee_id }}",
            actions=["read"],
            ttl_seconds=60,
        )
        payload = DelegationPayload(
            target_name="get_compensation",
            auth_enforced_by="target",
            route_attenuation=attenuation,
        )
        assert payload.route_attenuation.capabilities == ["read:compensation"]
        assert payload.route_attenuation.ttl_seconds == 60


class TestAttenuationConfig:
    """Tests for AttenuationConfig."""

    def test_basic_construction(self):
        config = AttenuationConfig(
            capabilities=["read:compensation"],
            actions=["read"],
        )
        assert config.capabilities == ["read:compensation"]
        assert config.actions == ["read"]
        assert config.resource_template is None
        assert config.ttl_seconds is None

    def test_frozen(self):
        config = AttenuationConfig(capabilities=["read"])
        with pytest.raises(Exception):
            config.capabilities = ["write"]

    def test_defaults(self):
        config = AttenuationConfig()
        assert config.capabilities == []
        assert config.actions == []
        assert config.resource_template is None
        assert config.ttl_seconds is None


class TestIdentityResult:
    """Tests for IdentityResult."""

    def test_accepted_result(self):
        subject = SubjectExtension(
            id="alice@corp.com",
            type=SubjectType.USER,
            roles=frozenset({"engineer"}),
            permissions=frozenset({"tool_execute"}),
        )
        result = IdentityResult(subject=subject)
        assert result.rejected is False
        assert result.subject.id == "alice@corp.com"

    def test_rejected_result(self):
        result = IdentityResult(
            rejected=True,
            reject_status=401,
            reject_reason="Token expired",
        )
        assert result.rejected is True
        assert result.reject_status == 401
        assert result.reject_reason == "Token expired"
        assert result.subject is None
