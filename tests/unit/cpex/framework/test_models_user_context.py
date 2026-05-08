# -*- coding: utf-8 -*-
"""Location: ./tests/unit/cpex/framework/test_models_user_context.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0

Tests for UserContext model and its propagation through GlobalContext / PluginContext.
The model and field shape mirror ContextForge main (#3152) so plugins coded against
the gateway's `context.user_context.X` API keep working unchanged.
"""

from datetime import datetime, timezone

from cpex.framework import GlobalContext, PluginContext, UserContext


def test_user_context_defaults():
    uc = UserContext(user_id="alice@example.com")
    assert uc.user_id == "alice@example.com"
    assert uc.email is None
    assert uc.full_name is None
    assert uc.is_admin is False
    assert uc.groups == []
    assert uc.roles == []
    assert uc.team_id is None
    assert uc.teams is None
    assert uc.department is None
    assert uc.attributes == {}
    assert uc.auth_method is None
    assert uc.authenticated_at is None
    assert uc.service_account is None
    assert uc.delegation_chain == []


def test_user_context_full_construction():
    ts = datetime(2026, 4, 30, 12, 0, 0, tzinfo=timezone.utc)
    uc = UserContext(
        user_id="bob@example.com",
        email="bob@example.com",
        full_name="Bob Builder",
        is_admin=True,
        groups=["eng", "sec"],
        roles=["admin"],
        team_id="t1",
        teams=["t1", "t2"],
        department="Platform",
        attributes={"locale": "en-US"},
        auth_method="bearer",
        authenticated_at=ts,
        service_account="svc-deploy",
        delegation_chain=["alice@example.com"],
    )
    assert uc.is_admin is True
    assert uc.auth_method == "bearer"
    assert uc.authenticated_at == ts
    assert uc.delegation_chain == ["alice@example.com"]


def test_user_context_serialization_roundtrip():
    ts = datetime(2026, 4, 30, 12, 0, 0, tzinfo=timezone.utc)
    original = UserContext(
        user_id="carol@example.com",
        email="carol@example.com",
        is_admin=False,
        groups=["eng"],
        attributes={"k": "v"},
        authenticated_at=ts,
        delegation_chain=["alice@example.com", "bob@example.com"],
    )
    restored = UserContext.model_validate(original.model_dump())
    assert restored == original


def test_global_context_user_context_default_none():
    gc = GlobalContext(request_id="r1")
    assert gc.user_context is None


def test_global_context_user_context_set():
    uc = UserContext(user_id="alice@example.com")
    gc = GlobalContext(request_id="r1", user_context=uc)
    assert gc.user_context is uc
    assert gc.user_context.user_id == "alice@example.com"


def test_plugin_context_user_context_property_proxies_global():
    uc = UserContext(user_id="alice@example.com", is_admin=True)
    pc = PluginContext(global_context=GlobalContext(request_id="r1", user_context=uc))
    # Property must return the same instance held on the global context.
    assert pc.user_context is pc.global_context.user_context
    assert pc.user_context is uc
    assert pc.user_context.is_admin is True


def test_plugin_context_user_context_property_returns_none_when_unset():
    pc = PluginContext(global_context=GlobalContext(request_id="r1"))
    assert pc.user_context is None


def test_plugin_context_user_email_from_user_context():
    uc = UserContext(user_id="alice@example.com", email="alice@example.com")
    pc = PluginContext(global_context=GlobalContext(request_id="r1", user_context=uc))
    assert pc.user_email == "alice@example.com"


def test_plugin_context_user_email_falls_back_to_legacy_string():
    pc = PluginContext(global_context=GlobalContext(request_id="r1", user="bob@example.com"))
    assert pc.user_email == "bob@example.com"


def test_plugin_context_user_email_falls_back_to_legacy_dict():
    pc = PluginContext(
        global_context=GlobalContext(request_id="r1", user={"email": "carol@example.com", "name": "Carol"})
    )
    assert pc.user_email == "carol@example.com"


def test_plugin_context_user_email_none_when_no_identity():
    pc = PluginContext(global_context=GlobalContext(request_id="r1"))
    assert pc.user_email is None


def test_plugin_context_user_groups_from_user_context():
    uc = UserContext(user_id="alice@example.com", groups=["eng", "sec"])
    pc = PluginContext(global_context=GlobalContext(request_id="r1", user_context=uc))
    assert pc.user_groups == ["eng", "sec"]


def test_plugin_context_user_groups_empty_when_no_user_context():
    pc = PluginContext(global_context=GlobalContext(request_id="r1"))
    assert pc.user_groups == []
