# Location: ./bindings/python/tests/test_wrappers.py
# Copyright 2026
# SPDX-License-Identifier: Apache-2.0
# Authors: Teryl Taylor
#
# DEMONSTRATION: the typed wrapper layer (handles, not dicts).
#
# Shows the three properties the dict path can't give you:
#   1. typed construction + typed attribute reads (backward-compat ergonomics)
#   2. invariants enforced by the Rust type system, not by convention
#   3. zero-conversion invoke (the wrapped Message goes through invoke_hook)
#
# Run under maturin:  cd bindings/python && maturin develop && pytest tests/test_wrappers.py

from pathlib import Path

import pytest

import cpex


# --- 1. typed construction + typed attribute reads -------------------------

def test_message_is_a_typed_object_not_a_dict():
    msg = cpex.Message(role="user", text="What is the weather?")
    assert msg.role == "user"            # typed enum -> str, not msg["role"]
    assert msg.text == "What is the weather?"
    assert msg.schema_version == "2.0"


def test_subject_extension_typed_sets():
    subj = cpex.SubjectExtension(
        id="alice",
        subject_type="user",
        roles=["hr", "auditor"],
    )
    assert subj.id == "alice"
    assert subj.roles == frozenset({"hr", "auditor"})


# --- 2. invariants enforced in Rust, not by convention ---------------------

def test_message_is_frozen():
    msg = cpex.Message(role="user", text="hi")
    with pytest.raises(AttributeError):
        msg.role = "assistant"           # no setter exists — immutable handle


def test_labels_are_monotonic_add_only():
    sec = cpex.SecurityExtension(labels=["PII"])
    sec.add_label("CONFIDENTIAL")
    assert sec.has_label("PII")
    assert sec.has_label("CONFIDENTIAL")
    assert sec.labels == frozenset({"PII", "CONFIDENTIAL"})


def test_label_removal_is_unrepresentable():
    sec = cpex.SecurityExtension(labels=["PII"])
    # The whole point: there is no API surface to remove a label.
    assert not hasattr(sec, "remove_label")
    assert not hasattr(sec, "clear_labels")
    # `.labels` is a frozenset snapshot — mutating it cannot affect the Rust set.
    snapshot = sec.labels
    with pytest.raises(AttributeError):
        snapshot.remove("PII")           # frozenset has no remove
    assert sec.has_label("PII")


# --- 3. zero-conversion invoke against a builtin plugin --------------------

FIXTURES = Path(__file__).parent / "fixtures"
PII_DENY = str(FIXTURES / "pii_deny.yaml")


@pytest.mark.asyncio
async def test_wrapped_message_clean_passes_builtin():
    # Typed Message with benign text → the builtin validator/pii-scan allows it.
    mgr = cpex.PluginManager(PII_DENY)
    await mgr.initialize()

    msg = cpex.Message(role="user", text="Hello, world!")
    result = await mgr.invoke_hook("cmf.tool_pre_invoke", msg)
    assert result.continue_processing is True

    await mgr.shutdown()


@pytest.mark.asyncio
async def test_wrapped_toolcall_triggers_builtin_pii_deny():
    # Fully typed construction — no dict anywhere — reproduces AE2:
    # a tool_call carrying an SSN routes through the builtin validator/pii-scan
    # (a real Rust plugin) and is denied. Proves a builtin executes against the
    # zero-conversion typed-handle fast path.
    mgr = cpex.PluginManager(PII_DENY)
    await mgr.initialize()

    tc = cpex.ToolCall(
        name="lookup_person",
        arguments={"ssn": "123-45-6789"},
        tool_call_id="tc_001",
    )
    msg = cpex.Message(role="assistant", content=[cpex.ContentPart.tool_call(tc)])

    result = await mgr.invoke_hook("cmf.tool_pre_invoke", msg)
    assert result.continue_processing is False, "pii-scan deny should halt pipeline"
    assert result.violation is not None
    assert "reason" in result.violation

    await mgr.shutdown()


# --- 4. full CMF + extension coverage --------------------------------------

def test_all_content_part_factories_construct():
    # Every ContentPart variant is constructable as a typed handle.
    parts = [
        cpex.ContentPart.text("hi"),
        cpex.ContentPart.thinking("hmm"),
        cpex.ContentPart.tool_call(cpex.ToolCall(name="t")),
        cpex.ContentPart.tool_result(
            cpex.ToolResult(tool_call_id="tc", tool_name="t", content={"ok": True})
        ),
        cpex.ContentPart.resource(
            cpex.Resource(resource_request_id="r", uri="file:///x", resource_type="file")
        ),
        cpex.ContentPart.image(cpex.ImageSource(type="url", data="http://x/y.png")),
        cpex.ContentPart.document(cpex.DocumentSource(type="url", data="http://x/d.pdf")),
    ]
    kinds = [p.kind for p in parts]
    assert kinds == [
        "text", "thinking", "tool_call", "tool_result", "resource", "image", "document",
    ]
    # Message accepts the typed content list and reads it back as typed parts.
    msg = cpex.Message(role="assistant", content=parts)
    assert [p.kind for p in msg.content] == kinds


def test_serde_wrapper_roundtrips_via_to_dict():
    # The macro-generated wrappers validate on construction and read via to_dict.
    tc = cpex.ToolCall(name="lookup", arguments={"id": 42}, tool_call_id="tc_9")
    assert tc.name == "lookup"
    assert tc.arguments == {"id": 42}

    agent = cpex.AgentExtension(session_id="s-1", turn=3)
    d = agent.to_dict()
    assert d["session_id"] == "s-1"
    assert d["turn"] == 3


def test_macro_types_have_typed_attribute_getters():
    # (b): macro-generated wrappers expose .field attribute access, not just
    # to_dict() — parity with the legacy pydantic attribute-access contract.
    agent = cpex.AgentExtension(session_id="s-1", turn=3, agent_id="a-9")
    assert agent.session_id == "s-1"
    assert agent.turn == 3
    assert agent.agent_id == "a-9"

    client = cpex.ClientExtension(client_id="c-1", roles=["svc"], trust_level="first_party")
    assert client.client_id == "c-1"
    assert client.roles == ["svc"]
    assert client.trust_level == "first_party"


def test_none_optional_attribute_reads_as_none():
    # Per-field serialization means an unset optional reads back as None
    # (NOT AttributeError) — matches legacy pydantic semantics.
    agent = cpex.AgentExtension(session_id="s-1")
    assert agent.parent_agent_id is None
    assert agent.conversation is None
    # And a set field on the same object is still readable.
    assert agent.session_id == "s-1"


def test_invalid_field_rejected_at_construction():
    # Schema validation at the boundary: a bad enum value raises ValueError.
    with pytest.raises(ValueError):
        cpex.CompletionExtension(stop_reason="not_a_real_reason")


def test_extensions_container_assembles_typed_slots():
    subj = cpex.SubjectExtension(id="alice", roles=["hr"])
    sec = cpex.SecurityExtension(labels=["PII"], classification="secret", subject=subj)
    ext = cpex.Extensions(
        security=sec,
        request=cpex.RequestExtension(request_id="req-1"),
        agent=cpex.AgentExtension(session_id="s-1"),
    )
    # Typed read-back through the container.
    assert ext.security.has_label("PII")
    assert ext.security.classification == "secret"
    assert ext.security.subject.id == "alice"
    # Full projection still available.
    assert ext.to_dict()["request"]["request_id"] == "req-1"


@pytest.mark.asyncio
async def test_wrapped_message_with_typed_extensions_through_builtin():
    # Typed Message + typed Extensions container, both zero-conversion, through
    # the builtin PII scanner.
    mgr = cpex.PluginManager(PII_DENY)
    await mgr.initialize()

    msg = cpex.Message(role="user", text="Hello, world!")
    ext = cpex.Extensions(security=cpex.SecurityExtension(labels=["PII"]))
    result = await mgr.invoke_hook("cmf.tool_pre_invoke", msg, ext)
    assert result.continue_processing is True

    await mgr.shutdown()


# --- 5. identity + delegation payloads -------------------------------------

def test_identity_payload_typed_construction_and_getter():
    # IdentityPayload is the resolve-INPUT: it carries the inbound raw_token +
    # its source, plus any pre-resolved subject.
    idp = cpex.IdentityPayload(
        source="bearer",
        subject={"id": "alice", "roles": ["hr"]},
        raw_claims={"iss": "https://idp.example"},
    )
    # Typed getter surfaces the nested subject as a typed handle.
    assert idp.subject.id == "alice"
    assert idp.subject.roles == frozenset({"hr"})
    assert idp.to_dict()["raw_claims"]["iss"] == "https://idp.example"


def test_delegation_payload_constructs():
    # target_name is the one required field; the bearer_token secret is
    # serde(skip) and can only be injected Rust-side.
    dp = cpex.DelegationPayload(target_name="hr-service", metadata={"reason": "obo"})
    d = dp.to_dict()
    assert d["target_name"] == "hr-service"
    assert d["metadata"]["reason"] == "obo"


def test_nested_fields_return_typed_handles():
    # Nested struct fields come back as live typed handles (not dicts), so you
    # read them with typed attribute access all the way down.
    comp = cpex.CompletionExtension(
        model="claude",
        tokens={"input_tokens": 10, "output_tokens": 5, "total_tokens": 15},
    )
    assert isinstance(comp.tokens, cpex.TokenUsage)        # handle, not dict
    assert comp.tokens.total_tokens == 15                  # typed attr, one level down
    assert comp.tokens.input_tokens == 10

    agent = cpex.AgentExtension(
        session_id="s-1",
        conversation={"summary": "weather chat", "topics": ["weather"]},
    )
    assert isinstance(agent.conversation, cpex.ConversationContext)
    assert agent.conversation.summary == "weather chat"
    assert agent.conversation.topics == ["weather"]


def test_nested_handle_lists_and_payload_handles():
    # Vec<Struct> fields come back as lists of handles.
    deleg = cpex.DelegationExtension(
        depth=1,
        chain=[{"subject_id": "alice", "scopes_granted": ["read"]}],
    )
    assert isinstance(deleg.chain, list)
    assert isinstance(deleg.chain[0], cpex.DelegationHop)
    assert deleg.chain[0].subject_id == "alice"
    assert deleg.chain[0].scopes_granted == ["read"]

    # Payload nested objects are handles too.
    idp = cpex.IdentityPayload(
        source="bearer",
        client={"client_id": "app-1", "trust_level": "first_party"},
    )
    assert isinstance(idp.client, cpex.ClientExtension)
    assert idp.client.client_id == "app-1"
    assert idp.client.trust_level == "first_party"


@pytest.mark.asyncio
async def test_identity_payload_routes_through_invoke(tmp_path):
    # A wrapped IdentityPayload reaches invoke_hook via the typed fast path.
    # No identity plugin configured → empty pipeline returns allow.
    cfg = tmp_path / "empty.yaml"
    cfg.write_text("plugins: []\n")
    mgr = cpex.PluginManager(str(cfg))
    await mgr.initialize()

    idp = cpex.IdentityPayload(source="bearer", subject={"id": "bob"})
    result = await mgr.invoke_hook("identity.resolve", idp)
    assert result.continue_processing is True

    await mgr.shutdown()


# --- 6. identity END-TO-END through the real apl-identity-jwt builtin -------
#
# We can't register a *Python* mock plugin (the binding exposes no plugin
# registration — that's the Phase-6 host bridge). Instead we drive the real
# Rust builtin `identity/jwt`, which is fully self-contained with an HS256
# shared secret: sign a JWT in the test, feed it as a typed IdentityPayload,
# and assert the plugin verified + resolved it.

import time

import jwt as pyjwt

_HS_SECRET = "cpex-test-secret-please-rotate-0123456789"
_ISSUER = "https://idp.test"
_AUDIENCE = "cpex-test"


def _jwt_config(tmp_path) -> str:
    cfg = tmp_path / "jwt_identity.yaml"
    cfg.write_text(
        f"""
plugins:
  - name: jwt_identity
    kind: identity/jwt
    version: 1.0.0
    hooks:
      - identity.resolve
    mode: sequential
    priority: 10
    on_error: fail
    config:
      role: user
      trusted_issuers:
        - issuer: "{_ISSUER}"
          audiences: ["{_AUDIENCE}"]
          algorithms: ["HS256"]
          decoding_key:
            kind: secret
            secret: "{_HS_SECRET}"
"""
    )
    return str(cfg)


def _sign(sub: str, *, exp_offset: int = 3600, secret: str = _HS_SECRET) -> str:
    return pyjwt.encode(
        {
            "iss": _ISSUER,
            "aud": _AUDIENCE,
            "sub": sub,
            "exp": int(time.time()) + exp_offset,
        },
        secret,
        algorithm="HS256",
    )


@pytest.mark.asyncio
async def test_identity_jwt_resolves_subject_from_typed_payload(tmp_path):
    mgr = cpex.PluginManager(_jwt_config(tmp_path))
    await mgr.initialize()

    token = _sign("alice")
    idp = cpex.IdentityPayload(
        source="bearer", headers={"authorization": f"Bearer {token}"}
    )
    result = await mgr.invoke_hook("identity.resolve", idp)

    assert result.continue_processing is True, "valid JWT must be allowed"
    # The resolver populated subject on the payload it modified.
    assert result.modified_payload is not None, "resolved payload must come back"
    assert result.modified_payload["subject"]["id"] == "alice"
    # No synthetic serialize error was appended (serialize_payload handles it).
    assert result.errors == []

    await mgr.shutdown()


@pytest.mark.asyncio
async def test_identity_jwt_rejects_expired_token(tmp_path):
    mgr = cpex.PluginManager(_jwt_config(tmp_path))
    await mgr.initialize()

    expired = _sign("alice", exp_offset=-86400)  # 1 day ago, beyond any leeway
    idp = cpex.IdentityPayload(
        source="bearer", headers={"authorization": f"Bearer {expired}"}
    )
    result = await mgr.invoke_hook("identity.resolve", idp)

    assert result.continue_processing is False, "expired JWT must be denied"
    assert result.violation is not None

    await mgr.shutdown()


@pytest.mark.asyncio
async def test_identity_jwt_rejects_bad_signature(tmp_path):
    mgr = cpex.PluginManager(_jwt_config(tmp_path))
    await mgr.initialize()

    forged = _sign("alice", secret="the-wrong-secret-entirely-32bytes!")
    idp = cpex.IdentityPayload(
        source="bearer", headers={"authorization": f"Bearer {forged}"}
    )
    result = await mgr.invoke_hook("identity.resolve", idp)

    assert result.continue_processing is False, "bad-signature JWT must be denied"
    assert result.violation is not None

    await mgr.shutdown()
