# Location: ./bindings/python/tests/test_builtins.py
# Copyright 2025
# SPDX-License-Identifier: Apache-2.0
#
# The builtin set the wheel ships: registered kinds and hooks, removed
# kinds, OPA and CIBA, the private-destination switch, and secret refresh.

import json
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from cpex import PolicyEngine

from _support import WIRE_COMPAT_JSON, tool_call, tool_route


@pytest.fixture(scope="module")
def wire_compat() -> dict:
    """The kind and hook list shared with the C FFI tests."""
    return json.loads(WIRE_COMPAT_JSON.read_text())


def _write(tmp_path, text: str) -> str:
    path = tmp_path / "config.yaml"
    path.write_text(text)
    return str(path)


def _load_error(tmp_path, body: str) -> str:
    """The load error for a config, or an empty string when it loads."""
    try:
        PolicyEngine(_write(tmp_path, body))
    except ValueError as e:
        return str(e)
    return ""


def _plugin_probe(kind: str, hook: str) -> str:
    return (
        "engine_settings:\n  dispatch: hooks\n"
        f"plugins:\n  - name: probe\n    kind: {kind}\n    hooks: [{hook}]\n"
    )


# ---------------------------------------------------------------------------
# Registered kinds and hooks
# ---------------------------------------------------------------------------


def test_plugin_kinds_match_the_wire_compat_fixture(tmp_path, wire_compat):
    """Every pinned plugin kind resolves; every removed kind does not."""
    for kind in wire_compat["plugin_kinds"]:
        err = _load_error(tmp_path, _plugin_probe(kind, "identity.resolve"))
        assert "no factory registered" not in err, f"{kind} must resolve; got: {err}"
    for kind in wire_compat["absent_plugin_kinds"]:
        err = _load_error(tmp_path, _plugin_probe(kind, "identity.resolve"))
        assert "no factory registered" in err, f"{kind} must not resolve; got: {err}"


def test_pdp_kinds_match_the_wire_compat_fixture(tmp_path, wire_compat):
    """Every pinned PDP kind resolves under `global.pdp`."""
    for kind in wire_compat["pdp_kinds"]:
        err = _load_error(tmp_path, f"global:\n  pdp:\n    - kind: {kind}\n")
        assert "no factory is registered" not in err, f"{kind} must resolve; got: {err}"
    err = _load_error(tmp_path, "global:\n  pdp:\n    - kind: no-such-pdp\n")
    assert "no factory is registered" in err


def test_session_store_kinds_match_the_wire_compat_fixture(tmp_path, wire_compat):
    """Every pinned session store kind resolves under `global.session_store`."""
    for kind in wire_compat["session_store_kinds"]:
        err = _load_error(tmp_path, f"global:\n  session_store:\n    kind: {kind}\n")
        assert "no factory is registered" not in err, f"{kind} must resolve; got: {err}"
    err = _load_error(tmp_path, "global:\n  session_store:\n    kind: no-such-store\n")
    assert "no factory is registered" in err


@pytest.mark.asyncio
async def test_secret_provider_kinds_match_the_wire_compat_fixture(tmp_path, wire_compat):
    """The engine lists its registered provider kinds for an unknown one."""
    eng = PolicyEngine(
        _write(
            tmp_path,
            "engine_settings:\n  dispatch: hooks\n"
            "secrets:\n  providers:\n    probe:\n      kind: no-such-backend\n"
            "  values:\n    probe_value:\n      provider: probe\n      ref: anything\n",
        )
    )
    with pytest.raises(ValueError) as info:
        await eng.initialize()
    listed = str(info.value).split("registered kinds are [")[1].split("]")[0]
    assert set(listed.split(", ")) == set(wire_compat["secret_provider_kinds"])


def test_hook_names_match_the_wire_compat_fixture(tmp_path, wire_compat):
    """Every pinned hook name loads; every removed legacy name is rejected."""
    pinned = {hook for family in wire_compat["hooks"].values() for hook in family}
    for hook in pinned:
        err = _load_error(tmp_path, _plugin_probe("identity/jwt", hook))
        assert "unknown hook" not in err, f"{hook} must load; got: {err}"
    for hook in wire_compat["removed_hooks"]:
        err = _load_error(tmp_path, _plugin_probe("identity/jwt", hook))
        assert "unknown hook" in err, f"{hook} must be rejected; got: {err}"


@pytest.mark.asyncio
async def test_removed_hook_names_are_refused_at_invoke(passthrough_engine, wire_compat):
    """Every removed legacy name raises at invoke time instead of allowing."""
    for hook in wire_compat["removed_hooks"]:
        with pytest.raises(ValueError, match=f"'{hook}' was removed; use"):
            await passthrough_engine.invoke_hook(hook, {})


@pytest.mark.parametrize("kind", ["validator/pii-scan", "audit/logger"])
def test_removed_builtin_kind_fails_with_unknown_kind_error(tmp_path, kind):
    """A config naming a builtin removed in 0.3 fails to load, naming the kind."""
    path = _write(
        tmp_path,
        "plugins:\n"
        "  - name: removed\n"
        f"    kind: {kind}\n"
        "    hooks: [cmf.tool_pre_invoke]\n"
        "routes:\n"
        "  - tool: lookup_person\n"
        "    authorization:\n"
        "      pre_invocation:\n"
        '        - "run(removed)"\n',
    )
    with pytest.raises(ValueError, match="no factory registered") as info:
        PolicyEngine(path)
    assert kind in str(info.value)


# ---------------------------------------------------------------------------
# OPA
# ---------------------------------------------------------------------------

OPA_CONFIG = """
global:
  pdp:
    - kind: opa
      modules:
        - |
          package cpex.test
          default allow := false
          allow if input.args.amount <= 100

routes:
  - tool: transfer
    authorization:
      pre_invocation:
        - opa:
            query: "data.cpex.test.allow"
"""


@pytest.mark.asyncio
async def test_opa_pdp_loads_and_decides(tmp_path):
    """An in-process Rego module allows and denies by tool argument."""
    eng = PolicyEngine(_write(tmp_path, OPA_CONFIG))
    await eng.initialize()
    small = await eng.invoke_hook(
        "cmf.tool_pre_invoke", tool_call("transfer", {"amount": 50}), tool_route("transfer")
    )
    large = await eng.invoke_hook(
        "cmf.tool_pre_invoke", tool_call("transfer", {"amount": 500}), tool_route("transfer")
    )
    await eng.shutdown()

    assert small.continue_processing is True
    assert large.continue_processing is False
    assert large.violation["code"] == "opa"


# ---------------------------------------------------------------------------
# CIBA and the private-destination switch
# ---------------------------------------------------------------------------


class _MockCiba(BaseHTTPRequestHandler):
    """A CIBA OP that accepts every backchannel request and never approves."""

    seen: list = []

    def do_POST(self):
        length = int(self.headers.get("content-length", 0))
        type(self).seen.append((self.path, self.rfile.read(length).decode()))
        if self.path.endswith("/auth"):
            status, body = 200, {"auth_req_id": "req-1", "expires_in": 120, "interval": 5}
        else:
            status, body = 400, {"error": "authorization_pending"}
        out = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *args):
        pass


@pytest.fixture
def mock_ciba():
    """A loopback CIBA OP. Yields its base URL; records requests in `seen`."""
    _MockCiba.seen = []
    server = HTTPServer(("127.0.0.1", 0), _MockCiba)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def _ciba_config(base: str) -> str:
    return f"""
plugins:
  - name: ciba-approver
    kind: elicitation/ciba
    hooks: [elicit]
    capabilities: [perform_http]
    config:
      backchannel_endpoint: {base}/ciba/auth
      token_endpoint: {base}/token
      client_id: cpex-test
      client_secret_source: {{kind: literal, secret: test-secret}}
      insecure_http: true

routes:
  - tool: send_email
    authorization:
      pre_invocation:
        - 'require_approval(ciba-approver, from: args.approver, purpose: "Approve email")'
"""


async def _send_email(eng: PolicyEngine):
    return await eng.invoke_hook(
        "cmf.tool_pre_invoke",
        tool_call("send_email", {"approver": "mona"}),
        tool_route("send_email"),
    )


@pytest.mark.asyncio
async def test_ciba_reaches_a_loopback_op_with_the_opt_in(tmp_path, mock_ciba):
    """With allow_private_destinations=True the backchannel POST goes out."""
    eng = PolicyEngine(_write(tmp_path, _ciba_config(mock_ciba)), allow_private_destinations=True)
    await eng.initialize()
    result = await _send_email(eng)
    await eng.shutdown()

    auth = [body for path, body in _MockCiba.seen if path == "/ciba/auth"]
    assert len(auth) == 1, f"one backchannel request expected, saw {_MockCiba.seen}"
    assert "login_hint=mona" in auth[0]
    # The approval is still pending, so the call does not proceed.
    assert result.continue_processing is False
    assert "egress_denied" not in result.violation["reason"]


@pytest.mark.asyncio
async def test_ciba_is_refused_a_loopback_op_by_default(tmp_path, mock_ciba):
    """Without the opt-in the transport refuses loopback and nothing is sent."""
    eng = PolicyEngine(_write(tmp_path, _ciba_config(mock_ciba)))
    await eng.initialize()
    result = await _send_email(eng)
    await eng.shutdown()

    assert _MockCiba.seen == []
    assert result.continue_processing is False
    assert "elicitation.egress_denied" in result.violation["reason"]


def test_allow_private_destinations_is_keyword_only(tmp_path):
    """The switch cannot be passed positionally."""
    path = _write(tmp_path, "plugins: []\n")
    with pytest.raises(TypeError):
        PolicyEngine(path, True)  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Secret refresh
# ---------------------------------------------------------------------------


def _secrets_config(secret_file) -> str:
    return (
        "engine_settings:\n  dispatch: hooks\n"
        "secrets:\n"
        "  providers:\n    local:\n      kind: file\n"
        f"  values:\n    api_key:\n      provider: local\n      ref: {secret_file}\n"
    )


@pytest.mark.asyncio
async def test_refresh_secrets_reports_updates_and_failures(tmp_path):
    """refresh_secrets returns the FFI report shape; last success tracks health."""
    secret_file = tmp_path / "api_key"
    secret_file.write_text("first")
    eng = PolicyEngine(_write(tmp_path, _secrets_config(secret_file)))

    assert eng.secrets_last_success("local") is None, "nothing resolved before initialize"
    await eng.initialize()
    first = eng.secrets_last_success("local")
    assert isinstance(first, datetime)
    assert first.tzinfo is not None and first.utcoffset() == timezone.utc.utcoffset(None)
    assert eng.secrets_last_success("no-such-provider") is None

    unchanged = await eng.refresh_secrets()
    assert unchanged == {"updated": [], "unchanged": 1, "failed": []}

    secret_file.write_text("second")
    rotated = await eng.refresh_secrets()
    assert rotated == {"updated": ["api_key"], "unchanged": 0, "failed": []}
    assert eng.secrets_last_success("local") >= first

    secret_file.unlink()
    broken = await eng.refresh_secrets()
    assert broken["updated"] == [] and broken["unchanged"] == 0
    assert len(broken["failed"]) == 1
    failure = broken["failed"][0]
    assert set(failure) == {"secret", "provider", "kind", "message"}
    assert failure["secret"] == "api_key"
    assert failure["provider"] == "local"
    assert failure["kind"] == "not_found"
    assert "second" not in failure["message"], "the message never carries the secret"
    assert eng.secrets_last_success("local") is None, "a failed refresh clears last success"

    await eng.shutdown()


@pytest.mark.asyncio
async def test_refresh_secrets_without_a_secrets_block_is_empty(passthrough_engine):
    """An engine with no `secrets:` block returns an empty report."""
    assert await passthrough_engine.refresh_secrets() == {
        "updated": [],
        "unchanged": 0,
        "failed": [],
    }
