# Location: ./bindings/python/tests/test_acceptance.py
# Copyright 2025
# SPDX-License-Identifier: Apache-2.0
#
# Acceptance flows through the native library, the way a Python host
# drives them: load a config, resolve identity from a bearer token, apply
# the subject to the tool call's extensions, and read the decision.
#
# The JWT issuer is a loopback JWKS server serving one HS256 key, so the
# tests need no crypto package and no network. Loopback is a private
# destination, so engines that fetch from it opt in with
# allow_private_destinations=True.
#
# Covered elsewhere and not repeated here: CIBA elicitation and the
# private-destination refusal for it (test_builtins.py), and the engine
# semantics behind each flow (PPE's own e2e suites). Delegation is not
# drivable from Python: inbound tokens are never serialized, so they
# cannot cross the binding into a later tool call. The Go acceptance
# suite covers it through the single-call identity path.

import base64
import hashlib
import hmac
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from cpex import PolicyEngine

from _support import tool_call, tool_route

ISSUER = "https://idp.acceptance.test"
AUDIENCE = "cpex-acceptance"
KID = "acceptance-key"
HS256_SECRET = b"acceptance-only-hs256-secret-0123456789"


# ---------------------------------------------------------------------------
# Loopback JWKS issuer
# ---------------------------------------------------------------------------


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def mint(sub: str, roles: list[str], *, exp_offset: int = 600, secret: bytes = HS256_SECRET) -> str:
    """An HS256 JWT signed with the issuer key (or `secret`, to forge one)."""
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT", "kid": KID}).encode())
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": sub,
        "iat": int(time.time()) - 5,
        "exp": int(time.time()) + exp_offset,
        "roles": roles,
    }
    body = _b64url(json.dumps(claims).encode())
    sig = hmac.new(secret, f"{header}.{body}".encode(), hashlib.sha256).digest()
    return f"{header}.{body}.{_b64url(sig)}"


class _Jwks(BaseHTTPRequestHandler):
    """Serves the issuer's key set and records each fetch."""

    fetches: list = []

    def do_GET(self):
        type(self).fetches.append(self.path)
        doc = {
            "keys": [
                {"kty": "oct", "kid": KID, "alg": "HS256", "use": "sig", "k": _b64url(HS256_SECRET)}
            ]
        }
        out = json.dumps(doc).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *args):
        pass


@pytest.fixture
def jwks_url():
    """A loopback JWKS endpoint. Fetches are recorded in `_Jwks.fetches`."""
    _Jwks.fetches = []
    server = HTTPServer(("127.0.0.1", 0), _Jwks)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}/jwks"
    server.shutdown()
    server.server_close()


def _idp_plugin(jwks: str, *, perform_http: bool = True) -> str:
    caps = "    capabilities: [perform_http]\n" if perform_http else ""
    return (
        "plugins:\n"
        "  - name: idp\n"
        "    kind: identity/jwt\n"
        "    hooks: [identity.resolve]\n"
        f"{caps}"
        "    config:\n"
        "      claim_mapper: standard\n"
        "      trusted_issuers:\n"
        f"        - issuer: {ISSUER}\n"
        f"          audiences: [{AUDIENCE}]\n"
        "          algorithms: [HS256]\n"
        "          decoding_key:\n"
        "            kind: jwks_url\n"
        f'            url: "{jwks}"\n'
        "            insecure_http: true\n"
    )


def _write(tmp_path, text: str) -> str:
    path = tmp_path / "policy.yaml"
    path.write_text(text)
    return str(path)


async def _engine(tmp_path, text: str, **kwargs) -> PolicyEngine:
    eng = PolicyEngine(_write(tmp_path, text), **kwargs)
    await eng.initialize()
    return eng


async def _resolve(eng: PolicyEngine, token: str, tool: str):
    """Run identity.resolve for a bearer token on `tool`'s route."""
    return await eng.invoke_hook(
        "identity.resolve",
        {"source": "bearer", "headers": {"authorization": f"Bearer {token}"}},
        tool_route(tool),
    )


async def _call(eng: PolicyEngine, token: str, tool: str, args: dict, session: str | None = None):
    """Resolve the caller, then run the tool call with their subject applied.

    Returns the pre-invoke result, or the identity result when resolution
    stops the request.
    """
    ident = await _resolve(eng, token, tool)
    if not ident.continue_processing:
        return ident
    ext = tool_route(tool)
    ext["security"] = {"subject": ident.modified_payload["subject"]}
    if session is not None:
        ext["agent"] = {"session_id": session}
    return await eng.invoke_hook("cmf.tool_pre_invoke", tool_call(tool, args), ext)


# ---------------------------------------------------------------------------
# Config load
# ---------------------------------------------------------------------------


def test_removed_global_policies_key_fails_naming_the_key(tmp_path):
    """A 0.2.x `global.policies:` block is an unknown key, named in the error."""
    path = _write(tmp_path, "global:\n  policies:\n    - name: legacy\n")
    with pytest.raises(ValueError, match="unknown key `policies`") as info:
        PolicyEngine(path)
    assert "groups" in str(info.value), "the error points at the replacement block"


def test_removed_global_apl_wrapper_fails(tmp_path):
    """The 0.2.x `global.apl:` wrapper is gone; its keys moved up a level."""
    path = _write(tmp_path, "global:\n  apl:\n    pdp:\n      - kind: cel\n")
    with pytest.raises(ValueError, match="unknown key `apl`"):
        PolicyEngine(path)


def test_legacy_hook_name_fails(tmp_path):
    """A 0.2.x hook name is rejected at load."""
    path = _write(
        tmp_path,
        "engine_settings:\n  dispatch: hooks\n"
        "plugins:\n  - name: idp\n    kind: identity/jwt\n    hooks: [identity_resolve]\n",
    )
    with pytest.raises(ValueError, match="unknown hook"):
        PolicyEngine(path)


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

IDENTITY_ROUTES = """
routes:
  - tool: get_compensation
    authentication: [idp]
    authorization:
      pre_invocation:
        - "require(authenticated)"
        - "require(role.hr)"
"""


@pytest.mark.asyncio
async def test_jwt_identity_gates_a_route_by_role(tmp_path, jwks_url):
    """A valid token resolves a subject; the route allows hr and denies others."""
    eng = await _engine(
        tmp_path, _idp_plugin(jwks_url) + IDENTITY_ROUTES, allow_private_destinations=True
    )
    assert _Jwks.fetches == ["/jwks"], "initialize fetches the key set once"

    ident = await _resolve(eng, mint("alice", ["hr"]), "get_compensation")
    hr = await _call(eng, mint("alice", ["hr"]), "get_compensation", {"employee_id": "e-1"})
    engineer = await _call(eng, mint("evan", ["engineer"]), "get_compensation", {"employee_id": "e-1"})
    await eng.shutdown()

    assert ident.continue_processing is True
    subject = ident.modified_payload["subject"]
    assert subject["id"] == "alice"
    assert subject["roles"] == ["hr"]
    assert "raw_token" not in ident.modified_payload
    assert hr.continue_processing is True
    assert engineer.continue_processing is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "token, code",
    [
        (mint("alice", ["hr"], exp_offset=-3600), "auth.token_expired"),
        (mint("alice", ["hr"], secret=b"not-the-issuer-key-not-the-issuer"), "auth.signature_invalid"),
        ("not-a-jwt", "auth.malformed"),
    ],
    ids=["expired", "forged", "malformed"],
)
async def test_jwt_identity_rejects_bad_tokens(tmp_path, jwks_url, token, code):
    """Identity resolution stops a bad token with its auth code."""
    eng = await _engine(
        tmp_path, _idp_plugin(jwks_url) + IDENTITY_ROUTES, allow_private_destinations=True
    )
    result = await _resolve(eng, token, "get_compensation")
    await eng.shutdown()

    assert result.continue_processing is False
    assert result.violation["code"].startswith(code), result.violation


@pytest.mark.asyncio
async def test_jwks_on_loopback_is_refused_without_the_opt_in(tmp_path, jwks_url):
    """By default the transport never reaches a loopback JWKS; tokens fail closed."""
    eng = await _engine(tmp_path, _idp_plugin(jwks_url) + IDENTITY_ROUTES)
    result = await _resolve(eng, mint("alice", ["hr"]), "get_compensation")
    await eng.shutdown()

    assert _Jwks.fetches == []
    assert result.continue_processing is False
    assert result.violation["code"] == "auth.jwks_unavailable"


@pytest.mark.asyncio
async def test_jwks_url_without_perform_http_fails_to_start(tmp_path, jwks_url):
    """A `jwks_url` issuer on a plugin without `perform_http` refuses to initialize."""
    eng = PolicyEngine(
        _write(tmp_path, _idp_plugin(jwks_url, perform_http=False) + IDENTITY_ROUTES),
        allow_private_destinations=True,
    )
    with pytest.raises(RuntimeError, match="perform_http") as info:
        await eng.initialize()
    assert "idp" in str(info.value)
    assert _Jwks.fetches == []


# ---------------------------------------------------------------------------
# PDP decisions on the resolved subject
# ---------------------------------------------------------------------------

CEDAR = """
global:
  pdp:
    - kind: cedar-direct
      policy_text: |
        @id("hr-read-compensation")
        permit(principal, action == Action::"read", resource)
        when { principal.roles.contains("hr") };

        @id("contractor-forbid")
        forbid(principal, action, resource)
        when { principal.roles.contains("contractor") };

routes:
  - tool: get_compensation
    authentication: [idp]
    authorization:
      pre_invocation:
        - cedar:
            action: 'Action::"read"'
            resource:
              type: Compensation
              id: e-1001
"""


@pytest.mark.asyncio
async def test_cedar_decides_on_the_jwt_subject(tmp_path, jwks_url):
    """Cedar permits hr, default-denies others, and names a forbid by policy id."""
    eng = await _engine(tmp_path, _idp_plugin(jwks_url) + CEDAR, allow_private_destinations=True)
    args = {"employee_id": "e-1001"}
    hr = await _call(eng, mint("alice", ["hr"]), "get_compensation", args)
    engineer = await _call(eng, mint("evan", ["engineer"]), "get_compensation", args)
    contractor = await _call(eng, mint("carl", ["hr", "contractor"]), "get_compensation", args)
    await eng.shutdown()

    assert hr.continue_processing is True
    assert engineer.continue_processing is False
    assert engineer.violation["code"] == "cedar.default_deny"
    assert contractor.continue_processing is False
    assert "contractor-forbid" in contractor.violation["code"]


OPA = """
global:
  pdp:
    - kind: opa
      modules:
        - |
          package cpex.acceptance
          default allow := false
          allow if {
            input.subject.id == "alice"
            input.args.amount <= 100
          }

routes:
  - tool: transfer
    authentication: [idp]
    authorization:
      pre_invocation:
        - opa:
            query: "data.cpex.acceptance.allow"
"""


@pytest.mark.asyncio
async def test_opa_decides_on_the_jwt_subject_and_args(tmp_path, jwks_url):
    """Rego reads the resolved subject and the tool arguments together."""
    eng = await _engine(tmp_path, _idp_plugin(jwks_url) + OPA, allow_private_destinations=True)
    alice = mint("alice", ["finance"])
    small = await _call(eng, alice, "transfer", {"amount": 50})
    large = await _call(eng, alice, "transfer", {"amount": 500})
    other = await _call(eng, mint("evan", ["finance"]), "transfer", {"amount": 50})
    await eng.shutdown()

    assert small.continue_processing is True
    assert large.continue_processing is False
    assert other.continue_processing is False
    assert other.violation["code"] == "opa"


# ---------------------------------------------------------------------------
# Session labels
# ---------------------------------------------------------------------------

SESSION = """
routes:
  - tool: get_compensation
    authentication: [idp]
    authorization:
      pre_invocation:
        - "require(role.hr)"
        - "taint(secret, session)"

  - tool: send_email
    authentication: [idp]
    authorization:
      pre_invocation:
        - "require(authenticated)"
        - "security.labels contains \\"secret\\": deny('write-down blocked', 'session_tainted')"
"""


@pytest.mark.asyncio
async def test_session_label_blocks_write_down_in_the_same_session(tmp_path, jwks_url):
    """Reading compensation taints the session; a later email there is denied."""
    eng = await _engine(tmp_path, _idp_plugin(jwks_url) + SESSION, allow_private_destinations=True)
    alice = mint("alice", ["hr"])
    email = {"to": "bob@corp.example"}
    before = await _call(eng, alice, "send_email", email, session="sess-1")
    read = await _call(eng, alice, "get_compensation", {"employee_id": "e-1"}, session="sess-1")
    after = await _call(eng, alice, "send_email", email, session="sess-1")
    fresh = await _call(eng, alice, "send_email", email, session="sess-2")
    other = await _call(eng, mint("evan", ["engineer"]), "send_email", email, session="sess-1")
    await eng.shutdown()

    assert before.continue_processing is True
    assert read.continue_processing is True
    assert after.continue_processing is False
    assert after.violation["code"] == "session_tainted"
    assert fresh.continue_processing is True, "labels stay in their session"
    assert other.continue_processing is True, "another subject's session is separate"
