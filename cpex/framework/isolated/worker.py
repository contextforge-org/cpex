# -*- coding: utf-8 -*-
"""Location: ./cpex/framework/isolated/worker.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Ted Habeck, Fred Araujo

Isolated plugin server
Module that contains plugin server code to invoke hooks in native plugins.
"""

import asyncio
import contextlib
import hashlib
import importlib.metadata
import io
import json
import logging
import platform
import sys
import traceback
from pathlib import Path
from types import ModuleType
from typing import List, Type, cast

from pydantic import SecretStr

from cpex.framework.base import HookRef, Plugin, PluginRef
from cpex.framework.constants import HOOK_TYPE

# Imported for its import-time side effect: cpex.framework.hooks.identity calls
# _register_identity_hooks() at module load, and cpex.framework.__init__ does not
# import it (unlike hooks.tools, hooks.prompts, hooks.resources, hooks.agents,
# hooks.http). Without this import the identity_resolve and token_delegate hooks
# are absent from the registry, so json_to_payload raises "No payload defined for
# hook identity_resolve" and no out-of-process identity or delegation plugin can
# run at all — credential field or not.
from cpex.framework.hooks import identity as _identity_hooks  # noqa: F401  (side effect: hook registration)
from cpex.framework.loader.plugin import ALLOWED_PLUGIN_DIRS
from cpex.framework.manager import PluginExecutor
from cpex.framework.models import PluginConfig, PluginContext, PluginPayload
from cpex.framework.utils import import_module, parse_class_name

logger = logging.getLogger(__name__)

# Hooks that receive raw credentials. These are the only two hook types for
# which the framework models a raw token on the payload itself
# (IdentityPayload.raw_token, DelegationPayload.bearer_token), so they are the
# only two the worker reconstructs. Delivering raw credentials to any other hook
# would require an Extensions credential slot the framework deliberately lacks.
IDENTITY_RESOLVE_HOOK = "identity_resolve"
TOKEN_DELEGATE_HOOK = "token_delegate"
CREDENTIAL_HOOKS = frozenset({IDENTITY_RESOLVE_HOOK, TOKEN_DELEGATE_HOOK})

# Task field the Rust host attaches the credential object to, and its two
# per-hook sub-objects. See the Wire Contract in
# docs/plans/2026-07-28-002-feat-worker-credential-consumption-plan.md.
CREDENTIAL_FIELD = "credential"

# credential.inbound.kind -> IdentityPayload.source. Token kinds that travel in
# an Authorization-style header map to "bearer"; anything else falls back to
# "custom" so a validator can inspect headers itself rather than trusting a
# source it does not recognize.
_BEARER_TOKEN_KINDS = frozenset({"jwt", "opaque", "spiffe_jwt", "ucan"})
_DEFAULT_CREDENTIAL_SOURCE = "custom"

# Placeholder substituted for the plaintext token in any *header* value.
#
# IdentityPayload.headers is dict[str, str], not SecretStr — it does NOT redact
# on serialization. So a header carrying the raw token serializes in the clear
# wherever the payload is dumped, most notably when a TRANSFORM-mode identity
# plugin echoes the payload back as modified_payload and the worker serializes
# the response to the stdout channel the host reads. The plaintext therefore
# lives on raw_token/bearer_token (which redact) and nowhere else; headers get
# this placeholder, and a plugin that needs the credential reads raw_token.
REDACTED_HEADER_VALUE = "**********"

# Shortest token the worker will use as a *substring needle*.
#
# Two of the three things done with a plaintext token are substring operations
# over data the token did not come from: `_scrub_token` rewrites any header
# key/value containing it, and `_result_contains_token` fails the task closed when
# the serialized result contains it. Both are meaningless below a few characters
# and actively harmful: a token of "a" makes every header containing the letter
# "a" mangle to the placeholder, and makes any result mentioning "a" anywhere read
# as a credential echo — failing a task closed for a leak that never happened.
#
# 12 is above the length of any credential a real issuer mints (the shortest
# plausible real bearer is a ~16-char opaque API key; JWTs and SPIFFE tokens run
# to hundreds) and well above the length at which a token collides with ordinary
# English words, header names, and status strings by accident. A token shorter
# than this is passed through to the plugin unchanged — it may be a legitimate
# test fixture, and it is not the worker's job to reject it — but it is not used
# as a needle, because at that length the needle does more damage than the leak
# it would catch.
MIN_SCRUBBABLE_TOKEN_LENGTH = 12

# Task field the Rust host attaches the capability-filtered extensions to, and
# the response field a plugin's modified extensions ride back on. The two names
# differ deliberately: the response is a serialized PluginResult, and that model
# already carries `modified_extensions` — the same field the in-process manager
# accumulates — so an out-of-process plugin returns extensions exactly the way
# its in-process equivalent does. See docs/specs/extensions-wire-contract.md.
EXTENSIONS_FIELD = "extensions"
MODIFIED_EXTENSIONS_FIELD = "modified_extensions"

# Headers stripped from extensions in *both* directions (cmf-message-spec §3.5).
#
# The host scrubs these before writing the task; the worker scrubs them again on
# the way back, because a plugin can put anything on its returned HttpExtension
# and the response is the stdout channel the host reads. A gap either direction
# leaks the credential the identity/delegation payload path is supposed to own.
# Compared case-insensitively: HTTP header names are case-insensitive, so a
# case-sensitive check would pass `authorization` straight through.
SENSITIVE_HEADERS = frozenset({"authorization", "cookie", "x-api-key"})


class CredentialError(Exception):
    """A credential field was present but could not yield a usable token.

    Raised to fail closed rather than proceed with an empty ``SecretStr`` that
    would authenticate downstream as an empty bearer. The message never
    includes credential contents — see ``process_task``'s handling, which
    converts this to a fixed error response.
    """


def _credential_source_from_kind(kind: object) -> str:
    """Map a wire ``kind`` to an ``IdentityPayload.source`` value.

    Args:
        kind: the credential's ``kind`` field, as it arrived on the wire.

    Returns:
        "bearer" for known bearer-style token kinds, else "custom".
    """
    if isinstance(kind, str) and kind.lower() in _BEARER_TOKEN_KINDS:
        return "bearer"
    return _DEFAULT_CREDENTIAL_SOURCE


def _is_scrubbable_token(token: str | None) -> bool:
    """Report whether ``token`` is long enough to use as a substring needle.

    Gates the two substring consumers of the plaintext — header scrubbing and the
    result leak check — without gating delivery of the credential itself. See
    ``MIN_SCRUBBABLE_TOKEN_LENGTH`` for why short tokens are excluded.

    Args:
        token: the plaintext token, or None for a non-credential hook.

    Returns:
        True if the token is usable as a needle.
    """
    return isinstance(token, str) and len(token) >= MIN_SCRUBBABLE_TOKEN_LENGTH


def _scrub_token(value: object, token: str) -> object:
    """Recursively replace the plaintext token everywhere inside ``value``.

    Header values arrive from ``json.loads`` of the task line, so a "header" can
    be any JSON type — including a list or nested object. Recursing is what makes
    the scrub total: a top-level ``isinstance(value, str)`` check silently forwards
    ``{"Authorization": ["Bearer <token>"]}`` in the clear.

    Args:
        value: any JSON-shaped value.
        token: the plaintext token to scrub. An empty needle scrubs nothing:
            ``"" in value`` is always True and ``str.replace("", x)`` injects ``x``
            between every character, so an empty token would shred the value it
            was meant to protect. Callers pass "" to mean "forward unscrubbed".

    Returns:
        A scrubbed copy, structurally the same.
    """
    if not token:
        return value
    if isinstance(value, str):
        return value.replace(token, REDACTED_HEADER_VALUE) if token in value else value
    if isinstance(value, dict):
        return {_scrub_token(k, token): _scrub_token(v, token) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_scrub_token(item, token) for item in value]
    return value


def _scrub_token_from_headers(headers: dict, token: str) -> dict[str, str]:
    """Build a ``dict[str, str]`` header map with the plaintext token removed.

    Header values are plain strings that serialize verbatim — ``IdentityPayload``
    declares ``headers: dict[str, str]``, but the payload is rebuilt with
    ``model_copy(update=...)``, which pydantic does **not** validate. So an
    off-type value (a list, a nested object) survives onto the model and then
    serializes in the clear wherever the payload is dumped — most consequentially
    when a plugin copies ``payload.headers`` into ``IdentityResult.raw_claims`` for
    audit, which puts it on the stdout channel the host parses.

    Two defenses, because either alone leaves a hole:

    * **Recursive scrub of keys and values**, so no nesting depth or key position
      carries the plaintext. Substring replacement (rather than dropping the key)
      preserves the scheme prefix, so a plugin can still tell ``Bearer`` from
      ``Basic`` without seeing the credential.
    * **Coercion to the declared type**, so what lands on the model matches
      ``dict[str, str]`` and cannot smuggle a container past ``model_copy``.

    Args:
        headers: the header map to copy, as it arrived on the wire.
        token: the plaintext token to scrub out of every key and value.

    Returns:
        A new ``dict[str, str]``, scrubbed and type-coerced.
    """
    scrubbed: dict[str, str] = {}
    for key, value in headers.items():
        scrubbed_key = _scrub_token(key, token)
        safe_key = scrubbed_key if isinstance(scrubbed_key, str) else str(scrubbed_key)
        safe_value = _scrub_token(value, token)
        # Coerce to str so a container cannot reach the dict[str, str] field via
        # model_copy's unvalidated update. json.dumps keeps a structured value
        # legible rather than rendering it as a Python repr.
        if not isinstance(safe_value, str):
            try:
                safe_value = json.dumps(safe_value)
            except (TypeError, ValueError):  # pragma: no cover - defensive
                safe_value = str(safe_value)
        scrubbed[safe_key] = safe_value
    return scrubbed


def _extract_credential_token(credential: object, sub_field: str) -> tuple[str, dict]:
    """Pull the plaintext token and its sibling fields out of the credential object.

    Args:
        credential: the raw ``credential`` task field.
        sub_field: "inbound" for identity, "delegated" for delegation.

    Returns:
        A ``(token, sub_object)`` tuple. The token is non-empty.

    Raises:
        CredentialError: if the field is malformed or yields no usable token.
            The message names only the shape problem, never a value.
    """
    if not isinstance(credential, dict):
        raise CredentialError("credential field is not an object")

    sub = credential.get(sub_field)
    if not isinstance(sub, dict):
        raise CredentialError(f"credential.{sub_field} is missing or not an object")

    token = sub.get("token")
    # strip() rather than a bare truthiness check: a whitespace-only token is a
    # truthy str, so it would pass — and "Authorization: Bearer    " is not
    # meaningfully different from an empty bearer to a downstream verifier, which
    # is exactly what this guard exists to prevent.
    if not isinstance(token, str) or not token.strip():
        raise CredentialError(f"credential.{sub_field}.token is missing or empty")

    return token, sub


def _require_payload_type(payload: PluginPayload, expected: type, hook_type: str) -> None:
    """Fail closed unless the payload is the type the hook's secret field lives on.

    Args:
        payload: the payload about to be reconstructed.
        expected: the payload class the hook declares.
        hook_type: the hook being invoked, for the error message.

    Raises:
        CredentialError: if the payload is not an instance of ``expected``. The
            message names types only, never a credential value.
    """
    if not isinstance(payload, expected):
        raise CredentialError(
            f"payload type {type(payload).__name__} does not match hook {hook_type} (expected {expected.__name__})"
        )


def reconstruct_credential_payload(hook_type: str, payload: PluginPayload, credential: object) -> PluginPayload:
    """Rebuild an identity/delegation payload with the plaintext token restored.

    ``IdentityPayload.raw_token`` and ``DelegationPayload.bearer_token`` are
    ``SecretStr``, which redacts on serialization — so the payload JSON the
    worker receives carries ``"**********"``, not the token. The plaintext must
    therefore come from the separate ``credential`` field the host attaches, and
    never from the payload JSON.

    ``PluginPayload`` is frozen (``model_config = ConfigDict(frozen=True)``), so
    the secret cannot be assigned in place; the payload is rebuilt via
    ``model_copy(update=...)``. ``model_copy`` bypasses validation, which is what
    we want here: the redacted payload already validated on construction, and we
    are substituting a same-typed field.

    Args:
        hook_type: the hook being invoked. Only ``identity_resolve`` and
            ``token_delegate`` are reconstructed.
        payload: the payload ``json_to_payload`` rebuilt, with secrets redacted.
        credential: the raw ``credential`` task field.

    Returns:
        A new payload carrying the plaintext secret, or ``payload`` unchanged
        when the hook is not credential-bearing.

    Raises:
        CredentialError: if the credential field cannot yield a usable token, or
            if the payload's type does not match the hook.
    """
    if hook_type == IDENTITY_RESOLVE_HOOK:
        # Verify the payload type before writing the secret. model_copy does not
        # validate, so on a hook_type/payload mismatch the secret would land on a
        # field the model does not declare while the field the plugin actually
        # reads keeps its redacted placeholder — a silent fail-open that never
        # raises. Checking converts that into the intended fail-closed error.
        _require_payload_type(payload, _identity_hooks.IdentityPayload, hook_type)
        token, inbound = _extract_credential_token(credential, "inbound")
        update: dict = {"raw_token": SecretStr(token)}

        # Repopulate source only if the redacted payload lost it, or left it at
        # the model default — a payload carrying a deliberate non-default source
        # is authoritative. getattr rather than attribute access because the
        # declared type here is the PluginPayload base, which has no `source`.
        existing_source = getattr(payload, "source", None)
        if not existing_source or existing_source == "bearer":
            update["source"] = _credential_source_from_kind(inbound.get("kind"))

        # Headers name *where* the credential came from; the credential itself
        # stays on raw_token. Any header value equal to the plaintext token (or
        # embedding it, as in "Bearer <token>") is replaced with a placeholder,
        # because headers do not redact on serialization.
        #
        # A token too short to be a real credential is not used as the scrub
        # needle: replacing a 1-2 char substring rewrites every header that merely
        # contains those characters, destroying the header map to hide a token that
        # is not a credential in the first place. Such headers are forwarded
        # type-coerced but unscrubbed — see MIN_SCRUBBABLE_TOKEN_LENGTH.
        scrub_needle = token if _is_scrubbable_token(token) else ""
        headers = inbound.get("headers")
        if isinstance(headers, dict) and headers:
            # Host-supplied headers are forwarded, minus the plaintext.
            update["headers"] = _scrub_token_from_headers(headers, scrub_needle)
        elif not getattr(payload, "headers", None):
            # Synthesize {source_header: <redacted>} so an extractor that keys off
            # headers still learns which header carried the credential; it reads
            # the value itself from raw_token.
            source_header = inbound.get("source_header")
            if isinstance(source_header, str) and source_header:
                # Scrub the header *name* too: it is attacker-influenced input as
                # far as this side of the boundary knows, and a source_header of
                # "X-<token>" would otherwise put the plaintext in a dict key.
                # Via _scrub_token so the short-token needle guard applies here as
                # well, rather than mangling the header name on a 1-char token.
                safe_header = str(_scrub_token(source_header, scrub_needle))
                update["headers"] = {safe_header: REDACTED_HEADER_VALUE}

        return payload.model_copy(update=update)

    if hook_type == TOKEN_DELEGATE_HOOK:
        _require_payload_type(payload, _identity_hooks.DelegationPayload, hook_type)
        token, _ = _extract_credential_token(credential, "delegated")
        return payload.model_copy(update={"bearer_token": SecretStr(token)})

    return payload


class TaskProcessor:
    """
    A Caching task processor that only reloads the plugin if the config has changed.
    """

    config_hash: str
    module_path_hash: str
    plugin_ref: PluginRef
    executor: PluginExecutor
    plugin_config: PluginConfig | None = None

    def __init__(self) -> None:
        """Initialize defaults."""
        hasher = hashlib.sha256()
        hasher.update(b"")
        self.config_hash = hasher.hexdigest()
        self.module_path_hash = self.config_hash

    def compute_hash(self, json_config_or_module_path: str):
        """Compute the hash of the supplied string"""
        hasher = hashlib.sha256()
        hasher.update(json_config_or_module_path.encode())
        return hasher.hexdigest()

    def initialize(
        self,
        plugin_ref: PluginRef,
        executor: PluginExecutor,
        json_config: str,
        module_path: str,
        plugin_config: PluginConfig,
    ):
        """Assign locals, and compute hashes."""
        self.plugin_ref = plugin_ref
        self.executor = executor
        self.config_hash = self.compute_hash(json_config_or_module_path=json_config)
        self.module_path_hash = self.compute_hash(json_config_or_module_path=module_path)
        self.plugin_config = plugin_config

    def get_hook_ref(self, hook_type: str) -> HookRef:
        """
        make sure that the hook ref is not stale for the current task data.
        """
        hook_ref = HookRef(hook_type, self.plugin_ref)
        return hook_ref


def _payload_secret_value(hook_type: str, payload: PluginPayload) -> str | None:
    """Read back the plaintext secret the reconstruction just set on the payload.

    Used only to know what string to scrub out of downstream error text. Reading
    it back off the payload (rather than threading the token through) keeps a
    single source of truth for what the hook can actually see.

    This is the single choke point for every substring use of the plaintext:
    ``execute_hook_scrubbed`` treats a None return as "non-credential hook" and
    skips log/exception/stream scrubbing and the result leak check entirely. So a
    token below ``MIN_SCRUBBABLE_TOKEN_LENGTH`` returns None here — it still
    reached the plugin on the payload's ``SecretStr``, but it is not used as a
    needle, because at that length ``_result_contains_token`` fires on any result
    that happens to contain those few characters and fails the task closed for a
    leak that did not occur.

    Args:
        hook_type: the hook being invoked.
        payload: the reconstructed payload.

    Returns:
        The plaintext secret, or None if the hook carries no secret field or the
        secret is too short to use as a substring needle.
    """
    field = "raw_token" if hook_type == IDENTITY_RESOLVE_HOOK else "bearer_token"
    secret = getattr(payload, field, None)
    if isinstance(secret, SecretStr):
        plaintext = secret.get_secret_value()
        return plaintext if _is_scrubbable_token(plaintext) else None
    return None


def _strip_sensitive_headers(headers: object) -> dict:
    """Drop sensitive entries from one header map, leaving the rest untouched.

    Args:
        headers: a header mapping, or anything falsy.

    Returns:
        A new dict without the sensitive entries. Empty when there was nothing.
    """
    if not headers:
        return {}
    return {name: value for name, value in dict(headers).items() if name.lower() not in SENSITIVE_HEADERS}


# Header-bearing fields on an HttpExtension, across both shapes.
#
# The Python model carries a single `headers` dict; the Rust one splits
# `request_headers` / `response_headers` (plus method/path/host/scheme). The two
# surfaces version independently, so rather than assume either shape this scrubs
# whichever of these the model in play actually declares. A gap here is a
# credential leak, so tolerating both beats pinning one.
_HTTP_HEADER_FIELDS = ("headers", "request_headers", "response_headers")


def sanitize_extensions_http(extensions):
    """Return ``extensions`` with sensitive headers stripped from its http slot.

    Applied to the extensions a plugin returns, before they are serialized onto
    the response the host reads. The host performs the same strip on the way out,
    so the rule holds symmetrically and a plugin cannot inject a credential
    header into the pipeline through its return value.

    Every header map the model declares is scrubbed, not just a request one: a
    response map can carry a ``Set-Cookie`` or an upstream ``Authorization`` echo
    just as a request map carries the inbound credential.

    ``Extensions`` and ``HttpExtension`` are frozen, so this builds new instances
    via ``model_copy`` rather than mutating. When nothing needed stripping the
    original object is returned unchanged, so the common case allocates nothing.

    Args:
        extensions: the plugin's returned Extensions, or None.

    Returns:
        The extensions with a scrubbed http slot, or the original when there was
        no http slot or nothing sensitive on it.
    """
    if extensions is None:
        return None

    http = getattr(extensions, "http", None)
    if http is None:
        return extensions

    declared = getattr(type(http), "model_fields", {}) or {}
    updates = {}
    for field in _HTTP_HEADER_FIELDS:
        if field not in declared:
            continue
        original = getattr(http, field, None) or {}
        scrubbed = _strip_sensitive_headers(original)
        if len(scrubbed) != len(original):
            updates[field] = scrubbed

    # Nothing was sensitive — hand back the original rather than a copy.
    if not updates:
        return extensions

    return extensions.model_copy(update={"http": http.model_copy(update=updates)})


def reconstruct_extensions(raw: object):
    """Rebuild a Python ``Extensions`` from the task's ``extensions`` field.

    ``Extensions`` is a frozen ``BaseModel``, which blocks mutation *after*
    construction, not construction from a dict — so ``model_validate`` is the
    right tool and the frozen-ness is preserved for the plugin.

    The inbound dict is the capability-filtered view the Rust host produced, so
    an absent slot means the plugin's capabilities excluded it. Slot visibility
    is not re-derived here.

    Unknown slots are dropped rather than raising. The two surfaces version
    independently, and a host that grows a slot ahead of the worker would
    otherwise take every plugin on this channel down at reconstruction — a
    failure mode far worse than ignoring a field this build cannot use.

    Args:
        raw: the task's ``extensions`` field: a dict, or None when absent.

    Returns:
        An ``Extensions``, or None when the field was absent or unusable.
    """
    if not isinstance(raw, dict):
        return None

    # Local import: the module is imported by the host-side tooling too, and
    # extensions are only needed on this path.
    from cpex.framework.extensions.extensions import Extensions

    known = {name: value for name, value in raw.items() if name in Extensions.model_fields}
    dropped = set(raw) - set(known)
    if dropped:
        # Worth a line: it means the host is ahead of this worker's model.
        logger.warning("Ignoring unknown extension slots not modeled by this cpex version: %s", sorted(dropped))

    try:
        return Extensions.model_validate(known)
    except Exception as e:
        # A malformed slot must not take the hook down: the plugin can still do
        # useful work with no extensions, exactly as it does today. Log loudly
        # rather than silently degrading, so the shape mismatch is findable.
        logger.warning("Could not reconstruct extensions from the task field; proceeding without them: %s", e)
        return None


@contextlib.contextmanager
def scrubbing_log_factory(token: str):
    """Redact ``token`` from every log record created inside this context.

    The executor in ``cpex/framework/manager.py`` logs plugin exceptions as
    ``logger.error("Plugin %s failed with error: %s", name, str(e))``, so a plugin
    that interpolates its own credential into an exception message lands the
    plaintext in the log stream before the worker regains control. This closes
    that sink, and every other logger in the process with it.

    Why the *record factory* rather than a filter on a logger or handler — each
    of the narrower placements has a hole that a plugin (or one of its
    dependencies) reaches without trying:

    * A filter on the root **logger** only runs for records logged directly on
      root. Records propagated from a child logger such as
      ``cpex.framework.manager`` skip root's filters entirely.
    * A filter on root's **handlers** misses records that never reach them: when
      root has no handlers, ``logging.lastResort`` emits to stderr carrying no
      filters at all; a logger with ``propagate=False`` and its own handler
      bypasses root; and a handler added — or root's handler list cleared — during
      the call is not in the snapshot the filter was attached to.

    ``setLogRecordFactory`` is a single global that *every* ``Logger.makeRecord``
    consults, so it runs before any of those topologies can diverge.

    Two things get scrubbed, and both matter:

    * **The rendered message.** Scrubbing ``record.msg`` and string ``record.args``
      separately misses any non-string arg — ``logger.error("failed: %s", exc)``
      renders the token at format time, after a filter has run. Rendering via
      ``getMessage()`` and storing the result flattens msg+args into one scrubbed
      string, which is immune to argument type and to nesting.
    * **The traceback.** ``logging.Formatter`` renders ``exc_info`` separately via
      ``formatException`` and appends it, so scrubbing the message alone leaves a
      ``logger.exception()`` traceback carrying the plaintext. Pre-rendering it
      into ``exc_text`` (which the formatter prefers when non-empty) and clearing
      ``exc_info`` puts it behind the same scrub.

    Args:
        token: the plaintext to redact from every record created in the context.

    Yields:
        None. The previous factory is restored on exit.
    """
    previous_factory = logging.getLogRecordFactory()

    def scrubbing_factory(*args, **kwargs) -> logging.LogRecord:
        """Create a record with the token redacted from message and traceback."""
        record = previous_factory(*args, **kwargs)

        # Flatten msg + args into one already-rendered, scrubbed string. getMessage
        # can raise if a caller passed mismatched format args; a logging failure
        # must not take down a credential task, and an unrendered record cannot
        # leak through this path anyway.
        try:
            rendered = record.getMessage()
        except Exception:  # pragma: no cover - defensive
            rendered = str(record.msg)
        if token in rendered:
            record.msg = rendered.replace(token, REDACTED_HEADER_VALUE)
            record.args = ()

        # Pre-render the traceback so it passes through the same scrub. The
        # formatter uses a non-empty exc_text in preference to re-rendering
        # exc_info, so clearing exc_info makes the scrubbed text authoritative.
        if record.exc_info:
            try:
                exc_text = "".join(traceback.format_exception(*record.exc_info))
            except Exception:  # pragma: no cover - defensive
                exc_text = ""
            if exc_text:
                record.exc_text = exc_text.replace(token, REDACTED_HEADER_VALUE)
                record.exc_info = None
        if record.exc_text and token in record.exc_text:
            record.exc_text = record.exc_text.replace(token, REDACTED_HEADER_VALUE)

        # stack_info is likewise formatted separately from the message.
        if record.stack_info and token in record.stack_info:
            record.stack_info = record.stack_info.replace(token, REDACTED_HEADER_VALUE)

        return record

    logging.setLogRecordFactory(scrubbing_factory)
    try:
        yield
    finally:
        # Restore before returning so the scrub cannot outlive this task, nor
        # retain a reference to the token across a later, unrelated one.
        logging.setLogRecordFactory(previous_factory)


async def execute_hook_scrubbed(
    tp: TaskProcessor,
    hook_type: str,
    payload: PluginPayload | None,
    plugin_context: PluginContext,
    plaintext_token: str | None,
    extensions=None,
):
    """Run the hook, scrubbing the plaintext token from every sink it can reach.

    When no plaintext is in play this is a plain pass-through to
    ``execute_plugin`` — non-credential hooks pay nothing. With a plaintext token
    live, four sinks need covering:

    * **logs** — via ``scrubbing_log_factory``, because the executor logs
      ``str(e)`` from a failing plugin before the worker regains control.
    * **the raised exception** — re-raised as a ``RuntimeError`` carrying scrubbed
      text, since ``main()``'s handler interpolates ``str(e)`` into both a log
      line and the stdout response the host reads.
    * **stdout written by the plugin** — stdout is the *framing channel* the host
      parses line-by-line, demuxing on ``request_id``. A plugin printing there
      both leaks and desyncs the stream, so the hook's stdout is redirected away
      from it for the duration of the call and re-emitted, scrubbed, on stderr.
    * **the returned result** — ``PluginResult.metadata``,
      ``IdentityResult.reject_reason``, and ``IdentityResult.raw_claims`` are plain
      types that ``main()`` serializes straight to stdout. A result echoing the
      inbound credential fails the task closed rather than shipping it.

    Args:
        tp: the caching task processor holding the executor and plugin ref.
        hook_type: the hook to invoke.
        payload: the (possibly reconstructed) payload.
        plugin_context: per-call plugin context.
        plaintext_token: the live plaintext, or None for non-credential hooks.
        extensions: the reconstructed Extensions, or None. The framework forwards
            it only to hooks whose signature accepts a third argument.

    Returns:
        The plugin result from ``execute_plugin``.

    Raises:
        RuntimeError: replacing any exception whose text carried the plaintext.
        CredentialError: if the plugin's own result echoes the plaintext.
    """

    async def _run():
        """Invoke the hook. Single call site, so the two paths cannot diverge."""
        return await tp.executor.execute_plugin(
            hook_ref=tp.get_hook_ref(hook_type),
            payload=payload,
            local_context=plugin_context,
            violations_as_exceptions=False,
            extensions=extensions,
        )

    if plaintext_token is None:
        return await _run()

    captured_stdout = io.StringIO()
    captured_stderr = io.StringIO()
    try:
        # redirect_std* swap sys.stdout/sys.stderr only; a plugin reaching
        # os.write(1, ...) is beyond an in-process barrier and out of scope.
        # stderr needs capturing too: the reference venv_comm.py reader drains and
        # re-logs worker stderr, so a plugin's direct print(..., file=sys.stderr)
        # reaches the host's log stream without passing through logging at all.
        with (
            scrubbing_log_factory(plaintext_token),
            contextlib.redirect_stdout(captured_stdout),
            contextlib.redirect_stderr(captured_stderr),
        ):
            result = await _run()
    except Exception as e:
        message = str(e)
        if plaintext_token in message:
            # Replace rather than re-raise: the original exception's __str__,
            # __repr__, args, and __cause__ chain all still carry the plaintext,
            # and main()'s handler stringifies whatever reaches it. `from None`
            # drops the leaking cause from the traceback chain.
            raise RuntimeError(
                f"{type(e).__name__}: {message.replace(plaintext_token, REDACTED_HEADER_VALUE)}"
            ) from None
        raise
    finally:
        _emit_captured_streams(captured_stdout.getvalue(), captured_stderr.getvalue(), plaintext_token)

    # A plugin must not hand the credential back on a field that serializes in the
    # clear. Fail closed: a result echoing its own inbound token is a plugin bug,
    # and shipping it would put the plaintext on the channel the host parses.
    if _result_contains_token(result, plaintext_token):
        raise CredentialError("plugin result echoed the inbound credential")

    return result


def _emit_captured_streams(captured_out: str, captured_err: str, token: str) -> None:
    """Re-emit what a plugin wrote to stdout/stderr, scrubbed, on real stderr.

    Diverted rather than discarded, so a plugin's debug output — and any log line
    its handlers wrote to the redirected stderr — stays visible to whoever reads
    worker stderr, minus the credential. stdout output is deliberately *not*
    returned to stdout: that stream is the response-framing channel the host
    demuxes on ``request_id``, and a plugin-authored line there would be parsed as
    a response.

    Args:
        captured_out: whatever the plugin wrote to stdout during the hook call.
        captured_err: whatever was written to stderr during the hook call.
        token: the plaintext to redact before re-emitting.
    """
    if captured_out:
        # print() rather than logger: logging may itself be writing into a stream
        # we just restored, and this must land on real stderr unconditionally.
        print(
            "[worker] plugin wrote to stdout during a credential-bearing hook; "
            "diverted from the response channel: " + captured_out.replace(token, REDACTED_HEADER_VALUE),
            file=sys.stderr,
            flush=True,
        )
    if captured_err:
        print(captured_err.replace(token, REDACTED_HEADER_VALUE), file=sys.stderr, end="", flush=True)


def _result_contains_token(result: object, token: str) -> bool:
    """Report whether the plaintext survives into the serialized result.

    Serializing is the check that matters: it is exactly what ``main()`` does
    before printing to stdout, so it sees the token through whatever plain-typed
    field carried it (``metadata``, ``reject_reason``, ``raw_claims``, a
    violation's ``details``) while respecting ``SecretStr`` redaction.

    Args:
        result: the plugin result.
        token: the plaintext to look for.

    Returns:
        True if the token appears in the serialized result.
    """
    if result is None:
        return False
    try:
        dumped = result.model_dump(mode="json") if hasattr(result, "model_dump") else result
        return token in json.dumps(dumped, default=str)
    except Exception:  # pragma: no cover - defensive
        # If it will not serialize here it will not serialize in main() either;
        # that failure surfaces there rather than being reported as a leak.
        return False


def get_environment_info():
    """Get information about current Python environment."""
    return {
        "python_version": sys.version,
        "python_executable": sys.executable,
        "platform": platform.platform(),
        "installed_packages": [str(d) for d in importlib.metadata.entry_points()][:10],  # First 10 packages
    }


# Wire-protocol features this worker actually implements, reported by the
# `capabilities` task so the host can refuse to run a plugin whose declared
# needs this worker would silently drop.
#
# Add a name here only when the corresponding code path exists. The host treats
# a missing name as "not supported" and fails closed, so an over-broad list here
# reintroduces exactly the silent-drop bug the handshake exists to prevent.
WORKER_PROTOCOL_VERSION = 1
WORKER_FEATURES = (
    # Reads CREDENTIAL_FIELD off the task and repopulates the redacted
    # SecretStr before the hook runs (see reconstruct_credential_payload).
    "credential",
    # Reads EXTENSIONS_FIELD, reconstructs a Python Extensions, and passes it
    # as extensions= to execute_plugin.
    "extensions",
    # Returns a plugin's modified extensions on MODIFIED_EXTENSIONS_FIELD.
    "modified_extensions",
)


def _installed_cpex_version() -> str | None:
    """The installed cpex distribution version, for diagnostics only.

    Advisory: the host gates on `features`, not on this. Two builds have shipped
    as 0.1.2 with different worker protocols, which is precisely why the version
    string cannot be the thing decisions are made on.
    """
    try:
        return importlib.metadata.version("cpex")
    except Exception:  # pragma: no cover - a source checkout may not be installed
        return None


async def process_task(task_data, tp: TaskProcessor):
    """Process the task received from parent."""
    task_type = task_data.get("task_type")

    if task_type == "info":
        return {
            "status": "success",
            "environment": get_environment_info(),
            "message": "Environment info retrieved successfully",
        }

    # Spawn-time handshake. Answered before any plugin code loads so the host
    # can fail a mismatch closed at startup rather than mid-request. A worker
    # predating this task type falls through to "task type not supported.",
    # which the host reads as "no features" — the correct conservative answer.
    if task_type == "capabilities":
        return {
            "status": "success",
            "protocol_version": WORKER_PROTOCOL_VERSION,
            "features": list(WORKER_FEATURES),
            "cpex_version": _installed_cpex_version(),
        }
    # This is essentially emulating the plugin loader's load and instantiate plugin
    if task_type == "load_and_run_hook":
        # relative path from project root.
        json_config = task_data.get("config")
        config_raw = json.loads(json_config)
        module_paths: List[str] = task_data.get("plugin_dirs")
        resolved_paths: List[str] = []
        for module_path in module_paths:
            path = Path(module_path).resolve()
            resolved_module_path = str(path)
            if path.exists():
                resolved_paths.append(resolved_module_path)
                if resolved_module_path not in sys.path:
                    if resolved_module_path.startswith(tuple(ALLOWED_PLUGIN_DIRS)):
                        sys.path.append(resolved_module_path)
                    else:
                        raise RuntimeError(f"plugin module_path '{resolved_module_path}' not in allowed plugin dirs.")
            else:
                raise RuntimeError(f"plugin module_path '{resolved_module_path}' does not exist.")

        if tp.config_hash != tp.compute_hash(json_config):
            # pull the resolved plugin path and only add the module path if it has the same root
            config: PluginConfig = PluginConfig(**config_raw)
            cls_name: str = task_data.get("class_name")
            mod_name, n_cls_name = parse_class_name(cls_name)
            module: ModuleType = import_module(mod_name)
            # cool, we found the module, and verified it implemented the hook type.
            class_ = getattr(module, n_cls_name)
            plugin_type = cast(Type[Plugin], class_)
            plugin = plugin_type(config)
            await plugin.initialize()
            plugin_ref = PluginRef(plugin)
            executor = PluginExecutor(None, 30)
            tp.initialize(
                plugin_ref=plugin_ref,
                executor=executor,
                json_config=json_config,
                module_path=json.dumps(resolved_paths),
                plugin_config=config,
            )
        # retrieve the context
        context = task_data.get("context")
        hook_type = task_data.get(HOOK_TYPE)
        plugin_context = PluginContext(
            state=context.get("state"), global_context=context.get("global_context"), metadata=context.get("metadata")
        )
        # The client serializes the payload with model_dump(mode="json") before
        # sending it over stdin, so it arrives here as a plain dict. Reconstruct
        # the typed PluginPayload (e.g. ToolPreInvokePayload) before invoking the
        # plugin — otherwise the hook receives a dict and attribute access such as
        # payload.args raises AttributeError. This mirrors the response path, which
        # rebuilds results via json_to_result on the client side.
        raw_payload = task_data.get("payload")
        payload = tp.plugin_ref.plugin.json_to_payload(hook_type, raw_payload) if raw_payload is not None else None

        # Identity and delegation payloads carry their raw token as a SecretStr,
        # which serializes redacted — so the plaintext arrives on a separate
        # `credential` task field instead and is folded back onto the payload
        # here, immediately before execution. Reconstruction is opt-in on the
        # field's presence: a credential-bearing hook with no credential field is
        # not an error, it just runs with whatever the payload carried.
        credential = task_data.get(CREDENTIAL_FIELD)

        # The capability-filtered extensions the host serialized for this plugin.
        # Reconstructed here so a 3-arg (payload, context, extensions) hook sees
        # out-of-process what its in-process equivalent would; the framework
        # withholds it from 2-arg hooks, so passing None for an absent field
        # leaves every existing plugin's behavior unchanged.
        extensions = reconstruct_extensions(task_data.get(EXTENSIONS_FIELD))

        # Plaintext held only for the duration of the hook call, and only to scrub
        # it back out of anything the hook logs, raises, prints, or returns (see
        # execute_hook_scrubbed). Reset per call, so no token crosses tasks.
        plaintext_token: str | None = None
        try:
            if payload is not None and credential is not None and hook_type in CREDENTIAL_HOOKS:
                payload = reconstruct_credential_payload(hook_type, payload, credential)
                plaintext_token = _payload_secret_value(hook_type, payload)
            elif payload is None and credential is not None and hook_type in CREDENTIAL_HOOKS:
                # The host attached a credential for a credential-bearing hook but
                # sent no payload to fold it onto, so the plaintext is discarded and
                # the hook runs without it. That is a host/worker contract violation
                # — every other way this path can fail raises CredentialError and
                # logs — so it gets logged rather than dropped silently, leaving the
                # authentication that quietly did not happen traceable. Logged, not
                # raised: the hook itself may legitimately take no payload, and the
                # framework's rule is that an absent payload is not an error.
                logger.warning(
                    "Credential field present for hook %s but no payload to reconstruct; "
                    "the credential was not delivered to the plugin",
                    hook_type,
                )

            # The hook runs behind a scrubbing barrier: a plugin is free to
            # interpolate its own credential into a log line, an exception, a
            # stdout write, or its returned result, and everything downstream of
            # here would forward that verbatim onto the channel the host reads.
            result = await execute_hook_scrubbed(
                tp=tp,
                hook_type=hook_type,
                payload=payload,
                plugin_context=plugin_context,
                plaintext_token=plaintext_token,
                extensions=extensions,
            )

            # A plugin's returned extensions ride back on the result's
            # `modified_extensions`, which main() serializes to the stdout channel
            # the host reads — so they get the same sensitive-header strip the
            # host applied on the way out. Leaving the field unset is the
            # contract's "no change" signal and is passed through untouched.
            modified = getattr(result, MODIFIED_EXTENSIONS_FIELD, None)
            if modified is not None:
                sanitized = sanitize_extensions_http(modified)
                if sanitized is not modified:
                    result = result.model_copy(update={MODIFIED_EXTENSIONS_FIELD: sanitized})

            return result
        except CredentialError as ce:
            # Fail closed, for both causes: a credential field that cannot yield a
            # usable token (proceeding would authenticate downstream as an empty
            # bearer), and a plugin result that echoed the plaintext (shipping it
            # would put the credential on stdout). str(ce) is safe to echo —
            # CredentialError messages name only the problem, never a value.
            logger.error("Credential handling failed for hook %s: %s", hook_type, str(ce))
            return {
                "status": "error",
                "message": f"Credential reconstruction failed: {str(ce)}",
                "request_id": task_data.get("request_id", "unknown"),
            }
    return {
        "status": "error",
        "message": "task type not supported.",
        "request_id": task_data.get("request_id", "unknown") if "task_data" in locals() else "unknown",
    }


def read_task_line(max_content_size: int | None) -> tuple[str, bool]:
    """Read one task line from stdin, enforcing max_content_size.

    TextIOWrapper.readline takes a positional size hint (readline(size=-1, /));
    there is no `limit` keyword. readline(size) returns *at most* size chars,
    stopping early at a newline. So if we read exactly max_content_size chars
    with no trailing newline, the task was truncated mid-line and the rest is
    still queued on stdin — if left there it would be mis-read as the next task,
    desyncing the request_id-demuxed stream. In that case we drain the remainder
    (bounded, discarded) so the next read starts on a fresh line.

    A line that is exactly max_content_size chars *including* its newline is a
    complete, valid task, not a truncation — hence the endswith check.

    Returns (line, oversized). When oversized is True the line was truncated and
    its content should not be parsed; the caller should reject the request. An
    empty line signals EOF.
    """
    if max_content_size:
        line = sys.stdin.readline(int(max_content_size))
    else:
        # on the first read, the plugin_config has not yet been initialized so just read.
        line = sys.stdin.readline()

    if not (max_content_size and len(line) == max_content_size and not line.endswith("\n")):
        return line, False

    # Drain the rest of the oversized line in bounded chunks so we never buffer
    # the giant remainder into memory. Track total drained length so the log
    # reflects how far over the limit the offending line actually was.
    drained_len = len(line)
    while True:
        remainder = sys.stdin.readline(int(max_content_size))
        drained_len += len(remainder)
        if not remainder or remainder.endswith("\n"):
            break
    logger.error(
        "Task line exceeds max content size (max=%d, read at least %d chars); rejecting request",
        max_content_size,
        drained_len,
    )
    return line, True


async def main():
    """Main function - continuously read from stdin, process tasks, write to stdout."""
    logger.info("Worker process started, waiting for tasks...")

    try:
        # Cache the plugin so that it only has to be initialized once
        tp = TaskProcessor()
        # Continuously read and process tasks
        while True:
            # Reset per iteration so an error before the task is parsed never
            # emits a *previous* request's id (venv_comm demuxes strictly on
            # request_id; a stale id misdelivers the error or hangs the caller).
            request_id = "unknown"
            try:
                # Read one line at a time. getattr rather than `in`/attribute
                # access because plugin_config is a PluginConfig model, not a
                # dict, and it may be None on the first read (config not yet
                # initialized) or lack the field on older cpex versions.
                max_content_size = getattr(tp.plugin_config, "max_content_size", None)
                line, oversized = read_task_line(max_content_size)
                # Check for EOF
                if not line:
                    logger.info("EOF received, shutting down worker")
                    break

                # An oversized (truncated) line was already drained from stdin by
                # read_task_line; its content is not reliably parseable JSON, so
                # request_id is unrecoverable and stays "unknown". Reject it.
                if oversized:
                    error_response = {
                        "status": "error",
                        "message": "Task line exceeds max content size",
                        "request_id": request_id,
                    }
                    print(json.dumps(error_response), flush=True)
                    continue

                # Parse the task
                task_data = json.loads(line.strip())
                request_id = task_data.get("request_id", "unknown")

                # Check for shutdown signal
                if task_data.get("task_type") == "shutdown":
                    logger.info("Shutdown signal received")
                    response = {"status": "success", "message": "Shutting down", "request_id": request_id}
                    print(json.dumps(response), flush=True)
                    break

                # Process the task
                response = await process_task(task_data, tp)

                # Serialize response. process_task returns either a pydantic
                # result model (the hook path) or a plain dict (the info,
                # unsupported-task-type, and fail-closed credential paths), so
                # only call model_dump when there is one to call — otherwise the
                # dict branches raise AttributeError into the generic handler and
                # their real message is replaced by a model_dump complaint.
                if response is None:
                    # none case should be a failure rather than success.
                    serializable_response = {"status": "success"}
                elif isinstance(response, dict):
                    serializable_response = response
                else:
                    serializable_response = response.model_dump(mode="json")

                # Add request_id to response
                serializable_response["request_id"] = request_id

                serialized_response = json.dumps(serializable_response)
                # Send response back to parent (one line per response)
                # workaround until cpex is updated beyond dev11: older cpex
                # (a dependency of the plugin) has a PluginConfig without
                # max_content_size, so use getattr rather than `in`/attribute
                # access. PluginConfig is a model, not a dict, so `in` raises.
                response_max_content_size = getattr(tp.plugin_config, "max_content_size", None)
                if response_max_content_size and len(serialized_response) > response_max_content_size:
                    logger.error("Serialized response exceeds max content size")
                    error_response = {
                        "status": "error",
                        "message": "Serialized response exceeds max content size",
                        "request_id": request_id,
                    }
                    serialized_response = json.dumps(error_response)
                print(serialized_response, flush=True)

            except json.JSONDecodeError as e:
                error_response = {
                    "status": "error",
                    "message": f"Invalid JSON input: {str(e)}",
                    "request_id": "unknown",
                }
                print(json.dumps(error_response), flush=True)

            except Exception as e:
                logger.error("Error processing task: %s", str(e))
                error_response = {
                    "status": "error",
                    "message": f"Unexpected error: {str(e)}",
                    # request_id is reset to "unknown" at the top of each loop
                    # iteration and set once the task line parses, so callers
                    # can demux without risk of a stale id from a prior request.
                    "request_id": request_id,
                }
                print(json.dumps(error_response), flush=True)

    except KeyboardInterrupt:
        logger.info("Worker interrupted")
    except Exception:
        logger.exception("Fatal error in worker main loop")
    finally:
        logger.info("Worker process shutting down")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
