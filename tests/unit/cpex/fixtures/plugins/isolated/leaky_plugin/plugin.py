"""A deliberately leaky identity plugin fixture, for redaction-hardening tests.

Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: habeck

Every hook here tries to exfiltrate the plaintext token it was handed, via a
different sink. The worker's scrubbing barrier is what must stop each one, so
these are the adversarial cases for
``tests/unit/cpex/framework/isolated/test_credential_e2e.py``.

The vector is chosen by the ``CPEX_LEAK_MODE`` environment variable so one
fixture covers every case without the test needing many plugin modules:

* ``log_exception``   — logger.exception() inside the hook (traceback carries it)
* ``log_exc_arg``     — logger.error("%s", exc) with an exception object arg
* ``log_container``   — logger.error("%s", [token]) with a list arg
* ``log_noprop``      — a logger with propagate=False and its own stderr handler
* ``raise_embedded``  — raise with the token interpolated into the message
* ``print_stdout``    — print() onto the worker's response-framing channel
* ``print_stderr``    — print() to stderr
* ``result_metadata`` — return the token in PluginResult.metadata
* ``result_claims``   — return the token in IdentityResult.raw_claims
* ``result_reason``   — return the token in IdentityResult.reject_reason
* ``echo_headers``    — copy payload.headers into raw_claims (the accidental case)
"""

import json
import logging
import os
import sys

from cpex.framework import Plugin, PluginConfig, PluginContext
from cpex.framework.hooks.identity import IdentityPayload, IdentityResolveResult, IdentityResult

logger = logging.getLogger(__name__)

LEAK_MODE_ENV_VAR = "CPEX_LEAK_MODE"


class LeakyPlugin(Plugin):
    """Attempts to leak its credential through whichever sink is selected."""

    def __init__(self, config: PluginConfig):
        """Entry init block for plugin.

        Args:
            config: the plugin configuration.
        """
        super().__init__(config)

    async def identity_resolve(self, payload: IdentityPayload, context: PluginContext) -> IdentityResolveResult:
        """Try to exfiltrate the token via the sink named by CPEX_LEAK_MODE.

        Args:
            payload: the identity payload, with raw_token reconstructed by the worker.
            context: contextual information about the hook call.

        Returns:
            A result, which for the ``result_*`` modes itself carries the token.

        Raises:
            ValueError: in ``raise_embedded`` mode, with the token in the message.
        """
        token = payload.raw_token.get_secret_value()
        mode = os.environ.get(LEAK_MODE_ENV_VAR, "")

        if mode == "log_exception":
            try:
                raise ValueError(f"inner failure {token}")
            except ValueError:
                # Caught by the plugin, so nothing propagates — only the rendered
                # traceback carries the token.
                logger.exception("decode failed")

        elif mode == "log_exc_arg":
            logger.error("decode failed: %s", ValueError(token))

        elif mode == "log_container":
            logger.error("candidates: %s", [token])
            logger.warning("as bytes: %s", token.encode())
            logger.info("nested: %s", {"outer": [{"inner": token}]})

        elif mode == "log_noprop":
            isolated = logging.getLogger("leaky.noprop")
            isolated.propagate = False
            isolated.handlers = [logging.StreamHandler(sys.stderr)]
            isolated.setLevel(logging.DEBUG)
            isolated.error("noprop leak: %s", token)

        elif mode == "raise_embedded":
            raise ValueError(f"could not decode token {token}")

        elif mode == "print_stdout":
            # Aimed at the framing channel the host demuxes on request_id.
            print(json.dumps({"status": "success", "request_id": "req-e2e-leak", "stolen": token}), flush=True)

        elif mode == "print_stderr":
            print(f"stderr leak {token}", file=sys.stderr, flush=True)

        elif mode == "result_metadata":
            return IdentityResolveResult(
                continue_processing=True,
                modified_payload=IdentityResult(),
                metadata={"leaked": token},
            )

        elif mode == "result_claims":
            return IdentityResolveResult(
                continue_processing=True,
                modified_payload=IdentityResult(raw_claims={"tok": token}),
            )

        elif mode == "result_reason":
            return IdentityResolveResult(
                continue_processing=True,
                modified_payload=IdentityResult(rejected=True, reject_reason=f"bad token {token}"),
            )

        elif mode == "echo_headers":
            # The accidental case: copying headers into raw_claims for audit, which
            # is what raw_claims is documented for.
            return IdentityResolveResult(
                continue_processing=True,
                modified_payload=IdentityResult(raw_claims={"hdrs": dict(payload.headers)}),
            )

        return IdentityResolveResult(continue_processing=True, modified_payload=IdentityResult())
