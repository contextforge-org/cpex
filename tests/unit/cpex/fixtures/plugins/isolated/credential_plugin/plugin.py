"""An identity/delegation plugin fixture that records the credential it received.

Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: habeck

Fixture for the isolated-worker credential path. The worker reconstructs the
plaintext token onto the payload's ``SecretStr`` field before invoking the hook
(the payload JSON itself carries only ``"**********"``, because ``SecretStr``
redacts on serialization). This plugin records what it actually observed so a
test can assert the plaintext arrived.

Hooks are 2-arg ``(payload, context)``: identity and delegation plugins read the
credential from their payload, not from a third ``extensions`` argument.

The observation is written to a file rather than a module global because the
worker runs in a separate process — an in-memory side effect would not be
visible to the test. The path comes from ``CPEX_CREDENTIAL_PROBE`` so the test
owns the location.
"""

import json
import logging
import os

from cpex.framework import Plugin, PluginConfig, PluginContext
from cpex.framework.hooks.identity import (
    DelegationPayload,
    DelegationResult,
    IdentityPayload,
    IdentityResolveResult,
    IdentityResult,
    TokenDelegateResult,
)

logger = logging.getLogger(__name__)

PROBE_ENV_VAR = "CPEX_CREDENTIAL_PROBE"


def _record(observation: dict) -> None:
    """Append one observation to the probe file, if one was configured.

    Args:
        observation: what the hook saw, as JSON-serializable data.
    """
    probe_path = os.environ.get(PROBE_ENV_VAR)
    if not probe_path:
        return
    with open(probe_path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(observation) + "\n")


class CredentialPlugin(Plugin):
    """Records the credential its identity/delegation hooks observed."""

    def __init__(self, config: PluginConfig):
        """Entry init block for plugin.

        Args:
            config: the plugin configuration.
        """
        super().__init__(config)

    async def identity_resolve(self, payload: IdentityPayload, context: PluginContext) -> IdentityResolveResult:
        """Record the raw token the worker delivered on the payload.

        Args:
            payload: the identity payload, with raw_token reconstructed by the worker.
            context: contextual information about the hook call.

        Returns:
            A passing result; the recording is the point of this fixture.
        """
        _record(
            {
                "hook": "identity_resolve",
                "raw_token": payload.raw_token.get_secret_value(),
                "source": payload.source,
                "headers": dict(payload.headers),
            }
        )
        return IdentityResolveResult(continue_processing=True, modified_payload=IdentityResult())

    async def token_delegate(self, payload: DelegationPayload, context: PluginContext) -> TokenDelegateResult:
        """Record the bearer token the worker delivered on the payload.

        Args:
            payload: the delegation payload, with bearer_token reconstructed by the worker.
            context: contextual information about the hook call.

        Returns:
            A passing result; the recording is the point of this fixture.
        """
        bearer = payload.bearer_token.get_secret_value() if payload.bearer_token is not None else None
        _record(
            {
                "hook": "token_delegate",
                "bearer_token": bearer,
                "target_name": payload.target_name,
            }
        )
        return TokenDelegateResult(continue_processing=True, modified_payload=DelegationResult())
