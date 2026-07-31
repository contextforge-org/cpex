"""A 3-arg plugin fixture that records the extensions it received.

Copyright 2026
SPDX-License-Identifier: Apache-2.0
Authors: habeck

Fixture for the isolated-worker extensions channel. Every other isolated fixture
takes 2-arg ``(payload, context)`` hooks, so none of them can observe this
channel at all — a 2-arg hook is never handed extensions, by design. This one
takes the 3-arg ``(payload, context, extensions)`` form that ``_accepts_extensions``
detects in ``cpex/framework/base.py``, which is the only shape the framework
forwards extensions to.

Two things get proven here that the in-process tests cannot:

* **The worker really reads the task's ``extensions`` field.** An in-process test
  builds the ``Extensions`` itself; only a subprocess proves the field crossed
  the process boundary and was reconstructed on the far side.
* **Sensitive headers really do not arrive.** The host strips them before writing
  the task, so a fixture that inspects its inbound headers is the check that the
  strip happened rather than being assumed.

The hook also appends a security label, exercising the return path: the plugin's
modified extensions ride back on ``PluginResult.modified_extensions``, which the
Rust host feeds into the executor's tier-validated merge.

Observations go to a file rather than a module global because the worker runs in
a separate process — an in-memory side effect would not be visible to the test.
The path comes from ``CPEX_EXTENSIONS_PROBE`` so the test owns the location.
"""

import json
import logging
import os

from cpex.framework import (
    Plugin,
    PluginConfig,
    PluginContext,
    ToolPreInvokePayload,
    ToolPreInvokeResult,
)

logger = logging.getLogger(__name__)

PROBE_ENV_VAR = "CPEX_EXTENSIONS_PROBE"

# Appended by the hook to exercise the monotonic tier on the way back.
APPENDED_LABEL = "SCANNED_BY_FIXTURE"

# Names the channel must never carry, in either direction.
SENSITIVE_HEADERS = frozenset({"authorization", "cookie", "x-api-key"})


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


def _describe(extensions) -> dict:
    """Summarize the extensions a hook received, as assertable data.

    Reports what arrived rather than the objects themselves, so the test asserts
    on plain JSON and the probe file never carries a credential even if one
    wrongly made it through.

    Args:
        extensions: the Extensions the framework forwarded, or None.

    Returns:
        A JSON-serializable summary.
    """
    if extensions is None:
        # The meaningful negative case: a task with no extensions field, or a
        # framework that failed to forward them.
        return {"extensions": None}

    security = getattr(extensions, "security", None)
    agent = getattr(extensions, "agent", None)
    http = getattr(extensions, "http", None)

    header_names = []
    if http is not None:
        # The Python HttpExtension carries a single `headers` map; the Rust one
        # splits request/response. Collect whichever exist so this fixture keeps
        # working if the model gains the split shape.
        for field in ("headers", "request_headers", "response_headers"):
            header_names.extend((getattr(http, field, None) or {}).keys())

    lowered = {name.lower() for name in header_names}
    return {
        "extensions": "present",
        "labels": sorted(getattr(security, "labels", None) or []),
        "classification": getattr(security, "classification", None),
        "agent_id": getattr(agent, "agent_id", None),
        "custom": dict(getattr(extensions, "custom", None) or {}),
        "header_names": sorted(lowered),
        # The assertion that matters most: nothing sensitive crossed the boundary.
        "leaked_headers": sorted(lowered & SENSITIVE_HEADERS),
    }


class ExtensionsPlugin(Plugin):
    """Records the extensions its 3-arg hook observed, then appends a label."""

    def __init__(self, config: PluginConfig):
        """Entry init block for plugin.

        Args:
            config: the plugin configuration.
        """
        super().__init__(config)

    async def tool_pre_invoke(
        self,
        payload: ToolPreInvokePayload,
        context: PluginContext,
        extensions=None,
    ) -> ToolPreInvokeResult:
        """Record the inbound extensions and return them with a label appended.

        Args:
            payload: the tool invocation payload.
            context: per-call plugin context.
            extensions: the capability-filtered extensions, or None when the task
                carried no extensions field.

        Returns:
            A result whose ``modified_extensions`` carries the appended label,
            or a plain allow when there were no extensions to modify.
        """
        _record({"hook": "tool_pre_invoke", **_describe(extensions)})

        if extensions is None or extensions.security is None:
            # Nothing to modify. Returning no modified_extensions is the wire
            # contract's "no change" signal.
            return ToolPreInvokeResult(continue_processing=True)

        # Extensions is frozen, so a modification is a new instance via
        # model_copy — the framework's documented pattern. Additive only, so the
        # host's monotonic check accepts it.
        new_labels = sorted(set(extensions.security.labels or []) | {APPENDED_LABEL})
        new_security = extensions.security.model_copy(update={"labels": new_labels})
        return ToolPreInvokeResult(
            continue_processing=True,
            modified_extensions=extensions.model_copy(update={"security": new_security}),
        )
