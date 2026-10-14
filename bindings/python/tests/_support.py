# Location: ./bindings/python/tests/_support.py
# Copyright 2025
# SPDX-License-Identifier: Apache-2.0
#
# Payload and extension builders shared by the binding tests.

from pathlib import Path
from typing import Any

FIXTURES_DIR = Path(__file__).parent / "fixtures"
PII_DENY_CONFIG = str(FIXTURES_DIR / "pii_deny.yaml")
PII_REDACT_CONFIG = str(FIXTURES_DIR / "pii_redact.yaml")
PASSTHROUGH_CONFIG = str(FIXTURES_DIR / "passthrough.yaml")

# The wire-compat list pinned by the C FFI tests. One file for both
# surfaces, so a new PPE builtin is one edit.
WIRE_COMPAT_JSON = (
    Path(__file__).resolve().parents[3]
    / "crates"
    / "cpex-ffi"
    / "tests"
    / "fixtures"
    / "wire_compat.json"
)


def tool_call(name: str, arguments: dict[str, Any], call_id: str = "tc_001") -> dict:
    """A CMF payload carrying one assistant tool call."""
    return {
        "message": {
            "role": "assistant",
            "content": [
                {
                    "content_type": "tool_call",
                    "content": {
                        "tool_call_id": call_id,
                        "name": name,
                        "arguments": arguments,
                    },
                }
            ],
        }
    }


def text_message(text: str) -> dict:
    """A CMF payload carrying one user text part."""
    return {
        "message": {
            "role": "user",
            "content": [{"content_type": "text", "text": text}],
        }
    }


def tool_route(name: str) -> dict:
    """Extensions that select the `routes:` entry for tool `name`.

    Under the default `dispatch: policy`, the engine picks the route from
    `meta.entity_type` and `meta.entity_name`.
    """
    return {"meta": {"entity_type": "tool", "entity_name": name}}
